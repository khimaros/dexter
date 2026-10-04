#!/usr/bin/env python3
"""the config driven byte mixer.

an app that keeps a key encrypted in its own code usually keys it with a stream
it mixes out of material it carries. those mixers are all the same shape, a byte
at a time over a fixed state, and differ in their constants and the operators
between them, so a config describes one as a list of steps, each with an input
to mix over, a number of rounds and an update expression:

    [[derive.steps]]
    input = "certs"
    rounds = 2
    update = "xor(add(rotl(v, 1), 33), S(j % n), D(i))"

an expression is a subset of python over the scalars v i j n m, the two byte
streams S and D, the arithmetic operators and the operator functions below, its
result taken modulo 256. each step's pass is generated from its expression and
compiled once, so a config holds whole algorithms, constants and all, and what
one expression cannot reach is another step in the list.

the state is rewritten while it is read, so a step whose input is the state
itself mixes in what the round before left there, as these mixers do."""

import functools
import itertools
import math
import re

# the scalars an update expression is given for each byte it rewrites
VARIABLES = {
    "v": "the state byte before this update",
    "i": "the index of the input byte being mixed",
    "j": "the index of the state byte being rewritten",
    "n": "the length of the source",
    "m": "the length of the input",
}

# the byte streams, each called with an index. indexes wrap, and a missing
# source or an empty input reads as zero.
STREAMS = {
    "S": "a byte of the source array the step is keyed from",
    "D": "a byte of the input the step is mixing over",
}


def _rot(value, bits):
    return ((value & 0xFF) << bits) | ((value & 0xFF) >> (8 - bits))


def _fold(operator, values):
    return functools.reduce(operator, values)


# the operator functions of an expression. python's own keywords are spelled
# bnot, bor and band so that an expression stays evaluable.
OPERATORS = {
    "add": lambda *values: sum(values),
    "mul": lambda *values: math.prod(values),
    "xor": lambda *values: _fold(int.__xor__, values),
    "bor": lambda *values: _fold(int.__or__, values),
    "band": lambda *values: _fold(int.__and__, values),
    "bnot": lambda value: ~value,
    "sub": lambda a, b: a - b,
    "mod": lambda a, b: a % b if b else 0,
    "min": lambda *values: min(values),
    "max": lambda *values: max(values),
    "shl": lambda a, b: a << b,
    "shr": lambda a, b: (a & 0xFF) >> b,
    "rotl": lambda a, b: _rot(a, b % 8),
    "rotr": lambda a, b: _rot(a, (-b) % 8),
}

# arity None takes any number of arguments
ARITY = {name: (None if name in ("add", "mul", "xor", "bor", "band", "min", "max")
               else 1 if name == "bnot" else 2) for name in OPERATORS}

TOKEN = re.compile(r"""(?P<space>\s+)
                     | (?P<call>//|<<|>>|[-+*%&|^~(),])
                     | (?P<number>0[xX][0-9a-fA-F]+|\d+)
                     | (?P<name>[A-Za-z_][A-Za-z0-9_]*)
                     | (?P<bad>.)""", re.VERBOSE)
# what may stand between two terms, and what may stand before one
BINARY = {"+", "-", "*", "%", "//", "&", "|", "^", "<<", ">>"}
UNARY = {"-", "~"}

# one step's pass, generated around its update expression. "byte" mixes an
# input byte over the whole state before the next byte, as a java loop does,
# and "state" holds one state byte while it works through the input.
PASS = {
    "byte": """
    for i in range(m):
        for j in range(len(state)):
            v = state[j]
            state[j] = (__UPDATE__) & 0xFF
""",
    "state": """
    for j in range(len(state)):
        for i in range(m):
            v = state[j]
            state[j] = (__UPDATE__) & 0xFF
""",
}
HEAD = '''
def mixing(state, data, source):
    n, m = len(source), len(data)

    def S(k):
        return source[k % n] if n else 0

    def D(k):
        return data[k % m] if m else 0
'''


class Expression:
    """a recursive descent check that an expression is one we can compile. it
    only verifies the shape, since the pass runs the config's own text."""

    def __init__(self, text):
        self.text = text
        self.tokens = []
        for match in TOKEN.finditer(text):
            if match.lastgroup == "space":
                continue
            if match.lastgroup == "bad":
                raise ValueError(f"{text!r}: cannot use {match.group()!r}")
            self.tokens.append(match.group())
        self.at = 0

    def parse(self):
        self.expression()
        if self.at != len(self.tokens):
            raise ValueError(f"{self.text!r}: unexpected {self.tokens[self.at]!r}")

    def expression(self):
        self.term()
        while self.peek() in BINARY:
            self.at += 1
            self.term()

    def term(self):
        token = self.next("expected a value")
        if token in UNARY:
            return
        if token == "(":
            self.expression()
            self.expect(")")
            return
        if token[0].isdigit():
            return
        if self.peek() == "(":
            self.at += 1
            count = 0 if self.peek() == ")" else 1
            if count:
                self.expression()
                while self.peek() == ",":
                    self.at += 1
                    self.expression()
                    count += 1
            self.expect(")")
            self.arity(token, count)
            return
        self.plain(token)

    def arity(self, name, count):
        if name in STREAMS:
            if count != 1:
                raise ValueError(f"{self.text!r}: {name}() takes one index, got {count}")
            return
        if name not in OPERATORS:
            raise ValueError(f"{self.text!r}: no operator {name}(), only "
                             f"{', '.join(sorted(OPERATORS))}")
        want = ARITY[name]
        if (want is None and count < 1) or (want is not None and count != want):
            raise ValueError(f"{self.text!r}: {name}() takes "
                             f"{'at least one' if want is None else want} argument(s), got {count}")

    def plain(self, token):
        if token in VARIABLES:
            return
        if token in STREAMS:
            raise ValueError(f"{self.text!r}: {token} is a byte stream, write {token}(k)")
        raise ValueError(f"{self.text!r}: no scalar {token!r}, only "
                         f"{', '.join(sorted(VARIABLES))}")

    def peek(self):
        return self.tokens[self.at] if self.at < len(self.tokens) else None

    def next(self, message):
        if self.at >= len(self.tokens):
            raise ValueError(f"{self.text!r}: {message}, but it ends here")
        token = self.tokens[self.at]
        self.at += 1
        return token

    def expect(self, token):
        if self.next(f"expected {token!r}") != token:
            raise ValueError(f"{self.text!r}: expected {token!r}")


def compile_pass(step):
    """a step's mixing pass, generated from its expression"""
    Expression(step["update"]).parse()
    try:
        loops = PASS[step["order"]]
    except KeyError:
        raise ValueError(f"order {step['order']!r} is not one of {', '.join(sorted(PASS))}") from None
    namespace = dict(OPERATORS)
    exec(HEAD + loops.replace("__UPDATE__", step["update"]), namespace)
    return namespace["mixing"]


def seed(spec, size, source):
    """the state an app starts mixing from"""
    if spec == "zero":
        return [0] * size
    if spec == "source":
        return (list(source) + [0] * size)[:size]
    start = bytes.fromhex(spec)
    if len(start) != size:
        raise ValueError(f"seed {spec!r} is {len(start)} bytes, not {size}")
    return list(start)


# what a step need not spell out
STEP_DEFAULTS = {"input": "none", "rounds": 1, "order": "byte"}
INPUTS = ("none", "certs", "state", "source")


def inputs(step, certs, state, source):
    """the byte strings a step mixes over, in order. the state is handed over
    live, so that mixing it over itself reads what the round before left"""
    which = step["input"]
    if which == "none":
        return []
    if which == "certs":
        return [pem.encode() for pem in certs]
    if which == "state":
        return [state]
    if which == "source":
        return [source]
    if isinstance(which, dict) and set(which) == {"text"}:
        return [which["text"].encode()]
    if isinstance(which, dict) and set(which) == {"bytes"}:
        return [bytes.fromhex(which["bytes"])]
    raise ValueError(f"input {which!r} is not one of {', '.join(INPUTS)}, "
                     "{text = ...} or {bytes = ...}")


def program(derive):
    """a [derive] config table as a mixer: its state size and seed and the steps
    to run over it, each with its pass compiled once"""
    steps = []
    for spec in derive["steps"]:
        if "update" not in spec:
            raise ValueError("a step needs an update expression")
        step = {**STEP_DEFAULTS, **spec}
        inputs(step, [""], [0], b"")  # an input nothing could mix over fails here
        steps.append({**step, "mixing": compile_pass(step)})
    return {"size": derive["state"], "seed": derive["seed"], "steps": steps}


def state_of(mix, certs, source):
    """the state this app would derive from some certificates and one source array"""
    state = seed(mix["seed"], mix["size"], source or b"")
    for step in mix["steps"]:
        for _ in range(step["rounds"]):
            for data in inputs(step, certs, state, source or b""):
                step["mixing"](state, data, source or b"")
    return state


# what the tool tries a configuration over, when an app mixes from its certificates
SELECTIONS = {
    "none": lambda certs: [list(certs)],
    "cert": lambda certs: [[cert] for cert in certs],
    "cert_pair": lambda certs: [list(pair) for pair in itertools.permutations(certs, 2)],
}


def selections(vary, certs):
    try:
        return SELECTIONS[vary](certs)
    except KeyError:
        raise ValueError(f"vary {vary!r} is not one of {', '.join(sorted(SELECTIONS))}") from None
