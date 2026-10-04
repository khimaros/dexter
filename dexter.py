#!/usr/bin/env python3
"""extract an apk's certificates and the private keys its code keeps encrypted

from a description in a config rather than in code: where in the apk
the material is, which certificate is the authority, how files are named, which
cipher protects a key, and how the app mixes the stream that key is keyed from.
android auto is configs/com.google.android.projection.gearhead.toml, so nothing
below names any app.

    dexter.py CONFIG [--apk APP.APK] [--out DIR] [--dump CERTS|ARRAYS]

a config may be given by its bare name, looked for under configs/. a private key
the app encrypts in its own code is found by replaying that app's derivation for
every candidate key material in its code. for an apk no config describes yet,
--dump lists the certificates and the byte arrays a config could point at. needs
only python and the openssl command."""

import argparse
import glob
import pathlib
import re
import struct
import subprocess
import sys
import tomllib
import zipfile
from functools import reduce

import mixer

SCRIPT_DIR = pathlib.Path(__file__).resolve().parent
CACHE = pathlib.Path.home() / ".cache" / "dexter"
# how a byte array's length is stored after the header that introduces it
SIZE_FORMATS = {"u16le": "<H", "u32le": "<I", "u32be": ">I", "u16be": ">H"}
# the android conventions, which a config overrides wherever an app differs
DEFAULTS = {
    "apk": {"path": "", "newest": True},
    "scan": {
        # which apk entries hold the code, and what to look for in them
        "entry": r"classes\d*\.dex",
        "certificate": r"-----BEGIN CERTIFICATE-----[A-Za-z0-9+/=\s\\n]+?-----END CERTIFICATE-----",
        # in the dex string pool a pem's line breaks are escaped
        "certificate_unescape": "\\n",
        "private_key": r"-----BEGIN PRIVATE KEY-----.*?-----END PRIVATE KEY-----",
        # a dex fill-array-data payload of single bytes: the ident, an element
        # width of one and the size as a uint32, the bytes following
        "array_header": "\x00\x03\x01\x00",
        "array_size": "u32le",
        "array_minimum": 16,
    },
    "certs": {"stem": "O", "root": {"file": "ca.crt", "self_signed": False,
                                    "subject": "", "issuer": "", "fingerprint": "",
                                    "verify": True}},
    "keys": {"require_certificate": True, "plaintext": False},
    # no derivation of any app's in here: a config that recovers a key says so
    "derive": {
        "state": 0,
        "seed": "zero",
        "vary": "none",
        "certificates": "all",
        "key_slice": [],
        "iv_slice": [],
        "decrypt": [],
        "source": {"from": "arrays", "minimum": 0, "maximum": 0, "multiple": 0},
        "blob": {"from": "arrays", "minimum": 0, "maximum": 0, "multiple": 0},
        "steps": [],
    },
    "output": {"dir": ""},
}


def overlay(base, extra):
    """a config over its defaults, recursively"""
    if not isinstance(extra, dict):
        return extra
    merged = dict(base)
    for name, value in extra.items():
        merged[name] = overlay(base.get(name, {}), value) if isinstance(value, dict) else value
    return merged


def config_path(name):
    """a config by its path, or by its name under configs/. a package name is
    full of dots, so the extension is added rather than trusted"""
    path = pathlib.Path(name).expanduser()
    for directory in (path.parent, SCRIPT_DIR / "configs"):
        for suffix in ("", ".toml"):
            if (found := directory / (path.name + suffix)).exists():
                return found
    sys.exit(f"no config {name}")


def load_config(name):
    path = config_path(name)
    config = overlay(DEFAULTS, tomllib.loads(path.read_text()))
    config["name"] = path.stem
    check(config)
    return config


def at(config, *names):
    """a value of a config, named by its path through it"""
    return reduce(dict.__getitem__, names, config)


def check_pattern(text, where):
    try:
        re.compile(text)
    except re.error as problem:
        sys.exit(f"config: {where} is not a regular expression: {problem}")


def check(config):
    """fail on a config the rest of the tool could not act on"""
    derive = config["derive"]
    for where in (("scan", "entry"), ("scan", "certificate"), ("scan", "private_key"),
                  ("certs", "stem"), ("certs", "root", "subject"), ("certs", "root", "issuer")):
        check_pattern(at(config, *where), ".".join(where))
    try:
        mixer.program(derive)
        mixer.selections(derive["vary"], [])
    except ValueError as problem:
        sys.exit(f"config: {problem}")
    for name in ("source", "blob"):
        if derive[name]["from"] not in ("arrays", "none"):
            sys.exit(f"config: derive.{name}.from is not arrays or none")
    if derive["certificates"] not in ("all", "leaf", "root"):
        sys.exit("config: derive.certificates is not all, leaf or root")
    if config["scan"]["array_size"] not in SIZE_FORMATS:
        sys.exit(f"config: scan.array_size is not one of {', '.join(SIZE_FORMATS)}")
    if derive["steps"]:
        check_key(config)


def check_key(config):
    """a derivation that could not be turned into a cipher key is a mistake"""
    derive = config["derive"]
    if derive["state"] < 1:
        sys.exit("config: derive.state must be the state size in bytes")
    if len(derive["key_slice"]) != 2:
        sys.exit("config: derive.key_slice must be the [from, to] state range holding the key")
    if not derive["decrypt"]:
        sys.exit('config: derive.decrypt must name the command that unlocks a blob, e.g. '
                 '["openssl", "enc", "-aes-256-cbc", "-d", "-K", "{key}", "-iv", "{iv}"]')
    for name in ("key", "iv"):
        span = derive[f"{name}_slice"]
        wanted = "{" + name + "}"
        if span and len(span) != 2:
            sys.exit(f"config: derive.{name}_slice must be a [from, to] state range or empty")
        if span and span[1] > derive["state"]:
            sys.exit(f"config: derive.{name}_slice runs past derive.state")
        if not span and wanted in "".join(derive["decrypt"]):
            sys.exit(f"config: derive.decrypt uses {wanted} but derive.{name}_slice is empty")


def natural(path):
    """a path split for a sort that reads digits as numbers, so that a version
    code directory sorts by its value and not its characters"""
    return [int(token) if token.isdigit() else token
            for token in re.split(r"(\d+)", str(path))]


def apk_path(config):
    """the apk to read: --apk wins, then the newest the config's glob matches"""
    pattern = config["apk"]["path"]
    if not pattern:
        sys.exit("the config names no apk path and no --apk was given")
    matches = sorted(glob.glob(str(pathlib.Path(pattern).expanduser()), recursive=True), key=natural)
    if not matches:
        sys.exit(f"no apk matches {pattern}")
    return pathlib.Path(matches[-1] if config["apk"]["newest"] else matches[0])


def regions(apk, config):
    """the raw bytes of every code entry of the apk"""
    entry = re.compile(config["scan"]["entry"])
    with zipfile.ZipFile(apk) as archive:
        return [archive.read(name) for name in archive.namelist() if entry.fullmatch(name)]


def certificates(apk, config):
    """every pem certificate in the apk's code, as text"""
    pattern = re.compile(config["scan"]["certificate"].encode())
    blocks = {block for region in regions(apk, config) for block in pattern.findall(region)}
    return sorted(unescape(config, block).decode() + "\n" for block in blocks)


def byte_arrays(apk, config):
    """every byte[] literal in the apk's code. the pattern also matches inside
    other literals, which the length filters of a config usually rule out"""
    header = re.escape(config["scan"]["array_header"].encode())
    size = struct.Struct(SIZE_FORMATS[config["scan"]["array_size"]])
    smallest = config["scan"]["array_minimum"]
    found = []
    for region in regions(apk, config):
        for head in re.finditer(header, region):
            length = size.unpack(region[head.end():head.end() + size.size])[0] \
                if head.end() + size.size <= len(region) else 0
            if smallest <= length <= len(region) - head.end() - size.size:
                start = head.end() + size.size
                found.append(region[start:start + length])
    return list(dict.fromkeys(found))


def selected(spec, arrays):
    """the byte arrays a derive step may be keyed from, or the blobs it may unlock"""
    if spec["from"] == "none":
        return [b""]
    chosen = [array for array in arrays
              if spec["minimum"] <= len(array)
              and (not spec["maximum"] or len(array) <= spec["maximum"])
              and (not spec["multiple"] or len(array) % spec["multiple"] == 0)]
    return sorted(chosen, key=len)


def openssl(*args, pem=""):
    return subprocess.run(["openssl", *args], input=pem, capture_output=True, text=True)


def describe(pem):
    """subject, issuer, validity and fingerprint, one per line"""
    return openssl("x509", "-noout", "-subject", "-issuer", "-dates", "-fingerprint", "-sha256",
                   pem=pem).stdout


def field(description, name):
    return next((line.split("=", 1)[1] for line in description.splitlines() if line.startswith(name + "=")), "")


def self_signed(description):
    return field(description, "subject") == field(description, "issuer")


def base_name(config, description):
    """a certificate's name, from the distinguished name field the config chooses"""
    found = re.search(rf"{config['certs']['stem']}=([^,]+)", field(description, "subject"))
    return re.sub(r"[^a-z0-9]+", "-", found.group(1).lower()).strip("-") if found else "unknown"


def public_key(pem):
    """the subject public key of a certificate, to pair keys with certificates"""
    return openssl("x509", "-noout", "-pubkey", pem=pem).stdout


def authority(config, apk, found):
    """the configured certificate authority, and the certificates under it"""
    spec = config["certs"]["root"]
    others = list(found)
    if not any(spec[name] or spec["self_signed"] for name in ("subject", "issuer")):
        return None, others
    roots = [(pem, text) for pem, text in found
             if (not spec["self_signed"] or self_signed(text))
             and (not spec["subject"] or re.search(spec["subject"], field(text, "subject")))
             and (not spec["issuer"] or re.search(spec["issuer"], field(text, "issuer")))]
    if len(roots) != 1:
        sys.exit(f"expected one authority in {apk}, found {len(roots)}: "
                 f"fix [certs.root] or run with --dump certs")
    return roots[0], [each for each in others if each != roots[0]]


def unique(directory, stem, suffix, taken):
    """a path no other certificate of this run already claimed"""
    name, repeat = stem, 2
    while name + suffix in taken:
        name, repeat = f"{stem}-{repeat}", repeat + 1
    taken.add(name + suffix)
    return directory / (name + suffix)


def write_certificates(config, out, root, others):
    """the authority as its configured file, the rest under their own names"""
    taken = set()
    if root:
        pem, text = root
        path = out / config["certs"]["root"]["file"]
        path.write_text(pem)
        print(f"{path}:\n{text}")
        taken.add(path.name)
    for pem, text in others:
        path = unique(out, base_name(config, text), ".crt", taken)
        path.write_text(pem)
        note = ""
        if root and config["certs"]["root"]["verify"]:
            signed = openssl("verify", "-no_check_time", "-CAfile",
                             out / config["certs"]["root"]["file"], pem=pem).returncode == 0
            note = f", {'signed' if signed else 'NOT signed'} by the authority"
        print(f"{path}{note}:\n{text}")


def feeding(config, found):
    """the certificates an app mixes its key stream from"""
    which = config["derive"]["certificates"]
    return [pem for pem, text in found
            if which == "all" or self_signed(text) == (which == "root")]


def decrypt(blob, command):
    return subprocess.run(command, input=blob, capture_output=True).stdout


def key_pattern(config):
    """what a private key looks like once it is in front of the tool"""
    return re.compile(config["scan"]["private_key"].encode(), re.S)


def unescape(config, block):
    """a pem as its app kept it, with its line breaks put back"""
    return block.replace(config["scan"]["certificate_unescape"].encode(), b"\n")


def unlock(program, config, blobs, sources, certs):
    """whatever the app's encrypted blobs hold, for every stream the app could
    have mixed: each candidate source array and each certificate selection"""
    derive = config["derive"]
    key_slice, iv_slice = derive["key_slice"], derive["iv_slice"]
    pattern = key_pattern(config)
    picks = mixer.selections(derive["vary"], certs)
    keys = set()
    print(f"{len(sources)} source arrays x {len(picks)} certificate selections "
          f"x {len(blobs)} blobs")
    for source in sources:
        for picked in picks:
            state = mixer.state_of(program, picked, source)
            template = {"key": bytes(state[key_slice[0]:key_slice[1]]).hex(),
                        "iv": bytes(state[iv_slice[0]:iv_slice[1]]).hex()}
            template["state"] = template["key"] + template["iv"]
            try:
                command = [part.format(**template) for part in derive["decrypt"]]
            except KeyError as missing:
                sys.exit(f"config: derive.decrypt names {{{missing.args[0]}}}, "
                         "of which only key, iv and state are filled in")
            for blob in blobs:
                if pem := pattern.search(decrypt(blob, command)):
                    keys.add(pem.group().decode() + "\n")
    return keys


def plaintext_keys(apk, config):
    """the private keys an app did not bother to encrypt"""
    if not config["keys"]["plaintext"]:
        return set()
    return {unescape(config, match.group()).decode() + "\n"
            for region in regions(apk, config) for match in key_pattern(config).finditer(region)}


def private_keys(config, apk, found):
    """every private key the app's code holds, encrypted or not"""
    keys = set(plaintext_keys(apk, config))
    if config["derive"]["steps"]:
        program = mixer.program(config["derive"])
        arrays = byte_arrays(apk, config)
        keys |= unlock(program, config, selected(config["derive"]["blob"], arrays),
                       selected(config["derive"]["source"], arrays), feeding(config, found))
    return sorted(keys)


def write_keys(config, apk, out, found):
    """the app's private keys, each under the name of the certificate holding
    the matching public key"""
    keys = private_keys(config, apk, found)
    if not keys:
        print(f"no private key in {apk}")
        return
    holders = {public_key(pem): text for pem, text in found}
    taken = {name.name for name in out.iterdir() if name.suffix == ".crt"}
    for index, key in enumerate(keys, 1):
        text = holders.get(openssl("pkey", "-pubout", pem=key).stdout)
        if text is None and config["keys"]["require_certificate"]:
            print(f"skipping a private key in {apk} no certificate here belongs to")
            continue
        stem = base_name(config, text) if text else f"key-{index}"
        path = unique(out, stem, ".key", taken)
        path.write_text(key)
        path.chmod(0o600)
        of = f", the private key of {path.with_suffix('').name}.crt" if text else ""
        print(f"{path}{of}, valid to {field(text, 'notAfter') if text else 'unknown'}")


def dump(apk, config, found, what):
    """what a config could point at, for an apk no config describes yet"""
    if what == "certs":
        print(f"{len(found)} certificates in {apk}")
        for pem, text in found:
            print(f"  {field(text, 'subject')}  issuer {field(text, 'issuer')}  "
                  f"{'self-signed' if self_signed(text) else 'issued'}  "
                  f"to {field(text, 'notAfter')}")
        return
    arrays = byte_arrays(apk, config)
    print(f"{len(arrays)} byte arrays in {apk}")
    for name in ("source", "blob"):
        chosen = selected(config["derive"][name], arrays)
        print(f"  {name} filters keep {len(chosen)}: sizes "
              f"{', '.join(str(len(array)) for array in chosen[:40])}"
              f"{' ...' if len(chosen) > 40 else ''}")


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("config", help="a config file, or its bare name under configs/")
    parser.add_argument("--apk", type=pathlib.Path, help="the apk to read, in place of the config's")
    parser.add_argument("--out", type=pathlib.Path, help="directory to write to")
    parser.add_argument("--dump", choices=("certs", "arrays"), help="describe the apk instead of writing")
    args = parser.parse_args()

    config = load_config(args.config)
    apk = args.apk or apk_path(config)
    found = [(pem, describe(pem)) for pem in certificates(apk, config)]
    if args.dump:
        dump(apk, config, found, args.dump)
        return
    root, others = authority(config, apk, found)
    out = args.out or pathlib.Path(config["output"]["dir"] or CACHE / config["name"]).expanduser()
    out.mkdir(parents=True, exist_ok=True)
    write_certificates(config, out, root, others)
    write_keys(config, apk, out, found)
    expected = config["certs"]["root"]["fingerprint"]
    if root and expected and field(root[1], "sha256 Fingerprint") != expected:
        print(f"warning: the authority differs from the one this config expects ({expected})")


if __name__ == "__main__":
    main()
