# design

## shape

dexter is four steps over one apk, each reading the config:

1. `regions` reads the apk entries the config calls code
2. `certificates` and `byte_arrays` find the material in them: pems by a regular
   expression, byte[] literals by the header a dex puts in front of them
3. `authority` splits the certificates into the one the config says is the
   authority and the rest, and `write_certificates` writes them and asks the
   openssl command whether the rest verify against it
4. `private_keys` finds keys in the clear and, if the config describes a
   derivation, replays it over every candidate until a blob opens

the config is loaded over `DEFAULTS` and `check`ed before any of that runs, so a
config that cannot be acted on fails at load with the name of the setting at
fault. `configs/template.toml` documents every setting and a test keeps it equal
to `DEFAULTS`.

## scan

an apk is a zip and its code is its dex files, whose string pool holds pems with
their line breaks escaped and whose byte[] literals are introduced by a
fill-array-data payload: an ident, an element width of one and a uint32 length.
Both are configurable, since another packing is another header and another
length.

the patterns are unanchored, so a match is found inside other literals too.
those are not filtered by what they are, only by the length bounds a config gives
`[derive.source]` and `[derive.blob]`, and the ones that survive are simply tried
and simply fail to decrypt.

certificates are returned in sorted pem order, which is the order a config's
`vary = "none"` mixes them in. Every other `vary` tries the orders, so a config
for an app whose order is unknown does not have to know it.

## names, and who a key belongs to

a certificate is named for the distinguished name field `[certs] stem` picks, so
that the files that come out of an apk read like the app. a private key is named
for the certificate whose subject public key matches it, which is why
`[keys] require_certificate` exists: a key whose certificate is not in this apk
has no name, and keeping it anyway means a name of its own.

## derivation

`mixer.py` knows the shape and nothing else. a derivation is a state size, a seed,
and an ordered list of steps; a step has an input to mix over, a number of rounds,
a loop order and an update expression.

each step's pass is *generated* from its expression: `compile_pass` checks the
expression and splices it into the body of a python function that loops over the
input and the state, then compiles that once. the tool therefore holds no app's
algorithm, not even as a fallback, and an expression costs nothing at the byte
beyond a python arithmetic op.

an expression sees the state byte `v`, the indexes `i` and `j`, the lengths `n`
and `m`, and two byte streams: `S(k)` for the source array and `D(k)` for the
input. Both wrap their index, which is what an app's `source[j % len(source)]`
means, and an index into the input is what lets a step mix over something other
than the byte under it.

the state is rewritten as it is read, so a step whose input is `state` itself
mixes in what the round before left there. that is how the apps here work, and
the reason the pass takes the state rather than a copy of it.

## cipher

a blob is opened by a command from the config, with the state's own bytes filled
in as hex: `{key}`, `{iv}`, and `{state}` for the two joined. the default is
`openssl enc -aes-256-cbc -d`. the search is over whatever that command returns,
looking for `[scan] private_key`, so a cipher openssl knows needs no code, and one
it does not needs a command.

## search

the cost is `sources x certificate selections x blobs` cipher invocations, which
is why the length bounds exist: android auto is 31 sources, 2 orders of its two
certificates and 3 candidate blobs, and takes a few seconds. `--dump arrays`
prints what a config's filters would keep, before paying for a run.

## trusting a config

an update expression is checked for shape and then compiled as python, since a
config that could not say `rotl` could not describe these apps. a config is
therefore trusted input, the same as the command in `derive.decrypt`: both run
whatever they name.

## testing

`tests/e2e/fakeapk.py` builds an apk of our own: an authority and a leaf from the
openssl command, pems escaped the way a string pool escapes them, and byte[]
literals with the header a dex gives them. `test_extract.py` mixes the blob with
its own loop over its own constants, which the config then describes from the
outside, so the fixture and the tool are two readings of what a mixer is. the
android auto tests run the real config against the cached apk and are skipped
when it is not there.
