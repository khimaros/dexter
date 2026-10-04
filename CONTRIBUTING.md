# contributing

## toolchain

`mise install` provides the pinned python and ruff. the tests also need the
`openssl` command on the path.

## commands

- `make`: byte compile everything and check the tool starts
- `make test-e2e`: the python end-to-end tests
- `make lint`: ruff
- `make precommit`: lint and the end-to-end tests. run before handing work over.

## layout

- `dexter.py`: the tool. config, scan, certificate handling, key recovery.
- `mixer.py`: the byte mixer. update expressions, generated passes, steps.
- `configs/`: one config per apk, named for its package name, plus
  `template.toml`, which documents every setting and is kept equal to `DEFAULTS`
  by a test.
- `tests/e2e`: python tests. `fakeapk.py` builds a synthetic apk; the mixer in
  `test_extract.py` is written out rather than imported from `mixer.py`, so a
  config is checked against a second reading of what a mixer is.

## adding an algorithm

do not. a step and an update expression are the extension point, and
`configs/template.toml` says what they can say. if an app truly needs a shape
they cannot reach, add it to `mixer.py` as another input kind or operator, with
a config for the app that needs it as its test, so the next app is still a config.

## testing

behaviour that can be seen from outside the tool is tested end to end, by running
it as a command against an apk and reading what it wrote. tests use only the
python standard library and the openssl command. an apk is a download, so the
test that uses the real one skips rather than fetches.

a config is data the tool acts on, so every rejection is a test: a bad
expression, a bad regular expression, a slice past the state, a missing cipher.

## style

python only, standard library only, `openssl` for anything cryptographic. no
argument parsing beyond argparse, no logging framework, no third party package:
the point of the tool is that it runs on a machine that has python and nothing
else.

comments and docs are lowercase, and say why. an expression, a config or a
constant that belongs to one app has its home in that app's config.

## references

- `../behead` is what consumes what comes out of here, and `make rpi-image`
  there reads the certificate cache this tool's android auto config writes to.
- the android auto extraction began as `tools/extract-certs.py` in that tree, a
  hard coded version of one config. its output for the cached apk is recorded in
  `tests/e2e/test_extract.py` as sha-256 digests, which is what a config has to
  keep reproducing.
