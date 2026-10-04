# dexter

extract the certificates an apk carries, and the private keys its code keeps
encrypted, from a description in a config rather than in code.

an android app that talks to something trusted usually carries a certificate
authority, a certificate that authority issued, and the key for it. some of those
apps keep the key aes encrypted inside their own code, keyed by a stream they mix
from the certificates they carry. dexter reads an apk for all of it, and replays
that mixing for the key.

what differs between apps lives in a config: where in the apk the material is,
which certificate is the authority, how files are named, which cipher protects a
key, and how the app mixes the stream that key is keyed from. the mixing is data
too, an expression per step, so a new app is a new config and not a new program.
android auto is `configs/com.google.android.projection.gearhead.toml`.

## use

    python3 dexter.py com.google.android.projection.gearhead

writes to `~/.cache/dexter/<config>`, or to `--out DIR`:

    ca.crt          the authority, as the config names it
    carservice.crt  every other certificate, named for its organization
    carservice.key  a private key, named for the certificate holding its public key

a config may be named by its bare name, found under `configs/`. `--apk` reads an
apk other than the one the config names.

    python3 dexter.py my-app --apk base.apk --out certs/

nothing is written outside the output directory, and a key is written unreadable
to others.

## an apk no config describes yet

`--dump` says what a config could point at:

    python3 dexter.py some-app --apk base.apk --dump certs
    python3 dexter.py some-app --apk base.apk --dump arrays

the first lists the certificates it found, with their issuers and how they expire,
and the second the byte[] literals in its code, with the sizes the config's
filters would keep. `configs/template.toml` documents every setting, and is the
shape the tool assumes when a config says nothing.

## writing a config for a new app

1. point `[apk] path` at it and run `--dump certs`. set `[certs.root]` until
   exactly one certificate matches, and `[certs] stem` until the names please.
2. if a key is in the clear, `[keys] plaintext = true` finds it.
3. if it is not, look for it with `[derive]`: `--dump arrays` for the literals,
   the state size and the mixing in the app's own code, which is a loop over a
   byte array. write those as steps, and check the constants against
   `configs/com.google.android.projection.gearhead.toml`, which is one worked
   out end to end.
4. run it. a wrong constant costs a run and finds nothing, which is the only
   feedback there is: the app does not tell you it failed.

## needs

python 3.12 or newer, and the `openssl` command. no packages, no build, no venv:

    make test-e2e

`make` byte compiles and checks the config loader starts. `make precommit` adds
the linter.

## limits

it reads the code of an apk. a key hidden in a native library, in a resource, or
built one character at a time is out of reach, since a config reaches material
through a regular expression over a dex file and through the header a dex puts in
front of a byte[] literal.

a derivation is a byte mixer over a fixed state, because that is what the apps
here do. an app that keys its blob some other way, with a hash chain for one,
needs a step the expression language cannot say, and that is a change to the
program.
