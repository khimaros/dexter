# requirements

DRAFT: transcribed from the product owner's request on 2026-10-04.
awaiting review; edit freely.

## product

R1. extract the certificates an apk carries, and the private keys its code
    keeps encrypted, for any apk: android auto is one configuration, not the
    program.

R2. everything that differs between apks, certificate authorities and keys
    lives in an external config: where in the apk the material is, which
    certificate is the authority, how files are named, which cipher protects a
    key, and how the app derives its key stream.

R3. the key stream derivation is data, not code: different algorithms, and
    different constants and operators within them, are expressed in the config
    alone.

R4. a config for a known app reproduces what the hand written extraction in
    `../behead/tools/extract-certs.py` produces, and is checked against it.

## operations

R5. needs only python and the `openssl` command: no build step, no venv, no
    third party packages.

R6. extracting from an apk never writes outside the output directory, and the
    private keys it recovers are written unreadable to others.

## testing

R7. the whole tool is testable end-to-end, with no apk download needed, by
    building a synthetic apk whose mixer is described only by a config.
