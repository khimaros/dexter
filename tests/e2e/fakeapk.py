#!/usr/bin/env python3
"""a synthetic apk: an app of our own making, whose code carries certificates
and a private key the way a real one does, so the tool can be tested against an
app no config was written for. the certificates come from the openssl command
and the code is a zip entry whose bytes hold what a dex string pool and its
byte[] literals hold: pems with their line breaks escaped, and fill-array-data
payloads."""

import pathlib
import struct
import subprocess
import zipfile

# a dex fill-array-data payload of single bytes: the ident, an element width of
# one and the size as a uint32, then the bytes
FILL_ARRAY = b"\x00\x03\x01\x00"
# how a cipher pads to its block size, in the form the openssl command reads it
BLOCK = 16


def padded(data):
    """a plaintext padded to a whole cipher block, which is what an app encrypts"""
    return data + bytes([BLOCK - len(data) % BLOCK]) * (BLOCK - len(data) % BLOCK)


def authority_and_leaf(directory):
    """a root certificate and a leaf under it, as three files, so that the
    openssl calls that connect them can read them back"""
    directory = pathlib.Path(directory)
    subject = "/C=US/O=%s/CN=%s"
    key = ("genpkey", "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:prime256v1")
    run(directory, *key, "-out", "root.key")
    run(directory, "req", "-x509", "-new", "-key", "root.key", "-nodes", "-days", "3650",
        "-subj", subject % ("Synthetic Authority", "Synthetic Root"), "-out", "root.crt")
    run(directory, *key, "-out", "leaf.key")
    run(directory, "req", "-new", "-key", "leaf.key", "-nodes",
        "-subj", subject % ("Synthetic Phone", "Synthetic Leaf"), "-out", "leaf.csr")
    run(directory, "x509", "-req", "-in", "leaf.csr", "-CA", "root.crt", "-CAkey", "root.key",
        "-days", "3650", "-set_serial", "7", "-out", "leaf.crt")
    return (read(directory / "root.crt"), read(directory / "leaf.crt"),
            read(directory / "leaf.key"))


def run(directory, *args):
    result = subprocess.run(["openssl", *args], cwd=directory, capture_output=True, text=True)
    if result.returncode != 0:
        raise RuntimeError(f"openssl {' '.join(args)} failed: {result.stderr}")


def read(path):
    return pathlib.Path(path).read_text()


def pool(pem):
    """a pem as a dex string pool keeps it, with its line breaks escaped"""
    return pem.replace("\n", "\\n").encode()


def literal(data):
    """a byte[] literal of a dex"""
    return FILL_ARRAY + struct.pack("<I", len(data)) + bytes(data)


def apk(path, pems, literals):
    """write the apk: one dex holding the pems and the byte[] literals, with
    padding between them, as a real one holds a great deal of other code"""
    code = b"\0" * 13 + b"".join(pool(pem) + b"\0" for pem in pems)
    code += b"\0" * 7 + b"".join(literal(each) for each in literals)
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("classes.dex", code)
        archive.writestr("AndroidManifest.xml", "<binary manifest/>")
    return pathlib.Path(path)
