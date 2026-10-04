#!/usr/bin/env python3
"""end to end tests for dexter.py: the tool as a command, a synthetic apk as the
app it reads, and the android auto apk when it is cached.

the synthetic app's mixer is written out below and not imported, so that the
config under test is checked against a second, independent reading of what a
mixer is, the way ../behead's scripted headunit is written independently of the
protocol code it drives."""

import hashlib
import pathlib
import subprocess
import sys
import tempfile
import tomllib
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(pathlib.Path(__file__).parent))

import fakeapk

import dexter

DEXTER = ROOT / "dexter.py"
ANDROID_AUTO_APK = (pathlib.Path.home() / ".cache/behead/apk"
                    / "com.google.android.projection.gearhead")
ANDROID_AUTO_CONFIG = "com.google.android.projection.gearhead"
# what the android auto extraction yielded on 2026-10-04, from version code
# 176663454, recorded from the hand written extraction this tool replaces
ANDROID_AUTO_VERSION = "176663454"
ANDROID_AUTO_FILES = {
    "ca.crt": "69550db8421dcd8c71d100fa4deabf8cc9effc0633f2b51e0101e8593a4a0cb5",
    "carservice.crt": "cb82ec3150c956165eb2e2b6cf561afeb21c69772d889c6dc77a9e1b75f0b9de",
    "carservice.key": "9ab815153e9de092650a153fc23f0ee758b3cf93367bfa177def0af15d3443c3",
}

# the mixer the synthetic app is built with, and the array it mixes from
STATE_BYTES, KEY_BYTES, ROTATE, ADD = 32, 16, 3, 17
SOURCE = bytes(range(1, STATE_BYTES + 1))
DECOY = bytes([0xa5]) * STATE_BYTES

CONFIG = """\
[apk]
path = "{apk}"

[certs]
stem = "O"

[certs.root]
file = "ca.crt"
self_signed = true
subject = "Synthetic Authority"
{fingerprint}
[derive]
state = {state}
vary = "cert_pair"
key_slice = [0, {key}]
iv_slice = [{key}, {state}]
decrypt = ["openssl", "enc", "-aes-128-cbc", "-d", "-K", "{{key}}", "-iv", "{{iv}}"]

[derive.source]
minimum = {state}
maximum = {state}

[derive.blob]
minimum = 16
multiple = 16

[[derive.steps]]
input = "certs"
update = "add(rotl(v, {rotate}), {add}) ^ S(j) ^ D(i)"

[output]
dir = "{out}"
"""

PLAINTEXT = """\
[apk]
path = "{apk}"

[certs]
stem = "CN"

[keys]
plaintext = {plaintext}
"""

# a derivation, as a string, for a wrong one to be refused by name
BROKEN = """\
[apk]
path = "/none.apk"

[derive]
state = 32
key_slice = [0, 16]
iv_slice = [16, 32]
decrypt = {decrypt}

[[derive.steps]]
input = "certs"
update = "{update}"
"""
CIPHER = '["openssl", "enc", "-aes-128-cbc", "-d", "-K", "{key}", "-iv", "{iv}"]'


def run(*args):
    return subprocess.run([sys.executable, DEXTER, *args], capture_output=True, text=True)


def mix(data, state, source):
    """one pass of the synthetic app's mixer, which rotates a byte left, adds a
    constant, and folds in the source byte at the state's own index and the
    input byte. the state is rewritten as it is read"""
    for i in range(len(data)):
        for j in range(STATE_BYTES):
            v = state[j]
            state[j] = ((((v >> (8 - ROTATE)) | (v << ROTATE)) + ADD)
                        ^ source[j % len(source)] ^ data[i]) & 0xFF


def stream(certs):
    """the stream the synthetic app keys its blob with: its mixer over each of
    its certificates, in the order it happened to use them"""
    state = [0] * STATE_BYTES
    for pem in certs:
        mix(pem.encode(), state, SOURCE)
    return state


def encrypt(data, state):
    key, iv = bytes(state[:KEY_BYTES]).hex(), bytes(state[KEY_BYTES:]).hex()
    done = subprocess.run(["openssl", "enc", "-aes-128-cbc", "-K", key, "-iv", iv],
                          input=data, capture_output=True)
    assert done.returncode == 0, done.stderr
    return done.stdout


def openssl(*args, pem=""):
    done = subprocess.run(["openssl", *args], input=pem, capture_output=True, text=True)
    return done.stdout


class Synthetic(unittest.TestCase):
    """a whole app, described only by a config: its mixer, its authority, the
    cipher protecting its key and the size of that key"""

    @classmethod
    def setUpClass(cls):
        cls.home = tempfile.TemporaryDirectory()
        directory = pathlib.Path(cls.home.name)
        cls.root_pem, cls.leaf_pem, cls.leaf_key = fakeapk.authority_and_leaf(directory)
        # the app mixes from its certificates in one order, and the tool has to
        # find it: reverse the order the tool sorts them into
        ordered = sorted([cls.root_pem, cls.leaf_pem])[::-1]
        blob = encrypt(fakeapk.padded(cls.leaf_key.encode()), stream(ordered))
        cls.apk = fakeapk.apk(directory / "synthetic.apk", [cls.root_pem, cls.leaf_pem],
                              [DECOY, SOURCE, blob])
        cls.out = directory / "certs"
        cls.config = directory / "synthetic.toml"
        cls.config.write_text(cls.text())
        cls.done = run(str(cls.config), "--out", cls.out)

    @classmethod
    def tearDownClass(cls):
        cls.home.cleanup()

    @classmethod
    def text(cls, fingerprint="", **changes):
        """a config for the synthetic app, with a setting of it changed"""
        fields = {"state": STATE_BYTES, "key": KEY_BYTES, "rotate": ROTATE, "add": ADD,
                  "apk": cls.apk, "out": cls.out, "fingerprint": fingerprint}
        fields.update(changes)
        return CONFIG.format(**fields)

    def run_elsewhere(self, **changes):
        """a run that must not disturb the one this class shares, in a directory
        of its own that goes away with the test"""
        home = pathlib.Path(self.enterContext(tempfile.TemporaryDirectory()))
        config = home / "other.toml"
        config.write_text(self.text(**changes))
        return run(str(config), "--out", home / "out"), home / "out"

    def test_writes_the_authority_and_its_leaf(self):
        self.assertEqual((self.out / "ca.crt").read_text(), self.root_pem)
        self.assertEqual((self.out / "synthetic-phone.crt").read_text(), self.leaf_pem)
        self.assertIn("signed by the authority", self.done.stdout)
        self.assertNotIn("warning", self.done.stdout + self.done.stderr)

    def test_recovers_the_key_under_its_certificates_name(self):
        path = self.out / "synthetic-phone.key"
        self.assertEqual(path.read_text(), self.leaf_key)
        self.assertEqual(path.stat().st_mode & 0o777, 0o600)

    def test_a_different_constant_finds_nothing(self):
        done, out = self.run_elsewhere(add=ADD + 1)
        self.assertIn("no private key", done.stdout)
        self.assertFalse(list(out.glob("*.key")))

    def test_an_unexpected_fingerprint_is_a_warning(self):
        done, _ = self.run_elsewhere(fingerprint='fingerprint = "' + "00:" * 31 + "00\"")
        self.assertIn("differs from the one this config expects", done.stdout)

    def test_the_output_the_config_names(self):
        """--out is a convenience over the config's own [output] dir"""
        done = run(str(self.config))
        self.assertEqual((self.out / "synthetic-phone.key").read_text(), self.leaf_key)
        self.assertIn(str(self.out), done.stdout)

    def test_dump_describes_an_undocumented_apk(self):
        done = run(str(self.config), "--dump", "certs")
        self.assertIn("2 certificates", done.stdout)
        self.assertIn("O=Synthetic Phone", done.stdout)
        self.assertIn("self-signed", done.stdout)
        done = run(str(self.config), "--dump", "arrays")
        self.assertIn("source filters keep 2", done.stdout)
        self.assertIn("blob filters keep 3", done.stdout)


class PlaintextKey(unittest.TestCase):
    """an app that keeps its key in the clear, with no derivation to replay"""

    @classmethod
    def setUpClass(cls):
        cls.home = tempfile.TemporaryDirectory()
        directory = pathlib.Path(cls.home.name)
        cls.root_pem, cls.leaf_pem, cls.leaf_key = fakeapk.authority_and_leaf(directory)
        cls.apk = fakeapk.apk(directory / "clear.apk", [cls.root_pem, cls.leaf_pem, cls.leaf_key],
                              [DECOY])
        cls.config = directory / "clear.toml"
        cls.out = directory / "out"

    @classmethod
    def tearDownClass(cls):
        cls.home.cleanup()

    def run_with(self, plaintext):
        self.config.write_text(PLAINTEXT.format(apk=self.apk, plaintext=str(plaintext).lower()))
        return run(str(self.config), "--out", self.out)

    def test_a_key_in_the_clear_needs_no_derivation(self):
        done = self.run_with(True)
        self.assertIn("synthetic-leaf.key", done.stdout)
        self.assertEqual((self.out / "synthetic-leaf.key").read_text(), self.leaf_key)

    def test_an_app_whose_key_is_left_alone_is_left_alone(self):
        done = self.run_with(False)
        self.assertIn("no private key", done.stdout)


class ConfigErrors(unittest.TestCase):
    """a config is data, so a wrong one has to be refused by name"""

    @classmethod
    def setUpClass(cls):
        cls.home = tempfile.TemporaryDirectory()
        cls.config = pathlib.Path(cls.home.name) / "broken.toml"

    @classmethod
    def tearDownClass(cls):
        cls.home.cleanup()

    def reject(self, text, message):
        self.config.write_text(text)
        done = run(str(self.config))
        self.assertNotEqual(done.returncode, 0, done.stdout)
        self.assertIn(message, done.stderr)

    def reject_update(self, update, message):
        self.reject(BROKEN.format(update=update, decrypt=CIPHER), message)

    def test_an_unknown_scalar(self):
        self.reject_update("xor(v, q)", "no scalar")

    def test_an_unknown_operator(self):
        self.reject_update("rol(v, 1)", "no operator rol")

    def test_the_wrong_number_of_arguments(self):
        self.reject_update("rotl(v)", "rotl() takes 2 argument")

    def test_a_stream_written_as_a_scalar(self):
        self.reject_update("add(v, S)", "byte stream")

    def test_what_is_not_an_expression(self):
        self.reject_update("__import__('os')", "cannot use")

    def test_a_pattern_that_is_not_one(self):
        self.reject('[certs]\nstem = "("\n', "stem is not a regular expression")

    def test_a_missing_cipher(self):
        self.reject(BROKEN.format(update="v", decrypt="[]"), "derive.decrypt")

    def test_a_slice_past_the_state(self):
        self.reject(BROKEN.format(update="v", decrypt=CIPHER).replace("state = 32", "state = 8"),
                    "runs past derive.state")


class Template(unittest.TestCase):
    """configs/template.toml is the documentation of the defaults, so it may
    not drift from them"""

    def test_the_template_says_what_the_tool_assumes(self):
        template = tomllib.loads((ROOT / "configs" / "template.toml").read_text())
        self.assertEqual(dexter.overlay(dexter.DEFAULTS, template), template)


class AndroidAuto(unittest.TestCase):
    """the config for the app the tool was written for, against the apk itself.
    it is a download, so it is skipped rather than fetched"""

    @classmethod
    def setUpClass(cls):
        versions = sorted(ANDROID_AUTO_APK.glob("*/base.apk"))
        if not versions:
            raise unittest.SkipTest(f"no android auto apk under {ANDROID_AUTO_APK}")
        cls.version = versions[-1].parent.name
        cls.home = tempfile.TemporaryDirectory()
        cls.out = pathlib.Path(cls.home.name)
        cls.done = run(ANDROID_AUTO_CONFIG, "--out", cls.out)

    @classmethod
    def tearDownClass(cls):
        cls.home.cleanup()

    def test_finds_the_authority_the_phone_pair_and_the_key(self):
        self.assertEqual(self.done.returncode, 0, self.done.stderr)
        self.assertEqual(sorted(path.name for path in self.out.iterdir()),
                         ["ca.crt", "carservice.crt", "carservice.key"])
        self.assertNotIn("warning", self.done.stdout)

    def test_the_leaf_verifies_against_the_authority(self):
        self.assertIn("signed by the authority", self.done.stdout)
        done = subprocess.run(["openssl", "verify", "-no_check_time",
                               "-CAfile", self.out / "ca.crt", self.out / "carservice.crt"],
                              capture_output=True, text=True)
        self.assertEqual(done.returncode, 0, done.stdout + done.stderr)

    def test_writes_the_bytes_the_extraction_it_replaces_wrote(self):
        """for as long as the cached apk is the version they were recorded from"""
        if self.version != ANDROID_AUTO_VERSION:
            raise unittest.SkipTest(f"recorded from version code {ANDROID_AUTO_VERSION}, "
                                    f"not {self.version}")
        written = {path.name: hashlib.sha256(path.read_bytes()).hexdigest()
                   for path in self.out.iterdir()}
        self.assertEqual(written, ANDROID_AUTO_FILES)

    def test_the_key_belongs_to_the_certificate_it_was_named_for(self):
        certificate = (self.out / "carservice.crt").read_text()
        public = openssl("x509", "-noout", "-pubkey", pem=certificate)
        from_key = openssl("pkey", "-pubout", pem=(self.out / "carservice.key").read_text())
        self.assertEqual(public, from_key)


if __name__ == "__main__":
    unittest.main()
