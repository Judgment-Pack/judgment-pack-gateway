"""Hand-written crypto has to answer to someone else's arithmetic.

These tests never check ed25519.py against itself. They check it against RFC
8032's published vector, and against vectors frozen from the `cryptography`
package -- an independent, vetted implementation. `cryptography` is not installed
in CI and is not a dependency of this repo; the frozen vectors are how its verdict
travels to a machine that does not have it.
"""

import binascii
import json
import os
import unittest

import ed25519

HERE = os.path.dirname(os.path.abspath(__file__))
unhex = binascii.unhexlify
tohex = lambda data: binascii.hexlify(data).decode("ascii")

# RFC 8032 section 7.1, TEST 1. Quoted from the standard.
RFC_SEED = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"
RFC_PUBLIC = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
RFC_SIGNATURE = ("e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e0652249015"
                 "55fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b")


class RFC8032Vector(unittest.TestCase):
    def test_public_key(self):
        self.assertEqual(tohex(ed25519.public_key(unhex(RFC_SEED))), RFC_PUBLIC)

    def test_signature_over_the_empty_message(self):
        self.assertEqual(tohex(ed25519.sign(unhex(RFC_SEED), b"")), RFC_SIGNATURE)

    def test_verifies(self):
        self.assertTrue(ed25519.verify(unhex(RFC_PUBLIC), b"", unhex(RFC_SIGNATURE)))


class IndependentlyDerivedVectors(unittest.TestCase):
    """corpus/ed25519-vectors.json was produced by `cryptography`, not by this file."""

    def setUp(self):
        with open(os.path.join(HERE, "corpus", "ed25519-vectors.json")) as handle:
            self.vectors = json.load(handle)["vectors"]

    def test_there_are_vectors(self):
        self.assertGreaterEqual(len(self.vectors), 5)

    def test_public_keys_match(self):
        for vector in self.vectors:
            self.assertEqual(tohex(ed25519.public_key(unhex(vector["seed"]))),
                             vector["publicKey"], vector["message"][:24])

    def test_signatures_match_byte_for_byte(self):
        # Ed25519 is deterministic, so agreement is exact rather than "also valid".
        for vector in self.vectors:
            self.assertEqual(tohex(ed25519.sign(unhex(vector["seed"]), unhex(vector["message"]))),
                             vector["signature"], vector["message"][:24])

    def test_verifies_the_other_implementation(self):
        for vector in self.vectors:
            self.assertTrue(ed25519.verify(unhex(vector["publicKey"]),
                                           unhex(vector["message"]),
                                           unhex(vector["signature"])))


class Rejects(unittest.TestCase):
    def setUp(self):
        self.seed = bytes(range(32))
        self.public = ed25519.public_key(self.seed)
        self.message = b"a receipt core"
        self.signature = ed25519.sign(self.seed, self.message)

    def test_accepts_the_genuine_signature(self):
        self.assertTrue(ed25519.verify(self.public, self.message, self.signature))

    def test_rejects_a_modified_message(self):
        self.assertFalse(ed25519.verify(self.public, b"a receipt c0re", self.signature))

    def test_rejects_a_flipped_signature_bit(self):
        for index in (0, 31, 32, 63):
            broken = bytearray(self.signature)
            broken[index] ^= 1
            self.assertFalse(ed25519.verify(self.public, self.message, bytes(broken)))

    def test_rejects_another_keys_signature(self):
        other = ed25519.public_key(bytes(range(1, 33)))
        self.assertFalse(ed25519.verify(other, self.message, self.signature))

    def test_rejects_non_canonical_scalar(self):
        # S >= L must be refused, or signatures become malleable.
        malleable = self.signature[:32] + int.to_bytes(ed25519.L + 1, 32, "little")
        self.assertFalse(ed25519.verify(self.public, self.message, malleable))

    def test_raises_on_malformed_inputs(self):
        with self.assertRaises(ed25519.SignatureError):
            ed25519.verify(self.public[:31], self.message, self.signature)
        with self.assertRaises(ed25519.SignatureError):
            ed25519.verify(self.public, self.message, self.signature[:63])
        with self.assertRaises(ed25519.SignatureError):
            ed25519.sign(b"too short", self.message)


class CrossCheckAgainstCryptography(unittest.TestCase):
    """Runs only where `cryptography` happens to be installed. CI relies on the
    frozen vectors instead; this is the check that produced them."""

    def setUp(self):
        try:
            from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        except ImportError:
            self.skipTest("cryptography is not installed (expected in CI)")
        self.private = Ed25519PrivateKey

    def test_agrees_on_random_seeds_and_messages(self):
        from cryptography.hazmat.primitives import serialization
        for index in range(8):
            seed, message = os.urandom(32), os.urandom(index * 11)
            key = self.private.from_private_bytes(seed)
            their_public = key.public_key().public_bytes(
                serialization.Encoding.Raw, serialization.PublicFormat.Raw)
            self.assertEqual(ed25519.public_key(seed), their_public)
            self.assertEqual(ed25519.sign(seed, message), key.sign(message))
            self.assertTrue(ed25519.verify(their_public, message, key.sign(message)))


if __name__ == "__main__":
    unittest.main()
