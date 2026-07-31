"""The corpus must have teeth.

It is easy to ship a conformance suite that every implementation passes, which
proves nothing. These tests check the other direction: implementations that are
wrong in the specific, realistic ways a second implementation goes wrong must be
CAUGHT by the corpus. Each divergence below is one a competent author would
plausibly ship, because it is the default behaviour of a standard library.
"""

import binascii
import json
import os
import shutil
import tempfile
import unittest

import attest
import conformance
import registry


class ReferenceAgreesWithCorpus(unittest.TestCase):
    def test_reference_passes_every_vector(self):
        failures, (canon_count, store_count) = conformance.run(conformance.Reference())
        self.assertEqual(failures, [], "reference disagrees with its own corpus")
        self.assertGreaterEqual(canon_count, 20)
        self.assertGreaterEqual(store_count, 12)


class PublicVerificationIsGenuine(unittest.TestCase):
    """Receipt version 2 exists so that checking does not require the power to
    forge. These tests assert that property directly rather than trusting it."""

    def test_the_corpus_ships_no_secret_to_its_verifier(self):
        # conformance.py reads the PUBLIC key file. The seed is published only so
        # the vectors can be regenerated, and nothing in the verify path reads it.
        source = open(os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                   "conformance.py")).read()
        self.assertIn("TEST-PUBLIC-KEY", source)
        self.assertNotIn("TEST-SEED", source)

    def test_verification_uses_only_the_public_key(self):
        public = binascii.unhexlify(
            open(os.path.join(conformance.CORPUS, "TEST-PUBLIC-KEY")).read().strip())
        self.assertEqual(len(public), 32)
        case = json.load(open(os.path.join(conformance.CORPUS, "stores", "valid-sealed.json")))
        root, store_root, registry_path = conformance._materialize(case)
        try:
            ok, findings = registry.verify_with_registry(
                attest.verify_store, store_root, public, registry_path, case["authority"])
        finally:
            shutil.rmtree(root, ignore_errors=True)
        self.assertTrue(ok, findings)

    def test_holding_the_public_key_grants_no_power_to_sign(self):
        # An Ed25519 seed and a public key are BOTH 32 bytes, so no length check
        # can tell them apart -- misusing one as the other is not refused, it is
        # simply a different identity. The property that matters is the
        # consequence: receipts produced that way do not verify under the real
        # public key, because they carry a different key id.
        public = binascii.unhexlify(
            open(os.path.join(conformance.CORPUS, "TEST-PUBLIC-KEY")).read().strip())
        root = tempfile.mkdtemp()
        try:
            misused = attest.Store(os.path.join(root, "store"), public, "gateway:corpus")
            self.assertNotEqual(misused.key_id, attest.key_id(public),
                                "using a public key as a seed must not reproduce its identity")
            payload = attest.canon({"n": 1})
            misused.stamp({"receiptVersion": attest.RECEIPT_VERSION, "sessionId": "s1",
                           "callIndex": 0, "prevSignature": None, "source": "s",
                           "argumentsDigest": "x", "resultDigest": misused.retain(payload),
                           "servedAt": "t", "authority": "gateway:corpus"})
            ok, findings = attest.verify_store(os.path.join(root, "store"), public,
                                               "gateway:corpus")
            self.assertFalse(ok)
            self.assertTrue(any(f["status"] == "key-mismatch" for f in findings), findings)
        finally:
            shutil.rmtree(root, ignore_errors=True)

    def test_a_forger_without_the_seed_cannot_pass_verification(self):
        public = binascii.unhexlify(
            open(os.path.join(conformance.CORPUS, "TEST-PUBLIC-KEY")).read().strip())
        attacker_seed = b"an-attacker-seed-of-32-bytes!!!!"
        self.assertEqual(len(attacker_seed), 32)
        root = tempfile.mkdtemp()
        try:
            # A complete, internally perfect store -- signed by the wrong key.
            store = attest.Store(os.path.join(root, "store"), attacker_seed, "gateway:corpus")
            reg = registry.Registry(os.path.join(root, "reg.jsonl"), attacker_seed)
            payload = attest.canon({"forged": True})
            store.stamp({"receiptVersion": attest.RECEIPT_VERSION, "sessionId": "s1",
                         "callIndex": 0, "prevSignature": None, "source": "s",
                         "argumentsDigest": "x", "resultDigest": store.retain(payload),
                         "servedAt": "t", "authority": "gateway:corpus"})
            reg.seal("s1", 1, "t")
            ok, findings = registry.verify_with_registry(
                attest.verify_store, os.path.join(root, "store"), public,
                os.path.join(root, "reg.jsonl"), "gateway:corpus")
            self.assertFalse(ok, "a forgery under a different key verified")
            self.assertTrue(any(f["status"] == "key-mismatch" for f in findings), findings)
        finally:
            shutil.rmtree(root, ignore_errors=True)


class _Divergent(conformance.Reference):
    """The reference with one realistic defect injected."""

    def __init__(self, canon_defect=None, drop_registry=False):
        self.canon_defect = canon_defect
        self.drop_registry = drop_registry

    def canon(self, source):
        if self.canon_defect is None:
            return super().canon(source)
        try:
            value = json.loads(source)
            attest.canon(value)          # keep the domain rules honest
        except attest.AttestationError:
            return None
        return self.canon_defect(value)

    def verify(self, store_root, registry_path, key, authority):
        if not self.drop_registry:
            return super().verify(store_root, registry_path, key, authority)
        # An implementation that verifies each receipt but forgets the registry
        # anchor -- exactly the gap the gateway exists to close.
        ok, findings = attest.verify_store(store_root, key, authority)
        return {"ok": ok, "findings": findings}


def _html_escaping(value):
    """Go's encoding/json escapes < > & by default."""
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
            .replace("<", "\\u003c").replace(">", "\\u003e").replace("&", "\\u0026")
            .encode("utf-8"))


def _ascii_escaping(value):
    """Python's json.dumps defaults to ensure_ascii=True."""
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _utf16_ordering(value):
    """Ordering member names by UTF-16 code unit -- what RFC 8785 says, and what
    the runtime's own internal/jcs does. It disagrees with code-point ordering on
    any non-BMP member name."""
    def order(node):
        if isinstance(node, dict):
            return {k: order(node[k])
                    for k in sorted(node, key=lambda s: s.encode("utf-16-be"))}
        if isinstance(node, list):
            return [order(item) for item in node]
        return node
    return json.dumps(order(value), sort_keys=False, separators=(",", ":"),
                      ensure_ascii=False).encode("utf-8")


class CorpusCatchesRealisticDivergence(unittest.TestCase):
    def _failures(self, **kwargs):
        failures, _counts = conformance.run(_Divergent(**kwargs))
        return failures

    def test_html_escaping_is_caught(self):
        failures = self._failures(canon_defect=_html_escaping)
        self.assertTrue(any("<a>&b</a>" in f for f in failures),
                        "corpus missed Go-style HTML escaping: %s" % failures)

    def test_ascii_escaping_is_caught(self):
        failures = self._failures(canon_defect=_ascii_escaping)
        self.assertTrue(any("caf" in f or "u00e9" in f for f in failures),
                        "corpus missed ensure_ascii escaping: %s" % failures)

    def test_utf16_member_ordering_is_caught(self):
        failures = self._failures(canon_defect=_utf16_ordering)
        self.assertTrue(failures, "corpus missed UTF-16 member ordering")
        self.assertTrue(any("CODE POINT" in f or "\\ud83d" in f or "\U0001f600" in f
                            for f in failures),
                        "caught something, but not the ordering vector: %s" % failures)

    def test_forgetting_the_registry_anchor_is_caught(self):
        failures = self._failures(drop_registry=True)
        joined = "\n".join(failures)
        for missed in ("tail-rollback", "unregistered-session", "count-exceeds-seal",
                       "sealed-session-missing"):
            self.assertIn(missed, joined,
                          "corpus did not catch a verifier ignoring the registry")


if __name__ == "__main__":
    unittest.main()
