"""The gateway demonstration: the sealed registry closes the two residuals the
inline attestation verify cannot catch on its own -- whole-session replay and
final-tail rollback -- and an HTTP acquire -> seal -> verify round trip works
end to end.
"""

import json
import os
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.request

import attest
import registry
import gateway

HERE = os.path.dirname(os.path.abspath(__file__))
KEY = b"gateway-reference-key-of-32-bytes"
AUTHORITY = "gateway:reference"


def _stamp_session(store, session_id, count):
    """Attest `count` chained receipts into one session, as the gateway would."""
    prev = None
    for index in range(count):
        digest = store.retain(attest.canon({"session": session_id, "n": index}))
        core = {
            "receiptVersion": "1", "sessionId": session_id, "callIndex": index, "prevHmac": prev,
            "source": "s", "argumentsDigest": store.keyed_digest("args", attest.canon({})),
            "resultDigest": digest, "servedAt": "2026-07-30T11:00:00Z", "authority": AUTHORITY,
        }
        prev = store.stamp(core)["hmac"]


class RegistryClosesResiduals(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.store_root = os.path.join(self.dir, "store")
        self.reg_path = os.path.join(self.dir, "registry.jsonl")
        self.store = attest.Store(self.store_root, KEY, AUTHORITY)
        self.reg = registry.Registry(self.reg_path, KEY)

    def tearDown(self):
        shutil.rmtree(self.dir, ignore_errors=True)

    def _verify(self):
        return registry.verify_with_registry(attest.verify_store, self.store_root, KEY, self.reg_path, AUTHORITY)

    def test_sealed_store_verifies(self):
        _stamp_session(self.store, "sess-a", 3)
        self.reg.seal("sess-a", 3, "2026-07-30T12:00:00Z")
        ok, findings = self._verify()
        self.assertTrue(ok, findings)

    def test_inline_verify_misses_what_the_registry_catches(self):
        # Build a genuine sealed session, then TRUNCATE its tail. The inline
        # verify (no registry) still passes -- the residual it cannot catch --
        # while the registry-anchored verify catches the rollback.
        _stamp_session(self.store, "sess-a", 3)
        self.reg.seal("sess-a", 3, "2026-07-30T12:00:00Z")
        os.remove(os.path.join(self.store_root, "receipts", "sess-a", "2.json"))
        inline_ok, _ = attest.verify_store(self.store_root, KEY, AUTHORITY)
        self.assertTrue(inline_ok, "inline verify cannot catch tail rollback")
        gateway_ok, findings = self._verify()
        self.assertFalse(gateway_ok)
        self.assertTrue(any(f["status"] == "tail-rollback" for f in findings))

    def test_whole_session_replay_is_unregistered(self):
        # A genuine session copied into a store the current registry never sealed
        # is caught: the session is unregistered. (The inline verify passes it.)
        _stamp_session(self.store, "replayed", 2)  # no seal for it
        inline_ok, _ = attest.verify_store(self.store_root, KEY, AUTHORITY)
        self.assertTrue(inline_ok, "inline verify passes a replayed session")
        ok, findings = self._verify()
        self.assertFalse(ok)
        self.assertTrue(any(f["status"] == "unregistered-session" for f in findings))

    def test_forged_seal_without_the_key_does_not_excuse_a_session(self):
        # An attacker appends a seal for the replayed session, but cannot HMAC it
        # without the key; load_seals drops it, so the session stays unregistered.
        _stamp_session(self.store, "replayed", 2)
        with open(self.reg_path, "ab") as handle:
            handle.write(json.dumps({"sessionId": "replayed", "finalCount": 2,
                                     "sealedAt": "x", "hmac": "0" * 64}).encode() + b"\n")
        ok, findings = self._verify()
        self.assertFalse(ok)
        self.assertTrue(any(f["status"] == "unregistered-session" for f in findings))

    def test_whole_session_deletion_is_caught(self):
        _stamp_session(self.store, "sess-a", 2)
        _stamp_session(self.store, "sess-b", 2)
        self.reg.seal("sess-a", 2, "t")
        self.reg.seal("sess-b", 2, "t")
        shutil.rmtree(os.path.join(self.store_root, "receipts", "sess-b"))
        ok, findings = self._verify()
        self.assertFalse(ok)
        self.assertTrue(any(f["status"] == "sealed-session-missing" for f in findings))

    def test_reseal_to_smaller_count_refused(self):
        self.reg.seal("sess-a", 3, "t")
        with self.assertRaises(ValueError):
            self.reg.seal("sess-a", 1, "t")  # append-only: no shrinking a seal


class SessionIdIsNotAPath(unittest.TestCase):
    """A session id names a directory under the store, and `verify` discovers
    sessions by enumerating that directory. A caller-supplied value that escaped it
    produced genuinely attested receipts that verify could never see -- so `verify`
    reported ok on a store missing sessions the gateway had signed."""

    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.store_root = os.path.join(self.dir, "store")
        self.store = attest.Store(self.store_root, KEY, AUTHORITY)

    def tearDown(self):
        shutil.rmtree(self.dir, ignore_errors=True)

    def _core(self, session_id):
        return {"receiptVersion": "1", "sessionId": session_id, "callIndex": 0,
                "prevHmac": None, "source": "s", "argumentsDigest": "x", "resultDigest": "y",
                "servedAt": "t", "authority": AUTHORITY}

    def test_absolute_path_session_is_refused(self):
        escaped = os.path.join(self.dir, "ESCAPED")
        with self.assertRaises(attest.AttestationError):
            self.store.stamp(self._core(escaped))
        self.assertFalse(os.path.exists(escaped))

    def test_parent_traversal_session_is_refused(self):
        with self.assertRaises(attest.AttestationError):
            self.store.stamp(self._core("../../TRAVERSED"))
        self.assertFalse(os.path.exists(os.path.join(self.dir, "TRAVERSED")))

    def test_nested_and_dot_sessions_are_refused(self):
        for bad in ("a/b", ".", "..", "", "x" * 129, "sess id", "sess\x00"):
            with self.assertRaises(attest.AttestationError):
                self.store.stamp(self._core(bad))

    def test_ordinary_session_ids_still_work(self):
        # Fully-formed receipts, so this asserts the hardening rejects nothing
        # legitimate rather than merely that stamping did not raise.
        for good in ("s1", "sess-a", "run_2026.07.30", "A" * 128):
            _stamp_session(self.store, good, 2)
        ok, findings = attest.verify_store(self.store_root, KEY, AUTHORITY)
        self.assertTrue(ok, findings)

    def test_registry_refuses_to_seal_an_escaping_session(self):
        reg = registry.Registry(os.path.join(self.dir, "r.jsonl"), KEY)
        with self.assertRaises(attest.AttestationError):
            reg.seal("../../ESCAPED", 1, "t")


# A trivial source: echoes back a fixed screening record, ignoring stdin.
SOURCE = r"""
import sys, json
sys.stdin.read()
sys.stdout.write(json.dumps({"status": "not_found", "checkedSuccessfully": True}))
"""


class HttpRoundTrip(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.source = os.path.join(self.dir, "source.py")
        with open(self.source, "w") as handle:
            handle.write(SOURCE)
        self.gw = gateway.Gateway(
            os.path.join(self.dir, "store"), KEY, AUTHORITY,
            os.path.join(self.dir, "registry.jsonl"),
            {"screening": [sys.executable, self.source]})
        self.server = gateway.serve("127.0.0.1", 0, self.gw)
        self.port = self.server.server_address[1]
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        time.sleep(0.05)

    def tearDown(self):
        self.server.shutdown()
        shutil.rmtree(self.dir, ignore_errors=True)

    def _post(self, path, body):
        req = urllib.request.Request("http://127.0.0.1:%d%s" % (self.port, path),
                                     data=json.dumps(body).encode(), method="POST")
        with urllib.request.urlopen(req, timeout=10) as resp:
            return json.loads(resp.read())

    def _get(self, path):
        with urllib.request.urlopen("http://127.0.0.1:%d%s" % (self.port, path), timeout=10) as resp:
            return json.loads(resp.read())

    def test_acquire_seal_verify(self):
        a0 = self._post("/acquire", {"session": "http-1", "source": "screening", "arguments": {"q": "acme"}})
        self.assertEqual(a0["result"]["status"], "not_found")
        self.assertEqual(a0["receipt"]["callIndex"], 0)
        self._post("/acquire", {"session": "http-1", "source": "screening", "arguments": {"q": "acme2"}})
        self._post("/seal", {"session": "http-1"})
        verified = self._get("/verify")
        self.assertTrue(verified["ok"], verified["findings"])
        # The gateway produced the receipts; nothing the client sent is trusted
        # as proof -- there is no facts/receipt field in the acquire request.
        self.assertNotIn("acme", json.dumps(a0["receipt"]))

    def test_escaping_session_is_rejected_over_http_and_writes_nothing(self):
        outside = os.path.join(self.dir, "ESCAPED")
        for bad in (outside, "../../TRAVERSED", "a/b"):
            req = urllib.request.Request(
                "http://127.0.0.1:%d/acquire" % self.port,
                data=json.dumps({"session": bad, "source": "screening",
                                 "arguments": {"q": "x"}}).encode(), method="POST")
            with self.assertRaises(urllib.error.HTTPError) as caught:
                urllib.request.urlopen(req, timeout=10)
            self.assertEqual(caught.exception.code, 400)  # a refusal, not a crash
        self.assertFalse(os.path.exists(outside))
        self.assertFalse(os.path.exists(os.path.join(self.dir, "TRAVERSED")))
        # And the store still verifies as empty rather than silently "ok" while
        # holding signed receipts somewhere else.
        self.assertEqual(os.listdir(os.path.join(self.dir, "store", "receipts")), [])


if __name__ == "__main__":
    unittest.main()
