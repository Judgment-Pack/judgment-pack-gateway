"""Sealed session registry — the external anchor the gateway holds that closes
the two residuals the inline attestation verify cannot catch on its own:

  - whole-session replay: a genuine past session (or a genuine prefix of one)
    copied verbatim into a fresh store is internally consistent and passes
    `attest.verify_store`; and
  - final-tail rollback: deleting the last k receipts of a session leaves a
    shorter, still-chained prefix that also passes.

Both need an anchor *outside* the store on which sessions exist and how many
receipts each holds. The gateway owns that anchor: as it attests, it seals each
session's final count under its protected key. A verifier obtains the seals from
the gateway (not from the untrusted store) and checks the store against them, so
a replayed or truncated store is caught because its sessions are unsealed or its
counts disagree — and an attacker cannot forge a seal without the key.

Standard library only.
"""

import json
import os

from attest import canon, require_key
import hashlib
import hmac


def _seal_hmac(key, session_id, final_count, sealed_at):
    body = canon({"sessionId": session_id, "finalCount": final_count, "sealedAt": sealed_at})
    return hmac.new(key, b"seal:" + body, hashlib.sha256).hexdigest()


class Registry:
    """The gateway's append-only seal log. One sealed record per closed session:
    the session id, the final receipt count, when it was sealed, and an HMAC over
    those under the gateway's key."""

    def __init__(self, path, key):
        self.path = path
        self.key = require_key(key)
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)

    def seal(self, session_id, final_count, sealed_at):
        """Seal a closed session's final receipt count. Append-only: sealing a
        session that is already sealed is refused, so a session's count cannot be
        re-sealed to a smaller value."""
        for record in self._read():
            if record.get("sessionId") == session_id:
                raise ValueError("session already sealed: %s" % session_id)
        record = {
            "sessionId": session_id,
            "finalCount": final_count,
            "sealedAt": sealed_at,
            "hmac": _seal_hmac(self.key, session_id, final_count, sealed_at),
        }
        with open(self.path, "ab") as handle:
            handle.write(canon(record) + b"\n")
            handle.flush()
            os.fsync(handle.fileno())
        return record

    def _read(self):
        if not os.path.exists(self.path):
            return []
        records = []
        with open(self.path, "rb") as handle:
            for line in handle:
                line = line.strip()
                if line:
                    try:
                        records.append(json.loads(line.decode("utf-8")))
                    except ValueError:
                        records.append({"_malformed": True})
        return records


def load_seals(path, key):
    """Return {sessionId: finalCount} for every seal whose HMAC verifies. A seal
    with a bad or forged HMAC is dropped (it did not come from the key holder),
    so a store cannot be excused by a forged registry."""
    require_key(key)
    seals = {}
    if not os.path.exists(path):
        return seals
    with open(path, "rb") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            try:
                record = json.loads(line.decode("utf-8"))
                expected = _seal_hmac(key, record["sessionId"], record["finalCount"], record["sealedAt"])
                if hmac.compare_digest(expected, record.get("hmac", "")):
                    seals[record["sessionId"]] = record["finalCount"]
            except (ValueError, KeyError, TypeError):
                continue
    return seals


def _session_count(store_root, session_id):
    session_dir = os.path.join(store_root, "receipts", session_id)
    if not os.path.isdir(session_dir):
        return 0
    return len([n for n in os.listdir(session_dir) if n.endswith(".json")])


def verify_with_registry(verify_store, store_root, key, registry_path, expected_authority=None):
    """Full gateway verification: the inline per-receipt verification, plus the
    registry anchor. Returns (ok, findings). Findings add:
      - unregistered-session : a session in the store the registry did not seal
        (whole-session replay, or a session forged without the key)
      - tail-rollback        : fewer receipts in the store than the seal records
      - count-exceeds-seal   : more receipts than the seal records
      - sealed-session-missing : a sealed session absent from the store
    """
    ok, findings = verify_store(store_root, key, expected_authority)
    seals = load_seals(registry_path, key)
    receipts_root = os.path.join(store_root, "receipts")
    store_sessions = set()
    if os.path.isdir(receipts_root):
        store_sessions = {n for n in os.listdir(receipts_root)
                          if os.path.isdir(os.path.join(receipts_root, n))}
    for session_id in sorted(store_sessions):
        if session_id not in seals:
            ok = False
            findings.append({"sessionId": session_id, "status": "unregistered-session"})
            continue
        have = _session_count(store_root, session_id)
        want = seals[session_id]
        if have < want:
            ok = False
            findings.append({"sessionId": session_id, "status": "tail-rollback",
                             "have": have, "sealed": want})
        elif have > want:
            ok = False
            findings.append({"sessionId": session_id, "status": "count-exceeds-seal",
                             "have": have, "sealed": want})
    for session_id in sorted(set(seals) - store_sessions):
        ok = False
        findings.append({"sessionId": session_id, "status": "sealed-session-missing"})
    return ok, findings
