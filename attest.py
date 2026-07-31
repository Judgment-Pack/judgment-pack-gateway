"""Attestation primitives — a hosted implementation of the acquisition-proxy
attestation format (judgment-pack-evaluator-experiments/acquisition-proxy/SPEC.md).

The gateway is the *hosted* deployment shape of the trustworthy-input-acquisition
line's inline attestation core: same receipt format, same canonicalization, same
verification, so a receipt this gateway issues verifies the same way the inline
proxy's does. What the gateway adds over the inline shape is a protected signing
identity and the external anchor in `registry.py` (a sealed session registry)
that closes the two residuals the inline verify cannot catch on its own —
whole-session replay and final-tail rollback.

Standard library only.
"""

import binascii
import datetime
import hashlib
import hmac
import json
import os
import re

RECEIPT_VERSION = "1"
MIN_KEY_BYTES = 32
_SAFE_INT_MAX = (1 << 53) - 1
_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
# A session id becomes a directory name under the store. It is caller-supplied and
# the caller is outside the trust boundary, so it is constrained to a flat token:
# anything else could steer signed writes out of the store, where `verify` -- which
# enumerates the store -- would never see them.
_SESSION_RE = re.compile(r"^[A-Za-z0-9._-]{1,128}$")


class AttestationError(Exception):
    """A result cannot be attested, or a store does not verify."""


def _check_domain(value):
    if value is None or isinstance(value, bool):
        return
    if isinstance(value, int):
        if not (-_SAFE_INT_MAX <= value <= _SAFE_INT_MAX):
            raise AttestationError("integer outside the canon safe range")
        return
    if isinstance(value, float):
        raise AttestationError("non-integer number is outside the canon domain")
    if isinstance(value, str):
        try:
            value.encode("utf-8")
        except UnicodeEncodeError:
            raise AttestationError("string with a lone surrogate")
        return
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise AttestationError("non-string object member name")
            _check_domain(item)
        return
    if isinstance(value, list):
        for item in value:
            _check_domain(item)
        return
    raise AttestationError("value outside the canon domain")


def canon(value):
    """Canonical serialization: sorted keys, compact, raw UTF-8, integer-only
    number domain (acquisition-proxy SPEC 'canon')."""
    _check_domain(value)
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    ).encode("utf-8")


def digest(data):
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _hexdigest(digest_string):
    return digest_string.split(":", 1)[1]


def require_key(key):
    if len(key) < MIN_KEY_BYTES:
        raise AttestationError("attestation key must be at least %d bytes" % MIN_KEY_BYTES)
    return key


def require_session(session_id):
    """A session id must be a flat token. It names a directory under the store, and
    a verifier discovers sessions by enumerating that directory -- so a value that
    escapes it (an absolute path, a `..` segment, a nested path) would produce
    genuinely attested receipts that `verify` can never find, silently voiding the
    registry's coverage guarantee."""
    if not isinstance(session_id, str) or not _SESSION_RE.match(session_id):
        raise AttestationError(
            "session id must match %s" % _SESSION_RE.pattern)
    if session_id in (".", ".."):
        raise AttestationError("session id must not be a path segment")
    return session_id


def now():
    return (
        datetime.datetime.now(datetime.timezone.utc)
        .replace(microsecond=0).isoformat().replace("+00:00", "Z")
    )


class Store:
    """The append-only receipt and content-addressed artifact store, keyed and
    signed by the gateway's protected identity."""

    def __init__(self, root, key, authority):
        self.root = root
        self.key = require_key(key)
        self.authority = authority
        os.makedirs(os.path.join(root, "artifacts"), exist_ok=True)
        os.makedirs(os.path.join(root, "receipts"), exist_ok=True)

    def keyed_digest(self, domain, data):
        return "hmac-sha256:" + hmac.new(
            self.key, domain.encode("ascii") + b":" + data, hashlib.sha256
        ).hexdigest()

    def _write(self, near, data, exclusive):
        tmp = "%s.%d.%s.tmp" % (near, os.getpid(), binascii.hexlify(os.urandom(6)).decode())
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        try:
            if exclusive:
                try:
                    os.link(tmp, near)
                except FileExistsError:
                    raise AttestationError("receipt already exists (append-only): %s" % near)
            else:
                os.replace(tmp, near)
            self._fsync_dir(os.path.dirname(near))
        finally:
            if os.path.exists(tmp):
                os.remove(tmp)

    @staticmethod
    def _fsync_dir(path):
        try:
            fd = os.open(path, os.O_RDONLY)
        except OSError:
            return
        try:
            os.fsync(fd)
        except OSError:
            pass
        finally:
            os.close(fd)

    def retain(self, canonical_result):
        result_digest = digest(canonical_result)
        self._write(os.path.join(self.root, "artifacts", _hexdigest(result_digest)),
                    canonical_result, exclusive=False)
        return result_digest

    def stamp(self, receipt_core):
        receipts_root = os.path.join(self.root, "receipts")
        session_dir = os.path.join(receipts_root, require_session(receipt_core["sessionId"]))
        # Defence in depth: never write a receipt outside the enumerated root, even
        # if the token check above is ever loosened.
        if os.path.dirname(os.path.realpath(session_dir)) != os.path.realpath(receipts_root):
            raise AttestationError("session directory escapes the receipt store")
        os.makedirs(session_dir, exist_ok=True)
        mac = hmac.new(self.key, canon(receipt_core), hashlib.sha256).hexdigest()
        stored = dict(receipt_core, hmac=mac)
        self._write(os.path.join(session_dir, "%d.json" % receipt_core["callIndex"]),
                    canon(stored) + b"\n", exclusive=True)
        return stored


def verify_store(store_root, key, expected_authority=None):
    """Verify every receipt: HMAC, location binding, artifact re-digest, per-
    session sequence and prevHmac chain. This is the inline core's verification;
    it does NOT catch whole-session replay or final-tail rollback (see
    registry.verify_with_registry)."""
    require_key(key)
    findings = []
    receipts_root = os.path.join(store_root, "receipts")
    all_ok = True
    if not os.path.isdir(receipts_root):
        return True, findings
    for session_id in sorted(os.listdir(receipts_root)):
        session_dir = os.path.join(receipts_root, session_id)
        if not os.path.isdir(session_dir):
            continue
        by_index = {}
        for name in sorted(os.listdir(session_dir)):
            if not name.endswith(".json"):
                continue
            try:
                with open(os.path.join(session_dir, name), "rb") as handle:
                    stored = json.loads(handle.read().decode("utf-8"))
                if not isinstance(stored, dict):
                    raise ValueError("not an object")
                status = _verify_one(stored, key, store_root, session_id, name, expected_authority)
            except Exception:
                all_ok = False
                findings.append({"sessionId": session_id, "file": name, "status": "malformed"})
                continue
            if status != "ok":
                all_ok = False
            else:
                by_index[stored["callIndex"]] = stored
            findings.append({"sessionId": session_id, "callIndex": stored.get("callIndex"), "status": status})
        chain = _verify_chain(by_index)
        if chain != "ok":
            all_ok = False
            findings.append({"sessionId": session_id, "callIndex": None, "status": chain})
    return all_ok, findings


def _verify_one(stored, key, store_root, session_id, name, expected_authority):
    if "hmac" not in stored or type(stored.get("callIndex")) is not int:
        return "malformed"
    result_digest = stored.get("resultDigest")
    if not isinstance(result_digest, str) or not _DIGEST_RE.match(result_digest):
        return "malformed"
    core = {k: v for k, v in stored.items() if k != "hmac"}
    expected = hmac.new(key, canon(core), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, stored.get("hmac", "")):
        return "hmac-mismatch"
    if stored.get("sessionId") != session_id or ("%d.json" % stored["callIndex"]) != name:
        return "misfiled"
    if expected_authority is not None and stored.get("authority") != expected_authority:
        return "authority-mismatch"
    artifact = os.path.join(store_root, "artifacts", _hexdigest(result_digest))
    if not os.path.exists(artifact):
        return "artifact-missing"
    with open(artifact, "rb") as handle:
        if digest(handle.read()) != result_digest:
            return "artifact-mismatch"
    return "ok"


def _verify_chain(by_index):
    if not by_index:
        return "ok"
    if sorted(by_index) != list(range(len(by_index))):
        return "sequence-broken"
    prev = None
    for index in range(len(by_index)):
        if by_index[index].get("prevHmac") != prev:
            return "chain-broken"
        prev = by_index[index]["hmac"]
    return "ok"
