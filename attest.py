"""Attestation primitives: content-addressed artifacts and signed, chained receipts.

The gateway signs each acquired result with an Ed25519 key it alone holds, and a
verifier checks those signatures with the **public** key. That asymmetry is the
whole point of receipt version 2: verifying no longer requires the power to forge,
so "a third party can check this" stops being aspirational.

Version 1 receipts were HMAC'd, which meant a verifier needed the signing secret.
That format is gone rather than deprecated -- the repository is pre-1.0 with no
deployments, and carrying a legacy path whose only property is "weaker" would keep
the symmetric-verification caveat alive in the specification forever.

Standard library only. The signature primitive is in `ed25519.py`, which carries
its own warning about being reference arithmetic rather than production crypto.
"""

import binascii
import datetime
import hashlib
import hmac
import json
import os
import re

import ed25519

RECEIPT_VERSION = "2"
SEED_BYTES = 32
_SAFE_INT_MAX = (1 << 53) - 1
_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
# A session id names a directory under the store. It is caller-supplied and the
# caller is outside the trust boundary, so it is constrained to a flat token:
# anything else could steer signed writes out of the store, where `verify` --
# which enumerates the store -- would never see them.
_SESSION_RE = re.compile(r"^[A-Za-z0-9._-]{1,128}$")

# Domain separation. A receipt signature must never verify as a seal signature,
# and vice versa, even though both are Ed25519 over canonical JSON.
RECEIPT_CONTEXT = b"judgment-pack-gateway/receipt/2:"
SEAL_CONTEXT = b"judgment-pack-gateway/seal/2:"


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
    number domain. Member names order by CODE POINT (see corpus/canon.json)."""
    _check_domain(value)
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    ).encode("utf-8")


def digest(data):
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _hexdigest(digest_string):
    return digest_string.split(":", 1)[1]


def require_seed(seed):
    if not isinstance(seed, bytes) or len(seed) != SEED_BYTES:
        raise AttestationError("an Ed25519 signing seed is %d bytes" % SEED_BYTES)
    return seed


def require_public_key(public):
    if not isinstance(public, bytes) or len(public) != ed25519.PUBLIC_KEY_BYTES:
        raise AttestationError(
            "an Ed25519 public key is %d bytes" % ed25519.PUBLIC_KEY_BYTES)
    return public


def require_session(session_id):
    """A session id must be a flat token. It names a directory under the store, and
    a verifier discovers sessions by enumerating that directory -- so a value that
    escapes it (an absolute path, a `..` segment, a nested path) would produce
    genuinely attested receipts that `verify` can never find, silently voiding the
    registry's coverage guarantee."""
    if not isinstance(session_id, str) or not _SESSION_RE.match(session_id):
        raise AttestationError("session id must match %s" % _SESSION_RE.pattern)
    if session_id in (".", ".."):
        raise AttestationError("session id must not be a path segment")
    return session_id


def key_id(public):
    """A short, stable name for a public key. A receipt carries the key id, never
    the key itself: a verifier must bring the public key it already trusts, or it
    would happily verify a forgery against the forger's own embedded key."""
    return hashlib.sha256(require_public_key(public)).hexdigest()[:32]


def arguments_key(seed):
    """The key for the arguments commitment, derived from the signing seed.

    Arguments are committed to with a keyed digest rather than a plain hash so a
    third party cannot brute-force a small argument space out of the receipt. The
    consequence is deliberate: a public verifier cannot recompute this value. It
    does not need to -- the signature covers it, so it is authenticated even
    though it is opaque."""
    return hashlib.sha256(b"judgment-pack-gateway/arguments-key/2:"
                          + require_seed(seed)).digest()


def now():
    return (
        datetime.datetime.now(datetime.timezone.utc)
        .replace(microsecond=0).isoformat().replace("+00:00", "Z")
    )


class Store:
    """The append-only receipt and content-addressed artifact store, signed by the
    gateway's protected identity."""

    def __init__(self, root, seed, authority):
        self.root = root
        self.seed = require_seed(seed)
        self.public_key = ed25519.public_key(self.seed)
        self.key_id = key_id(self.public_key)
        self.authority = authority
        os.makedirs(os.path.join(root, "artifacts"), exist_ok=True)
        os.makedirs(os.path.join(root, "receipts"), exist_ok=True)

    def keyed_digest(self, domain, data):
        return "hmac-sha256:" + hmac.new(
            arguments_key(self.seed), domain.encode("ascii") + b":" + data,
            hashlib.sha256).hexdigest()

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
        core = dict(receipt_core, keyId=self.key_id)
        signature = ed25519.sign(self.seed, RECEIPT_CONTEXT + canon(core))
        stored = dict(core, signature=binascii.hexlify(signature).decode("ascii"))
        self._write(os.path.join(session_dir, "%d.json" % core["callIndex"]),
                    canon(stored) + b"\n", exclusive=True)
        return stored


def verify_store(store_root, public_key, expected_authority=None):
    """Verify every receipt against the PUBLIC key: signature, key id, location
    binding, artifact re-digest, per-session sequence and prevSignature chain.

    It does NOT catch whole-session replay or final-tail rollback -- both need an
    anchor outside the store (see registry.verify_with_registry)."""
    require_public_key(public_key)
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
                status = _verify_one(stored, public_key, store_root, session_id, name,
                                     expected_authority)
            except Exception:
                all_ok = False
                findings.append({"sessionId": session_id, "file": name, "status": "malformed"})
                continue
            if status != "ok":
                all_ok = False
            else:
                by_index[stored["callIndex"]] = stored
            findings.append({"sessionId": session_id, "callIndex": stored.get("callIndex"),
                             "status": status})
        chain = _verify_chain(by_index)
        if chain != "ok":
            all_ok = False
            findings.append({"sessionId": session_id, "callIndex": None, "status": chain})
    return all_ok, findings


def _verify_one(stored, public_key, store_root, session_id, name, expected_authority):
    if "signature" not in stored or type(stored.get("callIndex")) is not int:
        return "malformed"
    result_digest = stored.get("resultDigest")
    if not isinstance(result_digest, str) or not _DIGEST_RE.match(result_digest):
        return "malformed"
    if stored.get("receiptVersion") != RECEIPT_VERSION:
        return "unsupported-version"
    # The receipt names a key; the verifier brought one. They must be the same key,
    # or a forger could sign with their own and label it as anyone's.
    if stored.get("keyId") != key_id(public_key):
        return "key-mismatch"
    core = {k: v for k, v in stored.items() if k != "signature"}
    try:
        signature = binascii.unhexlify(stored["signature"])
    except (binascii.Error, TypeError, ValueError):
        return "malformed"
    try:
        if not ed25519.verify(public_key, RECEIPT_CONTEXT + canon(core), signature):
            return "signature-mismatch"
    except ed25519.SignatureError:
        return "malformed"
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
        if by_index[index].get("prevSignature") != prev:
            return "chain-broken"
        prev = by_index[index]["signature"]
    return "ok"
