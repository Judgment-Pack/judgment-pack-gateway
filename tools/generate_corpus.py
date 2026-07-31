"""Regenerate the conformance corpus from the reference implementation.

The corpus is the arbiter a second implementation answers to, so it is checked in
as data and never computed at test time. This script rebuilds it; `conformance.py`
consumes it.

Honest about what the expectations are: they are produced by the Python reference
and then read against SPEC.md by hand. So the corpus pins *the reference's current
behaviour*. When a second implementation disagrees, that is not automatically the
second implementation being wrong -- it is a question about the spec that someone
has to answer, which is the entire point of having the corpus.

Usage: python3 tools/generate_corpus.py
"""

import binascii
import json
import os
import shutil
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import attest
import ed25519
import registry

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
CORPUS = os.path.join(ROOT, "corpus")

# A deliberately published test SEED. Receipts are signed, so conformance vectors
# cannot exist without one -- the same reason crypto RFCs ship test vectors with
# their keys. Its public half is what a verifier uses; the seed is published only
# so the vectors can be regenerated. It signs nothing real.
TEST_SEED = b"judgment-pack-gateway-corpus-see"   # exactly 32 bytes
AUTHORITY = "gateway:corpus"
PUBLIC_KEY = ed25519.public_key(TEST_SEED)


# ---------------------------------------------------------------- canon vectors

# Inputs are carried as JSON *text*, not as parsed JSON. That is deliberate: a
# vector has to be able to say "the integer 1" and "the number 1.0" and "a lone
# surrogate", and those distinctions do not survive being written into a JSON
# document that every language re-parses with its own defaults.
CANON_ACCEPT = [
    ("empty object", '{}'),
    ("empty array", '[]'),
    ("member names sort by code point", '{"b":1,"a":2}'),
    ("sorting is recursive", '{"z":{"b":1,"a":2},"a":[{"d":1,"c":2}]}'),
    ("array order is preserved, never sorted", '{"a":[3,1,2]}'),
    ("the empty string is a legal member name", '{"":1}'),
    ("non-ASCII is raw UTF-8, never \\u-escaped "
     "(a serializer defaulting to ASCII output fails here)", '{"k":"caf\\u00e9"}'),
    ("< > & are raw, never HTML-escaped "
     "(Go's encoding/json escapes these by default and fails here)", '{"k":"<a>&b</a>"}'),
    ("a non-BMP member name sorts by CODE POINT, not by UTF-16 code unit "
     "(a UTF-16-ordered canonicalizer emits these two in the other order)",
     '{"\\ud83d\\ude00":1,"\\ufffd":2}'),
    ("a non-BMP string value is raw UTF-8, not a surrogate pair", '{"k":"\\ud83d\\ude00"}'),
    ("the solidus is not escaped", '{"k":"a/b"}'),
    ("the standard short escapes", '{"k":"nl\\ntab\\tquote\\"backslash\\\\"}'),
    ("control characters take the \\u form", '{"k":"\\u0001"}'),
    ("zero, and a negative integer", '{"a":0,"b":-1}'),
    ("the largest integer in the domain", '{"n":9007199254740991}'),
    ("the smallest integer in the domain", '{"n":-9007199254740991}'),
    ("booleans and null are in the domain", '{"a":true,"b":false,"c":null}'),
    ("a bare string is a legal top-level value", '"hello"'),
    # Previously unpinned: a clean-room implementation had to guess each of these,
    # and recorded them as ambiguities. They are now stated in SPEC.md 1.1 and
    # fixed here, so a third implementation cannot guess differently in silence.
    ("the short escapes for backspace, formfeed and carriage return",
     '{"k":"\\b\\f\\r"}'),
    ("hex in a \\u escape is LOWERCASE", '{"k":"\\u001f"}'),
    ("DEL (U+007F) is emitted raw, not escaped", '{"k":"\\u007f"}'),
    ("U+2028 and U+2029 are emitted raw (some JSON writers escape them)",
     '{"k":"\\u2028\\u2029"}'),
]

CANON_REJECT = [
    ("a non-integer number is outside the domain", '{"n":1.5}'),
    ("an integer-valued FLOAT literal is still outside the domain",
     '{"n":1.0}'),
    ("exponent notation is a float literal, so it is outside the domain", '{"n":1e2}'),
    ("an integer above the safe range", '{"n":9007199254740992}'),
    ("an integer below the safe range", '{"n":-9007199254740992}'),
    ("a lone high surrogate is not encodable", '{"k":"\\ud800"}'),
    ("a lone low surrogate is not encodable", '{"k":"\\udc00"}'),
    ("a duplicate member name is refused: last-wins and first-wins are both "
     "defensible, they disagree, and the disagreement is silent",
     '{"a":1,"a":2}'),
]


def canon_vectors():
    vectors = []
    for note, source in CANON_ACCEPT:
        encoded = attest.canon(attest.loads(source))
        vectors.append({
            "note": note,
            "inputJson": source,
            "expectedHex": binascii.hexlify(encoded).decode("ascii"),
            "expectedUtf8": encoded.decode("utf-8"),
        })
    for note, source in CANON_REJECT:
        try:
            attest.canon(attest.loads(source))
        except attest.AttestationError:
            pass
        else:
            raise SystemExit("vector expected to be rejected but was accepted: %s" % source)
        vectors.append({"note": note, "inputJson": source, "reject": True})
    return vectors


# ---------------------------------------------------------------- store vectors

def build_reference_store(sessions):
    """Attest `sessions` = [(session_id, count)] into a fresh store, seal each,
    and return the store as a path -> text manifest plus the registry text."""
    root = tempfile.mkdtemp()
    store_root = os.path.join(root, "store")
    registry_path = os.path.join(root, "registry.jsonl")
    store = attest.Store(store_root, TEST_SEED, AUTHORITY)
    reg = registry.Registry(registry_path, TEST_SEED)
    for session_id, count in sessions:
        prev = None
        for index in range(count):
            payload = attest.canon({"session": session_id, "n": index})
            result_digest = store.retain(payload)
            core = {
                "receiptVersion": attest.RECEIPT_VERSION, "sessionId": session_id,
                "callIndex": index, "prevSignature": prev, "source": "corpus",
                "argumentsDigest": store.keyed_digest("args", attest.canon({"i": index})),
                "resultDigest": result_digest, "servedAt": "2026-07-31T00:00:00Z",
                "authority": AUTHORITY,
            }
            prev = store.stamp(core)["signature"]
        reg.seal(session_id, count, "2026-07-31T00:00:01Z")
    files = {}
    for base, _dirs, names in os.walk(store_root):
        for name in names:
            full = os.path.join(base, name)
            with open(full, "rb") as handle:
                files[os.path.relpath(full, store_root).replace(os.sep, "/")] = \
                    handle.read().decode("utf-8")
    with open(registry_path) as handle:
        registry_text = handle.read()
    shutil.rmtree(root, ignore_errors=True)
    return files, registry_text


def materialize(files, registry_text):
    root = tempfile.mkdtemp()
    store_root = os.path.join(root, "store")
    for path, text in files.items():
        full = os.path.join(store_root, path.replace("/", os.sep))
        os.makedirs(os.path.dirname(full), exist_ok=True)
        with open(full, "wb") as handle:
            handle.write(text.encode("utf-8"))
    os.makedirs(os.path.join(store_root, "receipts"), exist_ok=True)
    os.makedirs(os.path.join(store_root, "artifacts"), exist_ok=True)
    registry_path = os.path.join(root, "registry.jsonl")
    with open(registry_path, "wb") as handle:
        handle.write(registry_text.encode("utf-8"))
    return root, store_root, registry_path


def verdict(files, registry_text):
    root, store_root, registry_path = materialize(files, registry_text)
    try:
        ok, findings = registry.verify_with_registry(
            attest.verify_store, store_root, PUBLIC_KEY, registry_path, AUTHORITY)
    finally:
        shutil.rmtree(root, ignore_errors=True)
    return ok, findings


def receipt_path(files, session_id, index):
    return "receipts/%s/%d.json" % (session_id, index)


# Each mutation takes (files, registry_text) and returns the mutated pair. They
# are written against the spec's failure modes, one per status the spec names.
def mutate(name):
    def identity(files, reg):
        return files, reg

    def drop_last_receipt(files, reg):
        files = dict(files)
        del files[receipt_path(files, "s1", 2)]
        return files, reg

    def drop_seal(files, reg):
        return files, ""

    def count_exceeds_seal(files, reg):
        # Three correctly chained receipts, but the seal records two. Every
        # per-receipt check passes; only the registry sees the surplus.
        sealed_at = "2026-07-31T00:00:01Z"
        key_identifier = attest.key_id(PUBLIC_KEY)
        signature = ed25519.sign(
            TEST_SEED, registry._seal_body("s1", 2, sealed_at, key_identifier))
        record = {
            "sessionId": "s1", "finalCount": 2, "sealedAt": sealed_at,
            "keyId": key_identifier,
            "signature": binascii.hexlify(signature).decode("ascii"),
        }
        return files, attest.canon(record).decode() + "\n"

    def wrong_key_id(files, reg):
        # A receipt whose keyId names a different key, RE-SIGNED so the signature
        # itself is valid. Only the key-id check catches it. Without this vector
        # the status has no name an implementation could match.
        files = dict(files)
        path = receipt_path(files, "s1", 0)
        core = {k: v for k, v in json.loads(files[path]).items() if k != "signature"}
        core["keyId"] = "0" * 32
        core["signature"] = binascii.hexlify(
            ed25519.sign(TEST_SEED, attest.RECEIPT_CONTEXT + attest.canon(core))).decode("ascii")
        files[path] = attest.canon(core).decode() + "\n"
        return files, reg

    def wrong_version(files, reg):
        # A receipt declaring version 1, RE-SIGNED so nothing else is wrong.
        files = dict(files)
        path = receipt_path(files, "s1", 0)
        core = {k: v for k, v in json.loads(files[path]).items() if k != "signature"}
        core["receiptVersion"] = "1"
        core["signature"] = binascii.hexlify(
            ed25519.sign(TEST_SEED, attest.RECEIPT_CONTEXT + attest.canon(core))).decode("ascii")
        files[path] = attest.canon(core).decode() + "\n"
        return files, reg

    def break_chain(files, reg):
        # Receipt 1's prevSignature is re-pointed and the receipt is RE-SIGNED, so
        # it verifies on its own terms. Only the chain reconstruction catches it.
        files = dict(files)
        path = receipt_path(files, "s1", 1)
        stored = json.loads(files[path])
        core = {k: v for k, v in stored.items() if k != "signature"}
        core["prevSignature"] = "f" * 128
        core["signature"] = binascii.hexlify(
            ed25519.sign(TEST_SEED, attest.RECEIPT_CONTEXT + attest.canon(core))).decode("ascii")
        files[path] = attest.canon(core).decode() + "\n"
        return files, reg

    def tamper_artifact(files, reg):
        files = dict(files)
        key = sorted(k for k in files if k.startswith("artifacts/"))[0]
        before = files[key]
        stored = json.loads(before)
        stored["session"] = stored["session"] + "-tampered"
        files[key] = attest.canon(stored).decode()
        assert files[key] != before, "tamper produced identical bytes"
        return files, reg

    def remove_artifact(files, reg):
        files = dict(files)
        key = sorted(k for k in files if k.startswith("artifacts/"))[0]
        del files[key]
        return files, reg

    def tamper_receipt_field(files, reg):
        files = dict(files)
        path = receipt_path(files, "s1", 1)
        stored = json.loads(files[path])
        stored["servedAt"] = "2099-01-01T00:00:00Z"   # signature covers the old value
        files[path] = attest.canon(stored).decode() + "\n"
        return files, reg

    def wrong_authority(files, reg):
        files = dict(files)
        path = receipt_path(files, "s1", 0)
        stored = json.loads(files[path])
        core = {k: v for k, v in stored.items() if k != "signature"}
        core["authority"] = "gateway:not-the-expected-one"
        core["signature"] = binascii.hexlify(
            ed25519.sign(TEST_SEED, attest.RECEIPT_CONTEXT + attest.canon(core))).decode("ascii")
        files[path] = attest.canon(core).decode() + "\n"
        return files, reg

    def misfile(files, reg):
        files = dict(files)
        body = files.pop(receipt_path(files, "s1", 2))
        files["receipts/s1/7.json"] = body       # says callIndex 2, filed as 7
        return files, reg

    def break_sequence(files, reg):
        files = dict(files)
        del files[receipt_path(files, "s1", 1)]  # leaves 0 and 2
        return files, reg

    def malformed(files, reg):
        files = dict(files)
        files[receipt_path(files, "s1", 1)] = "{not json"
        return files, reg

    def foreign_key_seal(files, reg):
        # A seal validly SIGNED by the real key but naming a foreign keyId. The
        # keyId sits inside the signed payload, so the signature verifies; only a
        # verifier that also checks the keyId rejects it. SPEC.md step 2 said
        # "signature" and nothing else, and the clean-room implementation followed
        # that literally -- so the two implementations disagreed here with no
        # vector to catch it.
        sealed_at = "2026-07-31T00:00:01Z"
        foreign = "f" * 32
        signature = ed25519.sign(
            TEST_SEED, registry._seal_body("s1", 2, sealed_at, foreign))
        record = {"sessionId": "s1", "finalCount": 2, "sealedAt": sealed_at,
                  "keyId": foreign,
                  "signature": binascii.hexlify(signature).decode("ascii")}
        return files, attest.canon(record).decode() + "\n"

    def forged_seal(files, reg):
        # Right session, right count, right key id -- but no valid signature,
        # because producing one needs the seed.
        forged = json.dumps({"sessionId": "s1", "finalCount": 3, "sealedAt": "t",
                             "keyId": attest.key_id(PUBLIC_KEY), "signature": "0" * 128},
                            sort_keys=True, separators=(",", ":"))
        return files, forged + "\n"

    def delete_sealed_session(files, reg):
        files = {k: v for k, v in files.items() if not k.startswith("receipts/s2/")}
        return files, reg

    return {
        "valid-sealed": identity,
        "tail-rollback": drop_last_receipt,
        "unregistered-session": drop_seal,
        "artifact-mismatch": tamper_artifact,
        "artifact-missing": remove_artifact,
        "signature-mismatch": tamper_receipt_field,
        "authority-mismatch": wrong_authority,
        "misfiled": misfile,
        "sequence-broken": break_sequence,
        "malformed": malformed,
        "forged-seal-is-dropped": forged_seal,
        "sealed-session-missing": delete_sealed_session,
        "count-exceeds-seal": count_exceeds_seal,
        "chain-broken": break_chain,
        "key-mismatch": wrong_key_id,
        "unsupported-version": wrong_version,
        "seal-with-foreign-key-id-is-dropped": foreign_key_seal,
    }[name]


CASES = [
    ("valid-sealed", [("s1", 3)],
     "A sealed session whose receipts, chain, artifacts and count all agree."),
    ("tail-rollback", [("s1", 3)],
     "The last receipt is deleted. The remaining prefix is a VALID chain, so the "
     "per-receipt verification passes; only the seal's count reveals it."),
    ("unregistered-session", [("s1", 3)],
     "A genuine, correctly chained session with no seal -- what a whole-session "
     "replay into a fresh store looks like. Per-receipt verification passes."),
    ("artifact-mismatch", [("s1", 2)], "A retained artifact's bytes are altered."),
    ("artifact-missing", [("s1", 2)], "A receipt's artifact is absent from the store."),
    ("signature-mismatch", [("s1", 2)],
     "A receipt field is edited without re-signing, so the signature no longer covers it."),
    ("authority-mismatch", [("s1", 2)],
     "A receipt validly signed but carrying a DIFFERENT authority label. The signature "
     "verifies; "
     "the expected-authority check is what rejects it."),
    ("misfiled", [("s1", 3)],
     "A valid receipt moved to a filename that disagrees with its callIndex."),
    ("sequence-broken", [("s1", 3)], "A gap in the callIndex sequence."),
    ("malformed", [("s1", 2)], "A receipt that is not JSON."),
    ("forged-seal-is-dropped", [("s1", 3)],
     "A seal for the right session and count whose SIGNATURE was not produced by "
     "the key. It must be DROPPED, leaving the session unregistered -- not honoured."),
    ("sealed-session-missing", [("s1", 2), ("s2", 2)],
     "A sealed session deleted from the store entirely."),
    ("count-exceeds-seal", [("s1", 3)],
     "Three correctly chained receipts against a seal recording two. Every "
     "per-receipt check passes; only the registry sees the surplus."),
    ("key-mismatch", [("s1", 2)],
     "A receipt naming a different keyId, re-signed so its signature is valid. "
     "Only the key-id check rejects it -- without which a forger could sign with "
     "their own key and label it as anyone's."),
    ("unsupported-version", [("s1", 2)],
     "A receipt declaring receiptVersion 1, re-signed so nothing else is wrong. "
     "Version 1 is not accepted here."),
    ("seal-with-foreign-key-id-is-dropped", [("s1", 2)],
     "A seal validly signed by the real key but naming a FOREIGN keyId. The keyId "
     "is inside the signed payload, so the signature verifies -- only a verifier "
     "that also checks the keyId drops it, leaving the session unregistered."),
    ("chain-broken", [("s1", 3)],
     "A receipt whose prevSignature is re-pointed and which is then RE-SIGNED, so it "
     "verifies on its own terms. Only the chain reconstruction catches it."),
]


def store_vectors():
    cases = []
    for name, sessions, note in CASES:
        files, reg = build_reference_store(sessions)
        files, reg = mutate(name)(files, reg)
        ok, findings = verdict(files, reg)
        observed = {finding["status"] for finding in findings}
        if name in ("forged-seal-is-dropped", "seal-with-foreign-key-id-is-dropped"):
            expected_status = "unregistered-session"   # the forged seal is discarded
        elif name == "valid-sealed":
            expected_status = "ok"
        else:
            expected_status = name
        if expected_status not in observed:
            raise SystemExit(
                "case %r does not exercise %r -- observed %s. A mutation that "
                "silently does nothing would otherwise ship as a vector asserting "
                "the happy path." % (name, expected_status, sorted(observed)))
        cases.append({
            "name": name,
            "note": note,
            "authority": AUTHORITY,
            "files": dict(sorted(files.items())),
            "registry": reg,
            "expected": {
                "ok": ok,
                # Order is NOT normative -- see corpus/README.md. Sorted here so
                # the checked-in file is stable and diffable.
                "findings": sorted(findings, key=lambda f: json.dumps(f, sort_keys=True)),
            },
        })
    return cases


def main():
    stores_dir = os.path.join(CORPUS, "stores")
    os.makedirs(stores_dir, exist_ok=True)
    # Prune cases this generator no longer produces. Without this, a renamed case
    # leaves its predecessor behind as a vector nothing regenerates -- which is
    # how a stale receipt-version-1 store survived the move to signatures.
    expected_files = {"%s.json" % name for name, _sessions, _note in CASES}
    for stale in sorted(set(os.listdir(stores_dir)) - expected_files):
        if stale.endswith(".json"):
            os.remove(os.path.join(stores_dir, stale))
            print("pruned stale vector: %s" % stale)
    with open(os.path.join(CORPUS, "canon.json"), "w") as handle:
        json.dump({"key": None, "vectors": canon_vectors()}, handle, indent=2, sort_keys=False)
        handle.write("\n")
    for case in store_vectors():
        with open(os.path.join(CORPUS, "stores", "%s.json" % case["name"]), "w") as handle:
            json.dump(case, handle, indent=2, sort_keys=False)
            handle.write("\n")
    # The PUBLIC key is what verification consumes; the seed is published only so
    # these vectors can be regenerated. A verifier never needs it.
    with open(os.path.join(CORPUS, "TEST-PUBLIC-KEY"), "w") as handle:
        handle.write(binascii.hexlify(PUBLIC_KEY).decode("ascii") + "\n")
    with open(os.path.join(CORPUS, "TEST-SEED"), "w") as handle:
        handle.write(binascii.hexlify(TEST_SEED).decode("ascii") + "\n")
    print("canon vectors : %d" % len(canon_vectors()))
    print("store vectors : %d" % len(CASES))


if __name__ == "__main__":
    main()
