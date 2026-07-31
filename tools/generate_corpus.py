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
import registry

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
CORPUS = os.path.join(ROOT, "corpus")

# A deliberately published test key. Receipts are keyed, so conformance vectors
# cannot exist without one -- the same reason crypto RFCs ship test vectors with
# their keys. It signs nothing real and must never be used by a deployment.
TEST_KEY = b"judgment-pack-gateway-corpus-test-key-0001"
AUTHORITY = "gateway:corpus"


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
]


def canon_vectors():
    vectors = []
    for note, source in CANON_ACCEPT:
        value = json.loads(source)
        encoded = attest.canon(value)
        vectors.append({
            "note": note,
            "inputJson": source,
            "expectedHex": binascii.hexlify(encoded).decode("ascii"),
            "expectedUtf8": encoded.decode("utf-8"),
        })
    for note, source in CANON_REJECT:
        value = json.loads(source)
        try:
            attest.canon(value)
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
    store = attest.Store(store_root, TEST_KEY, AUTHORITY)
    reg = registry.Registry(registry_path, TEST_KEY)
    for session_id, count in sessions:
        prev = None
        for index in range(count):
            payload = attest.canon({"session": session_id, "n": index})
            result_digest = store.retain(payload)
            core = {
                "receiptVersion": attest.RECEIPT_VERSION, "sessionId": session_id,
                "callIndex": index, "prevHmac": prev, "source": "corpus",
                "argumentsDigest": store.keyed_digest("args", attest.canon({"i": index})),
                "resultDigest": result_digest, "servedAt": "2026-07-31T00:00:00Z",
                "authority": AUTHORITY,
            }
            prev = store.stamp(core)["hmac"]
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
            attest.verify_store, store_root, TEST_KEY, registry_path, AUTHORITY)
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
        record = {
            "sessionId": "s1", "finalCount": 2, "sealedAt": sealed_at,
            "hmac": registry._seal_hmac(TEST_KEY, "s1", 2, sealed_at),
        }
        return files, attest.canon(record).decode() + "\n"

    def break_chain(files, reg):
        # Receipt 1's prevHmac is re-pointed and the receipt is RE-KEYED, so it
        # verifies on its own terms. Only the chain reconstruction catches it.
        import hashlib
        import hmac as hmaclib
        files = dict(files)
        path = receipt_path(files, "s1", 1)
        stored = json.loads(files[path])
        core = {k: v for k, v in stored.items() if k != "hmac"}
        core["prevHmac"] = "f" * 64
        core["hmac"] = hmaclib.new(TEST_KEY, attest.canon(core), hashlib.sha256).hexdigest()
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
        stored["servedAt"] = "2099-01-01T00:00:00Z"   # hmac now covers the old value
        files[path] = attest.canon(stored).decode() + "\n"
        return files, reg

    def wrong_authority(files, reg):
        files = dict(files)
        path = receipt_path(files, "s1", 0)
        stored = json.loads(files[path])
        core = {k: v for k, v in stored.items() if k != "hmac"}
        core["authority"] = "gateway:not-the-expected-one"
        import hashlib, hmac as hmaclib
        core["hmac"] = hmaclib.new(TEST_KEY, attest.canon(core), hashlib.sha256).hexdigest()
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

    def forged_seal(files, reg):
        forged = json.dumps({"sessionId": "s1", "finalCount": 3,
                             "sealedAt": "t", "hmac": "0" * 64},
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
        "hmac-mismatch": tamper_receipt_field,
        "authority-mismatch": wrong_authority,
        "misfiled": misfile,
        "sequence-broken": break_sequence,
        "malformed": malformed,
        "forged-seal-is-dropped": forged_seal,
        "sealed-session-missing": delete_sealed_session,
        "count-exceeds-seal": count_exceeds_seal,
        "chain-broken": break_chain,
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
    ("hmac-mismatch", [("s1", 2)],
     "A receipt field is edited without re-keying, so the stored hmac no longer covers it."),
    ("authority-mismatch", [("s1", 2)],
     "A receipt validly keyed under a DIFFERENT authority label. The hmac verifies; "
     "the expected-authority check is what rejects it."),
    ("misfiled", [("s1", 3)],
     "A valid receipt moved to a filename that disagrees with its callIndex."),
    ("sequence-broken", [("s1", 3)], "A gap in the callIndex sequence."),
    ("malformed", [("s1", 2)], "A receipt that is not JSON."),
    ("forged-seal-is-dropped", [("s1", 3)],
     "A seal for the right session and count whose hmac was not produced by the key. "
     "It must be DROPPED, leaving the session unregistered -- not honoured."),
    ("sealed-session-missing", [("s1", 2), ("s2", 2)],
     "A sealed session deleted from the store entirely."),
    ("count-exceeds-seal", [("s1", 3)],
     "Three correctly chained receipts against a seal recording two. Every "
     "per-receipt check passes; only the registry sees the surplus."),
    ("chain-broken", [("s1", 3)],
     "A receipt whose prevHmac is re-pointed and which is then RE-KEYED, so it "
     "verifies on its own terms. Only the chain reconstruction catches it."),
]


def store_vectors():
    cases = []
    for name, sessions, note in CASES:
        files, reg = build_reference_store(sessions)
        files, reg = mutate(name)(files, reg)
        ok, findings = verdict(files, reg)
        observed = {finding["status"] for finding in findings}
        if name == "forged-seal-is-dropped":
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
    os.makedirs(os.path.join(CORPUS, "stores"), exist_ok=True)
    with open(os.path.join(CORPUS, "canon.json"), "w") as handle:
        json.dump({"key": None, "vectors": canon_vectors()}, handle, indent=2, sort_keys=False)
        handle.write("\n")
    for case in store_vectors():
        with open(os.path.join(CORPUS, "stores", "%s.json" % case["name"]), "w") as handle:
            json.dump(case, handle, indent=2, sort_keys=False)
            handle.write("\n")
    with open(os.path.join(CORPUS, "TEST-KEY"), "w") as handle:
        handle.write(TEST_KEY.decode("ascii") + "\n")
    print("canon vectors : %d" % len(canon_vectors()))
    print("store vectors : %d" % len(CASES))


if __name__ == "__main__":
    main()
