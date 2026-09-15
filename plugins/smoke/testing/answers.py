"""The engine's answers to a client plugin, as the local engine of
plugins/smoke/README.md ("The engine") gives them -- one synthetic source
named screening, no identity -- and the wrong answers the smoke checkers
must refuse. Shared by the stand-in engine and both checkers' tests, so
that the answers the checkers are tested against and the answers the
stand-in serves are one set. test_stand_in_engine.py holds that set to the
engine itself.

Nothing here is signed. Every signature, digest and key has the form the
engine's has (SPEC.md §1.2, §3) and no more: this stands in for the shape
of the engine's answers, never for their verification.
"""
import hashlib
import json
import re
import time
from typing import NamedTuple

SOURCE = "screening"
AUTHORITY = "gateway:smoke"
# the source as the README's engine is configured with it
# (--source screening=./my_source): the receipt names it as spelled
ADAPTER_NAME = "./my_source"
KEY_ID = hashlib.sha256(b"stand-in key id").hexdigest()[:32]
PUBLIC_KEY = hashlib.sha256(b"stand-in public key").hexdigest()
ADAPTER_DIGEST = "sha256:" + hashlib.sha256(b"stand-in adapter").hexdigest()
SESSION_PATTERN = re.compile(r"^[A-Za-z0-9._-]{1,128}$")
SESSION_REFUSAL = "session id must match ^[A-Za-z0-9._-]{1,128}$"

# an action at an engine with no identity: refused at the ladder's first
# step, before the body is read, with this body and a Bearer challenge
ACT_REFUSAL = {
    "error": "an action needs an authenticated requester; this engine has no identity configured",
    "refusedAt": "requester",
}


def go_json(value):
    """value as the engine writes it (Go's json.Marshal): compact, an
    object's keys sorted, no newline after, and <, >, &, U+2028 and U+2029
    escaped."""
    text = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    for raw, escaped in (("<", "\\u003c"), (">", "\\u003e"), ("&", "\\u0026"), ("\u2028", "\\u2028"), ("\u2029", "\\u2029")):
        text = text.replace(raw, escaped)
    return text


def stamp(at=None):
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(at))


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def digest(*parts):
    return "sha256:" + hashlib.sha256("\x00".join(parts).encode()).hexdigest()


def signature_for(*parts):
    # 128 lowercase hex characters, one per signed thing: the form of an
    # Ed25519 signature, and a different one for every receipt or seal
    return hashlib.sha512("/".join(str(p) for p in parts).encode()).hexdigest()


def public_key():
    return {"algorithm": "ed25519", "authority": AUTHORITY, "keyId": KEY_ID, "publicKey": PUBLIC_KEY}


def result_for(arguments):
    # the source echoes the canonical arguments it was given
    return {"synthetic": True, "arguments": arguments}


def acquisition(session, index, prev_signature, arguments, at):
    """The answer to an acquisition: the source's result, the complete
    version 3 receipt of §1.2 and §1.2a, and the arguments salt."""
    result = result_for(arguments)
    salt = hashlib.sha256(f"salt/{session}/{index}".encode()).hexdigest()
    receipt = {
        "acquisition": {
            "adapter": {"digest": ADAPTER_DIGEST, "name": ADAPTER_NAME, "version": ""},
            "endpoint": None,
            "observedAt": at,
            "peerIdentity": None,
            "schema": None,
            "shape": "command",
            "snapshot": None,
            "statement": None,
            "upstreamToken": None,
        },
        "argumentsCommitment": digest("arguments", salt, canonical(arguments)),
        "authority": AUTHORITY,
        "callIndex": index,
        "caller": None,
        "keyId": KEY_ID,
        "kind": "acquisition",
        "prevSignature": prev_signature,
        "receiptVersion": "3",
        "resultDigest": digest("result", canonical(result)),
        "servedAt": at,
        "sessionId": session,
        "signature": signature_for("receipt", session, index),
        "source": SOURCE,
    }
    return {"receipt": receipt, "result": result, "salts": {"args": salt}}


def seal(session, final_count, at):
    return {
        "finalCount": final_count,
        "keyId": KEY_ID,
        "sealedAt": at,
        "sessionId": session,
        "signature": signature_for("seal", session, final_count),
    }


class Fault(NamedTuple):
    """One wrong answer. At route, the member at path is replaced by value;
    with a status, the route answers that status with value as its whole
    body. check is the check that must refuse it, named as both checkers
    name it when it fails; checkers are the ones that read this answer."""
    name: str
    route: str
    path: tuple
    value: object
    check: str
    status: int = 0
    checkers: tuple = ("n8n", "activepieces")


ACCEPTED_ACT = {"result": {}, "receipt": {"kind": "action"}, "salts": {}}

# Each fault breaks one check and no other, so a check that stops
# refusing is a fault that passes: the wrong type, length and alphabet for
# each hex member, a number or a boolean where an integer or a string
# belongs, and a member more or a value off in the result.
FAULTS = (
    Fault("publickey-refused", "publickey", (), {"error": "not found"}, "connection validation", status=404, checkers=("activepieces",)),
    Fault("version", "acquire", ("receipt", "receiptVersion"), "2", "receipt version"),
    Fault("version-number", "acquire", ("receipt", "receiptVersion"), 3, "receipt version"),
    Fault("kind", "acquire", ("receipt", "kind"), "action", "receipt kind"),
    Fault("index", "acquire", ("receipt", "callIndex"), 1, "receipt index"),
    Fault("index-boolean", "acquire", ("receipt", "callIndex"), False, "receipt index"),
    Fault("session", "acquire", ("receipt", "sessionId"), "another-session", "receipt session"),
    Fault("signature-case", "acquire", ("receipt", "signature"), "A" * 128, "receipt signature"),
    Fault("signature-length", "acquire", ("receipt", "signature"), "a" * 127, "receipt signature"),
    Fault("signature-alphabet", "acquire", ("receipt", "signature"), "g" * 128, "receipt signature"),
    Fault("signature-number", "acquire", ("receipt", "signature"), 7, "receipt signature"),
    Fault("result", "acquire", ("result", "arguments"), {"subject": "someone else"}, "result"),
    Fault("result-member", "acquire", ("result", "extra"), 1, "result"),
    Fault("result-synthetic", "acquire", ("result", "synthetic"), 1, "result"),
    Fault("salt-absent", "acquire", ("salts",), {}, "arguments salt"),
    Fault("salt-length", "acquire", ("salts", "args"), "b" * 63, "arguments salt"),
    Fault("salt-alphabet", "acquire", ("salts", "args"), "z" * 64, "arguments salt"),
    Fault("salt-number", "acquire", ("salts", "args"), 5, "arguments salt"),
    Fault("act-accepted", "act", (), ACCEPTED_ACT, "act refusal", status=200),
    Fault("seal-count", "seal", ("finalCount",), 2, "seal count"),
    Fault("seal-count-boolean", "seal", ("finalCount",), True, "seal count"),
    Fault("seal-session", "seal", ("sessionId",), "another-session", "seal session"),
    Fault("seal-signature-case", "seal", ("signature",), "C" * 128, "seal signature"),
    Fault("seal-signature-length", "seal", ("signature",), "c" * 129, "seal signature"),
    Fault("seal-signature-alphabet", "seal", ("signature",), "x" * 128, "seal signature"),
    Fault("seal-signature-null", "seal", ("signature",), None, "seal signature"),
)
FAULT_NAMES = tuple(f.name for f in FAULTS)


def fault_named(name):
    return next(f for f in FAULTS if f.name == name)


def apply(fault, answer):
    """The answer with fault's member replaced, as a new object."""
    answer = json.loads(json.dumps(answer))
    if not fault.path:
        return json.loads(json.dumps(fault.value))
    target = answer
    for key in fault.path[:-1]:
        target = target[key]
    target[fault.path[-1]] = json.loads(json.dumps(fault.value))
    return answer
