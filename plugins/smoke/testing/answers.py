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
# the synthetic source of plugins/smoke/README.md ("The engine"): it echoes
# the canonical arguments it was given
SOURCE_SCRIPT = """#!/bin/sh
args=$(cat)
printf '{"synthetic":true,"arguments":%s}\\n' "${args:-null}"
"""
# the source as the README's engine is configured with it
# (--source screening=./my_source): the receipt names it as spelled, and
# digests the file's bytes
ADAPTER_NAME = "./my_source"
ADAPTER_DIGEST = "sha256:" + hashlib.sha256(SOURCE_SCRIPT.encode()).hexdigest()
PUBLIC_KEY = hashlib.sha256(b"stand-in public key").hexdigest()
# SPEC.md §1.2: the first 32 hex characters of SHA-256 over the key's bytes
KEY_ID = hashlib.sha256(bytes.fromhex(PUBLIC_KEY)).hexdigest()[:32]
SESSION_PATTERN = re.compile(r"^[A-Za-z0-9._-]{1,128}$")
SESSION_REFUSAL = "session id must match ^[A-Za-z0-9._-]{1,128}$"
MAX_SAFE_INTEGER = 2**53 - 1

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


def sha256_of(data):
    return "sha256:" + hashlib.sha256(data).hexdigest()


def commitment(salt_hex, label, value):
    """SPEC.md §1.2a: SHA-256 over salt || label || canon(value)."""
    return sha256_of(bytes.fromhex(salt_hex) + label.encode() + canonical(value).encode())


def signature_for(*parts):
    # 128 lowercase hex characters, one per signed thing: the form of an
    # Ed25519 signature, and a different one for every receipt or seal
    return hashlib.sha512("/".join(str(p) for p in parts).encode()).hexdigest()


class Refusal(Exception):
    """A 400 the engine gives a request body, in the engine's words."""

    def __init__(self, message):
        super().__init__(message)
        self.message = message


class _Number(str):
    """A number as written, and whether it was written with a fraction or
    an exponent."""

    def __new__(cls, literal, written_as_float):
        number = super().__new__(cls, literal)
        number.written_as_float = written_as_float
        return number


class _Members(list):
    """A JSON object as written: its members in order, duplicates kept."""


def _refuse_constant(name):
    raise ValueError(f"{name} is not JSON")


_READER = json.JSONDecoder(
    object_pairs_hook=_Members,
    parse_float=lambda literal: _Number(literal, True),
    parse_int=lambda literal: _Number(literal, False),
    parse_constant=_refuse_constant,
)
_JSON_SPACE = " \t\n\r"


def _one_value(text):
    """The one JSON value of a request body, as the engine's decoder takes it
    (decodeSingleJSON). A refusal whose words are Go's decoder's own
    carries different words here."""
    start = len(text) - len(text.lstrip(_JSON_SPACE))
    if start == len(text):
        raise Refusal("EOF")
    try:
        value, end = _READER.raw_decode(text, start)
    except ValueError as error:
        raise Refusal(f"the body is not JSON: {error}")
    rest = text[end:].lstrip(_JSON_SPACE)
    if rest:
        try:
            _READER.raw_decode(rest)
        except ValueError as error:
            raise Refusal(f"request body contains trailing content: {error}")
        raise Refusal("request body must contain exactly one JSON value")
    return value


def _json_type(value):
    if isinstance(value, _Members):
        return "object"
    if isinstance(value, list):
        return "array"
    if isinstance(value, bool):
        return "bool"
    if isinstance(value, _Number):
        return "number"
    return "string"


def _fold(name):
    # the case folding Go's decoder matches member names by: ASCII letters,
    # and the two runes that fold to one (the long s and the Kelvin sign)
    return "".join({"\u017f": "s", "\u212a": "k"}.get(c, c.lower() if c.isascii() else c) for c in name)


def request_fields(text, names):
    """The members of a request body the engine reads, as its decoder reads
    them into its struct: names matched without regard to case, the last
    of several taking the place, a null leaving a string as it was, and
    every other member ignored. arguments is any JSON value, as written."""
    value = _one_value(text)
    if not isinstance(value, _Members):
        raise Refusal(f"json: cannot unmarshal {_json_type(value)} into Go value of type struct")
    fields, mistyped = {}, None
    for key, member in value:
        name = next((n for n in names if _fold(key) == n), None)
        if name is None:
            continue
        if name == "arguments":
            fields[name] = member
        elif member is None:
            continue
        elif isinstance(member, str) and not isinstance(member, _Number):
            fields[name] = str(member)
        elif mistyped is None:
            mistyped = f"json: cannot unmarshal {_json_type(member)} into Go struct field .{name} of type string"
    if mistyped:
        raise Refusal(mistyped)
    return fields


def _go_quote(text):
    return '"' + text.replace("\\", "\\\\").replace('"', '\\"') + '"'


def _whole_scalars(text):
    for c in text:
        if 0xD800 <= ord(c) <= 0xDFFF:
            raise Refusal(f"lone surrogate \\u{ord(c):04x} is not encodable")


def canonical_arguments(value):
    """arguments held to the canonical domain as the engine holds them
    (parseJSON), in document order: no member name twice in an object, no
    fraction or exponent, no integer past the safe range, no lone
    surrogate; the value, as plain JSON, when it holds."""
    if isinstance(value, _Members):
        seen, out = set(), {}
        for key, member in value:
            _whole_scalars(key)
            if key in seen:
                raise Refusal(f"duplicate member name {_go_quote(key)}")
            seen.add(key)
            out[key] = canonical_arguments(member)
        return out
    if isinstance(value, list):
        return [canonical_arguments(member) for member in value]
    if isinstance(value, _Number):
        if value.written_as_float:
            if "." in value:
                raise Refusal("non-integer number is outside the canonical domain")
            raise Refusal("exponent notation is outside the canonical domain")
        number = int(value)
        if abs(number) > MAX_SAFE_INTEGER:
            raise Refusal(f"integer {value} is outside the safe-integer range")
        return number
    if isinstance(value, str):
        _whole_scalars(value)
        return str(value)
    return value


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
        "argumentsCommitment": commitment(salt, "args:", arguments),
        "authority": AUTHORITY,
        "callIndex": index,
        "caller": None,
        "keyId": KEY_ID,
        "kind": "acquisition",
        "prevSignature": prev_signature,
        "receiptVersion": "3",
        # the retained artifact is the result's canonical bytes
        "resultDigest": sha256_of(canonical(result).encode()),
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
    Fault("signature-array", "acquire", ("receipt", "signature"), ["a" * 128], "receipt signature"),
    Fault("result", "acquire", ("result", "arguments"), {"subject": "someone else"}, "result"),
    Fault("result-member", "acquire", ("result", "extra"), 1, "result"),
    Fault("result-synthetic", "acquire", ("result", "synthetic"), 1, "result"),
    Fault("salt-absent", "acquire", ("salts",), {}, "arguments salt"),
    Fault("salt-length", "acquire", ("salts", "args"), "b" * 63, "arguments salt"),
    Fault("salt-alphabet", "acquire", ("salts", "args"), "z" * 64, "arguments salt"),
    Fault("salt-number", "acquire", ("salts", "args"), 5, "arguments salt"),
    Fault("salt-array", "acquire", ("salts", "args"), ["b" * 64], "arguments salt"),
    Fault("act-accepted", "act", (), ACCEPTED_ACT, "act refusal", status=200),
    # a 401 for another reason -- an engine with an identity refusing a
    # request without a token -- which n8n words as it words every 401
    Fault("act-refused-otherwise", "act", (), {"error": "a bearer token from the configured issuer is required"}, "act refusal", status=401, checkers=("activepieces",)),
    Fault("seal-count", "seal", ("finalCount",), 2, "seal count"),
    Fault("seal-count-boolean", "seal", ("finalCount",), True, "seal count"),
    Fault("seal-session", "seal", ("sessionId",), "another-session", "seal session"),
    Fault("seal-signature-case", "seal", ("signature",), "C" * 128, "seal signature"),
    Fault("seal-signature-length", "seal", ("signature",), "c" * 129, "seal signature"),
    Fault("seal-signature-alphabet", "seal", ("signature",), "x" * 128, "seal signature"),
    Fault("seal-signature-null", "seal", ("signature",), None, "seal signature"),
    Fault("seal-signature-array", "seal", ("signature",), ["c" * 128], "seal signature"),
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
