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


MAX_BODY_BYTES = 1 << 20  # the engine's maxRequestBody
MAX_DEPTH = 10000  # Go's decoder, and the engine's canonical parser
_GO_ESCAPES = (("<", "\\u003c"), (">", "\\u003e"), ("&", "\\u0026"), ("\u2028", "\\u2028"), ("\u2029", "\\u2029"))


def _string(text, go):
    out = json.dumps(text, ensure_ascii=False)
    if go:
        for raw, escaped in _GO_ESCAPES:
            out = out.replace(raw, escaped)
    return out


def _write(value, go):
    """value as compact JSON, an object's keys sorted, written iteratively
    however deep it nests: Go's json.Marshal form when go -- which escapes
    <, >, &, U+2028 and U+2029 -- and the canonical form otherwise."""
    out, stack = [], [(False, value)]
    while stack:
        literal, item = stack.pop()
        if literal:
            out.append(item)
        elif isinstance(item, dict):
            parts = [(True, "{")]
            for n, key in enumerate(sorted(item)):
                parts += [(True, ("," if n else "") + _string(key, go) + ":"), (False, item[key])]
            stack.extend(reversed(parts + [(True, "}")]))
        elif isinstance(item, list):
            parts = [(True, "[")]
            for n, member in enumerate(item):
                parts += ([(True, ",")] if n else []) + [(False, member)]
            stack.extend(reversed(parts + [(True, "]")]))
        elif item is True or item is False or item is None:
            out.append({True: "true", False: "false", None: "null"}[item])
        elif isinstance(item, int):
            out.append(str(item))
        elif isinstance(item, str):
            out.append(_string(item, go))
        else:
            raise TypeError(f"not JSON the engine writes: {item!r}")
    return "".join(out)


def go_json(value):
    """value as the engine writes it (Go's json.Marshal): compact, an
    object's keys sorted, no newline after, and <, >, &, U+2028 and U+2029
    escaped."""
    return _write(value, True)


def stamp(at=None):
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(at))


def canonical(value):
    return _write(value, False)


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


class _Text(str):
    """A JSON string as read. Its value keeps each lone surrogate and each
    byte that is not UTF-8 as read; go is what Go's decoder makes of it, each
    replaced by U+FFFD; problem is the first of them, in the engine's
    canonical parser's words, or None."""

    def __new__(cls, text, go, problem):
        read = super().__new__(cls, text)
        read.go = go
        read.problem = problem
        return read


class _Members(list):
    """A JSON object as written: its members in order, duplicates kept."""


_JSON_SPACE = " \t\n\r"
_NUMBER = re.compile(r"-?(?:0|[1-9][0-9]*)(\.[0-9]+)?([eE][+-]?[0-9]+)?")
_ESCAPES = {'"': '"', "\\": "\\", "/": "/", "b": "\b", "f": "\f", "n": "\n", "r": "\r", "t": "\t"}


def _skip(text, i):
    while i < len(text) and text[i] in _JSON_SPACE:
        i += 1
    return i


def _hex4(text, i):
    digits = text[i:i + 4]
    if len(digits) != 4 or any(c not in "0123456789abcdefABCDEF" for c in digits):
        raise Refusal("invalid character in \\u hexadecimal character escape")
    return int(digits, 16)


def _read_string(text, i):
    """The JSON string at text[i], a quotation mark, and where it ends. A
    byte that is not UTF-8 arrives as the body's reading kept it, U+DC80 to
    U+DCFF."""
    i += 1
    value, go, problem = [], [], None
    while True:
        if i >= len(text):
            raise Refusal("unexpected end of JSON input")
        c = text[i]
        if c == '"':
            return _Text("".join(value), "".join(go), problem), i + 1
        if c == "\\":
            e = text[i + 1:i + 2]
            if e in _ESCAPES and e:
                value.append(_ESCAPES[e])
                go.append(_ESCAPES[e])
                i += 2
                continue
            if e != "u":
                raise Refusal(f"invalid character {e!r} in string escape code")
            high = _hex4(text, i + 2)
            i += 6
            if 0xD800 <= high <= 0xDBFF and text.startswith("\\u", i):
                low = _hex4(text, i + 2)
                if 0xDC00 <= low <= 0xDFFF:
                    pair = chr(0x10000 + ((high - 0xD800) << 10) + (low - 0xDC00))
                    value.append(pair)
                    go.append(pair)
                    i += 6
                    continue
            value.append(chr(high))
            if 0xD800 <= high <= 0xDFFF:
                go.append("\ufffd")
                problem = problem or f"lone surrogate \\u{high:04x} is not encodable"
            else:
                go.append(chr(high))
            continue
        if ord(c) < 0x20:
            raise Refusal(f"invalid character {c!r} in string literal")
        value.append(c)
        if 0xDC80 <= ord(c) <= 0xDCFF:
            go.append("\ufffd")
            problem = problem or "invalid UTF-8 in string"
        else:
            go.append(c)
        i += 1


def _read_key(text, i):
    i = _skip(text, i)
    if text[i:i + 1] != '"':
        raise Refusal("invalid character looking for beginning of object key string")
    key, i = _read_string(text, i)
    i = _skip(text, i)
    if text[i:i + 1] != ":":
        raise Refusal("invalid character after object key")
    return key, i + 1


def _read_value(text, i):
    """One JSON value from text at i, read iteratively however deep, and
    where it ends -- to Go's decoder's depth and no further. An object keeps
    its members in order, duplicates included. A refusal here is in words of
    this reader's own, as Go's decoder's are its own."""
    stack = []
    while True:
        i = _skip(text, i)
        if i >= len(text):
            raise Refusal("unexpected end of JSON input")
        c = text[i]
        if c in "{[":
            if len(stack) >= MAX_DEPTH:
                raise Refusal(f"invalid character {c!r} exceeded max depth")
            container, closer = (_Members(), "}") if c == "{" else ([], "]")
            i = _skip(text, i + 1)
            if text[i:i + 1] == closer:
                value, i = container, i + 1
            else:
                stack.append([container, closer, None])
                if closer == "}":
                    stack[-1][2], i = _read_key(text, i)
                continue
        elif c == '"':
            value, i = _read_string(text, i)
        elif c == "-" or c in "0123456789":
            match = _NUMBER.match(text, i)
            if not match:
                raise Refusal("invalid character in numeric literal")
            value, i = _Number(match.group(0), bool(match.group(1) or match.group(2))), match.end()
        elif text.startswith("true", i):
            value, i = True, i + 4
        elif text.startswith("false", i):
            value, i = False, i + 5
        elif text.startswith("null", i):
            value, i = None, i + 4
        else:
            raise Refusal(f"invalid character {c!r} looking for beginning of value")
        while True:
            if not stack:
                return value, i
            frame = stack[-1]
            if frame[1] == "}":
                frame[0].append((frame[2], value))
            else:
                frame[0].append(value)
            i = _skip(text, i)
            if i >= len(text):
                raise Refusal("unexpected end of JSON input")
            if text[i] == ",":
                i += 1
                if frame[1] == "}":
                    frame[2], i = _read_key(text, i)
                break
            if text[i] == frame[1]:
                stack.pop()
                value, i = frame[0], i + 1
                continue
            raise Refusal(f"invalid character {text[i]!r} after {'object key:value pair' if frame[1] == '}' else 'array element'}")


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


def request_fields(body, names):
    """The members of a request body the engine reads, as it reads them:
    at most 1 MiB, one JSON value, decoded into its struct -- names matched
    without regard to case, the last of several taking the place, a null
    leaving a string as it was, a string's lone surrogates and bytes that are
    not UTF-8 each read as U+FFFD, every other member ignored -- then no
    second value. arguments is any JSON value, kept as read for
    canonical_arguments. Each stage refuses before the next, as the engine's
    decoder does."""
    text = body[:MAX_BODY_BYTES].decode("utf-8", "surrogateescape")
    start = _skip(text, 0)
    if start == len(text):
        raise Refusal("http: request body too large" if len(body) > MAX_BODY_BYTES else "EOF")
    try:
        value, end = _read_value(text, start)
    except Refusal as refusal:
        if len(body) > MAX_BODY_BYTES and refusal.message == "unexpected end of JSON input":
            raise Refusal("http: request body too large")
        raise
    fields, mistyped = {}, None
    if value is not None:
        if not isinstance(value, _Members):
            raise Refusal(f"json: cannot unmarshal {_json_type(value)} into Go value of type struct")
        for key, member in value:
            name = next((n for n in names if _fold(key.go) == n), None)
            if name is None:
                continue
            if name == "arguments":
                fields[name] = member
            elif member is None:
                continue
            elif isinstance(member, _Text):
                fields[name] = member.go
            elif mistyped is None:
                mistyped = f"json: cannot unmarshal {_json_type(member)} into Go struct field .{name} of type string"
    if mistyped:
        raise Refusal(mistyped)
    rest = text[end:]
    if not rest.strip(_JSON_SPACE):
        if len(body) > MAX_BODY_BYTES:
            raise Refusal("request body contains trailing content: http: request body too large")
        return fields
    try:
        _read_value(rest, 0)
    except Refusal as refusal:
        raise Refusal(f"request body contains trailing content: {refusal.message}")
    raise Refusal("request body must contain exactly one JSON value")


def _go_quote(text):
    """text as Go's %q quotes it: the named escapes, \\x for another control
    byte, \\u or \\U for a rune that does not print, and the rest as it is."""
    named = {"\a": "\\a", "\b": "\\b", "\f": "\\f", "\n": "\\n", "\r": "\\r", "\t": "\\t", "\v": "\\v", "\\": "\\\\", '"': '\\"'}
    out = []
    for c in text:
        if c in named:
            out.append(named[c])
        elif ord(c) < 0x20 or ord(c) == 0x7F:
            out.append(f"\\x{ord(c):02x}")
        elif not c.isprintable():
            out.append(f"\\u{ord(c):04x}" if ord(c) <= 0xFFFF else f"\\U{ord(c):08x}")
        else:
            out.append(c)
    return '"' + "".join(out) + '"'


def canonical_arguments(value):
    """arguments held to the canonical domain as the engine holds them
    (parseJSON), in document order and iteratively however deep: no byte
    that is not UTF-8, no lone surrogate, no member name twice in an object,
    no fraction or exponent, no integer outside 64 bits or past the safe
    range; the value, as plain JSON, when it holds."""
    stack = [("value", value, None)]
    while stack:
        what, item, seen = stack.pop()
        if what == "key":
            if item.problem:
                raise Refusal(item.problem)
            if str(item) in seen:
                raise Refusal(f"duplicate member name {_go_quote(str(item))}")
            seen.add(str(item))
        elif isinstance(item, _Members):
            names = set()
            for key, member in reversed(item):
                stack += [("value", member, None), ("key", key, names)]
        elif isinstance(item, list):
            stack += [("value", member, None) for member in reversed(item)]
        elif isinstance(item, _Number):
            if item.written_as_float:
                if "." in item:
                    raise Refusal("non-integer number is outside the canonical domain")
                raise Refusal("exponent notation is outside the canonical domain")
            number = int(item)
            if not -(2**63) <= number < 2**63:
                raise Refusal(f"integer {item} is outside the canonical domain")
            if abs(number) > MAX_SAFE_INTEGER:
                raise Refusal(f"integer {item} is outside the safe-integer range")
        elif isinstance(item, _Text) and item.problem:
            raise Refusal(item.problem)
    return _plain(value)


def _plain(value):
    """A value as read, as plain JSON, built iteratively however deep."""
    holder = []
    stack = [(value, holder, None)]
    while stack:
        item, parent, key = stack.pop()
        if isinstance(item, _Members):
            made, children = {}, [(member, None, str(name)) for name, member in item]
        elif isinstance(item, list):
            made, children = [], [(member, None, None) for member in item]
        else:
            made = int(item) if isinstance(item, _Number) else str(item) if isinstance(item, _Text) else item
            children = []
        if isinstance(parent, dict):
            parent[key] = made
        else:
            parent.append(made)
        stack += [(member, made, name) for member, _, name in reversed(children)]
    return holder[0]


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
