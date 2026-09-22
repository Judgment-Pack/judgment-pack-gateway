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
import unicodedata
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


def _read_name(text, i):
    """The member name at text[i] and where it ends, the colon after it left
    where it is: the engine's decoder hands a name over as soon as it has
    read it, and what the reader of the envelope does with the name -- admit
    it, or refuse the body for it -- is decided before the colon is looked
    for. A body that ends where a token is wanted is the end of the stream
    to that decoder, which says so in that one word."""
    i = _skip(text, i)
    if i >= len(text):
        raise Refusal("EOF")
    if text[i:i + 1] != '"':
        raise Refusal("invalid character looking for beginning of object key string")
    return _read_string(text, i)


def _read_colon(text, i):
    """Past the colon that follows a member name in the envelope, where the
    decoder is reading a token at a time and says what it expected. Inside a
    member's value the scanner reads instead, and says what it found
    (_read_key)."""
    i = _skip(text, i)
    if i >= len(text):
        raise Refusal("EOF")
    if text[i:i + 1] != ":":
        raise Refusal("expected colon after object key")
    return i + 1


def _read_key(text, i):
    key, i = _read_name(text, i)
    i = _skip(text, i)
    if i >= len(text):
        raise Refusal("EOF")
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


def _ended_mid_value(message):
    """A body that ends inside a value, said as the engine's decoder says it:
    a value it had begun to read and could not finish is an unexpected end,
    where a body that ends between tokens is simply the end of the stream
    (_read_key, and the walk's own check before a value begins)."""
    return "unexpected EOF" if message == "unexpected end of JSON input" else message


def request_fields(body, names):
    """The members of a request body the endpoint reads, as the engine reads
    them (requestMembers): at most 1 MiB, one JSON object, walked member by
    member in the order written -- a name that is not exactly one of names
    refuses the body, and so does a name given twice, each before that
    member's value is read at all -- then nothing but whitespace after the
    object, and only then the members themselves, in the order the endpoint's
    handler reads them. A member the handler reads as a string that holds
    something else refuses the body; one that holds null, like one that is
    absent, leaves the endpoint an empty string. A string's lone surrogates
    and bytes that are not UTF-8 arrive as U+FFFD, which is what the name
    quoted in a refusal is made of too. arguments is any JSON value, kept as
    read for canonical_arguments, and null there is kept as null. Each stage
    refuses before the next, as the engine does: what the body is, then what
    it names, then what follows it, then what its members hold.

    names is the endpoint's own set, in its handler's order: the engine gives
    /acquire session, source and arguments and /seal session alone, and an
    action's body is never read here at all (an engine with no identity
    refuses it at the requester)."""
    text = body[:MAX_BODY_BYTES].decode("utf-8", "surrogateescape")
    over = len(body) > MAX_BODY_BYTES

    def ended():
        # The body's bound is reached by reading, so where the truncated text
        # runs out is where the engine's reader reports the bound. Below the
        # bound, a body that ends where a token is wanted is the end of the
        # stream, which the decoder says in that one word (_ended_mid_value
        # has the other case).
        raise Refusal("http: request body too large" if over else "EOF")

    i = _skip(text, 0)
    if i == len(text):
        ended()
    try:
        # The decoder reads the first token, and an object is what the
        # endpoint takes. An array is refused by that first delimiter, with
        # nothing inside it read; any other value is read whole first, so a
        # literal it cannot read is refused in the decoder's own words.
        if text[i] != "{":
            if text[i] != "[":
                _read_value(text, i)
            raise Refusal("request body must be a JSON object")
        fields, taken = {}, []
        i = _skip(text, i + 1)
        if i >= len(text):
            ended()
        if text[i] != "}":
            while True:
                # The name is judged as soon as it has been read: what
                # follows it -- the colon, the value, the rest of the body --
                # is never reached for a name this endpoint will not admit.
                key, i = _read_name(text, i)
                name = str(key.go)
                if name in taken:
                    raise Refusal(f"member {_go_quote(request_text(name))} appears twice")
                if name not in names:
                    raise Refusal("request body carries a member this endpoint does not read: " + request_text(name))
                taken.append(name)
                i = _read_colon(text, i)
                i = _skip(text, i)
                if i >= len(text):
                    ended()  # the member's value never began
                fields[name], i = _read_value(text, i)
                i = _skip(text, i)
                if i >= len(text):
                    ended()
                if text[i] == ",":
                    i = _skip(text, i + 1)
                    continue
                if text[i] == "}":
                    i += 1
                    break
                raise Refusal("invalid character %r after object key:value pair" % text[i])
        else:
            i += 1
    except Refusal as refusal:
        if over and refusal.message in ("EOF", "unexpected end of JSON input"):
            raise Refusal("http: request body too large")
        raise Refusal(_ended_mid_value(refusal.message))
    rest = text[i:]
    j = _skip(rest, 0)
    if j < len(rest):
        # What follows is judged by one token, as the engine judges it: an
        # object or an array is a second value at its opening delimiter,
        # whatever it holds, and anything else is read whole to tell a
        # second value from bytes that are no value at all.
        if rest[j] not in "{[":
            try:
                _read_value(rest, j)
            except Refusal as refusal:
                # What is after the object is read under the same bound as
                # what is inside it: a trailing value the bound cuts short is
                # the bound, not the end of the body.
                if over and refusal.message in ("EOF", "unexpected end of JSON input"):
                    raise Refusal("request body contains trailing content: http: request body too large")
                raise Refusal("request body contains trailing content: " + _ended_mid_value(refusal.message))
        raise Refusal("request body must contain exactly one JSON value")
    if over:
        raise Refusal("request body contains trailing content: http: request body too large")
    read = {}
    for name in names:
        if name == "arguments":
            if name in fields:
                read[name] = fields[name]
            continue
        member = fields.get(name)
        if member is None:  # absent, or null, which leaves the string empty
            continue
        if not isinstance(member, _Text):
            raise Refusal(f"member {_go_quote(name)}: json: cannot unmarshal {_json_type(member)} into Go value of type string")
        read[name] = member.go
    return read


def source_output_problem(arguments):
    """What the engine makes of the synthetic source's own output when the
    arguments it echoes nest as deep as the engine's parser descends: the
    source writes the result with the arguments inside it, one level deeper
    than they arrived, so arguments the request admitted at exactly that
    depth are past it once the source has written them into a result, and
    the acquisition fails on the source's output rather than on its request.
    The position is the engine's parser's own: the byte of the bracket it
    would have descended into. None when the output is one the engine
    reads."""
    raw = ('{"synthetic":true,"arguments":' + canonical(arguments) + "}").encode()
    depth, i = 0, 0
    while i < len(raw):
        c = raw[i:i + 1]
        if c == b'"':
            i += 1
            while i < len(raw) and raw[i:i + 1] != b'"':
                i += 2 if raw[i:i + 1] == b"\\" else 1
        elif c in b"{[":
            if depth >= MAX_DEPTH:
                return f"source did not return a canonical JSON value: nesting deeper than {MAX_DEPTH} levels at {i}"
            depth += 1
        elif c in b"}]":
            depth -= 1
        i += 1
    return None


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


def _printable(text):
    """text as the engine makes it printable (printableText): every control
    character -- C0, DEL and the C1 range -- and every byte that is not part
    of a valid UTF-8 sequence replaced by '?', one '?' for one byte, so what
    is quoted is as many bytes as what was sent. What prints is left as it
    was, outside ASCII included."""
    out = []
    for c in text:
        if 0xDC80 <= ord(c) <= 0xDCFF:  # one byte the body's reading kept
            out.append("?")
        elif unicodedata.category(c) == "Cc":
            out.append("?" * len(c.encode("utf-8")))
        else:
            out.append(c)
    return "".join(out)


def request_text(text):
    """The engine's requestText: the text made printable, then a UTF-8 prefix
    of at most 64 bytes of it, and how many bytes the whole was."""
    text = _printable(text)
    raw = text.encode("utf-8")
    if len(raw) <= 64:
        return text
    return raw[:64].decode("utf-8", errors="ignore") + f"…({len(raw)} bytes)"


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
                raise Refusal(f"duplicate member name {_go_quote(request_text(str(item)))}")
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
            # past 19 digits no literal is a 64-bit integer, and Python would
            # refuse to convert a long enough one at all
            number = int(item) if len(item.lstrip("-")) <= 19 else None
            if number is None or not -(2**63) <= number < 2**63:
                raise Refusal(f"integer {request_text(item)} is outside the canonical domain")
            if abs(number) > MAX_SAFE_INTEGER:
                raise Refusal(f"integer {request_text(item)} is outside the safe-integer range")
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
