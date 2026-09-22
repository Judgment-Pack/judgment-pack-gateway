"""The stand-in engine (stand_in_engine.py) held to the engine it stands in
for: the same requests, in the same order, sent to the engine as
plugins/smoke/README.md starts it and to the stand-in, and the answers
compared -- the status, the headers a comparison reads (harness.HEADERS),
every body member, and the bytes of every refusal.

What the engine derives from its key, its seed or the clock is compared by
its form, at its place in the answer, and by how it relates to the rest:
a key id is the first half of the SHA-256 of the key, a receipt's
prevSignature is its session's last signature, an arguments commitment is
recomputed from the salt the answer carries (SPEC.md §1.2a), a result digest
from the result, and times parse and never run backward. Everything else --
the result digest and the adapter digest included, which the seed does not
touch -- is compared exactly. Where the words are Go's JSON decoder's own
(a body that is not JSON at all), the status, the headers but the
length, and that the error is a string are compared, and not the words.

The engine is the binary GATEWAY_BIN names. Without one the comparison
skips, unless SMOKE_REQUIRE_ENGINE is set -- as CI sets it where it builds
the engine -- and then it fails. The fault and --require-length tests below
need no engine.
"""
import datetime
import hashlib
import json
import os
import re
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
# answers nested hundreds deep are formed and written here recursively
sys.setrecursionlimit(20000)
import answers  # noqa: E402
from harness import Engine, StandIn, early_act, exchange, raw_exchange, unfinished_upload  # noqa: E402

HEX = {n: re.compile(f"[0-9a-f]{{{n}}}") for n in (32, 64, 128)}
SHA256 = re.compile(r"sha256:[0-9a-f]{64}")
STAMP = re.compile(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ")
# the members the engine derives from its key, its seed or the clock, by
# their place in an answer, and the form each must have
FORMS = {
    ("keyId",): HEX[32],
    ("publicKey",): HEX[64],
    ("signature",): HEX[128],
    ("sealedAt",): STAMP,
    ("receipt", "signature"): HEX[128],
    ("receipt", "prevSignature"): HEX[128],
    ("receipt", "keyId"): HEX[32],
    ("receipt", "argumentsCommitment"): SHA256,
    ("receipt", "servedAt"): STAMP,
    ("receipt", "acquisition", "observedAt"): STAMP,
    ("salts", "args"): HEX[64],
}
CLOCK = {("sealedAt",), ("receipt", "servedAt"), ("receipt", "acquisition", "observedAt")}


def acquire(body=None, raw=None, **kw):
    return lambda p: exchange(p, "POST", "/acquire", body, raw=raw, **kw)


def seal(body=None, raw=None):
    return lambda p: exchange(p, "POST", "/seal", body, raw=raw)


def arguments(literal):
    return acquire(raw=b'{"session":"diff-1","source":"screening","arguments":' + literal + b"}")


# (what it is, how it is sent), in the order sent
REQUESTS = (
    ("the key document", lambda p: exchange(p, "GET", "/publickey")),
    ("the key document, asked for its head", lambda p: raw_exchange(p, b"HEAD /publickey HTTP/1.1\r\nHost: engine\r\nConnection: close\r\n\r\n")),
    ("the key document, asked by POST", lambda p: exchange(p, "POST", "/publickey")),
    ("the key document, asked with a query", lambda p: exchange(p, "GET", "/publickey?x=1")),
    ("an acquisition", acquire({"session": "diff-1", "source": "screening", "arguments": {"subject": "acme"}})),
    ("an acquisition without arguments", acquire({"session": "diff-1", "source": "screening"})),
    ("an acquisition with null arguments", acquire({"session": "diff-1", "source": "screening", "arguments": None})),
    ("an acquisition with a member the engine does not read", acquire({"session": "diff-1", "source": "screening", "arguments": "acme", "extra": 1.5})),
    ("an acquisition with its members in other cases", acquire({"Session": "diff-1", "SOURCE": "screening", "Arguments": {"a": 1}})),
    ("an acquisition naming its session twice", acquire(raw=b'{"session":"../x","session":"diff-1","source":"screening"}')),
    ("an acquisition whose session is null", acquire(raw=b'{"session":"diff-1","session":null,"source":"screening"}')),
    ("an acquisition naming its source twice, the same both times", acquire(raw=b'{"session":"diff-1","source":"screening","source":"screening"}')),
    ("an acquisition naming its arguments twice", acquire(raw=b'{"session":"diff-1","source":"screening","arguments":{},"arguments":{}}')),
    ("a member the engine does not read before a mistyped one", acquire(raw=b'{"extra":1,"session":3,"source":"screening"}')),
    ("a mistyped member before one the engine does not read", acquire(raw=b'{"session":3,"extra":1,"source":"screening"}')),
    ("a member the engine does not read before a value that is not JSON", acquire(raw=b'{"extra": x}')),
    ("mistyped members, answered in the order the handler reads them", acquire(raw=b'{"source":5,"session":true}')),
    ("a member the engine does not read at its quotation bound", acquire(raw=b'{"session":"diff-1","' + b"a" * 64 + b'":1}')),
    ("a member the engine does not read past its quotation bound", acquire(raw=b'{"session":"diff-1","' + b"a" * 65 + b'":1}')),
    ("a member the engine does not read, split within a UTF-8 sequence", acquire(raw='{"session":"diff-1","'.encode() + ("a" * 63 + "界").encode() + b'":1}')),
    ("a member the engine does not read whose name is empty", acquire(raw=b'{"":1}')),
    ("a member the engine does not read whose name carries an escape sequence", acquire(raw=b'{"session":"diff-1","\\u001b]0;changed\\u0007":1}')),
    ("a source whose name carries an escape sequence", acquire(raw=b'{"session":"diff-1","source":"\\u001b]0;changed\\u0007"}')),
    ("a source whose name carries a byte that is not UTF-8", acquire(raw=b'{"session":"diff-1","source":"a\xffb"}')),
    ("a body that ends after a member the engine does not read", acquire(raw=b'{"extra"')),
    ("a body that ends after a member named twice", acquire(raw=b'{"session":"a","session"')),
    ("no colon after a member the engine reads", acquire(raw=b'{"session" 1}')),
    ("no colon after a member the engine does not read", acquire(raw=b'{"extra" 1}')),
    ("a number no float64 holds, as the body", acquire(raw=b"1e1000")),
    ("a number of ten thousand digits, as the body", acquire(raw=b"9" * 10000)),
    ("a number no float64 holds, after the object", acquire(raw=b'{"session":"diff-1"} 1e1000')),
    ("a number of ten thousand digits, after the object", acquire(raw=b'{"session":"diff-1"} ' + b"9" * 10000)),
    ("arguments at the largest safe integer", arguments(b"9007199254740991")),
    ("arguments of minus zero", arguments(b"-0")),
    ("arguments with a fraction", arguments(b"1.5")),
    ("arguments with a fraction written whole", arguments(b"1.0")),
    ("arguments with an exponent", arguments(b"1e2")),
    ("arguments past the safe range", arguments(b"9007199254740992")),
    ("arguments below the safe range", arguments(b"-9007199254740992")),
    ("arguments naming a member twice", arguments(b'{"x":1,"x":2}')),
    ("arguments naming a member twice, deeper", arguments(b'[{"a":{"x":1,"x":2}}]')),
    ("arguments with a lone surrogate", arguments(b'"\\ud800"')),
    ("arguments refused before the session", acquire(raw=b'{"session":"../x","source":"screening","arguments":1.5}')),
    ("a fraction written with an exponent", arguments(b"1.5e2")),
    ("a bad number before a duplicate name", arguments(b'{"x":1.5,"x":2}')),
    ("a duplicate name before a bad number", arguments(b'{"x":1,"x":1.5}')),
    ("a duplicate name that is a control character", arguments(b'{"\\n":1,"\\n":2}')),
    ("arguments past 64 bits", arguments(b"9223372036854776000")),
    ("arguments with a byte that is not UTF-8", arguments(b'"\xff"')),
    ("arguments nested 600 deep", acquire(raw=b'{"session":"diff-600","source":"screening","arguments":' + b"[" * 600 + b"]" * 600 + b"}")),
    ("arguments nested as deep as the engine takes", acquire(raw=b'{"session":"diff-deep","source":"screening","arguments":' + b"[" * 9999 + b"]" * 9999 + b"}", parse=False)),
    # A member's value is read as a value of its own, so the decoder's depth
    # is the depth of the arguments themselves: at exactly that depth the
    # request is admitted and the source's own echo is what the engine
    # cannot read, one level deeper.
    ("arguments nested as deep as the engine reads but deeper than its source writes", acquire(raw=b'{"session":"diff-deep","source":"screening","arguments":' + b"[" * 10000 + b"]" * 10000 + b"}")),
    ("arguments nested past the engine's depth", acquire(raw=b'{"session":"diff-deep","source":"screening","arguments":' + b"[" * 10001 + b"]" * 10001 + b"}")),
    ("a body past 1 MiB", acquire(raw=b'{"session":"diff-big","source":"screening","arguments":"' + b"a" * (1 << 20) + b'"}')),
    ("a trailing value that crosses the bound", acquire(raw=b'{"session":"diff-1"} "' + b"a" * (1 << 20))),
    # A scalar the bound cuts short is the bound, wherever it stands: the
    # digits of a number, or a string stopped inside an escape, end where
    # the reading was stopped and not where they were written to end.
    ("a number longer than the bound, as the body", acquire(raw=b"9" * ((1 << 20) + 1))),
    ("a number longer than the bound, after the object", acquire(raw=b'{"session":"diff-1"} ' + b"9" * ((1 << 20) + 1))),
    ("a trailing string the bound cuts inside an escape", acquire(raw=b'{"session":"diff-1"} "' + b"a" * ((1 << 20) - 23) + b'\\u0041"')),
    ("a body past 1 MiB whose rest never arrives", lambda p: unfinished_upload(p, "/acquire", 2 << 20, b'{"session":"diff-big","source":"screening","arguments":"' + b"a" * ((1 << 20) + 10))),
    ("an integer 5000 digits long", arguments(b"9" * 5000)),
    ("a duplicate name at its quotation bound", arguments(b'{"' + b'a' * 64 + b'":1,"' + b'a' * 64 + b'":2}')),
    ("a duplicate name past its quotation bound", arguments(b'{"' + b'a' * 65 + b'":1,"' + b'a' * 65 + b'":2}')),
    ("a source at its quotation bound", acquire({"session": "diff-2", "source": "a" * 64})),
    ("a source past its quotation bound", acquire({"session": "diff-2", "source": "a" * 65})),
    ("a source split within a UTF-8 sequence", acquire({"session": "diff-2", "source": "a" * 63 + "界"})),
    ("a seal of a long session not held", seal({"session": "a" * 128})),
    ("an acquisition into a long session", acquire({"session": "a" * 128, "source": "screening"})),
    ("a seal of a long session", seal({"session": "a" * 128})),
    ("a second seal of a long session", seal({"session": "a" * 128})),
    ("an acquisition into a long sealed session", acquire({"session": "a" * 128, "source": "screening"})),
    ("a source with a lone surrogate", acquire(raw=b'{"session":"diff-2","source":"\\ud800"}')),
    ("a source with a byte that is not UTF-8", acquire(raw=b'{"session":"diff-2","source":"\xff"}')),
    ("a body that is null", acquire(raw=b"null")),
    ("a body that is a bare string", acquire(raw=b'"diff-1"')),
    ("a mistyped member before a second value", acquire(raw=b'{"session":3} {}')),
    ("a session refused before the source", acquire({"session": "../x", "source": "elsewhere"})),
    ("a source the engine does not have", acquire({"session": "diff-2", "source": "elsewhere", "arguments": {}})),
    ("a session that is not a flat token", acquire({"session": "../x", "source": "screening", "arguments": {}})),
    ("no session", acquire({"source": "screening"})),
    ("a session that is not a string", acquire(raw=b'{"session":5,"source":"screening"}')),
    ("a body with a second value", acquire(raw=b'{"session":"diff-1","source":"screening"} {}')),
    ("an empty body", acquire(raw=b"")),
    ("an acquisition whose body is not JSON", acquire(raw=b"nope")),
    ("an acquisition whose body is not an object", acquire(raw=b"[1]")),
    ("an action", lambda p: exchange(p, "POST", "/act", {"session": "diff-1", "platform": "tickets", "tool": "update_ticket", "arguments": {}})),
    ("an action whose body is not JSON", lambda p: exchange(p, "POST", "/act", raw=b"nope")),
    ("an action sent chunked", lambda p: exchange(p, "POST", "/act", {"session": "diff-1"}, chunked=True)),
    ("an action whose body has not arrived", early_act),
    ("a seal of a session the engine does not hold", seal({"session": "diff-none"})),
    ("a seal with a member it does not read", seal({"session": "diff-none", "source": "screening"})),
    ("a seal with a member it does not read, not a string", seal({"session": "diff-none", "source": 5})),
    ("a seal naming its session twice", seal(raw=b'{"session":"diff-none","session":"diff-none"}')),
    ("a seal carrying the arguments member /acquire reads", seal({"session": "diff-none", "arguments": {}})),
    ("a seal", seal({"session": "diff-1"})),
    ("an acquisition into a session about to be sealed", acquire({"session": "diff-sealed", "source": "screening", "arguments": {}})),
    ("a seal of that session", seal({"session": "diff-sealed"})),
    # The sealed session is refused before the source exists, so what the
    # source would have written of arguments this deep is never read.
    ("arguments at the parser's depth into a sealed session", acquire(raw=b'{"session":"diff-sealed","source":"screening","arguments":' + b"[" * 10000 + b"]" * 10000 + b"}")),
    ("a seal whose session member is in another case", seal({"SESSION": "diff-1"})),
    ("an acquisition into a sealed session", acquire({"session": "diff-1", "source": "screening", "arguments": {}})),
    ("an unknown source into a sealed session", acquire({"session": "diff-1", "source": "elsewhere"})),
    ("a seal whose body is not JSON", seal(raw=b"nope")),
    ("a read of a route that takes a POST", lambda p: exchange(p, "GET", "/acquire")),
    ("a route asked with a query", lambda p: exchange(p, "GET", "/acquire?x=1")),
    ("another method on a route", lambda p: exchange(p, "PUT", "/acquire")),
    ("a path the engine does not route", lambda p: exchange(p, "GET", "/nowhere")),
    ("another method on a path not routed", lambda p: exchange(p, "DELETE", "/nowhere")),
    ("a path under a route", lambda p: exchange(p, "POST", "/acquire/", {"session": "diff-1"})),
)
# the refusals whose words are Go's JSON decoder's own, and an answer nested
# past what Python's json module reads, whose body is left unread. A body
# that is not an object is not among them: the engine judges that at the
# first token, and says so in words of its own.
DECODER_WORDS = {
    "an acquisition whose body is not JSON",
    "a seal whose body is not JSON",
    "arguments nested as deep as the engine takes",
}


def formed(value, path=()):
    """value with each derived member replaced by the name of its form, at its
    place, or by what is wrong with it."""
    if isinstance(value, dict):
        out = {}
        for key, member in value.items():
            here = path + (key,)
            form = FORMS.get(here)
            if form is None:
                out[key] = formed(member, here)
            elif member is None and key == "prevSignature":
                out[key] = None
            elif isinstance(member, str) and form.fullmatch(member):
                out[key] = f"<{key}>"
            else:
                out[key] = f"<{key} NOT OF ITS FORM: {member!r}>"
        return out
    if isinstance(value, list):
        return [formed(v, path) for v in value]
    return value


def comparable(answer, words=True):
    """An answer as compared: JSON text, so true and 1 differ. Without its
    words, a decoder's refusal is compared by its status, its headers but the
    length, and that its error is a string."""
    status, headers, body = answer.get("status"), dict(answer.get("headers") or {}), answer.get("body")
    if not words:
        headers.pop("Content-Length", None)
        if isinstance(body, dict) and isinstance(body.get("error"), str):
            body = {**body, "error": "<the decoder's words>"}
    return json.dumps({"status": status, "early": answer.get("early"), "headers": headers, "body": formed(body)}, sort_keys=True, indent=1)


def transcript(port):
    return [(what, send(port)) for what, send in REQUESTS]


def when(stamp):
    return datetime.datetime.strptime(stamp, "%Y-%m-%dT%H:%M:%SZ")


def relations(test, answers_by_request, whose):
    """What a transcript's derived members must be to one another."""
    document = dict(answers_by_request)["the key document"]["body"]
    key = document["keyId"]
    test.assertEqual(key, hashlib.sha256(bytes.fromhex(document["publicKey"])).hexdigest()[:32], f"{whose}: the key id is not the key's")
    last, served, latest = {}, {}, datetime.datetime.min
    for what, answer in answers_by_request:
        body = answer.get("body")
        if answer.get("status") != 200 or not isinstance(body, dict):
            continue
        receipt = body.get("receipt")
        if receipt:
            test.assertEqual(receipt["keyId"], key, f"{whose}: {what}: the receipt's key id is not the key document's")
            session = receipt["sessionId"]
            test.assertEqual(receipt["prevSignature"], last.get(session), f"{whose}: {what}: prevSignature is not the session's last signature")
            last[session] = receipt["signature"]
            result = body["result"]
            test.assertEqual(receipt["resultDigest"], answers.sha256_of(answers.canonical(result).encode()), f"{whose}: {what}: the result digest is not the result's")
            test.assertEqual(receipt["argumentsCommitment"], answers.commitment(body["salts"]["args"], "args:", result["arguments"]), f"{whose}: {what}: the commitment is not the arguments'")
            observed, at = when(receipt["acquisition"]["observedAt"]), when(receipt["servedAt"])
            test.assertLessEqual(observed, at, f"{whose}: {what}: observed after it was served")
            test.assertLessEqual(latest, at, f"{whose}: {what}: served before an earlier answer")
            latest = at
            served.setdefault(session, []).append(at)
        if "finalCount" in body:
            test.assertEqual(body["keyId"], key, f"{whose}: {what}: the seal's key id is not the key document's")
            sealed = when(body["sealedAt"])
            test.assertTrue(all(at <= sealed for at in served.get(body["sessionId"], [])), f"{whose}: {what}: sealed before a receipt was served")
            latest = max(latest, sealed)


class FormTest(unittest.TestCase):
    """A member is formed by its place in an answer, never by its name: a
    member the source echoes back, named as a derived one is named, is
    compared exactly."""

    def test_a_derived_members_name_elsewhere_is_compared_exactly(self):
        base = {
            "result": {"arguments": {"signature": "a" * 128, "keyId": "b" * 32, "sealedAt": "2026-01-01T00:00:00Z", "args": "c" * 64}},
            "receipt": {"signature": "d" * 128},
        }
        for name, other in (("signature", "e" * 128), ("keyId", "f" * 32), ("sealedAt", "2026-01-02T00:00:00Z"), ("args", "0" * 64)):
            with self.subTest(name=name):
                changed = json.loads(json.dumps(base))
                changed["result"]["arguments"][name] = other
                self.assertNotEqual(formed(changed), formed(base))
        derived = json.loads(json.dumps(base))
        derived["receipt"]["signature"] = "9" * 128
        self.assertEqual(formed(derived), formed(base))


class StandInTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.binary = os.environ.get("GATEWAY_BIN")
        why = None
        if not cls.binary:
            why = "GATEWAY_BIN names no engine binary"
        elif not os.access(cls.binary, os.X_OK):
            why = f"GATEWAY_BIN is not an executable: {cls.binary}"
        elif sys.platform == "win32":
            why = "the synthetic source is a shell script"
        if why:
            if os.environ.get("SMOKE_REQUIRE_ENGINE"):
                raise AssertionError("the stand-in cannot be held to the engine: " + why)
            raise unittest.SkipTest(why)

    def test_the_stand_in_answers_as_the_engine_does(self):
        with Engine(self.binary) as engine:
            theirs = transcript(engine.port)
        with StandIn() as stand_in:
            ours = transcript(stand_in.port)
        relations(self, theirs, "the engine")
        relations(self, ours, "the stand-in")
        for (what, engine_answer), (_, stand_in_answer) in zip(theirs, ours):
            with self.subTest(request=what):
                words = what not in DECODER_WORDS
                self.assertEqual(comparable(stand_in_answer, words), comparable(engine_answer, words))
                if words and engine_answer["status"] != 200:
                    self.assertEqual(stand_in_answer["text"], engine_answer["text"], "the words differ")
                for whose, answer in (("the engine", engine_answer), ("the stand-in", stand_in_answer)):
                    if answer["status"] == 200 and isinstance(answer["body"], dict):
                        self.assertEqual(answer["text"], answers.go_json(answer["body"]), f"{whose}: not the engine's JSON form")


def unclocked(value, path=()):
    """value with the members the clock sets replaced, and nothing else."""
    if isinstance(value, dict):
        return {k: ("<clock>" if path + (k,) in CLOCK else unclocked(v, path + (k,))) for k, v in value.items()}
    if isinstance(value, list):
        return [unclocked(v, path) for v in value]
    return value


def exact(answer):
    return json.dumps({"status": answer["status"], "headers": answer["headers"], "body": unclocked(answer["body"])}, sort_keys=True, indent=1)


def differences(a, b, path=()):
    """Every place two JSON values differ, as paths; a member one of them
    lacks differs at its own path."""
    if isinstance(a, dict) and isinstance(b, dict):
        out = set()
        for key in set(a) | set(b):
            if key not in a or key not in b:
                out.add(path + (key,))
            else:
                out |= differences(a[key], b[key], path + (key,))
        return out
    if isinstance(a, list) and isinstance(b, list) and len(a) == len(b):
        out = set()
        for i, (x, y) in enumerate(zip(a, b)):
            out |= differences(x, y, path + (i,))
        return out
    return set() if json.dumps(a, sort_keys=True) == json.dumps(b, sort_keys=True) else {path}


def at(value, path):
    for key in path:
        value = value[key]
    return value


class FaultTest(unittest.TestCase):
    """Each fault changes the member it names and no other: the stand-in's
    answers to the smoke's requests with the fault and without it are the
    same, headers and every member, but for what the clock sets -- and at the
    fault's route they differ at that member alone, or, for a fault with a
    status, are that status and body."""

    FLOW = (
        ("publickey", lambda p, s: exchange(p, "GET", "/publickey")),
        ("acquire", lambda p, s: exchange(p, "POST", "/acquire", {"session": s, "source": "screening", "arguments": {"subject": "acme"}})),
        ("act", lambda p, s: exchange(p, "POST", "/act", {"session": s})),
        ("seal", lambda p, s: exchange(p, "POST", "/seal", {"session": s})),
    )

    def flow(self, *flags):
        with StandIn(*flags) as stand_in:
            return {route: send(stand_in.port, "fault-flow") for route, send in self.FLOW}

    def test_each_fault_changes_its_member_and_no_other(self):
        right = self.flow()
        for fault in answers.FAULTS:
            with self.subTest(fault=fault.name):
                wrong = self.flow("--fault", fault.name)
                for route in right:
                    if route != fault.route:
                        self.assertEqual(exact(wrong[route]), exact(right[route]), f"{fault.name} changed {route}")
                        continue
                    if fault.status:
                        self.assertEqual(wrong[route]["status"], fault.status)
                        self.assertEqual(json.dumps(wrong[route]["body"], sort_keys=True), json.dumps(fault.value, sort_keys=True))
                        continue
                    # judged without answers.apply, the stand-in's own
                    # means: every difference is at or below the fault's
                    # member, which holds the fault's value
                    self.assertEqual(wrong[route]["status"], right[route]["status"])
                    self.assertEqual({k: v for k, v in wrong[route]["headers"].items() if k != "Content-Length"}, {k: v for k, v in right[route]["headers"].items() if k != "Content-Length"})
                    changed = differences(unclocked(wrong[route]["body"]), unclocked(right[route]["body"]))
                    self.assertTrue(changed, f"{fault.name} changed nothing")
                    self.assertTrue(all(p[:len(fault.path)] == fault.path for p in changed), f"{fault.name} changed {sorted(map(str, changed))}")
                    self.assertEqual(json.dumps(at(wrong[route]["body"], fault.path), sort_keys=True), json.dumps(fault.value, sort_keys=True))


class RequireLengthTest(unittest.TestCase):
    def test_a_chunked_body_is_refused_before_any_route_answers(self):
        with StandIn("--require-length") as stand_in:
            for path in ("/acquire", "/act", "/seal"):
                with self.subTest(path=path):
                    self.assertEqual(exchange(stand_in.port, "POST", path, {"session": "s"}, chunked=True)["status"], 411)
            answer = exchange(stand_in.port, "POST", "/acquire", {"session": "s", "source": "screening", "arguments": {}})
            self.assertEqual(answer["status"], 200, answer)


if __name__ == "__main__":
    unittest.main()
