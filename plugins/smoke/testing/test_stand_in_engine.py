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
(a body that is not JSON, or not an object), the status, the headers but the
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
import answers  # noqa: E402
from harness import Engine, StandIn, early_act, exchange, raw_exchange  # noqa: E402

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
    ("a seal", seal({"session": "diff-1"})),
    ("a second seal, its member in another case", seal({"SESSION": "diff-1"})),
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
# the refusals whose words are Go's JSON decoder's own
DECODER_WORDS = {
    "an acquisition whose body is not JSON",
    "an acquisition whose body is not an object",
    "a seal whose body is not JSON",
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
