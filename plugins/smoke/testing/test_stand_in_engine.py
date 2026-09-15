"""The stand-in engine (stand_in_engine.py) held to the engine it stands in
for: the same requests, in the same order, sent to the engine as
plugins/smoke/README.md starts it and to the stand-in, and the answers
compared -- the status, the headers a client reads, and the body member
for member. What the engine derives from its key, its seed and the clock
(signatures, digests, key ids, salts, times) is compared by its form and by
how it relates to the rest: a receipt's and a seal's key id are the key
document's, a receipt's prevSignature is its session's last signature.
Everything else is compared exactly, the words of every refusal included,
except where the words are the JSON decoder's own.

The engine is the binary GATEWAY_BIN names. Without one the test skips,
unless SMOKE_REQUIRE_ENGINE is set -- as CI sets it where it builds the
engine -- and then it fails.
"""
import json
import os
import re
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import answers  # noqa: E402
from harness import Engine, StandIn, early_act, exchange  # noqa: E402

HEX = {n: re.compile(f"[0-9a-f]{{{n}}}") for n in (32, 64, 128)}
SHA256 = re.compile(r"sha256:[0-9a-f]{64}")
STAMP = re.compile(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ")
# the members whose values the engine derives from its key, its seed or the
# clock, and the form each must have
FORMS = {
    "signature": HEX[128],
    "prevSignature": HEX[128],
    "keyId": HEX[32],
    "publicKey": HEX[64],
    "args": HEX[64],
    "argumentsCommitment": SHA256,
    "resultDigest": SHA256,
    "digest": SHA256,
    "servedAt": STAMP,
    "observedAt": STAMP,
    "sealedAt": STAMP,
}

# (what it is, how it is sent); the words of a refusal from the JSON decoder
# are the decoder's, and are not compared
REQUESTS = (
    ("the key document", lambda p: exchange(p, "GET", "/publickey")),
    ("an acquisition", lambda p: exchange(p, "POST", "/acquire", {"session": "diff-1", "source": "screening", "arguments": {"subject": "acme"}})),
    ("an acquisition without arguments", lambda p: exchange(p, "POST", "/acquire", {"session": "diff-1", "source": "screening"})),
    ("an acquisition with null arguments", lambda p: exchange(p, "POST", "/acquire", {"session": "diff-1", "source": "screening", "arguments": None})),
    ("an acquisition with a member the engine does not read", lambda p: exchange(p, "POST", "/acquire", {"session": "diff-1", "source": "screening", "arguments": "acme", "extra": 1})),
    ("a source the engine does not have", lambda p: exchange(p, "POST", "/acquire", {"session": "diff-2", "source": "elsewhere", "arguments": {}})),
    ("a session that is not a flat token", lambda p: exchange(p, "POST", "/acquire", {"session": "../x", "source": "screening", "arguments": {}})),
    ("no session", lambda p: exchange(p, "POST", "/acquire", {"source": "screening"})),
    ("an acquisition whose body is not JSON", lambda p: exchange(p, "POST", "/acquire", raw=b"nope")),
    ("an action", lambda p: exchange(p, "POST", "/act", {"session": "diff-1", "platform": "tickets", "tool": "update_ticket", "arguments": {}})),
    ("an action whose body is not JSON", lambda p: exchange(p, "POST", "/act", raw=b"nope")),
    ("an action sent chunked", lambda p: exchange(p, "POST", "/act", {"session": "diff-1"}, chunked=True)),
    ("an action whose body has not arrived", early_act),
    ("a seal of a session the engine does not hold", lambda p: exchange(p, "POST", "/seal", {"session": "diff-none"})),
    ("a seal", lambda p: exchange(p, "POST", "/seal", {"session": "diff-1"})),
    ("a second seal", lambda p: exchange(p, "POST", "/seal", {"session": "diff-1"})),
    ("an acquisition into a sealed session", lambda p: exchange(p, "POST", "/acquire", {"session": "diff-1", "source": "screening", "arguments": {}})),
    ("an unknown source into a sealed session", lambda p: exchange(p, "POST", "/acquire", {"session": "diff-1", "source": "elsewhere"})),
    ("a seal whose body is not JSON", lambda p: exchange(p, "POST", "/seal", raw=b"nope")),
    ("a read of a route that takes a POST", lambda p: exchange(p, "GET", "/acquire")),
    ("a path the engine does not route", lambda p: exchange(p, "GET", "/nowhere")),
)
DECODER_WORDS = {"an acquisition whose body is not JSON", "a seal whose body is not JSON"}


def formed(value):
    """value with every derived member replaced by the name of its form, or
    by what is wrong with it."""
    if isinstance(value, dict):
        out = {}
        for key, member in value.items():
            form = FORMS.get(key)
            if form is None:
                out[key] = formed(member)
            elif member is None and key == "prevSignature":
                out[key] = None
            elif isinstance(member, str) and form.fullmatch(member):
                out[key] = f"<{key}>"
            else:
                out[key] = f"<{key} NOT OF ITS FORM: {member!r}>"
        return out
    if isinstance(value, list):
        return [formed(v) for v in value]
    return value


def strict(value):
    """value formed and written as JSON, so that a comparison tells true
    from 1 and false from 0, which Python's equality does not. An answer's
    raw text is left to text_holds."""
    if isinstance(value, dict) and "text" in value:
        value = {k: v for k, v in value.items() if k != "text"}
    return json.dumps(formed(value), sort_keys=True, indent=1)


def text_holds(test, what, engine_answer, stand_in_answer):
    """A refusal's bytes are the engine's, word for word; an answer's bytes
    are the engine's JSON form of its body, on both sides."""
    if what in DECODER_WORDS:
        return
    if engine_answer["status"] != 200:
        test.assertEqual(stand_in_answer["text"], engine_answer["text"], f"{what}: the words differ")
        return
    for whose, answer in (("the engine", engine_answer), ("the stand-in", stand_in_answer)):
        if isinstance(answer["body"], dict):
            test.assertEqual(answer["text"], answers.go_json(answer["body"]), f"{whose}: {what}: not the engine's JSON form")


def transcript(port):
    answers_by_request = []
    for what, send in REQUESTS:
        answer = send(port)
        if what in DECODER_WORDS and isinstance(answer.get("body"), dict) and "error" in answer["body"]:
            answer["body"]["error"] = "<the decoder's words>"
            answer["text"] = None
        answers_by_request.append((what, answer))
    return answers_by_request


def relations(test, answers_by_request, whose):
    """What a transcript's derived members must be to one another."""
    key = dict(answers_by_request)["the key document"]["body"]["keyId"]
    last = {}
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
        if "finalCount" in body:
            test.assertEqual(body["keyId"], key, f"{whose}: {what}: the seal's key id is not the key document's")


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
                self.assertEqual(strict(stand_in_answer), strict(engine_answer))
                text_holds(self, what, engine_answer, stand_in_answer)


class FaultTest(unittest.TestCase):
    """Each fault changes the member it names and no other: the stand-in's
    answers to the smoke's requests with the fault and without it differ at
    that member alone, or, for a fault with a status, in that route's whole
    answer alone."""

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
                        self.assertEqual(strict(wrong[route]), strict(right[route]), f"{fault.name} changed {route}")
                    elif fault.status:
                        self.assertEqual(wrong[route]["status"], fault.status)
                        self.assertEqual(strict(wrong[route]["body"]), strict(fault.value))
                    else:
                        self.assertEqual(wrong[route]["status"], right[route]["status"])
                        self.assertEqual(strict(wrong[route]["body"]), strict(answers.apply(fault, right[route]["body"])))
                        self.assertNotEqual(strict(wrong[route]["body"]), strict(right[route]["body"]), f"{fault.name} changed nothing")


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
