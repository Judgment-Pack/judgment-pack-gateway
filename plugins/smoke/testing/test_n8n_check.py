"""The n8n smoke checker (plugins/smoke/n8n/check.py) held to its refusals.

check.py reads n8n's own record of an execution -- its SQLite database, the
execution's data in the "flatted" form n8n stores -- and holds each node's
output to what the engine must have answered. A checker that cannot fail
proves nothing, so these tests write executions as n8n stores them, one as
the engine must have answered and one for each wrong answer in
answers.FAULTS that this checker reads, and require check.py to pass the
first and to fail each other on the one check the fault names, and on no
other.

The bytes are flatted's. fixtures/ holds what flatted 3.4.2 -- the copy the
pinned n8n image stores with -- wrote for the execution and for the
decoder's hard cases (make_flatted_fixtures.cjs), and the encoder here that
writes the wrong executions is held to those bytes. Standard library only;
no n8n, no engine, no container.
"""
import importlib.util
import json
import os
import re
import sqlite3
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import answers  # noqa: E402

CHECK = os.path.join(HERE, "..", "n8n", "check.py")
FIXTURES = os.path.join(HERE, "fixtures")
SESSION = "smoke-n8n-test-1"
AT = "2026-09-15T00:00:00Z"
ACT_NODE = "Act (refused: no identity)"
NODES = {"acquire": "Acquire", "act": ACT_NODE, "seal": "Seal"}


def load_check():
    spec = importlib.util.spec_from_file_location("n8n_check", CHECK)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


check = load_check()


def fixture(name):
    with open(os.path.join(FIXTURES, name), encoding="utf-8") as f:
        return f.read()


def strict(value):
    # JSON text, so a comparison tells "7" from 7 and true from 1
    return json.dumps(value, sort_keys=True, ensure_ascii=False)


INDEX_KEY = re.compile(r"0|[1-9][0-9]*")


def js_key_order(obj):
    # a JavaScript object's own keys in the order it enumerates them: the
    # ones that read as array indices first, ascending, then the rest as
    # they were added
    def index(key):
        return INDEX_KEY.fullmatch(key) is not None and int(key) < 2**32 - 1
    return sorted((k for k in obj if index(k)), key=int) + [k for k in obj if not index(k)]


def flatted(root):
    """The flatted form as flatted 3.4.2's stringify writes it: the root
    first, then each string and each object or array in the order it is
    first met -- the members of the root, then of the first found, and so
    on -- each distinct string once and each object once however often it is
    referred to, and every one of them written as its index, as a string,
    wherever it is referred to. Numbers, booleans and nulls stay inline.
    test_the_encoder_writes_what_flatted_writes holds it to the library's
    bytes."""
    known, members = {}, []

    def index_of(value):
        key = ("string", value) if isinstance(value, str) else ("object", id(value))
        if key not in known:
            members.append(value)
            known[key] = str(len(members) - 1)
        return known[key]

    def inline(value):
        if isinstance(value, (str, dict, list)):
            return json.dumps(index_of(value))
        return json.dumps(value)

    def written(value):
        if isinstance(value, dict):
            return "{" + ",".join(json.dumps(k, ensure_ascii=False) + ":" + inline(value[k]) for k in js_key_order(value)) + "}"
        if isinstance(value, list):
            return "[" + ",".join(inline(v) for v in value) + "]"
        return json.dumps(value, ensure_ascii=False)

    index_of(root)
    out, i = [], 0
    while i < len(members):
        out.append(written(members[i]))
        i += 1
    return "[" + ",".join(out) + "]"


def flatted_cases():
    # the object make_flatted_fixtures.cjs builds, built the same way
    shared = {"subject": "acme", "7": "seven"}
    items = ["7", 7, shared, None, True, False, "", "é中😀"]
    return {
        "seven": 7,
        "7": "7",
        "sevenAgain": "7",
        "shared": shared,
        "list": items,
        "nested": {"again": shared, "list": items, "10": 10, "2": "two", "02": "not an index"},
        "empty": {},
        "none": [],
    }


def good_outputs():
    return {
        "Acquire": answers.acquisition(SESSION, 0, None, {"subject": "acme"}, AT),
        ACT_NODE: {"error": check.EXPECTED_REFUSAL},
        "Seal": answers.seal(SESSION, 1, AT),
    }


def outputs_with(fault):
    outputs = good_outputs()
    node = NODES[fault.route]
    outputs[node] = answers.apply(fault, outputs[node])
    return outputs


def execution(outputs, error=None):
    run_data = {"Start": [{"data": {"main": [[{"json": {}}]]}}]}
    for node, output in outputs.items():
        run_data[node] = [{"data": {"main": [[{"json": output}]]}}]
    result = {"runData": run_data}
    if error:
        result["error"] = {"message": error}
    return {"resultData": result}


def write_execution_fixture():
    """Writes fixtures/n8n-execution.json, the execution as the engine must
    have answered; make_flatted_fixtures.cjs then writes it as n8n stores
    it."""
    with open(os.path.join(FIXTURES, "n8n-execution.json"), "w", encoding="utf-8") as f:
        json.dump(execution(good_outputs()), f, indent=1, ensure_ascii=False)
        f.write("\n")


def write_database(path, stored, status="success", executions=True):
    if os.path.exists(path):
        os.remove(path)
    db = sqlite3.connect(path)
    db.execute("create table execution_entity (id integer primary key, status text)")
    db.execute('create table execution_data ("executionId" integer, data text)')
    if executions:
        # an earlier execution first: the checker reads the latest
        db.execute("insert into execution_entity values (1, 'error')")
        db.execute("insert into execution_data values (1, ?)", (flatted(execution({}, "an earlier run")),))
        db.execute("insert into execution_entity values (2, ?)", (status,))
        db.execute("insert into execution_data values (2, ?)", (stored,))
    db.commit()
    db.close()


class FlattedTest(unittest.TestCase):
    def test_the_committed_execution_is_the_engines_answers(self):
        self.assertEqual(strict(json.loads(fixture("n8n-execution.json"))), strict(execution(good_outputs())),
                         "the answers changed: regenerate the fixtures (make_flatted_fixtures.cjs)")

    def test_the_encoder_writes_what_flatted_writes(self):
        self.assertEqual(flatted(json.loads(fixture("n8n-execution.json"))), fixture("n8n-execution.flatted.json"))
        self.assertEqual(flatted(flatted_cases()), fixture("flatted-cases.flatted.json"))

    def test_the_decoder_reads_what_flatted_writes(self):
        stored = json.loads(fixture("flatted-cases.flatted.json"))
        # the cases are what they claim to be: one member for the string
        # that recurs, one for the shared object, and 7 inline
        self.assertEqual([m for m in stored if m == "7"], ["7"])
        self.assertEqual(len([m for m in stored if isinstance(m, dict) and "subject" in m]), 1)
        self.assertEqual(strict(check.decode(stored)), strict(json.loads(fixture("flatted-cases.json"))))
        self.assertEqual(strict(check.decode(json.loads(fixture("n8n-execution.flatted.json")))), strict(execution(good_outputs())))


class CheckTest(unittest.TestCase):
    def setUp(self):
        self.db = os.path.join(tempfile.mkdtemp(), "database.sqlite")

    def run_check(self):
        return subprocess.run([sys.executable, CHECK, self.db, SESSION], capture_output=True, text=True)

    def failed(self, stored, **kwargs):
        write_database(self.db, stored, **kwargs)
        done = self.run_check()
        self.assertNotEqual(done.returncode, 0, done.stdout)
        return [line.split(":", 2)[1].strip() for line in done.stdout.splitlines() if line.startswith("FAIL: ")], done.stdout

    def test_the_execution_as_n8n_stored_it_passes(self):
        # the library's own bytes, not the encoder's
        write_database(self.db, fixture("n8n-execution.flatted.json"))
        done = self.run_check()
        self.assertEqual(done.returncode, 0, done.stdout + done.stderr)
        self.assertIn("n8n smoke ok: execution 2", done.stdout)

    def test_each_wrong_answer_fails_its_check_and_no_other(self):
        for fault in answers.FAULTS:
            if "n8n" not in fault.checkers:
                continue
            with self.subTest(fault=fault.name):
                failed, out = self.failed(flatted(execution(outputs_with(fault))))
                self.assertEqual(failed, [fault.check], out)

    def test_no_execution(self):
        failed, out = self.failed("", executions=False)
        self.assertEqual(failed, ["execution"], out)

    def test_an_execution_that_did_not_succeed(self):
        failed, out = self.failed(flatted(execution(good_outputs(), "the engine was not there")), status="error")
        self.assertEqual(failed, ["execution status"], out)
        self.assertIn("the engine was not there", out)

    def test_an_act_refused_for_another_reason(self):
        outputs = good_outputs()
        outputs[ACT_NODE] = {"error": "The resource you are requesting could not be found"}
        failed, out = self.failed(flatted(execution(outputs)))
        self.assertEqual(failed, ["act refusal"], out)


if __name__ == "__main__":
    unittest.main()
