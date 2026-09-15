"""The n8n smoke checker (plugins/smoke/n8n/check.py) held to its refusals.

check.py reads n8n's own record of an execution -- its SQLite database, the
execution's data in the "flatted" form n8n stores -- and holds each node's
output to what the engine must have answered. A checker that cannot fail
proves nothing, so these tests write executions the way n8n does, one right
and one for each wrong answer the checker names, and run the checker on
each. Standard library only; no n8n, no engine, no container.
"""
import json
import os
import sqlite3
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
CHECK = os.path.join(HERE, "..", "n8n", "check.py")
SESSION = "smoke-n8n-test-1"
REFUSAL = "Authorization failed - please check your credentials"


def flatted(root):
    """n8n's storage form (the flatted library): an array whose first member
    is the root, in which every string and every object or array inside an
    object or array is replaced by the index, as a string, of a member
    holding it; numbers, booleans and nulls stay inline."""
    out = [None]

    def ref(value):
        if isinstance(value, str):
            out.append(value)
            return str(len(out) - 1)
        if isinstance(value, (dict, list)):
            index = len(out)
            out.append(None)
            out[index] = convert(value)
            return str(index)
        return value

    def convert(value):
        if isinstance(value, dict):
            return {k: ref(v) for k, v in value.items()}
        if isinstance(value, list):
            return [ref(v) for v in value]
        return value

    out[0] = convert(root)
    return json.dumps(out)


def good_outputs():
    return {
        "Acquire": {
            "result": {"synthetic": True, "arguments": {"subject": "acme"}},
            "receipt": {"receiptVersion": "3", "kind": "acquisition", "sessionId": SESSION, "callIndex": 0, "signature": "a" * 128},
            "salts": {"args": "b" * 64},
        },
        "Act (refused: no identity)": {"error": REFUSAL},
        "Seal": {"sessionId": SESSION, "finalCount": 1, "sealedAt": "2026-09-15T00:00:00Z", "keyId": "0" * 16, "signature": "c" * 128},
    }


def execution(outputs, error=None):
    run_data = {"Start": [{"data": {"main": [[{"json": {}}]]}}]}
    for node, output in outputs.items():
        run_data[node] = [{"data": {"main": [[{"json": output}]]}}]
    result = {"runData": run_data}
    if error:
        result["error"] = {"message": error}
    return {"resultData": result}


def write_database(path, outputs, status="success", error=None, executions=True):
    db = sqlite3.connect(path)
    db.execute("create table execution_entity (id integer primary key, status text)")
    db.execute('create table execution_data ("executionId" integer, data text)')
    if executions:
        # an earlier execution first: the checker reads the latest
        db.execute("insert into execution_entity values (1, 'error')")
        db.execute("insert into execution_data values (1, ?)", (flatted(execution({}, "an earlier run")),))
        db.execute("insert into execution_entity values (2, ?)", (status,))
        db.execute("insert into execution_data values (2, ?)", (flatted(execution(outputs, error)),))
    db.commit()
    db.close()


class CheckTest(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.db = os.path.join(self.dir, "database.sqlite")

    def run_check(self):
        return subprocess.run([sys.executable, CHECK, self.db, SESSION], capture_output=True, text=True)

    def refused(self, outputs, says, **kwargs):
        write_database(self.db, outputs, **kwargs)
        done = self.run_check()
        self.assertNotEqual(done.returncode, 0, done.stdout)
        self.assertIn(says, done.stdout + done.stderr)

    def test_the_execution_the_engine_must_have_answered_passes(self):
        write_database(self.db, good_outputs())
        done = self.run_check()
        self.assertEqual(done.returncode, 0, done.stdout + done.stderr)
        self.assertIn("n8n smoke ok: execution 2", done.stdout)

    def test_no_execution(self):
        self.refused({}, "no execution recorded", executions=False)

    def test_an_execution_that_did_not_succeed(self):
        self.refused(good_outputs(), "ended error: the engine was not there", status="error", error="the engine was not there")

    def test_an_action_receipt_where_an_acquisition_belongs(self):
        outputs = good_outputs()
        outputs["Acquire"]["receipt"]["kind"] = "action"
        self.refused(outputs, "did not yield a version-3 acquisition receipt at index 0")

    def test_a_receipt_at_another_index(self):
        outputs = good_outputs()
        outputs["Acquire"]["receipt"]["callIndex"] = 1
        self.refused(outputs, "did not yield a version-3 acquisition receipt at index 0")

    def test_an_index_that_is_not_an_integer(self):
        outputs = good_outputs()
        outputs["Acquire"]["receipt"]["callIndex"] = False
        self.refused(outputs, "did not yield a version-3 acquisition receipt at index 0")

    def test_a_receipt_in_another_session(self):
        outputs = good_outputs()
        outputs["Acquire"]["receipt"]["sessionId"] = "another-session"
        self.refused(outputs, "is in session 'another-session'")

    def test_a_signature_of_another_form(self):
        outputs = good_outputs()
        outputs["Acquire"]["receipt"]["signature"] = "A" * 128
        self.refused(outputs, "carries no signature of the expected form")

    def test_a_result_that_is_not_the_sources_answer(self):
        outputs = good_outputs()
        outputs["Acquire"]["result"] = {"synthetic": True, "arguments": {"subject": "someone else"}}
        self.refused(outputs, "is not the source's answer")

    def test_a_result_with_a_member_more(self):
        outputs = good_outputs()
        outputs["Acquire"]["result"]["extra"] = 1
        self.refused(outputs, "is not the source's answer")

    def test_no_arguments_salt(self):
        outputs = good_outputs()
        outputs["Acquire"]["salts"] = {}
        self.refused(outputs, "no arguments salt of the expected form")

    def test_an_act_that_was_not_refused(self):
        outputs = good_outputs()
        outputs["Act (refused: no identity)"] = {"result": {}, "receipt": {"kind": "action"}}
        self.refused(outputs, "Act was not refused as the engine's 401 reads")

    def test_an_act_refused_for_another_reason(self):
        outputs = good_outputs()
        outputs["Act (refused: no identity)"] = {"error": "The resource you are requesting could not be found"}
        self.refused(outputs, "Act was not refused as the engine's 401 reads")

    def test_a_seal_at_another_count(self):
        outputs = good_outputs()
        outputs["Seal"]["finalCount"] = 2
        self.refused(outputs, "Seal did not seal the run's session at one receipt")

    def test_a_seal_of_another_session(self):
        outputs = good_outputs()
        outputs["Seal"]["sessionId"] = "another-session"
        self.refused(outputs, "Seal did not seal the run's session at one receipt")

    def test_the_flatted_form_is_decoded_as_n8n_writes_it(self):
        # a string that reads as a number and a number are different members:
        # the decoder must not take the one for the other
        outputs = good_outputs()
        outputs["Acquire"]["result"] = {"synthetic": True, "arguments": {"subject": "acme"}}
        outputs["Seal"]["keyId"] = "7"
        write_database(self.db, outputs)
        done = self.run_check()
        self.assertEqual(done.returncode, 0, done.stdout + done.stderr)


if __name__ == "__main__":
    unittest.main()
