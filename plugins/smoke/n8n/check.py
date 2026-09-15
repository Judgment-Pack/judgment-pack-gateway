"""Reads n8n's own record of the latest execution and holds each node's output
to what the engine must have answered: a receipt from Acquire, a refusal from
Act (this engine has no identity, so an action has no requester), a seal from
Seal. Every check has a name, and a check that fails prints its name first --
the names the Activepieces runner gives the same checks. Standard library
only.

    python3 check.py <n8n database> <session>
"""
import json
import sqlite3
import sys

# the words n8n 2.38.x puts on a 401 from the engine; a pinned image, so a
# pinned string -- another refusal (a 404, a citation the node itself
# refused) is not this one
EXPECTED_REFUSAL = "Authorization failed - please check your credentials"


def is_int(value):
    return isinstance(value, int) and not isinstance(value, bool)


def is_hex(value, length):
    return isinstance(value, str) and len(value) == length and all(c in "0123456789abcdef" for c in value)


def decode(raw):
    """n8n's stored execution data, decoded. n8n stores it in the "flatted"
    form (flatted 3.4.2 in the pinned image): an array whose first member is
    the root, in which every string and every object or array inside an
    object or array is the index, as a string, of the member that holds it --
    one member for each distinct string and each distinct object, however
    often it recurs. Numbers, booleans and nulls are written inline, and an
    object's keys are never indices. Each member is decoded once: an object
    referred to twice decodes to one object, and a cycle to a cycle, as the
    library's own parse gives them."""
    if not isinstance(raw, list):
        return raw
    made = {}

    def member(index):
        if index in made:
            return made[index]
        stored = raw[index]
        if isinstance(stored, list):
            out = made[index] = []
            out.extend(value(v) for v in stored)
            return out
        if isinstance(stored, dict):
            out = made[index] = {}
            for key, v in stored.items():
                out[key] = value(v)
            return out
        return stored

    def value(v):
        if isinstance(v, str):
            return member(int(v))
        if isinstance(v, list):
            return [value(x) for x in v]
        if isinstance(v, dict):
            return {key: value(x) for key, x in v.items()}
        return v

    return member(0)


def outputs_of(execution):
    """Each node's first output item, by node name."""
    outputs = {}
    for node, runs in execution["resultData"]["runData"].items():
        items = (runs[0].get("data") or {}).get("main", [[]])[0] or []
        outputs[node] = items[0].get("json", {}) if items else {}
    return outputs


def failed_checks(status, execution, session):
    """Every check the execution fails, as (the check's name, what was
    found)."""
    failed = []

    def check(name, holds, found):
        if not holds:
            failed.append((name, found))

    def shown(value):
        try:
            return json.dumps(value)[:300]
        except ValueError:
            return repr(value)[:300]

    outputs = outputs_of(execution)
    error = (execution["resultData"].get("error") or {}).get("message")
    check("execution status", status == "success", f"the execution ended {status}: {error}")
    acquire = outputs.get("Acquire", {})
    receipt = acquire.get("receipt") if isinstance(acquire.get("receipt"), dict) else {}
    check("receipt version", receipt.get("receiptVersion") == "3", f"Acquire's receipt is not version 3: {shown(receipt.get('receiptVersion'))}")
    check("receipt kind", receipt.get("kind") == "acquisition", f"Acquire's receipt is not an acquisition: {shown(receipt.get('kind'))}")
    check("receipt index", is_int(receipt.get("callIndex")) and receipt.get("callIndex") == 0, f"Acquire's receipt is not at index 0: {shown(receipt.get('callIndex'))}")
    check("receipt session", receipt.get("sessionId") == session, f"Acquire's receipt is in session {shown(receipt.get('sessionId'))}, not the run's {session!r}")
    check("receipt signature", is_hex(receipt.get("signature"), 128), f"Acquire's receipt carries no signature of the expected form: {shown(receipt.get('signature'))}")
    result = acquire.get("result")
    echo = isinstance(result, dict) and set(result) == {"synthetic", "arguments"} and result["synthetic"] is True and result["arguments"] == {"subject": "acme"}
    check("result", echo, f"Acquire's result is not the source's answer: {shown(result)}")
    salts = acquire.get("salts")
    check("arguments salt", isinstance(salts, dict) and is_hex(salts.get("args"), 64), f"Acquire yielded no arguments salt of the expected form: {shown(salts)}")
    act = next((v for k, v in outputs.items() if k.startswith("Act")), {})
    check("act refusal", act.get("error") == EXPECTED_REFUSAL, f"Act was not refused as the engine's 401 reads in this n8n: {shown(act)}")
    seal = outputs.get("Seal", {})
    check("seal count", is_int(seal.get("finalCount")) and seal.get("finalCount") == 1, f"Seal is not at one receipt: {shown(seal.get('finalCount'))}")
    check("seal session", seal.get("sessionId") == session, f"Seal is of session {shown(seal.get('sessionId'))}, not the run's {session!r}")
    check("seal signature", is_hex(seal.get("signature"), 128), f"Seal carries no signature of the expected form: {shown(seal.get('signature'))}")
    return failed


def main(argv):
    db = sqlite3.connect(argv[1])
    session = argv[2]
    row = db.execute(
        "select e.id, e.status, d.data from execution_entity e join execution_data d on d.executionId = e.id order by e.id desc limit 1"
    ).fetchone()
    if row is None:
        print("FAIL: execution: no execution recorded")
        return 1
    execution_id, status, data = row
    execution = decode(json.loads(data))
    failed = failed_checks(status, execution, session)
    for name, found in failed:
        print(f"FAIL: {name}: {found}")
    if failed:
        return 1
    outputs = outputs_of(execution)
    receipt, seal = outputs["Acquire"]["receipt"], outputs["Seal"]
    act = next(v for k, v in outputs.items() if k.startswith("Act"))
    print(f"n8n smoke ok: execution {execution_id} — Acquire receipt {receipt['sessionId']}/{receipt['callIndex']}, Act refused ({act['error']}), Seal finalCount {seal['finalCount']}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
