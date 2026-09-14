"""Reads n8n's own record of the latest execution and holds each node's output
to what the engine must have answered: a receipt from Acquire, a refusal from
Act (this engine has no identity, so an action has no requester), a seal from
Seal. Standard library only."""
import json
import sqlite3
import sys

db = sqlite3.connect(sys.argv[1])
expected_session = sys.argv[2]
# the words n8n 2.38.x puts on a 401 from the engine; a pinned image, so a
# pinned string -- another refusal (a 404, a citation the node itself
# refused) is not this one
expected_refusal = "Authorization failed - please check your credentials"


def is_int(value):
    return isinstance(value, int) and not isinstance(value, bool)


def is_hex(value, length):
    return isinstance(value, str) and len(value) == length and all(c in "0123456789abcdef" for c in value)

row = db.execute(
    "select e.id, e.status, d.data from execution_entity e join execution_data d on d.executionId = e.id order by e.id desc limit 1"
).fetchone()
if row is None:
    sys.exit("no execution recorded")
execution_id, status, data = row
raw = json.loads(data)


def unflatten(value, depth=0):
    # n8n stores execution data in the "flatted" form: an array whose first
    # member is the root, in which every string inside an object or array is
    # the index of another member -- the value itself when that member is a
    # string, a nested object or array otherwise. Numbers, booleans and
    # nulls are written inline.
    if depth > 200:
        raise ValueError("execution data nests too deep to be flatted")
    if isinstance(value, list):
        return [resolve(v, depth) for v in value]
    if isinstance(value, dict):
        return {resolve_key(k): resolve(v, depth) for k, v in value.items()}
    return value


def resolve_key(key):
    return key


def resolve(value, depth):
    if isinstance(value, str):
        target = raw[int(value)]
        return target if isinstance(target, str) else unflatten(target, depth + 1)
    return unflatten(value, depth + 1)


execution = unflatten(raw[0]) if isinstance(raw, list) else raw
result = execution["resultData"]
outputs = {}
for node, runs in result["runData"].items():
    items = (runs[0].get("data") or {}).get("main", [[]])[0] or []
    outputs[node] = items[0].get("json", {}) if items else {}

problems = []
if status != "success":
    problems.append(f"execution {execution_id} ended {status}: {(result.get('error') or {}).get('message')}")
acquire = outputs.get("Acquire", {})
receipt = acquire.get("receipt", {})
if receipt.get("receiptVersion") != "3" or receipt.get("kind") != "acquisition" or not (is_int(receipt.get("callIndex")) and receipt.get("callIndex") == 0):
    problems.append(f"Acquire did not yield a version-3 acquisition receipt at index 0: {json.dumps(receipt)[:300]}")
if receipt.get("sessionId") != expected_session:
    problems.append(f"Acquire's receipt is in session {receipt.get('sessionId')!r}, not the run's {expected_session!r}")
if not is_hex(receipt.get("signature"), 128):
    problems.append("Acquire's receipt carries no signature of the expected form")
result = acquire.get("result")
if not (isinstance(result, dict) and result.get("synthetic") is True and result.get("arguments") == {"subject": "acme"} and set(result) == {"synthetic", "arguments"}):
    problems.append(f"Acquire's result is not the source's answer: {result}")
if not is_hex((acquire.get("salts") or {}).get("args"), 64):
    problems.append(f"Acquire yielded no arguments salt of the expected form: {acquire.get('salts')}")
act = next((v for k, v in outputs.items() if k.startswith("Act")), {})
if act.get("error") != expected_refusal:
    problems.append(f"Act was not refused as the engine's 401 reads in this n8n: {json.dumps(act)[:300]}")
seal = outputs.get("Seal", {})
if not (is_int(seal.get("finalCount")) and seal.get("finalCount") == 1) or seal.get("sessionId") != expected_session or not is_hex(seal.get("signature"), 128):
    problems.append(f"Seal did not seal the run's session at one receipt: {json.dumps(seal)[:300]}")
for problem in problems:
    print("FAIL:", problem)
if problems:
    sys.exit(1)
print(f"n8n smoke ok: execution {execution_id} — Acquire receipt {receipt.get('sessionId')}/{receipt.get('callIndex')}, Act refused ({act.get('error')}), Seal finalCount {seal.get('finalCount')}")
