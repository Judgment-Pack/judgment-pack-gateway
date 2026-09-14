"""Reads n8n's own record of the latest execution and holds each node's output
to what the engine must have answered: a receipt from Acquire, a refusal from
Act (this engine has no identity, so an action has no requester), a seal from
Seal. Standard library only."""
import json
import sqlite3
import sys

db = sqlite3.connect(sys.argv[1])
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
if str(receipt.get("receiptVersion")) != "3" or receipt.get("kind") != "acquisition" or receipt.get("callIndex") != 0:
    problems.append(f"Acquire did not yield a version-3 acquisition receipt at index 0: {json.dumps(receipt)[:300]}")
if acquire.get("result") != {"synthetic": True, "arguments": {"subject": "acme"}}:
    problems.append(f"Acquire's result is not the source's answer: {acquire.get('result')}")
if "args" not in (acquire.get("salts") or {}):
    problems.append("Acquire yielded no arguments salt")
act = next((v for k, v in outputs.items() if k.startswith("Act")), {})
if "error" not in act:
    problems.append(f"Act was not refused: {json.dumps(act)[:300]}")
seal = outputs.get("Seal", {})
if seal.get("finalCount") != 1 or seal.get("sessionId") != receipt.get("sessionId"):
    problems.append(f"Seal did not seal the acquisition's session at one receipt: {json.dumps(seal)[:300]}")
for problem in problems:
    print("FAIL:", problem)
if problems:
    sys.exit(1)
print(f"n8n smoke ok: execution {execution_id} — Acquire receipt {receipt.get('sessionId')}/{receipt.get('callIndex')}, Act refused ({act.get('error')}), Seal finalCount {seal.get('finalCount')}")
