# Plugin smoke runs

The packages under `plugins/` are unit-tested against stand-ins. This directory runs each
of them the way its ecosystem runs it, against a real engine, and holds what comes back to
what the engine must have answered — the step that makes publishing and upstream submission
low-risk. Nothing here is a verification of receipts: the last step below shows where that
happens and what it says.

## The engine

A local engine with one synthetic source, as the top-level README starts one:

```
cd go && go build -o ../gateway .
cd .. && ./gateway keygen gateway.seed          # prints the public key to pin
cat > my_source <<'EOF2'
#!/bin/sh
args=$(cat)
printf '{"synthetic":true,"arguments":%s}\n' "${args:-null}"
EOF2
chmod +x my_source
./gateway serve ./store gateway.seed gateway:smoke ./registry.jsonl --source screening=./my_source --port 8787
```

The source echoes the canonical arguments it was given, so a result is checkable. No identity
is configured, so every receipt carries `caller: null` and an `Act` is refused before its body
is read — which is one of the things the runs check.

## n8n — the node inside the official image

```
cd plugins/n8n-nodes-judgment-pack && npm ci --ignore-scripts && npm run build && npm pack
plugins/smoke/n8n/run.sh plugins/n8n-nodes-judgment-pack/n8n-nodes-judgment-pack-0.1.0.tgz
```

`run.sh` installs the packed package under a fresh n8n data directory the way n8n's own
community-node installer lays it out, then runs `docker.n8n.io/n8nio/n8n` (`N8N_IMAGE` to
choose another) on the host network three times: `import:credentials`, `import:workflow`,
`execute`. The workflow is Start → Acquire → Act → Seal in one session named per run — the
runner writes a nonce into the workflow at import, so every node names the same literal and
no run reuses a session the engine has sealed; Act is set to continue on error, since this
engine refuses it. `check.py` then reads n8n's own record
of the execution from its database — n8n prints nothing on a successful headless run — and
requires: a version-3 acquisition receipt at index 0 whose `result` is the source's echo and
whose `salts` carry `args`; an error item from Act; a seal of the acquisition's session at one
receipt.

Last run here: n8n 2.38.7, Node 22 host, engine at `0406128`: `n8n smoke ok: execution 1 —
Acquire receipt smoke-n8n-1789419399-2167255/0, Act refused (Authorization failed - please
check your credentials), Seal finalCount 1`. n8n wraps the engine's 401 in its own words; the engine's
text (`an action needs an authenticated requester; this engine has no identity configured`) is
what the Activepieces run shows.

## Activepieces — the piece's actions as the framework calls them

```
cd plugins/activepieces/judgment-pack && npm ci --ignore-scripts && npm run build
plugins/smoke/activepieces/run.sh
```

`run.mjs` loads the built piece, runs the connection's `validate` as the framework does when a
connection is saved, then each action's `run` with the context shape the framework hands it:
Acquire (a version-3 receipt whose result is the echo), Act (the engine's 401 as the action's
error), Seal (the seal record). This exercises the piece definition and its transport, not an
Activepieces server; running the piece inside one is the monorepo's `AP_DEV_PIECES` flow, which
needs the monorepo.

Last run here: `ACTIVEPIECES SMOKE OK`, with the act refusal `the engine answered 401:
{"error":"an action needs an authenticated requester; this engine has no identity
configured","refusedAt":"requester"}`.

## Then verify — the consumer's step

```
./gateway verify ./store ./registry.jsonl gateway:smoke < publickey.hex
```

The verdict is the JSON, store-wide, and fails closed (`SPEC.md` §5a): every session the smoke
runs left is sealed, so their receipts read `ok`; a session left unsealed by a stray `curl`
reads `unregistered-session` and the whole verdict is `ok: false` until it is sealed or the
store is fresh. A consumer then binds the receipt it holds — signature-checked under the
pinned key, `(sessionId, callIndex)` among the `ok` findings — and re-digests the `result` it
kept to that receipt's `resultDigest` (§5a.4). The packages do none of this; the READMEs of
both say so.

## In CI

`.github/workflows/smoke.yml` runs both on demand (`workflow_dispatch`): it builds the engine
and the packages, starts the engine with the synthetic source, runs the two smokes, seals
nothing itself, and verifies the store. It is not part of the pull-request checks: it pulls
the n8n image and takes minutes, and what it establishes changes only when a package or the
engine's surface does.
