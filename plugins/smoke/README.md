# Plugin smoke runs

The packages under `plugins/` are unit-tested against stand-ins. This directory runs each
of them the way its ecosystem runs it, against a real engine, and holds what comes back to
what the engine must have answered — the step that makes publishing and upstream submission
low-risk. Nothing here is a verification of receipts: the last step below shows where that
happens and what it says.

## The engine

A local engine with one synthetic source, as the top-level README starts one:

```
(cd go && go build -o ../gateway .)
./gateway keygen gateway.seed | tee keygen.out   # prints the public key to pin
grep publicKey keygen.out | awk '{print $2}' > publickey.hex
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
(cd plugins/n8n-nodes-judgment-pack && npm ci --ignore-scripts && npm run build && npm pack)
plugins/smoke/n8n/run.sh plugins/n8n-nodes-judgment-pack/n8n-nodes-judgment-pack-0.1.0.tgz
```

`run.sh` installs the packed package under a fresh, private data directory the way n8n's
own community-node installer lays it out — without its `n8n-workflow` peer beside it, so
that in a fresh data directory the node resolves the image's own copy rather than one npm
would pull independently of the pinned image (the runner checks that no sibling copy was
installed; it does not read back which module n8n loaded, and a reused `N8N_SMOKE_DATA` is
the operator's to keep clean) — and removes that directory at the end (`N8N_SMOKE_KEEP=1` keeps a generated one; a directory named by
`N8N_SMOKE_DATA`, existing or not, is always kept), then runs the official image — pinned by digest to the version
the checks were written against, `N8N_IMAGE` to run another on purpose — on the host
network three times: `import:credentials`, `import:workflow`, `execute`. The workflow is Start → Acquire → Act → Seal in one session named per run — the
runner writes a nonce into the workflow at import, so every node names the same literal and
no run reuses a session the engine has sealed; Act is set to continue on error, since this
engine refuses it. `check.py` then reads n8n's own record
of the execution from its database — n8n prints nothing on a successful headless run — and
requires, each member of its JSON type: a version-3 acquisition receipt at index 0, in the
run's session, with a signature of the expected form, whose `result` is exactly the source's
echo and whose `salts.args` is 64 hex characters; an error item from Act carrying the words
this n8n version puts on the engine's 401 and nothing else (a citation the node refused
before asking, or a 404, is not that); a seal of the run's session at one receipt, signed.

Last run here: n8n 2.38.7 (the pinned digest, which bundles `n8n-workflow` 2.38.1, the copy
the node ran against), Node 22 host, engine at `0406128`: `n8n smoke ok: execution 1 — Acquire
receipt smoke-n8n-1789420858-2201294/0, Act refused (Authorization failed - please check your
credentials), Seal finalCount 1`. n8n wraps the engine's 401 in its own words; the engine's
text (`an action needs an authenticated requester; this engine has no identity configured`) is
what the Activepieces run shows.

## Activepieces — the piece's actions as the framework calls them

```
(cd plugins/activepieces/judgment-pack && npm ci --ignore-scripts && npm run build)
plugins/smoke/activepieces/run.sh
```

`run.mjs` loads the built piece, runs the connection's `validate` as the framework does when a
connection is saved, then each action's `run` with the context shape the framework hands it:
Acquire (a version-3 acquisition receipt at index 0 in the run's session, signed, with a
64-hex arguments salt, whose result is the echo), Act (the engine's 401 as the action's
error), Seal (the run's session at one receipt, signed). This exercises the piece definition and its transport, not an
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

## The checkers' own tests

A checker that cannot fail proves nothing, so `testing/` holds the smoke checkers to their
refusals without an engine, n8n or a container:

- `stand_in_engine.py` answers the four routes a client plugin calls as a local engine with
  one synthetic source and no identity answers them — unsigned: it stands in for the shape
  of the engine's answers, never their verification — and, with `--fault NAME`, answers
  wrongly in one named way (a receipt of another kind, index, session or signature form, a
  result that is not the source's, no salt, an act accepted, a seal of another count or
  session); `--require-length` refuses a request body sent chunked, as a server or proxy
  that takes no chunked upload would.
- `test_n8n_check.py` writes executions into a SQLite database the way n8n stores them —
  the "flatted" form `check.py` decodes — one as the engine must have answered and one for
  each wrong answer, and requires `check.py` to pass the first and name the fault in each
  other.
- `test_activepieces_runner.py` runs `activepieces/run.mjs` against the stand-in, as the
  engine answers and once for every fault, and requires the run to fail on each; and once
  against `--require-length`, which the piece passes because it states its body's length.
  It needs Node and the piece built, and skips without them unless `SMOKE_REQUIRE_PIECE` is
  set, as CI sets it where it builds the piece.

```
(cd plugins/activepieces/judgment-pack && npm ci --ignore-scripts && npm run build)
SMOKE_REQUIRE_PIECE=1 python3 -m unittest discover -s plugins/smoke/testing -v
```

CI runs them in the plugins job. The runs above against a real engine remain what they
were: the step before publishing, which these tests do not replace.
