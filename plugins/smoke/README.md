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
is configured, so every receipt carries `caller: null`, and the engine's handler refuses an
`Act` with a 401 without reading its body. Both runs check that refusal, in the words each
client surfaces.

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
Each of these is a named check, and a failure prints its name first.

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
error, the engine's own words), Seal (the run's session at one receipt, signed). Each is a
named check, with the n8n checker's names, and the first to fail prints its name and ends the
run. This exercises the piece definition and its transport, not an
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

A checker that cannot fail proves nothing. So `testing/` holds the smoke checkers to their
refusals without n8n or a container, and holds the stand-in they are tested against to the
engine:

- `answers.py` builds the engine's answers to a client plugin: the complete version 3 receipt,
  the seal, the key document and the act refusal, each in the engine's own JSON. It also builds
  the wrong answers the checkers must refuse (`FAULTS`). Each fault changes one member, and
  names the one check that must catch it, as both checkers name their checks.
- `stand_in_engine.py` answers as the engine above answers. It reads a body as the engine's
  JSON decoder does, and holds arguments to the canonical domain. It gives the same refusals,
  in the same order and the same words, except where the words are Go's decoder's own. It
  decides an action's 401 before reading the body. It chains a session's receipts and keeps a
  seal final. It routes other methods and query strings as the engine's router does, and sends
  the engine's headers. With `--fault NAME` it gives one wrong answer. With `--require-length`
  it refuses a chunked body, as a proxy that takes none would. Nothing it answers is signed: it
  stands in for the shape of the engine's answers, never for their verification.
- `test_stand_in_engine.py` sends the same 48 requests to the engine and to the stand-in and
  compares the answers:
  - the status;
  - the headers `Content-Type`, `Content-Length`, `Transfer-Encoding`, `Connection`,
    `WWW-Authenticate`, `X-Content-Type-Options` and `Server`;
  - every body member, compared as JSON text;
  - the bytes of every refusal.

  Where the words are Go's decoder's own, it compares the status, the headers but the length,
  and that the error is a string. What the engine derives from its key, seed and clock is
  compared by its form at its place in the answer. It is also compared by relation: the key
  id is the key's, `prevSignature` is the session's last signature, and times parse and never
  run backward. The arguments commitment and the result digest are recomputed. The adapter and
  result digests, which no seed touches, are compared exactly. The test needs the engine's
  binary, named by `GATEWAY_BIN`. CI's Linux Go job builds the engine and runs the test with
  `SMOKE_REQUIRE_ENGINE` set, so a stand-in that drifts from the engine fails there. The same
  file checks that each fault changes its one member and nothing else, headers included,
  except what the clock sets.
- `test_n8n_check.py` writes executions into a SQLite database as n8n stores them: one as the
  engine must have answered, and one for each fault this checker reads. It requires `check.py`
  to pass the first, and to fail each other at the fault's check and no other. The flatted
  bytes are the library's. `fixtures/` holds what flatted 3.4.2, the copy in the pinned n8n
  image, wrote for the execution and for the decoder's hard cases: a shared object, a
  recurring string, a key and a value that read as numbers beside a number, and cycles. The
  decoder gives a shared object back as one object and a cycle as a cycle. The encoder the
  tests write faults with is held byte for byte to those, for the integers they hold.
- `test_activepieces_runner.py` runs `activepieces/run.mjs` against the stand-in: once as the
  engine answers, and once for each fault, where the run must fail at the fault's check. It
  runs once more against `--require-length`, which the piece passes because it states its
  body's length. It needs Node and the piece built. It skips without them unless
  `SMOKE_REQUIRE_PIECE` is set, as CI sets it where it builds the piece.

```
(cd plugins/activepieces/judgment-pack && npm ci --ignore-scripts && npm run build)
(cd go && go build -o ../gateway .)
GATEWAY_BIN=$PWD/gateway SMOKE_REQUIRE_ENGINE=1 SMOKE_REQUIRE_PIECE=1 python3 -m unittest discover -s plugins/smoke/testing -v
```

When the answers change, the fixtures are written again: the execution by the tests' own code,
then its flatted bytes inside the pinned image.

```
python3 -c 'import sys; sys.path.insert(0, "plugins/smoke/testing"); import test_n8n_check; test_n8n_check.write_execution_fixture()'
docker run --rm -v "$PWD/plugins/smoke/testing:/work" --entrypoint node \
  docker.n8n.io/n8nio/n8n:2.38.7@sha256:a8c95f75c6fdf65f5f2b7a7b354744eaa1c62bb911b5c00af6499c3f38e4cd32 \
  /work/make_flatted_fixtures.cjs \
  /usr/local/lib/node_modules/n8n/node_modules/.pnpm/flatted@3.4.2/node_modules/flatted /work/fixtures
```

CI runs the checkers' tests in the plugins job, and the engine comparison in the Go job. The
runs above against a real engine remain the step before publishing, and these tests do not
replace them.
