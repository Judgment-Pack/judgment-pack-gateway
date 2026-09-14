# Design note: the executor

**Status: design note, not normative.** How a write happens through the engine, and what
refuses it. The receipt it produces is the action receipt [SPEC.md §1.2a](../../SPEC.md)
already defines and `verify` already resolves (§4 steps 5–7); this note is about the process
that mints one: `POST /act` on the engine (`go/act.go`), through the same boundary `/acquire`
uses, with the executor derived from the platform's `write` binding.

## The rule

A pack authorizes nothing. A write happens only on a request from an authenticated person,
and the receipt says who asked ([ADR-0001](../adr/0001-one-engine-four-processes.md)). The
executor refuses any write that cites no verifying judgment: before anything is sent to a
target system, the engine holds, in its own store and under its own decision-record
directory, the judgment the requester says the write relies on. What "verifying" means is
exactly what `verify` means by it and nothing more — the cited receipts are there, under the
engine's own key, and a decision record with the stated digest is there — because a stricter
reading would have the engine interpret a record, which nothing in this design does.

## The request

`POST /act`, authenticated like `/acquire` — a bearer token the configured identity provider
issued ([engine-config.md](engine-config.md)); a request with no authenticated requester is
refused before anything else is read, since an action receipt's `requester` is never null.

```json
{
  "session": "s-2026-09-14-a",
  "platform": "tickets",
  "tool": "update_ticket",
  "arguments": {"id": "T-1", "status": "approved"},
  "decision": {"recordDigest": "sha256:…", "packDigest": "sha256:…"},
  "cites": [{"sessionId": "s-2026-09-14-a", "callIndex": 3, "signature": "…"}]
}
```

`decision` and `cites` are the requester's assertions, recorded as given; the engine checks
that what they name exists and compares nothing inside it, which is §4's standard too.

## What refuses it, in order, before any executor runs

1. No authenticated requester → refused (401). Nothing is read.
2. The session is not open, or is sealed → refused, as `/acquire` refuses.
3. The platform is unknown, or its binding declares no `write` operation, or the
   configuration does not set `write: true` for it → refused. `write: true` says an executor
   may be pointed at the platform; it authorizes no particular write.
4. The tool is not one the `write` binding names → refused. The executor is spawned with
   `--tools=<that tool>` and nothing else, so a server offering more cannot be asked for more.
5. Each citation must resolve in the engine's store by §4 step 5's rule — its `sessionId`
   exactly a session directory name, its `callIndex` exactly a file stem, its `signature` the
   same string as that file's — and that receipt must pass the ladder under the engine's key.
   A citation that does not resolve, or a cited receipt that does not verify, refuses the
   request and names the citation. An empty `cites` is refused: a judgment that relied on no
   receipt is not one this engine can stand behind.
6. `decision.recordDigest` must equal the SHA-256 of some candidate under the configured
   `decisionRecords` directory by §4 step 6's rule — every regular file as its whole bytes,
   and every line of a `.jsonl` file — or the request is refused. `packDigest` is recorded as
   given and checked against nothing: the record's contents are the runtime's, and the engine
   reads none of them. Symbolic links are not followed; the walk is bounded as `verify`'s is.

A refused request executes nothing and mints nothing. The refusal names which step refused.

## The executor

The platform's `write` binding is a catalog entry ([catalog/README.md](../../catalog/README.md))
naming the same MCP server image the live operation uses, pinned by digest, with the
credentials file the configuration names for the `write` operation. The engine derives
`<platform>/write` exactly as it derives `<platform>/live`
([engine-config.md](engine-config.md)): `adapter-mcp`, spawned as the platform's user with the
declared environment and nothing more, `--tools=<tool>`, the canonical request
`{"tool": …, "arguments": …}` on stdin, the envelope on stdout. The executor is `adapter-mcp`
itself — a tool call is a tool call, and a write is a tool the vendor's server exposes — so no
new binary holds a credential, and the process boundary that keeps the signer from the
credentials is the one that already exists.

The target's response bytes are the artifact: retained under their digest as any result is,
and `resultDigest` names them. The engine then mints one receipt in the session chain:

| Member | From |
|---|---|
| `kind` | `"action"` |
| `caller` | the token identity |
| `argumentsCommitment` | a salted commitment over the canonical request body's `arguments`, salt returned |
| `action.requester` | the token identity again — the one who asked, named where the action is |
| `action.decision`, `action.cites` | as given |
| `action.tool` | `{"shape": "mcp", "endpoint": <binding endpoint or null>, "name": <tool>}` |
| `action.request` | a salted commitment over the canonical request sent to the executor, salt returned |
| `action.adapter` | from the envelope, as `acquisition.adapter` is |
| `action.observedAt` | when the target answered, from the envelope |

The response returns the target's result, the receipt, and the salts, as `/acquire` does.

## What it does not claim

The receipt is lineage of a request and a response. It does not say the write was right, and
it does not say the requester approved it: a token proves who asked. Evidence that a person
approved this specific action is an open question the plan names, and nothing here answers it.
A target that refuses the write is a response like any other — the receipt records the
refusal bytes — and an executor that cannot reach the target mints nothing.

## How it is held

- The refusal ladder above, each step with a test that reaches it and a mutation that
  removes it.
- An end-to-end test: an acquisition, a decision record written beside it citing the
  receipt, an `/act` that cites both, then `gateway verify` over the store, the registry and
  the decision-record directory reporting every receipt `ok` — the vector
  `v3-action-valid` is what a minted store must look like, and the verifier the corpus tests
  is what judges it.
- No new vectors: the receipt shape is the one the corpus already freezes.
