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

1. No authenticated requester → refused (401). Nothing is read: an engine with no identity
   configured refuses before the body, and one with an identity refuses a missing or bad token
   as `/acquire` does.
2. The session is not a session, is sealed in the registry on disk — the one record of a seal,
   this process's own or an earlier one's — or exists in the store as something this process did
   not mint → refused. The last is what a restart means: a session the store already holds
   cannot have its chain continued from an empty memory, and a write that ran and could not be
   receipted is the outcome this design exists to refuse, so an action after a restart opens a
   session of its own. "Did not mint" is judged by whether this process made the session's
   directory — an action's admission makes it, a read's stamp makes it, each by an exclusive
   `Mkdir` that finds a directory another process put there first, at any moment before it,
   rather than claims it — never by absence read at admission or before the stamp, which
   another process can end in between, and never by a receipt count, since a read into an old session can recreate a receipt that session
   lost and count on from there; an entry of any kind — a directory, a link, a file — is such a
   session, and a lookup that fails for any reason but absence refuses rather than passes.
   (`/acquire` differs: for a session it does not hold in memory it consults the registry's
   seals first and refuses one sealed there, or a registry it cannot read, before its source
   runs; otherwise it admits by memory, runs its source, and then stamps a receipt where none
   collides — continuing an old unsealed session, recreating a receipt it lost — or fails at
   the stamp where one does; either way it is a read, and a read's session is never an
   action's unless this process created it.) Admission itself — the atomic reservation
   against sealing — happens once the evidence below is held, as it does for a read, judges the
   session on disk once more under the same lock, and takes the session's directory for this
   process by `Mkdir` before any executor runs: two makers cannot both succeed, so a session
   another process put there in the meantime is refused here and not discovered at the stamp
   after the write. What remains outside the claim is a second engine writing receipts into a
   directory this one made — two engines on one store, which the design does not serve.
3. The platform is unknown, or its binding declares no `write` operation, or the
   configuration does not set `write: true` for it → refused. `write: true` says an executor
   may be pointed at the platform; it authorizes no particular write. Every member of the
   request is read at its own step — `session` at step 2, `platform` here, `tool` at step 4,
   `decision` and `cites` at theirs — absent, unparseable or of the wrong type is a refusal at
   that step — so a request with several faults is answered by the earliest step it fell at.
4. The tool is not one the `write` binding names → refused. The executor is spawned with
   `--tools=<that tool>` and nothing else — the binding's list narrowed to the one requested —
   so a server offering more cannot be asked for more. The arguments must be a JSON object:
   the executor sends `{tool, arguments}` as an object, and the commitment is over what is
   sent, so nothing is sent that is not what was committed to; arguments that do not parse
   are refused at this step.
5. The decision claim must have its shape — exactly `recordDigest` and `packDigest`, each a
   digest — or the request is refused here, before any citation is read.
6. Each citation must be exactly its three members and resolve in the engine's store by §4
   step 5's rule — its `sessionId` exactly a session directory name, its `callIndex` exactly a
   file stem, its `signature` the same string as that file's — and that receipt must pass the
   ladder under the engine's key. A citation that does not resolve, or a cited receipt that
   does not verify, refuses the request and names the citation. An empty `cites` is refused: a
   judgment that relied on no receipt is not one this engine can stand behind. (The verifier
   tolerates members it does not know inside a signed receipt; a requester's citation is not
   signed yet, and what the receipt will carry is exactly what was given, so a citation with
   more than its three members is refused rather than trimmed.)
7. `decision.recordDigest` must equal the SHA-256 of some candidate under the configured
   `decisionRecords` directory by §4 step 6's rule — every regular file as its whole bytes,
   and every line of a `.jsonl` file — or the request is refused. `packDigest` is recorded as
   given and checked against nothing: the record's contents are the runtime's, and the engine
   reads none of them. Symbolic links are not followed. The walk is `verify`'s own, and like
   it is not bounded in bytes, entries or time: availability is a stated limit of this
   reference ([SECURITY.md](../../SECURITY.md)), and an operator who mounts an archive as the
   decision-record directory has made the walk as long as the archive. A directory that cannot
   be read refuses the action without saying where it is.

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
`/verify` on the engine reads the same decision-record directory, so an action verifies there
as it does under `gateway verify --decision-records`.

## What it does not claim

The receipt is lineage of a request and a response. It does not say the write was right, and
it does not say the requester approved it: a token proves who asked. Evidence that a person
approved this specific action is an open question the plan names, and nothing here answers it.
A target that refuses the write is a response like any other — the receipt records the
refusal bytes: the executor is started with `--error-results`, under which `adapter-mcp`
envelopes a tool result that reports an error as the result of the call, where for a read the
same result is a failed acquisition — and an executor that cannot reach the target mints
nothing.

## How it is held

- The refusal ladder above, each step with a test that reaches it and a mutation that
  removes it; the interleavings the session step cannot see — a session another process puts
  in the store while a read into it is admitted and running, or in the last moment before the
  read's stamp, and a seal landing between the evidence checks and admission — each held to a
  session refusal with nothing run.
- An end-to-end test: an acquisition, a decision record written beside it citing the
  receipt, an `/act` that cites both, then `gateway verify` over the store, the registry and
  the decision-record directory reporting every receipt `ok` — the vector
  `v3-action-valid` is what a minted store must look like, and the verifier the corpus tests
  is what judges it.
- No new vectors: the receipt shape is the one the corpus already freezes.
