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
what `verify` means by it — the cited receipts are there, under the engine's own key, and a
decision record with the stated digest is there.

For a tool the operator holds to a **decision policy**
([ADR-0011](../adr/0011-hold-a-write-to-its-decision.md)), the engine holds one thing more
before anything is sent: it reads the record, which must be shaped as the runtime's evaluation
record and, when the policy names runtime keys, signed by one of them
([ADR-0012](../adr/0012-hold-a-write-to-a-signed-record.md)); the request's claims about it
must be the record's; and the record must meet the policy — an
outcome the policy allows, no handoff requested, a pack it names, reviewed law when it asks for
that, and the write's arguments equal to the record's facts where it binds them. The policy is
the operator's, in the engine's configuration ([engine-config.md](engine-config.md)), and
never the request's. For a tool the operator holds to none, nothing in the record is read, and
the executor behaves exactly as it did before policies existed.

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

`decision` and `cites` are the requester's claims, recorded as given. For a tool with no
policy the engine checks that what they name exists and compares nothing inside it; for a tool
with one it also compares them with the record they name (step 10).

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
   and every line of a `.jsonl` file — or the request is refused. For a tool with no decision
   policy, `packDigest` is recorded as given and checked against nothing: the record's
   contents are the runtime's, and the engine reads none of them; for a tool with one, step 10
   checks it. For a tool whose policy sets `requireSignedRecord`, the record is looked for
   under §4 step 6's exact reading — a line is all its bytes before the `0x0A`, a `0x0D` among
   them — since the digest a signature binds is of the bytes the runtime wrote, and a line
   converted to CRLF is other bytes; the receipt then carries `decision.recordBytes: "exact"`,
   and `verify` finds the record the same way. Symbolic links are not followed, and nothing is
   read by a path: the walk holds its root first, as the directory it was named by (not a link,
   and the directory opened the one judged, before the open and after it), then enumerates and
   reads everything through that held root and the directories it holds below it, each judged
   the same way, each file opened through its directory's handle and judged likewise. A link put
   in place of the root, a directory or a file as it is judged refuses the read; one put there
   once it is held is where the walk no longer looks. The walk is `verify`'s own, and like
   it is not bounded in bytes, entries or time: availability is a stated limit of this
   reference ([SECURITY.md](../../SECURITY.md)), and an operator who mounts an archive as the
   decision-record directory has made the walk as long as the archive. A directory that cannot
   be read refuses the action without saying where it is.

For a tool with no decision policy the ladder ends here, and nothing in the record is read. For
a tool with one, three steps follow, and a fourth when the policy sets `requireSignedRecord`, on
the bytes step 7 hashed — a regular file whole or a line of a `.jsonl` file, never a `.jsonl`
file whole — so the record judged is the record named:

8. **`record`**: the record must be a runtime evaluation record (SPEC.md §4 step 8): one JSON
   object, read by the canonical parser with a number of any form admitted — a name twice at
   any depth, a string that is not UTF-8 or a lone surrogate refused — whose `recordVersion` is
   `"1"`, whose `kind` is `"evaluation"` and whose `pack` carries a digest. Anything else is
   refused: an opaque file, another record version, a record without a pack digest, and a
   graph composite, which carries no pack and no inputs to hold a write to (whether a write can
   be held to a composite is a later decision).
9. **`policy-signed`**, when the policy sets `requireSignedRecord`
   ([ADR-0012](../adr/0012-hold-a-write-to-a-signed-record.md)): the record must have been signed
   by one of the runtime keys the policy names, in the runtime's sidecar beside it, by the
   record-signature rule the runtime's guide writes down (`docs/building-with-packs.md` in the
   runtime, "Record signatures, exactly"). The record must carry `trail`, 32 lowercase hex, and
   `sequence`, an integer from 1 to 2⁵³−2. A file named exactly `signatures.jsonl` must lie in
   the directory of a file the record was found in, found by step 7's walk as the record is: a
   regular file, never a link. One of its lines must be readable — ended by a newline, at most
   4096 bytes before it, one JSON object of exactly the seven members of a record signature, each
   of its form, whatever its whitespace — and name the record's `trail`, its `sequence` and, as
   `record`, `decision.recordDigest`, the SHA-256 of the exact bytes step 7 matched, never of a
   re-encoding. Its `keyId` must be the keyId of a key the policy names, and its signature must
   verify under that key over `judgment-pack-runtime/record-signature/1:` followed by the
   canonical form of `{"record", "sequence", "trail"}`. One such line admits the record. A
   `key-rotation` line is never followed: a key signs here because the policy names it. The
   step comes before anything in the record is compared, so a record no trusted key signed is
   judged no further, and a hand-written one learns nothing of which later check it would fail.
10. **`consistency`**: the request's claims must be the record's. The record's `pack.digest`
   must be `decision.packDigest`, and the record's `cites` must be the request's `cites` as a
   set of (sessionId, callIndex, signature). A record with no `cites` matches no action, since
   every action cites; one whose `cites` is not of the shape an action's takes matches none.
11. **The policy**, in this order, each its own step: **`policy-outcome`**, the disposition is
    of kind `outcome` and its `outcomeId` is one the policy's `outcomes` lists;
    **`policy-handoff`**, its `handoff.state` is `none` — a requested handoff never passes;
    **`policy-packs`**, when the policy lists `packs`, the record's pack digest is one of them;
    **`policy-reviewed`**, when the policy sets `reviewed: true`, the record carries
    `"reviewed": true`; **`policy-bind`**, for each binding, the argument pointer resolves in
    the request's arguments, the fact pointer in the record's `inputs.facts`, and the two values
    are equal as JSON values with their types: the same bytes in the canonical form of SPEC.md
    §1.1, so the string `"4"` never equals the number `4`, the members of an object may come in
    any order, and a fact outside the canonical domain — a fraction, an exponent, an integer
    past 2⁵³−1 — equals no argument, since arguments are held to the domain. This is what
    refuses a decision about revision 3 cited for a write to revision 4, or an approval of one
    order used for another.

A refused request executes nothing and mints nothing. The refusal names which step refused, in
`refusedAt`. A refusal at steps 8 to 11 names the check and never a value of the record's —
not its outcome, not a fact — since the requester may know a record by its digest and not by
its contents.

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
| `action.decision`, `action.cites` | as given; `action.decision.recordBytes` is `"exact"` for a tool whose policy requires a signed record, and absent otherwise |
| `action.policy` | for a tool with a decision policy, `"sha256:"` and the SHA-256 of the canonical form of the policy object as configured; absent for a tool with none |
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

Without a policy, the engine establishes only that the record exists with the stated digest and
that the cited receipts verify. It does not establish that the record permitted the write, that
its outcome is the one the write assumes, that its inputs are the object written, or that the
target was unchanged since. With a policy, it establishes exactly the policy's checks, at the
moment it made them, and no more; `action.policy` says which policy, and the configuration says
what that policy is — the receipt carries its digest, not its text. A precondition on the
target — a revision or an ETag compared on write — is still the only thing that closes the
interval between the check and the commit, and that is the target's or the adapter's to supply:
`bind` stops a substituted object, not a concurrent edit of the same one.

A record is found by its shape, so a policy holds a write to whatever record a writer of the
decision-record directory put there. With `requireSignedRecord`, the record was signed, in its
exact bytes, by whoever holds a key the policy names: a writer who cannot use one of those keys
cannot write a record the policy admits. That establishes nothing against the holder of a named
key, the operator among them, who can sign any record, and nothing of whether the trail is
complete or when the record was written.
A target that refuses the write is a response like any other — the receipt records the
refusal bytes: the executor is started with `--error-results`, under which `adapter-mcp`
envelopes a tool result that reports an error as the result of the call, where for a read the
same result is a failed acquisition — and an executor that cannot reach the target mints
nothing.

## How it is held

- The refusal ladder above, each step with a test that reaches it and a mutation that
  removes it — the policy's steps included, and a tool with no policy shown to read nothing
  in its record, not even a record that is not JSON; the signature step against the runtime's
  own test vector, and each way a sidecar can fail to sign a record; the interleavings the session step cannot see — a session another process puts
  in the store while a read into it is admitted and running, or in the last moment before the
  read's stamp, and a seal landing between the evidence checks and admission — each held to a
  session refusal with nothing run.
- Two end-to-end tests: an acquisition, a decision record written beside it citing the
  receipt, an `/act` that cites both, then `gateway verify` over the store, the registry and
  the decision-record directory reporting every receipt `ok` — the vector
  `v3-action-valid` is what a minted store must look like, and the verifier the corpus tests
  is what judges it; and the same with the write tool held to a policy that requires a signed
  record, a chained record in the runtime's own form, the write refused while no sidecar signs
  it, a write to another revision refused once one does, both before the executor starts, and
  the receipt naming the policy by the digest the configuration gives it.
- The receipt's one new member, `action.policy`, is held by the vectors `v3-action-policy`
  and `v3-action-policy-malformed`; what the verifier compares of a record, by
  `v3-decision-pack-mismatch`, `v3-decision-cites-mismatch` and
  `v3-decision-record-not-compared`.
