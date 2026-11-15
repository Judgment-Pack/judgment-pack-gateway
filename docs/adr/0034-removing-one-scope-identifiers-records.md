---
status: proposed
date: 2026-11-15
deciders: maintainer
---

# Removing one scope identifier's records: a signed removal of each sealed session that the verifier reads, made with the gateway stopped and, on the PostgreSQL kind, by the migration login

## Context and problem statement

The gateway removes one kept payload under a signed record (`gateway remove-artifact`,
ADR-0028, SPEC.md §1.3a) and has no operation that removes everything of one scope identifier
(ADR-0026) from a store (issue #434, and condition (h) of #430). What makes this more than a
deletion is the verifier: the registry is one append-only chain whose seals name no scope, and
a sealed session absent from the store is `sealed-session-missing` (SPEC.md §4, step 4), a
finding that fails the store-wide verdict (§5a.1). So a removal that leaves the seals, as it
must, makes every other scope's receipts read as a damaged store, and nothing tells a removal
from a deletion. Telling them apart needs a record the verifier reads, which is a change to
SPEC.md, to both verifiers and to the corpus. This record sets out the options; nothing of it
is built.

## Decision drivers

- After the call, every other scope identifier's receipts verify as before, and the store-wide
  verdict is `ok` where it was.
- A verifier reading the store, or an export of it, tells a removed session from a missing one
  by signed bytes in the store alone, under a key the registry's walk reaches, as it tells a
  removed payload from a missing one.
- No receipt or seal changes form; a store with no such record verifies as today, byte for byte,
  and every corpus vector stands.
- The run-time login of the PostgreSQL kind gains no DELETE (ADR-0031, decision 6).
- What remains after the call is stated, and a search of the store for the scope identifier, or
  for a payload's bytes, finds only that.
- The gateway is stopped while the call runs, as for `remove-artifact`, and a call cut off
  midway is completed by running it again.

## Considered options

For what the verifier reads:

- **A. One signed record per sealed session removed, in `artifact-removals.jsonl`, and one
  for the call.** A record of kind `session-removal` names the session (`sessionId`), its seal
  (the seal's `signature` and `finalCount`), the scope identifier, `removedAt`, `removedBy`,
  `keyId` and its signature, under its own signing domain; a record of kind `scope-removal`
  names the scope identifier, the counts removed (sessions sealed and open, receipts, payloads)
  and the same four members. Each is one line under the existing bound (4096 bytes) and loads
  by the existing rules (§1.3a, "Loading"). §4 step 4 changes: a sealed session absent from the
  store that a loaded `session-removal` record names, by session and seal, is no finding and
  carries the observation `session-removed`; a session the record names that is still in the
  store is verified as it is (a call cut off before its files went). A verifier written before
  this reports `sealed-session-missing` for such a session, as today.
- **B. One record for the whole scope, listing its sessions.** Fewer lines, but a scope's
  sessions do not fit the line bound, so the bound would rise or the record would span lines.
- **C. Remove the seals too.** The registry is append-only on both kinds (the PostgreSQL kind's
  run-time login holds no UPDATE or DELETE on it, and from schema version 4 its records are one
  chain), and a seal is what anchors a session against its tail being taken away (§2). Taking
  seals out would make a deleted session and a removed one read alike, which is the failure.
- **D. No verifier change.** The removed sessions stay `sealed-session-missing`; a consumer may
  take a session-scoped verdict (§5a.1) for another scope's session. The store-wide verdict is
  `ok: false`, and nothing tells a removal from damage; the drivers are not met.

For who removes on the PostgreSQL kind (the run-time login holds no DELETE):

- **1. The migration login, by SET ROLE to the owner, in a command of its own**
  (`gateway store remove-scope`, taking the connection as `store migrate` does): one
  transaction that holds the start lease (so no instance serves), sets `gateway.scope` to the
  scope's form for itself, so that the forced policy admits that scope's rows alone, names the
  scope in every DELETE besides, appends the records, and commits; the owner holds DELETE as the
  tables' owner. The records need a table of no scope (a new migration, SELECT and INSERT for
  the run-time role, so the export can write `artifact-removals.jsonl` from it).
- **2. A removal login of its own,** made by the operator, given DELETE on the scoped tables by
  `grants.sql`: a fourth role and a second grantee in the grants, for one command.
- **3. The run-time login with DELETE:** refused by ADR-0031, decision 6.

## Decision outcome

Recommended, for the maintainer to decide: **A** with **1**, because A reuses the file, its
loading rules and its bound, needs one change to one step of §4, and lets a verifier pair each
`sealed-session-missing` with a signed record of the session and its seal; and 1 adds no role
and no grant, and keeps the removal under the same lock and lease the migration and the
start already hold.

The narrowest form that meets the drivers, once decided:

1. `gateway remove-scope --scope <identifier> --by <label>` on the filesystem kind, the gateway
   stopped: it removes each session all of whose receipts carry the scope (their files and
   directory), and each payload that only those receipts name. A session holding receipts of
   the scope and of another scope or none is refused by name and left whole, since removing a
   part of it would break the chain of the receipts left (ADR-0026: on this kind nothing binds
   a session to one scope); so is a receipt outside the scope that cites one inside it. Every
   record is appended and made durable before any file is removed, as for `remove-artifact`.
2. `gateway store remove-scope` on the PostgreSQL kind, as in option 1, removing the scope's
   rows of `blobs`, `series`, `entries` and `documents` and its row of `scope_identifiers`.
3. What remains, stated on the operator page: the seals of the removed sessions (a session's
   id, its count, its time, the key's id and a signature: no receipt, payload or scope, though a
   session's id is the caller's and may say anything); the removal records, which name the
   scope identifier, the sessions and the counts; a payload's bytes another scope's receipt also
   names (on the filesystem kind, where one file holds them); and what lies outside the store:
   decision records and the action journal, which are the runtime's and the gateway's own files.
   The gateway holds no credential or cursor of a scope in the store: a source's credentials
   are the operator's files, and a token obtained for a scope is held in memory alone
   (ADR-0027).
4. SPEC.md §1.3a and §4 step 4, the Go and TypeScript verifiers, new store vectors (a store with
   a removed scope beside another scope's sessions, and the same store with a record taken
   away, which is `sealed-session-missing` again), and the conformance material, in one change.

### Consequences

- Good, because a removed scope's sessions read as removed, under the operator's key, and
  every other scope verifies as it did.
- Good, because no receipt, seal or existing record changes, and a store without the new
  records verifies as today.
- Bad, because it is a change to SPEC.md: a verifier written before it reports
  `sealed-session-missing` for each removed session and fails the store.
- Bad, because the records keep the scope identifier and the sessions' ids in the store after
  the call, as `remove-artifact`'s keep a receipt's signature.
- Bad, because on the filesystem kind a session of mixed scopes cannot be removed in part; the
  call names it and leaves it.
- Revisit when sessions are bound to one scope on every kind (ADR-0031, "Decisions open"), or
  when a seal names its scope (#442).

## More information

- Issue #434; #430, condition (h); ADR-0026; ADR-0028; ADR-0031, decision 6 and "Decisions open
  to the maintainer"; ADR-0033.
- SPEC.md §1.3a (removal records, their loading), §3 (the seal), §4 step 4
  (`sealed-session-missing`), §5a.1 (the store-wide verdict).
