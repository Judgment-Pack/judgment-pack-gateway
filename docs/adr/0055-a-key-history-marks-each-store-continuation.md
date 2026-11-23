---
status: proposed
date: 2026-11-22
deciders: maintainer
---

# A key history that marks each store continuation, so a repeated ordinal is refused

> **Summary (draft, unfinished).** Leaning to option 1: `keyHistoryVersion` `"2"` carries each store
> continuation the history crossed as a signed mark, the continuation's own registry line, on the entry of
> the key in force at that store rotation. Under `"2"` a rotation's `rotation` ordinal is one more than the
> one before it, and is 1 only at the first rotation and at the first after a store-continuation mark.
> Version `"1"`, and every `keyHistoryDigest` that names one, verify byte for byte as before.
> New members: TODO (working name `storeContinuation`, an entry member holding the registry line of a
> store continuation, without its `0x0A`).

## Context and problem statement

A key history's `rotation` ordinal is held to its form alone (SPEC.md §3e; `checkKeyHistory`,
`go/key_history.go:166`). It counts within one registry (§3b, step 3 of the walk) and starts again at 1
after a store continuation (§3d, ADR-0052), and `keyHistoryVersion` `"1"` carries no mark of a store
continuation. A verifier that reads only the history therefore cannot tell a repeated ordinal after a real
`gateway store rotate` from a replayed or corrupted rotation. The registry walk refuses the second as
`rotation-order`; the history alone cannot (#578).

## Decision drivers

- Version `"1"` histories, the carried `.key-history` bytes and the `gateway.key_history` row, and every
  `keyHistoryDigest` that names them, verify byte for byte unchanged.
- A history-only verifier refuses a repeated or skipped ordinal under the new version, Go and TypeScript.
- No record that a verifier of the registry reads changes: §3b's statements and §3d's continuation keep
  their bytes and their walk.
- A consumer of an earlier release refuses the new version, never reads it as `"1"`.
- Both storage kinds can produce it from what they already hold.

## Considered options

1. **A store-continuation mark in the history.** The history carries, at each store rotation it crossed,
   the store continuation itself, signed as it already is (§3d), on the entry of the key in force then.
   Ordinals restart at 1 after such a mark and nowhere else.
2. **Ordinals that keep counting across store rotations,** so any repeat is a replay.
3. TODO: any third option (for example a per-history rotation count signed elsewhere) to be weighed.

### Findings so far (from the code at 12b0f43)

- **A consumer of v0.38.0 refuses another version.** `checkKeyHistory` refuses any `keyHistoryVersion`
  other than `"1"`: `go/key_history.go:175-176` ("keyHistoryVersion is not \"1\""). It also refuses an
  entry member it does not list (`go/key_history.go:33`, `:241`).
- **verify-ts has no key-history check.** It reads `keyHistoryDigest` only as a member of the store
  continuation's form (`verify-ts/src/verify.ts:1846`, `:1868`); ADR-0053 §3 records the history as "not
  read" by verify-ts. Refusing a repeat in TypeScript means adding the whole §3e check there, not a change
  to an existing one. TODO: decide its scope (question for the maintainer).
- **Option 2 changes the registry walk.** §3b step 3 holds a `key-rotation`'s ordinal to one more than the
  rotations followed in that registry, from 0. Ordinals that keep counting would have a new store's first
  rotation signed as N+1, which every verifier of the registry, of this and earlier releases, refuses as
  `rotation-order`, unless the store continuation names the count before it: a new continuation member, so
  a `continuationVersion` `"2"`, and a change to §3b, §3d, both verifiers' walks and the `corpus/stores`
  vectors. The ordinal is inside each statement's signature, so no history can renumber what was signed.
- **Option 1 needs no new signed record.** The continuation is the new registry's first line, signed by
  the key in force, and `registryKeyHistory` already holds it (`go/key_history.go:105-150`,
  `w.continuation`). It binds the old registry by `previousLines` and `previousDigest` (the SHA-256 of the
  old registry's bytes whole, not of its last line, as #578 words it) and the carried history by
  `keyHistoryDigest`.

## Decision outcome

TODO. Leaning to option 1, for the two reasons above: it leaves every registry record and walk unchanged,
and the mark it carries is already signed.

TODO, still to decide and write:

- the member, its place (entry member, or a list beside `keys`), and its check: the line holds §3d's form,
  its `keyId` and `alg` the entry's, its signature verifies under the entry's key, its `continuedAt` within
  the entry's validity, and its `keyHistoryDigest` against the history it follows (or not: a history-only
  verifier holds no carried bytes);
- the ordinal rule under `"2"`, exactly;
- which version a gateway serves (opt-in by engine configuration `<engine-version: assigned at merge>`,
  or `"2"` only for a new store, or always `"2"` with a history crossing no store continuation), and how a
  consumer learns it (`keyHistoryVersion` in the answer; whether `/publickey` names it);
- what a carried history of version `"1"` becomes inside a `"2"` answer, and the `keyHistoryDigest` of a
  `"2"` history carried by a later store rotation;
- the interaction with `alg` (ADR-0053), `keyRotation` and `keyContinuation`;
- the PostgreSQL kind (`go/store_rotate_key_pg.go`, `gateway.key_history`).

## SPEC text

TODO: the exact sentences for §3e (and §3d, if touched).

## Vectors

TODO: verify-only vectors with expected verdicts, among them a replay refused under `"2"` and accepted
under `"1"`; where they live (ADR-0052 put no history in the corpus).

## What the release notes must say

TODO.

## Build plan

TODO: one pull request; the tests; the mutation checks.

## Consequences

TODO.
