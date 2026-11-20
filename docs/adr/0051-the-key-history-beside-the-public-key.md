---
status: proposed
date: 2026-11-19
deciders: maintainer
---

# The key history beside the public key, carried across a store rotation

## Context and problem statement

A verifier that pins the gateway's first key follows key rotations from the registry alone (SPEC.md §3b). A consumer that checks receipts one at a time, such as a receipt sink or a log pipeline, holds no registry to walk, and `/publickey` answers only the key in force, so a receipt signed before a rotation cannot be checked against it (#559). The history must cover the seed's key and every key-service key version (ADR-0050), stay current across a rotation while serving, and survive a store rotation (ADR-0048), after which the history before it lives in a registry the operator may archive or delete.

## Decision drivers

- It adds no trust: a consumer that pinned the first key checks every entry from the answer alone.
- An entry the registry's chain does not prove is never served, and a history that does not hold is a refusal, never the keys reached before it.
- A store rotated away from may be deleted under retention; the history must not need it.
- No engine configuration version: an open read path changes no configured behaviour.

## Considered options

1. **Carry the history into the new store at the rotation.** `gateway store rotate` writes the old store's history beside the new registry; the new store's gateway continues it.
2. **Read it from the old registry, named in configuration.** The history before a store continuation is walked from the registry `--previous` names.
3. **Put the history in the store continuation.**

## Decision outcome

Option 1.

- `GET /publickey/history`, open as `/publickey` is and under the same write bound, answers canon of `{keyHistoryVersion: "1", keys: [...]}` (SPEC.md §3e). Each entry is `keyId` and `publicKey`; every entry but the first has `validFrom` and the two statements of the rotation to it, as the registry's lines (`keyRotation`, `keyContinuation`); every entry but the last, the key in force, has `validTo`, the rotatedAt of the rotation from it. The first key has no `validFrom`: nothing signed says when it came into force.
- It is read from the registry at each request, walked as the gateway walks its own (§3b), seals passed over, and must end at the gateway's own key, as the gateway's own reading must: the first key-continuation's `previous` is anyone's to name, and only a walk to the gateway's key ties every key before it to that key's signature. A walk with a finding, of its rotations or its store continuation, and a history that does not hold, are answered `500` with a fixed sentence, the reason on stderr, as `/registry` is. The answer is held to the consumer's check from its own first key before it is written.
- The store rotation writes the old store's answer, its exact bytes, to the registry's path with `.key-history` appended, beside the new registry, durably and before the registry is made, so that a new registry that is there has its history beside it; a rerun that finds the new registry made carries the history where it is missing. A history that does not hold refuses the rotation. The new store's history is the carried one, its last key the one that signed the store continuation, which the new registry's rotations then end; one carried beside a registry that continues no store is refused.
- A consumer's check is §3b's, entry by entry: the first entry the key it pinned, each later entry's statements a rotation from the entry before to it, signed by both keys, of one ordinal and one rotatedAt, keys never repeated. The ordinal is held to its form only, since it starts again at 1 after a store continuation.
- **The PostgreSQL kind.** Its store rotation (#546) is to a new database or schema; it must write the history of the database rotated from into the new one beside its registry and `gatewayService.carriedKeyHistory` (go/key_history.go) must read it there; `store rotate`'s refusal of the kind names the same place. Until then a PostgreSQL registry continues no store, and every instance answers its walk, read at each request from the one registry they share.

### Why not option 2

It needs the store the operator was told is theirs to delete whole (ADR-0048), a configured path, and so an engine version, and a gateway reading another store's files at each request.

### Why not option 3

The store continuation is a closed form (§3d), linked to the old registry by its digest; a member more is a new `continuationVersion` that older verifiers report as a forged continuation.

### Consequences

- Each request reads the whole registry and parses each line, as `/registry` reads it; no seal's signature is checked.
- Between a rotation's append and its switch (ADR-0050) the registry ends at a key the gateway does not yet hold, and the history answers `500` for that moment.
- A store rotated before this change has no history carried and, its rotation marked, no rerun: its gateway answers from the key in force at its continuation, which a consumer pinning the first key refuses.
- No corpus vectors: the corpus's families are readings of a store, of witness statements, or of a witness's storage, each with its runner in `gateway conform` and the process contract; this answer is none of them, and the statements it carries are §3b's, whose checks the rotation vectors of `corpus/stores` hold. Its checks are held by go/key_history_test.go.
