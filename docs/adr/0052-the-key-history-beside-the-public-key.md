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
- The store rotation writes the old store's answer, its exact bytes, to the registry's path with `.key-history` appended, beside the new registry, durably and before the registry is made, so that a new registry that is there has its history beside it. The new registry's store continuation names those bytes: `keyHistoryDigest`, the lowercase hexadecimal SHA-256 of the file, of `previousDigest`'s form, inside what the continuation signs (§3d). A history that does not hold refuses the rotation. A rerun that finds the new registry made holds the history beside it to that digest, refusing where its bytes are other ones and nothing changed, and writes it again where it is missing, from the same bytes, only where they are the ones named. The new store's history is the carried one, its bytes the ones named and its last key the one that signed the store continuation, which the new registry's rotations then end; a continued registry with none carried, or one whose bytes are not the ones named, and one carried beside a registry that continues no store, are answered `500`.
- The member is required of every store continuation: every rotation carries a history, the continuation was not yet released, and a member present only when a history is carried would leave a continuation without it answering the shorter history this binding exists to refuse.
- A consumer's check is §3b's, entry by entry: the first entry the key it pinned, each later entry's statements a rotation from the entry before to it, signed by both keys, of one ordinal and one rotatedAt, keys never repeated. The ordinal is held to its form only, since it starts again at 1 after a store continuation.
- **The PostgreSQL kind.** Its store rotation (`storeRotatePostgres`) builds the history of the database rotated from and names it by `keyHistoryDigest` in the continuation it writes, but does not yet carry the bytes into the new database. Until it does and `gatewayService.carriedKeyHistory` (go/key_history.go) reads them there, a gateway on a rotated database answers the history `500`: the history it names is carried nowhere, and no shorter history is served. A database never rotated into answers its walk, read at each request from the one registry every instance shares.

### Why not option 2

It needs the store the operator was told is theirs to delete whole (ADR-0048), a configured path, and so an engine version, and a gateway reading another store's files at each request.

### Why not option 3

The store continuation is a closed form (§3d), linked to the old registry by its digest, and read by every verifier; the history, a statement pair per key, would make each continuation line grow with every rotation the gateway ever made. The continuation names the carried history by its digest instead, as it names the old registry: a member added while the continuation was not yet released, so no `continuationVersion` changed.

### Consequences

- Each request reads the whole registry and the carried history, and hashes them; the answer is made again, each line parsed, only when a byte of either, or the gateway's key, is not the last answer's. No seal's signature is checked.
- Between a rotation's append and its switch (ADR-0050) the registry ends at a key the gateway does not yet hold, and the history answers `500` for that moment.
- A carried history lost, in a restore or by its deletion, or cut, is answered `500` until the bytes named are back beside the registry: a consumer is told the history cannot be read rather than given a shorter one.
- No corpus vectors: the corpus's families are readings of a store, of witness statements, or of a witness's storage, each with its runner in `gateway conform` and the process contract; this answer is none of them, and the statements it carries are §3b's, whose checks the rotation vectors of `corpus/stores` hold. Its checks are held by go/key_history_test.go. The store-continuation vectors of `corpus/stores` hold `keyHistoryDigest` as a member of the continuation, required and of its form; no vector holds the history itself, which a verifier is not given.
