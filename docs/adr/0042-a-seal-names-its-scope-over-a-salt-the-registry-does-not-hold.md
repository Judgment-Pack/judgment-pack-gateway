---
status: accepted (autopilot; maintainer may revise)
date: 2026-11-18
deciders: maintainer
---

# A seal names its scope over a salt the registry does not hold, under a new seal version

## Context and problem statement

A seal of version 2 (ADR-0036, released in v0.31.0) names its session's scope identifier by
SHA-256 over the identifier and the session's id, with no key. `/registry` is open (ADR-0037,
decision 6), so anyone who reads it and guesses an identifier can recompute the digest for each
sealed session and learn which sessions are of that scope, with their counts and seal times.
ADR-0037 recorded this as a cost and named the revisit: "before the seal of version 2 is first
released, if a keyed digest is wanted". Version 2 is released, so the remedy is a new form that
verifiers accept beside it: version 2 seals already in registries keep verifying, and new seals
use the new form.

## Decision drivers

- A reader of the registry alone, with any number of guesses, learns nothing of which sessions
  are of a scope identifier.
- A third party holding the receipts of a session and the gateway's public key checks the seal's
  scope as before, with no gateway secret and no call to the gateway.
- Every existing store verifies unchanged; a verifier that does not know the new form fails
  closed.
- No storage layout or PostgreSQL schema change, so the change can ship in one release without a
  migration.

## Considered options

1. A per-session random salt carried in the session's receipts, under their signature, and in no
   registry line; the seal's digest taken over salt, identifier and session id.
2. A per-session salt kept in a store file or table of its own, returned to the caller.
3. A digest keyed by a gateway secret (HMAC under a key derived from the seed).
4. A key per scope identifier, the digest keyed by it.
5. Refusing scope identifiers of low entropy at configuration.

## Decision outcome

Chosen option: 1, because it is the only one that removes the oracle while keeping
verification public and the store's layout as it is.

1. A receipt of a session of a scope identifier carries `scopeSalt` (SPEC.md §1.2a): 64 lowercase
   hexadecimal characters, 32 bytes the gateway draws with the system's random source when it
   mints the session's first receipt of a scope identifier, the same in every receipt of the
   session. It is under the receipt's signature, so it is tamper-evident, and it is optional, so a
   verifier written before it tolerates it as it tolerates `scope`. Out of form, or without
   `scope`, the receipt is `malformed`.
2. A seal of version 3 (SPEC.md §3) has version 2's seven members with `sealVersion` `"3"`,
   signed under `judgment-pack-gateway/seal-version/3:`; its `scopeDigest` is SHA-256 over
   `judgment-pack-gateway/seal-scope/2:` and canon of `{salt, scope, sessionId}`. A seal after an
   interruption of version 3 (§3c) is the ten members under
   `judgment-pack-gateway/seal-after-interruption/3:`. Each prefix is its own, so no seal is
   read as another version's.
3. The gateway seals a session of a scope identifier with version 3 from this release. `gateway
   seal-open` seals one whose receipts carry a salt with version 3, and one whose receipts an
   earlier release minted, carrying none, with version 2, the only form those receipts can be
   held to. A session that holds no receipt is sealed in §3's form: no receipt carries a salt,
   so a digest over one would name the scope to no reader, a session-removal record among them.
4. A verifier holds the session's accepted receipts to a seal of version 3 as to one of version
   2: a receipt of another scope, of none, of no salt or of another salt is
   `seal-scope-mismatch`. Seals of version 2 verify as before.
5. A `session-removal` record (SPEC.md §1.3a) of a session sealed with version 3 carries the
   salt as a tenth member, `scopeSalt`, and names the session only where the digest over its
   scope and salt is the seal's. `gateway remove-scope` takes the salt from the session's
   receipts, on both storage kinds.

Options 2 to 5 were not taken. Option 2 needs a new file and a PostgreSQL table, a migration,
and a way to keep the salt with the receipts in an export; carrying the salt in the receipts
does all of that already. Option 3 makes the scope check one only the gateway can make, which
ends third-party verification of the seal's scope. Option 4 needs a key per scope kept and
rotated beside the gateway's, and any holder of one receipt of a scope could still test every
session of it. Option 5 is a weak remedy: it leaves a guessable identifier guessable, and an
operator's existing identifiers would be refused.

### Consequences

- Good, because the registry alone names no scope that can be tested, and two sessions of one
  scope are sealed over unrelated digests.
- Good, because a holder of a session's receipts checks its seal's scope with the public key
  alone, as before.
- Good, because no store layout, schema, engine configuration or request changes: the salt
  travels with the receipts, so an export carries it.
- Bad, because the salt is visible to anyone holding a receipt of the session: such a reader
  already holds the scope identifier, so it learns nothing it did not have, but it can recognise
  that session's seal in the registry, as before.
- Bad, because seals of version 2 already in a registry stay testable by a guess; that cannot be
  undone without rewriting signed history. SPEC.md §6 keeps the advice to choose identifiers of
  at least 128 bits of entropy for such registries.
- Bad, because a verifier written before this release (v0.31.0 and v0.32.0, Go and TypeScript)
  loads no seal of version 3 and rejects a session-removal record of ten members. For a session
  the store holds it reports `unregistered-session`: it fails closed there, and a reader needs
  this version. For a session removed from the store it fails open: it loads no seal naming the
  session and finds none of its receipts, so it reports nothing of it, and a store holding nothing
  else it refuses is `ok` to it.
- Bad, because `finalCount`, `sealedAt` and `sessionId` of every seal remain open on
  `/registry`, of either version.
- Revisit when the registry is kept per scope, or if a session's salt is wanted outside its
  receipts.

## More information

- SPEC.md §1.2a (`scopeSalt`), §1.3a ("A removed session"), §3 ("A seal of version 3"), §3c
  ("Naming the scope"), §4 step 3, §6 (`/registry`).
- ADR-0036 (seal of version 2), ADR-0037 (the open registry and the revisit this answers),
  ADR-0034 (session-removal records).
- Corpus vectors `v3-scope-salt-*` and `v3-seal-salted-*`.
