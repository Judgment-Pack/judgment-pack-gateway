---
status: proposed
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

## Amendment: a verdict and an export by scope (#478)

ADR-0036, decision 7, left a verdict by scope to its own issue, because seals an earlier release
wrote name no scope. Once the salt is in the receipts, a verifier that holds a store's receipts
can attribute a sealed session to a scope without the registry naming one. This amendment adds
decisions 6 to 9.

6. **Attribution by what is signed.** `gateway verify --scope S` and verify-ts's `verify --scope
   S` run the whole verdict (SPEC.md §4). They then attribute each session the store holds, and
   each sealed session it does not, to S, to another scope or none, or to neither
   (unattributed). A receipt counts where it passes SPEC.md §1.4's first six orders, so what it
   carries is the gateway's:
   - a held session is of S where such a receipt carries S;
   - otherwise, a seal of version 2 is attributed by recomputing its unkeyed digest;
   - a seal of version 3 is attributed to another scope where a held receipt's scope and stored
     salt digest to it;
   - a seal naming no scope is attributed to another scope where the store holds every receipt
     it counts, signed, and for a seal after an interruption its head;
   - a session no seal closes is attributed to another scope where its signed receipts each
     carry another scope and a salt;
   - a session gone is attributed by its session-removal record, or by a seal of version 2.

   Every other session is unattributed. The verdict reports what it finds of the sessions of S,
   of those unattributed, and of the registry's walk, and names the two lists in a `cut` member.
7. **An incomplete cut is reported, never left out.** #478 offered two rules: refuse the
   selection where earlier, unscoped seals are held, or report the cut incomplete and name what
   could not be attributed. The verdict reports. It names those sessions in `cut.unattributed`,
   reports their findings and observations, and is not `ok`. Refusing would give an operator of
   a store an earlier release wrote no verdict by scope, ever, and nothing to show which sessions
   stand in the way, since seals already written cannot be rewritten. A verdict that is not `ok`
   fails closed for a consumer that reads `ok` (SPEC.md §5a.2). It names what to act on, and it
   still lets a consumer take a session-scoped verdict for a session of the scope. The export
   refuses instead (decision 8): no file a verifier reads could say that a session was left out.
8. **An export by scope carries nothing of another scope.** `gateway export --scope S` writes:
   - the sessions of S, and the artifacts their receipts name;
   - the removal records of those sessions and of S;
   - the registry's rotation statements, and every line naming a session of S, in order and
     byte for byte;
   - a manifest naming S.

   It is refused, by name and before anything is written, where the gateway's own reading of
   its registry finds anything, where a session is unattributed, and where a session of S holds
   a signed receipt of another scope or none (only a release before ADR-0036 mints such a
   session). A session written whole would carry those receipts, and one written in part would
   break its chain. Every rotation is kept and the walk found nothing, so the export's registry
   walks from the pinned key to each line it keeps under the same key as the registry does.
   Against its own registry the export verifies by S as the store does by S, and whole to the
   same findings.

   It discloses nothing of another scope: no session id, count, seal time, digest, receipt or
   identifier. It shows the key's rotations, which are of the key. It does not show that the
   store held no other session of S. That rests on the exporter's attribution, which a reader of
   the export alone cannot repeat. A reader holding the gateway's registry bounds it (SPEC.md
   §5a, "An export by scope").
9. **Versions.** No receipt, seal, registry line, engine configuration or PostgreSQL schema
   changes. The verdict carries `cut` under the option alone. The export manifest gains an
   optional member `scope` under the same `exportVersion`. A `gateway export --check` written
   before it refuses a manifest holding the member, as one it does not know, which fails closed,
   and reads every other export as before. A verifier written before the option refuses it, and
   so disagrees with each corpus vector of a verdict by scope (`v3-cut-*`).

Options not taken:

- **Refusing a verdict by scope on any store holding a seal that names no scope.** Every store an
  earlier release wrote would then have no verdict by scope, permanently.
- **An export carrying the whole registry.** Its seals of version 3 of other scopes would be
  sealed sessions the export does not hold and cannot attribute, so the export would not verify
  by its scope. It would also hand a reader of one scope every other session's id, count and seal
  time, open on `/registry` but not that reader's to be given in an export.
- **An export carrying the salts of the sessions it leaves out,** so that its reader could show
  that each left-out seal is not of S. It would make each such seal testable by a guessed
  identifier for that reader, which undoes decision 1 for them.
- **An export holding a session of several scopes whole.** It would carry another scope's
  receipts, with their identifiers in clear.

Consequences:

- Good, because a consumer of one scope gets a verdict and an export of exactly its sessions, and
  a store an earlier release wrote says which sessions stand in the way.
- Bad, because a store holding a session an earlier release left open, or sealed in §3's form
  over a receipt it no longer holds, has no complete cut for as long as it holds that session.
  Its export by scope is refused; such a store is verified and exported whole.
- Bad, because the completeness of an export by scope rests on the exporter's attribution: a
  reader holding the gateway's registry bounds it, and cannot close it.
- `/verify` over HTTP is unchanged and stays a verdict of the whole store (ADR-0037).
- Corpus vectors `v3-cut-*`; SPEC.md §4 ("A verdict by scope"), §5a ("An export by scope"), §7;
  `docs/design/store-contract.md` ("The audit export").
