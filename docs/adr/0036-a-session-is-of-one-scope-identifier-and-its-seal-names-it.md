---
status: accepted (autopilot; maintainer may revise)
date: 2026-11-16
deciders: maintainer
---

# A session is of one scope identifier on every storage kind, and its seal names it under a new seal version

## Context and problem statement

Receipts carry the scope identifier under the signature (ADR-0026). Sessions, seals and registry
lines do not (issue #442): on the filesystem kind a session may hold receipts of several scope
identifiers, and of scoped and unscoped sources alike, and no seal names a scope, so a reader of
a seal cannot tell which scope it covers without reading each receipt, a removal of one scope
(ADR-0034) must refuse a session that mixes, and nothing a verifier reads ties a seal to a scope.
The PostgreSQL kind already holds a session's receipts to one scope (ADR-0033, decision 4), and
its seals name none either. Checked on `main` at v0.30.0 before this record: `admit` refuses an
acquisition of another scope only where the kind keeps scopes apart (`g.keeper != nil`), and the
seal is §3's four signed members on both kinds; the frozen vector `v3-scope-valid` is a sealed
session whose two receipts carry two scope identifiers, and verifies `ok`.

## Recommendation

Option (a): a session is bound to the scope identifier of its first acquisition, on every kind,
and an acquisition or an action of another scope, or of none, is refused before anything runs;
the seal of a session bound to a scope identifier is of a new seal version that names it under
the signature, and a verifier of this version holds the session's receipts to it. A session of
no scope is sealed in §3's form as before, byte for byte, and every store an earlier release
wrote verifies as it did. `gateway verify` and `gateway export` do not select by scope in this
change; the operator page says why (decision 7).

## Decision drivers

- A store an earlier release wrote verifies byte for byte as it did, every frozen vector
  included (`v3-scope-valid`, whose sealed session mixes two scope identifiers, among them).
- A seal is signed by the gateway's key over every member it carries: no member a verifier reads
  can be added, removed or changed without the seal loading nothing, and no new form can be read
  as an old one or the reverse.
- What a seal says of a scope is what the receipts it counts say, and a verifier checks it.
- One answer for both storage kinds (ADR-0033 already binds a session on PostgreSQL), and for
  several instances (ADR-0035: a session is held by the instance that minted it, so the binding
  in that instance's memory is the session's).
- Removing one scope (ADR-0034) meets fewer sessions it must leave whole.
- Both verifiers agree, and a verifier written before the change fails closed on the new form
  rather than reading it as the old one.

## Considered options

- **(a) A session bound to at most one scope identifier, refused otherwise, its seal naming it.**
- **(b) Sessions left mixed, the seal listing the scope identifiers it covers and a count for
  each.** A seal would need a list of variable length under the signature, and a verifier would
  count each receipt's scope against it. It keeps the filesystem kind's freedom to mix, which no
  caller is known to need, and the PostgreSQL kind could not make such a session at all (ADR-0033,
  decision 4: a session's series is one scope's), so the two kinds would answer differently for
  ever. A removal of one scope would still meet sessions it must leave whole, and a seal with a
  per-scope count still cannot be cut: the session's chain runs through every scope's receipts.
- **(c) The limit documented.** Nothing changes for earlier stores, but a seal still names no
  scope, the two kinds still differ, and the consequences of #442 stand.

## Decision outcome

Chosen option: (a), because it is the one under which a session and its seal are of one scope on
both kinds -- the PostgreSQL kind already works so, and the filesystem kind's freedom to mix is
what makes a removal by scope leave sessions whole and a seal unattributable -- and because a
seal that names one scope identifier is a fixed set of members, signed like the seal after an
interruption (§3c), where (b) needs a list and a count per entry. The cost (a caller who mixed
scopes in one session is refused) falls on a use that ADR-0026 recorded as a gap, not a feature.

1. **A session is of one scope on every kind.** The scope of a session is that of the source of
   the first acquisition this process admits into it ("" for none), held in the process's memory
   as on the PostgreSQL kind (`sessionState.scope`). An acquisition into a session of another
   scope identifier, of a scoped source into a session of no scope, or of an unscoped source into
   a scoped session, is refused `400` at admission, before the source runs, with ADR-0033's
   sentence, which names neither scope and no longer names a kind. An action (`/act`) into a
   session of a scope identifier is refused at its session step, since an action receipt carries
   no scope (ADR-0026, decision 6). A session this process does not hold is taken up only where
   the store holds no receipt in it (open_sessions.go), so its binding is always this process's;
   on the PostgreSQL kind the series row and its holder keep the scope as before.

2. **A seal of version 2.** A session of a scope identifier is sealed by

   ```
   { "finalCount": <integer>, "keyId": <hex>, "scope": <string>, "sealVersion": "2",
     "sealedAt": <string>, "sessionId": <string>, "signature": <hex> }
   ```

   its signature over `"judgment-pack-gateway/seal-version/2:"` and canon of the record without
   `signature`, every other member retained. A session of no scope is sealed in §3's form, the
   bytes it was sealed with before. The member `sealVersion` is what selects the form: a registry
   line that is one JSON object holding `sealVersion` and no `kind` is read as a seal of that
   version and as nothing else; `"2"` loads when the line holds exactly these seven members, each
   of its form (`scope` by ADR-0026's one function, `finalCount` from 0 to 2^53-1, `sealedAt` and
   `keyId` as §3c's), its `keyId` is the current key's at its line and its signature verifies; a
   line of any other `sealVersion` loads nothing.

3. **A seal after an interruption names the scope too.** `gateway seal-open` and the start's
   switch (§3c) seal a session every receipt of which carries one scope identifier with §3c's
   eight members and `scope` and `sealVersion: "2"`, signed under
   `"judgment-pack-gateway/seal-after-interruption/2:"`; a session of no scope, and a session an
   earlier release left open holding receipts of several scopes, or of a scope and none, in §3c's
   form as before. On the PostgreSQL kind the session's scope is its series' row.

4. **What a verifier checks.** A seal of either kind that names a scope anchors its session as
   its form without the member anchors it (counts, head). Beside that, at §4 step 3, a session
   whose first loadable seal names a scope identifier and that holds a receipt whose ladder
   status is `ok` and whose top-level `scope` is not that string, byte for byte (absent included),
   is **`seal-scope-mismatch`**, `{sessionId, status}`, once; the receipts' own findings stand
   beside it. It is listed with the seal findings of §5a.1. A seal of a form that names no scope
   asks nothing of its receipts' scopes, so a session an earlier release sealed over receipts of
   several scopes verifies as it did.

5. **Verifiers written before.** A verifier of v0.30.0 or earlier reads a seal of version 2 as a
   §3 seal: its signature does not verify over §3's four members under §3's prefix, so the seal
   loads nothing and the session is `unregistered-session`; it holds a seal after an interruption
   of ten members to §3c's eight and loads nothing either. It fails closed: no new seal is read as
   an old one. Readers of a scoped store need a verifier of this version.

6. **Registry lines.** The registry holds seals of §3's form, seals after an interruption, seals
   of version 2 and the rotation statements of §3b. A seal is of one session; under this decision
   a seal of version 2 names the scope of the session it seals, and a seal of §3's or §3c's form
   that this release writes is of a session of no scope (or, for §3c, one an earlier release left
   mixed). Seals an earlier release wrote name none, whatever their sessions held. A rotation
   statement is of the key, of no source, and names no scope. The removal records of
   `artifact-removals.jsonl` (ADR-0034) are no registry lines and already name the scope.

7. **Export and verify do not select by scope.** The registry is one chain that a verifier needs
   whole (§3b: the walk from the pinned key), and §4 step 4 reports every sealed session a store
   does not hold `sealed-session-missing`: a cut by scope would read as a damaged store. A
   verifier that excused an absent session by its seal's scope could do so only for seals of
   version 2; a seal of §3's form names no scope, and those an earlier release wrote may be of any
   session, so a cut could not be shown to hold every session of a scope that was sealed before
   this release. A verdict by scope is therefore a change to §4 and §5a, to both verifiers and to
   the corpus, and is left to its own issue. Until then a consumer of one scope verifies the
   whole store, or an export of it, and may take a session-scoped verdict (§5a.1) for each of the
   scope's sessions, whose seal now names the scope.

8. **Versions.** No engine configuration version and no receipt version are added: no
   configuration member is added, and a receipt is unchanged. The seal gains a version member;
   the PostgreSQL schema is unchanged (the registry's rows hold a line's bytes). SPEC.md §3, §3c,
   §4 step 3 and §5a.1, both verifiers and the corpus move together.

### Consequences

- Good, because a reader of a seal that loads under the operator's key learns which scope
  identifier its session is of, and a verifier of this version checks that every accepted receipt
  it counts says the same.
- Good, because the two storage kinds answer an acquisition of another scope alike, and a removal
  of one scope meets no session this release made that it must leave whole.
- Good, because a session of no scope, its seal and every store an earlier release wrote are
  byte for byte what they were, and verify as they did.
- Bad, because a caller that put acquisitions of several scopes, or a scoped and an unscoped
  source, into one session on the filesystem kind is now refused and must use one session per
  scope; an action cannot share a session with a scoped acquisition.
- Bad, because a verifier written before this change reports every session sealed by version 2
  `unregistered-session`; a reader of a store with scoped sessions needs this version.
- Bad, because seals an earlier release wrote stay unattributed, so nothing selects a scope's
  sessions by seal across a store's whole history, and export and verify still read a whole store.
- Revisit when a verdict by scope is designed (its own issue), when a caller's token is held to a
  scope (ADR-0026), or when the registry is kept per scope.

## More information

- Issue #442; ADR-0026, decisions 6 and 7 and its consequence "nothing binds a session to one
  scope identifier"; ADR-0033, decisions 4 and 5; ADR-0034 (removal by scope); ADR-0035 (a
  session held by its minting instance).
- SPEC.md §3 ("A seal of version 2"), §3c, §4 step 3, §5a.1; `go/serve.go` (`admit`,
  `sealSession`), `go/act.go` (`admitAction`), `go/store.go` (`registryWriter.seal`,
  `sealAfterInterruption`), `go/rotation.go` (the walk's loading), `go/seal_open.go`,
  `go/seal_open_pg.go`, `verify-ts/src/verify.ts`; the corpus vectors `v3-seal-scope-*`.
