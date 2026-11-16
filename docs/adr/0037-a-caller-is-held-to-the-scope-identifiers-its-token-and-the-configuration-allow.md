---
status: accepted (autopilot; maintainer may revise)
date: 2026-11-16
deciders: maintainer
---

# A caller is held to the scope identifiers its token names and the configuration grants its subject

## Recommendation

A caller's signed token names the scope identifiers it is for in one claim, `scope_ids`, the
claim the Runner reads in the same form (its ADR 0002, issue #304), so that one issuer serves
both. Engine configuration version 27 adds `identity.callerScopes`, which grants each subject
what it may be for. A request is held to the claim's scope identifiers, each of which the
subject's entry must grant, or the token is refused `401` before any route. The check is the
default: a configuration without the member holds every caller to the sources of no scope
identifier, and `callerScopes: "unchecked"` is written to keep the behavior before this change.
The start and `/posture` say which. Every route that reaches a session of a scope identifier
answers a caller of another one as it answers a request for a scope or a session that is not
there. The receipt records the caller as before, and not the claim.

## Context and problem statement

A source fixed to a scope identifier (ADR-0026) is served to a request that names the identifier,
and a session is of one scope identifier (ADR-0036). Nothing tied the caller's verified identity
to the identifier it named (issue #479): any admitted caller could name any scope identifier,
seal another scope's session, and read the store-wide verdict. Checked on the #442 branch before
this record: `scopeHolds` compares the request's `scope` with the source's and reads nothing of
the caller, and `/seal` and `/verify` read none either.

## Decision drivers

- Two keys: an issuer cannot widen a caller's reach on its own, and an operator's configuration
  grants nothing the issuer did not make the token for.
- One claim form for the gateway and the Runner, and the same reach for the same token.
- A refusal tells a caller nothing of a scope identifier or a session it may not use.
- A configuration that forgets the member is held, not opened; the start says so.
- No receipt, seal or registry line changes form; every store verifies as before.

## Decisions

1. **The claim.** `scope_ids`: a JSON array of 1 to 256 strings, each once, each a scope
   identifier in §1.2a's form or the marker `"unscoped"`, which names the sources of no scope
   identifier and is never a scope identifier a caller is granted; or absent. It is read only
   after the signature, issuer, audience, subject and validity checks pass. A claim present and
   not of the form refuses the token, `401`: "the token's scope_ids is not 1 to 256 scope
   identifiers, each once".
2. **The configuration.** `identity.callerScopes`, a version-27 member: the string `"unchecked"`,
   or an object whose names are subjects of the identity's one issuer and whose values are
   `"unscoped"`, `"installation"`, or an array of 1 to 256 strings, each once, each a scope
   identifier or the marker `"unscoped"`. A subject with no entry is `"unscoped"`. Absent, every
   subject is `"unscoped"`. An earlier version refuses the member by name.
3. **What a token reaches** (checked). `"installation"` grants every scope identifier and the
   marker.

   | Claim | Entry | Reach |
   |---|---|---|
   | absent | `"installation"` | every source, of every scope identifier and of none |
   | absent | `"unscoped"`, none, or a list holding the marker | the sources of no scope identifier |
   | absent | a list without the marker | refused `401` (decision 4) |
   | `S`, each granted | any | the scope identifiers of `S`; the sources of no scope identifier only if `S` holds the marker |
   | `S`, one not granted | any | refused `401` (decision 4) |

   The intersection is computed and a wider claim refused, not narrowed: a mis-issued token does
   not work in part.
4. **One refusal for a token the entry does not grant.** A claim wider than the entry, and a
   claimless token whose entry is a list without the marker, are refused `401` with one
   sentence: "the token's scope_ids names a scope identifier the configuration does not grant
   its subject". Neither names a scope identifier or the subject.
5. **A delegated request** (SPEC.md §11) carries no claim, and the chain's subject is stated by
   the issuing host, not by the identity's issuer: it reaches the sources of no scope identifier
   where its subject's claimless token would reach them, and never a scope identifier, an
   `"installation"` subject included. A host cannot widen a subject's reach.
6. **The routes.**
   - `/acquire`: the source's scope identifier must be the one the request names (as before)
     and one the caller reaches; otherwise the same `400` and sentence as a wrong scope, before
     the trail, the publisher policy, the grant, the admission, a delegation's count or the
     source. The scope the store, the admission and the receipt take is the source's, once both
     hold; on the PostgreSQL kind it chooses the transaction's view, so the view is one the
     caller's identity reaches, never one the body alone names.
   - `/act`: a write source and an action receipt are of no scope identifier (ADR-0026). A caller
     that does not reach the sources of no scope identifier is refused `403`, `refusedAt:
     "scope-identifier"`, before the body is read, so every answer it gets is the same whatever
     session it names. A caller that reaches them is answered as before.
   - `/seal`: a session whose scope the caller does not reach is answered `no such session`,
     byte for byte the answer for a session the gateway does not hold, before anything else of
     the session is read: one this process holds, and one it does not -- left open by another
     process, held by another instance serving the database, or unreadable -- whose scope the
     store gives (on the PostgreSQL kind its series' scope, on the filesystem kind its first
     receipt's). Where the store cannot give the scope, a caller that does not reach every source
     is answered so too. A seal in the registry is said to be one, since `/registry` serves it
     to anyone. An `/acquire` into a session of another scope than its source's is refused with
     the other-scope sentence whatever else the session holds, on both kinds.
   - `/verify`: the verdict is of the whole store and cannot be cut by scope (ADR-0036, decision
     7). It is served to a caller that reaches every source, and, where the configuration fixes
     no source to a scope identifier and the store holds no session of one (a receipt holding
     `scope`, or a seal of version 2), to one that reaches the sources of no scope identifier;
     every other caller is refused `403`, before the store is read where the configuration
     decides it, and with the same answer once the verdict finds such a session (of a scope
     since removed from the configuration, say).
   - `/registry` and `/publickey`: served whole to every caller, as open routes that need no
     token. Refusing a token there closes nothing, since the same bytes are served without one;
     filtering breaks the registry's chain, which a verifier walks whole (ADR-0036, decision 9).
     No registry line carries a scope identifier or a caller.
7. **Unchecked, and no identity.** With `"unchecked"` the claim is not read and every caller
   reaches every source, as before. Without `identity` there is no caller to hold, and every
   request reaches every source, as before. Wherever an identity is configured, or some source
   is fixed to a scope identifier, the start writes which of the three holds, and `/posture`
   reports `caller-scope-identifiers` `enforced` (checked) or `not-enforced` (unchecked, or no
   identity): with an identity and no scoped source, a token whose claim names a scope
   identifier the entry does not grant is refused `401` all the same (an issuer shared with the
   Runner), and the operator is told.
8. **What is recorded.** The receipt's `caller` is as before, and the claim is not recorded: the
   receipt's `scope` is the identifier the request was held to. A scoped caller's subject and
   issuer are written into its scope's receipts alone; no record another scope's caller or an
   unscoped caller reads through a route (a registry line, a seal, `/verify`'s findings,
   `/posture`) carries either.

## Consequences

- Good, because a caller reaches a scope identifier only where its issuer and the operator both
  allow it, on both storage kinds, and the Runner reads the same token the same way.
- Good, because a `/seal` of another scope's session no longer returns its scope digest
  (ADR-0036's consequence), and the `/act` of a caller that does not reach the sources of no
  scope identifier no longer tells a session of a scope from one of none.
- Bad, because an installation with `identity` and scoped sources holds every caller to the
  sources of no scope identifier after the upgrade until the operator writes the entries or
  `"unchecked"`. One with `identity` and no scoped source refuses `401` a caller whose tokens
  gain `scope_ids` for the Runner from a shared issuer. The release notes and the operator
  page's upgrade note say both.
- Bad, because a subject that works in a scope identifier and in the sources of no scope
  identifier needs a claim holding both and an entry granting both.
- Bad, because the session namespace is one across scopes (ADR-0033): a caller that reaches the
  sources of no scope identifier still learns from a refusal that a session name is taken by
  some scope, not which. Closing it needs a namespace per scope.
- Bad, because `/registry` stays open (decision 6) while a seal of version 2 names its scope by
  an unkeyed digest over the identifier and the session's id (ADR-0036): anyone who reads it and
  guesses a scope identifier can test the guess against each sealed session and learn which are
  of that scope, with their counts and seal times. Considered and not taken here: serving
  `/registry` under `identity` only to a caller that reaches every source. That would move the
  anchor a verifier fetches without a token behind one, so a third-party verifier would verify
  exports instead, and it changes the open routes the listener's rule (engine version 19) and
  several pages describe; the seal's form, merged in #477 and in no release yet, is unchanged
  either way. SPEC.md §6 and the operator page state the disclosure and advise scope
  identifiers of at least 128 bits of entropy where it matters.
- Revisit when a delegation carries scope identifiers (decision 5), when the registry is kept
  per scope, or before the seal of version 2 is first released, if a keyed digest is wanted.

## More information

- Issue #479; the Runner's issue #304 and its ADR 0002; ADR-0026, ADR-0033, ADR-0036.
- SPEC.md §6 ("Caller scope identifiers"); `docs/design/engine-config.md` ("Caller scope
  identifiers (engine version 27)"); `go/caller_scopes.go`.
