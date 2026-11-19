---
status: proposed
date: 2026-11-18
deciders: maintainer
---

# What one scope learns of another through a shared gateway

## Recommendation

A caller of scope identifier B is given the same answer whether or not the state of another
scope identifier A exists, on three surfaces that gave it something of A:

- **The MCP listing.** In the caller form (ADR-0038), each scope identifier's platforms, and the
  platforms of none, are bounded on their own. Each caller's listing is made, within the same
  8 MiB, from the platforms it reaches.
- **`/seal` through a front fixed to one scope identifier.** `/seal` takes an optional `scope`,
  read where `/acquire` reads it, and the fixed front always sends its own.
- **`/posture`.** A report served to a caller that does not reach every source is judged over
  the sources it reaches alone.

A fourth surface, the session namespace, stays shared. Per-scope session names need the store
layout, the seal and the verifier to tell two sessions of one id apart, which is the lane of the
seal-format and per-scope verification work (#478). Until then, the disclosure it leaves is
recorded here.

## Context and problem statement

ADR-0036 makes a session belong to one scope identifier. ADR-0037 holds each caller to the scope
identifiers its token and the configuration allow. ADR-0038 puts the MCP front in front of
scoped platforms. The reviews of those changes found places where a caller of B could still
learn something of A without reading any of A's receipts (#483, #494):

- In the caller form, the listing's 8 MiB bound, and which snapshots it dropped, were computed
  over every scope's platforms. A caller of B could see its tools listed without descriptions
  because A's platforms had filled the bound.
- A front fixed to B forwarded `engine.seal` for any session the caller's token reached, A's
  among them.
- `/posture` gave its counts over the caller's sources, but judged each line's state
  (`enforced`, `partial`) over every source. Its source-user line also named sources of every
  scope, and the delegation-grants and write-requesters lines counted platforms and tools of
  every scope. So a caller learned one bit or more about other scopes per line.
- A session name used by A is refused to B (`refusalOtherScope`), where an unused name is
  accepted. So B learns that the name is in use.

## Decision drivers

- What a caller of B is answered is a function of B's state alone, plus the state of the
  sources of no scope identifier where B reaches them.
- No refusal is weakened. The signer still re-checks every forward against the caller's own
  token, and nothing is served that a direct request would not be.
- The installation's caller, `"unchecked"` and a gateway without `identity` are answered as
  before, since they reach every source.
- The seal's signed form and the registry line are left as they are. Another change owns them
  (#478).

## Considered options

The listing bound (#483, part 1):

- (a) Hold each scope's described entries, and bound each caller's listing per caller.
- (b) Bound per scope at start, each scope taking its own share of the 8 MiB.
- (c) Document the disclosure.

The seal through a fixed front (#483, part 2):

- (a) `/seal` takes an optional `scope`; the signer answers a session of another scope
  `no such session`.
- (b) The front tracks the sessions it opened.

`/posture` (#494):

- Judge each line over the sources the caller reaches.
- Keep the state global and document the disclosure.

The session namespace:

- Make the namespace per scope.
- Make the smallest change that removes the disclosure.
- Record it and leave it open.

## Decisions

1. **The listing: option (a), bounded per scope at start and per caller at each request.** At
   start, the server groups the platforms: each scope identifier's on its own, and the platforms
   of none on theirs. In each group it applies the existing drop rule to the group's own listing,
   the seal tool and the group's tools. It drops the group's snapshots whole, in reverse table
   order, until that listing fits 8 MiB, and keeps each kept platform's described entries and by
   how much they grow an answer. Every snapshot is still read and verified, kept or not.

   At `tools/list`, a caller's listing is made from the tools it reaches, in table order. It
   starts from each tool described as if nothing were captured. Each platform its group kept is
   then described while the answer stays within 8 MiB, and none from the first that would pass
   it. The start still refuses a table whose listing without any snapshot passes 8 MiB, and
   names the snapshots each group dropped.

   - **Why not (b).** Equal shares make B's share a function of how many scopes exist. That leaks
     A's existence and shrinks every scope's listing as scopes are added. A share as large as the
     whole bound is (a)'s start step. Without (a)'s per-caller step, a caller reaching two scopes
     could be sent more than 8 MiB.
   - **Why not (c).** It leaves the disclosure.
   - **What a caller is listed.** A caller of one scope identifier is listed what a server fixed
     to it lists. Of a group's every tool, the listing is the group's own, since a group keeps
     the longest run from its start that fits.
   - **Other forms.** The fixed form and a server with no scoped platform have one group, so
     their listing is the one they had.

2. **The seal: option (a).** `/seal` reads a `scope` member, a string, where some source is fixed
   to a scope identifier, as `/acquire` reads it. Elsewhere, it is refused as a member `/seal`
   does not read, and a `scope` that is not a string is refused `400`. The caller's reach is
   narrowed to the scope named (`scopeReach.narrowedTo`): the scope if the caller reaches it, and
   nothing otherwise. So a session of another scope identifier, or of none, gets the answer
   `sealFor` already gives an unreached session: `no such session: <id>`, byte for byte the
   answer for a session the gateway does not hold.

   A front fixed to a scope identifier names it on every seal it forwards. The caller form names
   none, since its seal tool takes a session and no platform. Option (b) is not taken, because a
   front restart would leave sessions it opened unsealable through it.

3. **`/posture`: judged over the sources the caller reaches.** Served to a caller that does not
   reach every source, `hostPosture` takes the configured sources cut to that reach, once, and
   judges every line over them. That covers each line's state, its counts, and the sources or
   platforms it names: `source-user-switch`, `operator-program-confinement`,
   `delegation-grants`, `write-requesters`, `caller-scope-identifiers` and
   `read-only-credentials`. `programs` and `readOnlySources` list only those sources.

   Two lines get wording for a cut report:
   - Where the caller reaches no source, `source-user-switch` says the caller's token reaches
     none, rather than that the configuration names none.
   - Where it reaches no source fixed to a scope identifier, `caller-scope-identifiers` says so
     of the sources it reaches.

   The lines that are not of the sources (the seed, custody, the listener, the descendants'
   probe, the delegation's narrowing and sender constraint) are the same for every caller.

4. **The session namespace: left shared, and recorded.** A session id names a directory under
   the file store (`receipts/<sessionId>`, SPEC §3a). The verifier and export discover sessions
   by enumerating that directory. On the PostgreSQL kind, `series` is keyed by name alone
   (ADR-0035, `docs/postgresql-store.md`). The registry and the verifier match a seal to its
   session by `sessionId`.

   A per-scope namespace would make one id name two sessions. That needs a store layout keyed by
   scope, a migration of existing stores, and a seal and registry line that tell the two apart.
   It touches the seal's signed form and per-scope verification, which this change does not own.

   No smaller change removes the disclosure. B's first acquisition into a name A uses must be
   either accepted, which needs the per-scope namespace, or refused, which tells B the name is
   in use.

   What B learns is only that some other scope, or none, holds a session of a name it guessed.
   It does not learn which scope, nor the session's receipts, count or state: `/seal` answers
   `no such session`, and `/posture` and the listing say nothing of it. Where that must stay
   hidden, session ids are chosen unguessable, with at least 128 bits of randomness, as SPEC
   asks of scope identifiers that must not be guessed. The MCP front's own session names
   (`randomSessionName`) already carry 128.

## Consequences

- Good, because a caller of B gets the same listing bytes, `/seal` answers and `/posture` report
  whether or not A's platforms, sessions or sources exist (`go/scope_disclosure_test.go`).
- Good, because a front fixed to one scope identifier now does what an operator expects of it,
  sealing only that scope's sessions, with no state of its own to lose on a restart.
- Good, because the installation's caller and the unscoped forms are answered as before.
- Bad, because a server in the caller form holds up to 8 MiB of described entries per group,
  not 8 MiB in all, so its memory grows with the number of scope identifiers that pin snapshots.
- Bad, because a caller reaching several scopes can be listed fewer descriptions than each scope
  alone is. The start names only what each group dropped, not what a caller of several is not
  served.
- Bad, because one `/posture` no longer shows a scoped caller the state of the whole gateway.
  The installation's caller, or `gateway posture` on the host, reads that.
- Bad, because a session name in use by another scope is still told apart from an unused one.
- Revisit when per-scope seals and verification (#478) land: the session namespace can then be
  made per scope, with the store layout and its upgrade.

## More information

- Issues: #483 (listing bound, seal through a fixed front), #494 (`/posture`).
- SPEC.md §6, "Caller scope identifiers" (`/seal`, `/posture`) and "The MCP server on scoped
  platforms"; §11.9.
- `docs/design/mcp-server.md` ("Scope identifiers"); `docs/design/tool-descriptors.md` ("The
  listing"); `docs/design/engine-config.md` ("What the engine reports: `/posture`").
- Code: `go/descriptor_start.go` (`buildListing`, `heldListing.assemble`), `go/mcp_scope.go`
  (`toolList`), `go/mcp.go` (the seal forward), `go/caller_scopes.go` (`narrowedTo`,
  `callerScopesLine`), `go/serve.go` (`/seal`), `go/posture.go` (`reachedSources`).
- ADR-0036, ADR-0037, ADR-0038.
