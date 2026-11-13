---
status: proposed
date: 2026-11-12
deciders: maintainer
---

# A scope identifier fixed on a platform, repeated by each request and carried on its receipts

## Context and problem statement

A version 3 receipt names the authority, the source and the caller. An operator whose sources
serve more than one party has nothing on a receipt that says which party an acquisition was for,
and nothing that stops a request meant for one party's source being served by another's except
the source name the request gives (issue #420). The ask is an optional, opaque scope identifier,
fixed in the configuration, that a request states, that refuses a request stating another, and
that the receipt carries under its signature, with every configuration and receipt that has none
unchanged. A member under the signature is a specification change, and a refusal on `/acquire`
is part of the gateway's request boundary, so this is a decision and not only a member.

## Decision drivers

- A source fixed to no scope identifier behaves as before and mints the bytes it minted before;
  every frozen vector is unchanged.
- The identifier on a receipt is the operator's, not the caller's: the caller cannot choose it,
  only repeat it.
- A request for another scope is refused before anything of the source is reached: before the
  source runs, before the session is admitted and before a delegation counts the call.
- A refusal teaches a caller nothing about any scope identifier, the source's or another's.
- The identifier is shown to people, so it is held to the code points the project already
  refuses in what it shows them, and compared as written.
- A verifier written before the member keeps its verdicts, and what it does with the member is
  stated.
- No new receipt version, no new key, store, registry or listing.

## Considered options

- The request names a scope, and the receipt carries what it names.
- The configuration fixes the scope, and the receipt carries it whatever the request names.
- The configuration fixes the scope, a request repeats it, and one that does not is refused.
- A key, a store and a registry for each scope.

## Decision outcome

Chosen option: the configuration fixes the scope and a request repeats it, because the receipt
then carries an identifier that is the operator's and the request's alike. A scope the request
alone names would put on a signed receipt whatever a caller chose; one the configuration alone
fixes would serve a request for one party from another party's source on the source name alone,
which is the gap the issue names. Separate keys, stores and registries for each scope are a
different decision, of a second storage kind, and are not taken here.

1. Engine configuration version 20 adds `scope`, an optional member of a platform entry. Under
   version 19 or earlier the member is refused by name; a gateway older than this one refuses a
   version-20 file by its version. `gateway serve` from the command line has no flag for it.
2. A scope identifier is a JSON string of 1 to 128 bytes of UTF-8 holding no code point display
   policy 1 refuses (`docs/design/tool-descriptors.md`, Unicode 15.0.0) and neither tab nor line
   feed, which policy 1 admits in text of several lines. A configuration value out of that form,
   or not a string, is refused naming the platform and the form, and quoting nothing of the
   value. One function (`go/scope.go`, `isScopeIdentifier`) holds the form for the
   configuration, the service and the verifier.
3. The identifier is opaque. The gateway compares a request's with the configuration's byte for
   byte, and never case-folds, trims or normalizes either: `é` composed and `e` followed by a
   combining acute are two identifiers.
4. Every source the engine derives from the platform, its history and its live source, is fixed
   to the platform's identifier. A platform with a `scope` that sets `write: true` is refused,
   since `/act` takes no scope, and so is a `scope` in a configuration with `mcp`, since the MCP
   server forwards a call with no scope member and could serve none of the platform's sources.
5. `/acquire` reads a `scope` member, a string, only in a gateway whose configuration fixes some
   source to a scope identifier; a gateway fixing none refuses the member as any member it does
   not read, as it did before. A request to a scoped source that names no scope or another, and
   a request to an unscoped source that names one, are refused `400` with one sentence,
   `scope: the request's scope does not match the source's`, which names neither identifier. The
   check comes right after the source is known: before the trail's witness is looked up, and
   before the publisher policy, the grant, the session's admission, a delegation's count and the
   source. A `scope` that is not a string is refused `400` quoting nothing of it. Neither refusal
   writes a diagnostic line.
6. The receipt of a scoped source is a version 3 receipt with a top-level `scope` string,
   signed with every other member (`SPEC.md` §1.2a). A receipt of an unscoped source carries no
   such member and is the receipt it was before. The format admits the member on either kind;
   this gateway mints it on acquisitions alone. A seal and a registry line carry none.
7. A verifier of this version holds a `scope` present on a version 3 receipt to its form and
   reports one out of form `malformed` (§1.4, order 1). A verifier written before the member
   tolerates it as an unknown signed member, reaches the verdict it reached before, and holds it
   to no form: it answers `ok` for a receipt signed under the key it trusts whose `scope` this
   version reports `malformed`. A scope added, removed or changed after signing is
   `signature-mismatch` under both.
8. `connect --replace` keeps the scope of the entry it replaces, as it keeps a decision policy and
   `writeRequesters`, and refuses a replacement that sets `--write` before anything is asked;
   `connect` has no flag for the member.
9. Where the configuration cannot put a scope, the code refuses rather than mints a receipt that
   does not name it: a read-back (which names no scope) of a scoped live source, an action on a
   scoped write source, a scoped source under version 2 receipts, and a source handed to the
   service with an identifier out of form.

No listing gains a filter: the gateway has no listing of receipts by member. `gateway export` is
one consistent cut that a manifest and the seals hold whole, `/registry` serves the log as
written and `gateway verify` reads a whole store; a cut by scope would hold seals counting
receipts it left out.

### Consequences

- Good, because a reader of a receipt that verifies under the operator's key learns which scope
  identifier its operator fixed the source to, and that the request named it, from the receipt
  alone.
- Good, because a request for one party's source made with another party's identifier, or with
  none, is refused before the source is reached, and the refusal discloses no identifier.
- Good, because every configuration and receipt without the member is unchanged, and the corpus
  vectors of earlier versions are byte for byte what they were.
- Bad, because the identifier is a label and not a credential: any caller the gateway admits
  that names a source's identifier is served by it. Holding a caller's token to a scope is not
  done here.
- Bad, because nothing binds a session to one scope identifier: a session may hold receipts of
  several, and of scoped and unscoped sources alike, and its seal names none.
- Bad, because a verifier written before the member answers `ok` for a receipt whose `scope` is
  out of form, and reports no scope at all; a reader who relies on the member needs a verifier
  of this version.
- Bad, because a gateway whose configuration fixes some source to a scope answers an
  unscoped source's request that names one with the scope refusal, and a gateway fixing none
  answers it as an unknown member, so the answer tells a caller whether the gateway fixes any
  scope, though never which.
- Bad, because a scoped platform allows no write and no MCP server, until `/act` and the MCP
  server carry a scope.
- Revisit when a caller's token is to be held to a scope, when a session or a seal is to name
  one, when `/act` or the MCP server needs to reach a scoped platform, or when a second storage
  kind keeps each scope apart.

## More information

`SPEC.md` §1.2a (`scope`), §1.4 order 1, §5 and §6 (`/acquire`);
[engine-config.md](../design/engine-config.md) ("A platform's scope (engine version 20)");
`go/scope.go`, `go/engine.go` (`parsePlatformScope`, `deriveSources`), `go/serve.go`
(`requestScope`, `scopeHolds`, `acquireWithScope`), `go/receipt_builder.go`, `go/act.go`,
`go/connect.go`, `go/verify_v3.go`, `verify-ts/src/structure.ts`; the corpus vectors
`v3-scope-*`; issue #420.
