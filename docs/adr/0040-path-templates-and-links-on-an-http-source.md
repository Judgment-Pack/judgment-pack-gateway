---
status: proposed
date: 2026-11-18
deciders: maintainer
---

# An http source's paths may be templates a GUID fills, and a caller follows a next or delta link the endpoint handed out, both held to the endpoint and the paths before a connection

## Context and problem statement

An `http` source ([ADR-0024](0024-an-http-source-in-the-engine.md)) admits a request whose path
is exactly one of its binding's `paths`, with a query object. A directory API names one
object's member collection by its id (`/groups/<id>/members`), so a fixed list cannot name
it, and it pages by absolute URLs (`@odata.nextLink`, `@odata.deltaLink`) whose opaque
`$skiptoken` or `$deltatoken` a caller cannot re-derive into a query object faithfully: the
token is already percent-encoded, and re-encoding it is another request. Without a decision a
read-only directory source cannot be bound at all, and a caller paging one would have to
re-encode tokens the endpoint handed out. The two must not open a way to another host, another
resource, or bytes sent other than the binding and the receipt state.

## Decision drivers

- A request reaches only the binding's endpoint and a path its binding admits, and is refused
  before a connection (and, with a token step, before a token) otherwise.
- What is sent is what was written, byte for byte, and the statement commits to what was sent.
- A refusal of a link names nothing of it: it carries the endpoint's paging token.
- Both modules hold the rules alike (the core never imports the adapters), against one table.
- A reading of a configuration its author did not review is never applied silently.

## Considered options

- A. `{id}` templates matched by a GUID alone, and a `link` request form held to the endpoint's
  scheme, host and port and to the paths, sent as written.
- B. General templates (`{name}` of any segment characters) and links resolved against the
  endpoint as a browser resolves them.
- C. No templates; the caller splits each link into `path` and `query` itself.

## Decision outcome

Chosen option: "A", because a GUID is the one id form the target API's member paths take, so
no wider class is needed, and a GUID's characters (hex digits and four hyphens) cannot form a
dot segment, a slash, a percent escape or a brace; and because a link sent as written commits
the receipt to exactly the request the endpoint asked to be sent next, where option C re-encodes
tokens and option B resolves dot segments and percent escapes into requests the binding never
named.

1. **Templates.** A binding path may carry `{id}` at most once, as a whole segment; any other
   brace, two placeholders, or `{id}` within a segment is refused when the binding is loaded. The
   template is held to every rule of a path with a GUID in its place. A request's path matches
   it when every other segment is equal and that one is a GUID: 36 characters, hex digits of
   either case at every place but 8, 13, 18 and 23, which are hyphens. A `checkPath` is fixed.
2. **Engine version 31.** A template is a change to what a pinned binding admits, so a
   binding with one is refused under a configuration of version 30 or earlier, by name, at the
   start and at `connect`, which names the version and does not raise it.
3. **Links.** A request is `{"link", "method"?, "body"?}` or `{"path", "method"?, "query"?,
   "body"?}`, exactly one of `link` and `path`, no `query` beside a link. A link is at most
   16 KiB of visible ASCII; its scheme and host equal the endpoint's without regard to case, its
   port the endpoint's with the scheme's default standing for an absent one; it carries no user
   and no fragment; its path, as written, has no percent sign, backslash, dot segment or empty
   segment and is the endpoint's path followed by a path the binding admits; its query holds
   only RFC 3986 query characters, a `%` only before two hex digits. The request goes to the
   binding's endpoint with that path and query byte for byte. Each refusal is one fixed
   sentence; a transport error's diagnostic names no URL. A link reaches nothing a path and a
   query could not, so it is no configuration member and no version gates it.
4. **The statement** of a link request is `{"method", "path", "rawQuery"?, "body"?}`, the path
   under the endpoint and the query as sent; a path request's is as before, a template's path
   with its GUID. The acquisition's `endpoint` is the URL sent to, without its query.
5. **The engine's precheck.** For a source with a token step the engine holds a request to the
   same rules before it obtains a token, as it holds a path the binding does not name
   ([ADR-0027](0027-an-http-source-obtains-its-token-by-a-client-assertion.md)).
6. **`$` in a query object** is sent as written rather than `%24`: an OData endpoint reads its
   system options by that name, and `$` is a query character.
7. **The table.** `testdata/http-requests/cases.json`, written by hand, holds accepted and
   refused requests and templates, a rule on each side; the adapter's tests and the engine's both
   read it.
8. **A catalog binding**, `microsoft-graph`: `GET` alone, 24 v1.0 paths of which four are
   templates, the bearer from a token step ([catalog/README.md](../../catalog/README.md#microsoft-graph)).

### Consequences

- Good, because a directory's member collections and its paging are reachable through a pinned
  binding with no new shape, and each page is a receipt committing to exactly what was sent.
- Good, because a template admits no character a path could not already carry, so no rule of
  ADR-0024's path form is relaxed.
- Bad, because the same page asked by `path` and `query`, and by its link, are two statement
  forms (`query` and `rawQuery`); a reader comparing statements across them must read both.
- Bad, because a query object naming `$` reaches the endpoint as `$`, not `%24`, after this
  release; an endpoint that told the two apart would see another request. The statement, which
  records the object, is unchanged.
- Bad, because the binding's certificate form rests on an assertion the adapter signs RS256
  (or ES256), where the identity platform's page asks for PS256; it is untested against the
  service, and the federated form is the one tested, against a stand-in.
- Revisit when an API needs an id form other than a GUID, a second placeholder, or a link to
  another host than the endpoint (a regional host), each of which would be a new rule and a new
  version.

## More information

- [engine-config.md](../design/engine-config.md), "Path templates and links on an http source
  (engine version 31)"; [adapters/README.md](../../adapters/README.md#adapter-http); SPEC.md §6,
  "Adapter sources", "In the engine".
- `adapters/httpsource/target.go`, `go/http_request_target.go`, `go/token_step.go`
  (`tokenStepAdmits`), `testdata/http-requests/cases.json`.
