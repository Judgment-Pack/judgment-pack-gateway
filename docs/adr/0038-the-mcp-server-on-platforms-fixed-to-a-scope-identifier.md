---
status: proposed
date: 2026-11-16
deciders: maintainer
---

# The MCP server on platforms fixed to a scope identifier

## Recommendation

Engine configuration version 28 gives `mcp` two forms that serve platforms fixed to a scope
identifier. `mcp.scope` fixes the server to one scope identifier: it serves that identifier's
platforms and no other, and every forward names it. `mcp.scopeFrom: "caller"` serves the
platforms of every scope identifier over HTTP: each call names its tool's platform's identifier.
In both, a caller is listed, and may call, only the tools of the sources its token
reaches. The rule is ADR-0037's, computed by the signer's own function. A scope identifier never
comes from the client, and the server forwards nothing the caller could not send to `/acquire`
itself.

## Context and problem statement

ADR-0026 (decision 4) refused a platform's `scope` in a configuration with `mcp`, because the MCP
server forwarded every call with no `scope` member and so could serve none of the platform's
sources (issue #480). ADR-0037 then held each caller to the scope identifiers its token and the
configuration allow. An installation with scoped platforms therefore had no MCP front. A tool
argument naming the scope would let the client choose it, which is the thing ADR-0037 removed.

## Decision drivers

- The scope identifier a forward names is the configuration's, never the client's.
- The front adds no trust: the signer holds every forward as it holds a direct request.
- A caller learns nothing of a scope identifier its token does not reach, through the listing
  or a refusal.
- One rule for what a token reaches, at the front and at the signer.

## Considered options

- A tool argument, or a `_meta` member, naming the scope identifier. Not taken: the client would
  choose it.
- One fixed front per scope identifier only. Taken as the first form, but an operator of several
  scope identifiers would run one process each.
- The fixed form listing every tool to every caller, leaving the refusal to the signer. Not
  taken: a caller of another scope would read the platform's tool names and the listing's
  captured snapshots.

## Decisions

1. **The members.** `mcp.scope`, a scope identifier of §1.2a's form, or `mcp.scopeFrom`, the
   string `"caller"`. One or neither may be given. Each is a version-28 member, and an earlier
   version refuses it by name. A refusal names the member and the form, and quotes nothing of
   the value.
2. **The fixed form** (`mcp.scope`). The tool table holds the live tools of the platforms fixed
   to that identifier and no other, and every acquisition it forwards names it. Where no
   platform is fixed to it, the server refuses to start. The configuration refuses the marker
   `"unscoped"`, to which no platform of version 27 or later is fixed.
3. **The caller form** (`mcp.scopeFrom: "caller"`). The table holds the live tools of every
   platform. Each acquisition names its tool's platform's scope identifier, or none for a
   platform of none. The form needs `identity` with `callerScopes` checked. Without `identity`,
   or with `"unchecked"`, every caller reaches every source, and the configuration is refused.
   It is served over `--http` alone: over `--stdio` one token is given at start for the life of
   the process, and the start is refused.
4. **What a caller is served.** In both forms, `tools/list` lists, and `tools/call` admits, the
   platform tools whose platform's identifier the caller's token reaches (`reachOf`,
   `go/caller_scopes.go`). Any other tool is answered `unknown tool`, byte for byte as a name
   the table does not hold, and nothing is forwarded. The seal tool is listed to every caller,
   since the signer holds `/seal` to the caller itself (ADR-0037, decision 6). Over HTTP the
   reach is read from each request's token. Over stdio it is read once at start from
   `ENGINE_TOKEN`. With no `identity` (stdio only), every source is reached, as at the signer.
5. **The transport refuses what the signer refuses.** The front's token check applies the
   signer's rule. A token whose `scope_ids` is out of form, or wider than its subject's entry,
   is refused `401` at the HTTP transport, with the signer's sentence and the resource-metadata
   challenge. Over stdio, the same token stops the start.
6. **Nothing of the client names a scope.** No tool's input schema gains a member. A call's
   arguments are carried to the signer byte for byte. `_meta` is read for the session name
   alone. A scope identifier named in either has no effect on the forward.
7. **The forward is a request the caller could send.** It carries the caller's token, so the
   signer holds it to the source's scope identifier and to the caller's reach (ADR-0037,
   decision 6), and holds its session to one scope identifier (ADR-0036).
8. **No write tool** (unchanged). A binding's write operation gets no MCP tool in either form.
9. **The receipt is unchanged in form.** Its `scope` is the identifier the forward named and
   the signer held. A receipt of a platform of none carries no `scope`.
10. **The configuration.** A platform's `scope` beside an `mcp` of neither form is still
    refused, now naming the two members. This supersedes ADR-0026's decision 4 in part: the
    refusal beside `mcp` is narrowed to an `mcp` of neither form. ADR-0026 is otherwise
    unchanged.

## Consequences

- Good, because an installation with scoped platforms can serve them over MCP, and a forward
  names only an identifier the configuration chose.
- Good, because a caller of another scope sees neither form's tools, and its call is refused the
  same way as a call to a tool that does not exist.
- Bad, because over HTTP the token is checked up to three times per message: once at the
  front's transport, once for the reach, and once at the signer.
- Bad, because a transport session is not bound to a token (as before). Each request is held to
  its own token's reach, and the signer holds the receipt session to one scope identifier.
- Bad, because in the caller form a caller of two scope identifiers shares one default receipt
  session: the signer refuses its first call of the second identifier into it (ADR-0036). Such
  a caller names a session per scope identifier in `_meta`.
- Bad, because over stdio the reach read at start holds for the life of the process. The signer
  still checks the token on every forward, so an expired token is refused there.
- Revisit when receipt sessions get a namespace per scope identifier, or a delegation carries
  scope identifiers (ADR-0037, decision 5).

## More information

- Issue #480; ADR-0026, ADR-0036, ADR-0037.
- SPEC.md §6 ("The MCP server on scoped platforms"); `docs/design/mcp-server.md` ("Scope
  identifiers"); `docs/design/engine-config.md` ("The MCP server on scoped platforms (engine
  version 28)"); `go/mcp_scope.go`.
