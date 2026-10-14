---
status: accepted, 2026-10-13
date: 2026-10-13
deciders: maintainer
---

# A remote MCP server is reached by `adapter-mcp` itself, over Streamable HTTP at a URL the operator fixes, as a source and as the executor; the acquisition names it by its URL, the TLS identity it answered under and the name it gave itself, in two optional members of version 3

Issue #245. `adapter-mcp` reaches an MCP server over stdio only, and the servers that matter
next are remote: Databricks' managed MCP servers and Azure DevOps' remote server speak
Streamable HTTP with a bearer credential, and the deferred vendor connections asked for "the
shared remote MCP transport … implemented once and reused across providers". This record states
the design the pull request for #245 builds; the maintainer accepts or amends it, and it is
accepted at release.

**Checked against** gateway `main` at `dc9f6ee` (v0.12.0 and the thank-you bot change after it).

## Context and problem statement

**What exists.** `adapter-mcp` runs a pinned image or a local command and speaks JSON-RPC over
its stdio (`adapters/mcp`); the envelope names the server by the image, or by the command with the
version it gave itself and the digest of its executable, and records no transport identity. The
executor is the same adapter, spawned by the engine with `--tools=<one tool>` and
`--error-results` from a platform's `write` binding (`docs/design/executor.md`), and the action
receipt's `action.tool.endpoint` is the platform's `endpoint`. The gateway already holds a bounded
Streamable HTTP client, `adapters/mcphttp`, used by the Notion connection alone: `https` only, a
fixed tool list, session ids echoed, JSON and event streams read to a bound, no redirect followed,
an answer that repeats the token refused (`docs/design/connected-note-sources.md`). `adapter-http`
holds an operator's endpoint, a bearer from a credentials file, fixed headers and a CA file, and
records the TLS peer by the digest of its leaf certificate.

**What is missing.** Nothing lets a platform's `live` or `write` operation name a remote MCP
server: an operator wanting one today would run a local bridge as a "command" and the receipt
would name the bridge, not the server.

## Decision drivers

- The client is written once, in `mcphttp`, and reused; no provider's code enters the adapter.
- The stdio form's records do not move by a byte; a released verifier still verifies every
  store, and a verifier written now holds the new members to a form.
- The credential is never on a command line, in an error, in a log, in an envelope or in a report;
  the session id is recorded nowhere.
- A write through a remote server is held by the decision policy exactly as one through an image.

## Considered options

- **A. A third form of `adapter-mcp`**, `--url`, beside `--image` and a command, sharing the
  handshake, the tool rules, the result's reading, the check and the descriptors capture; the
  executor is unchanged but for what its endpoint names.
- **B. A client per provider, as Notion has**: each provider's URL, tools and quirks in a profile
  of its own. It suits a person's connection with an OAuth flow and a fixed tool list, and repeats
  the transport per provider, the thing the vendor issues asked not to do; and it serves no
  executor.
- **C. A separate adapter for remote servers.** A second program holding a credential, a second
  envelope writer, and a second set of tool, check and descriptor rules to keep in step with the
  first; the executor would need a second derivation.

## Decision outcome

Chosen option: A, because the tool rules, the result's reading and the executor are the stdio
form's already, and the transport is the only thing that differs.

### 1. The form

`adapter-mcp --url https://host[:port]/path` names the server, exclusive with `--image` and with a
command after `--`: given together, or with server arguments, refused before anything is read.
The URL is held as `adapter-http` holds its endpoint, a little narrower: `https`, or `http` at a
loopback address written as one (127.0.0.0/8 in dotted decimal, or `[::1]`; a name such as
`localhost` is not one, since what it resolves to is not in the text, which is the witness
origin's rule in ADR-0014); no user, no query, no fragment; at most 2048 bytes of printable ASCII,
the scheme in lower case. It is used exactly as written, nothing appended. No redirect is
followed: a `3xx` is a refusal naming the status, never the location. `--ca-file` is
`adapter-http`'s. `--endpoint` is refused beside `--url`, which is the endpoint.

*Amended 2026-10-14 (#251).* The URL has one form, stated once in `SPEC.md` §1.2a and
referred to from §6: at most 2048 characters of printable ASCII; `https://` or `http://`;
a host, then optionally `:` and a port, then nothing or `/` and a path; a host that is a
name of letters, digits, `-`, `.` and `_`, or hexadecimal digits, `:` and `.` in brackets;
a port from 1 to 65535 with no leading zero; no `?` and no `#` anywhere; no `@` in the
authority, which no host's characters include, so no user, while an `@` in the path is one
of its characters, as it was; every `%` in the path followed by two hexadecimal digits; and
after `http://` a loopback address written as one. The adapter's rule, which ended with
`net/url`, was tightened to it: a named host of a fixed alphabet where `net/url` also took
sub-delimiters and percent escapes, and no `:` without a port after it. The signer's rule, which
`gateway verify` and the engine share, and `verify-ts`'s were raised to it: they had held
the authority only to being non-empty and free of `@`, so an envelope naming
`https://mcp.example/%zz` or `https://:443/` was signed and verified. A table of accepted
and refused endpoints (`testdata/remote-endpoints/cases.json`) is read by a test of each of
the four, and eight vectors `v3-mcp-remote-endpoint-*` hold both verifiers to the form. After
the review round on #266, an address in brackets is an IPv6 address in the form RFC 3986
names `IPv6address` — eight groups of one to four hexadecimal digits separated by `:`, `::`
standing once for one or more groups of zeros, the last two groups optionally an IPv4 address
in dotted decimal — with no zone, rather than any run of hexadecimal digits, `:` and `.`,
which admitted `[abc]` and `[127.0.0.1]` that the transport's URL parser then refused; a
ninth vector, `v3-mcp-remote-endpoint-ipv6-literal-malformed`, holds both verifiers to it. In
the same round, a refusal of a binding's URL, as written, as a template or as the platform's
parameters resolve it, came to name the binding, the operation and the rule, and never the
URL, which may carry by mistake what is never to be shown.

### 2. The credential and the headers

`--bearer NAME` names the member of the `--credentials` JSON object sent as
`Authorization: Bearer`; nothing else of the file is sent, and every value in it is redacted from
every diagnostic (`internal/redact`, as the stdio form's are). `--credentials` without `--bearer`
is refused — a credentials file with no use is a mistake — and `--url` without either is a server
that takes no credential. An answer that repeats the credential, as written or escaped, is refused
before anything of it is read. `--header NAME=VALUE`, repeatable, is sent on every request as
written; a credential's headers, the protocol's (`Mcp-Session-Id`, `Mcp-Protocol-Version`,
`Last-Event-ID`) and the ones the client and the transport write (`Content-Type`, `Accept`, `Host`
among them) are refused. A read-only header a server honours is the operator's to send and the
server's promise; nothing in the record claims it.

### 3. The session

`mcphttp` gains a client opened for this form (`Open`): an optional token, fixed headers, a bound
per answer, an optional tool list, `http` at a loopback address, and errors that name what
happened — the status a server answered, its JSON-RPC error — while keeping the kinds the Notion
connection maps, so its behaviour is unchanged. One session per invocation: `initialize`, held by
the adapter to the stdio form's rules; `notifications/initialized`; the tool list; the one
`tools/call` (or, for `--check`, the list and the probe); the session ended with a `DELETE`. The
session id is the client's, sent on every later request and recorded nowhere. Each answer is read
no further than a limit of its kind (#250), a JSON body before any of it is parsed and an event stream
as a whole, its events parsed as they arrive and the response ending the reading; an encoded answer is
refused unread: a tool call's, the output bound and
64 KiB; `initialize`'s, 1 MiB; a page of the tool list's, 8 MiB. The tool's result is then held to
the output bound as over stdio. `--tools`, `--check`, `--probe`, the descriptors capture,
`--error-results` and the result's reading are the stdio form's, unchanged.

### 4. The acquisition

The envelope's eight members are every shape's, and §6 refuses one more, so the remote form is
recorded in the eight where their meaning carries it and in two optional members where it does
not:

| Member | Over stdio | For a remote server |
|---|---|---|
| `adapter` | the image; or the command, the version the server gave itself, the executable's digest | `adapter-mcp`, its version, the digest of its own executable: the program that fetched, as `adapter-http` names itself, since no program of the server's is there to digest |
| `endpoint` | `--endpoint`, or `null` | the URL as configured |
| `peerIdentity` | `null` | `tls:sha256:` and the digest of the leaf certificate of the answer that carried the result; `null` over plaintext loopback |
| `transport` | absent | `"http"` |
| `server` | absent | `{name, version}` as the server's `initialize` answer gave them, redacted as a diagnostic is |
| `statement`, `schema`, `snapshot`, `upstreamToken`, `observedAt` | the call; the output schema's digest or `null`; `null`; `null`; when the answer was read | the same |

`transport` and `server` are absent over stdio rather than `"stdio"` and `null`, so that the stdio
form's records are the bytes they were — a golden test holds them — and a record made before the
members reads as what it was, a stdio acquisition. They are present together, on shape `mcp`
alone; with them, `endpoint` and `peerIdentity` take the forms `SPEC.md` §1.2a states, and a
`transport` of another value, either member without the other, the two on another shape, or an
`endpoint` or a `peerIdentity` out of form is `malformed` (§1.4 order 1). A member of `server`
beside its two is tolerated by a verifier, as every signed member it does not know is; the signer
refuses it in an envelope. The members are optional members of version 3, as `action.policy`,
`decision.recordBytes` and `witness` are: a verifier written before them tolerates them.

### 5. What a remote acquisition establishes, and what it does not

It establishes byte lineage from that endpoint under that TLS identity: that an endpoint at that
URL, presenting that certificate, answered that tool call with those arguments with the bytes the
receipt names, at that time, under the operator's credential, where one is configured (the
record itself does not say whether one was sent) — as the adapter's testimony under the gateway's
signature, which is what every adapter record is.

It does not establish that the bytes are true; that the tool read rather than wrote, which the
adapter cannot tell (`--tools` is the only thing that keeps a source to reads); that the server is
honest, or is the vendor's, or that the name and version it gave itself are its own; or anything
the session carried beyond the one call.

### 6. The executor

Nothing changes in `go/act.go`. A binding's `mcp` operation may name `server` as
`{"url", "bearer", "headers"?}` instead of `{"image", "args"?}`; the engine derives
`adapter-mcp --url=… --credentials=<the operation's file> --bearer=… [--header=…] --tools=…`
(`--error-results` for `write`), and for a write the source's endpoint — what
`action.tool.endpoint` carries — is the URL. The decision policy holds the write before the
executor starts, so a write it refuses reaches no server.

### 7. How it is held

An in-process Streamable HTTP server (`adapters/internal/fakemcp`) that issues a session and holds
later requests to it, answers a refusal, a result at the bound and past it, a redirect, a body
that is not JSON and one of another content type; the form's rules, case by case, each refused
before the server is sent anything; the credential absent from every refusal, envelope and report;
the stdio form's records byte for byte (`adapters/mcp/testdata/stdio-golden`); `--check` over
HTTP; the gateway's own end-to-end runs, an acquisition over TLS and a write through a remote
binding under a policy; and nine vectors in `corpus/v3/stores/` that both verifiers answer.

### Delivery

| # | Repository | What | Needs |
|---|---|---|---|
| 1 | gateway | #245: this record; the remote form of `adapter-mcp` and `mcphttp`'s `Open`; the two members in `SPEC.md` §1.2a and §6, the signer, `gateway verify` and verify-ts; remote bindings in the engine; the vectors; one cross-vendor round (credentials and transport) | — |
| 2 | gateway | #246: Databricks, its SQL, Genie and Unity Catalog reads over the API and the managed MCP servers | 1 |
| 3 | gateway | #247: Azure DevOps, work items, repositories and pipelines over the API and its remote MCP server | 1 |
| 4 | gateway | #248: write-back platforms for Azure DevOps and Databricks under decision policies | 1, 2, 3 *Amended 2026-10-13: built in the pull request for #248, with the `azure-devops` and `databricks` bindings and a platform's `parameters` at engine configuration version 8, the answer to question 1 above.* |

### Consequences

- Good, because one client serves every remote server, a source and the executor alike, and the
  record names what reached it as `adapter-http`'s does, with the stdio form unchanged.
- Bad, because a remote server's tools are only as read-only as the credential and `--tools`
  make them; the adapter adds nothing there, and a read-only header is the server's word.
- Bad, because a binding pins a URL and not a program: the server behind it can change while the
  binding's digest does not, and the record shows it only in `server` and `peerIdentity`.
- Bad, because the action receipt names a remote write by `action.tool.endpoint` alone; the TLS
  identity of the write's answer is in the executor's envelope and not in the receipt.
- Revisit when a provider needs OAuth or dynamic client registration, a server asks the client
  for sampling or elicitation, or a remote server signs its answers.

### How this sits with earlier records

ADR-0002's envelope keeps its eight members and its rule that the gateway, not the adapter,
decides what is signed; the two members are an adapter's testimony like the rest. ADR-0011's and
ADR-0012's policies hold a remote write unchanged. ADR-0014's `witness` is the precedent for an
optional signed member of version 3, and its origin rule the precedent for a loopback address
written as one.

## Questions for the maintainer

*Answered 2026-10-13 by the maintainer: both as proposed. The proposed answers below are the decisions.*

1. **Where a tenant's URL lives.** A binding pins the URL, so a server whose URL names the tenant
   (a Databricks workspace, an Azure DevOps organisation) takes a binding per tenant. **Proposed:**
   accept that for #245, and let #246 and #247 say whether a platform's configuration supplies the
   URL beside a binding that names the transport.

   *Amended 2026-10-13 (#248).* The platform's configuration supplies the variable parts: a
   binding's `server.url`, and its operation's tools, may be a template whose placeholders,
   `{name}`, the platform's `parameters` fill (engine configuration version 8;
   `docs/design/engine-config.md`, "Bindings"). The binding's digest pins the template and the
   transport. The template writes the scheme, and writes the host or names it `{workspace}` alone
   over `https`, a value held to a Databricks workspace's host forms, so no parameter can send the
   credential to another host. The engine refuses to start on a placeholder no parameter gives, a
   parameter no placeholder names, or a resolved URL out of the endpoint form. The adapter is given
   the resolved URL, and the acquisition's `endpoint` and the action receipt's
   `action.tool.endpoint` carry it, never the template. #246 and #247 kept a connection's tenant in
   the connection's own configuration; #248 answers the question for the engine's bindings, and a
   binding per tenant is not needed.
2. **The remote write's TLS identity.** **Proposed:** leave `action` as it is here, and take an
   `action.tool.peerIdentity` up only with a reader who needs it.

## More information

- `SPEC.md` §1.2a ("A remote MCP server"), §1.4, §6 ("Shape `mcp`, by transport");
  [`adapters/README.md`](../../adapters/README.md), `adapter-mcp`, "The remote form";
  [`SECURITY.md`](../../SECURITY.md); [engine-config.md](../design/engine-config.md), Bindings;
  [executor.md](../design/executor.md).
- `adapters/mcp/remote.go`, `adapters/mcphttp/client.go`, `go/remote_acquisition.go`,
  `verify-ts/src/structure.ts`; `corpus/v3/stores/v3-mcp-remote-*.json`.
- [ADR-0002](0002-adapters-report-in-the-envelope.md), [ADR-0011](0011-hold-a-write-to-its-decision.md),
  [ADR-0012](0012-hold-a-write-to-a-signed-record.md), [ADR-0014](0014-a-receipt-names-the-witness.md);
  issues #245 to #248.
- Material-decision categories: public-surface, documented-claim, conformance, security.
