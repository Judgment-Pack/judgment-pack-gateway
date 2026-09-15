# Plugins: the engine reached from where work already happens

The plan's last phase promises three upstream plugins — an Activepieces piece, an n8n community
node, a ContextForge gateway plugin — so that a team already running a workflow tool or an MCP
gateway gets receipts without adopting anything new. This note says what a plugin is with
respect to the engine, which of the three are the same thing and which is not, what each ships
with, and what none of them claims. The packages live under `plugins/` in this repository and
are built and linted by the CI job "plugins"; publishing them, and asking each ecosystem to
list them, are separate, outward-facing steps a person takes ("Publishing", below).

## Two kinds of plugin

A plugin stands in one of two relations to the engine, and the relation decides what a
receipt it yields can mean.

**A client.** The workflow tool calls the engine's HTTP surface (`SPEC.md` §6): `/acquire`
runs a configured source and mints the receipt, `/act` performs a write through the platform's
write binding and mints the action receipt, `/seal` closes the session. The engine's own
adapters fetch the bytes, the engine's own key signs, and the plugin carries the answer —
result, receipt and salts — into the workflow as data. Nothing about the receipt's meaning
changes: it is exactly what a `curl` would have got. The n8n node and the Activepieces piece are
clients, and this note ships both.

**A witness.** An MCP gateway's plugin framework sees every tool call the gateway routes — the
tool name, the arguments, the result — but the gateway made the call, not the engine. A plugin
that wanted a receipt for such a call would have to hand the engine bytes it did not acquire,
and the engine would sign the plugin's testimony. That is the posture of an adapter (an adapter
holds the credentials and the engine signs what it reports, attributably), but §6 admits an
adapter only as a subprocess the engine spawned, with an identity the engine set, and takes no
envelope from a caller. A witness is a remote adapter, which the specification does not have.
The ContextForge plugin is a witness, and this note does not ship it; it states the choice
below.

## The clients

Both packages present the same three operations and the same credential, so a workflow reads
the same way in either tool.

| Operation | Calls | Sends | Yields |
|---|---|---|---|
| Acquire | `POST /acquire` | `session`, `source`, `arguments` (any value of the canonical JSON domain; left out when empty, for the engine's default `{}`) | `{result, receipt, salts}` |
| Act | `POST /act` | `session`, `platform`, `tool`, `arguments`, `decision` (`recordDigest`, `packDigest`), `cites` (an array of `{sessionId, callIndex, signature}`) | `{result, receipt, salts}` |
| Seal | `POST /seal` | `session` | the seal record |

The credential is the engine's URL and, when the engine is configured with an `identity`, a
bearer token the configured issuer signed ([engine-config.md](engine-config.md)): the token
names the caller on every acquisition receipt and the requester on every action receipt, and
an `/act` without one is refused before anything is read. The packages send the header only
when a token is given; the credential's test calls `GET /publickey`, which establishes that an
engine answers at the URL and nothing about the key's authenticity (§5).

**What the packages do not do.** They do not verify. A receipt's verification is `gateway
verify` over the store, the registry and the pinned key (§4), and it is the consumer's (§5a):
whoever relies on the bytes — the workflow itself, as often as not — checks the store-wide JSON
verdict before relying, never takes the engine's own `GET /verify` for it (§5a.3), and binds
before use (§5a.4): the receipt it holds signature-checked under the pinned key and among the
verifier's `ok` findings, and the bytes it kept re-digested to that receipt's `resultDigest`.
The packages hand the receipt on and say so, and their examples walk that ceremony — seal,
verify, bind — before an action session begins. They do not hold a session for the caller: the session
is a flat token the workflow chooses (§3a), and sealing it is an operation the workflow calls.
They take no dependency beyond each framework's own (n8n's verification rules forbid runtime
dependencies, environment variables and files; Activepieces pieces take the framework and
`tslib`), and they read nothing the caller did not pass as a parameter. One thing of the
framework's the piece does not use: `@activepieces/pieces-common`'s HTTP client, at the pinned
version, sets `NODE_TLS_REJECT_UNAUTHORIZED` to `0` for the whole process before every request,
which would let an impersonating engine over https collect the bearer, and which, once set,
decides for any transport that takes Node's default, `fetch` included; the piece sends through
Node's `http` and `https` modules asking for certificate verification on every connection
explicitly, touches no process state, and leaves the framework's custom-call action out for the
same reason. A test starts an https server with a self-signed certificate, sets the variable as
the framework's client leaves it, and requires the piece to refuse the connection. (The n8n node
sends through n8n's own transport, as n8n's verification requires; a node may not touch the
environment, and the transport is n8n's to keep honest.)

**n8n** (`plugins/n8n-nodes-judgment-pack`): one node, `Judgment Pack`, with the three
operations; one credential, `Judgment Pack Engine`; built with `@n8n/node-cli`, which is also
the linter n8n's verification runs; MIT, as verification requires, with its own LICENSE. The
node is usable as a tool: an agent in n8n may ask the engine for facts, which is the
orchestrator's place in the plan's second figure — it can ask, it cannot sign — and an `Act`
from an agent still needs a person's token and passes the engine's judgment gate like any other.

**Activepieces** (`plugins/activepieces/judgment-pack`): one piece,
`@activepieces/piece-judgment-pack`, with the three actions; a custom auth of URL and token.
Its source is laid out as the Activepieces monorepo's pieces are (`src/index.ts`,
`src/lib/auth.ts`, `src/lib/actions/`) and builds standalone here against the framework's
published packages, pinned. An upstream contribution would not be a copy: the monorepo
generates a piece's scaffold with workspace dependencies and its own lint rules, so the source
would be copied into that scaffold and adapted to the revision it targets. Activepieces takes no
such contribution now (below).

## The witness: what a ContextForge plugin would need

ContextForge's plugin framework is now the external CPEX package, which replaced the framework
ContextForge carried in its own tree (CPEX 0.1's documentation and ContextForge 1.0.10's
dependencies, read 2026-09-15). It runs a plugin at named hooks: `tool_pre_invoke` with the
tool's name and arguments, and `tool_post_invoke` with its name and result — the arguments are
not in the second, and a plugin that wants both keeps them in its own `PluginContext`, which, for
a plugin in one of the serial modes below, persists across a request's hooks. A hook answers with
`continue_processing`, an optional `modified_payload` or a `violation`. A plugin runs in the
gateway's process, in an isolated virtual environment, or as an external service
(`kind: external`) over MCP, gRPC or a Unix socket. Beside the modes this note first recorded —
`enforce` and `permissive`, with `enforce_ignore_error` and `disabled` — ContextForge now accepts
CPEX's own: `sequential`, `transform`, `audit`, `concurrent` and `fire_and_forget`, which run as
phases in that order, the plugins within each serial phase in ascending numeric priority (a lower
number runs first). So which result a `tool_post_invoke` hook sees depends on where it sits: a
`sequential` hook sees the changes of earlier `sequential` hooks, before later ones and the
`transform` phase, and an `audit` hook, when reached, sees the chained result after both. A
`fire_and_forget` hook does not. In CPEX 0.1.3, the version ContextForge pins
(`cpex/framework/manager.py` at the `0.1.3` tag), it is handed a snapshot of the payload the hook
was invoked with, before any plugin transformed it, though a comment there calls it the final
payload; it is given a fresh `PluginContext`, so it cannot read what its plugin kept at
`tool_pre_invoke`; and it is scheduled when a plugin halts the chain by returning a violation,
but not when one is raised as an exception, as ContextForge's tool calls raise them. A receipting
plugin is then a pair — a `tool_pre_invoke` hook that keeps the call, and a `tool_post_invoke`
hook that has the answer and wants both signed — run in a serial mode and placed by a choice of
which answer to report; run as `fire_and_forget`, it would have to pair the two by means of its
own. A second gateway offers a comparable hook with less to go on: Docker's MCP Gateway runs
interceptors `before` and `after` a tool call, and an `after` interceptor is handed the response
alone, with no call and nothing to pair it with one. Two designs would serve such a plugin; the
second is built ([mcp-server.md](mcp-server.md)), the first is not:

1. **A remote-adapter surface on the engine.** A new `POST` that takes an envelope of §6's form
   from an authenticated remote party — the plugin's identity as the adapter, the MCP server
   as the endpoint, the call as the statement, the result as the result — and mints a receipt
   whose `shape` says it was witnessed, not acquired. This is a change to `SPEC.md` (§1.2a's
   `shape` enumeration and §6's "no envelope from a caller") and belongs to an RFC in the
   specification repository through its review rounds, since it moves the honest bound: the
   engine would sign what a party it did not spawn reported, under that party's name.
2. **The engine as an MCP server.** A fifth process exposes each configured platform's live
   tools over MCP; a tool call becomes an `/acquire` under the caller's token and answers with
   the result and the receipt. An MCP gateway federates that server and every call through it
   is receipted with the engine's own adapters doing the fetching — honest by construction, no
   specification change, and no plugin: the gateway's operator registers a server. It covers
   the engine's platforms, not every server the gateway routes.

The first is what the plan's wording asks for and the second is what its rules permit today.
The second is built: [mcp-server.md](mcp-server.md) is its design and
[ADR-0003](../adr/0003-a-fifth-process-speaks-mcp.md) its record, and `gateway mcp` is the
process. The first stays an RFC question for the specification, because "receipts on every
tool call" across servers the engine never touches is a witness claim, and the specification
should say what such a receipt is worth before an engine mints one.

## Publishing, and what reaches each ecosystem

**n8n.** n8n verifies a community node only if it was published to npm from GitHub Actions with
a provenance statement, from 1 May 2026. `.github/workflows/publish-n8n.yml` publishes the node
that way, through `n8n-node release`, on a tag naming the package at its version; the node's
README gives the steps. Two stay with people: the npm account that is to own the package sets
up Trusted Publishing for that workflow, or a token, and asks for verification in n8n's Creator
Portal.

**Activepieces.** Activepieces has paused unsolicited pull requests from outside its core team,
closing them automatically, and asks that a piece be published as its own package instead (its
`CONTRIBUTING.md`, read 2026-09-15). The piece here is named
`@activepieces/piece-judgment-pack`, in a scope only Activepieces publishes to, so it cannot be
published as it stands: reaching Activepieces users means publishing it under a name in a scope
its publisher owns, for self-hosted instances to install. That name is the publisher's choice,
and this repository does not make it.

## Where the code lives and what checks it

`plugins/` holds one directory per ecosystem package, each with its own manifest, lock file,
licence and README, none linked to the Go modules: the core stays standard-library-only and the
adapters module's dependency rule is untouched. The CI job "plugins" installs each package from
its lock file, builds it, runs its linter (n8n's own for the node) and its tests — unit tests
over the request-building code, run with Node's test runner, no test dependency added. CI
publishes nothing: the n8n node is published by its own workflow, on a tag a person pushes
(above).

## What this does not claim

A client plugin makes the engine reachable; it adds no assurance. The receipt a workflow gets is
worth what `gateway verify` says about it later, under a key pinned out of band, and the
packages' READMEs say that where the receipt is handed over. Nothing here gives an MCP gateway
receipts on calls the engine did not make; that is the choice above, still open.
