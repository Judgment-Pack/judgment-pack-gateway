# Plugins: the engine reached from where work already happens

The plan's last phase promises three upstream plugins — an Activepieces piece, an n8n community
node, a ContextForge gateway plugin — so that a team already running a workflow tool or an MCP
gateway gets receipts without adopting anything new. This note says what a plugin is with
respect to the engine, which of the three are the same thing and which is not, what each ships
with, and what none of them claims. The packages live under `plugins/` in this repository and
are built and linted by the CI job "plugins"; their upstream submissions are a separate,
outward-facing step this note does not take.

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
| Acquire | `POST /acquire` | `session`, `source`, `arguments` (an object) | `{result, receipt, salts}` |
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
verdict before relying, and never takes the engine's own `GET /verify` for it (§5a.3); the
packages hand the receipt on and say so, and their examples seal and verify an acquisition
session before an action session begins. They do not hold a session for the caller: the session
is a flat token the workflow chooses (§3a), and sealing it is an operation the workflow calls.
They take no dependency beyond each framework's own (n8n's verification rules forbid runtime
dependencies, environment variables and files; Activepieces pieces take the framework and
`tslib`), and they read nothing the caller did not pass as a parameter. One thing of the
framework's the piece does not use: `@activepieces/pieces-common`'s HTTP client, at the pinned
version, sets `NODE_TLS_REJECT_UNAUTHORIZED` to `0` for the whole process before every request,
which would let an impersonating engine over https collect the bearer; the piece sends through
Node's own `fetch`, which verifies certificates and touches no process state, and leaves the
framework's custom-call action out for the same reason. A test holds the transport to that.

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
published packages, pinned. The upstream contribution is not a copy: the monorepo generates a
piece's scaffold with workspace dependencies and its own lint rules, so the source is copied
into that scaffold and adapted to the revision it targets.

## The witness: what a ContextForge plugin would need

ContextForge's plugin framework (the `cpex` package) runs a plugin at named hooks —
`tool_pre_invoke` with the tool name and arguments, `tool_post_invoke` with the result — and a
hook answers with `continue_processing`, an optional `modified_payload` or a `violation`; a
plugin runs in the gateway's process or as an external service over MCP (`kind: external`),
in `enforce` or `permissive` mode. A receipting plugin is a `tool_post_invoke` hook that has
seen the call and its answer and wants them signed. Two designs would serve it, and neither
exists yet:

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
The recommendation is to do the second first — it serves any MCP client, ContextForge among
them, and needs only engine work under the existing contract — and to put the first to the
specification as an RFC, because "receipts on every tool call" across servers the engine never
touches is a witness claim, and the specification should say what such a receipt is worth
before an engine mints one. Neither is in this change.

## Where the code lives and what checks it

`plugins/` holds one directory per ecosystem package, each with its own manifest, lock file,
licence and README, none linked to the Go modules: the core stays standard-library-only and the
adapters module's dependency rule is untouched. The CI job "plugins" installs each package from
its lock file, builds it, runs its linter (n8n's own for the node) and its tests — unit tests
over the request-building code, run with Node's test runner, no test dependency added. Publishing
to npm and the upstream pull requests are not CI's to do.

## What this does not claim

A client plugin makes the engine reachable; it adds no assurance. The receipt a workflow gets is
worth what `gateway verify` says about it later, under a key pinned out of band, and the
packages' READMEs say that where the receipt is handed over. Nothing here gives an MCP gateway
receipts on calls the engine did not make; that is the choice above, still open.
