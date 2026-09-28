---
status: proposed
date: 2026-09-28
deciders: maintainer
---

# The engine's configuration names the adapters the engine ships as services, and the MCP server lists the ones the operator opens to it

## Context and problem statement

Two adapters of the second module are bare sources under the `"command"` shape: the document
adapter of [ADR-0004](0004-documents-are-an-adapter-under-the-command-shape.md) and the
rendering adapter of [ADR-0006](0006-documents-are-rendered-by-an-adapter.md). A gateway
started from the command line serves either with `--source`. An engine started from its
configuration serves neither. `serve --config` takes the file and nothing beside it, the file
names platforms, and a platform's binding offers operations that the `airbyte` and `mcp` shapes
serve ([engine-config.md](../design/engine-config.md)). The MCP server lists the live tools of
platforms and sends each call to `<platform>/live` ([mcp-server.md](../design/mcp-server.md)).

So under a configuration neither adapter is reachable by `/acquire`, and no MCP client
reaches either. ADR-0004 named a binding for document sources as what would let the MCP
server serve them. ADR-0006, determination 8, named three things that do not exist: a binding
for a command-shaped source, the source the engine derives from it, and the MCP server's
listing and dispatch for it, with a schema for its arguments. It said that was a separate
decision. This is that decision.

## Decision drivers

- The configuration names what the engine may reach and never a process. Nothing in it is a
  command line (engine-config.md, "The rule").
- An adapter the engine ships is not an outside platform. It has no credential, no pinned
  image, and no licence of an artifact the engine pulls.
- Every source runs as a user of its own, never the signer's, and the engine refuses to start
  under a configuration where that does not hold.
- The MCP server is a client of the signer and nothing more
  ([ADR-0003](0003-a-fifth-process-speaks-mcp.md)). It holds no key, opens no store and starts
  no adapter.
- A receipt says the true thing. For these adapters that is the command shape.
- Bounds are the operator's, stated, and held to ceilings. A default admits little.
- An MCP host may show a tool's answer to a model. A file in an answer is base64.
- No change to `SPEC.md`.

## Considered options

- A `services` member of the configuration, naming for each service a kind the engine knows,
  the user it runs as and its bounds. The engine derives a bare source from each. The MCP
  server lists a service where its entry opens it to MCP.
- A catalog binding with an operation of a new `command` kind, and a platform entry that
  carries no credentials.
- `serve --config` taking `--source` beside the file.
- The MCP server starting the adapter itself.
- Leaving both adapters out of the configuration, for a gateway started with `--source`.

## Decision outcome

Chosen option: "a `services` member", because it names what the engine serves without naming a
process, keeps a service apart from a platform where the two differ, and gives the MCP server
a row to list without giving it anything to hold.

The determinations this record settles:

1. **The member.** `services` is an optional top-level member of the engine's configuration.
   It moves `engineVersion` to `"4"`, under the rule that a member change moves the version:
   a file of an earlier version loads without the member and is refused by name with it. It
   maps a name the operator chooses to a service:

   ```json
   "services": {
     "render": {
       "kind": "render",
       "user": "engine-render",
       "timeoutSeconds": 60,
       "maxOutputBytes": 6291456,
       "maxFileBytes": 4194304,
       "renderer": "render-pdf",
       "mcp": true
     },
     "documents": {
       "kind": "documents",
       "user": "engine-documents",
       "timeoutSeconds": 40,
       "maxOutputBytes": 8388608,
       "maxBytes": 16777216
     }
   }
   ```

   The kinds are a closed set, `render` and `documents`. A kind the engine does not know is
   refused by name, and so is a member a kind does not define.
2. **What the engine derives.** For each service one source, named by the service's name with
   no operation after it, declared with no shape, so that its receipts carry the command
   shape. It runs as the service's user. Its command line is built by the engine from the
   entry, every flag and its value as one word, and the adapter is found where a platform's
   adapters are found. Nothing in the entry is a command line.

   | Kind | Adapter | The entry's own settings |
   |---|---|---|
   | `render` | `adapter-render` | `maxBlocks`, `maxFileBytes`, `renderer` |
   | `documents` | `adapter-document` | `maxBytes`, `maxPages`, `maxTextBytes`, `maxInflateBytes`, `ocr`, `maxOcrOutputBytes` |

   Each setting is optional and is the adapter's own bound under another spelling. Absent, the
   adapter's default applies. The engine holds each to the adapter's ceiling when it loads the
   file, so that a configuration the adapter would refuse is refused at start and by name.
   What an adapter may read of a request is not a setting. The rendering adapter is given the
   engine's bound on a request, of determination 6, and the document adapter derives its own
   from `maxBytes`, as it does today.
3. **The name.** A service's name follows the rule of a platform's name: not empty, not
   padded, with no `/`, no `=` and no character that is not graphic. A name that a platform
   also has is refused, though `<platform>/live` and the service's name would not be
   the same source: one name means one thing in a configuration. A receipt's `source` is the
   service's name.
4. **The user.** Required, and held to every rule a platform's user is held to: it exists, and
   it is not root, not the signer's, not the MCP server's, and not the user of a platform or of
   another service. A service has no `credentials` member, and an entry that carries one is
   refused.
5. **The two bounds the gateway holds for the source.** `timeoutSeconds` is the source's
   timeout, and `maxOutputBytes` the bound on its output. Both are optional, default to what
   every derived source has today, thirty seconds and one mebibyte, and are held to the
   gateway's ceilings. The second is new to the core: one bound on output holds every source
   today, and a rendered file or a document's record needs more than a platform's answer
   does. The adapter's own deadline and its own bound on its record are not settings. The
   engine derives them: the deadline is the source's timeout less five seconds, which is room
   for the two-second wait on a program's output and for the record to be written, and the
   bound on the record is the bound on the source's output. A `timeoutSeconds` of five or
   less is refused.
6. **The bound on a request.** `maxRequestBytes` is a new optional top-level member, the
   `--max-request` of the command line: what `/acquire` reads of a body. It defaults to one
   mebibyte and is held to the same ceiling. It is the engine's and not a service's, since a
   body is read before its source is known. Content and documents ride in the request, so an
   operator who serves either sizes it.
7. **A program.** `renderer`, for `render`, and `ocr`, for `documents`, name the program the
   adapter runs, one word, resolved on the engine's `PATH` by the adapter. The program runs as
   the service's user. What ADR-0004 and ADR-0006 say of such a program holds unchanged: the
   adapter does not confine it, and the record names it with the digest of its file. The
   image ships neither.
8. **Over MCP.** The MCP server lists a service whose entry sets `"mcp": true`. Absent is
   `false`. It lists one tool for it, named `<service>.<tool>`, where the tool is the kind's:
   `render` for the kind `render`, `read` for the kind `documents`. The rows are held in the
   same table as the platforms' rows, and a name two rows would share is a refusal to start.
   - **The description and the schema** of the tool are the engine's own, part of the
     executable, and the same for every engine of that release. The schema is written within
     the grammar [tool-descriptors.md](../design/tool-descriptors.md) admits, which has no
     reference and no pattern, so it is looser than the adapter: a call that passes it can
     still be refused.
   - **A call** becomes `POST /acquire` with the service's name as `source` and the call's
     `arguments` as the arguments, byte for byte. They are not wrapped in
     `{"tool": …, "arguments": …}`, since the adapter reads its own arguments and knows no
     tool.
   - **The answer** is what it is for any tool: `{session, result, receipt, salts}`, as text
     and as structured content. For `render` the result is the render record, which holds the
     file.
   - **What a client binds** is what it binds for a platform's tool, with the service's name
     as the `source` it expects.
9. **What this record does not decide.** Whether the engine serves an artifact by its digest,
   so that an answer could name a file and not carry it. Saving a file, which is
   [ADR-0005](0005-personal-storage-controls.md)'s and is not a tool. `/act`, which the MCP
   server does not expose.

Why the other options were not chosen:

- **A binding of a `command` kind.** A binding says what an outside platform offers: a pinned
  image, the tools it may call, the licence of what is pulled, and credentials for each
  operation. None of those is true of an adapter the engine ships, and an entry with every
  one of them empty would be a platform in name only.
- **`--source` beside the file.** It puts a command line back on the command line, which is
  what the configuration exists to end, and leaves the MCP server nothing to read the source
  from.
- **The MCP server starting the adapter.** The receipt would then be of bytes the signer did
  not acquire, which ADR-0003 rules out, and the process that faces the network would start
  programs.
- **Leaving them out.** A desk on one machine is served by a gateway started with `--source`
  and can stay so. An operator who runs the engine from its image has no way to offer either
  adapter, and an MCP client has none at all.

### Consequences

- Good, because an operator who runs the engine from its configuration can serve rendering
  and document reading, each as a user of its own and within stated bounds.
- Good, because a receipt of either is the receipt it is today: version 3, the command shape,
  the service's name as its source.
- Good, because an MCP client reaches rendering with a receipt for every file, and the MCP
  server holds nothing more than it held.
- Bad, because the core changes: a member and a version of the configuration, a bound on
  output for each source where there was one for all, and a bound on a request that a
  configuration can set.
- Bad, because a rendered file rides in a tool's answer as base64, and a host that shows a
  tool's answer to a model hands the model the file. At the defaults an answer is under a
  mebibyte, as a platform tool's is. An operator who raises the bound and opens the service to
  MCP accepts the larger answer. Determination 9 names what would remove the cost.
- Bad, because reading a document over MCP takes the document's bytes in the arguments, which
  a host can supply and a model cannot usefully write. Listing `documents` serves a host that
  holds a file. It does not make document reading a tool a model can use by itself.
- Bad, because the schema the MCP server lists is looser than the adapter, and is the
  engine's word: it is not captured from a server and not pinned by the configuration, as a
  platform's descriptors are. It changes only with the engine.
- Bad, because the MCP server's table now holds rows of two kinds, which dispatch
  differently. The test that a call through the server and a direct `/acquire` commit to the
  same arguments has to hold for both.
- Bad, because a service opened to MCP is one more tool that spends the engine's time at a
  caller's word. The bounds of the MCP server hold it as they hold every tool: sessions,
  concurrency and calls a minute.
- Revisit when the engine serves an artifact by its digest; when a third kind is wanted, which
  is the point at which a closed set in the core should be weighed against a declaration an
  adapter ships with; or when the descriptor grammar admits references and patterns, so that
  the schema listed can be the adapter's own.

## More information

- [docs/design/engine-config.md](../design/engine-config.md) — the configuration, what the
  engine derives from it and what it refuses.
- [docs/design/mcp-server.md](../design/mcp-server.md) — the tool table, what a call becomes,
  the answer, and what a client binds.
- [docs/design/attachments.md](../design/attachments.md) and
  [ADR-0004](0004-documents-are-an-adapter-under-the-command-shape.md) — the document adapter,
  its bounds and its program.
- [ADR-0006](0006-documents-are-rendered-by-an-adapter.md) — the rendering adapter, and
  determination 8, which this record answers.
- [docs/design/tool-descriptors.md](../design/tool-descriptors.md) — the grammar a listed
  schema is written within.
- Nothing is built by this record. The configuration's new members, the derived sources, the
  bound on output for each source and the MCP server's rows are later pull requests, each
  with its own review.
- Material impact: public-surface, documented-claim, security. Cross-vendor review is recorded
  on the pull request that carries this record.
