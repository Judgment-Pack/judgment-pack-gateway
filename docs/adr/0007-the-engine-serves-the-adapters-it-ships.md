---
status: accepted
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
- Every platform runs as a user of its own, which its sources share, never the signer's, and
  the engine refuses to start under a configuration where that does not hold. A service is
  held to the same.
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
- A catalog binding with an operation of a new `command` kind that has members of its own,
  and a platform entry that carries no credentials.
- A declaration each adapter ships beside its executable, saying what it serves, its flags,
  their ceilings and its schema, which the engine reads.
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
       "timeoutSeconds": 30,
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

   An engine serves a file of version 4 that names at least one platform or one service.
   Its `platforms` may be an empty object where `services` names a service, and `catalog` is
   required exactly where `platforms` names a platform. So an engine can serve rendering and
   nothing else, with no platform configured to make it start. A file that names neither is
   still read, as it is today, since `connect` begins from one, and is still refused for
   serving.

   `connect` stays what it is, an operation on platforms. It adds a platform to a file that
   names a catalog, and refuses one that names none. It writes a file of version 4 as
   version 4, with its services and its bound on a request as they were. It holds a new
   platform's name and user against the services' as well as the platforms'.
2. **What the engine derives.** For each service one source, named by the service's name with
   no operation after it, declared with no shape, so that its receipts carry the command
   shape. It runs as the service's user. Its command line is built by the engine from the
   entry, every flag and its value as one word, and the adapter is found where a platform's
   adapters are found. Nothing in the entry is a command line.

   | Kind | Adapter | The entry's own settings |
   |---|---|---|
   | `render` | `adapter-render` | `maxBlocks`, `maxFileBytes`, `renderer` |
   | `documents` | `adapter-document` | `maxBytes`, `maxPages`, `maxTextBytes`, `maxInflateBytes`, `ocr`, `maxOcrOutputBytes` |

   Each setting is optional. A numeric setting is the adapter's own bound under another
   spelling, and absent, the adapter's default applies. `renderer` and `ocr` name a program
   and are determination 7's. When it loads the file, the engine holds every flag it will
   give the adapter, the ones it derives included, to the rule the adapter holds it to: its
   type, its least value, its ceiling and its unit. A configuration the adapter would refuse
   is refused at start and by name.

   What an adapter may read of a request is not a setting. The rendering adapter is given the
   engine's bound on a request, of determination 6, and the document adapter derives its own
   from `maxBytes`, as it does today.

   A service's source is started as a platform's is: through the same preflight, switched to
   its user, with an environment of that user's `HOME` and the engine's `PATH` and nothing
   else. A service has no `environment` member.
3. **The name.** A service's name follows the rule of a platform's name: not empty, not
   padded, with no `/`, no `=` and no character that is not graphic. A name that a platform
   also has is refused, though `<platform>/live` and the service's name would not be
   the same source: one name means one thing in a configuration. A receipt's `source` is the
   service's name.
4. **The user.** Required, and held to every rule a platform's user is held to: it exists, and
   it is not root, not the signer's, not the MCP server's, and not the user of a platform or of
   another service. A service has no `credentials` member, and an entry that carries one is
   refused. Every refusal of engine-config.md, "What the engine refuses", stands as it is:
   the seed's checks, the signer's capabilities, the switch, and the walk of every platform's
   credentials, which now also hold those files against a service's user. The one check that
   has nothing to do for a service is the walk of its own credentials, since it has none.
   Having no credential confines nothing: a service's adapter, and a program it starts, can
   read what its user can read.
5. **The two bounds the gateway holds for the source.** `timeoutSeconds` is the source's
   timeout, and `maxOutputBytes` the bound on its output. Both are optional and default to
   what every derived source has today, thirty seconds and one mebibyte. The second is new to
   the core: one bound on output holds every source today, and a rendered file or a
   document's record needs more than a platform's answer does.

   The adapter's own deadline and its own bound on its record are not settings. The engine
   derives them. The bound on the record is the bound on the source's output: the adapter
   writes its record in canonical form with nothing around it, so the two are the same
   bytes. The deadline is the source's timeout less five seconds.

   `timeoutSeconds` is from 6 to 605. The gateway admits a source a timeout of up to seven
   days, and both adapters refuse a deadline over ten minutes, so the adapters' ceiling is
   the one that holds. `maxOutputBytes` is from 1 to the gateway's ceiling, 64 MiB.

   The five seconds are a margin and not a promise. The gateway's clock for a source starts
   before it resolves, digests and starts the adapter, and the adapter's starts inside its
   own process. So what starting took comes out of the five seconds, and can use them up.
   Work between two of an adapter's checks of its deadline runs to its end, and so does the
   writing of a record. No receipt is minted for a source the gateway reports as timed out,
   whatever the source had written by then. An operator whose renderings or documents run
   close to their timeout raises it, as far as 605. A service opened to MCP is held to 30 by
   determination 8, so a service that needs more is not opened to MCP and is reached by
   `/acquire`.
6. **The bound on a request.** `maxRequestBytes` is a new optional top-level member of a
   version-4 file, the `--max-request` of the command line: what `/acquire` reads of a body.
   It defaults to one mebibyte and is from 1 to the gateway's ceiling, 64 MiB. It is the
   engine's and not a service's, since a body is read before its source is known. So it
   holds for every source: an operator who raises it for a service raises it for the
   platforms' sources as well. Content and documents ride in the request, so an operator who
   serves either sizes it.
7. **A program.** `renderer`, for `render`, and `ocr`, for `documents`, name the program the
   adapter runs, one word, held to the adapter's own rule for it when the file is loaded.
   The adapter resolves the name on the `PATH` it was given, when a request needs the
   program and not before: a name that resolves to nothing, or to a file that cannot be read
   or started, is the adapter's failure at that request, as it is today, and is not a
   refusal to start. The program runs as the service's user. What ADR-0004 and ADR-0006 say
   of such a program holds unchanged: the adapter does not confine it, and what a record
   says of it is what each adapter's contract says. A render record names the program of
   every PDF. A document's record names the OCR program whose answers it applied, and none
   where it applied none. The image ships neither program.
8. **Over MCP.** The MCP server lists a service whose entry sets `"mcp": true`. Absent is
   `false`. It lists one tool for it, named `<service>.<tool>`, where the tool is the kind's:
   `render` for the kind `render`, `read` for the kind `documents`.
   - **The table.** The rows are held in the same table as the platforms' rows. Each row
     says which of the two it is, a platform's tool or a service, and a call is routed by
     the whole name's row and never by a part of the name: a name may hold a full stop. A
     name two rows would share is a refusal to start.
   - **The description and the schema** of the tool are the engine's own, part of the
     executable, and the same for every engine of that release. The schema is written within
     the grammar [tool-descriptors.md](../design/tool-descriptors.md) admits. It is the
     structure of the adapter's arguments as far as that grammar can say it: every object
     closed, every member named with its type, the required members required, every
     enumeration stated, and the counts the contract fixes. Every request the adapter's
     contract admits passes it. What it cannot say stays the adapter's to refuse: the form
     of a text, a name, a digest or a target, a rule that relates two values, a bound the
     operator set, and whether a program is there. Tests hold the schema to the adapter's
     contract: its example requests pass, and requests broken in their structure do not.
   - **A call** becomes `POST /acquire` with the service's name as `source` and the call's
     `arguments` as the arguments, byte for byte. They are not wrapped in
     `{"tool": …, "arguments": …}`, since the adapter reads its own arguments and knows no
     tool. Absent arguments are `{}`, as for a platform's tool.
   - **The answer** is what it is for any tool: `{session, result, receipt, salts}`, as text
     and as structured content. For `render` the result is the render record, which holds the
     file.
   - **What a client binds.** A client holds a mapping of its own from a tool's whole name to
     what the name means: whether it is a platform's tool or a service, and the `source` it
     expects. It does not take either from the server, and it does not read them out of the
     name. Everything mcp-server.md has a client do for a platform's tool it does for a
     service: it verifies the store under the pinned key, reads the verdict, holds the
     session, the caller and the call's place among the findings, and digests the result it
     kept. For a service it holds the receipt to this besides: `source` is the service's
     name; the signed `acquisition.shape` is `command`; and the arguments commitment opens,
     under the salt it was handed, to the canonical form of the arguments it sent, alone.
     For a platform's tool the commitment opens to the canonical form of
     `{"tool": …, "arguments": …}`, as today. The tool's name is therefore no part of what a
     service's receipt commits to, and the `source` is what says which service answered. A
     receipt of the command shape states no endpoint, snapshot, schema, peer or statement,
     and carries no salt for a statement. Those are what the shape does not claim, and not a
     fault of the receipt.
   - **The tests** are the ones mcp-server.md names for a platform's tool, held for a
     service as well: that a call through the server and a direct `/acquire` commit to the
     same arguments, and that a call forwarded to another source is refused by a client that
     binds. A call forwarded to another service of the same kind passes the check of the
     shape and opens to the arguments sent, each commitment under its own salt, so what
     refuses it is the comparison of the signed `source` with the one the client expected.
     Between a service and a platform's tool the shape and what the commitment opens to
     differ too. The design notes state the cases when the rows are built.
   - **The MCP server's own limits stay what they are.** It reads a message of at most one
     mebibyte, reads a signer's answer of at most 8 MiB, and gives a forward 45 seconds
     (`go/mcp.go`). None is derived from a service's bounds, and `maxRequestBytes` does not
     raise the first. So over MCP a call's arguments are under a mebibyte whatever the engine
     admits by `/acquire`.
   - **What may be opened to MCP** is a matter of policy, and the policy is this. A service
     opened to MCP has a `timeoutSeconds` of at most 30 and a `maxOutputBytes` of at most
     6 MiB, and the engine refuses to start where an entry sets `"mcp": true` with more.
     Thirty seconds is the timeout the forward's 45 seconds were sized for: a source's
     thirty, the five the gateway waits for a source's output to close, and a margin
     (`go/mcp.go`). Six mebibytes is room for the record of a file at the default bound on a
     file, 4 MiB, and leaves two under the 8 MiB for the receipt, the salts and what JSON
     adds. Neither is a promise that an answer arrives. Within both, a forward can run out
     of time, and an answer can be too long for what JSON made of it. The outcome is then
     the one mcp-server.md states for every tool: `outcome: "unknown"`, with the signer free
     to have finished and minted a receipt the client did not see. The MCP server's bound on
     concurrency holds forwards that are outstanding, not acquisitions the signer has not
     finished, and a call made again is a new acquisition.
9. **What this record does not decide.** Whether the engine serves an artifact by its digest,
   so that an answer could name a file and not carry it. Saving a file, which is
   [ADR-0005](0005-personal-storage-controls.md)'s and is not a tool. `/act`, which the MCP
   server does not expose.

Why the other options were not chosen:

- **A binding of a `command` kind.** Such an operation could have members of its own and
  need none of an image's. What it costs is what a platform and a catalog mean. A binding is
  a file of the catalog, pinned by its digest so that a catalog's change is seen; a platform
  names credentials for each operation its binding offers, and the engine walks them. An
  adapter the engine ships changes with the engine and not with the catalog, and has no
  credential. Each rule of a platform would gain an exception for the two built-in kinds.
- **A declaration each adapter ships.** It would keep an adapter's flags, ceilings and
  schema in one place, where this record has the engine repeat them. It needs the engine to
  find the declaration, to hold it to a form, and to decide what a declaration may ask for,
  which is a design of its own. For two adapters of the same release the repetition is the
  smaller cost. The revisit condition names the point at which that changes.
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
  tool's answer to a model hands the model the file. At the defaults the record is at most a
  mebibyte. The answer is longer: it adds the receipt and the salts, JSON may spell a byte of
  the result as six (SECURITY.md), which the base64 of a file does not suffer and the text
  in a document's record can, and MCP carries the whole twice, as text and as
  structured content. An operator who opens a service to MCP accepts that, for hosts that
  keep the file from the model. Determination 9 names what would remove the cost.
- Bad, because a longer record costs the signer as well: it is parsed, put in canonical
  form, and retained in the artifact store, where a rendered file stays whether or not
  anyone saves it.
- Bad, because the schema, the flags and the ceilings of each adapter are now stated twice,
  in the adapter and in the engine, and the two are separate executables that the engine
  finds by name. They ship in one release. An operator who puts an adapter of another
  release beside the engine gets an engine that holds the adapter to rules that are not its
  own.
- Bad, because an operator who serves a service provides a user for it, and for a PDF or for
  scanned pages a program and the fonts or data it needs.
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
- Revisit when a host that an operator relies on cannot take a service's answer, for its
  length or for what it does with the file; when the engine serves an artifact by its
  digest; when a third kind is wanted, which is the point at which a closed set in the core
  should be weighed against a declaration an adapter ships with; or when the descriptor
  grammar admits references and patterns, so that the schema listed can say the forms as
  well as the structure. It would still not say what relates two values or what an operator
  configured.

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
