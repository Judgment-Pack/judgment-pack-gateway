# catalog

The bindings the engine ships: one file per platform, `<platform>.json`, in the shape
[docs/design/engine-config.md](../docs/design/engine-config.md) states. A configuration
pins the file it uses by digest — `gateway connect` computes the pin when it writes the
platform entry — so a catalog update never silently changes what a running engine reaches.

Every image is pinned by the digest of its manifest index, as the registry served it on
the date recorded here; every licence is copied from the artifact's own statement for that
version, never assumed. `go test ./...` in `go/` holds each file to its shape and to its
file name.

## postgres

| Operation | Artifact | Pinned | Licence | Where the licence is stated |
|---|---|---|---|---|
| `history` | `airbyte/source-postgres:3.8.5` | index digest `a36f1528…ded125`, read from Docker Hub 2026-09-13 | ELv2 | `airbyte-integrations/connectors/source-postgres/metadata.yaml` in the airbytehq/airbyte repository at the commit where `dockerImageTag` is `3.8.5` (`4e38cca211`, 2026-08-26): `license: ELv2` |
| `live` | `bytebase/dbhub:1.2.3` with `--transport stdio` | index digest `8fbdf3f5…9f5db`, read from Docker Hub 2026-09-14 | MIT | `LICENSE` in the bytebase/dbhub repository |
| `write` | the same server, the same arguments | the same digest | MIT | the same |

The `live` entry carries no `probe`: this server connects to the database as it starts and
exits before answering the handshake when it cannot (a wrong password ends it with
"Configuration source: environment variable" on stderr, and the adapter reports "the server
ended before answering initialize"), so the handshake itself establishes the connection —
the opposite of the previous server, `crystaldba/postgres-mcp`, which started and listed its
tools whether or not it could reach the database. Both of this server's tools take
arguments (`search_objects` requires an `object_type`), so no probe could be named even if
one were needed. The server's `execute_sql` answers a query as **JSON text** — a text content
item holding `{"success": true, "data": {"statements": [{"sql", "rows", "count"}], "source_id"}}`,
rows as objects keyed by column — which is why it replaced the previous server, whose
`execute_sql` answered with Python's rendering of a list of dictionaries and left no
published rule to derive facts by ([docs/design/both-paths-agreement.md](../docs/design/both-paths-agreement.md)).

The server takes its connection string from the environment variable `DSN`, so both
credentials files are `{"DSN": "postgresql://…"}`, an object of strings. **What holds the
`live` operation to reading is the role the operator names in that connection string**, not
the server: this server's own read-only switch is a `[[tools]]` entry in a `dbhub.toml` it
reads from a path, and a binding hands a server an environment and arguments, never a file.
The `live` role must hold `SELECT` alone — that is what holds it to reading — and should
carry `default_transaction_read_only = on` (set on the role with `ALTER ROLE … SET`) as a
guard on top, one a session may lift with `BEGIN READ WRITE` and a connection-string
`options=` setting cannot set at all, since the driver does not carry it. The both-paths
test's live fixtures were captured through such a role, its fresh fetch runs both operations
through one, and an `UPDATE` through it is refused by Postgres — "cannot execute UPDATE in a
read-only transaction" under the default, "permission denied for table city" once the session
lifts it — which the server reports as an error result and the adapter as a failed
acquisition. The `write` file
names a role that may write. The connector's `history` file is the configuration its `spec`
describes (`host`, `port` as a number, `database`, `username`, `password`, `ssl_mode` as an
object, `replication_method` as an object, `schemas` as a list). A platform names one file
per operation, the `write` file only when the platform sets `write: true`. The `write` entry
is derived only for such a platform, as `<platform>/write`, and only the executor runs it
(`docs/design/executor.md`); `/acquire` never names it.

**The golden records.** The both-paths agreement test (`adapters/agreement`) fetches one row
of the World sample database (`ghusta/postgres-world-db:2.15.1`, `city` where `id = 1`), and
one row of a table it adds holding 2^53 + 1, through both operations and holds the facts each
yields to byte identity under the rule the design note states: the history path takes the connector's record, the live path asks the
database to render the row as JSON and hand it over as text (`SELECT to_jsonb(c)::text …`),
so that the typing on both sides is Postgres's own and not a driver's. A plain `SELECT`
through this server renders the `bigint` columns as strings (the Node driver's default for
64-bit integers), and the same row then differs from the connector's on `id` and
`population`; a `to_jsonb` column without the cast is parsed into JavaScript numbers, and an
integer past 2^53 comes back rounded, where the connector and the text-carried rendering both
keep the spelling. Both captures are kept as fixtures, as the reasons for the rule.

ELv2 (the Elastic License 2.0) forbids providing the connector to third parties as a
managed service; an operator hosting the engine for others should read it before enabling
the history operation, which is why the licence is in the binding at all.

## azure-devops

| Operation | Artifact | Pinned | Licence | Where the licence is stated |
|---|---|---|---|---|
| `write` | the organization's remote Azure DevOps MCP server, `https://mcp.dev.azure.com/{organization}`, over Streamable HTTP | the URL template and the transport, by the file's digest; there is no image | hosted service: the operator's own service terms | the engine pulls and runs nothing of the server; its use is under the terms of the operator's own subscription |

A write-back platform (issue #248): the binding states a `write` operation and nothing else, since
a platform's reads of Azure DevOps are the connection's
([connection-catalog.md](../docs/design/connection-catalog.md#azure-devops-version-3)). The
platform gives the `organization` parameter (engine configuration version 8), and the URL is
"a hosted version of the Azure DevOps MCP Server" that clients reach "by using streamable HTTP
transport" at `https://mcp.dev.azure.com/{organization}`
([set up the remote Azure DevOps MCP Server](https://learn.microsoft.com/en-us/azure/devops/mcp-server/remote-mcp-server),
dated 2026-09-21). The `write` credentials file is `{"token": "…"}`: a Microsoft Entra access
token of a person, or of a principal, the operator holds for writes, sent as the bearer. "The
remote MCP Server uses Microsoft Entra ID (OAuth) for authentication. Personal access tokens
(PATs) aren't supported for the remote server"
([troubleshoot the remote server](https://learn.microsoft.com/en-us/azure/devops/mcp-server/remote-mcp-server-troubleshooting),
dated 2026-07-31). Its scopes must allow the write: `vso.work_write`, "Work items (read and
write)", "the ability to read, create, and update work items"
([OAuth scopes](https://learn.microsoft.com/en-us/azure/devops/integrate/get-started/authentication/oauth#available-scopes),
dated 2025-07-14), and "OAuth scopes don't override the permissions of the signed-in user"
(set up the remote server). The engine mints and renews no token.

The tools are the server's three work-item write tools, each a grouped dispatcher whose `action`
argument chooses the operation; the page marks every one of these actions not read-only:

| Tool | Actions (set up the remote server, 2026-09-21) |
|---|---|
| `wit_work_item_write` | `create`, `update` ("Update fields on a work item"), `update_batch`, `add_child` |
| `wit_work_item_comment_write` | `add` ("Add a comment to a work item"), `update` |
| `wit_work_item_link_write` | `link` ("Link two work items"), `unlink`, `link_to_pull_request`, `add_artifact_link` |

The page gives no argument shapes. The open-source server it is "a hosted version" of gives them
(`src/tools/work-items.ts` and `docs/TOOLSET.md` in `microsoft/azure-devops-mcp`, read
2026-10-13): `wit_work_item_write` `update` takes `id` and `updates`, JSON Patch operations of
`op`, `path` and `value`, and for "a safe read-modify-write, prepend a test operation on `/rev`
with value set to the numeric revision … Azure DevOps rejects the entire update if the current
revision differs"; `create` takes `workItemType` and `fields`; `update_batch` takes
`batchUpdates`, each naming its own work item; `wit_work_item_comment_write` `add` takes
`workItemId` and `text`; `wit_work_item_link_write` `link` takes `updates` of `id`, `linkToId`
and `type`; every tool takes an optional `project`. "The remote and local servers might be at
different versions" (troubleshoot the remote server), so the remote server's own input schemas
are what `connect` captures through the write operation's check, at the resolved URL, and what an
operator writes a policy against ([engine-config.md](../docs/design/engine-config.md), "The
write-back platforms", has one for `wit_work_item_write`: it binds the whole arguments to the
write the record states, since `bind` cannot fix `action` or refuse an operation it does not
name).

**No read-only header.** "Use the `X-MCP-Readonly` header to restrict the server to read-only
operations" (set up the remote server): the connection sends it on its reads, and a write needs
it absent, so this binding sends no header at all, and `go test` holds every catalog file's write
operation to sending none. The credential's scopes and its identity's permissions are what bound
a write, and the decision policy is what holds each one to its decision.

The organization's local MCP server (the npm package `@azure-devops/mcp`, over stdio) is not a
catalog entry: the catalog pins images, and the engine authors no binding of a server the
operator installs; an operator runs it as a source under `adapter-mcp`
([adapters/README.md](../adapters/README.md)). Whether the catalog ships one is #259.

## databricks

| Operation | Artifact | Pinned | Licence | Where the licence is stated |
|---|---|---|---|---|
| `write` | one Unity Catalog function's managed MCP server, `https://{workspace}/api/2.0/mcp/functions/{catalog}/{schema}/{function}`, over Streamable HTTP | the URL template, the tool's template and the transport, by the file's digest; there is no image | hosted service: the operator's own service terms | the engine pulls and runs nothing of the server; its use is under the terms of the operator's own subscription |

A write-back platform (issue #248): a write is a Unity Catalog function the workspace's owners
wrote, called through its managed MCP server, so that every argument is a named parameter a
decision policy can bind; the platform's reads are the connection's
([connection-catalog.md](../docs/design/connection-catalog.md#databricks-version-3)). The URL
is the pattern Databricks lists for the server,
`https://<workspace-hostname>/api/2.0/mcp/functions/{catalog}/{schema}/{function_name}`, with the
OAuth scope `unity-catalog`; the server "exposes the custom Python and SQL functions you register
in Unity Catalog as predefined tools for agents to call, with access governed by Unity Catalog
permissions" ([Unity Catalog functions MCP server](https://docs.databricks.com/aws/en/agents/mcp-tools/uc-functions),
updated 2026-10-07; the same URL in [Databricks-provided MCPs](https://docs.databricks.com/aws/en/agents/mcp-tools/built-in-mcp-services),
updated 2026-10-08), and "calling an existing function requires `EXECUTE` on it"
([create agent tools using Unity Catalog functions](https://docs.databricks.com/aws/en/agents/custom-agents/create-custom-tool),
updated 2026-10-07). The platform gives four parameters: `workspace`, the workspace's host, held
to the host forms the Databricks connection accepts (one to three lowercase labels under
`.cloud.databricks.com`, `.cloud.databricks.us`, `.cloud.databricks.mil`, `.gcp.databricks.com`
or `.azuredatabricks.net`, not the account console's), so no parameter can point the template off
a workspace; and `catalog`, `schema` and `function`, the function's three-part name. The `write`
credentials file is `{"token": "…"}`, a Databricks access token of the identity the operator
holds for writes, with `EXECUTE` on the function; the engine mints and renews none.

The tool is the one the server offers for the function, `{catalog}__{schema}__{function}`, and
its arguments are the function's named parameters. None of the reference pages above names the
tool or its arguments; they say only that the server exposes functions as tools. The name and
the arguments are what Databricks' own examples call: at `…/api/2.0/mcp/functions/system/ai`,
`call_tool("system__ai__python_exec", {"code": …})`, the built-in `system.ai.python_exec` with
its one parameter, `code`, and the same form for a function of one's own, the three-part name
joined by two underscores (`genai-agents/foundation/03-tools-and-data-access/references/managed-mcp-servers.md`
in Databricks' `vibe-coding-workshop-template` repository, last changed 2026-06-06). `connect`'s
check of the write operation fails when the server offers no tool by that name, and captures the
function's input schema, which is what a policy's pointers are written against.

**Raw SQL is no write tool.** The binding names no SQL server and no tool that takes a
statement: a decision could then authorize an arbitrary statement, which no policy can bind
argument by argument, since a statement's meaning is in its text. A function whose body runs a
statement it is given is raw SQL by another name, and its author is the one to refuse it. (The
`postgres` binding above predates this platform, and its `write` operation names `execute_sql`,
which takes a statement; the same limit holds for it, and #260 is to decide what becomes of it.)
