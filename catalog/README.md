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
acquisition. The connector's `history` file is the configuration its `spec`
describes (`host`, `port` as a number, `database`, `username`, `password`, `ssl_mode` as an
object, `replication_method` as an object, `schemas` as a list). A platform names one file
per operation.

**The binding has no `write` operation** (2026-10-14, #260). It once carried one, naming the
same server's `execute_sql`, a tool that takes a statement. A decision policy can bind a
statement's text only as a whole, never argument by argument, so a decision could authorize any
statement the requester wrote: raw SQL is no write tool (see the write-back platforms below),
and `postgres` holds to that rule now. The server (`bytebase/dbhub` 1.2.3) offers no narrower
tool, so none is named; a function or procedure write returns when a server offers one. A
platform that pins this binding and sets `write: true` is refused at start, naming the
platform and the rule, and its credentials name no `write` file. That historical change retained the then-current `history` and `live` entries.

Current shipped catalogs use owner declarations (bindingVersion 2 or 3), so their complete
digests change. Pin them explicitly and recapture per-operation snapshotV2 approval;
no old approval is silently reused. Exact historical V1 copies remain in
`testdata/catalog-v1` for readers. See [taxonomy migration](../docs/releases/taxonomy-v2-migration.md).

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
write-back platforms", has one for `wit_work_item_write`: it fixes `action` to `update` and the
form of the operations, binds the work item's id and revision to the record's facts, holds
`updates` to an array of two, and is closed, so an argument it does not name, or `updates` written
as an object, is refused).

**No read-only header.** "Use the `X-MCP-Readonly` header to restrict the server to read-only
operations" (set up the remote server): the connection sends it on its reads, and a write needs
it absent, so this binding sends no header at all, and `go test` holds every catalog file's write
operation to sending none. The credential's scopes and its identity's permissions are what bound
a write, and the decision policy is what holds each one to its decision.

The organization's local MCP server (the npm package `@azure-devops/mcp`, over stdio) is not a
catalog entry: the catalog's binding forms are an image pinned by digest or a remote server
named by URL and transport, and the engine authors no binding for a server the operator
installs; an operator runs it as a source under `adapter-mcp`
([adapters/README.md](../adapters/README.md)).

**Decided 2026-10-14 (#259): no catalog binding of the local server.** The catalog's bindings
take two forms: an image pinned by digest, or a remote server named by URL and transport. A
local executable or package is neither. Shipping the local server would mean the project
building, licensing and re-pinning an image of a third-party package, which it does not take on.
Write-back to Azure DevOps goes through the organization's remote server under a Microsoft
Entra token, as the binding above states; the local server stays an operator-level stdio source,
for reads. Revisit if an operator who can hold only a personal access token needs write-back.

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
statement it is given is raw SQL by another name, and its author is the one to refuse it. The
`postgres` binding holds to the same rule: it predated it, and its `write` operation, which
named `execute_sql`, was removed on 2026-10-14 (#260).

## microsoft-graph

| Operation | Artifact | Pinned | Licence | Where the licence is stated |
|---|---|---|---|---|
| `live` | the Microsoft Graph v1.0 API, `https://graph.microsoft.com`, read by `adapter-http` | the endpoint, the 24 paths, `GET` alone and the bearer, by the file's digest; there is no image | hosted service: the operator's own service terms | the engine pulls and runs nothing of the service; its use is under the terms of the operator's own tenant |

A read-only directory source: the binding's one operation is `live` of the `http` shape
([engine-config.md](../docs/design/engine-config.md#an-http-api-as-a-platforms-live-operation)),
whose method is `GET` alone, so no request through it is a write. What it may read beyond that
is the operator's to grant: the application permissions given the app registration the token
step signs in as. The binding names none and grants none. Four of its paths are templates,
so a configuration that pins it is of engine version 31 or later ("Path templates and links on
an http source (engine version 31)" in engine-config.md); under an earlier one it is refused by
name.

| Paths | What they read |
|---|---|
| `/v1.0/users`, `/v1.0/users/delta` | users, and their changes |
| `/v1.0/groups`, `/v1.0/groups/delta`, `/v1.0/groups/{id}/members` | groups, their changes, and one group's members |
| `/v1.0/directoryRoles`, `/v1.0/directoryRoles/{id}/members` | directory roles, and one role's members |
| `/v1.0/roleManagement/directory/roleDefinitions`, `/v1.0/roleManagement/directory/roleAssignments` | role definitions and assignments |
| `/v1.0/identityGovernance/privilegedAccess/group/eligibilityScheduleInstances`, `…/assignmentScheduleInstances` | privileged access for groups: eligible and active instances |
| `/v1.0/oauth2PermissionGrants` | delegated permission grants |
| `/v1.0/applications`, `/v1.0/servicePrincipals`, `/v1.0/servicePrincipals/{id}/appRoleAssignedTo`, `/v1.0/servicePrincipals/{id}/owners` | applications, service principals, the app roles assigned to one, and its owners |
| `/v1.0/auditLogs/directoryAudits`, `/v1.0/auditLogs/signIns` | directory audit events and sign-ins |
| `/v1.0/identityProtection/riskDetections`, `/v1.0/identityProtection/riskyUsers` | risk detections and risky users |
| `/v1.0/reports/authenticationMethods/userRegistrationDetails` | each user's registered authentication methods |
| `/v1.0/devices` | devices |
| `/v1.0/identity/conditionalAccess/policies` | conditional access policies |
| `/v1.0/organization` | the tenant's organization, which `checkPath` GETs |

A template's `{id}` is filled by a GUID alone, an object id, so a request names one group's,
role's or service principal's members and no other resource. A request the service refuses,
for want of a permission or for any other reason, is a failed source, and nothing is minted.

**The token.** The service takes an access token the identity platform issues by the
client-credentials grant, so the platform names a token step (engine-config.md, "A live
operation's token step (engine version 21)"):

```json
"directory": {
  "binding": "microsoft-graph@sha256:…",
  "credentials": {"live": {
    "file": "/run/secrets/directory-live",
    "tokenStep": {
      "endpoint": "https://login.microsoftonline.com/<tenant>/oauth2/v2.0/token",
      "clientId": "<the app registration's application id>",
      "federatedTokenFile": "/var/run/secrets/tokens/directory",
      "requestScope": "https://graph.microsoft.com/.default"
    }
  }},
  "user": "engine-directory"
}
```

- `endpoint` is the tenant's token endpoint, `<tenant>` its directory id, written out: a token
  step's endpoint takes no placeholder.
- `requestScope` `https://graph.microsoft.com/.default` asks for the application permissions
  granted to the app, all of them.
- `federatedTokenFile` is a token the workload's platform issues it, a projected service account
  token say, which the app registration trusts by a federated identity credential: nothing
  secret is kept on the host. In its place, `privateKey` names the PKCS #8 key of a certificate
  registered on the app, with `x5t#S256` its thumbprint. The identity platform asks of such an
  assertion a header whose "`alg` Should be **PS256**", a `x5t#S256`, and an `aud` of the token
  endpoint ([certificate credentials](https://learn.microsoft.com/en-us/entra/identity-platform/certificate-credentials),
  dated 2025-01-04, updated 2026-06-15); `adapter-http` signs RS256 for an RSA key and ES256 for a
  P-256 key, and no PS256, so whether the token endpoint takes its assertion is not established
  here. The federated form is the one this binding is tested in, against a stand-in.
- The live credentials file is still required, and nothing of it is sent: with a token step the
  binding's `bearer` member, `token`, is not read.

**Paging.** A collection is answered a page at a time, the next named by `@odata.nextLink`, an
absolute URL with `$skiptoken`; the last page of a delta round names `@odata.deltaLink`, with
`$deltatoken`, instead ([delta query overview](https://learn.microsoft.com/en-us/graph/delta-query-overview),
dated 2025-01-15, updated 2026-05-14). A caller sends the first page by `path` and `query` and
each next one by its link, as written, in the same session:

```json
{"session": "directory-users-1", "source": "directory/live",
 "arguments": {"path": "/v1.0/users", "method": "GET", "query": {"$select": "id,displayName,accountEnabled", "$top": "100"}}}
{"session": "directory-users-1", "source": "directory/live",
 "arguments": {"link": "https://graph.microsoft.com/v1.0/users?$select=id,displayName,accountEnabled&$top=100&$skiptoken=…", "method": "GET"}}
```

`$` is sent as written: "On the v1.0 endpoint, the $ prefix is optional for only a subset of
APIs. For simplicity, always include $" ([query parameters](https://learn.microsoft.com/en-us/graph/query-parameters),
dated 2025-07-02, updated 2026-03-07). Each page is its own receipt, whose statement commits to
the path and query sent; a link's commits to its query as `rawQuery`, byte for byte. Every page
must fit the adapter's 1 MiB envelope, and one past it is refused, not cut: `$select` narrows a
page, and `$top` shortens one where the path takes it, which a user or group delta does not
(delta query overview).

**An expired delta token.** "Delta query can return a response code of `410 Gone` and a
**Location** header containing a request URL with an empty `$deltatoken`", after which the
round starts again from the delta path; a delta token of a directory object is held "seven days"
(delta query overview). `/acquire` answers such a `410` with `source_reference_expired` and
nothing of the answer, the `Location` among it; the caller drops the delta link and sends the
delta path again. The same page says that "In case the token expires, the service should respond
with a 40X-series error with error codes such as `syncStateNotFound`": a `400` or a `404` so
answered is a failed source, as any other, and not `source_reference_expired`, so a caller that
kept a delta link past seven days reads again from the delta path either way. Which status the
service gives an expired directory delta token has not been observed here.

**Throttling.** A request the service throttles is answered `429 Too Many Requests` with a
`Retry-After` of seconds ([throttling](https://learn.microsoft.com/en-us/graph/throttling),
dated 2025-01-14, updated 2025-08-06); `/acquire` answers a `429` or a `503` with its class and
the wait, at most 3600 seconds, and does not retry: the caller waits and asks for the same page
again in the same session (engine-config.md, "A throttled answer").

The binding sets no header, so a request the service answers only beside a header of the
caller's choosing cannot be made through it; a header is a change to the binding, and so to its
digest. Every request in this binding's tests went to an invented stand-in on loopback
(`go/graph_binding_e2e_test.go`); none reached the service.

## google-workspace-directory and google-workspace-reports

| Binding | Live operation | Paths | Check |
|---|---|---|---|
| `google-workspace-directory` | `https://admin.googleapis.com`, `GET` alone, the token step's token as the bearer | users, a user (`{numericId}`), groups, a group and its members (`{alnumId}`), roles, a role, role assignments, a role assignment (`{numericId}`), under `/admin/directory/v1` and `customer/my_customer` | the roles listing, answerable under `admin.directory.rolemanagement.readonly` |
| `google-workspace-reports` | the same | the activities of all users for the applications `admin`, `login`, `token`, `user_accounts`, `groups`, `saml`, `drive` and `mobile`, fixed paths | the `admin` application's activities, under `admin.reports.audit.readonly` |

The Google Workspace Admin SDK's Directory and Reports APIs, read only
([ADR-0045](../docs/adr/0045-a-delegated-subject-token-signed-by-the-credentials-api.md)). Each
platform takes a token step of the `signedBy` form (engine version 33), whose scopes are the
Admin SDK's read-only ones alone; the service's own terms are the licence, since no image runs.
A user or group is named in a path by its unique id alone, never its address: an address goes
in a query member (`users?customer=my_customer&query=email:…`, `groups?userKey=…`). Paging is by
the `pageToken` query member. The Directory API's tokens resource is not bound: its scope,
`admin.directory.user.security`, also deletes tokens and signs users out.

## Action recovery

The write catalogs use bindingVersion 3. Each listed tool explicitly declares
`actionRecovery: null`: neither the generic function binding nor the remote
work-item tools declare a correlated idempotency/read-back contract. A keyed
uncertain action is never resent. An operator-owned function can supply a pinned
recovery contract and an approved read-only live tool; registration must recapture
all affected descriptors after the binding digest changes. A provider name or
tool annotation does not establish support. There is no shipped Drive action
binding; personal Drive storage keeps its separate durable-plan protocol.

See [action reconciliation](../docs/design/action-reconciliation.md) for the
contract, private journal backup requirements and platform limitations.
