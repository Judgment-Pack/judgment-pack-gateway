# Connection capability catalog

Status: shipped in v0.3.0 (#144, amended in #148); companion discovery contract,
version 2. It was proposed separately from the Notion/Obsidian connection review in
PR #143 and flagged for its own material-decision review. It does not change the
normative gateway receipt contract.

## Problem and behavior

A host with a built-in list can offer a connection that its installed companion
cannot implement. `gateway-connections --catalog` reports the connection protocols
in that binary. The host intersects these descriptors with its own supported UI
handlers before requesting account status or exposing controls.

The command emits one JSON document and exits. It takes no other flags or
positional arguments, reads no stdin, loads no publisher registration, opens no
credential store, creates no account state, and contacts no provider. It works
without `--state-dir` or `--principal`. Normal provider mode is unchanged.

Example descriptor, within `{ "version": 2, "providers": [...], "sources": [...] }`:

```json
{
  "id": "obsidian",
  "auth": "local-folder",
  "registration": "none",
  "selection": "source-search",
  "queryRequired": false,
  "operations": ["status", "configure", "disconnect", "search", "select"]
}
```

## Meaning

- `id`: stable provider identifier, not a user-supplied module name.
- `auth`: `oauth` or `local-folder` describes the existing consent flow.
  In catalog version 3, `credentials` is secrets typed into the setup form
  and used as given (Amazon S3, web search), and `client-credentials`
  (Databricks) is a setup form that carries either a token used as given or
  an OAuth client's id and secret, which the companion exchanges at the
  provider's token endpoint by the client-credentials grant for a
  short-lived access token it keeps in its own custody: no browser, and no
  person's consent.
- `registration`: `google-desktop`, `automatic` (Notion DCR), or `none`;
  `form` in version 3, where the setup form's object is sent to `configure`.
- `selection`: `mail-search` or `source-search` names an existing
  wire contract. It is not a component name, URL, or executable to load.
  `browser-picker` was Drive's until ADR-0010, and no provider has it.
  `none` (Databricks) is no search or selection: a read names what it reads
  in the source's request.
- `queryRequired`: search needs nonempty input. False permits initial bounded
  browsing; it does not imply unbounded account search.
- `operations`: companion control methods, also used by the broker to refuse
  unsupported methods after persisting operator policy. These include connection lifecycle
  operations, not permission to edit the provider's source content.

Only the four implemented providers are advertised: Google Drive, Gmail, Notion,
and Obsidian. The result has no account identity, credentials, endpoint, arbitrary
UI text, filesystem path, or acquisition grant. Each call returns fresh slices so
callers cannot mutate the broker's allowlist through a prior catalog value.

This is **implementation support**, not account availability. An operator may
still block a provider; app registration may be missing; consent may have expired;
provider service may be down. Clients must obtain live `status`, complete normal
consent, and use read grants that the host asked for. A grant says that the
host asked to read a resource; it does not say that a person chose it. Existing gateway checks still
apply on every operation. `--catalog` is not a tool listing, a signed receipt, a
health check, or a grant to enable account-wide assistant search.

## Host compatibility and limits

Desk consumes only its verified, revision-pinned local companion, with its normal
session and local/external configuration guards. It allows five seconds and 32 KiB
for discovery, with at most 32 providers and 16 distinct operations each. Version
and protocol shape are validated before display. Unknown provider IDs or protocol
combinations are not executed; a compatible older UI may omit a newer provider.

The catalog is not an extension loading mechanism. Labels, icons and handlers
remain shipped UI code; adding a provider still requires tested gateway behavior
and an appropriate host handler. Changing a selection protocol requires a new
recognized protocol identifier or catalog version, not silently reusing a name.

No fallback to a guessed catalog follows a command failure. Host cancellation,
malformed responses, unsupported versions, duplicate identifiers, over-budget
output or a failed process make discovery unavailable. The command's static output
is currently well below the stated budget.

## Validation

Gateway tests cover discovery with invalid publisher data and no state directory,
refusal of mixed command modes, unchanged filesystem, fresh descriptor ownership,
and operator-disable persistence even for unsupported requests. Existing provider fixture tests
exercise the advertised protocols. Desk separately tests the process boundary,
output/time bounds, authentication, external-gateway refusal, compatibility,
revoked capabilities, stale asynchronous replies and menu stability. No live
provider account or OAuth acceptance is implied by these fixture checks.

## Databricks (version 3)

Catalog version 3 advertises `databricks` with the protocol `databricks-v1`:
`status`, `configure`, `test` and `disconnect` over up to six named
connections, each to one workspace's REST API. Its `auth` is
`client-credentials`, its registration `form`, its selection `none`. The setup
fields are the workspace URL, the SQL warehouse ID, the authentication
(`token` or `service-principal`), a personal access token, or a service
principal's OAuth client ID, secret and scopes (`all-apis` unless given), an
optional default catalog and schema, the statement wait and the result bound.
Reads are made by `adapter-sources --provider databricks` (source `databricks`,
shape `http`, record `databricks-api-v1`), never by the companion, whose `test`
makes one request, for the first catalog of the listing, and answers only
whether it succeeded. The operation, the request, the bounds and the refusals
are in the [adapters README](../../adapters/README.md#databricks-connections-api-profile).
The API is as Databricks documents it in
[Execute a SQL statement](https://docs.databricks.com/api/workspace/statementexecution/executestatement)
and the [Statement Execution API tutorial](https://docs.databricks.com/aws/en/dev-tools/sql-execution-tutorial)
(updated 2026-10-06), the Unity Catalog listings and their paging
([catalogs](https://docs.databricks.com/api/workspace/catalogs/list),
[schemas](https://docs.databricks.com/api/workspace/schemas/list),
[tables](https://docs.databricks.com/api/workspace/tables/list),
[functions](https://docs.databricks.com/api/workspace/functions/list)), and
[OAuth machine-to-machine authentication](https://docs.databricks.com/aws/en/dev-tools/auth/oauth-m2m)
(updated 2026-10-12); the pages that show no date were read on 2026-10-13.
The managed MCP servers are the MCP profile, below.

**What a read establishes.** A read's receipt establishes that the adapter
received these bytes from that workspace endpoint, under the TLS identity the
receipt names, for that statement or listing, at that time, sent under the
credential the operator configured for the connection: the personal access
token, or an access token minted for the service principal.

**What it does not establish.** That the data is current or correct; that the
identity's grants are what the operator intends; or that a statement read
rather than wrote. Nothing in the connection holds a statement to reading: the
statement is sent as given, and the SQL warehouse's and Unity Catalog's grants
on the identity are what keep this profile to reads. An operator who wants
reads only gives the identity read privileges only.

**The MCP profile.** A connection may also enable the workspace's managed MCP
servers (`mcp` in `configure`): the Databricks SQL server, a Genie space's,
a Unity Catalog function's and an AI Search index's, each an endpoint under
the workspace that Databricks lists among the legacy workspace endpoints of
its [Databricks-provided MCPs](https://docs.databricks.com/aws/en/agents/mcp-tools/built-in-mcp-services)
(updated 2026-10-08), behind the Managed MCP Servers preview; and Unity
Gateway services, each an MCP service registered in Unity Catalog and reached
at `/ai-gateway/mcp-services/<catalog>.<schema>.<service>`, which that page
recommends "For new Genie One and Databricks SQL connections". Each is
enabled by its exact name, with the tools a read may call on it; the
connection neither discovers nor lists the workspace's services. A read is one
tool call over Streamable HTTP under the same credential, made by
`adapter-sources`; the companion's `test` lists each server's tools and calls
none. The servers, the request, the bounds and the refusals are in the
[adapters README](../../adapters/README.md#databricks-connections-mcp-profile).

**What an MCP read establishes.** A read's receipt establishes that the
adapter received these bytes from that server's endpoint under the workspace,
under the TLS identity the receipt names, for that tool and those arguments,
at that time, sent under the credential the operator configured for the
connection.

**What it does not establish.** That the answer is true or current, or that
the tool read rather than wrote. Databricks states of the
[Genie Agent server](https://docs.databricks.com/aws/en/agents/mcp-tools/genie-agent)
(updated 2026-10-07): "Read-only. The Genie Agent MCP server queries data; it
doesn't write to your tables." Of [Databricks SQL](https://docs.databricks.com/aws/en/agents/mcp-tools/databricks-sql)
(updated 2026-10-08) it states that "The MCP permits reads and writes by
default", and of the workspace endpoint this profile reaches that it "uses the
Managed MCP Servers workspace preview and underlying resource permissions": the
SQL server runs what it is sent, as far as the identity may. A
[Unity Catalog function](https://docs.databricks.com/aws/en/agents/mcp-tools/uc-functions)
(updated 2026-10-07) does what its body does, "with access governed by Unity
Catalog permissions". The identity's grants and the connection's tools list
are what keep this profile to reads; nothing in the connection holds a tool
call to reading, and the arguments are sent as given. A Unity Gateway
service is any MCP service registered in Unity Catalog under that name: one
Databricks provides under `system.ai` (Genie One, SQL, web search, a code
sandbox, and connectors to Slack, GitHub, Atlassian, Google Drive, Calendar,
Gmail and Microsoft 365), or an external MCP server an account registered from
a Unity Catalog connection ([register an external MCP server](https://docs.databricks.com/aws/en/ai-gateway/register-mcp-service),
updated 2026-10-07). It may be an external connector, and it may write; no
page states that a service is read-only, and the connection claims nothing of
the kind. The service list, the tools list and the identity's grants
(`EXECUTE` on the service, [govern an MCP](https://docs.databricks.com/aws/en/ai-gateway/govern-mcp-service),
updated 2026-10-08) are the only things that keep this profile to reads, and
the operator enables a service knowing what it is.

## Public URL sources (version 2)

Version 2 adds a separate `sources` list for explicit inputs without account
connections. The web descriptor and its bounds are defined in
[public web sources](public-web-sources.md). The provider dispatch allowlist is
unchanged. Version 1 clients must refuse this version rather than guess support.
