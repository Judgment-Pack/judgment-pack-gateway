# Connection capability catalog

Status: shipped in v0.3.0 (#144, amended in #148); companion discovery contract,
version 2. It was proposed separately from the Notion/Obsidian connection review in
PR #143 and flagged for its own material-decision review. It does not change the
normative gateway receipt contract.

Drive's additional recurring host controls are documented in
[recurring source observations](recurring-source-observations.md). They extend
catalog v3/v4 `operations` only, and declare no research or external lifecycle
capability.

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
  and used as given (Amazon S3, web search, Azure DevOps), and `client-credentials`
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
  `none` (Databricks, Azure DevOps) is no search or selection: a read names
  what it reads in the source's request.
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

## Azure DevOps (version 3)

Catalog version 3 advertises `azure-devops` with the protocol
`azure-devops-v1`: `status`, `configure`, `test` and `disconnect` over up to
six named connections, each to one project of one organization's REST API. Its
`auth` is `credentials`, its registration `form`, its selection `none`. The
setup fields are the organization URL (`https://dev.azure.com/{organization}`
or `https://{organization}.visualstudio.com`), the project (its name or id),
the authentication, the credential, and the result bound. The authentication
is one of two values:

- `token`: a personal access token, sent as HTTP basic authentication with an
  empty user name, as [use personal access tokens](https://learn.microsoft.com/en-us/azure/devops/organizations/accounts/use-personal-access-tokens-to-authenticate)
  (dated 2026-09-21) states it.
- `bearer`: a Microsoft Entra access token the operator pastes with its expiry,
  sent as a bearer token, as [service principals and managed identities](https://learn.microsoft.com/en-us/azure/devops/integrate/get-started/authentication/service-principal-managed-identity)
  (dated 2026-09-21) states it. The companion mints nothing and renews
  nothing; a token at or within a minute of its expiry is refused before any
  request.

Reads are made by `adapter-sources --provider azure-devops` (source
`azure-devops`, shape `http`, record `azure-devops-api-v1`), never by the
companion, whose `test` makes one request, a query for at most one of the
project's work items, and answers only whether it succeeded. The reads (work
items by a WIQL query, by id, or both as one acquisition; repositories, a
repository's items, commits and pull requests; pipelines, a pipeline's runs,
one run), the bounds and the refusals are in the
[adapters README](../../adapters/README.md#azure-devops-connections-api-profile),
with the REST API reference pages (version 7.1) each is made as. That
organization-level REST APIs "accept either URL form" is
[work with organization URLs](https://learn.microsoft.com/en-us/azure/devops/extend/develop/work-with-urls)
(dated 2026-04-03); the throttling headers are
[rate and usage limits](https://learn.microsoft.com/en-us/azure/devops/integrate/concepts/rate-limits)
(dated 2025-09-15).

**What a read establishes.** A read's receipt establishes that the adapter
received these bytes from that organization's endpoint, under the TLS identity
the receipt names, for that query or listing, at that time, sent under the
credential the operator configured for the connection, acting with that
credential's scopes and its identity's permissions.

**What it does not establish.** That a work item is current or complete; that
the credential's scopes are what the operator intends; or that a call read
rather than wrote. The connection makes only the reads it names, each a `GET`
but the WIQL query, which the API takes as a `POST`; the query is sent as
given. What keeps this profile to reads is the credential: Microsoft's guidance
is to "Select only the scopes required for the intended tasks" and, where a
personal access token is used, to "use an organization-scoped PAT with the
minimum scopes and shortest practical lifetime" (use personal access tokens,
dated 2026-09-21). For this profile those scopes are Work Items (Read), Code
(Read) and Build (Read), `vso.work`, `vso.code` and `vso.build` in the
[scopes](https://learn.microsoft.com/en-us/azure/devops/integrate/get-started/authentication/oauth#available-scopes)
(dated 2025-07-14); an operator who wants reads only issues a token with read
scopes only. A query's results are "truncated at 20,000 items - no error is
shown" ([work tracking limits](https://learn.microsoft.com/en-us/azure/devops/organizations/settings/work/object-limits),
dated 2026-09-10): a query's answer says nothing of whether it is complete.
Global personal access tokens stop working on December 1, 2026, by the same
page on personal access tokens; a connection configured with one stops reading
then.

**The MCP profile.** A connection may also enable its organization's remote
MCP server (`mcp` in `configure`, the server `remote`), "a hosted version of
the Azure DevOps MCP Server" at `https://mcp.dev.azure.com/{organization}`,
reached "by using streamable HTTP transport"
([set up the remote Azure DevOps MCP Server](https://learn.microsoft.com/en-us/azure/devops/mcp-server/remote-mcp-server),
dated 2026-09-21), with the tools a read may call on it. The endpoint is built
from the configured organization URL. The credential is the connection's
access token (`auth` `bearer`): "Personal access tokens (PATs) aren't
supported for the remote server"
([troubleshoot the remote server](https://learn.microsoft.com/en-us/azure/devops/mcp-server/remote-mcp-server-troubleshooting),
dated 2026-07-31), and the pages document a user's token only, with delegated
permissions on the Azure DevOps MCP application; no page states that an
application-only token is taken, so the companion mints none. Each request
carries the server's read-only header, `X-MCP-Readonly: true`, unless the
operator turns it off for the server (`readOnlyHeader: "off"`). A read is one
tool call over Streamable HTTP, made by `adapter-sources`; the companion's
`test` lists the server's tools and calls none. The request, the bounds and
the refusals are in the
[adapters README](../../adapters/README.md#azure-devops-connections-mcp-profile).
The organization's local MCP server (the npm package `@azure-devops/mcp`) is
not a connection: the connections run no third-party server process, and the
README documents it as an operator-level source under `adapter-mcp`.

**What an MCP read establishes.** A read's receipt establishes that the
adapter received these bytes from that organization's MCP endpoint, under the
TLS identity the receipt names, for that tool and those arguments, at that
time, sent under the access token the operator configured for the connection,
acting with that token's scopes and its user's permissions.

**What it does not establish.** That the answer is true or current, or that
the tool read rather than wrote. The read-only header is the server's promise:
the page offers it "to restrict the server to read-only operations", and the
connection neither checks nor records what a tool did. Most tools are grouped
dispatchers whose `action` argument chooses the operation, and the page marks
each action read-only or not; the tools list holds tool names, so a tool on
it may be called with any action it takes, and the arguments are sent as
given. What keeps this profile to reads is the tools list and the token's
permissions: "Grant read scopes when the client uses only read-only MCP
tools", and "OAuth scopes don't override the permissions of the signed-in
user. An MCP operation succeeds only when both the application scope and the
user's Azure DevOps permissions allow it" (set up the remote server).

## Public URL sources (version 2)

Version 2 adds a separate `sources` list for explicit inputs without account
connections. The web descriptor and its bounds are defined in
[public web sources](public-web-sources.md). The provider dispatch allowlist is
unchanged. Version 1 clients must refuse this version rather than guess support.

## Research capabilities (version 4)

`gateway-connections --catalog-v4` writes catalog version 4
([ADR-0017](../adr/0017-adapters-declare-research-capabilities.md)). It is version 3 with two
members more, `adapter` and `capabilities`, on each provider's `source` and on each entry of `sources`; nothing
else changes, and `--catalog-v3` and `--catalog` write versions 3 and 2 as before, for the hosts
that hold their members closed. A provider's source in version 4:

```json
{"id": "web-search", "shape": "http", "record": "web-search-v1", "adapter": "adapter-sources", "capabilities": ["answer", "search"]}
```

`record` is the result contract and stays as version 3 has it. `adapter` is the program whose
answer the read is written against, as its receipts carry it in `adapter.name`: `drive` is
`adapter-drive`, `gmail` is `adapter-gmail`, `web` and `web-discovery` are `adapter-web`, and
`notion`, `web-search`, `databricks` and `azure-devops` are `adapter-sources`. It is the program a
published dialect's `record` names for an unbound source (judgment-pack-spec#184), so for a source
of the `airbyte`, `mcp` or `http` shape a desk copies `adapter`, never `record`, into the unbound
source's `record`. The two `command`-shaped sources, Obsidian and S3, carry no `adapter`: their
receipt is minted by the gateway's serve path with the configured command's `argv[0]`, and RFC 0018
admits an unbound operation only for those three shapes (§4.4, §4.1), so they are not bindable this
way. An empty or unknown program, or one named for a `command`-shaped source, refuses the catalog
by name.

`capabilities` is the research contracts the gateway declares for the adapter, from the
research capabilities of RFC 0018 (`spec/dialect.md` §§4.3, 4.4 and 5.1 in the specification
repository): an array of distinct names from the closed set `answer`, `search` and `page`, in
that order, written `[]` for an adapter the gateway declares none for. The names are the
specification's: `answer` is a model's generated
answer, `search` an answer of links to a query, `page` one page read and retained. The adapters
declare:

| Adapter (acquisition id) | `capabilities` |
|---|---|
| `web` (`adapter-web`) | `["page"]` |
| `web-search` (`adapter-sources --provider web-search`), as the provider's source and as an explicit source | `["answer", "search"]` |
| `web-discovery`, `drive`, `gmail`, `notion`, `obsidian`, `aws-s3`, `databricks`, `azure-devops` | `[]` |

`web-search` declares `answer` because a connection of a `grounded-answer` provider serves one;
a connection of a `search-results` provider does not. What one connection serves, and the model
it serves it from, is in its `status` row, as the `research` member
([configurable web search](../web-search.md#connection-protocol)): that member, not the adapter's
declaration, is what an input profile for the connection's endpoint declares. `web-discovery`
returns a site's navigation manifest, which is neither a search for a query nor a retained page,
and declares nothing. The catalog names no model: a model is a connection's configuration, and
the catalog is static.

**What `[]` means.** No research contract the gateway declares for that adapter; not that the
adapter serves none of these upstream. A research source cannot bind an adapter that declares
no capability it needs, whatever the adapter does upstream. Two kinds of adapter declare `[]`
for that reason:

- **Selected reads.** A page or file a person selected through a connection is a selected read,
  which the dialect reads under its `selected-file` kind (§4.2), not the public page read that
  `page` names: Notion's pages, which are retained with their text, URL and original bytes, and
  Drive's files, Gmail's messages, Obsidian's notes and S3's objects. These are excluded by name,
  not overlooked.
- **Unclassified MCP paths.** The MCP tools a Databricks connection enables (a Genie space, a
  Unity Gateway service such as `system.ai`'s web search) and the tools of the organization's
  remote Azure DevOps server return what the service returns, which may be a model's answer or a
  search, from a model the gateway does not know. The gateway does not classify them: no
  capability is granted to them, and no research source binds them until a declaration for them
  exists.

**What it establishes, and what it does not.** A declaration says what the distribution's
adapter is built to return, as its providers document it; no provider was called with an
account to establish it. The gateway checks no binding: an installation writes its input
profiles, their class among the rest, and a Runner holds a research source's binding to them
(RFC 0018 §4.4). A declaration grants no acquisition and does not establish that an answer is
true, that a model ran, or which one.

## Current owner taxonomy contract

[ADR0021](../adr/0021-owner-taxonomy-binds-current-tool-approval.md) specifies current
bindingVersion2, per-operation snapshotV2/engine11 approval, and opt-in CatalogV5.
Historical readers do not admit unclassified current tools. Metadata grants no authority;
existing acquisition, sealing and action checks remain required.

### Operation and effect of every capability and connection operation

Each capability and each connection operation declares an `operation` and an `effect` from the
taxonomy of judgment-pack-agent ADR-0027 (#324). `--catalog-v5` writes them, and where a program
checks a capability or an operation before serving it -- a capability's declaration, the broker's
methods, the Databricks and Azure DevOps selectors -- it reads the same declaration: there is no
second table.

**Research capabilities**, each source's `capabilityTaxonomies`. Each is acquired and answered
with a signed receipt, so each is `read-external`:

| Capability | `operation` | `effect` |
|---|---|---|
| `answer` | `answer` | `read-external` |
| `search` | `discover` | `read-external` |
| `page` | `read` | `read-external` |

The declaration is part of the closed set: a capability without a valid one is refused wherever a
capability is declared, so neither the catalog's `capabilities` for an adapter nor a connection's
`research` member names it, and no research source binds it. A source's dispatch selector that
serves a capability under its name (`web`'s `page`, `web-search`'s `answer` and `search`) takes the
capability's declaration.

**Reads and listings**, each source's `dispatchTaxonomies`: a selected read (`drive`, `gmail`,
`notion`, `obsidian`, `aws-s3`) and an Azure DevOps work item, item or pipeline run read are
`read`; a listing, a query or a catalog walk is `discover`; all `read-external`. A Databricks
`statement` is `act`, since SQL can write, and a connection's generic MCP dispatch is `run`/`act`,
since it can reach any tool its server enables. Databricks and Azure DevOps refuse a request whose
selector has no declaration.

**The broker's methods**, each provider's `operationTaxonomies` and `operationDeclarations`. The
method's own operation is one component; the operator-policy preamble every method enters, an
`act`, is the other, so every method's summary is an `act`. A method that changes a resource or a
configuration is an act on its own: `files-commit`, `configure`, `disconnect`, `select`,
`source-bind` and `source-revoke`; `connect`, `poll` and `cancel` are `run`/`act`; `files-prepare`
and `files-prepare-google-document` are `propose`; `search` and `files-list` are `discover` and
`files-read` and `source-observe` are `read`, all `read-external`; `test` is a `check` of kind
`test`, `read-external`; `status`, `files-status` and `source-bindings` are `read`/`read`. The
broker refuses a method without a declaration before it dispatches it. Document processing, a
provider the broker is opened as and the catalog does not list, answers `status`, `configure` and
`test` under the same declarations.

A test walks what these programs serve, not the catalog that describes them -- every capability,
every method of every provider the broker opens, every dispatch selector of every source -- and
names the first without both fields.

**Posture and presets.** The families are exposed here, as each provider's and source's
`profile` (the strongest effect and the operations it holds), and in the `_meta` of every tool
`gateway mcp` serves ([tool-descriptors.md](tool-descriptors.md#what-a-served-tool-carries-of-its-owner)).
`gateway posture` reports the host's isolation protections and reads no family. The permission
presets of #314, which give `review` the families `discover`, `read` and `check` and `work` those
and `propose` and `act`, are not built; when they are, they read the families from these two
places and no other.
