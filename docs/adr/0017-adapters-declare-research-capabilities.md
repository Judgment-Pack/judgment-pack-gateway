---
status: accepted, 2026-10-17
date: 2026-10-15
deciders: maintainer
---

# Each adapter the connection catalog describes declares the research capabilities it can serve, in catalog version 4, and a search connection's status names what it serves and its model; the set is RFC 0018's, the gateway declares and the Runner checks

Issue #275. This record states the design the pull request for #275 builds; the maintainer
accepts or amends it.

**Checked against** gateway `main` at `264b330`, and the specification at `00c21b5`
(`spec/dialect.md` §§4.3, 4.4 and 5.1, RFC 0018 as its round 8 extended it).

## Context and problem statement

**What the specification asks.** A published `research` source names a `model` and the
`capabilities` it needs, from the closed set `answer`, `search` and `page`, in that order, with
`answer` required. An installation binds it at import to an AI profile for `answer` and to web
profiles for the others, all of class `generated`. A profile may declare `research`, a closed
object of `capabilities` and, exactly when they include `answer`, `model`. A bound profile whose
model is not the source's, or that lacks a capability it is bound for, is `profile-mismatch`
(§4.4, §5.1). The profile is the installation's and the Runner holds a binding to it
(judgment-pack-runner#88). The gateway is the channel that the profile classifies.

**What the gateway described.** Catalog version 3 (`gateway-connections --catalog-v3`) describes
each provider's source as `{id, shape, record}` and each explicit source as
`{id, input, mediaTypes, maxBytes}`. Nothing said which adapter reads a page, which answers a
search, or which carries a model's answer. An installation writing a profile's declaration had
only provider names to go by.

**What the gateway has.** `adapter-web` reads one public page (`web`). `adapter-sources
--provider web-search` (`web-search`) has two providers: Tavily, of kind `search-results`, gives
links and no generated answer; Google Cloud Search grounding, of kind `grounded-answer`, gives a
Gemini model's generated answer with the links it was grounded in, the model chosen per
connection ([web-search.md](../web-search.md)). `adapter-web --discover` (`web-discovery`) returns
one site's navigation manifest: it is not a search for a query and does not retain a page. The
connections read pages and files a person selected (Notion's pages, retained with their text, URL
and original bytes; Drive's files; Gmail's messages; Obsidian's notes; S3's objects). The MCP
tools a Databricks or Azure DevOps connection enables (a Genie space, a Unity Gateway service such
as `system.ai`'s web search, the organization's remote server) return what the service returns,
which may be a model's answer or a search, from a model the gateway does not know. The bindings in
`catalog/*.json` bind operations (`history`, `live`, `write`), and none is declared a research
capability.

## Decision drivers

- The names, their order and their meaning are RFC 0018's. The gateway adds no name.
- The Desk refuses a version 3 source contract with any member besides `id`, `shape` and
  `record`. Every Desk release pinned today must read version 3 as before.
- The catalog is static discovery: no account, no connection and no model a person chose.
- What the gateway says a channel serves is a declaration. The gateway checks no binding. This
  record changes no acquisition, receipt, policy or write-back.

## Considered options

- **A. A member on version 3's source contract.** Declined: the Desk's reader refuses it, so every
  pinned Desk would stop reading the catalog.
- **B. Catalog version 4, and the connection's declaration in status.** Chosen.
- **C. The model in the catalog.** Declined: a model is a connection's configuration, and a
  static catalog that named one would name an installation's choice.
- **D. A report of its own, as `--source-capabilities` is.** Declined: that report carries the
  operator's configuration of the web source (its redirect policies). What an adapter can serve
  belongs to the distribution, as its shape and record do, so it is written beside them.

## Decision outcome

Chosen: B. The capabilities stand where the shape and the record stand, in a new catalog version
that no closed reader of version 3 is given. The model stands beside the capabilities where the
gateway knows it: in the configured connection.

### 1. Catalog version 4

`gateway-connections --catalog-v4` writes version 4. It is version 3 with one member more:
`capabilities` on each provider's `source` and on each entry of `sources`. Nothing else changes.
The member is always written, `[]` for an adapter the gateway declares no research contract
for. `--catalog-v3` and `--catalog` write versions 3 and 2 unchanged, byte for byte.

| Adapter (acquisition id) | `capabilities` |
| --- | --- |
| `web` | `["page"]` |
| `web-search`, as the provider's source and as an explicit source | `["answer", "search"]` |
| `web-discovery`, `drive`, `gmail`, `notion`, `obsidian`, `aws-s3`, `databricks`, `azure-devops` | `[]` |

An adapter's declaration is what it can serve. `web-search` declares `answer` because a
grounded-answer connection serves one, and a Tavily connection does not. The declaration a
profile carries is its channel's, which section 3 gives.

`[]` means no research contract the gateway declares for that adapter. It does not mean the
adapter serves none of these upstream. A research source cannot bind an adapter that declares no
capability it needs, whatever the adapter does upstream. Two kinds of adapter declare `[]` so:

- **Selected reads, excluded by name.** A page or file a person selected through a connection
  (Notion's pages, and any other selected read: Drive, Gmail, Obsidian, S3) is read under the
  dialect's `selected-file` kind (§4.2), not as the public page read that `page` names.
- **Unclassified MCP paths.** The Databricks and Azure DevOps connections' MCP tools may carry a
  model's answer or a search. The gateway does not classify them. No capability is granted to them
  now, and no research source binds them until a declaration for them exists. A remote tool is not
  given `answer` for carrying a model's text.

**The program beside the record.** Version 4 also writes `adapter` on each provider's `source` and
on each entry of `sources` whose shape is `airbyte`, `mcp` or `http`: the program whose answer the
read is written against, as its receipts carry it in `adapter.name`. `drive` is `adapter-drive`,
`gmail` is `adapter-gmail`, `web` and `web-discovery` are `adapter-web`, and `notion`, `web-search`,
`databricks` and `azure-devops` are `adapter-sources`; each name is the one the adapter's code sets
where it mints the receipt. `record` stays the result contract (`web-search-v1`), for the
catalog's own purposes. Judgment-pack-spec#184 decided that an unbound source's `record` in a
published dialect is the program's name, matched against the profile's `adapter.name` at import
and against the receipt's by a verifier, so a desk that writes a dialect from the catalog copies
`adapter`, never `record`, into an unbound source's `record`: a dialect written by copying
`record` is refused `profile-mismatch`.

The two `command`-shaped sources, Obsidian and S3, carry no `adapter`. Their acquisition receipt
is minted by the gateway's serve path with the configured command's `argv[0]`, not with a program
name of the catalog's, and RFC 0018 admits an unbound operation only for the `airbyte`, `mcp` and
`http` shapes (§4.4; a command profile serves no operation, §4.1). They are not bindable this way,
so there is no program to name. An empty program, one the gateway mints no receipts for, or a
program named for a `command`-shaped source, is refused by name when the catalog is made. Versions
3 and 2 are unchanged, byte for byte.

### 2. The closed set

Each declaration is held to the set: each name is one of `answer`, `search` and `page`, none is
given twice, and they come in that order. A name outside the set is refused by name. A catalog
holding such a declaration is the distribution's error, and the catalog is not made. The tests
hold every declaration.

### 3. A search connection's declaration, in status

Each connection row of web-search `status` gains `research`, §5.1's form exactly: a Tavily
connection `{"capabilities": ["search"]}`, and a Google grounding connection
`{"capabilities": ["answer", "search"], "model": "<the connection's model>"}`. The declaration is
computed from the provider and the stored model, never stored and never taken from a caller.
`configure` refuses the member as an unknown one, as it did before. Only a connection acquisition
admits declares anything: one acquisition refuses as `setup-required` (a Tavily connection with a
stored model, a Google one whose model is not well-formed, a stored timeout or credential
`configure` would refuse) declares nothing. Status stays version 1. The member is additive,
as `timeout` was, and the Desk's reader of status does not hold rows closed.

The model is pinned where the receipt is. A grounded answer's acquisition endpoint is
`https://{host}/v1/projects/{project}/locations/{location}/publishers/google/models/{model}:generateContent`.
A profile pins the endpoint, and §5.2's check 3 holds each receipt to it. So a profile whose
endpoint is a connection's serves that connection's model, and its declaration names that model.
A Tavily connection's endpoint is `https://api.tavily.com/search`.

### 4. Who checks

The gateway declares. The installation writes the profile, its class among the rest. The Runner
compares a binding with the profiles it trusts (§4.4, judgment-pack-runner#88). The gateway
reads no profile and no dialect.

### Consequences

- Good, because an installation copies a connection's `research` into the profile it writes for
  that connection's endpoint, and versions 2 and 3 are unchanged for the hosts that read them.
- Bad, because the declaration is in two places. The adapter's, in the catalog, is what it can
  serve. The connection's, in status, is what it serves, with the model. A profile copied from
  the adapter's declaration would claim `answer` for a Tavily connection.
- Bad, because `web-discovery` declares nothing, so a research source cannot bind website
  exploration as `search`.
- Bad, because the declarations repeat the providers' documentation and were not observed. No
  provider was called with an account ([web-search.md](../web-search.md), "What was tested").
- Bad, because the MCP paths that may already carry a model's answer or a search (Databricks'
  and Azure DevOps' enabled tools) are unclassified: a research source cannot bind them, though
  they may serve what it needs.
- Revisit when a declaration for those MCP paths is designed, when one of the search integrations
  of #233 to #237 ships, when the dialect's `selected-file` kind is to be bound by research, when
  RFC 0018 changes the set, or when the Runner's check reads declarations from somewhere else.

## More information

[connection-catalog.md](../design/connection-catalog.md), "Research capabilities (version 4)";
[web-search.md](../web-search.md), "Connection protocol"; `adapters/connections/catalog_v4.go`.
