# Local research binding discovery

`adapter-sources --provider web-search --describe-research` describes the exact
configured search connection revision supplied on stdin:

```json
{"connection":"my-search","revision":"<current revision>"}
```

The operator supplies the same `--state-dir` and `--principal` as acquisition. The
mode is available only for `web-search`, never through an acquisition JSON member.
The host must launch the trusted installed adapter, whose executable digest is
verified separately. No network request, credential output, request charge or
acquisition receipt is produced. Reading custody takes its ordinary short lock;
opening an absent store may initialize its private storage as other adapter modes
do. This is installation metadata, not a permission grant or a portable artifact.

The description is version 2
([ADR-0019](../adr/0019-web-search-holds-its-arguments-to-one-table.md)). It has
version 1's members, each with the meaning it had, and three more:
`requestSchemaVersion`, `resultSchema` and `resultSchemaVersion`. Version 1, which
#281 wrote, had `version`, `shape`, `adapter`, `endpoint`, `research`,
`fixedArguments`, `requestSchema` and `resultRecord`, and was closed, so a reader
that holds it closed refuses version 2.

- `shape` is `http`; `adapter` is the same `{name, version, digest}` that the
  running executable places in acquisitions. A host must not substitute its own
  executable's identity or a release label.
- `endpoint` comes from the same construction as acquisition: Tavily's search
  endpoint or the configured Google project's regional/global model endpoint.
- `research` is the existing RFC0018 declaration from the valid connection.
- `fixedArguments` names the exact connection and revision. A host must retain
  these values and enforce them before dispatch; the model cannot change them.
- `requestSchema` describes the closed request object using JSON Schema 2020-12.
  It is generated from the table acquisition enforces (`searchArguments`), for the
  connection's provider: the arguments that provider takes, with the connection
  and its present revision as constants. A Tavily connection's adds the optional
  `includeDomains`, `excludeDomains` and `timeRange`; a Google connection's is
  version 1's, byte for byte. The query's description additionally states the
  adapter's 2,000 UTF-8-byte and no-control-character bounds, which a schema
  cannot state; a pattern means the same in ECMA-262 and RE2. The adapter enforces
  the same table, plus current connection, policy and allowance checks,
  independently of schema validation, and refuses any other member, and any
  argument the provider does not take, by name.
- `requestSchemaVersion` names the request schema: `tavily-request-1` or
  `google-grounding-request-1`.
- `resultRecord` is `web-search-v1`, the existing result contract. This command
  does not introduce a second result format or a new result-verification claim.
- `resultSchema` describes that result as a connection's acquisition writes it, in
  JSON Schema 2020-12: the provider's kind, the connection and revision as
  constants, and the bounds the adapter keeps each text, link and list to. A
  length is a bound in bytes of UTF-8 that a schema counts in characters, so the
  schema admits more than the adapter writes.
- `resultSchemaVersion` names it: `tavily-result-1` or `google-grounding-result-1`.

A change of what a schema says for a provider is a new version of it; a test holds
each version to the digest of the schema it named.

The host adds its Gateway authority/key, configured source ID and classification
when proposing a Runner input profile. Runner validates and registers the reviewed
profile through its existing boundary. Registration does not authorize acquisition.
Discovery remains available when a daily compute budget is exhausted; acquisition
still refuses at that budget. Changed, disabled, absent and invalid connections
are refused without exposing their credentials. A later configuration change makes
old request revisions unusable even if their immutable profile remains retained for
historical verification.

The command describes search only. A portable page profile currently pins one
exact endpoint; discovery does not supply a wildcard or permit rewriting receipt
endpoints. Multiple discovered page endpoints need the shared contract decision
tracked in Judgment-Pack/judgment-pack-spec#199. Request and result schemas for
the other adapters, and the single authoring boundary across two source
configurations, remain on #275.
