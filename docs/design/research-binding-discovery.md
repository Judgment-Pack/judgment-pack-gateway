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

The closed version-1 description has `version`, `shape`, `adapter`, `endpoint`,
`research`, `fixedArguments`, `requestSchema` and `resultRecord`:

- `shape` is `http`; `adapter` is the same `{name, version, digest}` that the
  running executable places in acquisitions. A host must not substitute its own
  executable's identity or a release label.
- `endpoint` comes from the same construction as acquisition: Tavily's search
  endpoint or the configured Google project's regional/global model endpoint.
- `research` is the existing RFC0018 declaration from the valid connection.
- `fixedArguments` names the exact connection and revision. A host must retain
  these values and enforce them before dispatch; the model cannot change them.
- `requestSchema` describes the closed request object using JSON Schema2020-12.
  The query's description additionally states the adapter's 2,000 UTF-8-byte and
  no-control-character bounds. The adapter enforces them, plus current connection,
  policy and allowance checks, independently of schema validation. Unsupported
  domain, freshness, endpoint, header and other request members are refused.
- `resultRecord` is `web-search-v1`, the existing result contract. This command
  does not introduce a second result format or a new result-verification claim.

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
tracked in Judgment-Pack/judgment-pack-spec#199. Broader capability request/result
schema discovery remains on #275.
