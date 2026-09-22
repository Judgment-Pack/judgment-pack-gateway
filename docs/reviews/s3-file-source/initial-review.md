# Independent initial S3 review — 2026-09-22

Reviewed the working draft in `/tmp/jp-s3-gateway-20260922`, based on commit `a986bef5ca9a52349938750ffc2e9e0086f7f108`; production files were not edited by this reviewer. This is a user-authorized Codex same-vendor independent review, not the cross-vendor review ordinarily required by `docs/adr/README.md`. Read `CONTRIBUTING.md` and `docs/adr/README.md`. The implementation and test work are ongoing; this report is not an exact-head approval.

Scope: `docs/design/s3-file-source.md`, `adapters/connections/s3.go`, `s3_network.go`, custody/grant helpers, catalog and executable dispatch changes. Focus: actual protocol behavior and security boundaries, without treating deferred broader integrations machinery as a reason to halt the first connector.

## Findings

### S3-IR-1 — P2: AWS canonical path encoding is incomplete

Location: `adapters/connections/s3_network.go:26` and `:44`.

`s3URL` uses Go `url.PathEscape` and the signer sets `DisableURIPathEscaping=true`. Go leaves `+`, `:`, `@`, `=`, `$`, and `&` unescaped in path segments. AWS requires percent encoding these characters before S3 signing; disabling signer escaping makes the unescaped result the canonical URI. A real object named `folder/a+b.txt`, for example, is requested/signed as `/review-bucket/folder/a+b.txt` instead of `/review-bucket/folder/a%2Bb.txt`. Listing uses query encoding and can succeed, but selection/read can fail authentication for these ordinary legal key names.

Reproduction: `TestIndependentS3PathMatchesAWS` compares `s3URL(...).EscapedPath()` directly to the pinned AWS Smithy `httpbinding.EscapePath(..., false)` implementation. Six cases fail; spaces, literal percent escapes, repeated slashes and dot segments serve as passing controls. This is a local protocol/encoder reproduction, not a live AWS claim.

Use AWS-compatible path encoding before signing; preserve exact slash and dot-segment bytes and avoid introducing double encoding. The pinned Smithy package already exports the appropriate encoder. Add a test whose expectation comes from AWS encoding, not from the current `url.PathEscape` output.

Sources: [AWS S3 signing URI encoding rules](https://docs.aws.amazon.com/AmazonS3/latest/developerguide/sigv4-query-string-auth.html); local pinned SDK `github.com/aws/smithy-go@v1.28.1/encoding/httpbinding/path_replace.go:82`, and `github.com/aws/aws-sdk-go-v2@v1.47.0/aws/signer/v4/v4.go:187`.

### S3-IR-2 — P2: Valid long-key pages cannot be browsed

Location: `adapters/connections/s3.go:113`, `:282-287`.

A permitted upstream response containing 24 valid 1024-byte keys is under the upstream bound but exceeds `ResourcePageBytes` because every full key is serialized twice (ID and title). The search returns `response-too-large` without exposing any items or a usable continuation cursor. Users cannot proceed past the offending page even though every object is within the advertised key/object limits. JSON escaping can amplify this further: keys containing `<`, `>`, or `&` cost six bytes per such byte under Go's default JSON encoding, so simply adjusting 24 to a moderately smaller count does not establish a worst-case fit.

Reproduction: `TestIndependentS3LongKeyPage` configures a broker with a fake transport, returns a compliant one-object configuration check, then a compliant 24-object list containing distinct 1024-byte ASCII keys and 1-byte text objects. `Handle("search")` returns `response-too-large`.

Keep the 48 KiB public limit. Make upstream paging fit the worst-case serialized response, or split a bounded upstream page into private/public pages while preserving selection and cursor binding. This is availability/usability, not a memory-bound bypass.

### S3-IR-3 — P2: Literal `null` versions are not actually pinned

Location: `adapters/connections/s3_network.go:207`.

`s3Get` emits `versionId` only when the selected version is nonempty and not the string `null`. In S3, `null` is a real version identifier for objects uploaded before versioning or while versioning is suspended. For example, select an existing `null` version in a versioning-enabled bucket, then upload a newer version. The selected `null` object remains retrievable, but the connector requests the new current object instead and rejects it as `source-changed`. The same selected-version guarantee works for ordinary version IDs and should work for `null`.

Reproduction: `TestIndependentS3NullVersionRemainsSelected` models the old `null` version remaining available and a new current version. The fixture returns the selected version only for `?versionId=null`. `s3Get` omits the parameter and returns `source-changed`.

Forward every nonempty selected VersionId, including the literal `null`. The final version/ETag/length comparison already fails closed, so this issue does not cause successful substitution of newer bytes.

Sources: [S3 objects retain null versions when versioning is enabled](https://docs.aws.amazon.com/AmazonS3/latest/userguide/manage-objects-versioned-bucket.html), [S3 GetObject version selection](https://docs.aws.amazon.com/AmazonS3/latest/API/API_GetObject.html).

## Reproduction artifacts

Independent tests live outside the production tree:

- `/tmp/jp-s3-review-probes/probe_test.go`
- `/tmp/jp-s3-review-probes/overlay.json`

Command, run from `/tmp/jp-s3-gateway-20260922/adapters`:

```sh
GOCACHE=/tmp/jp-s3-review-go-cache go test -overlay /tmp/jp-s3-review-probes/overlay.json ./connections -run '^TestIndependentS3' -count=1 -v
```

All three named tests fail against the initial draft for the reasons above. They are external review probes, not proposed production tests. The overlay adds only a virtual test file.

## Boundaries assessed and remaining evidence

The draft has fixed HTTPS AWS origins, no arbitrary endpoint or credential discovery path, no proxy or redirect following, bounded response reads, private opaque cursor custody, query/connection/epoch binding for browse state, single-use grant consumption, and post-fetch/post-processing connection checks. The credential-bearing state and S3 namespace use the existing private no-follow store implementation. Public source identity uses provider + bucket/key and body digest, without AWS request headers or credentials. I found no concrete new secret exfiltration, scope escape, or successful byte-substitution path in this initial review.

Catalog-v3 and generic `resource-v1` dispatch appear architecturally consistent with the unchanged Desk approach. The parent is completing localization, executable tests, and actual Desk browser evidence. Distribution notices must accompany the new AWS/Smithy dependencies; this report does not claim that unfinished delivery work is complete. Live AWS acceptance is explicitly pending and must remain labeled as such. A fresh exact-head review should verify dispositions and the final tests/documentation.
