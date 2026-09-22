# Independent final S3 connector review

Date: 2026-09-22.
Reviewed commit: `67b8f86f4eb4e1aff83a30cb28bd7bace50cb89b`.
Base commit: `a986bef5ca9a52349938750ffc2e9e0086f7f108`.
Reviewer: a separately tasked OpenAI Codex agent. The reviewer did not edit production files. The checkout was clean and remained at the reviewed SHA when validation finished.

## Decision

**Approve the reviewed implementation within its documented scope. No unresolved actionable findings remain from this review.** The three findings from the initial independent review are fixed, with production regression coverage and successful reruns of the original independent reproductions.

This is **same-vendor independent review under the user's explicit exception**, not cross-vendor compliance with the ordinary regime in `docs/adr/README.md`. Both drafting and review used OpenAI Codex. The review covers the new public surface, documented claims, security decisions, and dependency changes; it does not confer specification conformance or live-provider acceptance.

The approval is for the scoped, read-only, explicit-credential S3 file source described by the implementation. **No live AWS account test was performed by this reviewer, and this report makes no live AWS acceptance claim.** The recorded synthetic upstream and unchanged-Desk evidence must retain that qualification.

## Scope and findings disposition

Read `CONTRIBUTING.md`, `docs/adr/README.md`, the S3 design, the implementation and its diff from the base, the test additions, the credential-store/grant helpers, catalog and executable dispatch, dependency declarations and notices, `docs/reviews/s3-file-source/dispositions.md`, `validation.md`, and the browser smoke reproduction materials.

- **S3-IR-1, path encoding — resolved.** The request now uses the pinned AWS Smithy encoder before SigV4 signing. Explicit expected paths cover reserved characters, Unicode, literal percent sequences, repeated slashes, and dot segments. The original independent AWS-encoder comparison passes.
- **S3-IR-2, long-key page admission — resolved.** Admission checks the actual serialized resource page with cursor overhead reserved. When only part of an upstream page fits, private `StartAfter` state resumes after the final emitted key. The committed test covers maximum-length HTML-escaped keys. The original independent long-key reproduction passes.
- **S3-IR-3, literal null versions — resolved.** Every nonempty selected version ID, including the literal `null`, is sent as `versionId`. Both the production regression test and the original independent reproduction pass.

The additional policy-epoch binding is effective: grants issued before disable/re-enable cannot revive. Existing post-fetch and post-processing generation checks remain in place. The larger S3-only source-input bound accommodates legal JSON-escaped keys while preserving the previous input bound for other providers. Display-name shortening preserves the exact bucket/key source identity.

## Independent validation

The reviewer ran the following successfully from `adapters/` with an isolated Go build cache:

```sh
go vet ./...
go test ./... -count=1
go test -race ./connections -run '^TestS3' -count=1
go mod verify
```

The changed S3 and source-dispatch Go files were clean under `gofmt -l`. The first socket-dependent test attempt was prevented by the sandbox's loopback-listener restriction; the full suite and S3 race suite subsequently passed with local sockets enabled. That environmental failure is not counted as a product failure.

The original three reviewer-only probes were rerun using a Go overlay and all passed. An additional reviewer-only probe constructed 75 ordered objects mixing maximum-length escaped keys and short keys, traversed both page-splitting and vendor continuation paths, verified that every expected ID appeared exactly once, refused replayed public cursors, confirmed eviction of selections older than the eight retained pages, and successfully read a retained final-page selection. It passed. These probes were kept outside the production tree.

The full adapter suite includes the repository's module-boundary tests. The reviewed diff makes no changes to the core signing implementation, `SPEC.md`, or frozen corpus. The author's core test/conformance results are recorded in `validation.md`; this reviewer did not duplicate that separate core run.

## Security and dependency assessment

No concrete new credential disclosure, cross-principal/provider scope escape, grant replay, or successful object substitution path was found. The reviewed controls include fixed HTTPS AWS origins, proxy and redirect refusal, explicit credentials without ambient discovery, bounded upstream/XML/object admission, private cursor custody, query/connection/epoch binding, conditional metadata checks, single-use grants, selected versions, and connection checks around extraction. Acquisition remains outside the signing module and feeds the existing retained `resource-v1` document producer.

The two newly declared modules are pinned: `github.com/aws/aws-sdk-go-v2 v1.47.0` and `github.com/aws/smithy-go v1.28.1`. `go mod verify` succeeded. The resolved binary dependency list contains the AWS credential types, signer and Smithy support packages, but no AWS default-configuration loader, credential-provider chain, IMDS client or full S3 service client. The new repository license/notice copies exactly match their pinned module files.

A check of upstream advisories found no actionable advisory for this linked use. The AWS EventStream advisory [GHSA-xmrv-pmrh-hhx2](https://github.com/aws/aws-sdk-go-v2/security/advisories/GHSA-xmrv-pmrh-hhx2) concerns separate EventStream/service packages that are absent from this dependency graph. The [Smithy maintainer advisory page](https://github.com/aws/smithy-go/security/advisories) lists no published advisories. This is a targeted dependency review, not a claim that all upstream code has been audited or that no vulnerability exists.

## Desk evidence and acceptance boundary

The committed smoke harness routes only the S3 transport to a local TLS fixture. Configuration, discovery, private custody, signing, conditional reads, extraction, gateway receipts, and Desk verification use the real implementation. The recorded assertions cover scope display, pagination, text and PDF receipt verification, retained draft/focus, no premature conversation, unchanged Desk executable bytes, and truthful disconnect. The inspected setup and verified-PDF screenshots are consistent with those assertions. The reviewer inspected the harness and recorded evidence but did not rerun the full browser session.

The recorded unchanged Desk SHA is `aad78841c463d40dd66121b0f1b95e4f51584da8`, with executable SHA256 `da5d53877ede64eae12174b586267cfe6d768e5f082ba9af20e22f88ea5f75f6`. That demonstrates the intended generic host integration as synthetic acceptance evidence. Actual IAM/KMS policies, provider responses and live AWS operation remain pending the explicitly documented account test. No new cloud resource, paid AWS operation, or model chat was required for this review.
