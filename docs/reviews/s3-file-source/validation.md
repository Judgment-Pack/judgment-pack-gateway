# S3 validation — 2026-09-22

Base gateway: a986bef5ca9a52349938750ffc2e9e0086f7f108.
Unchanged Desk: aad78841c463d40dd66121b0f1b95e4f51584da8.
Runtime: d891b056133fea952ceb2c39e38a2ee16fee24ee.

- Adapter `go vet ./...` and full `go test ./...`: pass.
- Core `go vet ./...`, `go test ./...` and `go run . conform`: pass,
  30 canonicalization vectors + 41 store vectors, zero disagreements.
- S3 connection tests with `-race`: pass.
- The three independent initial-review reproductions: pass after fixes.
- Unchanged-Desk browser smoke: pass. Discovery, explicit credential form,
  scope display, pagination, signed text/PDF attachments, verified preview,
  retained draft/focus, no premature chat creation, truthful disconnect.
  No browser errors. Evidence is in `desk-findings.json` and the PNGs beside it.
- Desk executable SHA256 before/after the smoke:
  da5d53877ede64eae12174b586267cfe6d768e5f082ba9af20e22f88ea5f75f6.
- Reproduction: `testdata/s3-desk/README.md`; only the test transport routes to
  synthetic S3. The new gateway implementation and signing pipeline are real.

The S3 tests cover escaping/signature verification, scoped cursor/page binding,
serialized page sizing, conditional reads and null versions, malformed responses,
expired credentials/grants, unsupported/oversized sources, IAM/provider errors,
secret exclusion, disconnect races, policy epochs and ambient-credential refusal.
The source request admission is 16 KiB for S3 to fit worst-case JSON escaping of
legal keys; the existing other providers retain their 4 KiB input bound.

No live AWS account test or paid resource/API use has been performed. Real AWS
acceptance remains pending, including actual IAM/KMS policy and vendor behavior.
This work adds file sources only. It does not implement Spaces/Azure/Dropbox or
change chat/pack storage, gateway SPEC.md, receipts or the frozen corpus.
