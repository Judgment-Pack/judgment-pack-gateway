# Drive connection validation

- Gateway core suite passed (81.459 seconds); conformance: 30 canonicalization and
  41 store vectors, zero disagreements.
- Full adapters suite passed. Connection and attachment race suites passed.
- Adapter module vet passed; new commands cross-compile for Windows (credential
  custody refuses use there) and Linux. Production custody supports Linux/macOS.
- Thirteen compiled safeguard mutations were all caught; evidence in mutations.json.
  Three first-pass survivors exposed weak tests for selected-file identity, early
  byte admission, and token scopes. Tests were strengthened and all thirteen rerun.
- OAuth consent, refresh, metadata and downloads use isolated fake Google TLS
  endpoints in tests; no user tokens/documents or real API requests.
- Live Google consent remains untested pending an application registration.

This is author validation, not the independent material-decision review required
by docs/adr/README.md. No review approval is implied by green tests.


Clean-room Codex review was explicitly authorized as a one-time same-vendor
exception while Claude is rate limited. Initial findings and dispositions:
https://github.com/Judgment-Pack/judgment-pack-gateway/pull/139#issuecomment-5735414718

All four findings are addressed in this correction: persisted callback epoch,
refresh outside the state lock with guarded commit, the declared extraction
deadline, and producer schema alignment. Independent G1/G2 reproduction tests
were adapted in `adapters/connections/lifecycle_test.go`; no reviewer-authored
implementation text was adopted. Deadline and actual-output schema regressions
were authored separately. The schema check uses a pinned test-only Python
validator; neither gateway module gains a runtime dependency. Corrected-head
verification is still required before this review is treated as complete.
