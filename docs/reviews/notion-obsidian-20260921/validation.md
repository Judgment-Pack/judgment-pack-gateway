# Review remediation validation

Synthetic tests only. No live provider acceptance is claimed.

## Mutation checks

The gateway regressions killed all 16 compiling mutations exercised for the
reviewed gaps: discovery endpoints, PKCE/auth method, DCR echo, refresh commit,
callback Host/single use, selection epoch, foreign result URL, disconnect during
both kinds of read, in-vault symlink components, concurrent file edit, entry/depth
bounds, connected identity and snapshot version. The first concurrent-edit mutation
left an unused variable and did not compile; a corrected compiling mutation was
then killed by `TestVaultReadRejectsAnOverlappingEdit`. Build failures do not count.

Desk tests kill mutations removing resource binding, provider binding, retained
original matching, record-kind checks, connected argument commitments, Notion MCP
shape and ingestion-before-save kind checking. Existing/extended record tests also
cover identity and version binding.

Two single-guard removals remain redundant, and are retained as defense in depth:
- The explicit source-name allowlist: `readDocumentRecord` already restricts
  connected providers to Notion/Obsidian, and verification requires provider to
  equal the signed source. Removing only the allowlist admits no extra source.
- The early multiple-proof check: each present proof must independently match
  the same record's source kind; Drive, Gmail and connected kinds are mutually
  exclusive. Removing only the early check still refuses multiple proofs later.

The tests include those refusals, but do not misrepresent redundancy as an
independently discriminating test or weaken other checks to make a mutation fail.

## Checks

Gateway implementation candidate: `ff291e9` (the subsequent validation-only commit
does not alter its code).

- Required gateway core tests and vet passed; frozen corpus: 30 canonicalization
  vectors and 41 store vectors, zero disagreements.
- Required adapter tests and vet passed; Windows cross-vet passed.
- Desk backend tests and vet passed, including the 2.3-second synthetic companion
  commit that the former 2-second cancellation kill would interrupt.
- Desk focused suite: 226 tests passed. Full suite: 3,783 passed, one skipped,
  with two bundle assertions failing because the fresh clone had no dist yet;
  all three bundle assertions passed after the production build. Additional
  source-version tests passed. Typecheck and production build passed.
- All 926 mutation needles match; needle-script tests (7) and bundle-script tests
  (3) passed. All 12 locales have complete copy; no placeholder errors.
- Browser evidence is recorded in Desk's `docs/reviews/notion-review-recovery/`.

 The optional full
adapter race run encountered timing assertions in unchanged Airbyte/PDF/MCP process packages;
changed connection, attachment and source-command packages passed under `-race`.
