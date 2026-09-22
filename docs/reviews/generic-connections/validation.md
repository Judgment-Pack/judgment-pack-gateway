# Foundation follow-up validation

Implementation evidence, OpenAI Codex, 2026-09-22. This is not the independent
material-decision review. See the cloud-review-foundation-response design note
for the disposition of the earlier roadmap review.

- Full adapters suite and vet pass. Focused connections/CLI race tests pass.
  Windows adapter vet passes after limiting the local custody test to Linux/macOS;
  this does not claim working Windows custody.
- The shared resource producer extracts an actual generated PDF text layer without
  OCR, passes attachment.Check and the published document schema. CI executes
  the PDF producer/schema check in addition to the text record check.
- Desk independently verifies a signed PDF resource fixture with this record.
- Oversize control replies return a bounded error without a partial result.
  Resource pages test count, byte, cursor, duplicate, URL, metadata and size bounds.
  Local disconnect never defaults to successful provider revocation.

## Focused semantic mutation evidence

Run mutations.py with the complete gateway and Desk working trees and a JSON
output path. It creates temporary copies, checks both unmodified baselines, then
applies one recorded replacement at a time and executes the focused tests.
No real accounts, credentials or model API calls are used. See the JSON records
for the exact replacements and commands.

The initial run killed 10 of 11 mutants. Disabling the resource page item-count
check survived: that test generated control characters in some item identifiers,
so another guard rejected the oversized page. The test now uses valid decimal
identifiers to isolate the count boundary. The final run killed all 11 mutants;
there were no invalid/compile-only mutants. Both records are retained.

These results cover only the listed guards. The older Desk mutation needle rows
are separate evidence and are not presented as coverage of the new resource
contract. Production provider authentication, retrieval/version consistency,
server behavior and paid/live acceptance are outside these synthetic checks.
