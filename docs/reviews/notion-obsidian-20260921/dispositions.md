# Dispositions of the Notion/Obsidian review

The maintainer supplied the [independent review](claude-review.md). Its stated
reviewer is Claude Fable 5.1 (`claude-fable-5-1`, Anthropic); drafting was OpenAI.
Reviewed gateway: `5346eb6f158d035693c3205ad0f555d85d78d53f` (#143).
Reviewed Desk: `06a7bcd75a78c564d8ad010f9016b09752c6eb5f` (#122).
Codex prepared these dispositions and fixes in response. The reviewer identity is
recorded as supplied; this is not a claim of a new independent review. The record
covers these parents only, not catalog #144/#123 or public-web #148/#124.

## Gateway

| Finding | Disposition and evidence |
| --- | --- |
| G1 | Fixed for ordinary cancellation: refresh reserves 20 seconds, detaches only the started token exchange for 15 seconds, and atomically commits under the existing generation/refresh checks. Desk drains the in-flight companion response before stopping it. Strict rotating-provider cancellation/control tests and a Desk process test cover the former loss. Forced termination, network response loss and storage failure remain reconnect cases; no crash-proof distributed transaction is claimed. |
| G2 | Fixed: `invalid_client` on refresh or initial exchange clears registration/redirect with generation checks. A disconnected registration with an occupied callback port is replaced on the next connect. A live grant is not silently orphaned: disconnect first. Tests cover HTTP 400/401, initial consent and port replacement. |
| G3 | Corrected claim; retain serial broker control. Same-companion disconnect waits behind the operation's 50-second deadline. Separate-process custody changes still invalidate in-flight results. This bounded behavior avoids a new concurrent RPC protocol; it is no longer described as immediate. |
| G4 | Fixed: decoded fetch text, title and accepted page URL, and decoded search labels/URLs, are checked against the actual bearer used for that MCP session. Nested-JSON tests cover all fetch fields. Refusal returns no token or record. |
| G5 | Fixed conservatively: refuse provider-declared truncation with `source-incomplete`, an actionable Desk message, and no signed attachment. Do not alter retained source bytes or mislabel extraction status. Upstream partial-source metadata/consent is deferred to a separate contract extension. |
| G6 | Fixed producer encoding to `%20`; literal plus remains `%2B`. Existing consumers continue to decode earlier query encodings. Official Obsidian documentation was checked directly. |
| G7 | Adopted reviewer probes as permanent, attributed regressions; strengthened direct metadata/DCR assertions, callback single use, refresh commit race, in-vault symlink reads, overlapping edits, disconnect during reads, independent identity/version checks and traversal bounds. Added adapter-sources subprocess coverage. Mutation evidence is recorded with validation results; compile failures are not counted as caught mutations. |
| G8 | Accepted bounded local-caller authority; corrected the overstated search-only claim. `select` accepts a well-formed ID from the authenticated local caller within the current connection epoch. Grants remain single-use and resource-bound; Desk exposes only displayed results and no model tool can call this RPC. Persisting a search-result allowlist would add a separate authority model and is not part of this fix. |
| G9 | Fixed the Unix build tags on source tests and new private-store probes. Cross-vet Windows adapters to catch this class of compile regression. This does not claim Windows private-store execution. |
| G10 | Removed the discarded Obsidian acquisition statement/endpoint. Documented that the saved link uses a nonunique vault name, while custody uses private vault identity. The receipt attests bytes and the selected note, not globally unique vault identity. A new attested identity field is deferred. |
| G11 | Fixed: accept positive Notion token lifetimes and clamp the cache to 24 hours before duration conversion. Test uses the maximum int64 to cover overflow. Google behavior is unchanged. |
| G12 | Accepted current display limitation: Notion returns user/workspace IDs, used for custody and wrong-account checks, but the reviewed client has no verified workspace display name. Do not invent one or add an unreviewed identity lookup. The design now states that the Notion label is not a verified workspace name. |
| G13 | Use the required material-decision declaration and link this review record from #143. Categories remain public-surface, documented-claim, security. `SPEC.md`, canonicalization, signing, frozen corpus and normative receipt verification are unchanged; the attachment application variant is separate. |

## Desk

| Finding | Disposition and evidence |
| --- | --- |
| D1 | Added genuinely signed synthetic Notion and Obsidian v3 receipts, argument commitments and seals. Invalid cases are signed after changing the semantic relationship, so a signature failure cannot mask the intended binding test. Also test rejection before attachment persistence during ingestion. Redundant guards are reported separately in mutation results. |
| D2 | Added actionable error messages for wrong account, policy restriction, active sign-in, too many selections, size, changed source, incomplete source and dead registration. All added copy is translated in the 12 supported locales; UI translates canonical errors when rendering. |
| D3 | Preserve typed connection error codes through search and acquisition. Reconnect errors clear stale selections, invalidate status and expose an explicit Reconnect action. No background OAuth or automatic popup. |
| D4 | Corrected Gmail tests/comments: context is a connection epoch, shared across pages. An epoch change clears prior selections. Tests cover both cases. |
| D5 | Preserve and rerun the reproducible browser smoke for focus restoration/draft retention, adding route-change closure. This complements component tests; browser evidence is synthetic. |
| D6 | Commit the browser script with configurable bundle/runtime/project/browser paths and its invocation alongside results. Earlier screenshots/booleans are retained as historical evidence, not a substitute for the script. |

## Provenance and limitations

Gateway `review_*_test.go` fixtures adapt the reviewer-supplied probes under these
accepted findings; the recovery and deterministic race cases were written by Codex.
The original probes, mutation drivers and report are preserved at
`/tmp/jpack-handoff/review-notion-claude-20260921`.

Primary sources checked directly during remediation:
- https://developers.notion.com/guides/mcp/build-mcp-client (rotation, bounded previous-token tolerance, registration reuse).
- https://obsidian.md/help/uri (percent encoding).

No live Notion account, provider content, real vault, paid model call, Obsidian app
launch or Windows execution is used. Protocol fixtures do not establish live
provider compatibility. Independent review of later material features is still
required. None of these dispositions authorizes publishing credentials or bundling
a publisher Google registration.
