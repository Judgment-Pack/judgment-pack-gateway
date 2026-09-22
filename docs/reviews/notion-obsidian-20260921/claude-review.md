# Adversarial review: gateway #143, with dependent Desk #122

**Reviewer:** Claude Fable 5.1 (`claude-fable-5-1`), vendor **Anthropic**. No subagent or other
model took part in the review. A small summarising model inside the fetch tool read two public
documentation pages for me (see Limits); it judged nothing.
**Drafting vendor declared by the maintainer:** OpenAI. The vendors differ, as the regime requires.
**Reviewed SHAs:** gateway `5346eb6f158d035693c3205ad0f555d85d78d53f` (PR head, confirmed against
GitHub); Desk `06a7bcd75a78c564d8ad010f9016b09752c6eb5f`; candidate bundle manifest revision
`5346eb6f…`, all six binary hashes recomputed and matching.
**Date:** 2026-09-21. **Not merged; nothing posted.** Both checkouts were left byte-clean.

Model review substitutes for breadth; it is not decision authority. Each finding below needs a
written maintainer disposition on the gateway PR.

## Verdict

No blocker. I found no path that leaks a credential or vault path in ordinary operation, reads
outside the vault, reuses a grant, or gets a record past either verifier with the wrong identity.
The confinement, single-use and binding properties held under every probe I could build.

Three things should be fixed or explicitly accepted before merge: a canceled refresh can cost the
user the connection (G1), a dead client registration has no recovery path (G2), and the tests do
not protect most of the properties the PR says they cover (G7, D1) — which matters here because
the regime lets later fix-up commits land without a fresh review.

Severity: **MAJOR** = a claimed property is false, or a reachable failure has a lasting effect;
fix or accept in writing before merge. **MINOR** = real, bounded, fix when convenient.
**NOTE** = record and move on.

## Gateway findings (5346eb6)

### G1 · MAJOR · A refresh interrupted after the provider rotates loses the new token
`adapters/connections/notion_oauth.go:226-233` builds the refresh request on the caller's
context; the commit is at `:248-264`. If the caller goes away after Notion has rotated but before
the reply is stored, the stored refresh token is already retired.
**Repro:** `gateway-probes/review_probe_test.go`, `TestProbeCanceledRefreshLosesRotatedToken`.
Output: `after canceled refresh: err=provider-unavailable connected=true stored refresh="notion-private-refresh" provider now expects="rotated-refresh-1"`, then `next ordinary use: err=reconnect-required connected=false`. The control
(`TestProbeRotationControl`, eight workers, truly rotating provider) passes: one rotation, none refused.
**Reach:** the 45 s client timeout and 50 s/55 s deadlines; gateway shutdown; and Desk, which on
any aborted request closes the companion's stdin and SIGKILLs it after 2 s
(`internal/desk/connections.go:35`, `:120-121`). The pane aborts on Cancel, close, provider
switch and chat lock.
**Limit on this finding, against my own repro:** my fixture retires the old token at once.
Notion's client guide says a grant keeps the current and the immediately previous refresh token
valid, and that replay after "a brief grace period" is treated as theft and revokes the whole
grant. So an immediate retry probably recovers; a user who cancels and returns later probably
does not. The grace length is unpublished. The design's sentence "Other provider failures do not
erase an otherwise recoverable connection" does not survive this case.
**Suggest:** run the exchange and commit under `context.WithoutCancel` with its own short
deadline; have Desk not kill a companion mid-call.

### G2 · MAJOR · A dead client registration can never be replaced
`notion_oauth.go:244` treats `invalid_client` as terminal, but `:255-257` clears only the
connection. `broker.go:116-118` refuses `configure` for Notion and `:184-186` keeps `Client` on
disconnect, so `startNotion` (`:132-138`) reuses the dead `client_id` forever.
**Repro:** `TestProbeDeadClientRegistrationIsUnrecoverable` → `next sign-in uses client_id="notion-client", new registrations=0`.
The same missing reset makes a permanently occupied loopback port (chosen once at random,
persisted) unrecoverable. Recovery today means deleting `state.json` by hand. Whether Notion ever
expires registrations is undocumented. The design doc names only `invalid_grant` as terminal.
**Suggest:** when no connection exists, let `invalid_client` or an explicit reset drop
`Client`/`Redirect` and register again. That orphans no grant.

### G3 · MINOR · "Local disconnect takes effect immediately" is false for the broker
`broker.go:72-73` holds `b.mu` across the whole operation, provider I/O included, and
`cmd/gateway-connections/main.go:64-77` reads one request at a time.
**Repro:** `TestProbeDisconnectWaitsBehindSearch` → `disconnect still blocked after 750ms; credentials still on disk=true`; it completed only when the search was released. Bound is the
50 s operation deadline. The claim (design doc lines 49-50) is true of the state *file* lock and
of a separate adapter process, which is what the PR's own test exercises. Desk hides this by
disabling Disconnect while busy.

### G4 · MINOR · A bearer escaped in the inner JSON layer reaches the signed record
`mcphttp/client.go:283-289` checks the JSON-RPC message raw and with one layer of escapes
resolved. `connections/notion.go:280-283` then decodes the tool's text as JSON a second time, and
nothing checks the output.
**Repro:** `review_probe3_test.go`, `TestProbeCredentialEchoInsideNestedJSON` → plain echo
refused; inner-escaped echo: `err=<nil>, bearer present in record=true`. Needs the provider to
echo its own bearer that way, so likelihood is low; but "credential echoes (including JSON
escapes)" is a stated property. **Suggest:** check the final snapshot, title and URL.

### G5 · MINOR · Provider-reported truncation never reaches the structured fields
`notion.go:284-286` prepends a gateway-written sentence to the text. The record still says
`content.truncated=false`, `processing.status="complete"` (`review_probe4_test.go`). Desk's
partial-content consent reads those fields, so it does not fire; and the "retained original"
now contains words the provider never sent. Defensible reading: those fields describe
processing of the snapshot, not upstream completeness. Either way, say which in the design doc.
The `truncated` member itself is an unverified assumption about Notion's reply.

### G6 · MINOR · Obsidian links encode spaces as `+`; Obsidian specifies `%20`
`obsidian.go:100-102` uses `url.Values.Encode`. Bundled binary output:
`obsidian://open?file=Meeting+notes%2FQ3+plan&vault=vault`. Obsidian's URI page: "space characters
must be encoded as `%20`". Most note names contain spaces, and the URL is frozen into signed,
retained records. Both validators compare decoded values, so a producer-only fix is safe
(`+` → `%20`; a literal plus is already `%2B`). I could not run Obsidian to see whether it
tolerates `+`.

### G7 · MAJOR · The tests do not protect most of what the Verification section lists
I mutated each safeguard and ran the PR's suite (`mutate.py`, `mutate2.py`; green baseline first).
Survivors, excluding two I judged equivalent mutants:

| Safeguard removed | File | Why it survives |
| --- | --- | --- |
| issuer / endpoint pinning in AS metadata | `notion_oauth.go:61` | only the protected-resource document is ever falsified |
| S256 and `none` required | `:72` | no test |
| echoed redirect checked at registration | `:103` | no test |
| commit guard on a changed refresh token | `:252` | fixture never rotates |
| caller's `selectionContext` checked | `notion.go:106` | the only stale-context test is refused earlier, as not connected |
| foreign search-result URL filtered | `notion.go:212` | fixture's foreign result (`sources_test.go:112`) **shares the legitimate page ID**, so dedupe drops it; the test named for this cannot fail |
| disconnect during retrieval rechecked | `notion.go:298`, `obsidian.go:295` | no test, though the design states it |
| in-vault symlink component refused on read | `obsidian.go:73-76` | no test reads through a symlink |
| concurrent edit refused | `obsidian.go:92` | no test |
| entry cap, depth cap | `obsidian.go:210`, `:191` | no test |
| callback Host check, single-use flag | `broker.go:263`, `:279` | shared with Google; no test |
| `ValidConnectedSource`, version = document id | `attachment/check.go:829` | the one negative fixture also breaks the version, so identity is never isolated |

Killed, as they should be: foreign authorization server, cross-process lock, terminal
`invalid_grant`, resource audience, state comparison, grant removal/binding/expiry, hidden ids,
escaped credential echo, tool allowlist, redirects, response id, result-and-error, SSE event cap,
body bound, incomplete stream. `cmd/adapter-sources` has no test files.
**Every surviving guard works at this SHA** — I probed each directly (`review_probe2_test.go`:
stale context → `invalid-request`; straddled retrieval → `canceled`; 0 of 7 foreign results
admitted; five falsified metadata documents and three registration replies refused with no
foreign host contacted; rebinding Host → 400 without consuming the flow; depth 30 and 10,050
entries → `more=true`; ten tampered records refused). The defect is that a later commit can
delete any of them and stay green.

### G8 · MINOR · `select` grants any well-formed ID, not only search results
`notion.go:101-137`. **Repro:** `TestProbeSelectIsNotBoundToSearchResults`. The design's "Only
results with a matching Notion page ID and an approved Notion URL are selectable" is enforced by
Desk's UI, not the gateway. No model-reachable caller exists in Desk (I checked), so exposure is
low; correct the sentence or bind the grant to returned IDs.

### Notes
- **G9** `sources_test.go` lacks the `//go:build linux || darwin` tag its siblings carry, and uses
  `mustJSON` from a tagged file: `GOOS=windows go vet ./connections/` fails. CI's Windows leg
  builds only `go/`, so it stays green.
- **G10** `obsidian.go:291` computes a vault identity and statement that
  `source_document.go:57` returns before using. Obsidian records carry no vault identity beyond
  the folder's base name in the URL. Dead parameters, or a missing identity — decide which.
- **G11** `expires_in > 86400` is refused (`notion_oauth.go:245`, `provider.go:106`). Notion says
  about eight hours, "subject to change"; a longer lifetime would fail every sign-in. Clamp instead.
- **G12** The Notion account is labelled `"Notion"` (`broker.go:311`); the user cannot see which
  workspace is connected.
- **G13** The PR's declaration uses prose. The README requires
  `Material-decision impact: public-surface, documented-claim, security; review: <link>`. Classify
  whether a new attachment source kind is also `conformance`.

## Desk findings (06a7bcd)

### D1 · MAJOR · The consumer-side binding for connected sources has no discriminating test
`web/src/documents/client.ts:47, 54, 59, 68-69` and the ingest kind check at `:136`. All nine mutations
survived a green 217-test baseline (`mutate_desk.py`): resource binding, provider = receipt
source, retained-original match, source-kind, source-name allowlist, argument commitment over the
selection, Notion under `command`, several proofs at once, ingest kind. The fixtures
(`__fixtures__/*-snapshot.json`) are unsigned records with no receipt or proof, so
`docs/reviews/note-connections.md:32` ("Tests use … signed records") is not true of connected
sources.
**It works at this SHA.** I had the bundled gateway sign a real v3 acquisition of a synthetic note
with a synthetic key and ran Desk's `verifyDocument` on it (`desk-probes/review-probe.test.ts`,
`sign.py`): the control verifies, and all 13 tampered variants are refused — renamed note, swapped
grant, edited signed record, swapped retained original (both ways), relabelled source, dropped
proof, added Gmail proof, Drive selection, unsealed session, other signer. That harness could be
adopted as the missing test.

### D2 · MINOR · Notion/Obsidian errors collapse to "could not complete this request. Try again."
`web/src/connections/client.ts:17-26`. `wrong-account` (the account-change case),
`blocked-by-policy`, `authorization-in-progress`, `too-many-selections`, `file-too-large` and
`source-changed` all get the generic line; retrying cannot fix several of them.

### D3 · MINOR · No reconnect action after `reconnect-required`
`ConnectionsPane.tsx:101` only sets an error; status is cached 30 s (`client.ts:45`) and not
invalidated. After a 401 the gateway keeps the connection, so the pane shows "connected" with a
failing search and the only route is Disconnect, then Connect. The lifecycle table in
`docs/design/connections.md` promises a Reconnect action.

### Notes
- **D4** The Gmail pagination test mocks per-page contexts (`page-a`, `page-b`). The gateway's
  context is the store epoch (`gmail.go:201`), identical across pages; when it does differ the
  gateway refuses the older one. The grouping (`ConnectionsPane.tsx:108-117`) fails closed, but
  the comment and the design sentence describe behaviour the gateway does not have.
- **D5** Untested: closing the utility on route change; returning focus to the composer.
  Tested and killed: Assistant portal retention (drafts), account-change reset, abort on cancel.
- **D6** `docs/reviews/unified-connections/results.json` is self-reported booleans without the
  script that produced them; a reviewer cannot rerun it.

## What held
Discovery never contacts a non-Notion host and cannot redirect a credential (endpoints are
constants; discovery is a check, not a source). PKCE S256 with a 256-bit in-memory verifier;
callback is IPv4 loopback, Host-checked, state-checked in constant time, single use. Rotation is
serialized across processes. Disconnect during a refresh cannot restore tokens. MCP replies are
bounded in bytes, events and time; redirects refused; non-allowlisted tools uncallable. The vault
is confined: symlinked files and directories, an in-vault symlink to `.obsidian`, hidden files,
`.trash`, traversal, alternate-stream syntax and a FIFO were all refused; the vault was never
written; no absolute path appears in results or records. Grants: exactly one winner in 25
six-process races on one grant, refused on replay, wrong resource, other provider, after
disconnect, and through the signer. State is 0700/0600. No Google client ID or secret string is
embedded in any bundled binary, `jpack-desk` included; the source sentinel is `{}`. gofmt, vet
(linux, darwin) and the race detector on the three packages pass as the PR says.

## Limits of this review
- **No live Notion.** Unverified: discovery contents; registration accepting `scope: default` and
  a loopback redirect; the `resource` parameter; token reply shape on refresh; `scope` echo;
  rotation grace length; 202 for notifications; tool names; the shapes of
  `notion-get-tool-access`, `notion-search` (`query_type`, `results[]`, `has_more`) and
  `notion-fetch` (`title`, `url`, `text`, `truncated`). A wrong guess on most of these fails
  closed as `provider-unavailable`.
- Notion and Obsidian documentation was read through a summarising fetch tool; quotations are
  second-hand. Check them before relying on G1's grace-period caveat or G6.
- Obsidian itself not run. No browser driven. Windows not executed (vet only); macOS vet only.
- Code shared with Google (`broker.go` callback, `drive.go` grants) was probed only where this
  PR relies on it. Locales, styles and icons not reviewed.
- Probes are synthetic fixtures I wrote; a fixture can be wrong in the provider's favour or
  against it, as G1 shows.
