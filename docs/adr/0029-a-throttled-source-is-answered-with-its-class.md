---
status: proposed
date: 2026-11-13
deciders: maintainer
---

# A throttled http source is answered with its class and a bounded Retry-After; paging is the caller's

## Context and problem statement

When the endpoint behind an http source answers an acquisition with 429 or 503, `/acquire`
answers `400` with `source failed: …` and the start of what the adapter wrote on stderr (issue
#425). The endpoint's class and its `Retry-After` do not reach the caller, so a caller that
retries on throttling cannot tell a throttled source from any other failed source. The ask is
that `/acquire` answer with that class and pass on a well-formed `Retry-After`, bounded, with no
receipt, and every other failure unchanged.

The adapter protocol (SPEC.md §6, "Adapter sources") says a refusal by an exit status other than
0 and a line on stderr. The gateway reads the status only for a token step's four failure kinds
(ADR-0027, statuses 3 to 6), and the stderr text is the adapter's, not something the gateway can
parse or vouch for. Nothing in the protocol can say "throttled, retry after N".

Issue #389 asked for cursor or since tracking for generic sources: whether the gateway should
keep, per source, where the last acquisition ended. That is decided here too, since the paging
loop is where a throttled answer is met.

## Decision drivers

- Only the class (429 or 503) and a bounded wait cross from the endpoint's answer to the caller;
  the body, the other headers and the adapter's stderr do not. The wait is written by the
  gateway from a number, never echoed as bytes.
- An adapter written before the change, and every other source, is answered byte for byte as
  before.
- A throttled acquisition mints, retains and records nothing, as every failed one.
- A token step's token request answered 429 or 503 is answered the same way, and no failure is
  held in the token cache.
- `go/` links the standard library only; no engine, binding or receipt version moves.

## Considered options

1. The gateway parses the adapter's stderr for `the endpoint answered 429`.
2. A new exit status alone, with no wait.
3. A new exit status, 7, beside a report on stdout of exactly the class and the wait, read only
   from a source of the `http` shape.
4. The same report from every adapter shape.

## Decision outcome

Chosen option: 3. Option 1 reads a diagnostic as a protocol, and a diagnostic carries the
endpoint's body. Option 2 loses the wait the ask names. Option 4 opens a path for adapters
whose upstreams answer by other protocols (a connector's trace messages, an MCP server's
tool errors) and for the executor's sources, which `/act` reads; nothing asks for it,
and it can be added for a shape when one does.

1. **The report.** `adapter-http` exits 7 and writes `{"throttled": {"status": 429 | 503,
   "retryAfter": 0..3600 | null}}` on stdout when the source's endpoint answers 429 or 503, and
   when the token step's token endpoint does (in place of status 4, which it answered before).
   Its stderr is the diagnostic it wrote before for that answer. An answer of 401 to a token
   stays status 5, and every other refusing answer stays status 1 or 4.
2. **The wait.** The adapter reads exactly one `Retry-After` line: delta-seconds, or an HTTP-date
   of RFC 9110's three forms counted up to the next whole second; past 3600 seconds it is 3600;
   absent, repeated, of neither form, negative, fractional or a date at or before now, it is
   `null`. 3600 is the bound because a caller that waits longer than an hour on one answer has
   stopped being a retry, and because the caller the ask names gives up past it.
3. **The gateway.** It reads stdout beside status 7 from a source declared `http` alone, held
   strictly: one member, two members, the class 429 or 503, the wait 0 to 3600 or null, each
   integer spelled with no sign (so `-0` is refused), and nothing before or after the value,
   whitespace included. Anything else, status 7 from another shape, and the report beside
   another status are a failed source, `400`, as before. It answers the class, the body `{"error": "source failed: the source's
   endpoint answered 429 Too Many Requests; nothing was retained or minted"}` (or 503 Service
   Unavailable), and `Retry-After` as delta-seconds when a wait was reported. The text begins as
   every failed source's does, so `gateway adapter-conform` classes the answer `source-failed`
   unchanged.
4. **Versioning.** The adapter protocol carries no version number: its additions are made so
   that an adapter written before them is read as before. No shipped adapter exited 7, and a
   report is read only in its exact form beside it, so an older adapter, or any program of
   another shape that happens to exit 7, is answered as it was. A new `adapter-http` beside an
   older gateway is answered as before for an endpoint's 429 or 503 (the status is not read,
   and the stderr is unchanged); for a token endpoint's, the older gateway answers the adapter's
   stderr in place of its token-refused sentence. The engine starts the `adapter-http` its own
   release ships (ADR-0007), so the two are of one release there.
5. **The token step.** A throttled token request is the flight's failure: every acquisition
   waiting on it is answered the class, nothing is held, and the next acquisition requests a
   token again. A throttled request to the source does not drop the sealed token, which the
   source did not refuse.
6. **One acquisition.** An acquisition throttled at any of its runs fails as a whole, as an
   acquisition failing at any run did before, and nothing partial is receipted. The gateway
   does not retry or wait.
7. **The gateway's own 503.** Admission closed for maintenance carries no `Retry-After`: the
   closure lasts until its operator reopens admission, which the gateway cannot know. The
   delegation credential limit is an answer of `/delegation/credential`, not of `/acquire`, and
   is unchanged.
8. **The MCP front.** It lists no tool of an http platform, so it forwards to no such source; its
   error result already names the signer's status, and it carries no `Retry-After`. Unchanged.
9. **Paging is the caller's (#389).** The gateway keeps no cursor, no high-water mark and no
   "since" for a generic source: each `/acquire` is one receipted read of the page or window the
   request names, in parameters the binding admits (a path, a method, a query, a body), and the
   caller keeps where it is. A page is its own receipt; a session sealed after the last page
   covers the count of every page in it. The recurring observations of the one built-in provider
   that has them (`docs/design/recurring-source-observations.md`) are unchanged.
10. **Under a delegation.** A call under a delegation is admitted and counted immediately before
    its source starts (SPEC.md §11.5), and the platform's grant records its use then (§10,
    rule 3). A throttled call is no exception: like any call whose source fails, it has used one
    of the delegation's counted calls and one use of the grant, and a caller that asks again is
    counted again each time. Nothing is given back for a throttled answer, as nothing is for any
    call whose source failed.

### Consequences

- Good: a caller that retries on throttling can tell a throttled source from a failed one and
  wait what the endpoint asked, within an hour.
- Good: nothing of the endpoint's answer but its class and a number crosses, and the number is
  bounded and re-encoded.
- Bad: the class is the endpoint's; a 503 from a source and the gateway's own 503 for a closed
  admission differ by their sentence, and by `Retry-After` only when the source reported a wait:
  a throttled 503 with none reported carries no `Retry-After`, and differs by its sentence alone.
- Bad: a call under a delegation is counted, and its grant's use recorded, before its source
  starts, so a throttled call, as any failed one, has used one of the delegation's counted calls
  and one use of the grant, and each retry uses another (determination 10).
- Bad: a 429 or 503 from an adapter of another shape, or from a bare command, is still a `400`.
- Neutral: the wait is the adapter's reading of the endpoint's header at the moment it read the
  answer; acquisitions that shared one throttled token request are told the same number.
- Neutral: no receipt, record, schema or conformance vector changes; the corpus is untouched.

## More information

- RFC 9110 §10.2.3 (Retry-After), §5.6.7 (date formats) and §15.6.4 (503); RFC 6585 §4 (429).
- SPEC.md §6, "When an acquisition does not happen" and "Adapter sources";
  `docs/design/engine-config.md`, "An http live operation", for the paging example.
