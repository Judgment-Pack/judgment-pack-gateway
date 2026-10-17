---
status: accepted, 2026-10-17
date: 2026-10-17
deciders: maintainer
---

# A web-search acquisition holds each provider's arguments to one table: Tavily also takes a domain restriction and a time range, every other argument and every value out of its form is refused by name before anything is charged or sent, and `--describe-research` gives the table as a versioned request schema beside a versioned result schema, in description version 2

Issue #275, the part of its scope that reads "enforce provider-supported configuration and
allowed request scope at acquisition ... Unsupported controls must be explicit rather than
silently ignored", with its acceptance's "versioned discovery/configuration schemas" for the
search adapter. This record states the design the pull request builds; the maintainer accepts or
amends it.

**Checked against** gateway `main` at `8f7c619`, and at `552141b` (v0.18.0) with the clean-room
review of the pull request applied. It extends [ADR-0009](0009-named-web-search-connections.md),
whose acquisition arguments were the connection, its revision, the query and the maximum results,
and supersedes nothing.

## Context and problem statement

**What a caller could pass.** `adapter-sources --provider web-search` read four members:
`connection`, `revision`, `query` (1 to 2,000 bytes of UTF-8, no control character) and
`maxResults` (1 to 10). It sent Tavily `query` and `max_results`, with a basic search, no
generated answer and no page content fixed by the adapter. It sent Google the query inside the
adapter's own instruction and did not send the maximum; the adapter kept at most that many of the
answer's links. Every other member was refused by the decoder, and so was a value out of its form,
each as `invalid-request`, which names nothing.

**What that left open.** Nothing was silently dropped and nothing was forwarded unchecked, but a
caller could not restrict a search to some domains or to recent results, which Tavily's search
reference offers, and could not tell from a refusal which member was wrong.
`--describe-research` (#281) gave a request schema written beside the decoder, not derived from
it, with no version, and no result schema.

## Decision drivers

- One source of truth: what acquisition enforces and what discovery describes are the same
  table, so that they cannot differ.
- A refusal is deterministic and names the argument; it charges no allowance, sends nothing and
  gives the gateway nothing to mint a receipt from.
- A request without the new arguments is sent and recorded byte for byte as before.
- A control the adapter is not sure of is refused, never carried: a refusal costs nothing and can
  be lifted later, and a control carried on a wrong reading costs a request.
- No receipt member changes, and no verifier changes.

## Considered options

- **A. The table, enforced and described (chosen).** One table of arguments: each argument's name,
  whether every request carries it, the providers whose connections take it, the member of
  Tavily's request it is sent as, and its form. Acquisition reads a request by it;
  `--describe-research` generates the request schema from it.
- **B. Pass provider options through.** Declined: an argument forwarded unchecked is exactly what
  the issue excludes, and the provider's own refusal would cost an allowed request.
- **C. Hold hits to the domain restriction in the adapter.** Declined for now: a provider's reading
  of a domain list (a subdomain, a redirect) is its own, and an adapter that dropped hits by
  another reading would change the result. The restriction is the provider's to apply, and the
  schema says the adapter does not hold the hits to it.
- **D. Admit Google's domain exclusion (`googleSearch.exclude_domains`).** Declined for this
  change. Google documents it on the endpoint the adapter calls: the Vertex AI grounding page's
  `generateContent` example sends `"googleSearch": {"exclude_domains": [...]}`, with
  "EXCLUDE_DOMAINS: Optional: List of domains that aren't to be used for grounding", and the
  Vertex reference for `Tool.GoogleSearch` says "The default limit is 2000 domains". It is
  deferred because it is not observed (no provider was called with an account) and which models
  support it is not known. It stays refused by name; a later record can admit it as
  `google-grounding-request-2`. Google documents neither an include-list nor a time range for
  `googleSearch`, so those are refused for Google on their own grounds.
- **E. A description that stays version 1.** Declined: `docs/design/research-binding-discovery.md`
  states version 1 as closed, so new members are a new version.

## Decision outcome

Chosen: A.

### 1. The table

`adapters/connections/web_search_arguments.go`, `searchArguments`:

| Argument | Required | Tavily | Google | Form | Sent to Tavily as |
| --- | --- | --- | --- | --- | --- |
| `connection` | yes | takes | takes | a saved connection's name | not sent |
| `revision` | yes | takes | takes | 64 lowercase hexadecimal characters | not sent |
| `query` | yes | takes | takes | 1 to 2,000 bytes of UTF-8, no control character | `query` |
| `maxResults` | yes | takes | takes | an integer from 1 to 10 | `max_results` |
| `includeDomains` | no | takes | refused | 1 to 20 distinct domain names | `include_domains`, with `include_domains_mode: "restrict"` |
| `excludeDomains` | no | takes | refused | 1 to 20 distinct domain names | `exclude_domains` |
| `timeRange` | no | takes | refused | `day`, `week`, `month` or `year` | `time_range` |

A domain name is two or more labels of lowercase letters, digits and hyphens separated by dots,
each label 1 to 63 characters that neither begin nor end with a hyphen, at most 253 bytes in all,
the last label holding a letter: no scheme, path, port, wildcard, capital or final dot, no address
(`192.168.1.1`) and no name of digits alone (`1.2`). Twenty is the adapter's own bound, not a
provider's. Under `timeRange`, Tavily drops results it dates, by publish or last-updated date,
outside the span; results it cannot date are kept. The adapter does not send
`filter_by_published_date`, which would change what Tavily returns; that is a choice for a later
schema version. Google is sent the query inside the adapter's instruction and no other argument,
as before; `maxResults` bounds the links its answer keeps.

### 2. Refusals

A request is read in this order, and the first fault is the refusal:

1. Not a JSON object, a member named twice, text that is not UTF-8, or more than the program
   reads (16 KiB; the longest request in its form, as the gateway writes it, is under 14.5 KB):
   `invalid-request`, as before.
2. A member the table does not hold, the first in the order of names:
   `search-argument-unsupported: "<name>" is not an argument of web-search; nothing was sent`.
   The name is repeated only where it is a plain name (a letter, then up to 63 letters, digits
   and underscores); any other is `a member whose name is not a plain name`, so that a refusal
   never repeats a credential's form or needs an escape.
3. In the table's order, an argument required and absent, or a value out of its form, of any JSON
   type: `search-argument-invalid: "<name>" is required; nothing was sent` or
   `search-argument-invalid: "<name>" must be <its form in words>; nothing was sent`.
4. The connection is read, as before: blocked, absent, another revision, not in its form.
5. In the table's order, an argument the connection's provider does not take:
   `search-argument-unsupported: "<name>" is not an argument a <provider> connection takes; nothing was sent`.
6. The day's allowance, as before; only then is a request reserved and sent.

Nothing refused at any step is charged or sent, and the program writes nothing to its output, so
the gateway mints no receipt. A Tavily option the table does not hold (a topic, a search depth,
dates, a country, an answer, page content, images, `include_domains_mode`,
`filter_by_published_date`) is refused at step 2, as is a member named as Tavily names it
(`include_domains`).

### 3. What is sent and stated

A taken argument is sent to Tavily exactly as read, under its member there, beside the members the
adapter fixes, which no argument can be sent as. A request that carries `includeDomains` is also
sent `include_domains_mode: "restrict"`, Tavily's hard filter, so that the restriction does not
rest on Tavily's default mode; no other request is sent it, and a caller cannot send it. The
mode is the adapter's, as the other fixed members are, and is not in the statement. The
acquisition's statement names each argument the request carried beyond the four, by its name, as
it was sent; the receipt's `acquisition.statement` commits to it, and its `argumentsCommitment` to
the arguments, as both did. A request with none of them sends the bytes it sent before and has the
statement it had before; the golden comparison holds that, with the records written by
`552141b`'s code: each request's method, address, headers (a bearer value masked) and body, and
Google's token request with its assertion's header and claims, without the instants and the
signature.

### 4. Description version 2 and the schema versions

`--describe-research` writes version 2: version 1's members, each with its meaning, and three
more.

- `requestSchema` is `searchRequestSchema`'s, generated from the table for the connection's
  provider: the arguments it takes, the connection and its present revision as constants. A
  Google connection's is version 1's, byte for byte. A text's bound in bytes and its control
  characters, which a schema cannot state, its description states; a pattern means the same in
  ECMA-262 and in RE2.
- `requestSchemaVersion` and `resultSchemaVersion` name the schemas: `tavily-request-1`,
  `tavily-result-1`, `google-grounding-request-1`, `google-grounding-result-1`.
- `resultSchema` is the result member (`web-search-v1`) a connection's acquisition answers with,
  with the bounds the adapter keeps it to, as normalization's constants give them.

Any change of what a schema says for a provider is a new version of it. A test holds each version
to the digest of the schema it named, so a change without a new version fails.

### 5. What is not changed

The result (`web-search-v1`), the published `testdata/search/` schemas of version 1, which a
request without the new arguments still meets, the connection protocol, `status`, the catalogs,
the receipt and both verifiers. `SPEC.md` is unchanged: `statement` is a commitment to the request,
whatever the statement holds.

### Consequences

- Good, because the schema a host registers is the one acquisition enforces, and a refusal says
  which argument and why, before anything is spent.
- Good, because a Tavily search can be held to domains and, as Tavily dates results, to a span of
  time, and the receipt commits to that.
- Bad, because a refusal of an unknown member that was `invalid-request` is now
  `search-argument-unsupported`, and of a value out of its form `search-argument-invalid`: a
  client that matched `invalid-request` for those reads a new code.
- Bad, because the domain restriction and the time range are Tavily's to apply; the adapter does
  not hold the hits to them, and they repeat Tavily's search reference, not an observation. No
  provider was called with an account.
- Bad, because Google takes no domain exclusion here, though it documents `exclude_domains` for
  `googleSearch` on this endpoint, with a 2,000-domain default limit: it is not observed, and
  which models support it is not known (option D).
- Bad, because the Desk reads description version 1 closed and maps only `invalid-request` for a
  search refusal: judgment-pack-desk#444 reads version 2 and maps the named refusals, and must land
  with or before the Desk's pin moves to the gateway release that carries this record.
- Revisit when Google's domain exclusion is to be admitted, when another search provider is added
  (#233 to #237), when the adapter is to hold hits to a restriction, or when the single authoring
  boundary across two source configurations of #275 is designed.

## More information

[web-search.md](../web-search.md), "Acquisition";
[research-binding-discovery.md](../design/research-binding-discovery.md);
`adapters/connections/web_search_arguments.go`; the tests in
`adapters/connections/web_search_arguments_test.go` and `web_search_golden_test.go`.
