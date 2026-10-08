# Configurable web search

The managed local Gateway supplies a `web-search` source. Desk selects a named
connection; the provider adapter owns credentials, provider requests, limits and
normalization. Search and website discovery produce leads. Reading a page through
`web` produces the retained document used by citations.

## Providers

- **Tavily**: an account and API key. Calls `https://api.tavily.com/search` with
  basic search, no generated answer and no raw page content.
- **Google Cloud Search grounding**: project, location, Gemini model and a service
  account JSON credential with permission to call the model in that project.
  Billing and the Vertex AI API must be enabled. The adapter obtains an OAuth
  token from `https://oauth2.googleapis.com/token`, then calls the selected
  regional or global `aiplatform.googleapis.com` endpoint with `googleSearch`.
  The first version uses an explicitly configured service account, not ADC or a
  Google Drive login. The model must support Google Search grounding.

Google grounding is a generated answer with source links, not a conventional
search-results API. Its generated text, source links, search queries and provider
attribution markup remain distinct. An answer without grounded links and
attribution fails with `search-not-grounded`. Consumers must render returned
Search Suggestions safely with the associated answer. Provider documentation:
[Tavily](https://docs.tavily.com/documentation/api-reference/endpoint/search),
[Google grounding](https://cloud.google.com/vertex-ai/generative-ai/docs/grounding/grounding-with-google-search).

## Connection protocol

`gateway-connections --provider web-search --state-dir <private-directory>
--principal <principal>` serves the existing private JSON-line control channel.
Catalog v3 advertises `web-search-v1` and these operations:

- `status {}`: provider descriptors and sanitized named connections.
- `configure {id, revision, name, provider, dailyLimit, credential, ...}`:
  create with an empty revision or update using the current revision. A blank
  credential preserves the saved credential only for the same provider.
- `disconnect {id, revision}`: remove exactly that connection.
- `test {id, revision}`: make one metered search request; return only success.

Google configuration adds `project`, `location` and `model`. Tavily has no such
fields. Endpoints cannot be supplied by a caller. Up to six connections live in
Gateway's private `web-search` custody namespace. `status` never returns a
credential. There is no implicit fallback to a different provider.

## Acquisition

`adapter-sources --provider web-search --principal <principal>` reads:

```json
{"connection":"research","revision":"<64-hex-revision>","query":"public policy guidance","maxResults":5}
```

`JPACK_CONNECTIONS_DIR` names the private custody root. The local plan exposes
this adapter as source `web-search`, using the existing HTTP acquisition shape.
Results contain version, connection and revision, provider, query, retrieval
time, kind and bounded HTTPS hits. The receipt commits to the arguments, to a
statement of the request and to the normalized result. The statement names the
connection, revision, provider, query, maximum results, method and endpoint. It
is not the bytes sent: what the adapter adds to a query, which for Google is a
fixed instruction before it and fixed generation settings, is part of the
adapter, and the acquisition records the adapter's digest. The acquisition also
records the endpoint, the digest of the provider's response as received and the
observed TLS peer. It attests acquisition, not truth.

A hit's `url` is the provider's link as given. A link is kept only if it parses
as an HTTPS URL of at most 4,096 bytes that names a host, carries no user
information, and names no port or the port written `443`; any other is left
out. It may name any host, and need not be the address of the page it leads to.
Whoever reads it applies the reader's own admission of public addresses and of
each redirect.

Connections are checked before and after the request. Changing or removing a
connection invalidates an in-flight response. A durable per-connection daily
request counter is reserved before network access; concurrent calls cannot
exceed it. Attempts, including failed calls and connection tests, count. The
counter resets at midnight UTC. It limits requests, not currency or a cloud
billing account's total usage. A Google request may itself perform several
searches. Every response is capped at 2 MiB and ten normalized hits. No retry
silently spends more requests.

### How long a search may take

Each connection may set `timeoutSeconds`, a whole number from 10 through 120.
Left out, or zero as an earlier release stored it, it is 45 seconds. `status`
advertises the bounds as `timeout: {defaultSeconds: 45, minSeconds: 10,
maxSeconds: 120}`, so a client sends the field only to a gateway that advertises
them. Changing it changes the connection's revision. The deadline covers
authentication and fetching the whole response, and the caller may end a search
sooner; search has no shorter response-header cutoff, while the other Google
integrations keep theirs. A search that runs out of time answers
`search-timeout`, never a credentials error. A connection test has the same
deadline and metering as a search, and the companion allows it 125 seconds.

The local plan's ordinary `web-search` envelope is 60 seconds, the adapter
stopping at 55, which carries a timeout of up to 50 seconds. While a connection
has a longer one, `gateway-connections --local-plan`, reading the connections
directory its environment names and writing nothing, launches the source with
`--long-search` and 130 seconds, and the adapter stops at 125. A desk reads the
plan when it starts its local gateway, so a longer timeout takes the long
envelope at that gateway's next start, and only where the desk passes the
connections directory to `--local-plan`; until then a search that passes 55
seconds ends there, as `search-timeout`. With no such timeout the plan is
unchanged, and every desk takes it.

## The published form

The arguments and the result are published as JSON Schemas, with an example of
each kind of result beside them:

| File | What it describes |
| --- | --- |
| [`testdata/search/arguments-v1.schema.json`](../testdata/search/arguments-v1.schema.json) | what `adapter-sources --provider web-search` reads |
| [`testdata/search/result-v1.schema.json`](../testdata/search/result-v1.schema.json) | the `result` of what it answers |
| [`testdata/search/examples/`](../testdata/search/examples) | a request, the results of a search engine, a grounded answer |

CI holds a result of each kind, written by the source in the same run, to the
schema, and holds the schema to refuse a list of broken variants
(`testdata/search/check_schema.py`). The answers behind those results are the
test's own; no provider is asked.

A schema checks each value on its own, and says in its description where it is
looser than the adapter. Three things a consumer should not read into it:

- A title, an excerpt, a generated answer and a query the provider names are the
  provider's text, cut to length and otherwise as given. They may hold any
  character, a control character among them.
- `attributionHtml` is markup the adapter neither wrote nor read.
- A link that the schema admits is not thereby one that is safe to read. The
  reader's admission of public addresses is what decides that.

## What was tested

The tests answer from local TLS servers and a stand-in transport. They hold
the stored timeout to its bounds and its legacy default, the deadline a request
is given, a caller's earlier cancellation, the revision a change makes, the
metering of a failed attempt, and the plan's envelope to the timeouts stored.
No provider was called with an account, so nothing here is a claim that a live Tavily or
Google Cloud account is accepted, or of what a live answer holds: the form of
Google's source links, the size of its attribution markup and the models that
support grounding are as its documentation states them, not as observed.

## Adding a provider

Add future providers in the adapter registry with an explicit request builder,
credential validator and result normalizer. Desk consumes the provider's declared
fields; it does not send arbitrary endpoint templates or secrets in chat.
