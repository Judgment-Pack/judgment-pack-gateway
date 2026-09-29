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
time, kind and bounded HTTPS hits. The receipt commits to the exact request and
normalized result. The acquisition records endpoint, adapter digest, provider
response digest and observed TLS peer. It attests acquisition, not truth.

Connections are checked before and after the request. Changing or removing a
connection invalidates an in-flight response. A durable per-connection daily
request counter is reserved before network access; concurrent calls cannot
exceed it. Attempts, including failed calls and connection tests, count. The
counter resets at midnight UTC. It limits requests, not currency or a cloud
billing account's total usage. A Google request may itself perform several
searches. Every call is capped at 45 seconds, a 2 MiB provider response and ten
normalized hits. No retry silently spends more requests.

Add future providers in the adapter registry with an explicit request builder,
credential validator and result normalizer. Desk consumes the provider's declared
fields; it does not send arbitrary endpoint templates or secrets in chat.
