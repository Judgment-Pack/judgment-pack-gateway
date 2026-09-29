---
status: proposed
date: 2026-09-29
---

# Named web-search connections in the acquisition adapter

Desk needs to discover public sources without asking users to supply every URL,
and operators need to change search vendors without changing assistant models.

Keep credentials, provider-specific HTTP/auth code, durable request limits and
normalization in the adapters module's connection service. Add the separate
`web-search-v1` control protocol to catalog v3 and expose `web-search` using the
existing HTTP acquisition receipt shape. No receipt or verifier format changes.
The initial providers are Tavily and Google Cloud Search grounding.

Each named connection has an opaque revision. Acquisition arguments include that
revision, query and maximum results. Reject results after connection changes,
reserve a durable daily request before network access, and do not retry or fall
back silently. Gateway's signing core has no provider credentials or new module
dependencies. The adapters module uses golang.org/x/oauth2 for service-account
authentication.

Google's generated answer is separately classified and retains its attribution;
it never becomes a fetched-page excerpt. Desk verifies search receipts before
using their URLs for bounded reading and same-origin website discovery. Intent
selection and conversation ownership belong to Desk. The search configuration
contains no arbitrary HTTP endpoints or user-defined shell commands.

Material-decision categories: public-surface, documented-claim, security,
dependency. Cross-vendor review is required on the merging PR by the repository's
review policy; this proposed record does not claim that review has occurred.
