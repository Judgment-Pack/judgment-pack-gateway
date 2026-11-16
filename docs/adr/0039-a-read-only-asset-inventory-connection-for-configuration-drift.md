---
status: accepted (autopilot; maintainer may revise)
date: 2026-11-16
deciders: maintainer
---

# A read-only Asset Inventory connection for configuration drift

## Recommendation

Add one custody connection, `gcp-asset-inventory`, under `adapters/connections/`. It reads a
Google Cloud project's or folder's resources and IAM policies through the Cloud Asset Inventory
list operation, one page per `/acquire`, and returns them as an attested result for a caller to
compare against an adopter's registry (the registry companion of the specification, RFC 0034).
The connection is read-only by construction and by check:

- its token carries the read-only scope alone;
- at start, and on every token refresh, it asks the platform which of a fixed list of write
  permissions the credential holds on each configured parent, and refuses to serve if any is
  held;
- while serving IAM policies, it refuses if any resource binds its own principal to a role
  outside a fixed read-only list;
- a parent outside the configured set is refused before that check and before any request.

It keeps no payload by default (ADR-0028, `artifact: "not-retained"`). It keeps no cursor:
Asset Inventory's page token comes back in the result, and the caller sends it on the next
`/acquire` (the Runner's paged operation source, RFC 0033). An expired page token is answered
with the existing `410 source_reference_expired`. Facts compared through an ordinary pack; the
gateway judges nothing.

## Context and problem statement

An adopter keeps its environments' intended configuration in a registry: the entries of
adopter-declared kinds, resolved per environment, with secret references pinned to a store,
a project and a version (RFC 0034, RFC 0035). Its question is drift: does the platform hold
what the registry says, now? Examples are a Cloud Run service's image, its environment and the
secret versions it mounts, and who holds a role on a project.

The registry side can already turn entries into facts (RFC 0037). The other side, the
platform's state, needs a source the gateway attests, so that a drift finding can be shown to
rest on what the platform answered at a given time. No connection reads that state today. A
connection with any write capability on a production project is not acceptable for this use:
a drift reader that could change what it reads is a control surface, not a witness. A new
connection kind with a new refusal and a new start check is a material decision, so this is
an ADR and not only an adapter.

## Decision drivers

- Read-only is checked, not assumed. A credential that could write is refused, and the refusal
  says why without disclosing the credential.
- The gateway stays a witness. It reads and attests, and decides nothing about drift.
- Paging is the caller's, as for every other source (`docs/design/engine-config.md`, "The
  engine keeps no cursor"; ADR-0029). One `/acquire` is one upstream request and one receipt.
- Values the gateway should not hold are not held. Environment variable values are not kept
  at all, and a result payload is not kept by default.
- Nothing about an existing connection, receipt, store or frozen vector changes.
- Tests use in-process servers and hand-written synthetic fixtures only. No live project, and
  no fixture recorded from a run.

## Considered options

1. **A custody connection, read-only by check, one page per request.** Chosen.
2. **Gateway-side paging.** The connection would follow page tokens itself and return the whole
   listing as one result. Rejected: the Runner owns the loop and the cursor (RFC 0033). One
   receipt would stand for many upstream requests and no `callIndex` would name a page. A
   partial listing after a failure would have no shape a caller could resume, and the gateway
   would hold state between pages that it holds nowhere else.
3. **The generic `http` source with a token step (ADR-0027).** Rejected. It fixes endpoints,
   paths and methods, but it has no place for the write-capability check at start and on
   refresh, the parent allow-list, or the per-asset-type projection that drops values. Those
   are what makes the source acceptable.
4. **Read-only by documentation, as the Databricks and Azure DevOps connections are.** Their
   headers say what the credential may do is "the credential's scopes and its identity's
   permissions". Rejected for this connection: its purpose is to be pointed at production
   projects, and an operator's duty is not a check.
5. **Members hashed in the result.** A keyed hash of each IAM member would keep identities out
   of the result. Rejected: the registry side cannot reproduce a key it does not hold, so the
   comparison would fail for every member. Members are carried as written, and the result is
   not kept by default (decision 5).

## Decision outcome

Chosen option 1.

### 1. The connection

- Name `gcp-asset-inventory`. It is wired as the existing custody connections are:
  - `provider.go`, `store.go`, `broker.go`;
  - `cmd/adapter-sources`, `cmd/gateway-connections`;
  - the operation and effect tables in `catalog_v5.go` and `catalog_v4.go`;
  - ADR-0017's research-capability table (`[]`);
  - SPEC.md's grants record;
  - a section of `adapters/README.md`.
- One operation, `list`, of effect read. There is no write operation, and the catalog file has
  no `write` member. A configuration that sets `write: true` on it is refused at start.
- Configuration names:
  - one or more parents, each `projects/<project-id>` or `folders/<number>`;
  - the asset types served, an explicit list with no wildcard;
  - the content types served, `RESOURCE`, `IAM_POLICY` or both.
- A request names one configured parent, one content type and a subset of the configured asset
  types, and may name a page token and a page size up to the platform's bound. A request
  naming anything else is refused before any upstream call (decision 3).
- **Scope identifiers.** A `gcp-asset-inventory` source is fixed to at most one scope
  identifier, like any source (ADR-0026, ADR-0037). Every parent it names belongs to that
  scope, and parents of another scope need another source. On `/acquire`, the caller's reach
  to the source's scope identifier is checked first, with ADR-0037's rule and refusal. The
  parent check comes after it.
- `readTime` is the caller's. The connection does not choose one. A caller that wants pages of
  one instant sends the same `readTime` with each page.

### 2. Paging is the caller's

- One `/acquire` is one call to the list operation and one receipt, with its `callIndex` as for
  any source. `/seal` fixes the count.
- The result carries Asset Inventory's `nextPageToken` as written, or `null` on the last page.
  The connection never follows it. This is the Runner's paged operation source (RFC 0033,
  dialect format 4.1.0, accepted for specVersion 0.6.0), the same caller-driven form as
  Databricks' `next_page_token` and Azure DevOps' `continuationToken`.
- Asset Inventory refuses a page token it no longer honours. That answer is HTTP `400`, with
  `error.status` `INVALID_ARGUMENT` and a bad-request detail whose field violation names the
  page token. The builder confirms this form against the platform's documentation, and a
  hand-written fixture holds it. The connection answers it as `410` with
  `{"referenceExpired":{"status":410}}`, as SPEC.md §6 defines it: not receipted, no
  `callIndex`, the session left open, the caller to start the listing again. It applies only
  when the request sent a page token, so a refusal of a first page is never classed as an
  expired reference. Every other upstream error on a request with a page token, another `400`
  included, stays the ordinary upstream error. The `410` is today defined for the `http` shape alone. This decision
  extends it to this connection, and to no other.
- No new RFC is needed. RFC 0033 already gives the caller's side.

### 3. The credential is read-only, checked

- **Scope.** The token step requests exactly the read-only scope
  (`https://www.googleapis.com/auth/cloud-platform.read-only`). A token obtained another way is
  read from the platform's token-information endpoint, and only one form is: an access token
  from a federated token file (ADR-0027). The connection refuses any other form as
  `credential-scope-unknown`. A token with any scope beyond the read-only one is refused.
  The check fails closed: an answer from the token-information endpoint that is missing,
  unreadable, or carries no scopes is refused as `credential-scope-unknown`, not passed.
- **Parents first.** Every configured parent is checked against its own form before the
  credential is used, and a request's parent against the configured set before any upstream
  call. A parent outside the set is refused as `parent-not-configured`. The refusal names the
  parent the request gave, which is the caller's own text.
- **Write permissions.** For each configured parent, the connection calls the platform's
  `testIamPermissions` with a fixed list of write permissions. If the answer grants any of
  them, the connection refuses to serve: `credential-can-write: <permission>`, naming the first
  permission granted in the list's order. The list is part of the connection's code and
  versioned with it. It covers at least:
  - setting IAM policy on the project or folder;
  - updating and deleting Cloud Run services;
  - adding and destroying secret versions;
  - creating service account keys;
  - updating storage buckets;
  - creating Asset Inventory feeds.
  The adapter's README lists it in full. The platform accepts at most 100 permissions in one
  `testIamPermissions` call, so the list is checked in calls of at most 100. If any call
  fails, the start (or the refresh) is refused, just as for a grant.
- **Bound at a resource.** `testIamPermissions` on a parent does not see a role granted on one
  resource below it. Yet a grant such as `run.services.update` on one service, or
  `secretmanager.versions.add` on one secret, is write capability over something this
  connection reads. So, while serving an `IAM_POLICY` page, the connection looks at every
  binding in it. If a binding names its own principal (the service account, or the federated
  principal) with a role outside a fixed list of read-only roles, the connection refuses with
  `credential-bound-at-resource: <asset name>`. It then closes, as on a refresh refusal. The
  read-only list holds predefined roles only, and a custom role is never on it, whatever its
  name.
- **When.** The check runs at start, before the connection is offered, and again each time the
  token is refreshed, before the new token is used for any request. A refusal on refresh closes
  the connection for every request after it, and the start report and `/posture` say so.
- **Never the token.** No refusal, event, log line or posture entry carries the token, its
  digest or any part of it. A refusal names the permission found, or the parent, and nothing
  else.
- Each refusal path emits its event, and each event validates against the event schema with a
  malformed input, as AGENTS.md (e) requires.

### 4. What the result holds

- Each asset type served has an allow-list projection. Only the members named in it are carried
  into the result, and everything else is dropped before the result is digested.
- For Cloud Run services, environment variable values are never carried. A variable that names
  a secret carries the secret's name and version (`secretKeyRef`), because those are what a
  registry pins and what drift is checked against. A plain value carries the variable's name
  alone.
- The projections are listed in the adapter's README and held by tests, one per asset type.

### 5. IAM members, and the payload not kept

- IAM policy bindings carry their members as written (`user:`, `serviceAccount:`, `group:`,
  `domain:` and so on). That is what the registry side can compare (option 5).
- The connection's default is `artifact: "not-retained"` (ADR-0028): the gateway returns the
  result to the caller with its receipt and keeps only `resultDigest`. An operator who wants
  the bytes kept sets `artifact` explicitly, and the start report says so.
- An optional reduction, `members: "count-users"`, replaces each binding's `user:` members with
  their count and keeps the other members as written. It is off by default, because a count
  cannot be compared with a registry that lists users. It is for an adopter that checks only
  service accounts and groups, and wants no user identities in the result at all.
- The projection (decision 4) and `count-users` both run before `resultDigest` is taken. So the
  digest is of the projected result, and it is the same for every caller of the source.

### 6. Where judgment happens

The connection returns attested state. A drift finding is a pack over two sets of facts: the
registry's (RFC 0037) and these. It is evaluated by the Runner or the runtime like any other
pack. Facts compared through an ordinary pack; the gateway judges nothing.

### Consequences

- Good: a drift reader that cannot be quietly pointed at a writable credential, with a refusal
  an operator can act on.
- Good: no new paging model. The Runner's loop, the receipt per page, `/seal` and the `410` are
  all existing behaviour.
- Good: secret values and environment values never reach the gateway's store, and by default
  no payload does.
- Bad: the write list is fixed. A write permission the platform adds later, or one not on the
  list, goes undetected until the list is revised. The list is revisited when the asset types
  served change and on each release of the connection.
- Bad: the check of bindings at a resource sees only what this connection reads. Two cases
  still go undetected, and the README says so:
  - a binding on a resource whose asset type is not served, or whose IAM policy is not read
    because only `RESOURCE` is served;
  - a custom role whose name looks read-only. The check goes by role name, and it cannot tell
    what such a role grants. So the read-only list never holds a custom role, and a binding
    of the connection's principal to one is refused rather than trusted by its name.
- Bad: one more custody connection to keep. Tests are in-process only, and v1 has no live test.
- Neutral: the token information read is one more request at start and on refresh, and only
  for a federated token.

## Amendment (gateway #488): an engine source, two narrow tokens, projects first

The build found four points where the decision above does not meet the gateway or the
platform. The decisions below replace the parts they name. Everything else stands.

### A1. An engine source, not a custody connection

Supersedes decision 1's wiring list (the custody path: provider, store, broker,
`adapter-sources`, `gateway-connections`, the catalog tables, the grants record).

The custody path applies none of the protections this ADR promises:

- A source under plain `serve --source` has no scope identifier and no caller reach check.
- It has no `notRetained`, and the adapter envelope cannot set it. So the gateway would keep
  payloads the connection says it does not keep.
- It has no token step, start report or `/posture`.

Built as written, it would advertise protections the gateway does not apply.

So the connection is an engine source (`serve --config`), as `http` is:

- A new binding operation shape, `gcp-asset`, served by a new adapter, `adapter-gcp-asset`. It
  is derived like `http` in `deriveSources`, and its source carries `scope`, `notRetained` and
  its token source.
- Engine configuration version 29 admits the shape. Earlier versions refuse it, and nothing
  about the other shapes changes.
- Core changes: `go/engine.go` (version 29, the shape, the derivation); the binding parser (the
  shape's members: parents, asset types, content types, `members`); the start report and
  `/posture` (the token source, the write check's result, a refusal on refresh, an `artifact`
  other than `not-retained`); SPEC.md §6 (the shape, and its exit status 8 for the `410`, which
  extends the Amendment of ADR-0029 to this shape alone); and docs/design/engine-config.md.
- `write: true` on a platform of this shape is refused at start. A binding of this shape has
  no write operation.

### A2. Projects only, and two narrow tokens

Supersedes decision 3's "Scope" paragraph (the wording "one read-only token" is withdrawn) and
narrows decision 1's parents.

The platform's published API descriptions show the read-only scope does not cover the calls:
`assets.list` accepts `cloud-platform` or `cloudasset` only, and `folders.testIamPermissions`
accepts `cloud-platform` only.

- Parents are `projects/<project-id>` only in this version. A `folders/<number>` parent is
  refused at start, and folders are left to gateway #489.
- The adapter holds two tokens, each narrow to its use:
  - one of scope `https://www.googleapis.com/auth/cloudasset`, for the list operation alone;
  - one of scope `https://www.googleapis.com/auth/cloud-platform.read-only`, for
    `projects.testIamPermissions` and nothing else.
  The resource-binding check reads the `IAM_POLICY` page the first token returned, and makes no
  call of its own. So it runs only on the `IAM_POLICY` pages that callers request. A platform
  configured without the `IAM_POLICY` content type has no resource-binding check at all. Its
  start report and `/posture` say so (`resource-bindings: unchecked`). An operator who wants
  the check serves `IAM_POLICY`, and a Runner that wants it read every page reads them.
- `https://www.googleapis.com/auth/cloud-platform` is never requested. A token whose granted
  scopes include it, or any scope beyond the one requested, is refused `credential-scope-unknown`.
  The one exception is a fixed list of identity scopes that grant no API access: `openid`,
  `https://www.googleapis.com/auth/userinfo.email`, and their short form `email`. A token
  source may add these to what it grants. The list is closed, and any other scope is refused.
- The write list adds the Cloud Asset writes the `cloudasset` scope admits: creating, updating
  and deleting feeds and saved queries.
- It also adds the permissions that mint a token or a signature as a service account
  (`signBlob`, `signJwt`, `implicitDelegation`, `getOpenIdToken`), and the common writes on
  objects, jobs, compute instances and firewalls, functions, builds, services and organization
  policy. An answer to the check that is neither `{}` nor an object with `permissions` refuses.

### A3. Where the tokens come from

Supersedes decision 3's reliance on ADR-0027's token step. That step sends `client_credentials`
with a client assertion, which the platform's token endpoint does not accept. The adapter has its
own token source, one per platform, in this order of preference:

1. **The metadata server** of the platform's own compute: the attached service account, with
   each token's scope requested as it is minted. No key is on disk. This is the path when the
   gateway runs on Cloud Run.
2. **Federation:** an RFC 8693 token exchange at `https://sts.googleapis.com/v1/token`, then
   service-account impersonation (`generateAccessToken` with the one scope) for each token.
3. **A service-account key** with the `jwt-bearer` grant at `https://oauth2.googleapis.com/token`,
   the scope in the assertion. This is the least preferred, for local use. The key file is read
   under the gateway's existing secret-file rules.

For every source, the scope check reads the scopes actually granted, from the token response's
`scope` or from the token-information endpoint. It fails closed: an answer that is absent,
unreadable or holds no scopes is refused `credential-scope-unknown`. The write check and the
refresh re-check of decision 3 apply to every source.

### A4. What a first live run confirms

The platform documents that a page token expires 72 hours after the first page's token was
issued. It does not document the error an expired token draws. The `400` `INVALID_ARGUMENT`
form in decision 2 is an assumption: it stays as the one mapped form, held by a hand-written
fixture. The adapter's README marks it unconfirmed.

A first live run checks two things:
- the error an expired page token draws;
- the scopes each token source actually reports as granted (metadata server, federation with
  impersonation, key), against the requested scope and the identity-scope list of A2.

Until then, both are held by hand-written fixtures.

### Consequences of the amendment

- Good: every protection the decision names is one the gateway applies: scope, reach,
  `not-retained`, the start report and `/posture`.
- Good: on Cloud Run no key exists to leak.
- Neutral: the scopes narrow less than their names suggest. The `cloudasset` token reaches only
  the Cloud Asset API. The `cloud-platform.read-only` token can READ every API the identity's
  roles allow, but it cannot write through any of them. It is used only for
  `testIamPermissions`, and it is never offered to a caller.
- Bad: the OAuth scope is no longer "read-only" in name. The `cloudasset` token could call the
  Cloud Asset writes, were the identity granted them. The read-only guarantee rests, as the
  maintainer's decision states it ("viewer roles only; refuses to start if its credential can
  write"), on the `testIamPermissions` refusal. The scopes are defence in depth.
- Bad: folders wait. An adopter with many projects configures each one.
- Bad: more core surface than a custody connection: a new shape, a new engine version and a
  new adapter.

## More information

- Specification: RFC 0033 (paged operation source), RFC 0034 (registry profile), RFC 0035
  (references), RFC 0037 (facts contracts).
- Gateway: ADR-0015 (custody connections arrive through it), ADR-0017, ADR-0027 (token step),
  ADR-0028 (payloads not kept), ADR-0029 (paging is the caller's), SPEC.md §6
  (`source_reference_expired`).
- Review: this decision sets a security boundary. It had one same-vendor review round before
  merge, not a cross-vendor claim. The maintainer waived the different-vendor review for the
  registry line, and that waiver covers this decision.
