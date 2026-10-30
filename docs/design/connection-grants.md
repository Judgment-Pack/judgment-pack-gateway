# Connection grants

A connection reaches a platform through a standing provider authorization: an OAuth consent, a
service principal's client credentials, or a personal access token. Spec RFC 0030 §5 (a Draft)
calls it the **connection grant** and treats it as a resource that a principal holds. Gateway #357
records each grant, holds it to the least privilege its operations declare, and gives it an owner
and a lifecycle. The gateway is the RFC's first implementation; where this design departs from the
RFC, the departure is listed at the end.

The record and its rules live in the connection custody (`adapters/connections`), beside the
credentials they describe. The signer never reads the custody (ADR-0001, ADR-0020), so the report
is a mode of `gateway-connections`, not a line of `gateway posture`.

## Which connections have a grant

Google Drive, Gmail, Notion, Databricks and Azure DevOps. Each Drive, Gmail or Notion custody holds
at most one connection, named after its provider. Databricks and Azure DevOps name each connection
by its `id`.

These have no record in this release:

- an Obsidian folder, which is local;
- an object store's access keys;
- a search service's or a processing service's API key.

The gateway has no GitHub connection. A customer MCP server's publisher has its own record, kept by
the core beside the engine configuration ([below](#publisher-trust-for-customer-mcp)).

## The record

Custody keeps `connection-grants.json` in each provider's namespace, beside `state.json` and not
inside it, because an earlier release refuses a state member it does not know. Each record holds:

| Member | Form | Meaning |
| --- | --- | --- |
| `connection` | flat token | the connection |
| `provider` | string | the provider |
| `owner` | `{"kind": "person" \| "service", "issuer", "subject"}` or `null` | who authorized the grant and answers for it |
| `ownerHost` | flat token or `null` | the issuing host that holds the owner's standing |
| `scopes.required` | strings, sorted | the union of the scopes the connection's operations declare |
| `scopes.granted` | strings, sorted, or `null` | what the provider granted, as last read; `null` where the provider does not report it to the gateway |
| `scopes.used` | `[{"scope", "lastUsedAt"}]`, sorted by scope | each granted scope that a dispatched call's operation declares, and when last |
| `excess` | strings | granted scopes that no operation declares; they refuse |
| `wider` | strings | granted scopes wider than any operation needs, admitted and reported (Databricks' `all-apis`) |
| `createdAt` | time | when the record was made |
| `lastUsedAt` | time or `null` | the last dispatched acquisition or action |
| `idleExpiry` | integer milliseconds or `null` | the idle bound; `null` is none, the default |
| `state` | `active`, `quarantined` or `revoked` | `revoked` is terminal |
| `revocation` | `{"reason", "at", "providerRevoked", "report"}` or `null` | why and when; `report` is `provider-grant-may-persist` until the provider confirms |

A time is UTC with exactly milliseconds: `YYYY-MM-DDTHH:MM:SS.sssZ`.

The record carries no credential, no token, no token digest, no provider account and no content.
It also keeps the custody's own identifier of the connection, so that a connection made again
after a revocation becomes a new grant. That identifier is never reported.

The record is reconciled with custody whenever it is read:

- a connection without a live record gets a new record with no owner;
- a record whose connection has gone (disconnected) is revoked, with reason `disconnected`;
- a live record takes its required and granted scopes as they stand now.

## Least privilege

Each operation declares the narrowest scope it needs. The table is `grantDeclarations`, and the
declarations are the gateway's own, since few providers report which scope a call exercised.

| Provider | Operation | Declared scope |
| --- | --- | --- |
| Google Drive | read, observe, storage | `https://www.googleapis.com/auth/drive` (ADR-0010) |
| Gmail | read | `https://www.googleapis.com/auth/gmail.readonly` |
| Notion | read | `default` |
| Databricks | statement (Statement Execution) | `sql` |
| | catalog (Unity Catalog catalogs) | `unity-catalog` |
| | MCP `sql` / `genie` / `functions` / `ai-search` | `sql` / `genie` / `unity-catalog` / `ai-search` |
| | MCP `unity-gateway` | `ai-gateway` |
| Azure DevOps | `workitems.*` | `vso.work` |
| | `repos.*`, `pullrequests.list` | `vso.code` |
| | `pipelines.*` | `vso.build` |

A connection's required scopes are the union of the declarations of the operations it offers. A
Databricks connection offers a statement, a catalog listing, and each managed MCP server it
enables.

**A scope wider than needed.** Databricks' `all-apis` reaches every REST API the service principal
may use. It is what a service principal configured with no scope asks for. So it is admitted, but
recorded in `wider` and reported as `wider-than-needed`; it is not `required` and never refuses.
A statement or a catalog listing made under `all-apis` alone records `all-apis` as used. Whether
`all-apis` covers the managed MCP servers, no Databricks page states: an MCP call made under
`all-apis` alone records no scope as used, and the gateway does not take `all-apis` as sufficient
for one.

**At connect.** A Google or Notion token whose stated scope is more than the scope requested is
refused with `excess-scope: <extra scopes>`. A token of another or a narrower scope is still
`provider-unavailable`. A Databricks service principal configured with a scope that none of its
operations declares is refused the same way, and the connection is not saved.

**Drift.** Google states a token's scope at every renewal. A renewal that states a scope added
since consent is refused with `excess-scope`. The record then takes the granted scopes the
provider stated and the excess, and the connection is refused at every use until it is consented
to again. A Notion renewal is held to its own check: one that states another scope, a wider one
included, is refused as `provider-unavailable`, and no drift is recorded. A Databricks
connection's scope is read from custody at each use. So a connection saved
by an earlier release that asks for more than it declares is refused at its next use, and
reported.

**Unreadable grants.** A Databricks or Azure DevOps personal access token, and an Entra token, do
not report their scopes to the gateway. Their `granted` is `null`. No excess and no unused scope
is derived for them, and the report says `scopes-unreadable`.

**Granted against used.** At each dispatched acquisition or action, every granted scope that the
operation declares is recorded as used, with the time. The report lists `granted` minus `used` as
`unused`: the scopes to trim.

## Owner and lifecycle

**Owner.** The operator records a grant's owner and its issuing host once, with `set-owner`. A
second owner is refused (`owner-recorded`). This release has no reassignment. A grant recorded
before this release, or with no owner set, has no owner record. It is used as before, and the
report flags it `owner-missing` (spec #284 NC3).

**The owner read.** Before every use of the credential of a grant that has an owner, the gateway
asks the owner's issuing host whether the owner is still a current principal. The request
is a synchronous HTTPS `POST` to the address the operator configured for that host (`owner-reads`):

- it carries `Authorization: Bearer <credential>`;
- its body is `{"host": <ownerHost>, "owner": <owner>}`;
- the host answers 200 with exactly `{"standing": "current"}` or `{"standing": "removed"}`, in
  at most 4096 bytes;
- redirects are not followed, and the read has 5 seconds.

What follows:

- `current` admits the call.
- `removed` applies the operator's removal policy to every grant of that owner in this custody,
  and refuses the call with `owner-removed`.
- Anything else refuses the call with `owner-unknown` and changes nothing. That covers an
  unconfigured host, a refusal, a timeout, an unreadable answer or another standing.

A use is any call that reads the grant's credential to reach the provider: an acquisition, an
action, a search, a file operation, a selection's read, and a connection test, MCP included
(`grantCredential`, at `provider.access` for Drive, Gmail and Notion, at the token for Databricks,
and at each read and test for Azure DevOps). One call makes one owner read: an acquisition's
check marks its call, and the credential read in the same call re-reads the grant's state under the
lock without a second read. Its cost is one synchronous request to the issuing host per call.
Operations that do not reach the provider (status, configure, disconnect, a selection's
listing) make none. An owner's grants in other providers' custody are refused at their own next
use of any kind, since each makes its own read.

**Owner removal.** `remove-owner` names an owner and its host. Every grant of that owner, in every
provider's custody for the principal, is then revoked or quarantined:

- the request's `removal` member chooses which;
- without one, the operator's configured `removal` applies;
- without either, the grant is revoked (open question 13).

A quarantined grant keeps its credential, admits no call, and is refused as `grant-quarantined`
before its credential is read. Its state is read again once a token is held after a renewal (a Google
renewal of this call's, another process's renewal taken in its place, or Notion's) or a Databricks
token is held, immediately before the call is sent. The gate holds the ledger to custody before it
reads a grant's state, so a connection made again under its id after its grant was revoked is a
new grant there, as in the report. It leaves quarantine only when the operator revokes it.

**Idle expiry.** `set-idle-expiry` sets or clears the bound. A grant is expired when its last use
is at least the bound before now; a grant never used is measured from its record's creation, and
equal counts as expired. A time the record cannot be read for counts as expired. An expired grant
is revoked at its next use of any kind (as above: a search or a connection test as much as an
acquisition), which is refused as `grant-idle-expired`, or by the next `sweep`. A grant with no bound that has been unused for 90
days or more is reported as `idle` (open question 14).

**Revocation.** The gateway deletes the credential from custody, records the reason, and then:

- **Drive and Gmail:** it calls Google's token revocation endpoint (RFC 7009) and records the
  confirmation.
- **Notion, Databricks and Azure DevOps:** these offer the gateway no revocation endpoint, so the
  record keeps `provider-grant-may-persist`.
- **A provider that does not confirm:** the record also keeps `provider-grant-may-persist`.

A disconnect made through the connection's own controls is recorded the same way.

**Pending actions.** A revocation or a quarantine deletes no journal of a pending change
(`storage-intent.json`) and no action reservation. Reconciliation proceeds as it would without
the revocation. A read-back that needs the revoked grant cannot run, so its outcome stays
`unknown` (spec #284 NC4, its first option). A quarantined grant serves no read-back.

## The operator's commands

```
gateway-connections --grants OPERATION --state-dir <dir> --principal <name> [--provider P]
```

The command covers every provider with grants, unless `--provider` names one. `report` reads no
input. Every other operation reads one JSON request from stdin. The answer is one JSON line on
stdout. A refusal is `grants: <code>` on stderr with exit 1. A mode beside it, or an operation it
does not know, exits 2.

| Operation | Request | Effect |
| --- | --- | --- |
| `report` | none | the connections report; reads, writes nothing, makes no custody |
| `set-owner` | `{"provider", "connection", "owner", "ownerHost"}` | records the owner once |
| `set-idle-expiry` | `{"provider", "connection", "idleExpiry": ms \| null}` | sets or clears the bound (at most ten years) |
| `owner-reads` | `{"version": 1, "removal": "revoke" \| "quarantine", "hosts": [{"host", "url", "credential"}]}` | configures the owner read in each provider's custody; the answer repeats no address and no credential |
| `remove-owner` | `{"owner", "ownerHost", "removal"?}` | revokes or quarantines the owner's grants |
| `revoke` | `{"provider", "connection"}` | revokes one grant |
| `sweep` | `{}` | revokes idle grants and makes the owner read for every live owned grant; each result is `idle-expired`, `owner-removed`, `owner-unknown` or `current` |

The report gives each grant the record's members except the custody identifier, together with:

- `scopes.unused`;
- `idle`, one of `none`, `within`, `idle` or `expired`;
- `findings`, each a code and a fixed sentence: `owner-missing`, `quarantined`, `excess-scope`,
  `wider-than-needed`, `scopes-unreadable`, `unused-scopes`, `idle`, `idle-expired` and `provider-grant-may-persist`.

A finding's sentence names no path, no account and no token, as `/posture`'s public reasons do
not (#350). The report's members are the owner reference and scope names, and never a provider
account.

## Publisher trust for customer MCP

A customer binding (`"customer": true`, #348) may declare its server's publisher with a binding
member:

```json
"publisher": {"kind": "registry", "name": "npm:@acme/tickets-mcp"}
"publisher": {"kind": "repository", "name": "github.com/acme/tickets-mcp"}
"publisher": {"kind": "domain", "name": "acme.example"}
```

The member is refused on a binding that is not a customer's.

**A domain publisher is a registrable domain:** the name a registrant holds at its registry, such
as `acme.example` or `acme.co.uk`, never a host under it. The core reads no public-suffix list, so
the rule at parse is this:

- the name has exactly two labels, or exactly three under a two-label public suffix of a fixed,
  partial list (`co.uk`, `nhs.uk`, `com.au`, `co.jp`, `com.es`, `on.ca` and so on);
- a host under a domain of that list's suffixes is refused, and the message names the domain to
  declare (`tickets.acme.co.uk` → declare `acme.co.uk`);
- any other name of three labels or more is refused without naming a domain: the gateway cannot
  tell a host under a registrable domain (`tickets.acme.example`) from a registrable domain under a
  public suffix it does not list (`acme.com.zz`), and the name it would suggest could be another's
  domain or a suffix; such a server declares its repository or package, or no publisher;
- a listed public suffix itself (`co.uk`, `nhs.uk`) is refused. The list is partial: a public
  suffix it does not name, declared as a two-label domain, parses, and is read as that suffix's
  registry object, which says nothing of a publisher. Such a declaration is meaningless, and
  is the operator's to avoid;
- a shared platform's domain, under which anyone may be given a host (`vercel.app`, `netlify.app`,
  `github.io`, `pages.dev`, `herokuapp.com`, `azurewebsites.net` and others), is refused, and so
  is any host on one.

Such a server declares its repository or its package as its publisher instead. The binding digest covers it, as it
covers every member.

**Liveness.** The gateway reads it from public sources:

| Kind | Source | Unmaintained when (evidence of a lapse) | Unverifiable when | Maintained when |
| --- | --- | --- | --- | --- |
| `registry` | the npm registry | the package's latest version is deprecated (a message, or `true`) | the registry shows no public package of that name (private, or never published) | the latest version is listed and not deprecated |
| `repository` | GitHub's repository API | the repository is archived or disabled | no public repository of that name answers (private, or not there) | it is neither |
| `domain` | the registry's own RDAP service, as the IANA RDAP bootstrap names it for the top-level domain | the registry answers that the domain is not registered (it lapsed and was deleted, or was never registered), the registration has expired (equal is expired), or the domain is in its redemption period or pending deletion | the bootstrap names no RDAP service for the top-level domain | the registration is current |

The 404 cases are these, exactly:

- **npm and GitHub:** a 404 is `unverifiable`. An unauthenticated read cannot tell a private
  package or repository from one unpublished or deleted.
- **RDAP:** a 404 from the registry's own service for the registrable domain declared is
  `unmaintained`, with the reason "the registry's RDAP service answers that the domain is not
  registered". That is the window in which another can register the name.
- **No service:** a top-level domain absent from the bootstrap (for example `.io`) is
  `unverifiable`. A bootstrap that cannot be read, is empty, or lists the top-level domain with no
  HTTPS service, is inconclusive (`unknown`).
- **Never the name above:** the gateway asks for the declared name alone. It never reads the
  object of a name above it, such as a public suffix's own object.

Any other answer leaves the state `unknown`.

**An inconclusive reading never lifts a conclusive one.** `maintained` and `unmaintained` are
conclusive; `unknown` (a read that failed, timed out, was refused or rate-limited, or answered
what cannot be read) and `unverifiable` are not. When a re-check or a recapture reads a publisher
inconclusively, and its record holds a conclusive reading of the same declared publisher:

- the record keeps that state and its time;
- the failed read is recorded beside it (`lastAttempt`, `attemptState` and `attemptReason`) and
  reported as `publisher-read-inconclusive`;
- `gateway publishers --check` warns on stderr and exits 3, after writing the record.

So under `refuse`, an unmaintained publisher stays refused until a conclusive `maintained`
reading, and a recapture whose reading fails is refused as before. A platform with no conclusive
reading yet takes the inconclusive state, and is not refused. A customer binding that declares no publisher is
`undeclared`. The reads disclose to those public services which servers an operator uses, so their
schedule is the operator's.

**Where it is read and kept.** The read happens at registration: `gateway connect` for a customer
binding, `--replace` (a recapture) included. It happens before any adapter is run, and its lines
are shown with the approval. It happens again on the operator's schedule, with
`gateway publishers --config <engine.json> --check`. What was read goes in
`<engine.json>.publishers.json`, by platform: the binding reference it was read for, the
publisher, its state, when it was checked, and a fixed reason. The reason names no path, no
account and no token.

Every read-modify-write of the record is made under the configuration's own lock
(`<engine.json>.lock`, the one `connect` holds). `connect` writes the record under its lock once
the configuration is in place. `gateway publishers --check` makes its liveness reads without the
lock, then merges what it read into the record as it stands under the lock. A policy set
meanwhile is kept. So is a platform's record written meanwhile, by a `connect` or a recapture: a
record whose binding or reading time differs from the one the re-check started from is left as
written, and is read again at the next re-check. A `gateway publishers` that finds a `connect` holding the lock
waits up to ten seconds, then refuses. The record is given the configuration's own mode and
owner, as a replaced configuration is: a root `connect` or a root-run `gateway publishers` over a
configuration the signer owns leaves a record the signer can read.

**Policy.** `gateway publishers --config <engine.json> --policy report|refuse` sets the operator's
policy; `report` is the default (open question 15). An unmaintained publisher is always reported
as `publisher-unmaintained`, and an unverifiable one as `publisher-unverifiable`. Under `refuse`,
a record of the platform's own binding that says `unmaintained` (evidence of a lapse, never a
404) also refuses three things:

- its registration;
- each acquisition, before the source starts;
- each action, before an executor runs.

A record that cannot be read refuses as `publisher-record-unreadable`; the reason answered to
`/acquire` and `/act` names no path. An `unverifiable`, `unknown` or `undeclared` publisher is not
refused, under either policy.

**Name lookalike.** A registration is flagged `name-lookalike` when its platform name, or its
binding's platform name, closely matches one of the integrations the gateway ships while its
declared publisher is not that integration's. The integrations are `azure-devops`, `databricks`,
`postgres`, `google-drive`, `gmail`, `notion`, `obsidian` and `aws-s3`. Names are compared after
folding case, punctuation and look-alike characters: fullwidth letters to their
ASCII forms, Cyrillic and Greek letters drawn like a Latin letter to that letter (capitals and
small letters, from a fixed table), Latin letters with a diacritic to their base letter (the
Latin-1 Supplement and Latin Extended-A, and a decomposed spelling, whose combining mark is
dropped), the mathematical alphanumeric symbols, small capitals and a few Armenian letters
(`օ`, `ս`, `հ`, `ո`, `ց`), and `0`→`o`, `1`→`l`, `3`→`e`, `5`→`s`, `rn`→`m`, `vv`→`w`. The core
has no Unicode normalization or confusables data, so letters outside these tables are known
misses. A close match is any of these, after that folding:

- the name equals the integration's;
- the name is one edit away from it (two edits for a name of ten characters or more);
- the name contains it.

The flag is shown with the approval and recorded. It is a report, never a refusal.

## Departures from RFC 0030 §5

- **More members.** The record adds `provider`, `createdAt`, `excess`, `wider` and `revocation`, and keeps
  an unreported custody identifier. `createdAt` is what "a grant never used is measured from its
  creation" needs.
- **An unreadable grant.** `scopes.granted` is `null` where the provider does not report the
  grant. The RFC has only an array.
- **A wider scope admitted.** Databricks' `all-apis` is not in `required` and is reported as
  `wider-than-needed`, but it is admitted rather than refused, because a service principal
  configured with no scope asks for it; refusing it would refuse every such connection.
- **Drift at renewal.** Drift is read where the provider states a token's scope, which for Google
  is at each renewal, and not by an extra provider request on every use. A Databricks connection's
  configured scope is read at each use.
- **Excess is refused.** Every provider with a record can narrow its grant, so a scope no
  operation declares is refused and reported; the one admitted-and-reported case is `all-apis`
  above.
- **One owner read per call.** The owner read is made before every use of the credential, and once
  per call: an acquisition's credential read re-checks the grant's state, not the owner.
- **The owner read's wire.** The RFC names the read but not its wire. The address and credential
  are the operator's configuration, held in custody.
- **Not built.** Delegated calls and the admission read carrying the owner (spec #284 NC2) belong
  to #356. Reassignment out of quarantine, and acceptance, are not built.
- **Where the publisher record lives.** It is kept beside the engine configuration and not in the
  connection grant record. A customer MCP server is registered by the core (`gateway connect`), not
  by a connection custody. A customer binding without a declared publisher is `undeclared`. The
  RFC has `null` for "otherwise".
- **Publisher sources.** Liveness is read from npm, GitHub and RDAP only. The `registry` and
  `repository` kinds accept only those, and another registry or forge is refused at parse.
- **No policy refuses a lookalike.** The RFC lets an operator policy make `name-lookalike` a
  refusal. This release reports it only; no policy refuses it.
- **Unverifiable is its own state.** The RFC's states are `maintained`, `unmaintained` and
  `unknown`. A package or repository the public source does not show (a 404), and a top-level
  domain with no RDAP service, are `unverifiable`: reported, never refused. A registry's own 404
  for a declared domain is `unmaintained`.
- **A domain publisher is a registrable domain, by a partial list.** Without a public-suffix
  list, a domain under a two-label public suffix the gateway does not list cannot be declared as a
  domain publisher. Hosts, including hosts on shared platforms, cannot be declared at all; such a
  server declares its repository or package.
- **Name lookalike against the gateway's own integrations.** The known integrations are the ones
  the gateway ships, a fixed list. The operator cannot extend it in this release.
- **Owner removal at use.** An owner read that answers `removed` changes the grants in the custody
  being used. The owner's grants in other providers' custody are refused at their own next use of
  any kind, by their own owner read, and changed then, by a `sweep`, or by `remove-owner`.
