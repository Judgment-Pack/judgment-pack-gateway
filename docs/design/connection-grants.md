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

The gateway has no GitHub connection. A customer MCP server's publisher is a separate record (the
publisher-trust change).

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
| `excess` | strings | granted scopes that no operation declares |
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

Each operation declares the scopes it needs. The table is `grantDeclarations`, and the
declarations are the gateway's own, since few providers report which scope a call exercised.

| Provider | Operation | Declared scope (any one of) |
| --- | --- | --- |
| Google Drive | read, observe, storage | `https://www.googleapis.com/auth/drive` (ADR-0010) |
| Gmail | read | `https://www.googleapis.com/auth/gmail.readonly` |
| Notion | read | `default` |
| Databricks | statement | `sql`, `all-apis` |
| | catalog | `unity-catalog`, `all-apis` |
| | MCP `sql` / `genie` / `functions` / `ai-search` | `sql` / `genie` / `unity-catalog` / `ai-search`, or `all-apis` |
| | MCP `unity-gateway` | `ai-gateway` |
| Azure DevOps | `workitems.*` | `vso.work` |
| | `repos.*`, `pullrequests.list` | `vso.code` |
| | `pipelines.*` | `vso.build` |

A connection's required scopes are the union of the declarations of the operations it offers. A
Databricks connection offers a statement, a catalog listing, and each managed MCP server it
enables.

**At connect.** A Google token whose stated scope is more than the scope requested is refused
with `excess-scope: <extra scopes>`. A token of another or a narrower scope is still
`provider-unavailable`. A Databricks service principal configured with a scope that none of its
operations declares is refused the same way, and the connection is not saved.

**Drift.** Google states a token's scope at every renewal. A renewal that states a scope added
since consent is refused with `excess-scope`. The record then takes the granted scopes the
provider stated and the excess, and the connection is refused at every use until it is consented
to again. A Databricks connection's scope is read from custody at each use. So a connection saved
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

**The owner read.** Before every acquisition or action through a grant that has an owner, the
gateway asks the owner's issuing host whether the owner is still a current principal. The request
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

Control operations (status, search, select, test, configure) check the grant's state, but make no
owner read.

**Owner removal.** `remove-owner` names an owner and its host. Every grant of that owner, in every
provider's custody for the principal, is then revoked or quarantined:

- the request's `removal` member chooses which;
- without one, the operator's configured `removal` applies;
- without either, the grant is revoked (open question 13).

A quarantined grant keeps its credential, admits no call, and is refused as `grant-quarantined`
before its credential is read. It leaves quarantine only when the operator revokes it.

**Idle expiry.** `set-idle-expiry` sets or clears the bound. A grant is expired when its last use
is at least the bound before now; a grant never used is measured from its record's creation, and
equal counts as expired. An expired grant is revoked at its next use, which is refused as
`grant-idle-expired`, or by the next `sweep`. A grant with no bound that has been unused for 90
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
  `scopes-unreadable`, `unused-scopes`, `idle`, `idle-expired` and `provider-grant-may-persist`.

A finding's sentence names no path, no account and no token, as `/posture`'s public reasons do
not (#350). The report's members are the owner reference and scope names, and never a provider
account.

## Departures from RFC 0030 §5

- **More members.** The record adds `provider`, `createdAt`, `excess` and `revocation`, and keeps
  an unreported custody identifier. `createdAt` is what "a grant never used is measured from its
  creation" needs.
- **An unreadable grant.** `scopes.granted` is `null` where the provider does not report the
  grant. The RFC has only an array.
- **Declarations with alternatives.** A Databricks operation may declare alternatives (any one of
  them is enough), and `required` is the union of every accepted name.
- **Drift at renewal.** Drift is read where the provider states a token's scope, which for Google
  is at each renewal, and not by an extra provider request on every use. A Databricks connection's
  configured scope is read at each use.
- **Excess is always refused.** Every provider with a record can narrow its grant, so excess is
  refused and reported. This release has no admitted-and-reported case.
- **Owner reads at acquisitions and actions only.** The owner read is made before every
  acquisition and every action, but not before control operations (search, select, test), which
  check the grant's state only.
- **The owner read's wire.** The RFC names the read but not its wire. The address and credential
  are the operator's configuration, held in custody.
- **Not built.** Delegated calls and the admission read carrying the owner (spec #284 NC2) belong
  to #356. Reassignment out of quarantine, and acceptance, are not built.
- **Owner removal at use.** An owner read that answers `removed` changes the grants in the custody
  being used. The owner's grants in other providers' custody are caught at their own next use, by
  a `sweep`, or by `remove-owner`.
