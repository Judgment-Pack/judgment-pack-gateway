---
status: accepted
date: 2026-10-18
deciders: maintainer
---

# Recurring Drive reads use separate revocable host bindings

## Context and problem statement

Policy source synchronization needs repeated reads after process restart. A
one-use selected-file grant records a different request and cannot be silently
expanded into recurring access. A source snapshot also cannot supply external
publication or withdrawal authority that Drive does not expose.

## Decision drivers

- Explicit resource-scoped recurring consent and independent revocation.
- Current account/connection generation, including in-flight races.
- Durable uncertain-delivery recovery without recreating revoked grants.
- Exact original/extraction provenance and existing module/receipt boundaries.

## Considered options

- Reuse or renew one-use picker grants automatically.
- Give the model or signer a new recurring provider acquisition authority.
- Add private host controls with separate body-bound durable bindings.

## Decision outcome

Chosen option: private host controls with separate durable bindings, because the
host owns user consent and scheduling while the adapter already owns credentials
and the real bounded Drive acquisition/extraction path.

1. Drive alone advertises `source-bind`, `source-bindings`, `source-revoke` and
   `source-observe` through the existing additive catalog operations pattern.
   The legacy catalog, research declarations and model-facing tools are unchanged.
2. A bind requires explicit `recurring-read`, a resource and current selection
   epoch, and a caller-persisted operation ID. Its body-bound receipt is retained
   across restart and revocation. Independent operation IDs have independent
   revocation; bounded storage refuses capacity rather than evicting identities.
3. Recurring reads recheck current binding, account, connection epoch and recorded
   OAuth consent around provider I/O and after real extraction. Revocation and
   final acceptance share the custody lock. Reconnect invalidates old bindings.
4. Observations retain exact original and canonical existing attachment identities
   separately from opaque provider revision. Coverage is `snapshot-only` and
   lifecycle `not-exposed`; source failures make no policy withdrawal assertion.
5. These are local host observations without signed Gateway receipts or policy
   authorization claims. The signer remains outside credential custody and links
   no adapter code.

### Consequences

- Good, because consent, revocation, uncertain retries and byte provenance have
  separate explicit identities without changing receipt semantics.
- Bad, because the first bounded operation journal has an explicit lifetime
  capacity and does not implement a scheduler or complete revision feed.
- Revisit when durable non-replay retention needs larger scale, another provider
  implements the protocol, or verified lifecycle/event ordering is available.

## More information

- [The implemented host contract](../design/recurring-source-observations.md).
- [Issue #295](https://github.com/Judgment-Pack/judgment-pack-gateway/issues/295).
- [ADR-0001](0001-one-engine-four-processes.md),
  [ADR-0004](0004-documents-are-an-adapter-under-the-command-shape.md),
  [ADR-0005](0005-personal-storage-controls.md) and
  [ADR-0010](0010-a-drive-connection-is-of-the-whole-drive.md).

Material-decision impact: public-surface, security, documented-claim. Accepted
with merged [PR #297](https://github.com/Judgment-Pack/judgment-pack-gateway/pull/297),
whose reviewed head was `27df7367b6be5f380c6ae5989bde625bf9dde68a` and whose squash
merge was `5b2136c5f0b43c1c42831b7d05109c791606861b`, with an identical source tree.
The review used OpenAI models over an OpenAI implementation: same-vendor review,
not different-vendor review. The maintainer explicitly granted a
[one-time exception to merge the named exact-head PRs](https://github.com/Judgment-Pack/judgment-pack-gateway/pull/297#issuecomment-6248852465).
That exception records the approval for this merged decision; it does not waive
review requirements for later material changes or authorize a release.
