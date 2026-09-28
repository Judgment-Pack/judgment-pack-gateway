---
status: accepted
date: 2026-09-28
deciders: maintainer
---

# Personal file management uses the connection host control plane

## Context and problem statement

Desk users need bounded storage browsing and deliberate file changes on the same
Drive, S3 and local-vault connections used to attach evidence. Treating those
changes as source acquisition would falsely label a mutation as a verified read;
requiring a judgment before a person edits a file would also invent a dependency
that personal file management does not have.

## Decision drivers

- A user can browse without downloading or evaluating an entire store.
- Deletes require explicit, target-specific confirmation in the trusted host.
- Credentials and provider behavior remain in the companion, outside Desk and the
  signing process.
- An interrupted mutation must not be silently retried.
- Manual edits must not be confused with engine-governed, receipt-producing actions.

## Considered options

- Model tools that directly mutate connected storage.
- Add file changes to the source acquisition interface.
- Require every personal edit to go through `/act` with a judgment and citations.
- Add a bounded personal host-control protocol beside existing connection controls.

## Decision outcome

Choose the personal host-control protocol in `gateway-connections`. Catalog v3
advertises list, read, prepare, commit and status operations for existing storage
providers. Preparation freezes the target, payload, base version and connection
generation. The trusted host reviews it; deletion additionally requires exact
filename/key confirmation. Commit records an execution claim before mutation and
never replays it. Status retrieval is not provider reconciliation.

This is a material addition to the public control surface and security posture.
It is not a change to SPEC.md or receipt semantics. It partially narrows the broad
README phrase that every write goes through the engine: **engine-governed** writes
still use `/act`; personal file edits use a separately documented trust boundary.
No determination of ADR-0001 about the core/adapters dependency split is replaced.

### Consequences

- The same provider connections support personal browsing and edits without a new
  storage service, a background crawl or broader automatic account grants.
- A typed string is a trusted-host consent mechanism, not cryptographic proof of
  human intent. Programs under the same OS principal remain trusted. Hosts must
  not expose commit as an assistant tool or a scheduled-job action.
- No signed action receipt or historical audit log is produced. The one retained
  plan supports crash/replay handling only; account permissions remain decisive.
- Local revision rechecks cannot eliminate races with noncooperating editors.
  Provider conditional operations are required where used; Drive changes fail
  closed when a usable ETag is absent.
- An uncertain result requires source inspection and sometimes deliberate
  reconnection. Automatic retry/reconnection would defeat the chosen boundary.
- Revisit this decision before adding autonomous writes, remote multi-tenant
  connection controls, bulk deletion, or independently verifiable consent.

## More information

[Protocol, provider limits and failure handling](../design/storage-files.md).
Material impact: public-surface, documented-claim, security. Cross-vendor review
or an explicit maintainer exception must be recorded on the implementing PR.
