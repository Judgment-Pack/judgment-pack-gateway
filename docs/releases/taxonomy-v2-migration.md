# Current tool taxonomy migration

Gateway324 changes current admission deliberately: V1 MCP bindings and snapshots remain
readable for historical inspection but cannot register, start configured execution or
serve unclassified tools. Supply a bindingVersion2 `toolTaxonomies` map for every exact
allowed tool, update the pinned catalog explicitly, then recapture with `connect --replace`.
History has its own owner `taxonomy`. This never infers classification from names, hints,
model text or a prior receipt.

Engine11 stores separate `operationDescriptors` for enabled live/write operations. Both
must capture successfully before replacement. Preview chooses `--operation live` or
`--operation write` when both exist. Changed owner/constraint/server/endpoint evidence
requires explicit new whole-byte approval and restart of both configured processes.
Unused immutable declarations/snapshots after failure are retained; do not delete them as
an automatic retry step. Metadata files must remain readable by the configured platform
user under existing directory/ownership rules; credentials remain separate and private.

MCP hints derive from truthful effect; seal and arbitrary execute_sql are act. Existing
`/acquire`, `/seal`, `/act` transport, decision and approval checks retain their meanings.
Read-external classification is not evidence that a signature was verified. Loss of an
executed action's outcome remains uncertain and is never grounds for automatic replay.

Request `gateway-connections --catalog-v5` for owner declarations and derived complete
profiles. Broker methods include an explicit act-classified operator-policy constituent;
`operationDeclarations` preserves the intrinsic method and the complete derived profile.
Only the catalog CLI's separate `discoveryTaxonomy` is pure. Acquisition read-external
includes only same-identity/scope fixed authorization, grant, accounting and receipt
bookkeeping; it cannot conceal customer-resource/configuration changes or new authority.
Derived hints promise neither free repeats nor replay safety. Older catalog versions and the default output remain unchanged and lack this
current contract. Unknown MCP child tools cannot be imported merely from an act-labelled
container. Agent current V2 import, exact selected-call approvals and receipt verification
remain paired integration work. Signed descriptors313, posture/presets314, customer
sandbox310 and reconciliation316 are not completed by this producer change.

See [ADR0021](../adr/0021-owner-taxonomy-binds-current-tool-approval.md) for the complete
versioned shape and shared vectors. Native OS CI, integrated validation and independent
review remain required before release.
