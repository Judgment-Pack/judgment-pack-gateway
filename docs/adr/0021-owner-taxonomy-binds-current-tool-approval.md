---
status: proposed
date: 2026-10-25
deciders: maintainer
---

# Owner taxonomy is part of current tool approval

## Context and problem statement

Gateway324 and Agent ADR0027 require owner-declared operation/effect independently of
server hints and model text. Existing snapshots and catalogs have closed historical
shapes. A single descriptor pin cannot bind independent live and write servers, and
placing a complete declaration on argv exceeds supported process command-line capacity.

## Decision outcome

This distribution adds bindingVersion `2`, snapshotVersion `2`, engineVersion `11`,
and opt-in connection catalog `5`. Receipt formats and frozen historical records do
not change. Source implementation leads these distribution contracts; SPEC.md and
corpus remain unchanged. This ADR is proposed pending the required independent review.

Every current MCP binding operation declares `toolTaxonomies` covering the exact
allowed raw names after parameter substitution. History declares `taxonomy`.
Taxonomy is a closed object with mandatory `operation` and `effect`, optional boolean
`experimental`, and `checkKind` only for `check`. Gateway refuses Runtime-only
`evaluate`; its shared table otherwise follows Agent ADR0027, including reviewed
unpublished `run/propose`. Standard hints derive from effect. Destructive true or
readOnly false from a server contradicts a non-act owner; readOnly true cannot weaken
an act owner. Arbitrary SQL is act absent an independently enforced narrower contract.
The shipped Postgres execute_sql is act/act; search_objects is discover/read-external.

Current registration, configured execution startup and MCP offering refuse missing
owner declarations. V1 bindings/snapshots remain decodable and inspectable, preserving
their original bytes. They are not current live admission evidence. Migration requires
operator declarations and explicit `connect --replace` recapture; no inferred defaults,
automatic rewrite or opt-out makes an unclassified tool executable.

SnapshotV2 retains numeric display `policy:1`, adding string `snapshotVersion:"2"`
and mandatory `operation:"live"|"write"`. Each exact allowed tool retains mandatory
`taxonomy`, optional display candidates and optional `serverAnnotations` containing
only recognized boolean MCP hints. Classification cannot disappear with display fallback.
These bytes, endpoint, platform, binding, server identity, operation and constraints
all participate in the canonical whole-byte digest. Canonical JSON uses Gateway's
Unicode code-point ordering, not an unrelated language serializer's ordering.

Engine11 stores `operationDescriptors:{live:<digest>,write:<digest>}` with exactly the
enabled MCP operations and no legacy `descriptors` member. Disabled writes have no pin.
Both captures and immutable publications must succeed before config replacement.
An unused immutable file left by failure grants nothing and is retained. Each invocation
selects the corresponding operation's approval before credentials or target startup,
then checks real initialization and the full approved tools/list projection before one
selected tools/call. Unallowed upstream tools may be ignored; aliases, duplicates,
missing allowed tools and changed approved metadata refuse. Observation retains the
original capture timestamp for comparison; it never refreshes approval. This is bounded
observed drift detection, not remote attestation or a guarantee against later server change.

The full projection and execution allowlist are distinct. Capture requires exact equality.
Approved invocation may use a nonempty subset of approved leaves as its execution
allowlist; `/act` retains its one selected tool and all original decision/citation/argument
checks. Observation still validates every approved sibling. Metadata grants no authority:
live frontend calls still use `/acquire`, seal uses `/seal`, writes use `/act`. Act-labelled
live acquisitions are not action-policy receipts. Read-external labels do not prove any
signature; a consumer must perform its actual receipt signature/binding verification.

The immutable owner input is a separate closed canonical envelope:
`{declarationVersion:"1",platform,binding,operation,tools}`. It is derived from the pinned
resolved binding and source identity, published through the existing protected immutable
snapshot directory, and addressed by its own exact digest. Product launch uses
`--owner-declaration-file` and `--owner-declaration-pin`, mutually exclusive with direct
legacy declaration chunks. The adapter reads a bounded regular no-link file once,
checks directory/file identity around open and verifies canonical bytes, digest and
trusted capture/approved context before credentials or target startup. Complete input is
at most327680 bytes, the existing complete snapshot ceiling. Declaration and snapshot
are distinct identities; no additional mutable approval map is introduced. Only product
publication's transient staging names are removed; immutable evidence is not cleaned up.
Native Linux evidence captures an exact327680-byte snapshot with a289844-byte declaration
and26258-byte argv. This does not establish native Windows/macOS behavior; the required
integrated OS matrix remains a gate.

CatalogV5 adds source `taxonomy`, `capabilityTaxonomies`, `dispatchTaxonomies` and
`profile`, and provider `taxonomy`, `operationTaxonomies`, `operationDeclarations` and `profile`. Existing
capability/operation string arrays retain their meanings. Profiles are complete child
unions with strongest effect. Same family/check subkind retains that family; mixed
families or differing check subkinds summarize as run. Missing classification refuses
current discovery/admission, rather than shrinking to a weaker profile. Output maps/slices
are detached. The default and V2/V3/V4 discovery encodings remain unchanged; consumers
must request `--catalog-v5` to receive owner classifications.

The actual Broker entry reconciles operator policy before every method. That persisted
preamble can advance the policy epoch and cancel work, so every provider method summary
has effect act. Each `operationDeclarations[method]` is closed over `taxonomy`, `profile`
and `components`, with exactly `operator-policy:{operation:"act",effect:"act"}` and
`operation:<intrinsic owner tuple>`. Its summary and profile derive from both components;
the provider profile flattens every constituent, preserving discover/read/check/propose
families even when the strongest effect is act. Persisted credential/configuration
changes are act, never in-run own-state. Poll/cancel can affect authorization state and
are intrinsically run/act. Local status/plan inspection is intrinsically read/read but
still carries the policy preamble at Broker entry. No enforcement is relocated.
Only the actual side-effect-free catalog CLI advertises top-level
`discoveryTaxonomy:{operation:"discover",effect:"pure"}`.

Bounded source acquisition does not enter that Broker preamble. Its intrinsic
read-external includes fixed, non-model-selectable protocol bookkeeping necessary for an
already admitted read: receipt creation, one-use grant consumption and durable usage
accounting, bound to the same connection/principal/scope. This grants no new resource
permission and makes no independent customer-resource or configuration change. Token
renewal must preserve that admitted identity/scope. Drive refresh checks returned scope,
client/connection/epoch and recorded consent. Databricks requests its saved configured
scope using saved client credentials and retains tokens only for the same connection
revision; its opaque token response does not independently prove provider-granted scope.
No classification claims cryptographic token verification. SQL writes, arbitrary MCP
effects, new scope/principal, source binding/revocation/configuration and other resource
mutations are excluded from this bookkeeping rule. Read-only/idempotent hints grant no
permission and promise neither free repeats nor replay safety. Agent ADR0027 must carry
this same narrow interpretation during paired integration.

Connection SQL and generic enabled MCP dispatch can mutate, so their complete source
containers are act/run as declared in V5. This grants neither arbitrary child import nor
an approval: unknown customer MCP leaves still require explicit registration and current
snapshot evidence. Existing connection control consent, storage proposal/commit, source
binding and transport checks remain. Posture/presets324 companion314, signed snapshot313,
three-OS customer sandbox310 and action reconciliation316 remain separate unmet work.

## Consumer contract

Shared handwritten vectors are `testdata/tool-taxonomy/v2.json`. Import requires exact
operation/platform/raw key/source identity, approved whole canonical snapshot digest and
matching binding owner projection. Frontend name mapping is explicit platform plus raw
key; a dotted model-visible name cannot establish source identity. MCP tools/list publishes
flat `_meta.operation`, `_meta.effect`, optional `_meta.checkKind`/`experimental`, plus
owner-derived standard `annotations`; it does not grant source approval. Agent's selected
call/args/descriptor approval and result/receipt verification remain required dependent
integration. Historical reader success is never current import admission.
