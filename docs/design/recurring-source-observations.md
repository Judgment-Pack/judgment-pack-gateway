# Recurring Google Drive source observations

Status: implemented on main for Google Drive; policy sync and governed admission remain under #295. This is a local host control
contract, not an adopted portable Policy schema or a change to signed receipts.

`gateway-connections --provider google-drive` answers four additional methods
over its existing private `{id,method,params}` JSON-line pipe. Catalog versions
3 and 4 advertise them only in Drive's `operations`; catalog version 2, research
capabilities, model tools and the engine's `/acquire` interface are unchanged.
The host authenticates its caller, presents recurring consent and keeps these
operations out of model-facing authority. Other programs running as the same OS
principal are inside this trust boundary: `consent: "recurring-read"` records a
host request, not a signed proof that a human consented.

The provider adapter holds credentials. Desk holds policy interpretation,
scheduling, source-state history and its own transactional eligibility rules.
Gateway does not publish, approve, withdraw or authorize a policy. A directly
returned observation carries no signed Gateway receipt.

## Binding and recovery

| Method | Parameters | Result |
| --- | --- | --- |
| `source-bind` | `operationId`, `resourceId`, `selectionContext`, `consent` | A `SourceBinding` |
| `source-bindings` | `{}` | `{version:1,bindings:SourceBinding[]}` |
| `source-revoke` | `bindingId` | `{revoked:true}` |
| `source-observe` | `bindingId` | A `SourceObservation`, or a refusal without partial content |

`source-bind` takes exactly these four string members:

```json
{
  "operationId": "<64 lowercase hexadecimal characters>",
  "resourceId": "<Drive file ID>",
  "selectionContext": "<current search selectionContext>",
  "consent": "recurring-read"
}
```

The current Drive search response supplies `selectionContext`; the existing
`select` response does not. A one-use selection grant cannot be submitted as a
recurring binding, and selecting or reading a file never creates a binding.
The host persists a fresh, unpredictable 32-byte operation ID before dispatch.
It also retains the exact request, including the resource and connection epoch.

Bindings and body-bound operation records live in the existing private custody
store's separate `source-bindings.json`, with atomic replacement and the store's
cross-process lock. They contain no provider credentials. Each binds the
connection ID, account ID, connection epoch and resource ID. Current recorded
Drive OAuth consent is required. Disconnect, reconfigure, policy disable or
reconnect invalidates recurring bindings even for the same account and bytes.
Successful interactive same-account Drive reconsent durably revokes current
recurring binding records before replacing credentials. It preserves the
established one-use picker/storage connection ID and epoch; ordinary access-token
refresh preserves recurring bindings too. A later credential-write failure can
conservatively revoke recurring consent, but cannot restore old authority.

Same operation ID and same canonical request returns the existing binding's
current state. A changed request returns `source-binding-idempotency-conflict`.
Distinct operation IDs create independently revocable bindings even when they
name the same resource: one policy's revocation cannot revoke another's consent.

```json
{
  "version": 1,
  "operationId": "<operation ID>",
  "bindingId": "<opaque 64-character lowercase hexadecimal ID>",
  "source": {
    "provider": "google-drive",
    "accountId": "<Drive account permission ID>",
    "resourceId": "<Drive file ID>"
  },
  "createdAt": "2026-10-18T12:00:00Z",
  "state": "active",
  "coverage": "snapshot-only",
  "lifecycle": {"kind": "not-exposed"}
}
```

Revocation preserves the operation record and changes its state to `revoked`.
Repeating the bind recovers that revoked row and never recreates authority.
`source-bindings` includes active and revoked rows only from the current
connection/account/epoch, allowing uncertain bind delivery to be reconciled by
operation ID. A recovered result requires current access just like a new read.
Replaying an old connection/account/epoch returns `source-binding-unavailable`;
it cannot recover sensitive old-account metadata or recreate a grant after
disconnect/reconnect. Same-account interactive reconsent preserves that legacy
epoch, so a retry recovers the retained `revoked` row instead; only a fresh
explicit operation can establish recurring consent again.

This first implementation permits 32 active bindings in the current generation
and retains at most 48 operation records per installation principal, including
revoked and old-generation records. Records are never evicted or silently reset.
Exhaustion returns `source-binding-limit` without mutation. This conservative
bound intentionally prefers explicit capacity refusal over replay after lost
outcomes; expanding it needs a durable non-replay storage/retention design.
Deleting custody is not a supported way to recover a lost operation outcome.

## Observation bytes and revisions

`source-observe` reuses the same real acquisition and document processor as a
one-use Drive read: metadata, bounded download/PDF export, fresh metadata,
extraction and the existing checked Drive attachment record. It compares the
provider revision, name, media type and size around the read. Credential refresh
is outside the custody lock, so its commit retains the existing generation
checks. Recurring authority and current recorded OAuth consent are checked before
and after provider I/O, after extraction and again before accepting the result.
Final admission of the observation into the host's reply is serialized with
revocation by the custody lock. A revocation that commits before final admission
wins; an in-flight response/extraction then returns a refusal without releasing
the artifact. Pipe delivery may follow admission. A revocation after admission
does not retract an already admitted response. Desk must also fence a delivered
observation against its own current policy binding/generation before storing it.

```json
{
  "version": 1,
  "bindingId": "<binding ID>",
  "observationId": "<new opaque delivery ID>",
  "source": {"provider":"google-drive","accountId":"<account>","resourceId":"<file>"},
  "sourceRevision": "<opaque provider revision>",
  "observedAt": "2026-10-18T12:00:00Z",
  "availability": "present",
  "content": {
    "bytesDigest": "sha256:<original bytes digest>",
    "byteLength": 23,
    "mediaType": "text/plain"
  },
  "extraction": {
    "content": {
      "bytesDigest": "sha256:<canonical attachment record digest>",
      "byteLength": 1800,
      "mediaType": "application/vnd.jpack.attachment+json"
    },
    "profile": "attachment-record-v1/canon",
    "processor": "adapter-document/text/1",
    "processorVersion": "<actual adapter version>",
    "configurationDigest": "sha256:<recorded processing profile digest>"
  },
  "coverage": "snapshot-only",
  "lifecycle": {"kind":"not-exposed"},
  "document": {"attachmentVersion":"1","...":"existing complete attachment record"}
}
```

The examples use placeholders, not valid document records. The actual record is
the existing [attachment contract](attachments.md), checked by
`adapters/attachment.Check`; its types are in `adapters/attachment/record.go`.
`document.original` retains exact bytes as standard padded base64, with
`retention: "inline"` and `encoding: "base64"`. The decoded length and SHA-256
match `content` and `document.document.size`/`id`. For a Google-native document,
these are the actual exported PDF bytes and PDF media type; the provider's native
media type remains in `document.provenance.source.mediaType`.

`sourceRevision` remains the provider's opaque revision, separately retained in
the attachment's document version and Drive source provenance. Equal bytes with
a new provider revision are a distinct observation. No ordering is inferred from
revision text or observation time.

The extraction artifact is the entire exact canonical attachment record,
including text, processing status, errors, limits and provenance. Its reference
is SHA-256 and byte length of that artifact; the `document` object transports
those canonical bytes. The profile uses Gateway's existing `canon` domain:
Unicode-code-point-sorted keys, safe integers, canonical escapes, duplicate keys
and invalid Unicode refused. It is not a claim of JCS equivalence. The private
observation pipe encodes this reply with that profile, preserving raw HTML
characters and U+2028/U+2029 inside the attachment instead of re-escaping them.

`configurationDigest` hashes the canonical `drive-document-processing-v1`
profile: actual recorded processing bounds, adapter identity, processor, actual
request OCR mode, and applied OCR program/digest or `null`. It excludes observed
time, duration and the applied OCR page list. It identifies these recorded
processing inputs, not unrecorded external/cloud settings. Processor version is
the actual attachment adapter version; processor name is its actual provenance
processor. The existing shared Drive request currently asks for OCR `auto`.

Full record digests can change on an unchanged poll because timestamp and
duration are retained. Desk verifies the exact artifacts before computing a
separate meaningful-change projection from provider revision, original bytes,
extracted content, processor/configuration and lifecycle/coverage. Such a
projection must never be substituted for an original or extraction byte digest.

Each successful poll gets a new observation ID. Gateway retains durable bindings,
not a scheduler, cursor, observation delivery outbox or complete revision history.
Desk owns retry/delivery deduplication and atomically retains its observation,
tracking revision and any source-update gate.

## The journal in an audit export

`gateway-connections --state-dir <dir> --principal <name> --export-observations` writes the
operation journal, `source-bindings.json`, to stdout as the custody holds it: read under the
custody lock once it reads as a journal, or the empty journal `{"version":"1","operations":[]}`
where the principal's namespace keeps none yet. It serves nothing and reads no stdin, it runs
for the provider these bindings are of and beside no other mode, and a custody that is not there
is refused with nothing made for it. The journal
carries the operation, binding, connection and epoch identifiers, the account and the resource of
each binding, revoked ones too, and no credential. `gateway export --observations <file>` takes
the file so written into an audit export, named by its digest; the signer never reads the custody
([store-contract.md](store-contract.md)).

## Bounds and failures

Original bytes are nonempty and at most 4 MiB, including streaming reads with an
untrusted/missing `Content-Length`. Provider metadata is at most 64 KiB. Existing
document bounds and deadlines apply; partial/truncated extraction remains
explicit in the checked attachment, rather than becoming a completeness claim.
The observation is at most 16 MiB under its canonical encoding. Only
`source-observe` has a pipe reply bound of **16 MiB + 64 KiB**, including the
outer request ID/result and newline. Every recurring-control request still has
the ordinary 64 KiB bound, and other reply limits are unchanged. A too-large
reply returns `response-too-large`, never truncated or partial JSON/content.

Binding refusals are `source-binding-unavailable`,
`source-binding-idempotency-conflict` and `source-binding-limit`; existing stable
connection, provider, processing and size errors remain in use. Provider failure,
lost access, a missing/trashed file or a changed-during-read resource returns no
partial observation. It never creates a deletion, publication or withdrawal
assertion. Drive is only advertised here as a snapshot source with lifecycle
`not-exposed`; polling proves no continuous coverage or intermediate revisions.

This is material `public-surface`, `security` and `documented-claim` work. Its
eventual PR needs the repository's different-vendor adversarial review and
maintainer dispositions against the reviewed commit. SPEC, signer imports,
receipt meanings and the frozen corpus are unchanged.
