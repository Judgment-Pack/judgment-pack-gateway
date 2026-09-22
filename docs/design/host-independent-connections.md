# Connections independent of host provider releases

Status: proposed. This extends the connection companion and attachment contracts;
it does not change gateway SPEC.md, receipt signing, or the frozen corpus.

## Discovery and compatibility

`gateway-connections --catalog-v3` emits catalog version 3. `--catalog` retains
version 2 for existing consumers. Both are stateless, offline discovery modes,
and refuse mixed command-line modes. A provider is advertised only when its
implementation ships. Fixtures are never added to production discovery.

Version 3 retains provider id, auth, registration, selection, queryRequired and
operations. It adds:

- `protocol`: `connection-v1`.
- `presentation`: brand name, optional PNG data URI as `icon` (empty means host
  fallback), description and instructions. The latter two are locale-to-text
  maps with an English fallback. Shipped descriptions/instructions cover Desk's
  twelve locales. Text is rendered literally, without HTML or executable markup.
- `setup`: at most twelve `{key,type,label,required}` fields. Version 1 supports
  text and password fields; labels are localized maps. `form` registration sends
  the resulting object to configure. Inputs are never included in discovery or
  returned account status. Provider implementations remain responsible for strict
  input validation, custody and permission checks.
- `authorizationEndpoints`: exact HTTPS origin/path pairs for explicit browser
  authorization. The flow URL may add OAuth query parameters. It may not change
  the declared origin/path, carry user information, or introduce a fragment.
- `source`: acquisition id, receipt shape and result contract. Legacy drive-v1,
  mail-v1 and note-v1 preserve their existing provider-specific restrictions.
  New providers use resource-v1 with an acquisition id equal to the provider id.

The host checks supported protocol combinations rather than requiring a known
provider name for resource-v1. Unsupported combinations remain visible with an
update message but do not cause status, configuration or source calls. An icon
may only be inline PNG data, at most 22,000 encoded characters and dimensions
1..128; there are no remote image URLs, SVG, scripts or host component names.
Malformed discovery is refused as a whole. Desk's envelope limit is 128 KiB,
32 providers, 32 explicit sources, 16 distinct operations per provider.

The existing Google desktop-registration and native picker protocols remain
specialized host controls. A new interaction protocol requires a host update.
Additional provider names within an implemented protocol do not.

## Common source operations

connection-v1 retains status/configure/connect/poll/cancel/disconnect. Source
search takes `{query,pageToken?}` and returns `{selectionContext,items,more,
nextPageToken?}`. Each item carries id, title, URL and optional description.
Selecting `{resourceIds,selectionContext}` returns resourceId/grant pairs, with
the current provider's existing grant bounds and lifecycle. A connection is not
permission for account-wide agent search or provider writes.

The shared host form is used for Obsidian's existing path configuration. OAuth
starts only from the user's connect action. Saving OAuth registration does not
silently grant account access. Successful source attachment restores the chat's
draft and focus without sending a message.

## Resource record

The new attachment source variant is `connection-resource`, with provider,
resourceId, url, version and format `retained-file-v1`. The provider is a bounded
identifier; resourceId is an opaque UTF-8 identifier, 1..4096 bytes without
controls. The URL is empty or a bounded HTTPS display link with no credentials,
query or fragment. Temporary authenticated download URLs do not belong here.
Version equals document.version and document.id, the retained-byte digest; it is
not a provider revision or an assertion about live content.

Original bytes are retained inline, canonical base64, and must match document
identity and size. Existing extraction, partial-result and OCR rules still apply.
`ResourceDocument` produces this record after the provider adapter has admitted
and consumed a source grant and bounded its read. It neither authorizes nor
retrieves the source. The helper processes existing PDF/text inputs with OCR off.

The consumer verifies the current signer, sealed receipt, acquisition source,
supported receipt shape, argument commitment, selected resource id, signed provider
identity, retained bytes and document metadata. The proof is stored with the
original and can be reverified after disconnect without a current catalog.
Legacy proofs retain their original checks. A generic proof cannot be substituted
for a legacy proof without a different signed result. Receipts establish byte
lineage under a key, not accuracy or the correctness of authorization.

## Local source launch plan

`gateway-connections --local-plan` emits version 1 installation metadata naming
the adapters, bounded arguments, shapes, timeouts and whether connection custody
is required. It is read only from the verified installed companion, never the
browser or a project configuration. Each executable must be an adapter basename
present in the verified bundle manifest. Desk bounds the plan to 32 KiB/64 sources,
rejects duplicate ids, word-splitting arguments and unrecognized shapes, and
constructs the gateway CLI without a shell. Only JPACK_CONNECTIONS_DIR may be
passed as source environment. The private signing seed remains with the core.

Provider changes therefore remain in gateway code: its implementation, catalog
and source plan. Generic Desk relay routing and UI do not need a new provider case.

## Distribution

Desk keeps its default reviewed gateway revision. An operator may install a
different reviewed bundle and approve the exact gateway-bundle.json SHA-256 at
Desk process startup. Every binary listed in that manifest is also checked.
The catalog/source-plan versions still have to be supported. This enables a
gateway-only local update without rebuilding Desk. It is not a network updater
or a publisher-signature system; it relies on the operator choosing a trusted
installation and digest. No registration or personal cloud credential is shipped.

The new public surface, source contract and trust input require a fresh recorded
different-vendor material-decision review. Earlier Notion findings do not review
this design. Dropbox, S3, Spaces and Azure remain subsequent provider work;
generic fixture acceptance must not be called live provider acceptance.
