# Response to the cloud-source roadmap review

Status: implementation response, pending independent review. This is not a
maintainer approval or a claim that the source reviewer approved the new code.

The supplied Anthropic review evaluates the September 21 cloud-source proposal
and reads gateway f62de27 / Desk 88009f9. It explicitly says no tests/build were
run, it reviews a scope proposal, and it covers no PR. The new foundation in
gateway #149 / Desk #125 postdates those inputs. Its useful technical findings
become acceptance requirements; its recommendation to halt all implementation
does not supersede the user's explicit instruction to continue the foundation.

## Scope and decisions already established

This slice supplies common connection discovery, presentation, configuration,
source selection, retained document verification and independent local bundle
replacement. Cloud names on the roadmap mean **file sources** here. Deployment,
remote storage for packs/chats, infrastructure inventory and cost management
are separate programs, not permissions this work infers.

No AWS/Spaces/Azure/Dropbox implementation, credential chain or vendor SDK is
introduced. No cloud billing or account registration is authorized by these
fixtures. Provider authentication and retrieval belong in gateway adapters;
that boundary does not dictate whether a future adapter implements sign-in,
uses a vendor SDK or consumes an explicitly selected external credential.

## Major findings

| Finding | Disposition for this foundation |
| --- | --- |
| F01 authentication ownership | Accept need for an explicit AWS intake/custody decision before its adapter. Do not infer that only the CLI can authenticate; vendor SDKs support IAM Identity Center. No external profile/cache, environment chain, IMDS or credential_process is introduced here. |
| F02 false revocation | Accept and fix the shared default: no remote-revoked claim without a completed revoke request. Desk requires local disconnect confirmation and explains that provider access may remain. A production static-key store remains separate work. |
| F04 signing / SDK | Accept as a provider implementation decision. ADR-0001 explicitly permits reviewed dependencies in adapters; ADR-0004 chose no library for the first PDF adapter, not a permanent ban on SDKs. No signing transport is invented by the foundation. |
| F05 each provider needs a new PDF variant | The closed old variants were real, but a separate variant per vendor is not necessary. The new connection-resource contract binds provider/resource identity and retained bytes. Actual PDF producer output, published schema and signed Desk verification now exercise it. |
| F06 limits | Accept. Keep four files, 4 MiB per source and the 64 KiB control line. Display effective file limits, disable known oversize rows, define a 50-item/48-KiB resource page and refuse oversized replies explicitly. No existing-provider limits are raised. |
| F10 live acceptance | Accept the missing formal evidence for these new providers. Synthetic foundation acceptance needs no paid account. The user has reported a successful Drive test, which is useful user acceptance but does not prove the four future integrations. Registration/funding/live tests are requirements for each provider delivery. |
| F11 enums / browsing | Address through catalog v3 (v2 preserved), credentials/form metadata, explicit text/prefix query semantics, bounded cursors and the shared resource selection pane. No new provider-name switch is needed in Desk. Hierarchical navigation is outside this flat listing protocol. |
| F18 unreadable objects | Accept and add disabled rows with bounded reason codes plus actionable localized copy. Provider adapters must map real storage states and enforce them again at retrieval. No automatic paid restore, requester-pays acceptance or broader permissions. |

## Other findings and remaining provider obligations

F13/F16/F17/F19/F26 remain provider work: fixed host admission and SSRF controls,
conditional/version-bound reads and grants, measured vendor pagination, bounded
retry/Retry-After handling, and provider-specific synthetic servers followed by
explicit live acceptance. No shared foundation can establish those properties
for a provider that has not been implemented.

F14/F23/F24/F25/F29 inform the common interface: public resource identity,
credential replacement copy, declared exact authorization endpoints, a neutral
icon fallback and provider-independent Desk routing. Actual Entra tenant endpoint
selection must be validated inside its future gateway adapter; do not relax host
checks to arbitrary browser-supplied URLs.

F09/F12 are retained as test obligations. Generic protocol negative tests and
focused mutations are recorded separately from the old 926 guard rows; those
rows do not prove new connection guards. A future SigV4 implementation must test
header/URL/receipt secret exclusion directly, not rely on token-byte matching.
F22 is stated precisely: current source rows expose metadata; the retained
verified content preview opens after acquisition/attachment. This does not
claim a pre-attachment provider content preview. F28: the managed local
connections implementation remains Linux/macOS and single operator; compiling
or vetting on Windows does not establish working Windows credential custody.

F21/F27: review both exact gateway/Desk heads and their parent stack before
merge. Dependent drafts may be developed and tested without declaring their
parents approved. The original roadmap review is not that code review.

Dropbox's official OAuth guide instructs app developers to register one app
rather than require every end user to register one. That is a real provider
onboarding constraint; a production Dropbox slice needs a separate distribution
choice consistent with the user's prohibition on shipping personal publisher
registrations. It does not block an OAuth-neutral foundation. No hosted
publisher or personal registration is added by this change.

References rechecked for this response:
- https://docs.aws.amazon.com/sdkref/latest/guide/feature-sso-credentials.html
- https://docs.dropboxapi.com/dropbox-api/docs/oauth
- https://docs.digitalocean.com/products/spaces/reference/s3-compatibility/
- https://learn.microsoft.com/en-us/azure/storage/blobs/authorize-access-azure-active-directory

The review's worker count is not evidence of correctness; reproducible claims,
applicable policy, the reviewed artifact and tests determine each disposition.
