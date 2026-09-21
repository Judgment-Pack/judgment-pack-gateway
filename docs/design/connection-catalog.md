# Connection capability catalog

Status: proposed; companion discovery contract, version 1. This change is separate
from Notion/Obsidian connection review in PR #143 and requires its own material-
decision review. It does not change the normative gateway receipt contract.

## Problem and behavior

A host with a built-in list can offer a connection that its installed companion
cannot implement. `gateway-connections --catalog` reports the connection protocols
in that binary. The host intersects these descriptors with its own supported UI
handlers before requesting account status or exposing controls.

The command emits one JSON document and exits. It takes no other flags or
positional arguments, reads no stdin, loads no publisher registration, opens no
credential store, creates no account state, and contacts no provider. It works
without `--state-dir` or `--principal`. Normal provider mode is unchanged.

Example descriptor, within `{ "version": 1, "providers": [...] }`:

```json
{
  "id": "obsidian",
  "auth": "local-folder",
  "registration": "none",
  "selection": "source-search",
  "queryRequired": false,
  "operations": ["status", "configure", "disconnect", "search", "select"]
}
```

## Meaning

- `id`: stable provider identifier, not a user-supplied module name.
- `auth`: `oauth` or `local-folder` describes the existing consent flow.
- `registration`: `google-desktop`, `automatic` (Notion DCR), or `none`.
- `selection`: `browser-picker`, `mail-search`, or `source-search` names an existing
  wire contract. It is not a component name, URL, or executable to load.
- `queryRequired`: search needs nonempty input. False permits initial bounded
  browsing; it does not imply unbounded account search.
- `operations`: companion control methods, also used by the broker to refuse
  unsupported methods before touching custody. These include connection lifecycle
  operations, not permission to edit the provider's source content.

Only the four implemented providers are advertised: Google Drive, Gmail, Notion,
and Obsidian. The result has no account identity, credentials, endpoint, arbitrary
UI text, filesystem path, or acquisition grant. Each call returns fresh slices so
callers cannot mutate the broker's allowlist through a prior catalog value.

This is **implementation support**, not account availability. An operator may
still block a provider; app registration may be missing; consent may have expired;
provider service may be down. Clients must obtain live `status`, complete normal
consent, and use existing user-selection grants. Existing gateway checks still
apply on every operation. `--catalog` is not a tool listing, a signed receipt, a
health check, or a grant to enable account-wide assistant search.

## Host compatibility and limits

Desk consumes only its verified, revision-pinned local companion, with its normal
session and local/external configuration guards. It allows five seconds and 32 KiB
for discovery, with at most 32 providers and 16 distinct operations each. Version
and protocol shape are validated before display. Unknown provider IDs or protocol
combinations are not executed; a compatible older UI may omit a newer provider.

The catalog is not an extension loading mechanism. Labels, icons and handlers
remain shipped UI code; adding a provider still requires tested gateway behavior
and an appropriate host handler. Changing a selection protocol requires a new
recognized protocol identifier or catalog version, not silently reusing a name.

No fallback to a guessed catalog follows a command failure. Host cancellation,
malformed responses, unsupported versions, duplicate identifiers, over-budget
output or a failed process make discovery unavailable. The command's static output
is currently well below the stated budget.

## Validation

Gateway tests cover discovery with invalid publisher data and no state directory,
refusal of mixed command modes, unchanged filesystem, fresh descriptor ownership,
and unsupported-method refusal before custody. Existing provider fixture tests
exercise the advertised protocols. Desk separately tests the process boundary,
output/time bounds, authentication, external-gateway refusal, compatibility,
revoked capabilities, stale asynchronous replies and menu stability. No live
provider account or OAuth acceptance is implied by these fixture checks.
