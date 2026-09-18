# Personal Gmail connections through the gateway

Status: in progress; separate from the reviewed Drive implementation.

Gmail shares the gateway-owned OAuth lifecycle, private storage safeguards and
selected-resource grants. Consent, tokens, refresh, revocation and provider API
calls stay in the adapters module. A separate provider namespace isolates Gmail
from Drive credentials, grants and connection epochs. Desk owns Admin controls and
a compact message-search/selection dialog opened from the chat + menu.

The initial scope is read-only email search and explicit message selection. The
fixed OAuth scope is `gmail.readonly`; no send, draft, delete, label or mailbox-write
operation is exposed. This scope permits mailbox-wide reading at Google; the UI
must explain it, rather than claim Google's permission is limited to selections.
Only selected messages become chat attachments. Search result previews remain in
the picker and are not automatically provided to an assistant.

Search uses bounded `users.messages.list` followed by metadata reads. Selection
mints short-lived single-use grants bound to the current personal connection and
message IDs. `adapter-gmail` retrieves selected messages, emits a plain-text
message export with source identity/version and bounded extraction, and returns
it through the same signed HTTP acquisition and independent Desk verification
used for Drive. Remote images and message markup are never executed. Downloading
separate mail attachments is outside this initial slice.

The initial deployment remains personal Linux/macOS. Explicit external gateways
never fall back to local credentials. A shared enterprise connection needs an
identity/policy service; a local UI toggle is not that service. Google Workspace
administrators may separately restrict OAuth applications. App registration must
enable Gmail API and the appropriate consent scope. Live sign-in/retrieval needs
operator registration and consent; synthetic provider tests do not prove it.

References checked 2026-09-18:
- https://developers.google.com/workspace/gmail/api/auth/scopes
- https://developers.google.com/workspace/gmail/api/reference/rest/v1/users.messages/list
- https://developers.google.com/workspace/gmail/api/reference/rest/v1/users.messages/get

Google revocation is project-wide, even across OAuth client IDs. Local provider
namespaces prevent token/grant confusion but cannot change Google's revocation
semantics. Admin warns before disconnecting; another connection may need sign-in
again when registrations share a Cloud project. Requests explicitly disable
incremental scope inclusion and refuse an unexpected returned scope. Separate
Cloud projects are required when an operator needs independent upstream revocation.
See https://developers.google.com/identity/protocols/oauth2/web-server#tokenrevoke .

The adapters module adds golang.org/x/net v0.59.0 (HTML tokenizer and charset
reader) and its golang.org/x/text v0.42.0 dependency. They convert bounded email
bodies into text without executing markup or fetching resources. Neither signer
module nor receipt verification depends on these packages. Review impact includes
dependency and security.

Search returns an opaque connection context. Selection must echo it, and the
gateway verifies it atomically before issuing grants. Disconnect, reconnect, or
account changes invalidate old search results even if Desk has not polled status.
