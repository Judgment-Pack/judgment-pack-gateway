# Personal Drive connections through gateway companions

Status: implementation in progress; requires material security/public-surface review.

Provider authorization and retrieval live in the gateway's adapters module, in
separate executables from the signer. Desk provides controls and previews, and
never receives Google access or refresh tokens. No JPS or receipt-format change.

`gateway-connections` speaks bounded JSON lines over its parent's private pipes.
Its operator supplies one principal and a private storage directory. Requests
cannot supply or override that principal, paths, endpoints, scopes, or executables.
This is a personal OS-account connection, not a shared enterprise identity issuer.
A remote/shared deployment must provide an authenticated principal mapping before
exposing this protocol; arbitrary HTTP relay of its management operations is not
supported. `--disabled` is an operator restriction which UI requests cannot undo. It updates the personal store restriction; reads
check that restriction before dispatch. Another process launched by the same OS
operator can change it. This is not an organization policy boundary.

Google Desktop OAuth client registration is operator configuration. User tokens
are kept in gateway-owned 0700/0600 storage, outside chat/project storage. The
callback uses a temporary IPv4 loopback listener, state, PKCE S256, an expiry,
and one-time consumption. Google native Picker combines consent and selected-file
access with `drive.file`; tokens never reach Desk or the Google Picker JavaScript
in its page. Google scopes permitting writes do not expose write operations here.

A persisted authorization epoch survives the disconnected state. Disconnect and
configuration changes invalidate callbacks from every companion for that principal.
Token refresh runs outside the private state lock, then commits only if its epoch
and connection still match, so a slow provider cannot block local disconnect.

A successful picker creates short-lived random read grants, scoped to a selected
file and the connection generation. `adapter-drive` consumes a grant once, refuses
expired/replayed/revoked grants, and checks the connection under the same private
store lock. It retrieves through fixed Google endpoints with redirects refused,
checks the file version before and after retrieval, and produces an HTTP-shaped
acquisition with an attachment record containing the retained original. All Google
Docs, Sheets and Slides exports in this first slice are PDFs. Download size is
bounded to 4 MiB; output is bounded to 16 MiB including retained base64 and extracted
text. Extraction uses the existing bounded parser with an explicit 25-second processing
deadline, separate from the outer retrieval deadline. No OCR executable is selected
by a caller. No automatic retry mints an additional receipt.

Disconnect removes local access immediately and attempts upstream revocation;
failure to revoke is reported, not described as successful revocation. Previously
retained evidence is not deleted. In-flight reads already dispatched may finish;
Desk discards late results after cancellation/context change.

Source extension: `provenance.source.kind = "google-drive"` with `fileId`,
`version`, and `mediaType` (the source type before export). `document.version`
matches source version. `original.retention = "inline"`, encoding `base64`, bytes
must match document ID and size. These are additions to the extensible version 1
attachment source vocabulary, not alterations to receipt semantics.

References checked 2026-09-18:
- https://developers.google.com/workspace/drive/picker/guides/desktop-mobile-picker
- https://developers.google.com/identity/protocols/oauth2/native-app
- https://developers.google.com/workspace/drive/api/guides/manage-downloads
