# Personal Drive connections through gateway companions

Status: shipped in v0.3.0 (#139). The scope, and how a file is chosen, are as
[ADR-0010](../adr/0010-a-drive-connection-is-of-the-whole-drive.md) decides.

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
and one-time consumption. The consent asks for the scope
`https://www.googleapis.com/auth/drive`, the whole of the person's Drive to read
and to change, and for no other; a token that Google says is of another scope is
refused. It asks for no chooser of Google's, and the Picker API is not used.
Tokens never reach Desk. The source described here reads files and changes
nothing; the changes the scope permits are the
[storage controls'](storage-files.md), each on a person's confirmation.

What a consent was for is recorded when it is given, in `consent.json` beside
the state: the connection, a digest of the refresh token, a digest of the
access token, and the scope. It is written again at every renewal, under the
lock the state is written under. The state itself is not changed, so that an
earlier release reads it. Every request that needs Drive under the tokens the
custody holds is held to that record, and not to what a renewal of the token
says, which need not name a scope. The one request made under a token the
custody does not yet hold is the consent's own: the callback asks Drive who
the account is, under the token the consent just gave, before anything is
written. A connection without a record of a consent for `drive` for the tokens
it holds is answered `reconnect-required` from its first such request, and
Drive is asked nothing under its token. That is every connection made under
the scope `drive.file` that earlier releases asked for; a connection whose
tokens another put in place of what the record names, an earlier release's
consent or renewal after a rollback of the desk's managed install among them;
and a connection that a process renewed and ended before it wrote the record.
The person connects again. A consent that gives no refresh token of its own
keeps the earlier one only where that one is recorded as of `drive`, since a
refresh token renews to tokens of the consent that gave it; otherwise the
consent is refused with `reconnect-required` and the person consents again.
A process that holds a snapshot of the connection from before another process
renewed or remade it is not refused for that: it looks again at what is held,
before a renewal where the record is not of its snapshot, and after a renewal
that Google refused where another process's renewal was given a new refresh
token in the meantime. A renewal that Google refuses for another reason is
answered `reconnect-required`, as it was.

An earlier release, run against this custody after a rollback, ignores the
record. It uses a token of the whole Drive for as long as the token lasts and
takes a renewal that names no scope; it cannot narrow or revoke what the
person consented to, and only Google's account page or `disconnect` does. It
refuses a renewal that names `drive`, and its `connect` asks for `drive.file`
again. `status` does not say any of this: it says `connected` of any
connection that is held, as it did, and `select` needs nothing of Drive and
answers as before. To disconnect removes the record.

A persisted authorization epoch survives the disconnected state. Disconnect and
configuration changes invalidate callbacks from every companion for that principal.
Token refresh runs outside the private state lock, then commits only if its epoch
and connection still match, so a slow provider cannot block local disconnect.

`search` takes `{ "query": "words" }` and answers with at most twenty files of
the connected Drive: with words, what Drive finds for them, in the order Drive
gives them, and no order is asked; with none, what was changed last. It names
no `corpora`, so what is searched is what Drive searches when none is named.
It offers a file that `adapter-drive` would take by what Drive says of it: one
of the kinds that are read and no folder, with a name that is not empty, has at
most 250 bytes and no control character, that may be downloaded, and, unless
it is a document of Google's own, of more than no bytes and at most 4 MiB. A
document of Google's own has no size until it is exported, so one that a
search offers may still be refused by the read for its size. Each file has its
`id`, its name as `title`, held to 128 characters and cleared of the marks
that set the direction of text (Unicode's `Bidi_Control`), an address made of
the ID, and the media type as `description`. `more` says that there may be
more than was given: Drive named a further page, or said that its search was
not complete. A search has no second page, and is narrowed by its words. The
answer carries a `selectionContext`.

`select` takes `{ "resourceIds": ["id"], "selectionContext": "context-from-search" }`,
of at most four files, and answers with `{ "resourceId", "grant" }` for each.
It takes any file's ID, one a search gave or another: what a grant says is that
the host asked to read that file, and nothing of who chose it. A selection
creates short-lived random read grants, scoped to a selected
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

References checked 2026-09-18, and the scopes on 2026-09-29:
- https://developers.google.com/workspace/drive/api/guides/api-specific-auth
- https://developers.google.com/identity/protocols/oauth2/native-app
- https://developers.google.com/workspace/drive/api/guides/manage-downloads
