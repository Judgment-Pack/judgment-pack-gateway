# Personal storage file management

Status: shipped in v0.4.0 (#166). The creation of a Google Doc from a Word file
([below](#a-google-doc-made-of-a-word-file)) came after that release and is in none yet.

The `gateway-connections` private pipe supports browsing and explicitly requested
file changes for Google Drive, Amazon S3 and the existing local Obsidian connection.
This is a **personal host control plane**, separate from the engine's `/acquire`
and `/act` interfaces. It does not mint evidence receipts or action receipts, does
not accept a judgment as permission, and is not an autonomous job executor. The
Desk host authenticates its caller and owns the user interaction. It must never
expose `files-commit` as an assistant tool. Other local programs running as the
same OS principal are inside this trust boundary; a typed string is not a signed
human-consent proof against such programs.

Catalog v3 advertises five additive operations for these three providers, and a
sixth, `files-prepare-google-document`, for Drive alone. The storage controls
left the legacy catalog, attachment operations, signed acquisition formats and
frozen conformance corpus unchanged. ADR-0010 has since changed Drive's entry in
the catalog and how a Drive file is chosen. No credentials or upstream cursors
reach the browser. S3's and the vault's scope restrictions remain in force.
Drive's scope is the whole of the connected Drive, as
[ADR-0010](../adr/0010-a-drive-connection-is-of-the-whole-drive.md) decides.

## Operations

All calls use the existing `{id, method, params}` JSON-line protocol. Each returns
`{id, result}` or `{id, error}`. The authenticated Desk relay exposes the same
method through `POST /api/connections/<provider>/<method>`.

| Method | Parameters | Result |
| --- | --- | --- |
| `files-list` | `folder`, `query`, optional `pageToken` | `items`, connection `context`, opaque `nextPageToken`, `scope`, `searchMode`, `truncated` |
| `files-read` | `id`, exact listed `revision`, listed `context` | `file` metadata and `contentBase64` |
| `files-prepare` | `action` (`create`, `update`, `delete`), target fields below | Reviewable, expiring change plan; no file content mutation |
| `files-prepare-google-document` | Drive only: `context`, `folder`, `name`, `mediaType`, `contentBase64` | The same kind of plan, for a Google Doc made of a Word file; see [below](#a-google-doc-made-of-a-word-file) |
| `files-commit` | plan `id`, exact `confirmation` for deletion | Durable plan status; no replay of a claimed mutation |
| `files-status` | plan `id` | The stored status, without retrying the change |

Every read/change must carry the opaque connection `context` from its file/list
response. Disconnect/reconfigure invalidates it even if two locations happen to
contain the same filename and bytes. It is a generation marker, not a credential.

Create takes that `context`, `folder`, a single-component `name`, `mediaType`, `contentBase64`.
Update takes `id`, the read `revision`, `mediaType`, `contentBase64`; renaming is
not part of update. Delete takes `id` and `revision`, and no content or media type.
Plan metadata includes its target, name, revision, size, effect (`write`, `trash`,
`delete`), expiration and confirmation text. States are `prepared`, `completed`,
`refused`, `needs-attention`. Plans expire after five minutes before commitment.

A browse returns at most 24 entries. File reads/uploads are limited to 4 MiB.
Ordinary pipe replies remain at most 64 KiB. File-list replies allow 512 KiB
for JSON escaping of bounded names and keys; file-read replies allow 6 MiB
to carry base64. Only the two requests that carry a file, `files-prepare` and
`files-prepare-google-document`, have the larger request bound.
Metadata and payload validation reject unknown fields and duplicate JSON keys.

## Discovery budgets

- **Drive:** one indexed `files.list` request per page, with a partial field mask,
  24 items and escaped `fullText contains`/parent predicates. The listing is of
  the whole of the connected Drive, under the scope `drive` that the person
  consented to at connection, and answers with the `scope` `account-files`. No
  scope is asked for that ADR-0010 does not name. Native Google
  documents may be listed and moved to trash when permitted; their editor is the
  source application. This API edits ordinary uploaded files, not Docs/Sheets.
  A listing without search words asks Drive for its order `folder,name`, and
  gives the items as Drive gave them. A search by words asks for no order,
  because Drive refuses one for it, and comes in the order Drive gives it,
  which Drive's refusal says is of relevance.
- **S3:** one bounded ListObjectsV2 page within the configured bucket/prefix.
  The folder field is a literal prefix; use a trailing slash for directory-like
  selection. Name terms filter the returned page; an empty page with a cursor
  does not mean that later pages have no matches. No object download during search.
- **Local:** metadata-only directory iteration. Name searches may descend into
  nonhidden folders, with at most 256 entries examined per call, 256 queued
  directories, depth 24 and 10,000 entries over a browse. A limit reports
  `truncated`; refine the folder/query. Symlinks, hidden paths and special files
  are excluded. The connection still requires an existing `.obsidian` vault.

Only one browse is retained per provider process. Its opaque cursor is bound to
query, folder, connection generation and a five-minute lifetime. A new search,
process restart or expired cursor requires restarting the browse. The UI replaces
pages instead of retaining an unbounded list. No periodic crawl or LLM scan runs.

## Changes, consent and uncertain outcomes

Preparation stores the exact target, base revision, payload and connection
generation in a private atomic file. Only one pending/recent plan is retained per
connection: this is recovery state, **not a historical audit log**. A new plan
invalidates an earlier uncommitted plan. Preparation of Drive creates reserves a
file ID but does not create a file.

Commit requires the same connection generation and, for deletion, the exact
filename (Drive/local) or full object key (S3). A host must collect this in a
user confirmation dialog; an assistant's proposed text or a standing job setting
is not consent. The claim is durably recorded before sending a mutation. A second
commit for that ID returns its state; it never sends the operation again. Provider
requests are not automatically retried. Completed/refused/uncertain records drop
the uploaded payload. A crash may retain the prepared payload until replacement
or connection-state cleanup; treat the connection-state directory as sensitive.

- **S3:** creates use `If-None-Match: *`; updates and deletes use `If-Match` with the
  reviewed ETag. Conflicts are refused. Writes require separately granted
  `s3:PutObject` or `s3:DeleteObject` on the selected prefix; the application does
  not change IAM. Read/browse needs `s3:GetObject` and `s3:ListBucket`. KMS-encrypted
  objects may require the corresponding KMS permissions. No object version ID is
  supplied to delete: versioned buckets use their normal delete-marker behavior;
  unversioned deletion can be permanent.
- **Drive:** updates/trash require a strong ETag and send `If-Match`; a missing
  version lock refuses the change (`conditional-write-unavailable`). Version,
  filename and capability changes are checked again before mutation. Deletes set
  `trashed=true`; they never call permanent deletion. Creates use the reserved ID.
- **Local:** creates are exclusive. Updates recheck the content digest and retain
  the previous bytes under `.jpack-history/<plan-id>` before atomic replacement.
  Deletes move the file to `.jpack-trash/<plan-id>/<name>`. These hidden directories
  are excluded from browsing. Local filesystem rechecks cannot provide atomic CAS
  against independent external editors; there remains a check/rename race. Existing
  files should not be concurrently modified outside Desk during a change. No
  recursive folder deletion or automatic trash/history cleanup is provided.

Transport failure, unexpected provider response or loss of the durable completion
record is `needs-attention`, not an invitation to retry. `files-status` does not
probe/reconcile the provider. Inspect the source before starting another change.
If the process crashed with an executing claim, new plans are refused for that
connection generation; after inspecting the source, reconnect to reset custody.
Never reconnect automatically to bypass an uncertain claim.

## A Google Doc made of a Word file

`files-prepare-google-document` prepares the creation of a Google Doc from a Word
file, by Drive's own conversion. It is the one change that makes a native Google
document, and it is Drive's alone: S3, a local vault and every other provider
refuse the method, and the catalog lists it for Drive only. A host that does not
know the method never calls it. `files-commit` and `files-status` are the same
calls as for any plan.

**The request** has five members and no others: the `context`, a `folder` that may
be empty, a single-component `name`, a `mediaType` and `contentBase64`. It has no
`action`, no `id` and no `revision`, since it creates and nothing else. It is
refused

- as `unsupported-file` unless the media type is exactly
  `application/vnd.openxmlformats-officedocument.wordprocessingml.document` and the
  file begins with the four bytes an archive begins with, `PK`, 0x03, 0x04. Nothing
  more of the file is read. Whether it is a Word file Drive can convert is Drive's
  to say, at the commit;
- by the rules every create has: the 4 MiB bound on the file (`file-too-large`),
  the name (`invalid-request`), a folder that is a folder and takes children
  (`unsupported-file`), and the connection the `context` names (`source-changed`);
- as `invalid-request` where it has any other member.

`files-prepare` takes no such request. Its plan and its stored record have a member
`convertTo` only where the plan is of a conversion, and a `files-prepare` that
carries the member is refused.

**The plan** is a create whose `convertTo` is `"google-document"`, so that a person
sees what the file becomes before they confirm. Its `target` is empty. Preparing it
asks Drive for no ID, and with no folder it asks Drive nothing at all.

**No ID is reserved, because Drive takes none.** Every other Drive create sends an
ID reserved beforehand, which is what makes a lost answer safe to reason about.
Drive's documentation says that pre-generated IDs are not supported for the
creation of Google Workspace files, nor for an upload that asks for a conversion.
So this create is the one Drive change that has no name until Drive has made it.
What that costs is under *What is not known*, below.

**The commit** is one upload. Its metadata names the document, its folder if it has
one, and the media type `application/vnd.google-apps.document`, which is how Drive
is asked for the conversion. It carries no ID. The file is sent under the Word
media type. The answer is asked for its `id` and its `mimeType`, and

| Drive answers | The plan |
| --- | --- |
| 200 or 201, an ID, and the media type of a Google Doc | `completed`; `target` is the ID |
| 200 or 201, an ID, and any other media type or none | `needs-attention`, `conversion-unconfirmed`; `target` is the ID |
| 403 | `refused`, `permission-required` |
| 409 or 412 | `refused`, `source-changed` |
| anything else, an answer that cannot be read, or no answer | `needs-attention`, `operation-uncertain`; `target` is empty |

`conversion-unconfirmed` says that Drive made a file and did not say it is a Google
Doc. The file exists and is named by the plan's target. A person looks at it and
decides what to do with it; the controls do not remove it.

**What is not known.** Where the answer is lost, the controls do not know whether a
document was made, and have no ID to look for. The plan is `needs-attention` like
any uncertain outcome, the commit is never sent again, and new plans are refused
for the connection until a person has looked and reconnected. Here the person has
less to go on than for any other change: they look in the folder for a document of
that name. Preparing the same document again after that makes a second document if
the first was made.

**What is made** is a native Google document. The controls then treat it as they
treat any: it can be listed and moved to trash where Drive permits, and it is read
and edited in Google Docs, not here. Its name is the name given; whether Drive
keeps an extension written in the name was not tried. The scope stays `drive.file`,
under which an application creates files and sees the ones it created.

**An earlier release does not read the plan.** A stored record is decoded
strictly, so a release that does not know `convertTo` takes the record of a
conversion for one it cannot read, and refuses new plans until an operator has
looked, as for any such record. That matters only where a gateway is put back to an
earlier release while the record of a conversion is the one stored.

**None of this was tried against a Google account.** The tests use a stand-in for
Drive. That Drive converts a Word file this way, that it answers with the media
type of what it made, and what it does with a file it cannot convert are read from
Drive's documentation and are assumptions until someone tries them. Drive's own
limits on what it converts are not stated on the page read, and are not checked
here.

## Verification and limits

Tests use temporary local vaults and TLS provider fakes, including independent
SigV4 verification of S3 payloads and conditional headers, Drive multipart bodies,
wrong delete confirmations, stale revisions, reconnects, crash/replay and bounds,
and the metadata, the single upload and the answers of a create by conversion.
They do not establish live Google/AWS account behavior. The Drive missing-ETag
refusal is retained until determination 4 of ADR-0010 is built, which holds a
change of a Drive file to the file's version in its place.

One try against a live Drive account, on 2026-09-29 and under a `drive.file`
grant, recorded these three observations:

- Drive refused a search by words that asked for an order (status 403, "Sorting
  is not supported for queries with fullText terms"). Every search by words was
  answered `provider-unavailable` until the order was left out of it.
- A file's metadata came with no ETag. Every update and every move to trash was
  therefore refused with `conditional-write-unavailable`, for a file that the
  listing called editable and deletable. On that account the controls could make
  a file and read one, and could change none.
- A file's version moved in the seconds after the file was made. A read and a
  change prepared at once were refused with `source-changed`; the same read
  twenty seconds later was answered.

It was one account and one day, and establishes nothing of another.

References: [Drive search](https://developers.google.com/workspace/drive/api/guides/search-files),
[Drive upload](https://developers.google.com/workspace/drive/api/guides/manage-uploads),
[Drive scopes](https://developers.google.com/workspace/drive/api/guides/api-specific-auth),
[S3 conditional writes](https://docs.aws.amazon.com/AmazonS3/latest/userguide/conditional-writes.html),
[S3 conditional deletes](https://docs.aws.amazon.com/AmazonS3/latest/userguide/conditional-deletes.html).

### Review hardening

Local changes, including deletion, require a content digest obtained by reading
at most 4 MiB; a browse-only metadata revision cannot authorize a mutation.
Larger local files remain browseable but are changed in the source application.
Unreadable or malformed prior operation records block preparation. Executing or
uncertain records block new changes in the same connection generation even if
the host loses its recovery hint. Repair of corrupt local state requires explicit
operator inspection; it is never treated as proof that no write happened.
Stored status and settled commit replay do not contact the provider or refresh
its credentials. They still require the original local connection generation.
