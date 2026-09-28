# Personal storage file management

Status: implemented locally; material review is required before merge.

The `gateway-connections` private pipe supports browsing and explicitly requested
file changes for Google Drive, Amazon S3 and the existing local Obsidian connection.
This is a **personal host control plane**, separate from the engine's `/acquire`
and `/act` interfaces. It does not mint evidence receipts or action receipts, does
not accept a judgment as permission, and is not an autonomous job executor. The
Desk host authenticates its caller and owns the user interaction. It must never
expose `files-commit` as an assistant tool. Other local programs running as the
same OS principal are inside this trust boundary; a typed string is not a signed
human-consent proof against such programs.

Catalog v3 advertises five additive operations for these three providers. The
legacy catalog, attachment operations, signed acquisition formats and frozen
conformance corpus remain unchanged. No credentials or upstream cursors reach
the browser. Existing provider scope restrictions remain in force.

## Operations

All calls use the existing `{id, method, params}` JSON-line protocol. Each returns
`{id, result}` or `{id, error}`. The authenticated Desk relay exposes the same
method through `POST /api/connections/<provider>/<method>`.

| Method | Parameters | Result |
| --- | --- | --- |
| `files-list` | `folder`, `query`, optional `pageToken` | `items`, connection `context`, opaque `nextPageToken`, `scope`, `searchMode`, `truncated` |
| `files-read` | `id`, exact listed `revision`, listed `context` | `file` metadata and `contentBase64` |
| `files-prepare` | `action` (`create`, `update`, `delete`), target fields below | Reviewable, expiring change plan; no file content mutation |
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
Ordinary pipe replies remain at most 64 KiB; only file-read replies may reach
6 MiB to carry base64. Only file-prepare requests need the larger request bound.
Metadata and payload validation reject unknown fields and duplicate JSON keys.

## Discovery budgets

- **Drive:** one indexed `files.list` request per page, with a partial field mask,
  24 items and escaped `fullText contains`/parent predicates. Only files already
  authorized through the existing `drive.file` grant are visible. This is not
  whole-account search, and no broad scope is silently requested. Native Google
  documents may be listed and moved to trash when permitted; their editor is the
  source application. This API edits ordinary uploaded files, not Docs/Sheets.
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
  Deletes move the file to `.jpack-trash/<plan-id>-<name>`. These hidden directories
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

## Verification and limits

Tests use temporary local vaults and TLS provider fakes, including independent
SigV4 verification of S3 payloads and conditional headers, Drive multipart bodies,
wrong delete confirmations, stale revisions, reconnects, crash/replay and bounds.
They do not establish live Google/AWS account behavior. In particular, retain the
Drive missing-ETag refusal until a real connection supports conditional updates.

References: [Drive search](https://developers.google.com/workspace/drive/api/guides/search-files),
[Drive upload](https://developers.google.com/workspace/drive/api/guides/manage-uploads),
[Drive scopes](https://developers.google.com/workspace/drive/api/guides/api-specific-auth),
[S3 conditional writes](https://docs.aws.amazon.com/AmazonS3/latest/userguide/conditional-writes.html),
[S3 conditional deletes](https://docs.aws.amazon.com/AmazonS3/latest/userguide/conditional-deletes.html).
