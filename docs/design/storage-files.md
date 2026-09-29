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

Every read and every prepared change must carry the opaque connection `context`
from its file/list response. Disconnect/reconfigure invalidates it even if two
locations happen to contain the same filename and bytes. It is a generation
marker, not a credential. `files-commit` and `files-status` take a plan's `id`
and no `context`: the plan is held to the connection it was prepared under.

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
`files-prepare-google-document`, have the larger request bound: the line of one
is at most 6 MiB, and the line of any other request at most 64 KiB, counted
without the line's ending. A longer line is refused as `invalid-request` where
the pipe reads it. The pipe reads 6 MiB and three bytes of a line, its ending
counted, and 6 MiB and two of a last line that has no ending. A line with more
is not read to its end: the pipe ends, and that request has no answer. All of
this is of a line that is a request. A line that is no JSON, or whose `id` is
longer than 64 bytes, ends the pipe whatever its length.
Validation of a method's parameters rejects unknown fields and duplicate JSON
keys, and takes a member by its name as written: one named in another case is
refused, as of #185. It takes `null` for a value left out, except in
`files-prepare-google-document`, whose members are strings. The envelope around
the parameters is held to none of these rules.

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
file ID but does not create a file. A create by conversion reserves none
([below](#a-google-doc-made-of-a-word-file)).

Commit requires the same connection generation and, for deletion, the exact
filename (Drive/local) or full object key (S3). A host must collect this in a
user confirmation dialog; an assistant's proposed text or a standing job setting
is not consent. The claim is durably recorded before sending a mutation. A second
commit for that ID returns its state; it never sends the operation again. That
holds of a commit that finds its plan claimed by another process in the moment
before its own claim: it answers with what is stored of the plan, and not that
the plan expired. Provider
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
  `trashed=true`; they never call permanent deletion. Creates use the reserved ID,
  except a create by conversion, which has none.
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

**Let a commit end before anyone looks.** `files-status` reports a plan that was
claimed and has not settled as `needs-attention`, and it reports it so whether
the process that claimed it has ended or is still sending. A look at the source
while a request is outstanding shows what is there at that moment, and not what
the request will leave. So a host

- knows of every commit it started, and lets each end before it tells a person
  to look. The pipe gives a request fifty seconds;
- does not take the end of its own process, or a cancelled request, for the end
  of the provider's work on what was sent;
- keeps what it needs to look by, the account, the folder, the name, the plan's
  ID and the target where the plan has one, before it reconnects. Reconnecting
  puts the plan's status out of reach, and the next plan replaces its record. A
  commit that ends after that cannot record what it made: its answer is
  `operation-uncertain`, and the ID the provider gave it is lost.

## A Google Doc made of a Word file

`files-prepare-google-document` prepares the creation of a Google Doc from a Word
file, by Drive's own conversion. It is the one change that makes a native Google
document, and it is Drive's alone: S3, a local vault and every other provider
refuse the method, and the catalog lists it for Drive only. A host that does not
know the method never calls it. `files-commit` and `files-status` are the same
calls as for any plan.

**The request** has four members that are required, `context`, `name`,
`mediaType` and `contentBase64`, and one that may be left out, `folder`. It has
no others: no `action`, no `id` and no `revision`, since it creates and nothing
else. Each member is a JSON string and is named exactly, so `Name` is not
`name` and `null` is not a folder.

- `name` is what the document is to be called: 1 to 250 bytes of UTF-8, with no
  control character, no `/` and no `\`, and neither `.` nor `..`.
- `folder` is a Drive ID and not a folder's name: 1 to 200 of the letters, the
  digits, `_` and `-`. It may be empty, which is the same as leaving it out.
- `contentBase64` is the file in base64 with its padding. A carriage return or
  a line feed within it is passed over, and any other character that is not
  of base64 refuses the request.

The request is refused

- as `invalid-request` where a required member is missing, where it has any
  other member, or where a value is not a string;
- as `unsupported-file` unless the media type is exactly
  `application/vnd.openxmlformats-officedocument.wordprocessingml.document` and the
  file is framed as a Word file is, which the next paragraph states;
- by the rules every create has: the 4 MiB bound on the file (`file-too-large`,
  which is also the word for content that is not base64), the name and the
  folder's ID (`invalid-request`), a folder that is a folder and takes children
  (`unsupported-file`), and the connection the `context` names
  (`source-changed`). A request whose text is not UTF-8, or holds half of a
  surrogate pair, is `invalid-request` as for every method.

**What is checked of the file** is its framing, and no more. The file begins with
the four bytes an archive's first entry begins with, `PK`, 0x03, 0x04. It ends
with an archive's end record, whose comment runs to the last byte of the file. And
it holds the name `[Content_Types].xml`, which every package of this kind has. No
entry is read and nothing is decompressed. This is a test of three signatures
and not of an archive or a package. It keeps out some of what is no Word file,
so that no upload is spent on it: text, a file whose end was cut off, a file
with bytes before its first entry or after its end record. It admits whatever
holds the three: a spreadsheet sent under a Word file's media type, a package
whose entries are damaged, and 45 bytes that are no archive at all. It may keep
out a file that some reader takes for a Word file, one with a byte after its
end record for instance. What Drive makes of a file that is admitted, or would
have made of one that is refused, is Drive's to say and was not tried.

`files-prepare` takes no such request. Its plan and its stored record have the
members `convertTo`, `folder` and `providerStatus` only where the plan is of a
conversion, and a `files-prepare` that carries a member `convertTo`, whatever its
value, is refused.

**The plan** is a create whose `convertTo` is `"google-document"`, so that a person
sees what the file becomes before they confirm. Its `target` is empty. Its
`folder` is the folder the request named, and is absent where the request named
none: Drive's reference says that a file created with no parent "is placed
directly in the user's My Drive folder". Preparing the plan asks Drive for no
ID, and with no folder it asks Drive's files nothing. A token that is about to
expire is renewed first, as for any call.

**No ID is reserved, because Drive takes none.** Every other Drive create sends an
ID reserved beforehand, which is what makes a lost answer safe to reason about.
Drive's documentation says that pre-generated IDs are not supported for the
creation of Google Workspace files, nor for an upload that asks for a conversion.
So this create is the one Drive change that has no name until Drive has made it.
What that costs is under *What is not known*, below.

**The commit** is one upload. Its metadata names the document, its folder if it has
one, and the media type `application/vnd.google-apps.document`, which is how Drive
is asked for the conversion. It carries no ID. The file is sent under the Word
media type. The answer is asked for its `id` and its `mimeType`, and each is read
on its own, so that one that cannot be read does not lose the other.

The table is of a commit that sent the upload and recorded what came of it.

| Drive answers | The plan |
| --- | --- |
| 200 or 201, an ID, and the media type of a Google Doc | `completed`; `target` is the ID |
| 200 or 201, an ID, and any other media type, one that is no string, one given twice, or none | `needs-attention`, `conversion-unconfirmed`; `target` is the ID |
| 403 | `refused`, `permission-required` |
| 409 or 412 | `refused`, `source-changed` |
| any other status; or 200 or 201 with no ID that can be read, with an ID given twice, with an ID that is a part of the access token, or with an answer in which the token can be read | `needs-attention`, `operation-uncertain`; `target` is empty; `providerStatus` is the status, where it is three digits |
| an answer longer than 64 KiB, one that cannot be read to its end, or none | `needs-attention`, `operation-uncertain`; `target` is empty |

The last row comes first: an answer that cannot be read whole is that row
whatever its status, a 403 included. The two members are read by their exact
names, `id` and `mimeType`, and whatever else the answer holds is not read for
them.

**The token and the ID.** The ID of a conversion is whatever the answer says it
is, so an answer that repeated the access token could put it in a plan. No ID is
taken from an answer in which the whole token can be read, as the answer is
written or in any string or name of it once decoded, nor where the ID is itself
a part of the token. That is all this holds. An ID that holds a part of the
token and something else is taken, and so is one that holds the token in other
letters. It is a guard against an answer that repeats the token, and no defence
against a provider that means to pass it on: an ID is up to 200 characters of
the provider's choosing. It has a cost. A file's ID that happens to be a part
of the token is refused with the rest, and the plan of a document that was made
then needs attention and names no target.

Three things are outside the table:

- A commit can end before it sends. Then it answers with an error and no plan,
  as any call does, or the plan is `refused` under `canceled` or
  `blocked-by-policy`: the connection changed, or policy did, after the claim.
- A commit that sent the upload and cannot record what came of it answers with
  the error `operation-uncertain` and no plan. What `files-status` says after
  that goes by the connection first and then by what is stored.
  - A call that cannot be answered at all has the error any call has:
    `connect-required` where there is no connection, `blocked-by-policy`,
    `private-storage-unavailable`.
  - Where the connection is not the one the plan was prepared under, because
    it was made again, or where the record was replaced by another plan's:
    `selection-expired`, whatever came of the upload.
  - Where the connection is the same and the record of the claim is still the
    one stored: `needs-attention`. The ID Drive answered with is lost.
  - Where the connection is the same and the record of the outcome was
    written, the failure having come after, in making it durable: the plan as
    it settled, with its target.
- That 403, 409 and 412 mean that nothing was made is read from what those
  statuses mean. It was not tried.

`providerStatus` is what Drive said and not what the controls know. It is a hint
for the person who looks and not a cause that was established: the controls read
no reason out of the answer, and a 404 may be of a folder that has gone or of
one the connection may not see. The plan is `needs-attention` for every status
of this row, 4xx and 5xx alike: that a 4xx means nothing was made is likely, and
is not something the controls have seen Drive keep to.

`conversion-unconfirmed` says that Drive's answer gave an ID the controls take,
and did not give the media type of a Google Doc once and as a string, which is
the table's rule. The plan's target is that ID. The answer is asked for an ID
and a media type and for nothing else: that a file of that ID is there, and
where, is taken on trust and was not looked at. A person looks at it and
decides what to do with it. The controls do not remove it, and while the plan
stands they refuse every new plan for the connection, the trashing of that file
included: it is removed in Drive, or through the controls after the person has
looked and reconnected. That is more than the outcome needs, since the ID is
known. It is the one rule the controls have for a plan that needs a person.

**What is not known.** Where the answer is lost, the controls do not know whether a
document was made, and have no ID to look for. The plan is `needs-attention` like
any uncertain outcome, the commit is never sent again, and new plans are refused
for the connection until a person has looked and reconnected. Here the person has
less to go on than for any other change. The plan's status gives the `name` and
the `folder`, and the person looks there for a document of that name, after the
commit has ended ([above](#changes-consent-and-uncertain-outcomes)). A name is
not an ID: Drive's reference says of a name that it "isn't necessarily unique
within a folder". So a document of that name may be an earlier one. That none
is there does not show that none was made: what Drive shows, and when, was not
tried. Preparing the same document again and committing it makes a second
document if the first was made.

**What is made.** What is asked for is a native Google document of the name given,
in the folder given. What is checked is that Drive answered with an ID and with
the media type of a Google Doc. Nothing checks the name Drive gave the document,
where Drive put it, or what it holds, and whether Drive keeps an extension
written in the name was not tried. The controls then treat the document as they
treat any native one: it can be listed and moved to trash where Drive permits,
and it is read and edited in Google Docs, not here. The scope stays `drive.file`,
under which an application creates files and sees the ones it created.

**An earlier release does not read the plan.** A stored record is decoded
strictly, so a release that does not know the members of a conversion's plan
takes its record for one it cannot read. It answers neither `files-status` nor
`files-commit` for it and refuses new plans, and reconnecting does not help,
since the record is read before it is replaced. That matters only where a
gateway is put back to an earlier release while the record of a conversion is
the one stored, and reading the plan's status does not change the record. The
way out has three steps, with the later release put back. Read the plan's
status and look at Drive. Where the plan needs attention, reconnect. Then
prepare an ordinary change, which need not be committed: its record takes the
place of the conversion's, and an earlier release reads it.

**What a desk does with the method is not established here.** The relay named
under [Operations](#operations) is another program. That it passes this method,
shows the plan's new members to a person, and takes a request of this size is
for that program to show.

**None of this was tried against a Google account.** The tests use a stand-in for
Drive. That Drive converts a Word file this way, that it answers with the media
type of what it made, what it does with a file it cannot convert, where it puts
a file with no parent, and what its statuses mean for whether a file was made
are read from Drive's documentation and are assumptions until someone tries
them. Drive's own limits on what it converts are not stated on the page read,
and are not checked here.

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
[Drive files reference](https://developers.google.com/workspace/drive/api/reference/rest/v3/files),
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
