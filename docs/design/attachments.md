# Document attachments: the record an adapter writes, version 1

A person working in a desk attaches a document — a PDF of a policy, a scanned form, a
spreadsheet exported as text — and wants what it says available to the assistant, cited, and
covered by a receipt as any other source is. This note fixes the contract for that: what a
caller hands the gateway, and the one record the gateway attests in return. It is written
before the adapter so that a desk integration can be built against it.

It changes nothing in `SPEC.md`: no receipt member, no shape, no verifier rule. Document
processing is an adapter in the second module — a process the signer never links
([ADR-0001](../adr/0001-one-engine-four-processes.md)) and, when the operator gives it an
identity of its own, one that cannot read the seed — and the record it writes is a result like
any other: canonicalized, retained as the artifact, its digest signed into a version 3 receipt.
**What the receipt then proves is byte lineage: these bytes, returned by the source the operator
configured, at this call in this session, under this key.** It does not prove that the text is
what the document says, that the extraction is complete, or that a scanned page was read right.
The record states, for every page, what was done and what was not, and a consumer reads those
statements rather than assuming.

The contract is versioned by the record's first member, `attachmentVersion`. This is
version `"1"`. What a version promises, and what may change without a new one, is in
[Versioning](#versioning).

## The parties

- **The caller** — a desk, through its chassis — holds the document's bytes and hands them to
  the gateway as the arguments of one `/acquire` call. It keeps the bytes it handed over; the
  record binds them by digest.
- **The gateway** runs the source, canonicalizes what the adapter wrote, retains it, and mints
  the receipt. It reads nothing of the document.
- **The adapter**, `adapter-document`, reads the arguments on stdin, establishes the document's
  identity, extracts what it can within its bounds, and writes the record on stdout. It holds
  no credential in this release; retrieval from a drive, which does, is the next note.
- **An OCR program**, when the operator configures one, is a separate executable the adapter
  runs for the pages that have no text layer. The record says which pages took its answer; it
  vouches for nothing the program did.

## How it is wired

The adapter is a bare source: no `--source-shape`, so the receipt's `acquisition.shape` is
`"command"` (SPEC.md §1.2a) — the shape that opts out of the envelope's acquisition members.
The gateway names the adapter by the first word of the command as the operator configured it
(the program, without its flags) and by the digest of the file that word resolved to, read
before the process was started — a replacement of the file between that read and the start is
not detected (SECURITY.md) — sets the other nullable acquisition members to `null`, leaves
`pageItems` absent, and stamps its own `observedAt`. That is the true shape for a
document the caller supplied: there is no endpoint, no snapshot and no peer to record, and the
arguments commitment already commits to the bytes. The record carries what the adapter adds —
its own account of itself, when it read the request, which extractor it ran — inside the signed
artifact, in the clear, as the adapter's testimony.

```
gateway serve ./store gateway.seed gateway:desk ./registry.jsonl --receipt-version 3 \
  --source documents='adapter-document --max-bytes 16777216 --max-output 8388608' \
  --source-user documents=engine-documents \
  --source-max-output 8388608
```

**The adapter's identity, and the seed.** `--source-user` runs the source as another operating
system user, and that is what keeps the document parser and the OCR program away from the seed:
the gateway switches credentials only when a user is configured (`go/spawn_unix.go`), and a
source run as the signer's own user can read what the signer can, as SECURITY.md says of every
source. The engine image gives each adapter a user of its own; a deployment that runs
`gateway serve` and the adapter as one user — a desk on a single machine — has no such
separation, and the isolation this note describes is a property of the deployment that provides
it, not of the contract. State it that way in a desk's documentation.

A request:

```
POST /acquire
{"session": "…", "source": "documents", "arguments": {"document": {"name": "fswp.pdf", "mediaType": "application/pdf", "bytes": "<base64>"}}}
```

The answer is `{result, receipt, salts}` as for any acquisition; `result` is the record below.

**The request bound, stated plainly.** `/acquire` reads at most 1 MiB of body
(`maxRequestBody`, SPEC.md §6 reference implementation), and the gateway cancels a source's
context at thirty seconds. A document travels inline, base64-encoded, so until the gateway grows
operator bounds for both — `--max-request BYTES` and `--source-timeout NAME=SECONDS`, a separate
change to the core with its own review — an inline document is at most about 760 KiB, and its
processing, OCR included, is cancelled at thirty seconds; what cancelling does and does not
guarantee is in [Bounds and cancellation](#bounds-and-cancellation). The adapter's own
`--max-bytes` and `--timeout` sit under whatever the gateway allows; the record's
`processing.bounds` says which bounds applied.

## The arguments

The canonical arguments (SPEC.md §1.1) the gateway hands the adapter on stdin. Members are
exact at every level: one the adapter does not name, one given twice, or one of another type
refuses the request before anything is read.

| Member | Type | Meaning |
|---|---|---|
| `document` | object | required |
| `document.name` | string | the name the caller gives the document: 1 to 255 bytes of UTF-8, no control character (U+0000–U+001F, U+007F). A label, carried into the record as given; the adapter derives nothing from it |
| `document.mediaType` | string | the media type the caller declares: `type/subtype`, each part 1 to 127 characters, starting with a lowercase letter or digit and continuing with lowercase letters, digits and `! # $ & ^ _ . + -` (RFC 6838's restricted names, lowercase only), with no parameters. A declaration outside that syntax refuses the request. Version 1 processes `application/pdf`, `text/plain`, `text/markdown`, `text/csv` and `application/json`; any other declaration within the syntax yields a record whose processing failed with `media-type-unsupported` |
| `document.bytes` | string | the document, in standard base64 (RFC 4648 §4), padded, with no line break and every unused bit of the last group zero — the one encoding of its bytes, so that decoding and encoding again gives the same string. Empty, or anything else, refuses the request |
| `document.sha256` | string — optional | the caller's own digest of the bytes, `"sha256:"` + 64 lowercase hex. When present it must equal the digest the adapter computes, or the request is refused: a mismatch is a transport defect, not a document to record |
| `options` | object — optional | |
| `options.ocr` | string — optional | `"auto"` (default): run the configured OCR program for the pages that need it; `"never"`: run it for none, and report those pages as needing it |

**What the gateway refuses first.** The gateway reads `/acquire`'s body and parses the arguments
before it starts a source (the acquire handler in `go/serve.go`): a body past its request bound,
arguments that are not JSON, and arguments outside the canonical domain — a member name given
twice, a fraction — are answered by the gateway in its own words, and the adapter never runs.
What follows is the contract for requests that reach the adapter.

**Refusals.** A refused request is the adapter exiting 1 with one line on stderr and nothing on
stdout; the gateway then mints nothing and retains nothing. The adapter checks in this order and
refuses at the first check that fails:

1. stdin holds more than the **read bound**, 4 × ⌈`--max-bytes` / 3⌉ + 65,536 bytes — the base64
   length of a document at `--max-bytes`, plus room for the name, the media type, the digest and
   the options at their longest: `request-over-bound`;
2. the arguments are not what the arguments table admits — not a JSON object, a member missing,
   unknown, duplicated or of another type, a name or media type outside its rule, `bytes` empty
   or not its one encoding, a `sha256` not in digest form, an `options.ocr` of another value:
   `arguments-invalid`;
3. the decoded document is longer than `--max-bytes`: `document-over-bound`. A request can fit
   the read bound and still decode past the document bound, so the two are checked apart;
4. the decoded document's digest differs from `document.sha256`: `digest-mismatch`.

**An oversized inline document is refused, never recorded**, and a desk that knows the bound
refuses it before the call. Everything the adapter admits — an unsupported type, an encrypted or
malformed PDF included — is a **record**, since the document's identity is established and the
outcome is worth attesting.

The refusal line is ASCII, at most 160 bytes, and begins with its code and a colon —
`document-over-bound: the document is 1048577 bytes, past --max-bytes 1048576` — followed by
the bound or rule it names. The reference gateway, at the commit this note was written against,
answers the caller `400` with `{"error": "source failed: " + the first 200 bytes of the
source's stderr}` (`runSource` and the acquire handler in `go/serve.go`), so a line within that
length arrives whole. A failure of the adapter itself after admission — a record past
`--max-output`, an executable it cannot read — is reported the same way, under
`record-over-bound` and `adapter-failed`. A consumer treats a code it does not know as a refusal
whose reason it does not know.

**Retrying is a new acquisition.** `/acquire` is not idempotent: the same arguments sent twice
mint two receipts and two records, at two call indexes. A desk that wants one record per
document keeps the one it verified.

## The record

The result the gateway attests: one JSON object, written by the adapter in the canonical
domain — member names in code-point order, strings in UTF-8, integers only, no fractional or
exponent number anywhere, since the gateway's canonicalizer refuses those, and no integer past
2^53 − 1. Every member below is present in every version 1 record; a member without a value is
`null`, never absent, so that a record made with a capability switched off never reads the same
as one made before the member existed. The set of members below is **the version 1 set**, and it
is frozen; what may be added within version 1 is in [Versioning](#versioning).

```json
{
  "attachmentVersion": "1",
  "document": {
    "id": "sha256:3f2a…",
    "name": "fswp.pdf",
    "mediaType": "application/pdf",
    "detectedMediaType": "application/pdf",
    "size": 184320,
    "version": null,
    "encryption": null
  },
  "original": {"retention": "caller", "encoding": null, "bytes": null},
  "content": {
    "kind": "text",
    "extraction": "text-layer",
    "pageCount": 3,
    "truncated": false,
    "chars": 5410,
    "pages": [
      {"number": 1, "status": "ok", "extraction": "text-layer", "text": "Federal Skilled Worker Program\nMinimum requirements …", "chars": 2210, "unmapped": 0},
      {"number": 2, "status": "ok", "extraction": "text-layer", "text": "…", "chars": 3200, "unmapped": 0},
      {"number": 3, "status": "no-text", "extraction": "text-layer", "text": "", "chars": 0, "unmapped": 0}
    ]
  },
  "processing": {
    "status": "complete",
    "errors": [],
    "bounds": {"maxBytes": 16777216, "maxPages": 500, "maxTextBytes": 8388608, "maxInflateBytes": 67108864, "maxOcrOutputBytes": 33554432, "timeoutMs": 25000},
    "durationMs": 118
  },
  "provenance": {
    "adapter": {"name": "adapter-document", "version": "0", "digest": "sha256:9c1e…"},
    "source": {"kind": "inline"},
    "observedAt": "2026-09-16T14:05:11Z",
    "processor": "adapter-document/pdf/1",
    "ocr": null
  }
}
```

### `document` — identity

| Member | Type | Meaning |
|---|---|---|
| `id` | digest | the SHA-256 of the original bytes, as `"sha256:"` + 64 lowercase hex. **This is the document's identity**: two attachments of the same bytes have the same `id` whatever they were named, and a consumer that holds the bytes can recompute it. It is the same digest the caller may have claimed in `document.sha256`. It identifies the document, not this extraction of it: see [Identity, and what a citation binds](#identity-and-what-a-citation-binds) |
| `name` | string | as the caller gave it |
| `mediaType` | string | as the caller declared it |
| `detectedMediaType` | `"application/pdf"`, `"text/plain"` or `null` | what the bytes look like to the adapter, for the declarations it checks: `"application/pdf"` for a declared PDF whose first 1024 bytes contain `%PDF-`; `"text/plain"` for a declared text type whose bytes are valid UTF-8; `null` otherwise, and for a declaration version 1 does not process |
| `size` | integer | the original's length in bytes |
| `version` | string or `null` | a version the *source* reported for the document — a drive's file version — `null` for a document the caller supplied |
| `encryption` | object or `null` | `{"handler": string or null, "revision": integer or null, "opened": boolean}` when the adapter read a trailer that names an encryption dictionary: the dictionary's `/Filter` name as the document declares it, or `null` when that is absent or not a name; its `/R` as declared when that is an integer from −(2^53 − 1) to 2^53 − 1, the canonical domain's range, and `null` when it is absent, not an integer (a real such as `4.0` included), or outside that range; and whether the adapter opened the document. Version 1 opens only handler `Standard` at revisions 2 to 6 (RC4 and AES) with an empty user password; a document that needs a password, declares another handler or revision, or whose encryption dictionary cannot be read is not opened and fails with `pdf-encrypted`. `null` when the adapter read a trailer that names no encryption dictionary, and also when it did not get as far as a trailer — a mismatched or unsupported declaration, or a PDF that failed as `pdf-malformed` before its trailer was read — so `null` says no encryption was found, not that none exists |

### `original` — where the bytes are

| Member | Type | Meaning |
|---|---|---|
| `retention` | `"caller"` or `"inline"` | `"caller"`: the caller supplied the bytes and holds them; this record binds them by `document.id` and the receipt's arguments commitment commits to them. `"inline"`: the bytes are in this record, base64, and the retained artifact therefore holds the original — the form retrieval from a drive will use, since the caller never had the bytes. Version 1's only source kind, `"inline"`, is a document the caller supplied, so its records carry `"caller"` |
| `encoding` | `"base64"` or `null` | `"base64"` exactly when `retention` is `"inline"` |
| `bytes` | string or `null` | the original, base64, exactly when `retention` is `"inline"` |

Extracted content is never a substitute for the original. A consumer that needs the document
itself — to show it, to re-extract it with a better tool, to hand it to a person — uses the
bytes it holds (`"caller"`) or the bytes in the record (`"inline"`), checked against
`document.id`, and never the text.

### `content` — what was extracted

| Member | Type | Meaning |
|---|---|---|
| `kind` | `"text"` | the only kind in version 1 |
| `extraction` | `"text-layer"`, `"ocr"`, `"mixed"`, `"verbatim"` or `"none"` | derived from the listed pages' `extraction` values other than `"none"`: none of them — `"none"`; only `"text-layer"` — `"text-layer"`; only `"ocr"` — `"ocr"`; both of those — `"mixed"`; `"verbatim"` — `"verbatim"`. A page counts whatever its status, so a document of blank text-layer pages is `"text-layer"` |
| `pageCount` | integer | how many pages the page-tree walk found, at most `maxPages` ([step 4](#how-a-document-is-processed)); `1` for a text document that reached step 3; `0` for a document that reached neither step, or whose walk ended at a defect |
| `truncated` | boolean | `true` exactly when the page-tree walk stopped at the page bound or at the deadline ([step 4](#how-a-document-is-processed)), or fewer pages are listed than `pageCount`; `false` otherwise, a document that failed before or during the walk for any other reason included. A page that is listed but still needs OCR does not make a record truncated. **Every listed page is whole**: its `text` is the whole of what produced it, never a fragment |
| `chars` | integer | the sum of the pages' `chars` |
| `pages` | array of page objects | in page order, one per listed page, numbers ascending and distinct, never more than `pageCount` |

A page object:

| Member | Type | Meaning |
|---|---|---|
| `number` | integer | 1-based, in document order |
| `status` | `"ok"`, `"no-text"`, `"needs-ocr"` or `"failed"` | as [Page outcomes](#page-outcomes) assigns it |
| `extraction` | `"text-layer"`, `"ocr"`, `"verbatim"` or `"none"` | the method that produced this page's `text`, as [Page outcomes](#page-outcomes) assigns it |
| `text` | string | the page's text after [normalisation](#text-normalisation); `""` for every status but `"ok"`, and never `""` for `"ok"`. Glyphs the adapter could not map to Unicode are U+FFFD |
| `chars` | integer | the number of Unicode scalar values in `text` |
| `unmapped` | integer | for a `"text-layer"` page, the number of glyphs rendered as U+FFFD because their font had no usable mapping; `0` for every other page. A page with many is a page whose text is not to be trusted, and a consumer should say so rather than cite it |

### Page outcomes

Every listed page is exactly one of these, and its `status`, `extraction` and `text` follow:

| The page | `status` | `extraction` | `text` |
|---|---|---|---|
| a PDF page whose content could not be interpreted | `"failed"` | `"none"` | `""` |
| a PDF page whose text-layer text is empty after normalisation and whose content draws at least one image, with no OCR answer applied | `"needs-ocr"` | `"none"` | `""` |
| the same page, with an OCR answer applied whose text is non-empty after normalisation | `"ok"` | `"ocr"` | the answer's text |
| the same page, with an OCR answer applied whose text is empty after normalisation | `"no-text"` | `"ocr"` | `""` |
| any other PDF page whose text-layer text is non-empty after normalisation | `"ok"` | `"text-layer"` | the text |
| any other PDF page — empty text-layer text and no image drawn | `"no-text"` | `"text-layer"` | `""` |
| a text document whose text is non-empty after normalisation | `"ok"` | `"verbatim"` | the text |
| a text document whose text is empty after normalisation — a file of blank lines | `"no-text"` | `"verbatim"` | `""` |

An image is drawn when the page's content stream, or a form XObject it draws, paints an image
XObject or an inline image. A failed page's error names its number.

**What the text is, and is not.** For a PDF the text is what the extractor derived from the
content streams in stream order: the words as the fonts map them to Unicode, spaces inserted
where the glyph positions jump, line breaks where the text position moves down. Reading order
is stream order, which is usually reading order and is not always: a two-column page may read
across, a footer may come first. Hyphenation is not repaired; ligatures are mapped where the
font maps them. Whitespace is a heuristic of layout, not a fact about the document, and a
consumer matching an excerpt should fold it. Text from OCR is what the program answered. For a
text document the text is the file's characters. All three pass through the one normalisation
below, and nothing else.

### Text normalisation

Every page's text, whatever produced it, is normalised in this order, and `chars`, `text` and
the text bound are computed on the result:

1. if the first character is U+FEFF, it is removed; a U+FEFF anywhere else stays;
2. each `\r\n` becomes `\n`, and then each remaining `\r` becomes `\n`;
3. every character from U+0000 to U+0008, from U+000B to U+001F, and U+007F is removed — so
   `\t` and `\n` are the only control characters left below U+0080;
4. the text is split at each `\n` into lines; a line is **blank** when every character in it is
   U+0020 or U+0009, the empty line included; blank lines are removed from the start and from
   the end; the remaining lines are joined with `\n`. A text of blank lines only becomes `""`.

Nothing else is done: characters other than U+0020 and U+0009 are never blank, whatever
Unicode says of them; spaces inside a line are not collapsed; a line that is not blank is not
trimmed; Unicode is not recomposed. A text document that began with a blank line has lost it;
the record says the page is `"verbatim"` and this section says what verbatim means.
`testdata/attachments/normalisation-v1.json` holds input and output pairs that an implementation
of these four steps reproduces exactly.

### Identity, and what a citation binds

`document.id` says which bytes. It does not say which extraction: the same bytes under another
bound, another `options.ocr`, another deadline, another OCR program or another `processor`
yield other pages, and an OCR program's digest identifies the file the adapter read before it
started the program — not a file replaced after that read, and not what the program in turn
runs. So:

- deduplicate **documents** by `document.id`;
- bind a **citation** to the record it was taken from — the receipt's `sessionId`, `callIndex`
  and `signature`, or the artifact's `resultDigest` — then the page `number`, then the excerpt
  as text matched against that page's `text`, exactly or with whitespace folded. Never by offset
  into a concatenation the record does not carry; offsets within a page's `text` are the
  consumer's own, in whatever unit it counts, and `chars` lets it check it read the whole page;
- never expect a second acquisition of the same bytes to yield the same pages: the bounds, the
  options, the deadline, the load on the machine and the OCR program can each change them. The
  record a citation was taken from is the record to keep.

### `processing` — what was done

| Member | Type | Meaning |
|---|---|---|
| `status` | `"complete"`, `"partial"` or `"failed"` | derived from the pages and the errors: `"failed"` when no page is listed; otherwise `"complete"` when `errors` is empty and `truncated` is `false`; otherwise `"partial"`. A record lists no page only when it carries an error, so a `"failed"` record always has one, and its `extraction` is `"none"`. A document stopped after its pages were counted — its first page past the text bound, the deadline before its first page — is `"failed"` with `pageCount` above `0` and `truncated` `true` |
| `errors` | array of error objects | why the status is not `"complete"`, one entry per condition met. Their order is not part of the contract |
| `bounds` | object | the bounds that applied: `maxBytes`, `maxPages`, `maxTextBytes`, `maxInflateBytes`, `maxOcrOutputBytes`, `timeoutMs`, each an integer. A consumer that finds `truncated` reads these to know what to raise |
| `durationMs` | integer | wall time the adapter spent from reading the request to writing the record, in milliseconds |

An error object: `{"code": string, "message": string, "page": integer or null}`. `message` is
for a person, at most 512 bytes of UTF-8, and never carries the document's content; `page` is
the page the condition belongs to, or `null` for the document as a whole. The codes of
version 1, with the statuses a record carrying them can have — which follow from the status
rule above and the step that meets each code:

| Code | Statuses | Meaning |
|---|---|---|
| `media-type-unsupported` | failed | the declared media type is not one version 1 processes |
| `media-type-mismatch` | failed | the bytes are not what the declared type says: a declared PDF without `%PDF-` in its first 1024 bytes, a declared text type that is not valid UTF-8 |
| `document-over-bound` | failed | a **retrieved** document exceeds `maxBytes`; nothing past the size check was done. An inline document past the bound is refused at the request and never reaches a record |
| `document-empty` | failed | zero bytes — refused at the request, but named here for a source that fetched an empty file |
| `pdf-malformed` | failed | the reader stopped before the page-tree walk completed, for a reason other than encryption or the deadline ([step 4](#how-a-document-is-processed)) |
| `pdf-encrypted` | failed | the document is encrypted and was not opened: a user password is required, or the handler or revision is not one the adapter implements |
| `pdf-unsupported` | partial | a page's content uses a stream filter the reader does not implement; the page named is listed as `"failed"` ([step 5](#how-a-document-is-processed)) |
| `pdf-page-failed` | partial | a page's content could not be interpreted for another reason; the page named is listed as `"failed"` |
| `pdf-pages-over-bound` | partial or failed | the walk found more pages than `maxPages`; the rest were not processed |
| `text-over-bound` | partial or failed | a page's text would have taken the listed text past `maxTextBytes` ([steps 5 and 6](#how-a-document-is-processed)); the page named is the first one this stopped |
| `stream-over-bound` | partial | a stream of a page's content inflated past the per-stream or total inflate bound; the page named is listed as `"failed"`. A stream met in step 4 that does so is `pdf-malformed` |
| `timeout` | partial or failed | a check of the adapter's deadline found it passed ([How a document is processed](#how-a-document-is-processed)); what was done before it is reported |
| `ocr-not-run` | partial | pages need OCR and no program was started: none is configured, or the caller asked `"never"`. The message says which |
| `ocr-failed` | partial | the OCR program was not resolved, digested or started, exited with a non-zero status, wrote past `maxOcrOutputBytes`, or wrote an answer that [step 6](#how-a-document-is-processed) refuses. **No answer of it is applied** |
| `ocr-incomplete` | partial | the OCR program's answer was admitted and left out pages it was asked for; the message counts them, and they stay `"needs-ocr"` |
| `ocr-timeout` | partial | the OCR program was started, and the deadline had passed when the adapter took its outcome: a program not yet finished was ended, one that had finished was not, and in either case no answer of it is applied |

A consumer treats a code it does not know as an error whose class it does not know: the
status still says what the record is good for.

### `provenance` — who did it, and how

| Member | Type | Meaning |
|---|---|---|
| `adapter` | `{"name": string, "version": string, "digest": digest}` | the adapter **as it describes itself**: its name, its own version string, and the SHA-256 of the file the operating system reports as its own executable, read by the adapter at run time. This is testimony. The receipt's `acquisition.adapter` is the **gateway's** record: the first word of the command as the operator configured it, the version `""` a bare command has (`commandAcquisition`), and the digest of the file the gateway read before starting the process. They are separate readings from separate sources; nothing checks one against the other, and they need not agree — a command configured by path names the path, and a file replaced between the readings yields two digests |
| `source` | object | where the bytes came from. Version 1 has one kind: `{"kind": "inline"}`, a document the caller supplied, with no other member. Retrieval from a drive will add its own kind with its members, recorded in the changelog; a consumer reads `kind` first, and a `kind` it does not know is a source it does not know — the record is still a record, its provenance unread |
| `observedAt` | string | when the adapter had read the request in full, `YYYY-MM-DDThh:mm:ssZ`, UTC, whole seconds, by the adapter's clock. The receipt's own `observedAt` for a bare command is the gateway's stamp of when it read the output, which happens later; the two are readings of clocks at whole seconds that nothing relates, so they may be equal and a clock step can put the gateway's first. A consumer infers no order from them |
| `processor` | string or `null` | the extraction implementation and its algorithm version: `"adapter-document/pdf/1"`, `"adapter-document/text/1"`. It moves when the extractor's output for the same bytes changes. `null` when no extractor ran: an unsupported or mismatched type, a retrieved document that is empty or past the size bound |
| `ocr` | object or `null` | the provenance of **applied** OCR answers: `{"program": string, "digest": digest, "pages": array of integers}` — the program as configured, the SHA-256 of the file that name resolved to, read by the adapter before starting it, with a replacement between that read and the start not detected, and the numbers of the pages whose `extraction` is `"ocr"`, ascending and distinct. An object exactly when at least one page's `extraction` is `"ocr"`, and `null` otherwise. A run that applied nothing — `ocr-failed`, `ocr-timeout` and an admitted answer of no pages among them — is recorded only by its errors, and the record does not identify the program that ran |

## How a document is processed

The adapter works in this order, and the record is what these steps produced.

**The deadline.** `--timeout` runs from when the adapter starts, before it reads the request.
Steps 4 and 5 check it at the points they name; the first of those checks to find it passed
records `timeout`, and the adapter goes to step 7. Step 6 checks it once, after the OCR program
is resolved and digested and immediately before it is started: if the deadline has passed, the
program is not started, `timeout` is recorded, and the adapter goes to step 7. A program that
was started has **finished** when it has exited and its stdout has reached its end, as the
adapter observes both. The adapter takes the program's outcome only once it has observed both
or ended the program; if the deadline has passed by then, the outcome is `ocr-timeout` and no
answer is applied, even when the answer the program wrote was complete. A program still running
at the deadline, or exited with its stdout held open by a process it left behind, is ended. A
record carries at most one of the two.
[Bounds and cancellation](#bounds-and-cancellation) says what the deadline does not interrupt.

1. **Admit the request**, or refuse it ([Refusals](#the-arguments)). A refused request has no
   record.
2. **Check the declaration.** A declared type version 1 does not process yields
   `media-type-unsupported`. A declared PDF without `%PDF-` in its first 1024 bytes, or a
   declared text type whose bytes are not valid UTF-8, yields `media-type-mismatch`. Either is a
   `"failed"` record with `processor` `null`, and the adapter goes to step 7.
3. **A text document** is one page: its characters, normalised, as [Page outcomes](#page-outcomes)
   assigns them, and `pageCount` is 1. If the page's text is longer than `maxTextBytes` in bytes
   of UTF-8, it is not listed and `text-over-bound` names page 1. The adapter then goes to
   step 7.
4. **A PDF is opened and its pages counted.** The adapter reads the cross-reference, the trailer
   and the encryption dictionary the trailer names, and then walks the page tree in document
   order, the deadline checked before each page-tree node. The walk ends in one of four ways:
   - **it completes**: the tree ended, having named at least one page. `pageCount` is the
     number of pages found, and the adapter goes on to step 5;
   - **at the page bound**: a page past `maxPages` was found. `pageCount` is `maxPages`,
     `pdf-pages-over-bound` is recorded, `truncated` is `true`, and the adapter goes on to
     step 5;
   - **at the deadline**: `pageCount` is the number of pages found so far, `timeout` is recorded,
     `truncated` is `true`, and the adapter goes to step 7;
   - **at a defect**: the document is encrypted and not opened — `pdf-encrypted`, with
     `encryption.opened` `false` — or anything else stops the reader before the walk completes:
     no usable cross-reference and no objects found by scanning, a page tree with no page, a
     page-tree node that cannot be read, a stream it cannot decode or that inflates past a
     bound, or a structure past a structure bound. That is `pdf-malformed`. Either way no page
     is listed, `pageCount` is 0, `truncated` is `false`, and the adapter goes to step 7.
5. **Each counted page is extracted**, from page 1 to page `pageCount`. The deadline is checked
   before each page and between the operators the adapter interprets on it; a page whose
   extraction the deadline interrupts is not listed, nor is any later page. The page's outcome
   is assigned from [Page outcomes](#page-outcomes). A page whose content cannot be
   interpreted is listed as `"failed"`, with one error naming it. The page's content is its
   content streams and the streams of the form XObjects it draws, and the operators in them:
   `pdf-unsupported` when one of those streams uses a filter the reader does not implement,
   `stream-over-bound` when one inflates past a bound, and `pdf-page-failed` for anything else,
   a structure bound or the operator bound met on the page included. Every other resource the
   page names is not its content, and nothing about one is an error, whatever the reason — a
   filter, a bound, an object that cannot be read or is not there: a font the reader cannot use
   leaves its glyphs unmapped and counted in `unmapped`, an image counts as drawn whether or
   not it could be decoded, and a form XObject that cannot be found is not drawn. An
   `"ok"` page's text takes bytes of UTF-8 from the **text budget**, `maxTextBytes`; a page of
   any other status takes none. An `"ok"` page whose text does not fit the budget left — a sum
   that reaches the bound exactly fits — is not listed, `text-over-bound` names it, and no later
   page is extracted or listed.
6. **OCR**, when step 5 listed at least one `"needs-ocr"` page and recorded no `timeout`:
   - with `options.ocr` `"never"`, or no `--ocr` program configured, nothing is started:
     `ocr-not-run`, and the pages stay `"needs-ocr"`;
   - otherwise the program named by `--ocr` is resolved on the adapter's `PATH` and its file
     digested; the deadline is then checked, as "The deadline" says; and it is started, once,
     with the numbers of the listed `"needs-ocr"` pages as its arguments, in decimal,
     ascending, and the original document's bytes on stdin. Its environment is the adapter's
     own: what the gateway declared with `--source-env`, plus `PATH`, which the gateway copies
     unless declared (and `SYSTEMROOT` on Windows). Its stderr is discarded. It stays in the
     adapter's process group. A name that does not resolve, a file that cannot be digested or a
     program that cannot be started is `ocr-failed`;
   - its stdout is read up to `maxOcrOutputBytes`; a byte more ends it and is `ocr-failed`. A
     non-zero exit is `ocr-failed`, and so is a program that exits and whose stdout has not
     reached its end two seconds later, its pipe then closed, unless the deadline has passed by
     then. A deadline passed before the adapter has taken the outcome makes it `ocr-timeout`, as
     "The deadline" says;
   - its output is **admitted** only if all of these hold, or it is `ocr-failed`: it is one JSON
     value in the domain the gateway's canonicalizer admits (`adapters/internal/canon`: valid
     UTF-8, no duplicate member name, no unpaired surrogate escape, no number with a fraction
     or an exponent, no integer past 2^53 − 1, nothing after the value but whitespace); that
     value is an object whose only member is `pages`, an array; each entry is an object whose
     only members are `number`, an integer, and `text`, a string; and every `number` is one of
     the page numbers the program was given, at most once;
   - an admitted answer is **applied** page by page in ascending page number, whatever its
     order: the answer's text is normalised; if its bytes of UTF-8 fit the text budget left
     after step 5 and the answers already applied, the page takes it and its outcome from
     [Page outcomes](#page-outcomes); if not, that page and every later answered page stay
     `"needs-ocr"`, and `text-over-bound` names the page. Pages that stay listed as
     `"needs-ocr"` this way do not make the record truncated;
   - the numbers the program was given and its admitted answer did not include stay
     `"needs-ocr"`, and one `ocr-incomplete` counts them. An admitted answer of no pages is
     incomplete for all of them.
7. **The record is written**: `content.extraction`, `chars` and `status` derived as their
   tables say, `provenance.ocr` from the pages that took an answer.

A wrapper that renders pages and runs Tesseract is the expected OCR program; the contract admits
any that keeps to step 6. The record says which pages took its answer, and nothing more: a wrong
reading of a scanned page is the program's, and the receipt does not make it right.

## Bounds and cancellation

Every bound is the operator's, on the adapter's command line, and the record reports the ones
that applied:

| Flag | Default | Bounds |
|---|---|---|
| `--max-bytes` | 16 MiB | the decoded document; the read bound derives from it ([Refusals](#the-arguments)). A retrieved document past it is `document-over-bound` |
| `--max-pages` | 500 | pages counted and listed; past it, `pdf-pages-over-bound` and `truncated` |
| `--max-text` | 8 MiB | the text budget: the sum of applied page text, in bytes of UTF-8 after normalisation, OCR included; past it, `text-over-bound` ([steps 5 and 6](#how-a-document-is-processed)) |
| `--max-inflate` | 64 MiB | the total a document's streams may inflate to, with 16 MiB for any one stream. Every stream the reader decodes counts against the total, a font's or an image's included. Past either bound, a stream of a page's content is `stream-over-bound` and fails that page, a stream read before the walk completes is `pdf-malformed`, and a font or image stream is no error (step 5); a later stream that finds the total spent is past it too — a small file that inflates without end is not read further |
| `--ocr-max-output` | 32 MiB | the OCR program's stdout; past it, `ocr-failed` |
| `--max-output` | 1 MiB | the record on stdout; at or below the gateway's `--source-max-output`. A record that would exceed it is not cut: the adapter refuses with `record-over-bound`, and a document whose text or inline original cannot be carried is one the operator sizes the bounds for |
| `--timeout` | 25 s | the adapter's deadline, a whole number of milliseconds, reported as `timeoutMs`; past it, `timeout` or `ocr-timeout` |

Each bound is a positive integer no larger than the ceiling the adapter states for it in its
documentation, and `--timeout` a positive duration in whole milliseconds under its ceiling; any
other value is a usage error, and the adapter exits 2 without reading the request. Every ceiling
keeps the bound, and every figure derived from it, within the canonical domain's integers; for
`--max-bytes`, whose read bound is derived from it, that holds up to 6,755,399,441,006,589, and
`attachment.Check` refuses a record reporting a larger `maxBytes`. Object count,
nesting depth, cross-reference chain length, page-tree depth and operators per page are bounded
by constants the adapter states in its documentation: one met while the document is opened or
its page tree walked is `pdf-malformed` (step 4), and one met in a page's content fails that
page (step 5).

**A deadline is when work stops being started, not a completion guarantee.** The adapter checks
its deadline at the points [the steps](#how-a-document-is-processed) name, and an operation
between two checks runs to its end. At the deadline, an OCR program that has not finished is
ended: the adapter kills the process it started, not that process's own children, waits up to
two seconds for that process to exit and its stdout to reach its end, and then closes the pipe
itself, so a process left behind holding it does not delay the record past those two seconds.
The record is therefore written some time after the deadline, which is why `--timeout` sits
under the gateway's thirty seconds with room to spare.

The gateway, for its part, cancels the source's context at thirty seconds (`runSource`,
`go/serve.go`). On Unix it kills the source's process group, which holds the adapter, an OCR
program the adapter started, and any descendant of either that did not leave the group; it
kills that group again once the source has been waited for. On other platforms it kills the
source process alone (`go/spawn_other.go`), and an OCR program or its descendants can outlive
the adapter. After cancelling, the gateway waits up to five seconds (`sourceWaitDelay`) for the
source's output pipes to close; that wait bounds pipe draining, not the whole call. A source
ended this way has produced no receipt. A caller that gives up on a call cannot cancel the
source through `/acquire`: the call completes or times out on its own, and a receipt may be
minted for a document the caller no longer wants. That is the gateway's contract for every
source, and the desk should hold a document call to its own budget before making it.

## Text documents

`text/plain`, `text/markdown`, `text/csv` and `application/json` are carried as one page of
`"verbatim"` text: the bytes, required to be valid UTF-8, after the normalisation above and
nothing else. Nothing is parsed — JSON is not canonicalized, CSV is not split — so the text is
the file's characters. The same bounds apply.

These types are here so that a desk can give every attachment the same lineage, not because
the adapter adds anything to them.

## What a consumer should do

For a desk, which verifies receipts under a pinned key (SPEC.md §5a) and withholds what a
failed receipt covers:

1. **Verify the receipt first**, as for any acquisition. Its `acquisition.shape` is
   `"command"`, which SPEC.md §1.2a defines and a version 3 verifier admits (this repository's
   `verify-ts` does); `acquisition.adapter.name` is the first word of the command as the gateway
   was configured, and its `digest` is of the file the gateway read before starting it.
2. **Keep what reproduces the commitment.** The arguments commitment is over the whole
   canonical arguments — the bytes, the name, the media type, and whether `sha256` and
   `options` were given — under the salt `salts.args`. The salt alone reproduces nothing: a
   desk that wants to show, later, exactly what it submitted keeps the canonical arguments (or
   the exact submitted arguments, canonicalized again) beside the salt, the record and the
   receipt.
3. **Hold the record to `attachmentVersion` `"1"`** and to this note's shapes before reading
   further; a record of another version is not this contract.
4. **Read `processing.status` before `content`.** A `"failed"` record is an attachment that
   was submitted and not read; show the errors, keep the receipt, offer no text. A
   `"partial"` record is text with gaps; show which pages are `"needs-ocr"` or `"failed"` and
   whether `truncated` is set, beside the text. A `"complete"` record can still carry pages
   that are `"no-text"`.
5. **Deduplicate by `document.id`, cite by record and page** (above). Two uploads of the same
   file are one document with two names and two records.
6. **Never let `original.bytes` reach a model** or a log: it is the document, base64, present
   only when the adapter retained the original inline.
7. **Read `unmapped`.** A page with a large share of U+FFFD is a page the extractor could not
   read; treat it like a page that needs OCR.

## Versioning

`attachmentVersion` names this contract. The members this note lists are **the version 1
set**: every one is present in every version 1 record, `null` when it has no value, and none is
ever removed, renamed, retyped or given another meaning. Within version `"1"`:

- a member may be **added** only as an optional one: absent from records written before it
  existed, and read as "not stated" when absent — the presence rule above is for the frozen set,
  not for additions. Each addition is recorded in this note's changelog with the adapter version
  that first writes it;
- a value may be added to an enumeration, or a variant to `provenance.source`, recorded the
  same way;
- an adapter writes exactly what this note and its changelog say; the record schema beside it
  and `attachment.Check` are the **producer's**: members closed, enumerations closed, additions
  added as they are made;
- a **consumer** validates for compatibility, not conformance: it tolerates a member it does
  not know at any depth, and reads an enumeration value it does not know as the class's
  unknown — an unknown `status` is not `"complete"`, an unknown page `status` is not `"ok"`, an
  unknown error code is an error, an unknown `retention` is bytes it does not hold, an unknown
  `source.kind` is provenance it cannot read. A consumer that copies the producer's schema and
  validates strictly will refuse records a later adapter of the same version writes, and that
  is its choice to make.

Anything else is version `"2"`, written by an adapter that is asked for it, never silently.

Changelog:

- `"1"` — this note. Written by `adapter-document` from its first release.

## The schemas, the check and the examples

`adapters/attachment` is the reference check of this note: `attachment.Check` takes a record's
bytes and returns every rule of this note it finds broken, each under a rule identifier, or
nothing. Its tests hold every example below to it, hold each of its rules to a record built to
break it that must be refused under that rule's identifier, and fail when a rule has no such
record; `adapter-document`, which follows this note in its own change, is to hold every record
it writes to the same check. Where the check and this note disagree, the note is right and the
check is a defect. The same package carries `NormalizeText`, which answers to
`testdata/attachments/normalisation-v1.json`, and `IsNormalized`, the test for a string
normalisation can yield — which is not "normalising it again changes nothing": a text that
begins with U+FEFF behind a removed blank line keeps it, and a second pass would not.

`testdata/attachments/attachment-v1.schema.json` checks **each value on its own**: the member
set of every object, types, enumerations, ranges, and the lexical forms of names, media types,
digests, timestamps, base64 and page text, with patterns written to mean the same under a
JavaScript and a Python regular-expression engine. It relates no value to another — a page's
status to its text, a code to a status, a count to a list — and a record that passes it is not
thereby a record this note describes. Those relations are the check's.

`testdata/attachments/arguments-v1.schema.json` describes the arguments within the descriptor
grammar version 1 (`docs/design/tool-descriptors.md`), which admits no pattern: the media type's
syntax, the base64 encoding and the digest's form are the adapter's checks.

`testdata/attachments/examples/` holds one record per outcome. Every example's document fits the
reference gateway's request bound as it stands. The digests in them are illustrative, except in
`complete-verbatim-text.json` and `complete-blank-text.json`, whose documents are small enough to
state: `"line one\r\nline two\r\n"` and `"\n"`.

## What this is not

- **Not a claim about the text.** The receipt covers the record's bytes. The record's own
  claims — this page had a text layer, that one took the program's answer — are the adapter's
  testimony, in the clear.
- **Not a document store.** The gateway retains the record as an artifact because it retains
  every result; a document whose original is retained inline is in the store because the
  adapter put it in the record. Neither the gateway nor the adapter indexes, lists or serves
  documents.
- **Not a change to the signer.** Nothing here touches the core module; a new bound on the
  request body and a per-source timeout are proposed as a separate change, and the contract
  holds with or without them.
- **Not reachable through the engine's MCP server.** The MCP server serves the tools of
  platforms bound in an engine configuration, and this release binds no bare command and no
  `http` shape there. A desk reaches the documents source over `/acquire`.
- **Not retrieval.** A document fetched from a drive on the caller's behalf, with the
  caller's authorisation, is the next note; it writes this same record with a
  `provenance.source.kind` naming the drive, `document.version` from the drive, and the
  original retained inline, under the `http` shape, whose acquisition members it can honestly
  fill.
