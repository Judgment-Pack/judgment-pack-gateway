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
**What the receipt then proves is byte lineage: these bytes, from this program, at this call in
this session, under this key.** It does not prove that the text is what the document says, that
the extraction is complete, or that a scanned page was read right. The record states, for
every page, what was done and what was not, and a consumer reads those statements rather than
assuming.

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
  runs for the pages that have no text layer. The adapter records that it ran and what it
  answered; it vouches for nothing the program did.

## How it is wired

The adapter is a bare source: no `--source-shape`, so the receipt's `acquisition.shape` is
`"command"` (SPEC.md §1.2a) — the shape that opts out of the envelope's acquisition members.
The gateway names the adapter as the operator configured it and pins it by the digest of its
executable, sets every other acquisition member to `null`, and stamps its own `observedAt`.
That is the true shape for a document the caller supplied: there is no endpoint, no snapshot
and no peer to record, and the arguments commitment already commits to the bytes. The record
carries what the adapter can add — its own identity, when it received the bytes, what it
ran — inside the signed artifact, in the clear.

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
separation, and the isolation this note claims is a claim about the deployment that provides
it, not a property of the contract. State it that way in a desk's documentation.

A request:

```
POST /acquire
{"session": "…", "source": "documents", "arguments": {"document": {"name": "fswp.pdf", "mediaType": "application/pdf", "bytes": "<base64>"}}}
```

The answer is `{result, receipt, salts}` as for any acquisition; `result` is the record below.

**The request bound, stated plainly.** `/acquire` reads at most 1 MiB of body
(`maxRequestBody`, SPEC.md §6 reference implementation), and a source's context is cancelled
at thirty seconds. A document travels inline, base64-encoded, so until the gateway grows
operator bounds for both — `--max-request BYTES` and `--source-timeout NAME=SECONDS`, a separate
change to the core with its own review — an inline document is at most about 760 KiB and its
processing, OCR included, at most thirty seconds. The adapter's own `--max-bytes` and
`--timeout` sit under whatever the gateway allows; the record's `processing.bounds` says which
bounds applied.

## The arguments

The canonical arguments (SPEC.md §1.1) the gateway hands the adapter on stdin. Members are
exact at every level: one the adapter does not name, one given twice, or one of another type
refuses the request before anything is read.

| Member | Type | Meaning |
|---|---|---|
| `document` | object | required |
| `document.name` | string | the name the caller gives the document: 1 to 255 bytes of UTF-8, no control character (U+0000–U+001F, U+007F). A label, carried into the record as given; the adapter derives nothing from it |
| `document.mediaType` | string | the media type the caller declares, as `type/subtype` in lowercase with no parameters. Version 1 processes `application/pdf`, `text/plain`, `text/markdown`, `text/csv` and `application/json`; any other declared type yields a record whose processing failed with `media-type-unsupported` |
| `document.bytes` | string | the document, in standard base64 (RFC 4648 §4, padded, no line breaks). Empty, or not base64, refuses the request |
| `document.sha256` | string — optional | the caller's own digest of the bytes, `"sha256:"` + 64 lowercase hex. When present it must equal the digest the adapter computes, or the request is refused: a mismatch is a transport defect, not a document to record |
| `options` | object — optional | |
| `options.ocr` | string — optional | `"auto"` (default): run the configured OCR program for the pages that have no text layer; `"never"`: run it for none, and report those pages as needing it |

**Refusals.** A request refused is the adapter exiting 1 with the reason on stderr and nothing
on stdout; the gateway then mints nothing and retains nothing, and answers the caller with a
failed acquisition whose diagnostic is that reason. What is refused: not a JSON object; a
member missing, unknown, duplicated or of another type; a name outside its rule; `bytes` empty
or not base64; a `sha256` that does not match; and a request past the adapter's **read
bound** — `--max-bytes` × 4/3 plus 64 KiB, so that a document within `--max-bytes` always fits
with the longest name, the digest and the options — whose reason names the bound. Because
base64 grows a document by a third, an inline document past `--max-bytes` is always past the
read bound too: **an oversized inline document is refused, never recorded**, and a desk that
knows the bound refuses it before the call. Everything within the read bound that is not a
refusal above — an unsupported type, an encrypted or malformed PDF — is a **record**, since the
document's identity is established and the outcome is worth attesting.

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
      {"number": 3, "status": "no-text", "extraction": "none", "text": "", "chars": 0, "unmapped": 0}
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
| `detectedMediaType` | string or `null` | what the bytes look like to the adapter — `application/pdf` for a file beginning `%PDF-` within its first 1024 bytes, `text/plain` for valid UTF-8 declared as a text type — or `null` when the adapter recognised nothing. A declared PDF that does not look like one fails with `media-type-mismatch`; the adapter never processes bytes as something other than what was declared |
| `size` | integer | the original's length in bytes |
| `version` | string or `null` | a version the *source* reported for the document — a drive's file version — `null` for a document the caller supplied |
| `encryption` | object or `null` | for a PDF that declares encryption: `{"handler": string, "revision": integer, "opened": boolean}` — the security handler's name and revision as the document states them, and whether the adapter could open it. Version 1 opens the standard handler with an empty user password (revisions 2 to 6: RC4 and AES); a document that needs a password, or uses another handler, is not opened and fails with `pdf-encrypted`. `null` for a document that declares no encryption |

### `original` — where the bytes are

| Member | Type | Meaning |
|---|---|---|
| `retention` | `"caller"` or `"inline"` | `"caller"`: the caller supplied the bytes and holds them; this record binds them by `document.id` and the receipt's arguments commitment commits to them. `"inline"`: the bytes are in this record, base64, and the retained artifact therefore holds the original — the form retrieval from a drive uses, since the caller never had the bytes |
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
| `extraction` | `"text-layer"`, `"ocr"`, `"mixed"`, `"verbatim"` or `"none"` | how the document's text was obtained, over all listed pages: from the PDF's own text layer; from the OCR program; from both, on different pages; verbatim, for a text document; or not at all |
| `pageCount` | integer | the pages the adapter found, walking the page tree up to `maxPages` and one more: a document with more pages than the bound has `pageCount` = `maxPages` and `truncated` = `true` |
| `truncated` | boolean | `true` when pages exist that are **not listed**: past the page bound, past the text bound, or past the deadline. **Every listed page is complete**: its `text` is the whole of what the extractor derived for it, never a fragment |
| `chars` | integer | the sum of the pages' `chars` |
| `pages` | array of page objects | in page order, one per listed page, numbers ascending and distinct, never more than `maxPages` |

A page object:

| Member | Type | Meaning |
|---|---|---|
| `number` | integer | 1-based, in document order |
| `status` | `"ok"`, `"no-text"`, `"needs-ocr"` or `"failed"` | `"ok"`: text was obtained; `"no-text"`: no text was found — the page has neither text operators nor images, or the OCR program answered it with nothing; `"needs-ocr"`: the page has images and no text layer, and no OCR text was applied — a scanned page; `"failed"`: the page's content could not be interpreted, and `processing.errors` names why with this page's number |
| `extraction` | `"text-layer"`, `"ocr"`, `"verbatim"` or `"none"` | where this page's text came from: the PDF's text layer, the OCR program, verbatim for a text document, or nowhere. `"ok"` and `"no-text"` name their source; `"needs-ocr"` and `"failed"` are `"none"` |
| `text` | string | the page's text after [normalisation](#text-normalisation); `""` when there is none. Glyphs the adapter could not map to Unicode are U+FFFD, and counted |
| `chars` | integer | the number of Unicode scalar values in `text` |
| `unmapped` | integer | the number of glyphs rendered as U+FFFD: a font with no usable encoding. A page with many is a page whose text is not to be trusted, and a consumer should say so rather than cite it |

**What the text is, and is not.** For a PDF the text is what the extractor derived from the
content streams in stream order: the words as the fonts map them to Unicode, spaces inserted
where the glyph positions jump, line breaks where the text position moves down. Reading order
is stream order, which is usually reading order and is not always: a two-column page may read
across, a footer may come first. Hyphenation is not repaired; ligatures are mapped where the
font maps them. Whitespace is a heuristic of layout, not a fact about the document, and a
consumer matching an excerpt should fold it, as the desk's citation matching already does.
Text from OCR is what the program answered. For a text document the text is the file's
characters. All three pass through the one normalisation below, and nothing else.

### Text normalisation

Every page's `text`, whatever produced it, is normalised in this order, and `chars`, the text
bound and every count are computed on the result:

1. a byte-order mark (U+FEFF) at the start is removed;
2. `\r\n` and a lone `\r` become `\n`;
3. every C0 control character other than `\t` and `\n`, and U+007F, is removed;
4. leading blank lines are removed, and the text ends without a line terminator: trailing
   `\n` are removed, so a page's last line is its last character.

Nothing else is done: spaces are not collapsed, lines are not trimmed, Unicode is not
recomposed. A text document that began with a blank line has lost it; the record says the
document is `"verbatim"` and this section says what verbatim means.

### Identity, and what a citation binds

`document.id` says which bytes. It does not say which extraction: the same bytes under another
bound, another `options.ocr`, another deadline, another OCR program or another `processor`
yield other pages, and even the same OCR wrapper's digest pins the wrapper and not the engine
behind it. So:

- deduplicate **documents** by `document.id`;
- bind a **citation** to the record it was taken from — the receipt's `sessionId`, `callIndex`
  and `signature`, or the artifact's `resultDigest`, as the desk's citation trace already binds
  a source — then the page `number`, then the excerpt as text matched against that page's
  `text`, exactly or with whitespace folded. Never by offset into a concatenation the record
  does not carry; offsets within a page's `text` are the consumer's own, in whatever unit it
  counts, and `chars` lets it check it read the whole page;
- expect the same pages again only from the same bytes under the same `processor`, the same
  bounds and the same `options`, with no OCR page involved. With OCR, the program's answer is
  the program's, each time.

### `processing` — what was done

| Member | Type | Meaning |
|---|---|---|
| `status` | `"complete"`, `"partial"` or `"failed"` | `"complete"`: every listed page is `"ok"` or `"no-text"`, `truncated` is `false` and `errors` is empty. `"partial"`: the document was read, and not all of it became content — a page needs OCR, a page failed, pages were cut by a bound or the deadline; `errors` has at least one entry. `"failed"`: no content could be produced because the document could not be read: unsupported or mismatched type, encrypted and not openable, malformed past recovery, or a retrieved document past the size bound; `pages` is empty, `extraction` is `"none"`, `errors` has at least one entry |
| `errors` | array of error objects | why the status is not `"complete"`, one entry per condition, in the order they were met; empty exactly for a complete record |
| `bounds` | object | the bounds that applied: `maxBytes`, `maxPages`, `maxTextBytes`, `maxInflateBytes`, `maxOcrOutputBytes`, `timeoutMs`, each an integer. A consumer that finds `truncated` reads these to know what to raise |
| `durationMs` | integer | wall time the adapter spent from reading the request to writing the record, in milliseconds |

An error object: `{"code": string, "message": string, "page": integer or null}`. `message` is
for a person, at most 512 bytes of UTF-8, and never carries the document's content; `page` is
the page the condition belongs to, or `null` for the document as a whole. The codes of
version 1:

| Code | Status it yields | Meaning |
|---|---|---|
| `media-type-unsupported` | failed | the declared media type is not one version 1 processes |
| `media-type-mismatch` | failed | the bytes are not what the declared type says: a PDF without a PDF header, a text type that is not valid UTF-8 |
| `document-over-bound` | failed | a **retrieved** document exceeds `maxBytes`; nothing past the size check was done. An inline document past the bound is refused at the request and never reaches a record |
| `document-empty` | failed | zero bytes — refused at the request, but named here for a source that fetched an empty file |
| `pdf-malformed` | failed | not parseable as a PDF past recovery: no usable cross-reference and no objects found by scanning, no page tree, or a structure the parser could not follow within its bounds |
| `pdf-encrypted` | failed | the document is encrypted and was not opened: a user password is required, or the handler or revision is not one the adapter implements |
| `pdf-unsupported` | partial or failed | a feature the extractor does not implement stopped it: a stream filter it cannot decode on a content stream, a predefined CMap it does not carry. With a page number when it stopped one page; without one when it stopped the document |
| `pdf-page-failed` | partial | a page's content stream could not be interpreted; the page is listed as `"failed"` |
| `pdf-pages-over-bound` | partial | the document has more pages than `maxPages`; the rest were not processed |
| `text-over-bound` | partial | listing the page named would take the sum of the listed pages' text past `maxTextBytes` — bytes of UTF-8 after normalisation; a sum that reaches the bound exactly is within it. That page and every later page are not listed, and `truncated` is `true`. For an OCR answer, the page named stays `"needs-ocr"` instead, and later OCR pages are not applied |
| `stream-over-bound` | partial or failed | a stream inflated past the per-stream or total inflate bound; the object depending on it was not read |
| `timeout` | partial or failed | the adapter's deadline passed; what was done before it is reported |
| `ocr-not-run` | partial | pages need OCR and no program ran: none is configured, or the caller asked `"never"`. The message says which |
| `ocr-failed` | partial | the OCR program could not be resolved or started, exited with a non-zero status, wrote past `maxOcrOutputBytes`, or wrote something that is not its contract — not the shape below, a page twice, a page outside the document, invalid UTF-8. **No page it answered is applied**; every page it was asked for stays `"needs-ocr"` and `provenance.ocr` is `null` |
| `ocr-incomplete` | partial | the OCR program answered validly but left out pages it was asked for; the message counts them, the answered pages are applied, and the rest stay `"needs-ocr"` |
| `ocr-timeout` | partial | the OCR program did not finish in the time left under the deadline; it was ended, and its pages stay `"needs-ocr"` |

A consumer treats a code it does not know as an error whose class it does not know: the
status still says what the record is good for.

### `provenance` — who did it, and how

| Member | Type | Meaning |
|---|---|---|
| `adapter` | `{"name": string, "version": string, "digest": digest}` | the adapter **as it identifies itself**: its name, its own version string, and the SHA-256 of its own executable, read at run time. The receipt's `acquisition.adapter` is the **gateway's** identification of the same program — the command as the operator configured it, the version `""` a bare command has (`commandAcquisition`), and the digest of the file the gateway resolved and started. The two digests agree when nothing replaced the executable between the two reads |
| `source` | object | where the bytes came from: `{"kind": "inline"}` for a document the caller supplied. Retrieval from a drive adds its own kind with its members; the members present depend on `kind`, a consumer reads `kind` first, and a `kind` it does not know is a source it does not know — the record is still a record, its provenance unread |
| `observedAt` | string | when the adapter had read the request in full, `YYYY-MM-DDThh:mm:ssZ`, UTC, whole seconds — the form `servedAt` takes. The receipt's own `observedAt` for a bare command is the gateway's stamp of when it read the output, which is not earlier and, at whole seconds, may be equal |
| `processor` | string or `null` | the extraction implementation and its algorithm version: `"adapter-document/pdf/1"`, `"adapter-document/text/1"`. It moves when the extractor's output for the same bytes changes. `null` when no extractor ran: an unsupported or mismatched type, a retrieved document past the size bound |
| `ocr` | object or `null` | `{"program": string, "digest": digest, "pages": array of integers}` when an OCR answer was applied: the program as configured, the SHA-256 of the executable that name resolved to, and the pages whose text came from it, ascending and distinct. The digest pins the program named, not what it in turn runs. `null` when no OCR text was applied |

## Scanned pages, and OCR

A page is scanned when its content draws images and shows no text: no text-showing operator
in its content stream or in the form XObjects it draws, and at least one image XObject or
inline image. Such a page is `"needs-ocr"` unless an OCR program was configured and answered
for it. The adapter does not rasterise pages and does not carry an OCR engine; the engine
image is built from nothing that varies, and an OCR model is exactly that. OCR is therefore an
operator's program, run out of process:

- `--ocr PROGRAM` names one executable, one word, resolved on the adapter's `PATH` and digested
  before it is started. A name that does not resolve, or a program that cannot be started, is
  `ocr-failed`.
- It is run once per document, with the 1-based numbers of the pages to read as its arguments,
  ascending, and the original document's bytes on stdin. Its environment is the adapter's own:
  what the gateway declared with `--source-env`, plus `PATH`, which the gateway copies unless
  declared (and `SYSTEMROOT` on Windows), and nothing else.
- It writes one JSON object on stdout: `{"pages": [{"number": integer, "text": string}, …]}`,
  at most `maxOcrOutputBytes`. Each number once, each within the document; a page it was not
  asked for is ignored. An answer that is not this — another shape, a page twice, a page out
  of range, invalid UTF-8, more bytes than the bound, a non-zero exit — is `ocr-failed`, and no
  page of it is applied.
- A valid answer need not cover every page asked for. Each page it answers is applied: its
  text normalised, `extraction` `"ocr"`, `status` `"ok"`, or `"no-text"` when the text is
  empty after normalisation. Each page asked for and not answered stays `"needs-ocr"`, and one
  `ocr-incomplete` error counts them. An answer with no pages at all is valid and incomplete.
- Applied text counts against the same `maxTextBytes` as the text layer, in page order: an
  answered page whose text would take the sum past the bound is not applied, stays
  `"needs-ocr"`, and `text-over-bound` names it; later answered pages are not applied either.
- It has the time left under the adapter's deadline and no more; at the deadline it is
  ended — with its process group where the platform has one, the process alone elsewhere —
  and the outcome is `ocr-timeout`.
- The record says it ran (`provenance.ocr`), and nothing more: a wrong reading of a scanned
  page is the program's, and the receipt does not make it right.

A wrapper that renders pages and runs Tesseract is the expected program; the contract admits
any that keeps to it.

## Bounds and cancellation

Every bound is the operator's, on the adapter's command line, and the record reports the ones
that applied:

| Flag | Default | Bounds |
|---|---|---|
| `--max-bytes` | 16 MiB | the decoded document; the read bound derives from it (above). A retrieved document past it is `document-over-bound` |
| `--max-pages` | 500 | pages listed; past it, `pdf-pages-over-bound` and `truncated` |
| `--max-text` | 8 MiB | the sum of listed pages' text, in bytes of UTF-8 after normalisation, OCR included; past it, `text-over-bound` and `truncated` |
| `--max-inflate` | 64 MiB | the total a document's streams may inflate to, with 16 MiB for any one stream; past it, `stream-over-bound` — a small file that inflates without end is not read further |
| `--ocr-max-output` | 32 MiB | the OCR program's stdout; past it, `ocr-failed` |
| `--max-output` | 1 MiB | the record on stdout; at or below the gateway's `--source-max-output`. A record that would exceed it is not cut: the adapter fails the acquisition, and a document whose text or inline original cannot be carried is one the operator sizes the bounds for |
| `--timeout` | 25 s | the whole run, under the gateway's thirty seconds; past it, `timeout`, with the pages done reported |

Object count, nesting depth, cross-reference chain length and page-tree depth are bounded by
constants the adapter states in its documentation; a document past any of them is
`pdf-malformed`.

Cancellation is the deadline. The adapter checks it between pages and between objects, ends
the OCR program at it, and writes what it has. The gateway, for its part, cancels the source's
context at thirty seconds — killing the process group on Unix, the process alone on other
platforms (`go/spawn_other.go`) — then waits up to five more seconds for the pipes to close
before it answers the caller with a failed acquisition; an adapter that runs into that kill has
minted nothing, which is why the adapter's own deadline sits under the gateway's. A caller that
gives up on a call cannot cancel the source through `/acquire`: the call completes or times
out on its own, and a receipt may be minted for a document the caller no longer wants. That is
the gateway's contract for every source, and the desk should hold a document call to its own
budget before making it.

## Text documents

`text/plain`, `text/markdown`, `text/csv` and `application/json` are carried as one page of
`"verbatim"` text: the bytes, required to be valid UTF-8, after the normalisation above and
nothing else. Nothing is parsed — JSON is not canonicalized, CSV is not split — so the text is
the file's characters. The same bounds apply; the only failure a text document has past its
type is `media-type-mismatch` on invalid UTF-8.

These types are here so that a desk can give every attachment the same lineage, not because
the adapter adds anything to them.

## What a consumer should do

For a desk, which already verifies receipts under a pinned key (SPEC.md §5a) and withholds
what a failed receipt covers:

1. **Verify the receipt first**, as for any acquisition. Its `acquisition.shape` is
   `"command"`, which the desk's verifier already admits; `acquisition.adapter.name` is the
   command as the gateway was configured, and its `digest` pins the executable.
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
   whether `truncated` is set, beside the text. A `"complete"` record still carries pages that
   are `"no-text"`.
5. **Deduplicate by `document.id`, cite by record and page** (above). Two uploads of the same
   file are one document with two names and two records.
6. **Never let `original.bytes` reach a model** or a log: it is the document, base64, present
   only when the adapter retained the original inline.
7. **Read `unmapped`.** A page with a large share of U+FFFD is a page the extractor could not
   read; treat it like a page that needs OCR.

## Fixtures

The adapter ships with fixtures under `adapters/document/testdata/`, one per outcome, each with
the record it yields (`observedAt`, `durationMs` and the executable digests normalised):

| Fixture | What it is | Record |
|---|---|---|
| `normal.pdf` | three pages of text: a WinAnsi Type1 font, a TrueType font with a ToUnicode map, a ligature, a blank third page | complete, `text-layer` |
| `scanned.pdf` | two pages that draw one image each and no text | partial, `ocr-not-run`, both pages `needs-ocr` |
| `mixed.pdf` | one text page and one image-only page | partial, `ocr-not-run`, without an OCR program; complete, `mixed`, once one answers the second page |
| `encrypted-rc4.pdf`, `encrypted-aes.pdf` | the standard handler, an owner password only, RC4 and AES-128 | complete, `document.encryption.opened` `true` |
| `encrypted-user.pdf` | the standard handler with a user password | failed, `pdf-encrypted` |
| `malformed-truncated.pdf` | `normal.pdf` cut mid-stream | recovered by scanning where the objects survive, else `pdf-malformed` |
| `malformed-xref.pdf` | a cross-reference table with wrong offsets | complete: objects found by scanning |
| `not-a-pdf.pdf` | text declared as a PDF | failed, `media-type-mismatch` |
| `many-pages.pdf` | sixty one-line pages | partial under `--max-pages 50`, `truncated` |
| `inflate-bomb.pdf` | a content stream that inflates past the bound | `stream-over-bound` |
| `notes.txt` | a UTF-8 text file with mixed line endings | complete, `verbatim` |

Oversize is exercised by bound, not by a large file in the tree: the tests run `normal.pdf`
under a `--max-bytes` smaller than it and hold the refusal to its wording.

## Versioning

`attachmentVersion` names this contract. The members this note lists are **the version 1
set**: every one is present in every version 1 record, `null` when it has no value, and none is
ever removed, renamed, retyped or given another meaning. Within version `"1"`:

- a member may be **added** only as an optional one: absent from records written before it
  existed, and read as "not stated" when absent — the presence rule above is for the frozen set,
  not for additions. Each addition is recorded in this note's changelog with the adapter version
  that first writes it;
- a value may be added to an enumeration, recorded the same way;
- an adapter writes exactly what this note and its changelog say, and the JSON schema beside
  it is the **producer's** schema: strict, enumerations closed, additions added as they are
  made;
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

## What the schema does not check

`testdata/attachments/attachment-v1.schema.json` expresses what JSON Schema can: the member
set, types, enumerations, the digest form, integer maxima, that a `"failed"` record lists no
pages, that a `"complete"` record is not truncated and has no errors, that a `"partial"` or
`"failed"` record has at least one error, that inline retention carries bytes and caller
retention does not, that OCR pages are distinct. It cannot check, and a producer's tests do:
that `chars` is the count of scalar values in `text` and `content.chars` their sum; that page
numbers ascend, are distinct and do not exceed `pageCount`; that `name` and `message` keep to
their **byte** limits (`maxLength` counts code points); that `processor` is `null` exactly
when no extractor ran; that every integer is written without fraction or exponent; that a
page's `extraction` agrees with its `status`; that an error's `page` names a listed page or
the first unlisted one.

## What this is not

- **Not a claim about the text.** The receipt covers the record's bytes. The record's own
  claims — this page had a text layer, that one was read by the program named — are the
  adapter's testimony, in the clear.
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
  caller's authorisation, is the next note; it writes this same record with
  `provenance.source.kind` naming the drive, `document.version` from the drive, and the
  original retained inline, under the `http` shape, whose acquisition members it can honestly
  fill.
