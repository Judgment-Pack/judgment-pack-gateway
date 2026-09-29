# Rendering: the record an adapter writes, version 1

A desk, or an assistant working through one, has content it wants as a document: the report of
a decision, a letter, a summary. This note fixes the contract for that: what a caller hands
the gateway, and the one record the gateway attests in return, which holds the file.
[ADR-0006](../adr/0006-documents-are-rendered-by-an-adapter.md) decided the design; this note
is its contract.

It changes nothing in `SPEC.md`: no receipt member, no shape, no verifier rule. Rendering is an
adapter in the second module, a process the signer never links
([ADR-0001](../adr/0001-one-engine-four-processes.md)), and the record it writes is a result
like any other: canonicalized, retained as the artifact, its digest signed into a version 3
receipt. **What the receipt then proves is byte lineage: these bytes, returned by the source
the operator configured, at this call in this session, under this key.** It does not prove
that the file is a correct rendering of the content, or that any reader shows it as the caller
meant.

The adapter writes **Word files** itself. A **PDF** is produced by a rendering program the
operator configures, which the adapter hands the Word file it wrote for the same content
([The PDF](#the-pdf)); where no program is configured, a request for a PDF is refused by
name. A Google Doc is not a format of this contract (ADR-0006, determination 6).

The contract is versioned by the record's member `renderVersion`. This is version `"1"`. What a
version promises is in [Versioning](#versioning).

## The parties

- **The caller**, a desk through its chassis, holds the content and hands it to the gateway as
  the arguments of one `/acquire` call.
- **The gateway** runs the source, canonicalizes what the adapter wrote, retains it, and mints
  the receipt. It reads nothing of the content or of the file.
- **The adapter**, `adapter-render`, reads the arguments on stdin, holds them to the rules
  below, writes the file, and writes the record on stdout. It holds no credential and opens
  no connection. For a Word file it reads no file but its own executable and starts no
  process. For a PDF it also reads the rendering program's file, for its digest, and starts
  that program.
- **A rendering program**, when the operator configures one, is a separate executable the
  adapter runs for a PDF. The record says which program it was. It vouches for nothing the
  program did.

## How it is wired

The adapter is a bare source: no `--source-shape`, so the receipt's `acquisition.shape` is
`"command"` (SPEC.md §1.2a). What the gateway records of a bare source is in
[attachments.md](attachments.md#how-it-is-wired), and is the same here. The name of the source
is the operator's; the examples use `render`.

```
gateway serve ./store gateway.seed gateway:desk ./registry.jsonl --receipt-version 3 \
  --source render='adapter-render --max-output 6291456' \
  --source-user render=engine-render \
  --source-max-output 6291456
```

A request:

```
POST /acquire
{"session": "…", "source": "render", "arguments": {"format": "docx", "document": {"title": "Refund decision", "blocks": [{"type": "paragraph", "runs": [{"text": "The refund is approved."}]}]}}}
```

The answer is `{result, receipt, salts}` as for any acquisition; `result` is the record below.

**The gateway's bounds, stated plainly.** The content travels in the request and the file
travels in the result. `/acquire` reads at most 1 MiB of body by default, and counts the JSON
values of the arguments, refusing past 524,288 of them whatever the body bound
(`maxArgumentValues`, `go/serve.go`). The gateway reads at most 1 MiB of a source's output by
default. A file of *n* bytes is 4 × ⌈*n* / 3⌉ bytes of base64. The record around it is about
one kibibyte for a short title, and grows with the title, with the name of a rendering
program, and with the version the adapter was built with, which has no bound. For an adapter
whose version is 32 bytes or fewer it is under three kibibytes, so at the defaults the largest
file that fits is about 766 KiB. An
operator raises the two byte bounds with `--max-request` and `--source-max-output`, each up
to 64 MiB, on the command line only: under an engine configuration both keep their defaults.
The example above carries a file of 4 MiB, the adapter's default bound on the file.

**What names the adapter.** The desk's local plan does, as the source `render`
(`gateway-connections --local-plan`,
[host-independent-connections.md](host-independent-connections.md#local-source-launch-plan)).
It starts `adapter-render --max-output 6291456` as a bare source with a timeout of thirty
seconds, and leaves the adapter's other bounds and its deadline at their defaults. The plan
names no rendering program, so a desk's request for a PDF is refused as
`renderer-not-configured`.

Two things follow for a desk that takes this plan. The desk holds itself to the first, and
nothing holds it to the second:

- **Its bundle carries `adapter-render`.** A desk takes a plan only where every program the
  plan names is in its verified bundle
  ([host-independent-connections.md](host-independent-connections.md#local-source-launch-plan)).
  One whose bundle has no `adapter-render` refuses the plan whole, and has no local source
  at all, the document adapter's included.
- **It runs the gateway with a `--source-max-output` of 6,291,456 or more.** Under a smaller
  one the gateway ends the adapter where its record is longer than that, and the acquisition
  fails, though the adapter was allowed the record.

No engine
configuration and no image names the adapter; an operator who wants it there adds the
`--source` above. No image carries a rendering program either: an operator who wants PDFs
installs one, and the fonts it needs, and names it with `--renderer`
([The PDF](#the-pdf) has a command line for that).

**The adapter's identity, and the seed.** As for every source, `--source-user` is what keeps
the adapter away from the seed, and a deployment that runs the gateway and the adapter as one
user has no such separation ([attachments.md](attachments.md#how-it-is-wired), SECURITY.md).

## The arguments

The canonical arguments (SPEC.md §1.1) the gateway hands the adapter on stdin. Every object is
closed: a member the contract does not name, one given twice, or one of another type refuses
the request, and nothing is rendered in part. Member names are exact, so a name that differs
in case is another member.

| Member | Type | Meaning |
|---|---|---|
| `format` | string | required. `"docx"`, or `"pdf"` where the operator configured a rendering program |
| `document` | object | required. The content |
| `document.title` | string | required. The title of the document: 1 to 255 bytes of UTF-8, with no character from U+0000 to U+001F, no U+007F, and neither U+FFFE nor U+FFFF. It is written into the Word file's properties. It is not a file name, and the adapter derives none |
| `document.language` | string — optional | a language tag: two or three letters, then any number of parts of two to eight letters or digits, each after a hyphen, at most 35 bytes in all (`en`, `pt-BR`, `zh-Hant-HK`). The form is checked and the tag is not looked up in any registry. It is written into the Word file as given, as the language of the document |
| `document.blocks` | array | required. 1 to `--max-blocks` blocks, in the order they are to appear |
| `cites` | object — optional | what the caller says the document reports |
| `cites.decision` | string | required in `cites`. The digest of a decision record, `"sha256:"` and 64 lowercase hexadecimal characters. **The caller's assertion**: the adapter copies it into the record and checks nothing about it, not that such a record exists and not that the content reports it |

### Blocks

A block is an object whose `type` is one of four. There is no other block, and no block holds
another: a list is not nested in a list, and a table's cell holds runs and nothing else.

| `type` | Members | Meaning |
|---|---|---|
| `"heading"` | `level`, `runs` | a heading. `level` is an integer from 1 to 6 |
| `"paragraph"` | `runs` | a paragraph |
| `"list"` | `ordered`, `items` | a list. `ordered` is `true` for a numbered list and `false` for a list with bullets. `items` is an array of 1 to 1,000 items, each an object with the one member `runs`. Every numbered list begins at 1 |
| `"table"` | `header` (optional), `rows` | a table. `rows` is an array of 1 to 1,000 rows, each an array of 1 to 64 cells; a cell is an object with the one member `runs`. `header`, where present, is one row of cells in the same form. Every row holds the same number of cells, and the header that number too |

`runs` is an array of 0 to 512 runs. A run is an object:

| Member | Type | Meaning |
|---|---|---|
| `text` | string | required. The text, which may be empty |
| `bold`, `italic`, `code` | boolean — optional | emphasis, each `false` when absent. `code` asks for a fixed-width typeface |
| `link` | string — optional | the target of a link whose text is the run's |

### Text is literal

What this section and the two after it say is said of the Word file, which the adapter writes
for either format. Of a PDF the adapter promises none of it: a PDF holds what the rendering
program made of that Word file, and the adapter does not read it ([The PDF](#the-pdf)).

A run's text is written into the Word file as the characters it holds. Nothing in it is
evaluated, expanded or fetched: no markup, no field, no formula, no include. It is not
normalised and not trimmed.

- U+000A, a line feed, is a line break inside the paragraph, and U+0009 is a tab.
- Every other character from U+0000 to U+001F, and U+007F, refuses the request. A carriage
  return is one of them.
- U+FFFE and U+FFFF, which a Word file cannot carry, refuse the request.
- Everything else is carried as given, whatever its script or its direction. That includes
  characters a reader does not draw, or draws as a change of direction. The adapter does not
  judge what text looks like.

Nothing is removed or replaced to make a text admissible. A text is carried whole or the
request is refused.

### Links

A link is a text and a target. The adapter writes the target into the Word file and **never
follows it**: nothing is resolved, fetched or checked for existence. A target is:

- 1 to 2,048 bytes, with no character from U+0000 to U+0020, no U+007F, and neither U+FFFE
  nor U+FFFF;
- a URL whose scheme is `https`, `http` or `mailto`, in either case;
- for `https` and `http`, one that names a host. The host is what stands before any port, so
  `http://:80/` names none. That there is a host is what is checked, not that it is a name
  any host could have;
- for `mailto`, one address in its plainest form: one or more characters, an at sign, and one
  or more characters, with no second at sign and none of `/ \ : , ; < > " %`. No percent
  sign means nothing in the address is spelt by an escape, so the address is what it reads
  as. A question mark and what a mail program is to fill in may follow it, and that is not
  read. A fragment, which a `#` begins, may not. A list of addresses is not admitted, and
  neither is an address in quotation marks. The form is what is checked. Whether the address
  exists is not.

Any other target refuses the request. The target is written as given, not normalised: a
target the adapter admits is read back out of the file as the same string, and a test holds
that. What a reader does when a person follows a link is the reader's.

### Nothing is brought in

The request is everything the Word file is made from. There is no member for an image, a
font, a style sheet, a template or an include, and the adapter reads nothing from disk or
network to make the file. What a rendering program reads to make a PDF is its own.

## Refusals

A refused request is the adapter exiting 1 with one line on stderr and nothing on stdout; the
gateway then mints nothing and retains nothing. The line is ASCII, at most 160 bytes, and
begins with its code and a colon. It names the rule or the bound, and the block by its
position, counted from 1. Where the rule is a member's, it names the member, which is one the
contract defines: `a run's bold is true or false`. It repeats no member name the contract
does not define and no value the caller wrote.

The gateway refuses some requests before the adapter runs: a body past its request bound,
arguments that are not JSON, and arguments outside the canonical domain
([attachments.md](attachments.md#the-arguments)). For a request that reaches it, the adapter
checks in this order and refuses at the first check that fails:

1. stdin holds more than `--max-request` bytes: `request-over-bound`;
2. the arguments are not what the arguments table admits: `arguments-invalid`, for each of
   three checks in turn. First their depth: arguments whose objects and arrays nest deeper
   than nine, which is a run in a cell of a table, are refused by one pass over their bytes,
   before they are read for anything else. Then the canonical domain, over the whole of the
   arguments: arguments that are not JSON, a fraction, or a member named twice in any object,
   a block or a run included. Then the members of the arguments, of `cites` and of
   `document`: one missing, unknown or of another type, a `format`, `title`, `language` or
   `cites.decision` outside its rule;
3. `document.blocks` is empty: `content-invalid`; it holds more than `--max-blocks` blocks:
   `content-over-bound`;
4. each block in order, and within it each member in the order the adapter reads them. A
   block, a run, an item or a cell that breaks a rule of its form, a text or a target that
   breaks its rule: `content-invalid`. More runs, items, rows or cells than the structure
   admits: `content-over-bound`. The first failure met is the one reported;
5. the format is `"pdf"` and no rendering program is configured: `renderer-not-configured`.
   The content of such a request has been held to every rule above by then;
6. the deadline has passed, before the Word file is written or once the writing has ended:
   `timeout`. A rendering whose deadline passed while the file was written is refused for
   that, whether or not the file is within its bound. The Word file is written for either
   format;
7. the parts of the Word file together hold more than `--max-file` bytes, or the file itself
   is longer than that: `file-over-bound`
   ([Bounds and the deadline](#bounds-and-the-deadline)). For a PDF this is before the
   program is run;
8. for a PDF, what the rendering program did ([The PDF](#the-pdf)). The deadline had passed
   when the program was to be started, or when its outcome was taken: `timeout`. Anything
   else that is not an answer: `renderer-failed`;
9. the file's base64 alone is longer than `--max-output`, which is found before the file is
   encoded, or the record is longer than that: `record-over-bound`.

A failure of the adapter itself is `adapter-failed`: an executable of its own it cannot read, a
request whose reading has not ended two seconds past the deadline
([attachments.md](attachments.md#bounds-and-cancellation) states that cutoff, and the adapter
reads its request with the same code), a record it built that does not pass its own check, a
record it could not write.

**A rendering is whole or it is refused.** The adapter writes no record of a failure and no
record of part of a rendering: a record exists only where there is a file.

**An output that fails is the one case with something on stdout.** Everything above is
decided before the adapter writes anything. Writing the record can itself fail, and can fail
after stdout has taken part of it: the adapter then exits 1 with `adapter-failed`, and what
stdout took is not a record. That holds where stdout is a pipe whose reader has gone: the
adapter ignores the signal such a write raises, so that the write fails and is reported. The
gateway reads none of the output of a source that exited with a failure (`runSource`,
`go/serve.go`), so nothing is retained and nothing is minted.

**Retrying is a new acquisition.** `/acquire` is not idempotent: the same arguments sent twice
mint two receipts over two records. For a Word file the two hold the same file, from the same
build. For a PDF they need not.

## The record

One JSON object, written in the canonical form of SPEC.md §1.1: member names in code-point
order, integers only. Every member below is present in every version 1 record, but for the two
the table says are for a PDF only, which a record of a Word file does not have. A member
without a value is `null`, never absent. This is the record of the request under
[How it is wired](#how-it-is-wired), as one build of the adapter wrote it with every bound at
its default, laid out here for reading and with the file's base64 left out. The command line
shown there raises `--max-output`, and its record states that bound as `6291456`:

```json
{
  "file": {
    "bytes": "<3,860 characters of base64>",
    "encoding": "base64",
    "mediaType": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    "sha256": "sha256:5854407c533fae348fb3bcea207d8109aeba64fe02696c165e1d0387c328dc5d",
    "size": 2895
  },
  "provenance": {
    "adapter": {"digest": "sha256:6575af8d85e15d1f89b7abaf92d7c9885b4e2e796ae99a1d21febf6ce445f7ba", "name": "adapter-render", "version": "0"},
    "observedAt": "2026-09-28T22:09:02Z"
  },
  "renderVersion": "1",
  "rendering": {
    "bounds": {"maxBlocks": 2000, "maxFileBytes": 4194304, "maxOutputBytes": 1048576, "maxRequestBytes": 1048576, "timeoutMs": 25000},
    "durationMs": 6,
    "renderer": {"kind": "module", "name": "adapter-render/docx/1"},
    "status": "complete"
  },
  "request": {
    "blocks": 1,
    "cites": null,
    "contentDigest": "sha256:09eaf3124a60f28af3bb88fc7523d1ff862f5125e06eb5c3a149350a9507cf47",
    "format": "docx",
    "language": null,
    "textBytes": 23,
    "title": "Refund decision"
  }
}
```

| Member | Type | Meaning |
|---|---|---|
| `renderVersion` | string | `"1"` |
| `request.format` | string | the format asked for and written: `"docx"` or `"pdf"` |
| `request.title` | string | `document.title`, as given |
| `request.language` | string or `null` | `document.language`, as given |
| `request.contentDigest` | string | the SHA-256 of the canonical form (SPEC.md §1.1) of the `document` member of the arguments: the title, the language and the blocks. Two requests that spell the same content differently have one digest. It does not cover `format` or `cites` |
| `request.blocks` | integer | the number of blocks |
| `request.textBytes` | integer | the bytes of UTF-8 in the text of every run. The title and the targets are not counted |
| `request.cites` | object or `null` | `{"decision": …}` as the caller gave it: the caller's assertion, which the adapter did not check |
| `file.mediaType` | string | the media type of the file |
| `file.size` | integer | the length of the file in bytes |
| `file.sha256` | string | the SHA-256 of the file |
| `file.encoding` | string | `"base64"` |
| `file.bytes` | string | the file, in standard base64 (RFC 4648 §4), padded, with no line break: the one encoding of its bytes |
| `rendering.status` | string | `"complete"`. Version 1 has no other |
| `rendering.renderer.kind` | string | `"module"`: the file was written by the adapter's own code. `"program"`: it was written by the rendering program |
| `rendering.renderer.name` | string | for a module, which writer of the adapter wrote the file: `"adapter-render/docx/1"`. For a program, the program as the operator configured it: 1 to 255 bytes of UTF-8 with no character from U+0000 to U+0020 and no U+007F |
| `rendering.renderer.digest` | string | for a program only, and absent for a module: the SHA-256 of the file the program's name resolved to, read before the program was started |
| `rendering.source` | object | for a PDF only, and absent for a Word file: what the program was offered on its stdin. `mediaType`, `size` and `sha256` of the Word file, and `renderer`, the module's writer that wrote it. It does not hold the file, and it does not say that the program read it |
| `rendering.bounds` | object | the bounds that applied, as configured: each a positive integer of at most its ceiling ([Bounds and the deadline](#bounds-and-the-deadline)) |
| `rendering.durationMs` | integer | the time from when the adapter began reading the request to when it built the record, in milliseconds |
| `provenance.adapter` | object | the adapter as it describes itself: its name, its version, and the SHA-256 of the file the operating system reports as its executable. The adapter's testimony. The receipt carries the gateway's own reading of the same file |
| `provenance.observedAt` | string | when the adapter had read the request in full, in UTC to the second |

## The Word file

The file is a ZIP archive of seven XML parts: the content types, the package's relationships,
the properties, the document, the document's relationships, the styles and the numbering.

**How the archive is laid out.** The seven parts are its entries, by these names and in this
order: `[Content_Types].xml`, `_rels/.rels`, `docProps/core.xml`, `word/document.xml`,
`word/_rels/document.xml.rels`, `word/styles.xml`, `word/numbering.xml`. Each is deflated, and
is stated by its own header and by the directory in the same words: version 2.0, no flag, the
one timestamp, its checksum and its two sizes, its name and nothing beside the name. The
entries lie one after another from the first byte of the file. The directory follows the
last of them, the record that ends the archive follows the directory, and nothing follows
that: no comment, and no byte before, between or after. A test writes the archive again from
its parts by these rules, in code of its own and not the writer's, and holds it to be the
file, byte for byte.

**What it holds.** Every block in the order given, as the heading, the paragraph, the list or
the table it was; every run with the emphasis it had; every character of every text. A link
is a relationship of the document to a target outside the file, one for each distinct target.
A table's header is marked as a header row and written in bold. Each list numbers or bullets
its own items. The title, and the language where one was given, are the file's properties,
and the language is also stated as the default language of the text.

**What it does not state.** No author, no time of creation or change, no application name and
no revision. No page size and no margins: the page is the reader's default.

**What the writer chooses.** The request gives no sizes, colours or spacing, so the writer
supplies them, the same for every file:

- text at 11 points, with lines at 1.08 of their height;
- 8 points after a paragraph of the body and after a paragraph in a cell; 12 points before a
  heading and 4 after it; 3 points after an item of a list, and none between two items that
  follow one another;
- headings in bold, at 16, 13 and 12 points for levels 1 to 3 and 11 points for levels 4 to
  6, each kept with the paragraph after it and marked with its outline level;
- a list indented half an inch, its bullet or number hanging a quarter of an inch, with a
  bullet of `•` and numbers as `1.`;
- a link in blue, underlined;
- a table with single borders and cell margins, given the whole width of the text, its
  columns stated as equal widths. Those are preferred widths: the table's layout is not
  fixed, and a reader that lays a table out to its content may give them other widths;
- a header row in bold, marked to be repeated where the table continues on another page;
- an empty paragraph after a table that ends the document, and between two tables that
  follow one another, which a reader would otherwise join.

These are part of what `adapter-render/docx/1` names. None of them is content, and the empty
paragraphs are the only paragraphs in the file that the request did not give.

**The same content gives the same bytes.** Two requests whose `document` has the same
canonical form yield the same file, byte for byte, from the same build of the adapter. No
bound changes the bytes, only whether the rendering is refused, and `cites` is no part of the
file. The parts are written in one order, each under one fixed timestamp (1 January 1980),
each compressed before it is stored so that its sizes are in its own header, and nothing is
taken from the clock, the environment or a random source. Another build may write other bytes
for the same content: the compression is the standard library's, and a release of Go may
change what it writes. `provenance.adapter.digest` names the build.

**What is the reader's.** How the text is laid out, where a line or a page breaks, and
whether the reader has a typeface for a script. The file names typefaces and embeds none: the
text's own typeface is left to the reader, and `code` names `Courier New`, for which a reader
substitutes what it has. The language is stated for a reader's proofing. It sets no direction
of text and chooses no typeface. The file holds the text of any language as text. Whether it
is shown is not the adapter's to promise.

## The PDF

A PDF is what the rendering program wrote. The adapter's part is the Word file it hands the
program, which is the file a request for `"docx"` yields for the same content, byte for byte.

**What the program is given.** It is run once for a request, with two arguments, `docx` and
`pdf`: what it is handed and what is asked of it. The Word file is on its stdin, and the
adapter does not know whether the program read it. Its environment, its working directory
and its process group are the adapter's own. Its stderr is discarded.

**The program is one written for this.** A converter named by itself is handed `docx` and
`pdf` as its arguments and makes of them what it will. LibreOffice, named as `soffice`,
takes them for the names of two files to open, and opens a window to say that it cannot find
them. The operator names a program that reads its stdin and writes its stdout, as the
example below does.

**What it answers.** The PDF on its stdout, within `--max-file`, and a successful exit. The
adapter admits what it wrote only where it begins as a PDF does, with `%PDF-`, a digit, a
full stop and a digit, and the marker `%%EOF` stands in its last 1,024 bytes. That is a test
of form. The adapter does not open the PDF, and says nothing of what it holds.

**How it is run.** Under the lifecycle [attachments.md](attachments.md#how-a-document-is-processed)
states for the OCR program, from the same code, `adapters/internal/program`:

- The program's name is resolved and its file is read for its digest. A name with no path
  separator is looked for on the adapter's `PATH`, and one found through an entry of `PATH`
  that is not an absolute path is not used. That last is the Go library's rule and not the
  adapter's own: an adapter started with `GODEBUG=execerrdot=0` in its environment uses such
  a program. A name with a path separator is a path, from the adapter's working directory
  where it is a relative one. The deadline is then checked, and
  a program whose deadline has passed is not started: `timeout`.
- Resolving the name, reading the file and starting the program are not interrupted by the
  deadline. A name that resolves to something that does not end when it is read, a pipe for
  one, holds the adapter until the gateway ends it. The operator names a regular file.
- A program has finished when it has exited and its stdout has reached its end, in either
  order. One still running at the deadline is ended: the process the adapter started, not
  that process's own children. It is ended at once, by a signal it cannot catch, so it
  clears nothing up. One that writes past `--max-file` is ended at once in the same way.
- A stdout still open is waited for by one timer of two seconds, started when the adapter
  first observes the exit or the deadline. When the timer ends the adapter closes the pipe.
  The exit of the process the adapter started is waited for with no timer of its own.
- The outcome is taken once the adapter has observed the exit, and either the end of stdout
  or its own closing of the pipe. If the deadline has passed by then the rendering is
  refused with `timeout`, and nothing the program wrote is used, even a PDF that was whole.
  That is so of a program the adapter ended, and of one that had exited and left its stdout
  open in a process of its own: the refusal does not say which.
- Otherwise each of these is `renderer-failed`: a name that does not resolve, a file that
  cannot be read for its digest, a program that cannot be started, a failed exit, output
  past the bound, a stdout closed by the adapter before it ended, and an answer that is not
  a PDF by the test above.

A refusal says which of these it was, in the adapter's words. It repeats nothing the program
wrote, on either of its outputs.

**The adapter does not confine the program.** It hands the program the Word file and no
credential. The program can read what the operating-system user it runs as can read, reach a
network, and write files. Separation from the seed and from platform credentials comes from
`--source-user`, as for every source.

**What the record says of the program.** Its name as configured, and the SHA-256 of the file
that name resolved to, read before the program was started. A replacement of the file
between that read and the start is not detected. Where the program is a script, the digest
is the script's and says nothing of the interpreter; it says nothing of a library, a font
or a further program the first one uses.

**What is not promised of a PDF.** That the same content gives the same bytes: a program may
write the time into what it makes. That a script is shown: that depends on the program and
the fonts installed with it, which are the operator's to supply. That the PDF says what the
Word file says: the adapter does not read it.

**Time.** A program that starts a word processor takes seconds. The adapter's deadline and
the gateway's timeout for the source are the operator's to size for it, the first under the
second with room for the two-second timer:

```
gateway serve ./store gateway.seed gateway:desk ./registry.jsonl --receipt-version 3 \
  --source render='adapter-render --max-output 6291456 --timeout 55s --renderer render-pdf' \
  --source-user render=engine-render \
  --source-timeout render=60 \
  --source-max-output 6291456
```

**A program, as an example.** Nothing in this repository is a rendering program, and none
is recommended. This script is one way to make one of LibreOffice, and was tried with
version 6.4.7, where a rendering took twenty seconds with a new profile made for the run:

```sh
#!/bin/sh
# adapter-render hands the Word file on stdin and takes the PDF from stdout.
set -eu
dir=$(mktemp -d)
trap 'rm -rf "$dir"' EXIT
cat > "$dir/in.docx"
soffice --headless "-env:UserInstallation=file://$dir/profile" \
  --convert-to pdf --outdir "$dir" "$dir/in.docx" >/dev/null 2>&1
cat "$dir/in.pdf"
```

What such a script reads, writes and starts is its own and the operator's. The record names
the script. Two things follow from how a program is ended:

- The script's `trap` runs when the script exits of itself. It does not run when the adapter
  ends the script at the deadline, and the directory then stays, with the Word file in it.
  An operator clears such directories by other means.
- The word processor is the script's child and not the adapter's. When the adapter ends the
  script, the word processor goes on until it ends of itself. An operator who needs it ended
  bounds it in the script, or runs the source under a supervisor that ends the whole group.

## Bounds and the deadline

Every bound is the operator's, on the adapter's command line, and the record reports them.

| Flag | Default | Ceiling | Bounds |
|---|---|---|---|
| `--max-request` | 1 MiB | 64 MiB | the request read from stdin; at or below the gateway's `--max-request` |
| `--max-blocks` | 2,000 | 100,000 | the blocks of one document |
| `--max-file` | 4 MiB | 64 MiB | the file; for a Word file, what its parts hold once they are read out of it; for a PDF, what the rendering program may write, and the Word file it is handed as well. The default is the payload ceiling of the storage controls ([storage-files.md](storage-files.md)) |
| `--max-output` | 1 MiB | 1 TiB | the record on stdout; at or below the gateway's `--source-max-output` |
| `--timeout` | 25 s | 10 min | the adapter's deadline, from its start, a whole number of milliseconds |

`--renderer PROGRAM` names the rendering program and is absent by default. An empty name is
no program. Any other is 1 to 255 bytes of UTF-8 with no character from U+0000 to U+0020 and
no U+007F: one word, with no space in it. The name is resolved when a PDF is asked for, not
when the adapter starts.

Each bound is a positive integer at most its ceiling; any other value, a renderer's name
outside its rule, an unknown flag or a positional argument is a usage error, and the adapter
exits 2 without reading the request.

The structure's own bounds are the contract's and not the operator's: 6 heading levels, 512
runs in one block, item or cell, 1,000 items in a list, 1,000 rows and 64 columns in a table,
2,048 bytes in a target. The structure does not nest, so its depth is fixed at nine: the
arguments, the document, its blocks, a block, its rows, a row, a cell, its runs, a run. The
text of a document is bounded by the request that carries it.

**The file's parts are bounded as the file is.** A Word file is a compressed archive, and its
parts are XML, which says at length what the request said briefly and compresses well. A
request of 879 KiB has been made to yield a file of 37 KiB whose document part holds
11.4 MiB. So `--max-file` is held over two things: the bytes the seven parts hold together,
as a reader of the file is given them, and the bytes of the archive. The parts have been the
longer of the two in every file the adapter has been seen to write, so they are what the
bound meets, and the archive is held to it as a second guard.

The adapter refuses a file past either. `render.Check` holds a record to both as well, and
to the layout of the archive. It takes the seven parts out of the file from where the writer
puts them, writes the archive of those parts again with the writer's own code, and refuses a
file that is not that archive byte for byte: one with other entries, or with thousands of
them, with entries that share their bytes, with a comment, or with any byte the writer does
not write. It refuses a record whose parts together state more than
`rendering.bounds.maxFileBytes`, and a record whose bounds are past the ceilings an adapter
can be configured with. It then reads each part out of its inflater, asking for no more than
the part states and one byte, and refuses a part that holds other than it states, whose
checksum is not the one stated, or whose data holds anything after what it holds. What the
check reads of a file is the file, and what it takes out of the inflaters is within the
bound and a byte for each part. An inflater holds some of what it has inflated inside
itself, of a fixed size, before it is asked for it.

The check writes the archive with the writer's code, so what it holds a file to is what the
writer writes. That what the writer writes is the layout stated under
[The Word file](#the-word-file) is held by the tests, which read and write the archive by the
format's rules in code of their own.

A consumer that runs the check on a record of a Word file can take
`rendering.bounds.maxFileBytes` as a bound on what opening that file unpacks. One that does
not enforces a limit of its own as it extracts, as it would for any archive.

**None of this is so of a PDF.** The check reads every byte of a PDF for its digest and
parses none. Of what makes a file a PDF it holds the file to its first bytes and its last
1,024, and to nothing between. A PDF holds compressed streams of its own, and the bound on the file
says nothing of what they hold once they are read: a PDF of 8,603 bytes has been made that
passes the check under a bound of 4 MiB and holds a stream of 8 MiB. A consumer that opens a
PDF limits what its reader may use, whatever the check said.

**What bounds the adapter's memory for a Word file is the request, not this.** The writing
stops early, at the first block that begins with the document part and the targets of its links
together past the bound. That saves work. It is not a bound on what the adapter holds, which
includes the arguments as read, one block past the point where the writing stops, and the parts
before they are compressed. One block can carry the whole text of a request, and the XML is
longer than the request that carried it: about fifteen times the request's bytes at the worst
found, which is twenty-two and a half times the text's, for text that alternates an ampersand
and a tab. An operator who raises `--max-request` raises that with it.

**For a PDF it is the bound on the file as well.** A rendering program can answer with as
much as `--max-file` admits whatever the request's size. The adapter holds that answer, then
its base64, then the record, and the record again while it checks it. On one machine, a
request of under a hundred bytes whose program answered 4 MiB took the adapter to 66 MiB of
memory, and one whose program answered 64 MiB to 990 MiB. A file whose base64 alone is past
`--max-output` is refused before any of that is made of it: the same 64 MiB under a bound on
the record of 6 MiB was refused at 134 MiB when the maintainer measured it and at 263 MiB
when the reviewer did. These are measurements and not bounds. An operator who raises
`--max-file` for PDFs raises what the adapter may hold with it.

A record past `--max-output` is not cut, and a file past `--max-file` is not cut: the adapter
refuses. With the defaults as they stand, a file of more than about 766 KiB is refused with
`record-over-bound`, since its record is past a mebibyte, and an operator who wants larger
files raises `--max-output` and the gateway's `--source-max-output` together. Text that does
not compress reaches that within the default request bound: a request of a mebibyte of it
makes a file of some 770 KiB.

**A deadline is when work stops being started, not a completion guarantee.** The deadline runs
from the adapter's start. The reading of the request is inside it. It is checked before the
Word file is written and once the writing has ended, each time by the clock as well as by
the timer; a rendering whose deadline has passed at either check is refused. For a PDF it is
read twice more, as [The PDF](#the-pdf) says: before the program is started, and when its
outcome is taken. Nothing else reads
the deadline, and what is done between resolving the program and starting it is not
interrupted by it. The arguments are read and held to their rules before the first check, and the
file is written between the two, and each runs to its end. The record is encoded and written
after the second check, and that is not checked again. The gateway's own timeout for the
source, thirty seconds by default, ends the process whatever it is doing.

## What a consumer should do

1. Verify the receipt as for any acquisition. It covers the record, and so the file.
2. Read `renderVersion`, and treat a version it does not know as a record it cannot read.
3. Decode `file.bytes`, and compare the length with `file.size` and the SHA-256 with
   `file.sha256`. The reference check does both. For a Word file it also reads the file's
   parts to hold them to the record's bound, and a consumer that opens a Word file without
   the check limits what it extracts. For a PDF the check bounds nothing of what the PDF
   holds: a consumer limits what its reader may use.
4. Name the file itself. The title is a title: it may hold characters a file system refuses.
5. Treat `request.cites` as what the caller said. Whoever relies on it checks the decision
   record it names.
6. Save the file where the person chooses, by whatever the deployment provides for that. The
   adapter saves nothing. The gateway retains the record, as it retains every result, so the
   file is in the artifact store whether or not it is saved anywhere else.

## Versioning

`renderVersion` names this contract. The members this note lists are the version 1 set: every
one that is not optional is present in every version 1 record, and none is removed, renamed,
retyped or given another meaning. The optional ones are the two the record's table says are
for a PDF only. Within version `"1"`:

- a member may be added to the record only as an optional one, read as "not stated" when
  absent;
- a value may be added to `request.format`, with its media type, to `rendering.renderer.kind`
  and to `rendering.renderer.name`;
- a block type, a member of a run, or a link scheme may be added to what the arguments admit.
  An adapter that does not know one refuses the request, as the closed structure requires;
- `render.Check` and the schemas beside this note are the producer's, closed as the adapter
  writes. A consumer validates for compatibility: it tolerates a member it does not know, and
  reads a `status` it does not know as not `"complete"`.

A writer whose files differ for the same content is given another `rendering.renderer.name`
where the difference is one of structure. A difference of compression alone, from a release of
Go, is not.

Changelog:

- `"1"` — this note. Written by `adapter-render` from its first release, for `"docx"`.
- `"1"`, added for a PDF by a rendering program: the format `"pdf"` with the media type
  `application/pdf`; the renderer kind `"program"`, whose `name` is the program as
  configured; the optional members `rendering.renderer.digest` and `rendering.source`, each
  present for a PDF and absent for a Word file; the refusal code `renderer-failed`. A record
  of a Word file is what it was.

## The check, the schemas and the examples

`render.Check` in `adapters/render` is the reference check of the record: it takes a record's
bytes and says whether they are a version 1 record — the members closed, each of its form, and
the file what the record says of it, its base64 the one encoding of bytes of the stated size
and digest. For a Word file those bytes are the archive the writer writes, of seven parts
that hold no more than the record's bound on the file. For a PDF they begin and end as a PDF
does, and the record names a program with its digest and says what the program was handed.
The check says nothing of whether the file is a correct rendering of any content, nor of
what a Word file's parts or a PDF hold: it reads neither. The adapter holds every record it
writes to the check before it writes it.

The check is of a record's form. It does not show that an adapter could have written the
record. It does not relate the counts of the request to the bounds the record states, so it
admits a record of seven blocks under a bound of one. It does not hold the record's own
length to `maxOutputBytes` either: a consumer bounds what it reads by a limit of its own. And it cannot know what a program was
handed: of `rendering.source` it holds the form, and that the size is within the bound on
the file. What makes a record an adapter's is the receipt over it.

`testdata/rendering/arguments-v1.schema.json` and `testdata/rendering/render-v1.schema.json`
describe the arguments and the record as JSON Schema. They check each value on its own. The
rules that relate values are the adapter's and the check's, with one exception: that every
row of a table holds the same number of cells, that the size and the digest are the file's,
that the file's parts are within the bound, that the file is laid out as the writer lays it
out. The exception is the format: the record schema holds the media type, the kind of the
renderer and the presence of `rendering.source` to the format the record states. And a schema
is looser than the adapter in five places, each stated in the schema's own description and,
where a parsed value can show it, held by the script as something the schema admits:

- a schema counts a length in characters where the adapter counts bytes of UTF-8, so a title
  of 128 characters of two bytes each passes the schemas, and neither the adapter nor the
  check. The same is so of a rendering program's name in the record;
- the arguments schema does not parse a target, so it admits an `http` target that names a
  port and no host;
- the arguments schema does not know the operator's `--max-blocks`;
- neither schema knows how a value was written. A schema reads JSON that has been parsed,
  where a member named twice is one member, `7.0` is the integer 7 and `-0` is 0. The first
  two are outside the canonical domain. The third is inside it, and the adapter and the check
  refuse it all the same: they read an integer as digits, with no sign;
- the record schema's pattern for an instant admits a day the month does not have, the
  thirtieth of February, which the check refuses.

The depth of the arguments and of a record is not among them: each schema is closed and no
part of it holds itself, so nothing deeper than the structure passes it.

The arguments schema is not written within the descriptor grammar of
[tool-descriptors.md](tool-descriptors.md): it names its shared parts by reference and states
lexical forms as patterns, and that grammar admits neither.

`testdata/rendering/examples/` holds a request, `refund-decision.request.json`, and the record
one build of the adapter wrote for it, `refund-decision.record.json`. It holds the record of
the same request for a PDF as well, `refund-decision.pdf.record.json`, made with a stand-in for
a rendering program that answers one small PDF whatever it is handed: the record shows the
members of a PDF's record, and its file is not a rendering of the content. The adapter's tests
hold the record to the check, and hold the request to yield the record's `request` member, its
`contentDigest` included, and a file whose seven parts are the example's once each is read out
of its archive. They do not hold it to yield the record's file byte for byte, since another
build may write other bytes. `testdata/rendering/check_schema.py` holds both examples, and a
record written in the run that checks it, to the schemas; holds the schemas to refuse a list of
broken variants of each; and holds them to admit the differences listed above.

## What this is not

- **Not a claim about the file.** The receipt covers the record's bytes. That a Word file
  holds the text and the structure of the content is what the adapter is built and tested to
  do, and is the adapter's testimony. Of a PDF the adapter says which program wrote it and
  what that program was handed, and nothing of what it holds.
- **Not a conversion.** The adapter takes no HTML and no Markdown. A caller holding either
  converts it to blocks first.
- **Not a layout.** No page size, column, image, footnote, header or footer, and no position
  on a page. Content that needs one is not content this contract renders.
- **Not a save.** The adapter writes nothing to disk or to any storage. A rendering program
  may: the example under [The PDF](#the-pdf) writes the Word file and the PDF to a directory
  of its own. Saving is a separate act, under
  [ADR-0005](../adr/0005-personal-storage-controls.md).
- **Not evidence.** A rendering is an output. It is not evidence for the decision it reports.
- **Not reachable through the engine's MCP server.** The server serves the live tools of
  platforms bound in an engine configuration, and no binding serves a bare command
  (ADR-0006, determination 8).
- **Not a change to the signer.** Nothing here touches the core module.
