---
status: accepted
date: 2026-09-28
deciders: maintainer
---

# A document is rendered by an adapter under the command shape, and its record carries the file

## Context and problem statement

A desk, and an assistant working through one, needs to produce documents: a Word file, a PDF, a
Google Doc. Nothing in this repository renders one today, and a survey of published servers
found none that returns the file, keeps the text of every language and stays inside the access
this repository holds ([docs/design/rendering-survey.md](../design/rendering-survey.md)). The
question is where rendering lives, what it takes and returns, and what a receipt over it is
worth, settled before the adapter exists so that a desk integration can be built against it.

## Decision drivers

- The signer renders nothing, as it parses nothing
  ([ADR-0001](0001-one-engine-four-processes.md)).
- No change to `SPEC.md`: the receipt, its shapes and every verifier keep working unchanged.
- A receipt over a rendering should cover the document. That needs the file in the result, not
  a path to it.
- The adapter itself needs no credential and no network. It holds no credential and opens no
  connection.
- A document keeps the text it was given, in any language. Whether a reader or a renderer can
  show that text is a matter of fonts and layout, which the adapter does not supply.
- A rendering is an output. It is not evidence for the decision it reports, and producing it
  asks for no change to any connected storage.
- Outside catalogs are consumed, never vendored, and every dependency is a material decision
  (ADR-0001).

## Considered options

- Front a published Model Context Protocol (MCP) server through a catalog binding.
- An adapter in the second module under the `"command"` shape, taking structured content and
  writing a versioned record that holds the file. Word written in the module against the
  standard library; PDF produced by a program the operator configures.
- The same adapter, with PDF also written in the module.
- The same adapter, with one configured program producing both formats.
- A third-party rendering library as a dependency of the adapters module.
- Rendering in the desk, in the page or in its host.
- A new shape in `SPEC.md` for a rendering.

## Decision outcome

Chosen option: "an adapter under the command shape, Word in the module and PDF by a configured
program", because the receipt then covers the document, the adapter's own output keeps text of
any language, and no rendering code enters the tree that the repository does not review.

It is the reverse of what
[ADR-0004](0004-documents-are-an-adapter-under-the-command-shape.md) decided. There an adapter
takes a document and writes a record of its text. Here an adapter takes content and writes a
record that holds a document.

The determinations this record settles:

1. **The adapter.** `adapter-render`, in the adapters module, wired as a bare `--source` under
   the `"command"` shape of `SPEC.md` §1.2a, as `adapter-document` is. It holds no credential
   and opens no connection. What it reads and writes is its request, its result, and the
   rendering program it is configured with. What that program may reach is a separate matter,
   under determination 5.
2. **What it takes.** One request: a format, a title, and content as a structure of blocks —
   headings, paragraphs, lists and tables, with runs of text that may be emphasized or linked.
   It takes no HTML and no Markdown; a caller holding either converts it first. The structure
   is held to four rules.
   - It is closed. A request carrying a block, a run or a member the contract does not define
     is refused, not rendered in part.
   - Text is literal. Nothing in it is evaluated, expanded or fetched.
   - Nothing is brought in from outside the request: no image, font, stylesheet or include,
     and nothing is fetched or run. A link is another matter. It is a text and a target, the
     adapter writes the target into the file and never follows it, and the contract names the
     schemes a target may have.
   - Depth, counts and sizes are bounded.

   The claim this supports is about the adapter's own transformation: a Word file it writes
   holds the text and the structure the request gave. It is not a claim about what a PDF
   program does with them.
3. **What it returns.** One versioned record holding the file, base64-encoded, with its media
   type, its size and its SHA-256; a digest of the content it was given; the bounds that
   applied; and what rendered it. The receipt's output commitment therefore covers the file.
   That is a statement of which bytes were returned, not that they are a correct rendering.
   The exact members, and what each digest covers, are the contract's.
4. **Word.** Written by the module against the standard library. A `.docx` file is a ZIP
   archive of XML text, so text in any language is stored as text. A request that renders in
   full yields the same bytes whenever the canonical request, the adapter's effective
   configuration and the adapter's build are the same. That needs every part of the package
   written deterministically — entry order, timestamps, compression, and the order of every
   generated element and relationship — with nothing taken from the environment. The promise
   is about the file's bytes. How a reader lays the text out, and whether it has the fonts to
   show it, is the reader's.
5. **PDF.** Produced by a rendering program the operator configures, which the adapter runs as
   a separate process. With no program configured, a PDF request is refused by name and
   nothing is rendered.
   - **Lifecycle.** The program's lifecycle is the OCR program's, as
     [docs/design/attachments.md](../design/attachments.md) states it and
     `adapters/document/ocr.go` implements it.
     - The deadline is checked after the program is resolved and digested, immediately before
       it is started. If it has passed, the program is not started.
     - A program has finished when it has exited and its output has reached its end, in
       either order.
     - A program still running at the deadline is ended: the process the adapter started, not
       that process's own children. One that writes past the output bound is ended at once.
     - Output that has not reached its end a fixed time after the exit, or after the ending
       at the deadline, is closed by the adapter. The contract sets that time.
     - The outcome is taken once the adapter has observed the exit, and either the end of
       the output or that closing. If the deadline has passed by then, nothing the program
       wrote is used, even an answer that was complete. Otherwise output past the bound,
       output that was closed before it ended, and a failed exit are each a failure.
     - The adapter's deadline sits under the gateway's source timeout by enough to clean up
       and report. Where a program was ended at the deadline, the record is written some
       time after it.

     The deadline is neither the end of the call nor proof that every process the program
     started has stopped.
   - **No confinement.** The adapter hands the program the content and no credential, and it
     does not confine it. A program can read what the operating-system user it runs as can
     read, reach a network, and write files. Handing it no credential does not put
     credentials out of its reach. Separation from the seed and from platform credentials
     comes from giving the source a user of its own with `--source-user`, which the engine
     image does and a single-user desk deployment does not, as ADR-0004 records for the
     document adapter.
   - **What the record says.** It names the program as configured and the SHA-256 of the file
     that name resolved to, read before the program was started, as the attachment record
     does for an OCR program. A replacement between that read and the start is not detected.
     The digest says nothing of an interpreter, a library, a font or a further program the
     first one uses. The record vouches for nothing the program did, and does not claim that
     the same request yields the same bytes.
   - **Languages.** Which scripts a PDF shows depends on the program and the fonts installed
     with it. Supplying both is the operator's, and the record claims nothing about coverage.
6. **A Google Doc is not rendered, and cannot be made today.** The storage controls of
   [ADR-0005](0005-personal-storage-controls.md) create and update ordinary uploaded files.
   They refuse a native Google media type and have no conversion. Making a Google Doc from a
   rendered Word file would be an extension of those controls, with a contract and a review of
   its own. This record decides only that it is not rendering. It is a write, it needs a
   network and a credential, and the adapter has neither.
7. **What a rendering may cite.** A request may name the decision record the document reports,
   by digest. The adapter records that as the caller's assertion and checks nothing about it.
8. **How it is reached.** A desk reaches the adapter through its local plan, as it reaches
   `documents`. An MCP client cannot reach it through the engine today. The engine's bindings
   serve `history` by the `airbyte` shape and `live` and `write` by the `mcp` shape, and the
   MCP server lists live tools and sends each call to `<platform>/live`
   ([engine-config.md](../design/engine-config.md), [mcp-server.md](../design/mcp-server.md)).
   Serving this adapter needs three things that do not exist: a binding for a command-shaped
   source, the source the engine derives from it, and the MCP server's listing and dispatch
   for it, with a schema for its arguments. ADR-0004 named the first as the condition for
   serving document sources. That is a separate decision. It has not been made, and no record
   of it exists.

Why the other options were not chosen:

- **A published server.** Rejected for the versions, tools and unmodified bindings the survey
  read, against what this feature needs. One renders Latin text only. One saves the file to
  disk and answers with a message naming the path, and no tool of that release returns the
  file's bytes. One requests scopes beyond `drive.file`. An
  operator who accepts such a limit can bind such a server today, and nothing here prevents
  it.
- **PDF in the module.** A writer limited to the standard PDF fonts shows Latin text only. One
  that embeds fonts must also shape and break text for each script, which is the work of a
  layout engine.
- **One program for both formats.** It would make a Word file depend on an operator's program,
  where the module can write one with no program and reproducibly.
- **A rendering library.** Rejected for the dependency: a library linked into the adapter is
  code in the adapter's process that the repository does not review. A configured program's
  failure modes are not the repository's either. What separates the two is the process
  boundary, the deadline and the output bound, and that an operator may configure none.
- **Rendering in the desk.** A desk could render a file and hand it to a source that returns
  it, and the receipt would cover those bytes: `SPEC.md` §6 attests whatever a configured
  source returns. Rejected for what that receipt would say, which is that a source returned
  bytes it was handed, not that an adapter the gateway started made them from the content.
  ADR-0004 drew the same line for extraction.
- **A new shape.** The command shape already says the true thing about a rendering, which has
  no endpoint, no snapshot and no peer.

### Consequences

- Good, because a rendering's receipt is a version 3 receipt of a shape `SPEC.md` already
  defines, and its output commitment covers the file's bytes.
- Good, because a Word file needs no program, no dependency and no network, and its bytes are
  reproducible under determination 4.
- Good, because the signer's attack surface does not grow, and the adapter's is a closed
  structure it validates.
- Bad, because PDF is unavailable until an operator configures a program and the fonts it
  needs, and installing and updating both is then the operator's. A desk deployment has to
  supply them or go without. Accepted over a PDF written in the module that shows Latin text
  only.
- Bad, because a PDF's bytes depend on a program the repository does not review, and the
  record's digest identifies one file of it.
- Bad, because the module now maintains a Word writer, and the two formats are produced by
  different means and may lay the same content out differently.
- Bad, because a caller holding Markdown must convert it first. Accepted over an adapter that
  parses markup.
- Bad, because the content rides in the request. `--max-request` bounds an `/acquire` body at
  one mebibyte by default, and under an engine configuration `/acquire` keeps that default.
  Content that is large as text can pass it even where the Word file made from it would be
  small.
- Bad, because the file rides in the result. A file of 4 MiB is 5,592,408 bytes in base64,
  before the record around it. The gateway's default bound on a source's output is one
  mebibyte, which admits a file of under 768 KiB; a deployment that carries more raises
  `--source-max-output`, and under an engine configuration a derived source keeps the
  default. The adapter's own bound on the file is the storage controls' payload ceiling of
  4 MiB, so that no rendering is too large for them. Whether a save succeeds depends on more
  than size.
- Bad, because the gateway retains the result, as it retains every acquisition's. A rendered
  document is kept in the artifact store whether or not anyone saves it elsewhere.
- Bad, because an MCP client cannot reach the adapter through the engine until the separate
  decision of determination 8 is made and built.
- Revisit when a real document needs a layout the block structure cannot express; when the
  engine image ships a rendering program and fonts, each pinned by digest, for every platform
  the image is built for; or when a published server, bound unmodified, returns the file in
  its result, requests no scope beyond `drive.file`, and renders the sample text the survey
  note fixes for the twelve locales by the criterion the note states.

## More information

- [docs/design/rendering-survey.md](../design/rendering-survey.md) — the published servers
  read on 2026-09-28, at which release, from which files, and what each reading supports.
- [ADR-0004](0004-documents-are-an-adapter-under-the-command-shape.md) — the command shape for
  a supplied document, and the precedent this record follows in reverse.
- [ADR-0005](0005-personal-storage-controls.md) — where a rendered file is saved, and why that
  step is not an assistant's tool.
- [docs/design/attachments.md](../design/attachments.md) — how an operator's program is
  resolved, digested, bounded, ended and recorded, for OCR.
- [SPEC.md §1.2a and §6](../../SPEC.md) — the `"command"` shape, and what `/acquire` attests
  and retains.
- The contract — the request, the record, the refusals and the bounds — is written as
  `docs/design/rendering.md` in the pull request that adds the adapter.
- Material impact: public-surface, documented-claim, security, dependency. Cross-vendor review
  is recorded on the pull request that carries this record.
