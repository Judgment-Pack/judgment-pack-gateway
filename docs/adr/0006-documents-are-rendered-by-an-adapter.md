---
status: proposed
date: 2026-09-28
deciders: maintainer
---

# A document is rendered by an adapter under the command shape, and its record carries the file

## Context and problem statement

A desk, and an assistant working through one, needs to produce documents: a Word file, a PDF, a
Google Doc. Nothing in this repository or beside it renders one today. The question is where
rendering lives, what it takes and returns, and what a receipt over it is worth. It is settled
before the adapter exists, so a desk integration can be built against it, as
[ADR-0004](0004-documents-are-an-adapter-under-the-command-shape.md) settled reading.

Rendering is the reverse of what ADR-0004 decided. There an adapter takes a document and writes
a record of its text. Here an adapter takes content and writes a record that holds a document.

A survey of published Model Context Protocol (MCP) servers on 2026-09-28 found none that meets
the catalog's constraints without a gap. The three strongest, each read at its released version:

- `cyanheads/docgen-mcp-server` 0.2.3 returns a PDF inline and renders offline. Its README says
  it renders "structured layout (headings, paragraphs, lists, tables) but not arbitrary CSS,
  images, or scripts", and its renderer embeds Helvetica and keeps printable Latin-1 only.
- `valdo404/docx-mcp` 1.6.0 writes Word files and meets the constraints as published. Its
  `document_save` tool saves "to disk", so an acquisition would return a path and not the file.
- `taylorwilsdon/google_workspace_mcp` 1.29.0 creates Google Docs. For documents it requests the
  scopes `documents.readonly`, `documents`, `drive.readonly` and `drive.file`, where this
  repository's Drive connection holds `drive.file` alone.

## Decision drivers

- The signer renders nothing, as it parses nothing
  ([ADR-0001](0001-one-engine-four-processes.md)).
- No change to `SPEC.md`: the receipt, its shapes and every verifier keep working unchanged.
- A receipt over a rendering should cover the document. That needs the file in the result, not
  a path to it.
- Rendering needs no credential and no network. The adapter holds no credential and opens no
  connection.
- Text in every language a desk serves. The desk ships twelve locales, Japanese, Korean and
  Chinese among them, which the standard PDF fonts cannot show.
- A rendering is an output. It is not evidence for the decision it reports, and producing it
  writes nothing to anyone's storage.
- Outside catalogs are consumed, never vendored, and every dependency is a material decision
  (ADR-0001).

## Considered options

- Front a published MCP server through a catalog binding.
- An adapter in the second module under the `"command"` shape, taking structured content and
  writing a versioned record that holds the file. Word written in the module against the
  standard library; PDF produced by a program the operator configures.
- The same adapter, with PDF also written in the module.
- A third-party rendering library as a dependency of the adapters module.
- Rendering in the desk, in the page or in its host, with the gateway attesting nothing.
- A new shape in `SPEC.md` for a rendering.

## Decision outcome

Chosen option: "an adapter under the command shape, Word in the module and PDF by a configured
program", because it is the one option under which the receipt covers the document, every
language a desk serves is rendered, and nothing enters the tree that the repository does not
review.

The determinations this record settles:

1. **The adapter.** `adapter-render`, in the adapters module, wired as a bare `--source` under
   the `"command"` shape of `SPEC.md` §1.2a, as `adapter-document` is. It holds no credential,
   opens no connection, and reads no file but the rendering program it is configured with.
2. **What it takes.** One request: a format, a title, and content as a structure of blocks —
   headings, paragraphs, lists and tables, with runs of text that may be emphasized or linked.
   It takes no HTML and no Markdown. Content a caller holds in either is converted by the
   caller, so the adapter parses no markup and what it renders is what it was given.
3. **What it returns.** One versioned record holding the file, base64-encoded, with its media
   type, its size and its SHA-256; the digest of the content it was given; the bounds that
   applied; and what rendered it. The receipt's output commitment therefore covers the document.
4. **Word.** Written by the module against the standard library. A `.docx` file is a ZIP
   archive of XML text, and the application that opens it lays the text out, so every language
   is carried as text. The same request and the same adapter yield the same bytes: entries are
   written in a fixed order with fixed timestamps, and nothing in the file is random.
5. **PDF.** Produced by a rendering program the operator configures, which the adapter runs as
   a separate process under its deadline and its output bound. The adapter hands it the content
   and no credential. It does not confine the program: what the program may reach, a network
   included, is settled by the user it runs as and by the operator who chose it. The record
   names the program as configured and the SHA-256 of the file that name resolved to, read
   before it was started, as the attachment record does for an OCR program. With no program
   configured, a PDF request is refused by name and nothing is rendered. The record vouches for
   nothing the program did, and does not claim that the same request yields the same bytes.
6. **A Google Doc is not rendered.** It is a Word file saved to Drive with conversion asked
   for, which is a write. It belongs to the storage controls of
   [ADR-0005](0005-personal-storage-controls.md), stays inside `drive.file`, and is not decided
   here.
7. **What a rendering may cite.** A request may name the decision record the document reports,
   by digest. The adapter records that as the caller's assertion and checks nothing about it.
8. **How it is reached.** A desk reaches it through its local plan, as it reaches `documents`.
   An MCP client reaches it through the engine's MCP server once the engine's configuration can
   name an operation served by an adapter shipped with the engine. ADR-0004 named that
   condition for document reading, and it is one decision for both. It changes the
   configuration and the MCP server's tool table, and it has a record of its own.

Fronting a published server was rejected on what the survey found, not on principle. The PDF
candidate cannot show five of the desk's twelve locales. The Word candidate returns a path, so a
receipt would cover a name and a size. The Google candidate asks for more access than this
repository holds. An operator who accepts those limits can bind such a server today; nothing
here prevents it.

PDF in the module was rejected for the languages. A writer limited to the standard fonts shows
Latin text only. One that embeds fonts must also shape and break text for each script, which is
the work of a layout engine and not of an adapter.

A rendering library was rejected as ADR-0004 rejected a PDF library: its bounds and failure
modes would not be the repository's. Rendering in the desk was rejected because the gateway
would never see the file, so no receipt could cover it. A new shape was rejected because the
command shape already says the true thing about a rendering, which has no endpoint, no
snapshot and no peer.

### Consequences

- Good, because a rendering's receipt is a version 3 receipt of a shape `SPEC.md` already
  defines, and its output commitment covers the file.
- Good, because a Word file, and a Google Doc made from one, needs no program, no dependency
  and no network, and is reproducible.
- Good, because the signer's attack surface does not grow, and the adapter's is a structure it
  validates and not a markup language it parses.
- Bad, because PDF is unavailable until an operator configures a program. A desk deployment
  has to supply one or go without. Accepted: the alternative is a PDF that cannot show the
  text.
- Bad, because a PDF's bytes depend on a program the repository does not review. The record
  says which program, and claims no more.
- Bad, because a caller holding Markdown must convert it first. Accepted over an adapter that
  parses markup from a model.
- Bad, because the file rides in the result, so the gateway's bound on a source's output
  constrains it, as `--max-request` constrains the content. The adapter's bound on the file
  is set at the storage controls' limit of 4 MiB, so that a rendering can always be saved.
- Bad, because an MCP client cannot reach the adapter through the engine until determination 8's
  condition is met.
- Revisit when a layout need the block structure cannot express is shown by a real document,
  when the engine image can carry a rendering program without varying, or when a published
  server returns the file inline and renders every locale.

## More information

- [ADR-0004](0004-documents-are-an-adapter-under-the-command-shape.md) — the command shape for
  a supplied document, and the precedent this record follows in reverse.
- [ADR-0005](0005-personal-storage-controls.md) — where a rendered file is saved, and why that
  step is not an assistant's tool.
- [docs/design/attachments.md](../design/attachments.md) — how an operator's program is
  resolved, digested, bounded and recorded, for OCR.
- [SPEC.md §1.2a](../../SPEC.md) — the `"command"` shape and what it records.
- The contract — the request, the record, the refusals and the bounds — is written as
  `docs/design/rendering.md` in the pull request that adds the adapter.
- Material impact: public-surface, documented-claim, security. Cross-vendor review is recorded
  on the pull request that carries this record.
