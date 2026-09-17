---
status: proposed
date: 2026-09-16
deciders: maintainer
---

# A document attached to a desk is processed by an adapter, and attested under the command shape

## Context and problem statement

A desk lets a person attach a document — a PDF, a scanned form, a text export — and wants
its content available to the assistant with the same lineage a page fetched through
`adapter-http` has: a receipt per document, verifiable under the gateway's key, and a record
that says what was extracted and what was not. Extracting text from a PDF is parsing of
hostile input, and reading a scanned page needs an OCR engine the engine image cannot carry
without varying. Neither belongs in the process that holds the seed. The question is where
document processing lives, what shape its receipts take, and what the record it writes
promises — settled before the adapter exists, so a desk integration can be built against it
([docs/design/attachments.md](../design/attachments.md)).

## Decision drivers

- The signer parses nothing it did not have to before: no PDF parser, no image, no OCR in
  the core module ([ADR-0001](0001-one-engine-four-processes.md)).
- No change to `SPEC.md`: the receipt, its shape enumeration and every verifier — the
  reference, the second implementation, a desk's own — keep working unchanged.
- A receipt must not say more than what happened. A document the caller supplied has no
  endpoint, no snapshot and no peer; a receipt that named a transport shape for it would
  record an acquisition that did not take place.
- Extracted text is a derivative and the original is the document: the record must keep
  them apart, bind the original by digest, and say for every page what was done.
- Scanned pages are the common case for the documents that matter — forms, letters, legacy
  policy — and must be handled explicitly, never silently as empty text.
- Bounded processing with a partial result on the deadline, not a kill with nothing minted.

## Considered options

- A document adapter in the second module, wired as a bare `--source` (the `"command"` shape
  of SPEC.md §1.2a), writing one versioned record as its result.
- The same adapter declared `--source-shape documents=http`, writing the §6 envelope with
  `null` for every transport member.
- A new `"document"` shape in SPEC.md §1.2a and §6, with the verifiers and the corpus
  extended to admit it.
- Processing in the desk (a JavaScript PDF library in the page), with the gateway attesting
  the text the desk extracted.
- A third-party PDF library as the adapter's first dependency.

## Decision outcome

Chosen option: "an adapter under the command shape", because it records no more than the
gateway knows — the receipt names the command's first word as configured and the digest of the
file that word resolved to, read before the process was started, and every acquisition member a
command cannot record is `null` or, for `pageItems`, absent, which is what a supplied document
has — and because it needs
no change to the specification or to any verifier. The record the adapter writes carries what
the adapter can add, as its testimony, in the clear inside the signed artifact: its account of
itself, when it read the request, the document's digest, the outcome of every listed page, the
bounds that applied, and the OCR program whose answers it applied. Retrieval from a drive,
which does have an endpoint, a version and a TLS peer, is a later note and a separate source
under the `http` shape, writing the same record.

Processing in the desk was rejected as a matter of what this feature chooses to attest, not
of what the specification forbids: SPEC.md §6 attests whatever a configured source returns,
and a source that echoed caller-supplied text would be within it. The evidence this feature
wants is stronger — the configured adapter's testimony, attributed by the receipt, that it
derived the text from bytes the arguments commitment covers and whose digest the record states,
given by a source the gateway started and whose file the receipt digests. Neither the receipt
nor any check establishes that derivation; the gateway commits to the arguments and to the
output separately. A desk-side extractor cannot give even that testimony, since the gateway
would never have seen the bytes the text came from. That the file digested is the program that
ran assumes it was not replaced between the gateway's read and the start, a race SECURITY.md
states and the gateway does not detect. A new shape was rejected for this line because it is a
normative change every verifier must follow before a single receipt is useful, and the command
shape already says the true thing: it opts the source out of the envelope's acquisition
reporting, which for a supplied document has nothing to report. The adapter takes no third-party
dependency in its first release: the PDF reader is written in the module
against the standard library, with every bound explicit, so what runs in the engine image is
what the repository reviews.

### Consequences

- Good, because a document receipt is a version 3 receipt of a shape SPEC.md §1.2a already
  defines, so a verifier of version 3 receipts needs no change to verify it.
- Good, because the signer's attack surface does not grow: the parser of hostile input runs as
  a source, under the bounds and the kill every source runs under — and away from the seed
  when the operator gives it a user of its own (`--source-user`), which the engine image does
  and a single-user desk deployment does not.
- Good, because scanned pages are a stated status, OCR is an operator's program run out of
  process and recorded, and nothing pretends to have read what it did not.
- Bad, because a command-shaped receipt records less than an envelope would: the adapter's
  own observation time and identity are in the record, not in the receipt's acquisition.
  Accepted: for a supplied document the difference is the adapter's testimony either way.
- Bad, because an inline document rides in `/acquire`'s arguments, which the reference
  implementation bounds at 1 MiB, and a source runs for thirty seconds. Accepted for the
  contract; a separate core change proposes `--max-request` and a per-source timeout, and the
  contract states the bounds that apply until then.
- Bad, because a PDF reader in the module is code this repository must maintain. Accepted
  over a dependency whose bounds and failure modes the repository does not control.
- Revisit when a receipt consumer needs the document's acquisition in the receipt itself —
  then the `"document"` shape is the proposal, as a specification change with its corpus
  vector — or when the engine configuration grows a binding for document sources, which the
  MCP server could then serve.

## More information

- [docs/design/attachments.md](../design/attachments.md) — the contract, version 1.
- [SPEC.md §1.2a](../../SPEC.md) — the `"command"` shape and what it records.
- [ADR-0002](0002-adapters-report-in-the-envelope.md) — why an adapter that can report its
  acquisition does so in the envelope; the document adapter under the `http` shape, for
  retrieval, will.
