# What SPEC.md left open, and what it settles that is easy to miss

A second implementation has to answer every question the text leaves to its
reader. The first part below lists those questions and the answer taken for
each, so that a disagreement with another implementation is a question about
the text, not a surprise. None is exercised by a corpus vector; each is a
candidate for a sentence in `SPEC.md` and a vector beside it. The second part
lists readings the text does settle, when read closely, and which a reader could
miss; they are recorded with the clause that settles them. Every reading in
both parts is held by a test.

## Open: questions the text leaves to its reader

1. **A value outside the canonical domain inside a receipt that is otherwise
   well formed** — a float in a member the version does not name, an integer
   past ±(2⁵³−1), or a lone surrogate escaped in a string, which RFC 8259's
   grammar admits and §1.1 refuses. Read here: the receipt parses, so it is not
   `malformed` for a version 2 receipt, whose order-1 list is explicit, nor for a
   version 3 one where the member's type is right; its signing input is
   undefined, so its signature cannot verify: `signature-mismatch`. Decoding the
   surrogate to U+FFFD instead would verify a different value than the one
   written.
2. **The case of a version 3 `keyId`.** §1.2 gives its form — the first 32
   characters of a SHA-256 in hex — and not its case. Read here: 32 hexadecimal
   characters of either case are of the form; one that is not the verifier's own
   key id, which is lowercase, is `key-mismatch`.
3. **The form of a version 3 `prevSignature`.** §1.2a names two forms, a digest
   and a signature, and says which members take each; `prevSignature` is not
   among them. Read here: only its type is structural, a string or `null`, and a
   `prevSignature` that names no previous receipt breaks the chain.
4. **Hex, for a version 2 signature.** Read here: an even number of hexadecimal
   digits of either case. An odd number is *not hex*, so `malformed`; an even
   number that is not 64 bytes is `signature-mismatch`, as §1.2a says version 2
   classed a wrong length.
5. **What a session is, and what it counts.** Read here: a session is a directory
   under `receipts/` — not a link to one. Its count is its entries whose names end
   in `.json` and are not directories; a link so named is counted and read
   through.
6. **A receipt file that cannot be read.** §4.1 names the receipts directory, not
   a file in it. Read here: no verdict, the evidence being present and
   unreadable.
7. **An artifact path that is a directory, or under an `artifacts` that is not
   one.** Read here: no artifact is at the path, so `artifact-missing`.
8. **What makes a registry line a loadable seal.** Read here: one JSON object,
   giving no name twice, whose `sessionId`, `sealedAt` and `keyId` are strings,
   whose `finalCount` is an integer, and whose `signature` is hex — and then §4
   step 2's two conditions. A member beyond the four the signature covers is
   neither signed nor read, and does not stop the seal loading.
9. **A citation in a decision record carrying members beyond the three.** Read
   here: tolerated, as a receipt's unknown members are, and held to the
   canonical domain with the rest of `cites`.
10. **A cited file that gives `signature` twice.** It has no one signature. Read
    here: nothing resolves against it.
11. **A public key of another length than 32 bytes on stdin.** Outside the
    process contract. Read here: no verdict.

## Settled: what the text requires, and a reader could miss

- **Bytes that are not UTF-8 are unparseable**, so `malformed` at order 1: a
  receipt is canonical JSON, raw UTF-8 (§1.1), and bytes that are not UTF-8 are
  no JSON text (RFC 8259 §8.1).
- **A version 3 `callIndex` below zero is `malformed`.** §1.2's index is
  `0`-based, and §1.2a makes every structural constraint of the members it
  inherits an order-1 condition.
- **A version 3 `keyId` not of §1.2's form is `malformed`**, not `key-mismatch`:
  the form is inherited as the index's is.
- **A session's head naming a previous receipt breaks the chain.** §1.2 says
  `prevSignature` is `null` at `callIndex` 0, and §1.4 checks the chain.
- **A citation reads nothing of the cited file but its signature** (§4 step 5):
  a cited receipt that is itself `malformed` — a name given twice elsewhere in
  it, say — is that receipt's own finding, and a citation of its one signature
  resolves. Step 7 resolves as step 5 does.
- **Within `cites` of a decision record, a name given twice is
  `record-citation-malformed`**, as `cites` is held to the canonical domain (§4
  step 7); a name given twice elsewhere in the record does not stop `cites` being
  read, since nothing else in it is.
- **Two candidates holding the same record report twice**: step 7 reports for
  each candidate.
- **A spelling §4.1 refuses is refused before anything is read**, the store
  included.
- **A decision-record directory named without a trailing separator that is a
  link has no candidates.** §4.1 says the walk stops at the link; the directory
  is there, and with no candidate every action receipt that passed is
  `decision-record-mismatch` (§4 step 6). With a trailing separator, the
  platform resolves the link and the walk goes on below it.
