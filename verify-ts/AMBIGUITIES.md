# What SPEC.md left open, and the answer taken here

Questions a second implementation had to answer that neither `SPEC.md` nor the
corpus settles. Each is recorded with the reading taken, so that a disagreement
with another implementation is a question about the text, not a surprise. None
is exercised by a corpus vector; each is a candidate for a sentence in `SPEC.md`
and a vector beside it.

## Receipts

1. **Bytes that are not UTF-8.** Not a JSON text at all (RFC 8259 §8.1), so
   *unparseable*: `malformed` at order 1.
2. **A value outside the canonical domain inside a receipt that is otherwise
   well formed** — a float in a member the version does not name, an integer
   past ±(2⁵³−1), or a lone surrogate escaped in a string, which RFC 8259's
   grammar admits and §1.1 refuses. The receipt parses, so it is not
   `malformed` for a version 2 receipt, whose order-1 list is explicit, nor for
   a version 3 one where the member's type is right; its signing input is
   undefined, so its signature cannot verify: `signature-mismatch`. Decoding the
   surrogate to U+FFFD instead would verify a different value than the one
   written.
3. **A version 3 `callIndex` below zero.** §1.2 calls it `0`-based; read as a
   structural constraint, so `malformed`. (A version 2 receipt's order 1 asks only
   that it be an integer.)
4. **The form of a version 3 `keyId` and `prevSignature`.** §1.2a names two
   forms, a digest and a signature, and neither is either. Only their type is
   structural: `keyId` a string, `prevSignature` a string or `null`. A `keyId`
   that is not the verifier's is `key-mismatch`; a `prevSignature` that names no
   previous receipt breaks the chain.
5. **Hex, for a version 2 signature.** An even number of hexadecimal digits of
   either case. An odd number is *not hex*, so `malformed`; an even number that
   is not 64 bytes is `signature-mismatch`, as §1.2a says version 2 classed a
   wrong length.
6. **A session's head naming a previous receipt.** §1.2 says `prevSignature` is
   `null` at `callIndex` 0; a head that names one breaks the chain, and the
   session reports `chain-broken`.

## The store

7. **What a session is, and what it counts.** A session is a directory under
   `receipts/` — not a link to one. Its count is its entries whose names end in
   `.json` and are not directories; a link so named is counted and read through.
8. **A receipt file that cannot be read.** No verdict: the evidence is present
   and unreadable, as §4.1 says of the receipts directory.
9. **An artifact path that is a directory, or under an `artifacts` that is not
   one.** No artifact is at the path: `artifact-missing`. Any other failure to
   read one is no verdict.

## The registry

10. **What makes a line a loadable seal.** One JSON object, giving no name twice,
    whose `sessionId`, `sealedAt` and `keyId` are strings, whose `finalCount` is
    an integer, and whose `signature` is hex — and then §4 step 2's two
    conditions. A member beyond the four the signature covers is neither signed
    nor read, and does not stop the seal loading. Any other line is dropped.

## Decision records

11. **A decision-record directory named without a trailing separator that is a
    link.** §4.1 says the walk stops at the link: the directory is there, and the
    walk finds no candidate in it, so every action receipt that passed is
    `decision-record-mismatch`. With a trailing separator, the platform resolves
    the link and the walk goes on below it.
12. **A citation in a decision record carrying members beyond the three.**
    Tolerated, as a receipt's unknown members are. A name given twice anywhere
    inside `cites` is outside the canonical domain it is held to, and
    `record-citation-malformed`; a name given twice elsewhere in the record does
    not stop `cites` being read.
13. **Resolving a citation against a file that gives a name twice.** It has no
    one `signature` member, so nothing resolves against it.
14. **Two candidates holding the same record.** Step 7 reports once per record;
    here that is once per candidate, so the same bytes in two files report twice.

## The process

15. **A public key of another length than 32 bytes on stdin.** No verdict.
