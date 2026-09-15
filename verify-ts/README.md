# verify-ts: a second implementation of the attestation format

A verifier of this gateway's receipts, in TypeScript: the canonical form
(`SPEC.md` §1.1) and registry-anchored verification (§1.4, §4, §4.1) of receipt
versions 2 and 3, a version 3 action's citations and decision record, and a
decision record's own citations included. It mints nothing and serves nothing;
the HTTP surface of §6 is not part of it.

It answers to the frozen corpus through the process contract of
[`corpus/README.md`](../corpus/README.md), so the gateway's own runner holds it
to the same vectors it holds the Go implementation to:

```
cd go && go build -o gateway . && ./gateway conform --impl ../verify-ts/impl
```

`impl canon` reads one JSON document on stdin and writes its canonical bytes,
exiting 1 for a document outside the domain and 2 for one past what it reads;
`impl verify <store-root> <registry-path> <authority> [<decision-records-dir>]`
reads the 32-byte public key on stdin and writes `{"ok": …, "findings": […]}`,
exiting 0 whenever it reached a verdict and 2 when it could not.

## How it was written, and what that makes it

From `SPEC.md` and the corpus, without reading the Go implementation's source,
in another language on other libraries: Node's own Ed25519 (OpenSSL) and a JSON
reader of its own that keeps a number's spelling and a name given twice, where
the reference uses Go's `crypto/ed25519` and `encoding/json`. Where the
specification left a question open, the answer taken is recorded in
[`AMBIGUITIES.md`](AMBIGUITIES.md) rather than settled silently, beside the
readings the text settles that a reader could miss.

It is not a clean-room implementation in the strict sense the corpus's history
describes — an author barred from reading the reference. Its author had earlier
changed the reference's registry handling (the engine making its registry at
start), and knew that code's shape from doing so. What it is: a second body of
code, written to the text, that agrees with the reference on every vector and
disagrees with it nowhere the corpus looks. Whether that meets a two-implementation
bar is for whoever holds the bar to judge.

## Its limits

`SPEC.md` sets none of these but the last; each is this implementation's, and
each ends in no verdict rather than in a verdict reached on less than the store
holds — but for the nesting bound, the reference's own, past which a document is
unparseable, so that a receipt nested too deep is `malformed`, as it is to the
reference.

- **Windows.** §4.1's Windows spelling rules are not implemented, so it refuses to
  run there rather than read a path Windows would resolve otherwise.
- **Only regular files are read.** A receipt, the registry or an artifact that
  is a FIFO, a device or another special file — a link to one included — is no
  verdict; each is opened without waiting on a writer, so nothing in a store can
  make it hang. (A directory in an artifact's place is no artifact:
  `AMBIGUITIES.md`, question 7.) Under the decision-record directory, only
  regular files are candidates, as §4 step 6 says.
- **64 MiB for a JSON document.** A receipt larger than that is no verdict. A
  registry line or a decision record that long is read only as far as its first
  byte that is not whitespace: one that opens an object could be a seal, or a
  record that cites, and is no verdict; any other is not one JSON object, and is
  not read — a record is still hashed for §4 step 6. Artifacts and `.jsonl`
  files are hashed as they are read, whatever their size. Standard input is held
  to the same bound, and the key on it to 32 bytes.
- **A million values in a JSON document.** Parsed, a value costs far more than
  its bytes, so a document of more than 2²⁰ values — scalars and containers
  alike — is read no further. A receipt past it is no verdict. A registry line
  or a decision record past it is no verdict if it opens an object, which could
  be a seal or a record that cites, and otherwise is not read. `canon` exits 2,
  which is not a refusal of the document as outside the domain.
- **What is kept.** One document is held at a time. Of each receipt only its
  file name, status and index are kept; of one that passed, also what the chain
  walk compares; of an action that passed, the record it names and its bytes'
  digest, its citations being read again once every receipt is indexed — and
  its bytes then must be what they were, or there is no verdict. Beside those,
  the index citations are resolved against: each receipt file's stem, and its
  signature when it has the form a citation can match. Of the decision records,
  only which of the named ones were found, and the findings for those that fail,
  one each, as reported.
- **256 MiB kept.** Everything verification keeps is charged, as it is kept,
  to a budget of 256 MiB, strings at two bytes a character: each session, for
  what is kept of it empty or not — 1 KiB, and its name; each receipt file,
  charged when it is met for all that will be kept of it — 2 KiB, and its name
  twice; each seal; each directory under the decision records still to walk;
  and the buffer of failing records' findings, 33 bytes each. The charge that
  passes the budget is no verdict, made before anything more is read:
  directories are read an entry at a time, so a store too large is refused
  before any receipt is read, and a registry at the seal that passes it, before
  a later line is read for a seal. Findings are not kept: the verdict is written as it is made,
  a finding at a time. One document is read at a time beside the budget, within
  the bounds above.
- **Arguments are their bytes.** The platform hands a program its arguments
  decoded as UTF-8 with replacement, so a path holding a byte that is not UTF-8
  would arrive as another path. On Linux, which shows a process its arguments'
  bytes, an argument that is not UTF-8 is no verdict; elsewhere, an argument
  holding U+FFFD, which cannot be told from one, is no verdict.
- **An index of more than 64 digits.** A receipt whose `callIndex` is that long
  is no verdict: it cannot verify, the canonical domain ending at sixteen
  digits, and its finding would carry it whole.
- **Nesting past ten thousand levels.** Like the reference, it reads nothing
  deeper (§5).

## Running it

Node 22.18 or later runs the TypeScript directly; nothing is built and nothing
is installed to run it. The compiler is only its typecheck:

```
npm ci --ignore-scripts
npm run typecheck
npm test
```

The tests read the corpus themselves, as the runner hands it over, and go past
it: receipts, seals and decision records signed under the corpus's published
test seed, each departing from a valid one in one respect the corpus does not
exercise; §4.1's absent and unreadable inputs; and the reader at its edges.
