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

`impl canon` reads one JSON document on stdin and writes its canonical bytes;
`impl verify <store-root> <registry-path> <authority> [<decision-records-dir>]`
reads the 32-byte public key on stdin and writes `{"ok": …, "findings": […]}`,
exiting 0 whenever it reached a verdict and 2 when it could not.

## How it was written, and what that makes it

From `SPEC.md` and the corpus, without reading the Go implementation's source,
in another language on other libraries: Node's own Ed25519 (OpenSSL) and a JSON
reader of its own that keeps a number's spelling and a name given twice, where
the reference uses Go's `crypto/ed25519` and `encoding/json`. Where the
specification left a question open, the answer taken is recorded in
[`AMBIGUITIES.md`](AMBIGUITIES.md) rather than settled silently.

It is not a clean-room implementation in the strict sense the corpus's history
describes — an author barred from reading the reference. Its author had earlier
changed the reference's registry handling (the engine making its registry at
start), and knew that code's shape from doing so. What it is: a second body of
code, written to the text, that agrees with the reference on every vector and
disagrees with it nowhere the corpus looks. Whether that meets a two-implementation
bar is for whoever holds the bar to judge.

## What it does not do

- **Windows.** §4.1's Windows spelling rules are not implemented, so it refuses to
  run there rather than read a path Windows would resolve otherwise.
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
