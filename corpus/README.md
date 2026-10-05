# Conformance corpus

Frozen vectors that any implementation of this gateway's attestation format must
reproduce. The corpus is **the arbiter** — not tests belonging to an
implementation, but a third thing every implementation answers to, including the
one in this repository.

```
cd go && go build -o gateway .
./gateway conform                     # this implementation
./gateway conform --impl ./other      # any implementation (contract below)
```

## The corpus is frozen, and that now matters more than it did

These vectors are **hand-maintained normative data**. They are not regenerated
from the implementation that reads them, and there is deliberately no generator in
this repository any more.

That constraint used to be a nicety and is now load-bearing. This repository had
two implementations — a Python reference and a clean-room Go one — and the corpus
was generated from the Python. With the Python retired, a generator would
regenerate expectations from the *only* implementation, which makes the corpus a
mirror of that code rather than a check on it: drift would be dutifully recorded
as the new correct answer, and every vector would still pass.

So: **changing a vector is a specification change.** It needs the same
justification as changing `SPEC.md`, and the two should move together. If a vector
looks wrong, the question is whether `SPEC.md` is wrong — not whether the code
disagrees with it.

The standing this data has comes from history rather than from authority: an
implementation written from `SPEC.md` and these vectors alone, by an author barred
from reading the reference, converged on all of them. What it could *not* derive
from `SPEC.md`, and had to reconstruct from these files instead, is recorded in
[`../go/AMBIGUITIES.md`](../go/AMBIGUITIES.md) — and is why `SPEC.md` §1 exists.

## The corpus has teeth, and that is tested

A conformance suite everything passes proves nothing, so
[`../go/teeth_test.go`](../go/teeth_test.go) checks the other direction: each of
these defects must be **caught**. Every one is the *default* behaviour of some
standard library.

| Divergence | Where it comes from |
|---|---|
| `<` `>` `&` escaped to `<…` | Go's `encoding/json` does this by default |
| non-ASCII escaped to `café` | many encoders default to ASCII-only output |
| member names ordered by UTF-16 code unit | RFC 8785 — and the judgment-pack runtime's own `internal/jcs` |
| per-receipt checks pass, registry anchor ignored | the exact gap this gateway exists to close |

The third is worth dwelling on: an implementer would very reasonably reach for an
existing JCS package. It orders by UTF-16 code unit, this format orders by code
point, and the two disagree on any member name outside the BMP. One vector catches
it; no amount of code review would.

## What is in it

**`canon.json`** — 30 vectors mapping a value to its exact canonical bytes. Inputs
are carried as JSON *text*, not parsed JSON, deliberately: a vector has to
distinguish the integer `1` from the number `1.0`, and to express a lone
surrogate, and neither survives being written into a document each language
re-parses with its own defaults. Accepting vectors carry `expectedHex`; refusing
vectors carry `reject: true`.

**`stores/*.json`** — 21 vectors, each a complete store (a `path → text` map plus
the registry text) and its expected `(ok, findings)`. There is one per status an
implementation can emit. Two of them, `key-mismatch` and `unsupported-version`,
exist because a second implementation pointed out that those statuses were
unspecified *and* untestable — the claim of one vector per status had quietly
become false.

Four hold what makes a registry line a seal (`SPEC.md` §4 step 2): a seal whose
signature the key did not make is dropped (`forged-seal-is-dropped`), and so is
one the key signed naming a foreign `keyId`
(`seal-with-foreign-key-id-is-dropped`); a seal the key signed counting below
zero is not. As the first of three seals for its session it is the one the
session's count is compared with (`negative-seal-count-loads`); and a session
sealed so, at the least integer §1.1 admits, is `sealed-session-missing` when
the store lacks it (`negative-seal-count-session-missing`). The first of those
two exists because the two implementations disagreed on such a store, with no
vector to see it: the reference dropped the seal counting below zero, and the
second implementation loaded it, as the text reads. It also holds step 2's rule
that the first loadable seal for a session wins, first in the registry's lines:
its three seals are ordered so that a verifier letting the last seal, the
largest count or the latest `sealedAt` win grades it `ok`, as one that drops the
seal counting below zero does, and one letting the smallest count or the
earliest `sealedAt` win compares the session with a seal of -2. When it was
written no other store vector, of either receipt version, held two loadable
seals for one session, so an edit to it can take that rule's coverage with it.

**`witness/*.json`** — the checkpoint witness's vectors, below.

**`ed25519-vectors.json`** — signature vectors generated by the `cryptography`
Python package, an independent vetted implementation that is a dependency of
nothing here. They are how that implementation's verdict travels to a machine that
does not have it, so the signature layer is never checked against itself.

**`TEST-PUBLIC-KEY`** — what verification consumes, and the only key the runner
reads. **`TEST-SEED`** — published solely so a maintainer can construct new
vectors deliberately; no verifier needs it, and `conform` never reads it.

Read either **whitespace-stripped**: a checkout that converts line endings would
otherwise leave a `\r` inside the key, and then every signature in the corpus
fails for a reason that looks exactly like a format disagreement. That is not
hypothetical — it is how this corpus first failed on Windows CI. `.gitattributes`
marks `corpus/**` non-text so the fixtures are never converted in the first place.

Receipts are signed, so conformance vectors cannot exist without a key; crypto
RFCs publish test vectors with their keys for the same reason. It signs nothing
real and must never be used by a deployment.

## What the corpus covers, and what it does not

The corpus is the arbiter of the **format**: canonicalization and
verification, the two layers where a second implementation silently drifting
would void every receipt. It deliberately does not exercise the HTTP
reference surface — an implementation could return a response shape SPEC.md
§6 forbids and still pass every vector here (issue #15 records this). That
trade holds while the Go binary is the only server; a second independent
implementation of the HTTP surface is the reopening condition for an
acquire/response vector class.

## Version 3 vectors, and when they arbitrate

**`v3/stores/*.json`** — 31 vectors for receipt version 3 (`SPEC.md` §1.2a,
§4 steps 5 to 8), in the same shape as `stores/` plus an optional
`decisionRecords` map, materialized as the directory a verifier is handed for
§4 step 6. They cover: a valid sealed version 3 session; an action receipt whose
citation and decision record both resolve; `citation-unresolved` for a wrong
signature; `malformed` for the right signature cited in another case, since a
cited signature has the form §1.2a gives it; `decision-record-mismatch`,
with the directory present and with it absent;
`malformed` for a `kind` outside its values, for a `null` requester, for a
version 2 receipt relabelled `"3"`, for an `argumentsDigest` carried into
version 3, for a session id that is not a flat token, and for an
`action.policy` that is not a digest; `signature-mismatch` for a member appended
inside `acquisition` after signing and for a version 3 receipt signed under the
version 2 prefix; a store holding one session of each version; and a session
that mixes versions, which is `chain-broken`. For §4 step 8: an action receipt
carrying `action.policy` whose record is a runtime evaluation record bearing it
out, its citations given twice where the receipt gives them once;
`decision-pack-mismatch`; `decision-cites-mismatch` for a record that cites
nothing; and a graph composite, which is not compared, so the receipt that
names it is `ok` whatever it claims. The records of the earlier action vectors
carry no pack digest, so they are not runtime evaluation records and are not
compared either.

Six hold `decision.recordBytes` (§1.2a; ADR-0012): a receipt whose member is
`"exact"` finds its record by a line's exact bytes, and one without it by step
6's reading, one trailing `0x0D` removed. A record stored as a line ending in
`0x0A` is found exactly; the same record stored with `0x0D 0x0A` after it is
`decision-record-mismatch` for the exact receipt and found for one without the
member, over the same archive; a record named with its trailing `0x0D`, the
only and unterminated piece of its file, is found exactly and compared —
`decision-pack-mismatch` — where step 6's reading finds the digest only as the
file whole and compares nothing; a line of `0x0D` alone is a candidate under
the exact reading, where step 6's leaves an empty piece; and a `recordBytes` of
another value is `malformed`.

They are as frozen as the rest and were written against the specification, not
against an implementation: no implementation answered them when they were
written, and the first that did was built afterwards to the text. `gateway
conform` reads both directories. A vector that fails is a specification
question before it is an implementation one, the same rule as above.

## Witness vectors

**`witness/*.json`** — 54 vectors for the checkpoint witness's statement (`SPEC.md` §8),
each a reading of §8.6: the trail being verified (`trail`), the witness keys supplied, in
order (`keys`, each 64 lowercase hexadecimal characters), the statements files
(`witness`), a head file when there is one (`head`), and the answer expected
(`expected`). Each also names its family and says in `note` what it holds and why.

| Family | Vectors | What they hold |
|---|---|---|
| `valid` | 9 | chains that read: one statement; read to a head; a conflict after a later checkpoint, which leaves coverage where it was; a retired trail; one chain in two files, out of order, with blank lines, a statement in both and a last line with no newline; a statement respelled, which is the same statement; a chain running past its head; a head one past the statements supplied, which joins the chain; a head alone at index 0 |
| `begins-late` | 3 | a chain without its index 0, with and without a head, and nothing supplied: `witness-chain-broken` |
| `equivocation` | 2 | two statements at one index, both verifying, in one file and as a head: `witness-equivocation` |
| `head` | 2 | a head more than one index past the statements supplied, `witness-head-unreached`; and one index past, naming another statement's signature, `witness-chain-broken` |
| `key` | 6 | the key rule of §8.4: two encodings that are not canonical, which a lenient decoder reads as the identity, and two keys of small order, each with a statement no private key made that such a decoder verifies, refused before anything is read; a key that is no point, refused although the chain verifies under another key supplied; and a key of mixed order, accepted |
| `signature` | 8 | the equation of §8.4: a signature only the cofactored check accepts, two ways; `S` of L or more; an `R` of small order that the equation accepts; a `keyId` naming no key supplied, and one naming another key supplied than the one that signed; a statement altered after signing, whose findings are its own and no hole's; and a signature checked before a trail |
| `trail` | 1 | a statement of another trail: `witness-trail-mismatch` |
| `malformed` | 6 | a member the format does not define and a fifth member of the checkpoint, each signed with it; another `witnessVersion`; an index spelled `-0`; a signature in upper case; a head file of two statements: `witness-malformed` |
| `chain` | 10 | the chain rule of §8.6: a hole, and one whose next statement names the signature before it; a previous signature not the one before; index 0 naming a previous and index 1 naming none; a checkpoint sequence not increasing; a conflict above the latest checkpoint and one with none before it; a retirement not last and one repeating an earlier checkpoint: `witness-chain-broken` |
| `bound` | 7 | the bounds of §8.7, at and one past each: 16 keys, 67108864 bytes, 110000 statements; and 4194304 one-byte lines, far over the statement bound within the byte bound, refused without keeping every line |

**The answer.** A refusal is `{"refused": <reason>}`, compared by its reason. A reading is
`{"ok": false, "findings": [...]}`, its findings compared as a **set** of names — how many
times, and where, a reader reports one is not normative here — or, with no finding,
`{"ok": true, "findings": [], "reading", "headIndex", "highestIndex", "latestCheckpoint":
{"index", "sequence", "witnessedAt"}, "conflicts", "retired"}`, every member compared:
`reading` is `"current"` with a head and `"historical"` without; `headIndex` is the head's
index, or `null`; `highestIndex` is the chain's; `conflicts` are the conflict statements'
sequences in index order.

**A file at the bound.** A file is a string, its text exactly, or
`{"parts": [{"text": …, "times": n}, …]}`, the bytes of each part's text repeated `n`
times, in order. The five vectors of the byte and statement bounds are stated so: one
statement and 67107902 or 67107903 blank lines, or one statement line 109999 or 110000
times — each beside a head file holding the same statement — or 4194304 lines of `x`,
rather than landing files of up to 64 MiB. A runner writes the bytes out in full before an
implementation reads them, so what is read is the file, never the description of it.

**The keys.** The statements are signed under `TEST-SEED`, since a witness signs with the
gateway's seed (`SPEC.md` §8.3), and verify under `TEST-PUBLIC-KEY`. No other seed is in
the corpus. The other keys a vector supplies are public keys only: the base point times 1
to 16, whose secret is their own name and which sign nothing here; the test key plus the
point of order 2, a key of mixed order, under which statements are signed with the test
seed's scalar; and encodings the key rule refuses. The signatures were made from
`TEST-SEED` with the `cryptography` package, and those no honest signer makes — an `R` with
a part of small order, `S` with L added, an `R` that is the identity, a key of mixed order,
and the statements under keys of small order — by the arithmetic each vector's note
states, each checked against both the equation and the cofactored check. Every expected
answer was written from `SPEC.md` §8, not computed by a reader; the reference and
`verify-ts` were then written to agree with them. Like the rest of the corpus, no
generator for them is kept here.

**No vector lands unread.** `gateway conform` refuses a corpus that holds an entry it does
not read — a file or directory at the top it has no rule for, anything but vectors among
the vectors — a witness vector with a member it does not know or of a family it does not
read, one whose `name` is not its file's, and one whose `expected` holds a member its form
does not, at any depth. It also refuses a corpus whose counts this README misstates: the
totals of `canon.json`, `stores/`, `v3/stores/` and `witness/`, and each row of the family
table above. `gateway conform` checks them on every run, the image's and a release's
included; `go/conformance_test.go` holds that check to each misstatement. `TEST-SEED` is read by no runner, and
`ed25519-vectors.json` by each implementation's own tests rather than through the process
contract, which carries no raw signature.

## The process contract

`--impl CMD` drives any implementation, in any language, with no dependency on
this one:

- `CMD canon` — stdin: one JSON document (the *text*). stdout: the canonical
  bytes, exactly, no trailing newline. Exit 0 if inside the domain, non-zero if
  refused.
- `CMD verify <store-root> <registry-path> <authority> [<decision-records-dir>]`
  — stdin: the 32-byte Ed25519 **public** key, raw bytes, never a secret.
  stdout: `{"ok": bool, "findings": [...]}`, and optionally the
  `observations` member of `SPEC.md` §4, which the runner does not read. Exit 0
  whenever a verdict was produced; a *failing* verdict is still exit 0. The fourth argument is the
  decision-record directory of `SPEC.md` §4 step 6; the runner passes it
  exactly when the vector carries a `decisionRecords` map, materialized with
  each key as a path under a fresh directory, and passes nothing when the map
  is absent, so an absent map means an absent directory and never an empty one.
- `CMD witness --trail <hex> --witness-key <file>... [--witness <file>]...
  [--witness-head <file>]` — the flags of the runtime's `audit verify`: the trail being
  verified; each key a file holding its 64 lowercase hexadecimal characters and a
  newline, in the vector's order; each statements file, in the vector's order; and the
  head file, exactly when the vector has one. stdout: the answer, as above, a refusal
  among them. Exit 0 whenever an answer was given; non-zero when none could be, which the
  runner reports as an implementation that could not answer, never as a refusal.

Findings are compared as a **multiset**: order is not normative.

## Two implementations again

[`../verify-ts/`](../verify-ts/README.md) is a second implementation of the
format — the canonical form, and registry-anchored verification of both
receipt versions — in TypeScript, written from `SPEC.md` and these vectors
without reading the Go source. CI drives it through the contract above, with
`gateway conform --impl ../verify-ts/impl`, so each implementation answers to
the corpus and neither to the other. Its author was not barred from the
reference, as the Go implementation's author was from the Python one; its
README says what it is on those terms, and its
[`AMBIGUITIES.md`](../verify-ts/AMBIGUITIES.md) records the questions it had
to answer that neither `SPEC.md` nor these vectors settle.

## Ambiguities this corpus surfaced

Recorded rather than silently pinned. Both are now stated in `SPEC.md`, but the
history is kept, because it is the argument for writing specifications down.

1. **Findings order is not normative.** Compared as a multiset. An implementation
   emitting per-session findings in filename-string order reports `0, 1, 10, 2, …`
   for a session with ten or more receipts; one sorting numerically is not wrong.
2. **A failing receipt produces a second, consequential finding.** A receipt that
   fails is excluded from the chain reconstruction, so a failure at `callIndex` 0
   also yields `sequence-broken`, while the same defect later in the session does
   not. That second finding is informative about *position*, not about the defect.
