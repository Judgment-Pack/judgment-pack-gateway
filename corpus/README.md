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

**`stores/*.json`** — 51 vectors, each a complete store (a `path → text` map plus
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

Seven, each named `rotation-*`, hold the walk of a registry's key rotations
(`SPEC.md` §3b; issue #317), each verified from `TEST-PUBLIC-KEY` alone, as a
verifier verifies a rotated store from the one key it pinned: two rotations
followed, with a session sealed before the first, one running across it and one
after the second, `ok`, the report naming both (`rotation-followed-twice`); a
continuation with no rotation the current key signed, `rotation-forged`; a
rotation with no continuation on the line after it, `rotation-break`
(`rotation-missing-continuation`); a second rotation carrying the first one's
ordinal, `rotation-order` (`rotation-ordinal-replay`); a rotation to the identity
point, a key of small order under which a signature needs no private key,
`rotation-key-refused` (`rotation-next-key-small-order`); a seal the key rotated
from made after the rotation, which loads nothing (`rotation-old-key-seal-dropped`);
and a session whose second receipt goes back to the key rotated from,
`chain-broken` (`rotation-key-goes-back`). Five more hold a check each that a
verifier could drop with the seven still passing: a continuation another key
signed, `rotation-break` (`rotation-continuation-signed-by-another-key`); a
`key-rotation` as the registry's last line, `rotation-break` after one rotation
followed (`rotation-registry-ends-in-a-rotation`); a rotation back to a key
reached, `rotation-key-refused` (`rotation-back-to-a-key-reached`); a seal the
next key made before the rotation, which loads nothing
(`rotation-seal-before-its-key`); and a hop the current key signed whose `keyId`
names another key, `rotation-forged` (`rotation-hop-names-another-key`). Each walk that stops leaves the keys
after it reached by nothing, so the sessions under them are `key-mismatch` and
`unregistered-session` beside the walk's finding, which a verifier that follows
the broken rotation would grade `ok`. The keys rotated to are made from published
seeds, as `TEST-SEED` is: the SHA-256 of the ASCII text `judgment-pack-gateway
corpus rotation key 1`, and of the same text ending in `2`. Like `TEST-SEED` they
sign nothing real and must never be used by a deployment. A vector whose walk
followed a rotation gives `rotations` in `expected`, `{"count", "keyId"}`, and a
runner compares it whole with the implementation's; a vector without the member
expects none, and an implementation that followed none leaves the member out.

Thirteen, each named `interruption-seal*`, hold the seal made after an
interruption (`SPEC.md` §3c; issue #395), each over the three receipts of
`valid-sealed`: the seal the operator's command makes, which anchors the session
and verifies `ok` (`interruption-seal`), and the one the gateway's start makes
(`interruption-seal-by-the-start`); one another key signed, which loads nothing
(`interruption-seal-forged`); a line of that kind carrying the signature a seal of
§3's form would carry, which loads nothing either, since a line of that kind is
read as that seal and as nothing else (`interruption-seal-is-not-an-ordinary-seal`
— a reader from before §3c grades it `ok`); one with a member its form does not
hold (`interruption-seal-member-more`); one naming another receipt as the last,
`seal-head-mismatch` (`interruption-seal-head-mismatch`); one counting fewer
receipts than the store holds, `count-exceeds-seal`, and one counting more,
`tail-rollback` (`interruption-seal-counts-fewer`, `interruption-seal-counts-more`);
one beside a seal of §3's form for the same session, and two for one session,
each `seal-conflict` (`interruption-seal-beside-an-ordinary-seal`,
`interruption-seal-twice`); one for a session the store does not hold,
`sealed-session-missing` (`interruption-seal-session-missing`); and, after the
first rotation of `rotation-followed-twice`, one the key rotated to signed over
receipts the key rotated from signed, `ok`, and one the key rotated from signed,
which loads nothing (`interruption-seal-after-rotation`,
`interruption-seal-old-key-after-rotation`). They state no observations and are run
without the option, so they hold what they held when they were written.

Five hold what a verifier reports of such a session beyond `ok` and findings (`SPEC.md`
§4, §7; issue #398), each over the store and registry of the vector its name ends in,
unchanged, and each stating its observations: the session the operator's seal anchors,
`ok`, observed `sealed-after-interruption` on receipt 2, the receipt at `finalCount − 1`
(`observations-interruption-seal`); and four run under `--ordinary-seals-only`
(`ordinarySealsOnly`, below): that session, now the finding `sealed-after-interruption`
and observed nothing (`ordinary-seals-only-interruption-seal`); two such seals for it, the
finding beside `seal-conflict`, once, and observed nothing
(`ordinary-seals-only-interruption-seal-twice`); one another key signed, which anchors
nothing, so the option finds no more — `unregistered-session`, and the session's receipts
whole, observed `session-open` on its last
(`ordinary-seals-only-interruption-seal-forged`); and a seal of §3's form, for which the
option changes nothing, `ok` and observed nothing (`ordinary-seals-only-valid-sealed`). A
verifier that reports no observations disagrees with the first and the fourth, and one that
takes the option and ignores it with the second and the third, and each agrees with every
other vector; one that refuses the option, giving no verdict, disagrees with the four run
under it and with no other. The last holds the option to changing nothing for a seal of §3's
form. The
rows of
[`../testdata/interruption-seal/cases.json`](../testdata/interruption-seal/cases.json),
which both implementations run, hold more over these stores — a receipt taken away or torn
after the seal, a registry edited beside it — and are not conformance.

**`observations` and `ordinarySealsOnly`.** A vector that states observations gives them in
`expected` as `observations`, each `{"sessionId", "callIndex", "observation"}` (`SPEC.md`
§4), and a runner compares them with the implementation's as a **multiset**: order aside,
and how many counted, since each observation is carried once, on the one receipt §4 names
for it. `[]` expects none, and an implementation that reports none may leave the member
out. A vector that states the member as `null`, or with an element that is `null` or no
object, refuses the run: it states nothing a runner could compare. An implementation's
`"observations": null` counts as none, as a left-out member does, and a member that is no
array of objects disagrees with a vector that states observations. Unlike `witnesses` and `rotations`, a vector **without** the member is not compared on
observations at all: what an implementation reports of them there is not read, so every
vector written before the member holds what it held. A vector run under the option gives
`"ordinarySealsOnly": true` beside `registry`, and the runner passes `--ordinary-seals-only`
to the implementation's `verify` first (the process contract, below); a vector without the
member is run without it.

**`witness/*.json`** — the checkpoint witness's vectors, below.

**`witness-recovery/*.json`** — the witness's own storage: what its start-up checks,
its repair and its writer do with its log, marks and registrations, below.

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

A checkpoint witness's endpoints (`SPEC.md` §6, "Witness endpoints") are on the same
terms: no vector holds a submission or a read and its answer. What a witness serves is
statements, and those are held by `witness/`, whose vectors a reader reads whatever served
them; a deliverer's hand-over is to be acknowledged by such a statement, read so (ADR-0013,
question 5). The requests and answers themselves have one implementation, this one, held by
its tests (`go/witness_serve_test.go`), and a second implementation of the surface reopens
the question for them too.

## Version 3 vectors, and when they arbitrate

**`v3/stores/*.json`** — 133 vectors for receipt version 3 (`SPEC.md` §1.2a,
§4 steps 5 to 8), in the same shape as `stores/` plus an optional
`decisionRecords` map, materialized as the directory a verifier is handed for
§4 step 6, and an optional `witnesses` in `expected` (below). They cover: a valid sealed version 3 session; an action receipt whose
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

Nine hold the `witness` member (§1.2a, §4;
`docs/adr/0014-a-receipt-names-the-witness.md`), each named `v3-witness-*`: an
acquisition and an action naming one witness for one trail, the action's record
a runtime evaluation record of that trail, both `ok` and the witness reported
once; two witnesses named for one trail after a change, the second at a loopback
address over `http`, both reported; a receipt naming a witness that fails the
ladder (`artifact-missing`), which names nothing; an action whose record is of
another trail than its witness names, `decision-trail-mismatch` beside its `ok`;
`malformed` for an `http` origin off loopback, for an origin with a path and for
a `keyId` in upper case; `signature-mismatch` for the member added after signing;
and the member on a seal, which a seal does not sign, so the seal loads by its
four members and names nothing. The witnesses are keys the witness vectors
already name, the base point times 1 and times 2, so no secret beyond `TEST-SEED`
is in the corpus.

Eighteen hold what a remote MCP server adds to an acquisition (§1.2a, §6 shape `mcp`;
`docs/adr/0015-a-remote-mcp-server-as-a-source-and-executor.md`), each named
`v3-mcp-remote-*`: a sealed session of two, one over TLS with an `https` endpoint
and a `tls:sha256:` peer identity and one over plaintext at a loopback address with
a null one, both `ok`; `malformed` for a `transport` outside its one value, for an
`http` endpoint at a name, for an endpoint with a user, for a peer identity in upper
case, for a null peer identity over TLS, for `transport` without `server`, and for
the two on shape `http`; and a `server` carrying a member beside its two, which a
verifier tolerates as it tolerates any signed member it does not know, `ok`. Nine
more, each named `v3-mcp-remote-endpoint-*`, hold the endpoint to the one form
§1.2a states for the adapter, the signer and both verifiers (issue #251): `malformed`
for a percent escape that is not one (`%zz`), for a port and no host, for a `$` in
the host, for an address in brackets that is no IPv6 address (`[abc]`), for a `:`
after the host and no port, for the port 65536, for an endpoint
of 2049 characters, and for `http` at the name `localhost`; and an endpoint with a
port and a percent escape in its path, each of the form, `ok`, so a verifier holding
the endpoint tighter than the form is caught as well as one holding it looser. Every one is signed with its members, so what
each holds is the member's form and not the signature.

Six hold what a write to a remote MCP server adds to an action (§1.2a; issue #268), each
named `v3-action-*` and each the action of `v3-action-valid` with its `action.tool` changed
and signed again: `transport` `"http"` with an endpoint of the form, `ok`; `malformed` for
`transport` with the endpoint `https://:443/`, for a `transport` of `"stdio"`, for one of
`null`, and for `transport` on a tool of shape `http`; and a tool with no `transport` whose
endpoint is `https://:443/`, `ok`, since without the member the endpoint is the platform's and
held to nothing more, so a verifier that applies the form to every endpoint, or reads the
transport from the endpoint's spelling, is caught as well as one that drops the rule. The
earlier action vectors carry no `transport`, and their endpoint, `https://mcp.example.com/`,
is held to nothing by it.

Twelve hold what a call made under a delegation adds (`SPEC.md` §11.7; issue #356), each
named `v3-delegation-*` or `v3-reconciler-*` and signed with its members by a signer that shares
no code with the gateway: an acquisition and an action carrying the `delegation` member, `caller`
and `requester` naming its subject, both `ok`; a member beside the six §11.7 names, tolerated,
`ok`; `malformed` for a requester, and for a caller, naming another subject than the member's,
for a `null` caller, for an empty `chain`, for an `admittedAt` without milliseconds, and for a
`subject` carrying a label; `signature-mismatch` for the member's `actor` changed after signing;
an uncertain delegated action and its read-back sent by the issuing host, whose `caller` is the
subject's and whose `reconciler` names the host, all three `ok` and the action observed
committed; and `malformed` for a `reconciler` of another kind and for one on an acquisition that
carries no `reconciliation`. A verifier written before the members (v0.23.0, in Go and in
TypeScript) answers `ok` for every one of them but the tampered member, and reads `caller` as
naming the subject: that is the compatibility §11.7 states, and these vectors hold the readers
that know the members to more.

Seventeen are of the `scope` member (§1.2a; `docs/adr/0026-a-scope-identifier-fixed-on-a-platform.md`;
issue #420), each named `v3-scope-*` and signed with its members by a signer that shares no code
with the gateway; sixteen hold the member, and one held it when signed and has had it removed: a sealed session of two acquisitions whose scope identifiers differ, one of them
non-ASCII and holding a space, both `ok`, since no scope identifier is compared with another; one
of exactly 128 bytes, made of four-byte and two-byte characters, `ok`; an action carrying the
member, `ok`, since the format admits it on either kind; `malformed` for 129 bytes that are 128
code points and 128 UTF-16 code units, for the empty string, for `null`, for a C0 control, for a
tab and for a line feed, which display policy 1 admits and a scope identifier does not, for
U+200B, for U+202E, for a private-use code point, for U+2FFC, unassigned in Unicode 15.0.0 and
assigned later, so a verifier reading its runtime's own later tables is caught, and for a
noncharacter; and `signature-mismatch` for the member changed, added and removed after signing.
A verifier written before the member (v0.26.0, in Go and in TypeScript) answers `ok` for every
one of them but the three tampered receipts, which it answers `signature-mismatch`: that is the
compatibility §1.2a states, and these vectors hold the readers that know the member to more.

Thirty-six are of payload retention (§1.3a; `docs/adr/0028-payloads-a-gateway-does-not-keep.md`;
issue #422), each named `v3-artifact-*` and signed, receipts, seals and removal records alike,
by a signer that shares no code with the gateway, its expected answers written from §1.3a; the
signer reproduces the frozen seal of `v3-scope-valid` byte for byte. Each states its
observations. Of a source that keeps no payload: a receipt carrying `artifact: "not-retained"`
with no bytes anywhere, `ok` with the observation `artifact-not-retained`; with its bytes in the
store, `ok` and no observation, and with other bytes there, `artifact-mismatch`; with its bytes
supplied, `ok` and no observation, with other bytes supplied, `artifact-mismatch`, and with a
supplied directory holding only another digest's bytes, `ok` with the observation; two
receipts of one digest, one never kept, both `ok` on the bytes the other kept. Of the member's
form: `malformed` for the string `"kept"`, for `true`, for `null`, and on an action;
`signature-mismatch` for the member added after signing to a kept receipt whose bytes are gone,
and removed after signing. Of a recorded removal: a record naming the receipt, `ok` with the
observation `artifact-removed`; with its bytes supplied, `ok` and no observation, and other bytes
supplied, `artifact-mismatch`; other bytes put back after the removal, `artifact-mismatch`; the
bytes still there, `ok` and no observation; and `artifact-missing` for a kept receipt with no
record whose bytes are supplied, for a record under a key no walk reaches, for one signed by
another key under the test key's id, changed after signing, carrying a tenth member, torn, naming
another receipt, naming another index, naming another session, naming another digest, and with a
`removedAt` of its form that names no instant. Two hold the bound on a line (§1.3a): a record on
a line of exactly 4096 bytes before its line feed loads, `ok` with the observation; one on a
line of 4097 loads nothing, `artifact-missing`, and the record on the line after it loads. Three hold a rotation: a
record signed by the key rotated to names a receipt made under the key rotated from, `ok` with
the observation; a record signed by the key rotated from names no receipt made under the
key rotated to, `artifact-missing`; and, beside two such records, one signed by the key rotated
to names it, `ok` with the observation, whichever comes first. One holds the record between
lines that load nothing, `ok` with the observation; one holds two receipts of one digest and a
record naming one of them, the one `ok` with the observation and the other `artifact-missing`.
Six supply bytes (`suppliedArtifacts`, below). A verifier written before §1.3a (v0.26.0, in
Go and in TypeScript) answers `artifact-missing` where these vectors expect `ok` with an
observation, gives no verdict for the six that supply bytes, and answers `ok` for the four
receipts whose member is not of its form or is on an action; it agrees with the rest.

**`witnesses`.** A vector whose report names witnesses gives them in `expected`
as `witnesses`, each `{"trail", "origin", "keyId"}`, and a runner compares them
with the implementation's as a **set**, order and repetition aside; a vector
without the member expects none, and an implementation that reports none leaves
the member out. They are compared in every vector, where observations are compared
only in a vector that states them: a verifier that does not read the member
reports none, and those vectors catch it.

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

**The answer.** A refusal is `{"refused": <reason>}`, compared whole: its reason, and no
other member. A reading is
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
does not, at any depth, and a store vector, of `stores/` or `v3/stores/`, with a member it
does not know, at the top or in `expected`. Store, witness and witness recovery vectors are
held to that: a member the runner does not read refuses the corpus. `canon.json` is not:
read for its vectors' `inputJson`, `expectedHex` and `reject`, it passes over any other
member, such as a vector's `expectedUtf8`. A member is read by its exact name, in every
family (`SPEC.md` §7): one whose name differs from a member the runner reads, if only in
case, such as `Authority` beside or in place of `authority`, is a member it does not read,
refused in a store, witness or witness recovery vector and passed over in `canon.json`.
Every file is UTF-8, and a name is compared as decoded, its escapes read: `"\u006fk"` is
`ok`, so an object giving both gives one name twice. In every family `note` is the member
for commentary, read by no comparison. Every file of every family is read as exactly one JSON value, with
nothing after it and no member given twice in one object at any depth, and a recovery vector
whose run never reaches a fault it declares disagrees. It also refuses a corpus whose counts
this README misstates: the
totals of `canon.json`, `stores/`, `v3/stores/` and `witness/`, and each row of the family
table above. `gateway conform` checks them on every run, the image's and a release's
included; `go/conformance_test.go` holds that check to each misstatement. `TEST-SEED` is read by no runner, and
`ed25519-vectors.json` by each implementation's own tests rather than through the process
contract, which carries no raw signature.

## Witness recovery vectors

**`witness-recovery/*.json`** — 25 vectors for the witness's own storage, written against
`docs/adr/0013-checkpoint-witness.md` §4 ("Endpoints and storage": the log, the marks, the
registrations, the order sign, durable, marked, published, the start-up checks, and the three
rules of recovery), not against `SPEC.md`, which leaves a witness's storage to it. They live
beside `witness/` rather than in it because they are not readings of a chain: a reader holds a
witness's statements, never its log, its marks or its registrations, so neither `verify-ts` nor
the runtime has anything to answer them with, and they are not in the process contract.
`gateway conform` runs them against this implementation's witness only, and only on Unix,
where a witness keeps its files; with `--impl`, or elsewhere, it reads every one and holds it
to its form and to the counts here, and runs none.

Each vector gives the files a witness finds (`files`: `log`, `marks`, `registrations`, each
its exact text, a file absent when it is not given), the witness's clock (`clock`), how it
registers trails (`registration`), the statements its writer may make (`statements`), and
`steps`, each one action with what it is expected to give:

- `open`: the start-up checks, expected to give an `outcome` and `findings`, the set of names
  found. The witness starts on `start` alone, and stays open for the steps that write.
- `repair`: what the three rules allow and nothing else, expected to give the outcome it acted
  on and its findings; `files` then states each file as it must be afterwards, `null` for one
  that must not be there, so a refusal is held to having written nothing.
- `replace`: the operator puts files in place, as a restored log copy.
- `submit`, `retire` and `register`, to the witness open, expected to give an `answer`: the
  statement answers `signed`, `held`, `conflict`, `below-head` and `retired`, each with its
  statements' exact lines, or `failed`, `stopped`, `unregistered`, `registered-elsewhere`,
  `refused-lines`, `nothing-to-retire` or `registered`. `registerOffline` registers a trail
  with the witness stopped. A `fault` fails the first write or sync of one step of the fixed
  order — `append`, `sync`, `mark`, `mark-sync`, `publish`, `register`, `register-sync` —
  leaving in its file `nothing` of what it wrote, a `torn` half of it, all of it but its newline
  (`unterminated`) or all of it (`whole`); a failed sync leaving `nothing` loses what was
  written, and one leaving `whole` keeps it; a sync fails only when it is the one that covers a
  write of that step. That is the state a crash at that step leaves, since the writer writes
  nothing after a failure.
- `concurrent`: submissions at once with one `fault`, reached by whichever writes first, their
  `answers` compared as a set, and at most `notEndingCleanlyAtMost` of the log and the marks
  not ending in a newline afterwards.
- `files` alone compares the files as they are.

The outcomes are the rules' own: `start`; `mark-completed` and `newline-and-mark-completed`,
rule 2's one mark; `set-aside`, rule 1's one release; `registration-set-aside`, for the last
bytes of the registrations, which are never served and are written before anything is signed
under them; `refused`, when the marks are intact and the log does not satisfy them, so that only
a copy of the log that passes the checks against them, or a new key, lets the witness go on —
or when a trail with statements has no registration or a registration line does not read,
until the registrations are restored or the trail is registered with the witness stopped;
and `new-key`, rule 3. Findings use the reader's names where they apply —
`witness-malformed`, `witness-signature-invalid`, `witness-chain-broken` — and, of the files
only a witness keeps, `witness-log-torn`, `witness-log-unterminated`, `witness-marks-lost`,
`witness-marks-torn`, `witness-marks-unterminated`, `witness-mark-malformed`,
`witness-mark-unreached`, `witness-unmarked`, `witness-registration-malformed`,
`witness-registrations-torn`, `witness-registrations-unterminated` and `witness-unregistered`.
As a reader does, the checks stop walking chains at the first statement that fails, so a hole it
leaves is not reported as well.

| Family | Vectors | What they hold |
|---|---|---|
| `accepted` | 2 | a log damaged on disk, refused, then a restored copy that passes against the intact marks, which starts with no repair; and a witness of two trails and every kind of statement answering from what it holds — retired, held, below the head, a conflict signed once and given again |
| `mark` | 2 | a whole unmarked last statement, its mark completed; and one missing only its newline, its newline and mark completed and no index released |
| `set-aside` | 1 | torn last bytes of the log with the marks ending cleanly, set aside and their index released |
| `refused` | 5 | a stale valid backup behind the marks; an acknowledged last statement cut short; a retirement erased by a stale restoration; more than one unmarked statement; an unmarked statement before the log's end |
| `new-key` | 8 | an unmarked last statement that fails the checks, nothing written; a torn published mark with a stale backup log, the statement a retirement; torn, and unterminated, last bytes of the marks; a lost marks file; a damaged mark line and an unreadable one, neither the file's last bytes; both files not ending cleanly |
| `registration` | 2 | a trail with statements and no registration, refused until the operator registers it; torn last bytes of the registrations, set aside |
| `writer` | 5 | an append, a sync and a mark failure on one trail, each stopping signing on another trail until restart; one crash under the writer lock with two trails submitting, in an append and in a mark, at most one file not ending cleanly |

**The order, as well as the outcome.** Every operation a vector's witness makes on its files —
an append, a sync, a cut, a file made, a directory synced, a lock, and the notes of a hold, a
read, a start, a publication, a read-back and the end of a repair or a registration — goes
through one seam, and the runner
holds their order to one rule: nothing is relied on, served or built upon until the bytes it
rests on are durable (`go/witness_trace.go`). In particular, no mark is appended before the
log line it names is synced; nothing is published, and no witness starts, before the log, the
marks and the registrations are synced; no file is cut before the bytes it loses are kept in
the set-aside file, synced and read back from it as its reader reads them; a file made has its
directory synced before anything is written to it; no file is read before it is locked; what a
start, a repair or a registration read is synced, files and directories, before anything after
it; a repair or a registration ends with what it wrote synced; and no statement is appended
while its registration is not synced. A vector whose outcome is right and whose order is not
disagrees. The tests hold the order in which syncs are requested; that each request reaches
the system is one line, `syncToSystem` in `go/witness_log.go`, which a Linux test observes
asking the kernel; that the kernel and its disk then keep the bytes, no test here shows. Every
line a witness writes is held, before it is written, to the function and the 4096-byte bound
its own start reads that kind of line with, and no line is appended to last bytes another write
left: the set-aside file's own are ended where they stand. Every repair leaves every line of the
set-aside file a record, or kept whole by records of the set-aside file itself, and reads the
whole file back to that before it cuts anything. A start or a repair refuses a file whose length
differs from what it read; other bytes of the same length, written by something that ignores
the locks, are not found, and the locks are what keep every other writer of this program out.

**No secret.** The statements are signed under `TEST-SEED` and checked under
`TEST-PUBLIC-KEY` before a step runs. A writer step signs nothing: the runner gives the writer
a statement's signature only for exactly the bytes a statement of the vector signs, so a writer
that builds other bytes — another time, another index, another previous signature — gets no
signature, and the step disagrees. The expected outcomes, findings, answers and files were
written from ADR-0013 §4, not computed by the witness; like the rest of the corpus, no
generator for them is kept here.

## The process contract

`--impl CMD` drives any implementation, in any language, with no dependency on
this one:

- `CMD canon` — stdin: one JSON document (the *text*). stdout: the canonical
  bytes, exactly, no trailing newline. Exit 0 if inside the domain, non-zero if
  refused.
- `CMD verify [--ordinary-seals-only] [--artifacts <dir>] <store-root> <registry-path> <authority> [<decision-records-dir>]`
  — stdin: the 32-byte Ed25519 **public** key, raw bytes, never a secret.
  stdout: `{"ok": bool, "findings": [...]}`, and optionally the
  `observations` member of `SPEC.md` §4, which the runner compares as a multiset
  for a vector that states them and does not read for any other (above), the
  `witnesses` member, which it compares as a set (above), and the `rotations`
  member, which it compares whole (above). Exit 0
  whenever a verdict was produced; a *failing* verdict is still exit 0. The fourth argument is the
  decision-record directory of `SPEC.md` §4 step 6; the runner passes it
  exactly when the vector carries a `decisionRecords` map, materialized with
  each key as a path under a fresh directory, and passes nothing when the map
  is absent, so an absent map means an absent directory and never an empty one.
  `--ordinary-seals-only` is the option of `SPEC.md` §4, given first, before the
  store root, as `gateway verify` and verify-ts take it; the runner passes it
  exactly when the vector gives `"ordinarySealsOnly": true`, and nothing in its
  place otherwise. An implementation that gives no verdict for a vector run
  under the option, exiting non-zero as one that does not take the option does
  when it refuses it, disagrees with that vector, `store <name>: no verdict
  under --ordinary-seals-only:` and at most 256 bytes of its standard error,
  quoted; the run goes on, and exits 1. No verdict for a vector run without the
  option still stops the run, exit 2.
  `--artifacts <dir>` is the supplied-bytes option of `SPEC.md` §4, given after
  `--ordinary-seals-only` where both are and before the store root; the runner passes
  it exactly when the vector carries a `suppliedArtifacts` map, each key the 64
  lowercase hexadecimal characters of a file's name in a fresh directory and each value
  that file's bytes, and nothing in its place otherwise. No verdict for a vector run
  with it disagrees with that vector, `store <name>: no verdict under --artifacts:`, and
  the run goes on, as under `--ordinary-seals-only`.
- `CMD witness --trail <hex> --witness-key <file>... [--witness <file>]...
  [--witness-head <file>]` — the flags of the runtime's `audit verify`: the trail being
  verified; each key a file holding its 64 lowercase hexadecimal characters and a
  newline, in the vector's order; each statements file, in the vector's order; and the
  head file, exactly when the vector has one. stdout: the answer, as above, a refusal
  among them. Exit 0 whenever an answer was given; non-zero when none could be, which the
  runner reports as an implementation that could not answer, never as a refusal.

Findings are compared as a **multiset**: order is not normative. Observations are
compared as a multiset too, and only for a vector that states them; witnesses are
compared as a set, and rotations whole.

An answer, a verdict or a witness answer, is read by its members' exact names, as decoded
(`SPEC.md` §7). A member whose name differs from one the runner reads, if only in case, is not read:
the answer is compared as one without that member, and an object compared whole (a finding,
an observation, a witness, the rotations, a witness answer's refusal and its
`latestCheckpoint`) holding it disagrees. An answer in which an object, at any depth, gives
one name twice disagrees with that vector, `store <name>: the verdict gives a member twice
in one object:` or `witness <name>: the answer gives a member twice in one object:` and the
name, quoted, at most 256 bytes of it; the run goes on, and exits 1. A name given twice is
looked for once the answer is read as one JSON value and before any member is read, so an
answer giving one beside a member of the wrong type disagrees too. An answer that is not
one JSON value, is not an object, or gives a member the runner reads with the wrong type
still stops the run, exit 2.

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

The four `v3-descriptor-*` stores hold SPEC.md §9: a valid capture reference,
missing statement or snapshot artifacts, and changed statement bytes. Inputs and
expected findings are hand-authored; signatures were computed independently
with the published corpus test key, without calling either implementation.
