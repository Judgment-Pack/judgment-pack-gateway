# Gateway specification

The gateway is the **hosted deployment shape** of the trustworthy-input-acquisition
line ([judgment-pack-evaluator-experiments](https://github.com/Judgment-Pack/judgment-pack-evaluator-experiments),
ADR-0002). It reuses the inline attestation format unchanged and adds exactly one
mechanism on top: a **sealed session registry** that closes the two residuals the
inline verify cannot catch on its own.

**This document is normative for receipt version 2.** It began by deferring the
format to the acquisition-proxy
([`acquisition-proxy/SPEC.md`](https://github.com/Judgment-Pack/judgment-pack-evaluator-experiments/blob/main/acquisition-proxy/SPEC.md)),
which specifies version 1. Version 2 **diverges** from it: receipts and seals are
Ed25519 signatures rather than HMACs, the chain link is `prevSignature` rather than
`prevHmac`, and a receipt carries a `keyId`. A version 1 receipt does not verify
here, and is not accepted — the research artifact keeps its format, this gateway
owns the one that gets deployed and independently implemented.

The reason for the divergence is the property version 1 could not have: verifying an
HMAC requires the key that mints it, so "an independent party can check this" was
never true of version 1. See §5.

## 1. The format

Everything a signature depends on is stated here. An earlier revision of this
document declared itself normative for version 2 while still deferring the base
format to the acquisition-proxy specification — which specifies version 1. A
clean-room second implementation had to reconstruct the canonical form, the
receipt schema, `keyId` derivation, the store layout and the registry file form
from `corpus/` by inspection, because none of it was written down. That is the
defect this section exists to close.

### 1.1 Canonical form (`canon`)

`canon` maps a value to the exact bytes that get signed. Two implementations that
canonicalize differently disagree about *every* receipt, so this is stated
exhaustively.

**Domain.** Objects, arrays, strings, integers, `true`, `false`, `null`. Anything
else is **refused**.

- **Numbers are integers only**, within ±(2⁵³−1). A float *literal* is refused
  even when integer-valued: `1.5`, `1.0` and `1e2` are all outside the domain.
  `-0` is accepted and emitted as `0`.
- **Strings** must be encodable UTF-8. A lone surrogate is refused.
- **Duplicate member names are refused.** A document two conforming parsers read
  as two different values has no place in a format whose purpose is that two
  parties agree on which bytes were signed; last-wins and first-wins are both
  defensible, they disagree, and the disagreement is silent.

**Output.**

- Object member names are ordered by **Unicode code point** — *not* by UTF-16
  code unit. The two disagree on any name outside the BMP, and RFC 8785 (and the
  judgment-pack runtime's own `internal/jcs`) specify the UTF-16 ordering, so an
  implementer reaching for an existing JCS package gets this wrong.
- Array order is preserved, never sorted.
- Compact: no whitespace anywhere.
- Raw UTF-8. Non-ASCII is **not** `\u`-escaped, and `<`, `>`, `&` are **not**
  escaped (Go's `encoding/json` escapes them by default). The solidus is not
  escaped.
- Escapes are `\"`, `\\`, and the short forms `\b`, `\f`, `\n`, `\r`, `\t`.
  Other C0 controls take `\u00xx` with **lowercase** hex. `U+007F`, `U+2028` and
  `U+2029` are emitted raw.

### 1.2 The receipt

A receipt is a canonical JSON object. Every member is required.

| Member | Type |
|---|---|
| `receiptVersion` | the **string** `"2"` (not the integer) |
| `sessionId` | a flat token (§3a) |
| `callIndex` | integer, `0`-based, contiguous within a session |
| `prevSignature` | the previous receipt's `signature`; `null` at `callIndex` 0 |
| `source` | operator-configured source name |
| `argumentsDigest` | `"hmac-sha256:" + hex`, keyed and therefore **opaque to a public verifier** — but deterministic per arguments under one key, so argument *equality* across receipts is observable to any party able to invoke `/acquire` (§5) |
| `resultDigest` | `"sha256:" + 64 lowercase hex` over the retained artifact bytes |
| `servedAt` | timestamp string |
| `authority` | operator-configured authority label |
| `keyId` | `sha256(public key, 32 raw bytes)` in hex, **first 32 characters** |
| `signature` | Ed25519 signature, hex |

**What the signature covers** — `"judgment-pack-gateway/receipt/2:"` followed by
`canon` of the receipt object with **the `signature` member removed and every
other member retained**.

This is security-relevant and is stated because no vector can distinguish it: an
implementation that instead signed a *fixed list* of the eleven known members
would let an attacker append arbitrary **unsigned** members to a validly signed
receipt, and it would still verify. Covering "everything except `signature`" means
appending anything invalidates the signature.

The context prefix domain-separates a receipt signature from a seal signature
(§3), so neither can be replayed as the other.

### 1.3 Store layout

```
<root>/receipts/<sessionId>/<callIndex>.json   one canonical receipt, newline-terminated
<root>/artifacts/<hex>                          the retained bytes; <hex> is resultDigest's hex
```

The registry is a separate file: one canonical seal object per line, newline
separated.

### 1.4 Verification statuses

Per receipt, **at most one finding**, taken at the first failure in this order:

| Order | Status | Condition |
|---|---|---|
| 1 | `malformed` | unparseable, duplicate member names, missing `signature`, `callIndex` not an integer, `resultDigest` not of the stated form, or `signature` not hex |
| 2 | `unsupported-version` | `receiptVersion` is not `"2"` |
| 3 | `key-mismatch` | `keyId` is not the verifier's own key id |
| 4 | `signature-mismatch` | the signature does not verify over §1.2's input |
| 5 | `misfiled` | the filename stem is not `callIndex`, **or** `sessionId` is not the directory name |
| 6 | `authority-mismatch` | `authority` is not the expected authority |
| 7 | `artifact-missing` | no artifact at `resultDigest`'s path |
| 8 | `artifact-mismatch` | the artifact re-digests to something else |
| — | `ok` | none of the above |

Both halves of `misfiled` are load-bearing: without the `sessionId`↔directory
binding, a genuine session could be copied into a store under a different
directory name whose seal happens to record the same count.

Per session, over the receipts that passed:

- if their `callIndex` values are not exactly `0..n-1`, the session reports
  **`sequence-broken`** and **the chain is not checked** — a chain cannot be
  reconstructed over a sequence with a hole;
- otherwise each `prevSignature` must name the previous receipt's `signature`,
  and the **first** break reports one **`chain-broken`** for the session.

A receipt that fails is excluded from that reconstruction, so a failure at
`callIndex` 0 also produces `sequence-broken`. That second finding is a
consequence of position, not additional evidence.

## 2. What per-receipt verification catches, and what it cannot

`attest.verify_store` checks every receipt against the public key: signature, key
id, location binding, result re-digest, per-session `callIndex` sequence, and the
`prevSignature` chain. That
makes a store *internally* consistent-or-not. Two attacks leave a store internally
consistent yet not faithful:

- **Whole-session replay.** A genuine session — every receipt validly chained and
  signed under the real key — copied verbatim into another store passes
  `verify_store` there too. Nothing inside a session says *which store it belongs
  to* or *that it is current*.
- **Final-tail rollback.** Deleting the last *k* receipts of a session leaves a
  shorter prefix `0..n-k-1` that is still a valid chain. `verify_store` cannot know
  the session once had more, because the evidence that it did was in the deleted
  receipts.

Both require an anchor **outside** the store: a record of which sessions exist and
how many receipts each finally held, kept by the party that did the attesting and
not forgeable by whoever holds the store.

## 3. The seal

When a session closes, the gateway seals it. A seal is one append-only record:

```
{ "sessionId": <string>, "finalCount": <integer>, "sealedAt": <string>,
  "keyId": <hex>, "signature": <hex> }
```

`signature` = Ed25519, under the gateway's signing seed, over
`"judgment-pack-gateway/seal/2:" + canon({sessionId, finalCount, sealedAt, keyId})`.
The context prefix domain-separates a seal signature from a receipt signature
(`"judgment-pack-gateway/receipt/2:"`) so neither can be replayed as the other.

Checking a seal needs only the **public** key — see §5.

The registry is an append-only file, one seal per line. Sealing a session that is already sealed is **refused** — a session's
`finalCount` can never be re-sealed to a smaller value, so a seal cannot be walked
backward to excuse a rollback.

## 3a. Session identifiers

A session id names a directory under the store, and a verifier discovers sessions by
**enumerating** that directory. The id is caller-supplied and the caller sits outside
the trust boundary, so it is constrained to a flat token:

```
[A-Za-z0-9._-]{1,128}          (and never "." or "..")
```

Anything else — an absolute path, a `..` segment, a nested path — is refused
(`400` over HTTP) before any source runs. This is load-bearing, not hygiene: an id
that escaped the receipts root would produce **genuinely attested, gateway-signed
receipts that verification could never enumerate**, so `/verify` would answer `ok`
for a store missing sessions the gateway had itself signed — silently voiding §4's
coverage guarantee. The store enforces the same rule on write, so the guarantee does
not rest on the HTTP layer alone.

## 4. Registry-anchored verification

`verify_with_registry(verify_store, store_root, key, registry_path, authority)`:

1. Runs `verify_store` (all per-receipt findings carry through unchanged).
2. Loads the seals, **dropping any seal whose `keyId` is not the verifier's own or
   whose signature does not verify** under the public key. Both conditions are
   required: `keyId` sits *inside* the signed payload, so a seal signed by this key
   while naming a foreign `keyId` verifies happily, and an earlier revision that
   said "signature" and nothing else was followed literally by a second
   implementation — the two then disagreed, with no vector to catch it. A seal
   forged by someone without the seed is discarded either way, so a store cannot be
   excused by a forged registry.

   Where a registry contains more than one loadable seal for one session — which
   §3's append-only rule forbids a conforming gateway from writing, but says
   nothing about a verifier receiving — the **first** wins.
3. For each session present in the store, where its **count is the number of
   `.json` files present**, whether or not each verified — so a rollback can be
   disguised by dropping a junk file in place of a deleted receipt. The store is
   rejected either way, but the diagnosis then reads `malformed` rather than
   `tail-rollback`:
   - not in the loaded seals → **`unregistered-session`** (whole-session replay, or
     a session forged without the key).
   - store count `<` sealed count → **`tail-rollback`**.
   - store count `>` sealed count → **`count-exceeds-seal`** (receipts beyond the
     seal; a seal is a high-water mark).
4. For each sealed session **absent** from the store → **`sealed-session-missing`**
   (a whole sealed session deleted).

`ok` is true only if the inline verify passed **and** no registry finding fired.

The verifier must obtain the registry from the gateway (the key holder), **not** from
the untrusted store. That is the whole point: the anchor's authority comes from being
outside the store's reach and sealed under a key the store's holder does not have.

### 4.1 Absent and empty inputs

A verifier asked to check something that is partly not there still **produces a
verdict**; it does not refuse. Non-zero exit is reserved for being unable to reach
a verdict at all.

| Situation | Reading |
|---|---|
| `<root>/receipts` does not exist | zero sessions — every sealed session is then `sealed-session-missing` |
| `<root>/receipts` exists but is not a directory | no verdict — the verifier refuses (non-zero exit); the evidence is present and unreadable, not absent |
| `<root>/receipts` is a directory that cannot be read | no verdict — the verifier refuses (non-zero exit); the evidence is present and unreadable, not absent |
| the registry file does not exist | no seals load — every session in the store is then `unregistered-session` |
| a session directory holding no receipts | a session with count 0, judged against its seal like any other |

Each of these fails **closed**: an absent anchor cannot make a store verify, it can
only fail to excuse one. A store that is genuinely empty against an empty registry
verifies, because there is nothing it contradicts.

A verifier does **not** re-apply §3a's token rule to the directory names it
enumerates. Directory enumeration cannot yield `.`, `..` or a path separator, so
the escape §3a exists to prevent cannot arise on the read path; a name outside the
token rule is evidence the store was not written by a conforming gateway, but it is
not itself a finding.

## 5. Trust boundary and honest bounds

- The gateway holds **one protected signing identity** (an Ed25519 seed). It lives
  in the service, never in a client or a downstream consumer. A client calls
  `/acquire` and **cannot supply a receipt** — the gateway produces every receipt.
  This is what removes the model/agent from the proof path: a caller can lie about
  facts, but it cannot manufacture the gateway's signature.
- **Verification needs only the public key.** Receipt version 2 signs rather than
  HMACs, so a verifier can check every receipt and seal without holding anything
  that would let it produce one. This is the property that makes independent
  verification meaningful rather than nominal.
- **The public key must arrive out of band.** Fetching it from the gateway under
  audit and then checking that gateway's store proves internal consistency, not
  authenticity: an impostor serves its own key and its own store, and they agree.
  A receipt therefore carries a `keyId` and never a key, so an implementation
  cannot accidentally trust the key a store hands it. Establishing that channel is
  out of scope here.
- A signature still proves only **byte-lineage under an operator-configured
  authority label**: not that a genuinely-named source returned the bytes (the
  recorded `source`/`authority` is a label, not an authenticated origin). The seal
  inherits exactly this — it proves *this key holder sealed this count*, not *this
  count is true of the world*.
- The registry closes whole-session replay and tail rollback **relative to a
  verifier that trusts the gateway's registry over the store**. It does not defend a
  compromised gateway (key disclosure forges anything), and it is a single-identity,
  single-operator reference — not a multi-tenant or federated trust root.
- Scope not claimed: no availability/HA guarantees, no authenticated transport
  (binds localhost), no access control on the HTTP surface. This is a reference for
  self-hosting a trust root and for demonstrating the mechanism, not a hardened
  public deployment.

## 5a. Consuming an attestation

Everything above specifies how receipts are produced and verified. This section is
normative for the **consumer**: what a verdict means, and every step between holding
one and acting on the bytes. Each rule below was re-derived independently by early
consumers — and the first was answered two opposite ways by two consumers of the
same spec — which is why they are written down.

**5a.1 The verdict is store-wide, and fails closed.** A consumer's verdict is the
`ok` of its own verifier run (§4). `ok: false` — from any finding, in any session —
withholds **every** session in the store: a store that failed verification anywhere
is not a store to selectively believe. A consumer MAY instead apply a deliberate
**session-scoped** verdict, and then all of the following must hold for the one
session it acts on:

- its own findings are all `ok`, and at least one finding names the session — a
  session with no findings holds no accepted receipt (it is absent, or validly
  sealed at count zero, which §4.1 permits) and there is nothing in it to act on;
- it is registered: no `unregistered-session` finding names it;
- its seal holds: no `tail-rollback`, `count-exceeds-seal`, or
  `sealed-session-missing` finding names it;
- its chain holds: no `sequence-broken` or `chain-broken` finding names it.

Session-scoping is a choice with a name, made deliberately in the consumer's code or
configuration. Silence means store-wide. The list above leans on an invariant of
this verifier's report: **every finding carries `sessionId` and `status`.** A
verifier extended with a store-level finding that names no session must extend this
list with it, or the scoped check goes blind to it.

**5a.2 The verdict is the JSON, never the exit code.** Per §4.1 a verifier that
reached a verdict exits `0` whether the verdict is good or bad; non-zero is reserved
for reaching no verdict at all. A consumer gating on exit status alone accepts a
store that failed verification. Read `ok` and `findings`.

**5a.3 `GET /verify` is not evidence.** That endpoint is the audited party grading
itself. A consumer runs the verifier itself, over a store it holds, with the
registry fetched from the key holder, under a public key pinned **out of band**
(§5) — never the key the same store or gateway handed it.

**5a.4 The artifact selector is bound to an accepted receipt, then the bytes are
re-digested.** `gateway verify` re-digests every artifact while verifying and
returns none of them — and returns no receipt either, so a `resultDigest` a
consumer picked up elsewhere selects nothing trustworthy by itself: a receipt file
read *after* verification can have been replaced, and an orphan file under
`artifacts/` is invisible to verification entirely. Before any use of bytes, a
consumer therefore establishes **both** halves:

1. **Binding**: the `resultDigest` comes from a receipt the consumer itself
   checked — either read from the exact store snapshot its verifier run audited
   *and* signature-checked under the pinned key (§1.2's coverage rule), or the
   complete acquire response receipt (§6) signature-checked the same way — and
   that receipt's `(sessionId, callIndex)` appears among the verifier's `ok`
   findings, so the checked receipt is a member of the verified store rather
   than a look-alike.
2. **Re-digest**: the bytes actually loaded re-digest to that receipt's
   `resultDigest`, whose hex is validated as exactly 64 lowercase hex characters
   before it is ever used in a path.

Bytes nobody re-checked are bytes nobody attested, and a digest no accepted
receipt covers selects nothing.

The consumer's ceremony, in order: **obtain the snapshot → verify under a pinned
key → bind the receipt → re-digest → use.** Acquiring and sealing are the
*producer's* steps and precede it; an offline consumer of an already-sealed store
starts at the snapshot. `go/ceremony_test.go` walks both executably against this
implementation, refusal legs included.

What follows the ceremony is out of scope here: turning verified bytes into a claim
by a checkable rule is a derivation rule's job — specified in the
`judgment-pack-evaluator-experiments` repository (`derivation-rule/`) — and
byte-lineage never becomes truth on the way through (§5).

## 6. HTTP surface (reference)

Localhost, JSON, standard library only.

| Method | Path        | Body / result |
|--------|-------------|---------------|
| POST   | `/acquire`  | `{session, source, arguments}` → runs the configured source, attests, chains, retains; returns `{result, receipt}`, where `receipt` is the complete receipt object of §1.2 — every member, `keyId` and `signature` included, the same object written under `receipts/<session>/<index>.json`. The response body is ordinary JSON, not the receipt's canonical form: a caller checking the signature canonicalizes the receipt per §1.1 first — a caller holding the binary has `gateway canon` for exactly that — and then applies §1.2's coverage rule. No receipt is accepted from the caller. `session` must be a flat token (§3a) or the call is refused `400` before the source runs. |
| POST   | `/seal`     | `{session}` → seals the session's final count; returns the seal record. |
| GET    | `/verify`   | → `{ok, findings}` from `verify_with_registry`. |
| GET    | `/registry` | → the raw registry bytes, for a verifier to fetch the anchor from the key holder. |
| GET    | `/publickey`| → `{algorithm, keyId, publicKey, authority}`. Convenience only — a verifier that obtains the key here and then audits this same gateway has checked consistency, not authenticity (§5). |

A `source` is an operator-configured subprocess that reads the canonical arguments on
stdin and emits a JSON result on stdout. The gateway attaches no transport of its own
— it attests whatever bytes a configured source returns, which is exactly the inline
core's boundary: **proof of the bytes, not proof of their truth.**

## 7. Conformance

An implementation of this specification is checked against the frozen vectors in
[`corpus/`](corpus/README.md), never against another implementation's source. The
corpus is **frozen**: hand-maintained normative data, not output regenerated from
whichever implementation exists. Changing a vector is a specification change and
needs the same justification as changing this document. Two families:
**canon vectors** (a value → its exact canonical bytes, or a refusal) and **store
vectors** (a complete store and registry → the expected `(ok, findings)`), with one
store vector per status this document names.

`gateway conform` runs them, and `--impl CMD` drives any other implementation
through a small process contract, so an implementation in any language can answer
to the corpus without depending on this one. Findings are compared as a multiset: **order is not normative.**

Two questions this specification does not yet settle, surfaced by building the
corpus and recorded in [`corpus/README.md`](corpus/README.md): the order of
findings, and whether a receipt that fails verification is *required* to also
produce the `sequence-broken` that follows from its exclusion from the chain
reconstruction. An implementation that differs on either is not thereby
non-conforming; the specification is what needs to improve.

The vectors are signed under a published test seed (`corpus/TEST-SEED`), which signs
nothing real and must never be used by a deployment. Verification consumes only
`corpus/TEST-PUBLIC-KEY` — running the corpus never hands the runner a secret,
which is the same property receipt version 2 gives a real verifier.
