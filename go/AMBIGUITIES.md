# Ambiguities found building a second implementation

This records every place where `SPEC.md` did not determine behaviour and this Go
implementation had to make a judgment call. It is written from `SPEC.md`,
`CONTRACT.md` and `corpus/` alone — no other implementation of this format was
read.

Each entry says what the specification does say, what it fails to say, what was
chosen here, and what a different implementer could equally reasonably have
chosen. Where a claim is reproducible, the probe that shows it is named; the
probes live in `probes_test.go` (`go test -run TestProbes -v`).

The headline is entry **0**: most of this format is not in its specification at
all. Everything after it is a detail by comparison.

---

## 0. `SPEC.md` does not contain the format it is normative for

**What it says.** "This document is normative for receipt version 2." It then
describes the seal record, the registry-anchored checks, the trust boundary and
the HTTP surface, and defers the rest to the acquisition-proxy specification —
which, by `SPEC.md`'s own second paragraph, specifies **version 1** and
**diverges** from version 2 in exactly the places that matter (signatures not
HMACs, `prevSignature` not `prevHmac`, a `keyId` field).

**What it fails to say.** Everything a signature actually depends on. None of the
following appears anywhere in `SPEC.md`, and all of it had to be reconstructed
from the corpus by inspection:

| Reconstructed from the corpus | Value |
|---|---|
| The canonical JSON form | code-point member ordering, raw UTF-8, integer-only numbers, safe-integer bounds — inferred entirely from `corpus/canon.json` |
| The receipt's member set | `argumentsDigest`, `authority`, `callIndex`, `keyId`, `prevSignature`, `receiptVersion`, `resultDigest`, `servedAt`, `sessionId`, `signature`, `source` |
| `receiptVersion`'s type | the **string** `"2"`, not the integer `2` |
| What a receipt signature covers | context prefix + `canon(` every member except `signature` `)` |
| How `keyId` is derived | `sha256(publicKey_raw_32_bytes)` hex, truncated to the first 32 hex characters |
| The store layout | `<root>/receipts/<sessionId>/<callIndex>.json`, `<root>/artifacts/<sha256-hex>` |
| `resultDigest`'s form | `"sha256:" + hex(sha256(artifact bytes))` |
| The registry's file form | one JSON object per line, newline-separated |

The corpus rescues this: it is detailed enough that a clean-room implementation
converged. But `corpus/README.md` is explicit that the corpus "pins **the
reference's current behaviour**, not an independently derived truth", so what
converged here is agreement with the reference, not conformance to a
specification. The single highest-value change to `SPEC.md` would be to state
the canonical form and the receipt schema normatively, in the document, rather
than by reference to a document that specifies a different version.

The one thing `SPEC.md` *does* pin exactly — the seal signing input,
`"judgment-pack-gateway/seal/2:" + canon({sessionId, finalCount, sealedAt,
keyId})` — verified against the corpus on the first attempt. That is the
argument for writing the rest down the same way.

---

## 1. What a receipt signature covers

**What it says.** §2 gives the seal's signing input as an explicit four-member
list, and names the receipt's context prefix `"judgment-pack-gateway/receipt/2:"`.

**What it fails to say.** What follows that receipt prefix.

**Chosen here.** `canon` over *every* member of the receipt object except
`signature`. This verified against all corpus receipts, so it is certainly what
the reference produces for receipts of the expected shape.

**Equally reasonable.** `canon` over a **fixed list** of the ten non-signature
members. The two readings are indistinguishable on every corpus vector and
differ on exactly one input: a receipt carrying an *extra* member. Under the
"all members" reading the extra member is covered, so appending one invalidates
the signature; under the "fixed list" reading it is not covered, so an attacker
can append arbitrary unsigned members to a validly signed receipt and it still
verifies. Probe **B** shows this implementation answering `signature-mismatch`
where a fixed-list implementation would answer `ok`. This is a security-relevant
fork in the specification, not a cosmetic one, and no vector distinguishes it.

Relatedly: `argumentsDigest` is `hmac-sha256:…`. `SPEC.md` never mentions the
field, and §4's claim that "verification needs only the public key" quietly
depends on the arguments digest never being *re*computed by a verifier — an HMAC
can only be recomputed by the key holder. So the arguments are attested only in
the sense that an opaque string about them is signed. Worth saying out loud in
§4's honest-bounds list.

---

## 2. Duplicate member names in canonical JSON

**What it says.** Nothing.

**What it fails to say.** Whether `{"a":1,"a":2}` is inside the canonical domain,
and if so which value survives.

**Chosen here.** Refused, with the same status as any other domain violation.
For a format whose whole purpose is that two parties agree on which bytes were
signed, a document that two conforming parsers read as two different values does
not belong in the domain.

**Equally reasonable.** Last-wins (what `json.loads` and Go's `encoding/json` both
do) or first-wins. Both are defensible and they disagree with each other. A
receipt file carrying a duplicate member is `malformed` here (probe **E**) and
would be `ok` under a last-wins reader that re-canonicalizes.

---

## 3. Escaping choices `corpus/canon.json` does not reach

**What it says.** Nothing directly; the corpus pins the cases below that are
marked "pinned".

| Case | Pinned? | Chosen here | Equally reasonable |
|---|---|---|---|
| `"` `\` `\n` `\t` | pinned | short escapes | — |
| `\b` `\f` `\r` | **not** pinned | short escapes (`\b`, `\f`, `\r`) | `\u0008`, `\u000c`, `\u000d` |
| other C0 controls | `\u0001` pinned | `\u00xx` | — |
| hex case in `\u` escapes | **not** pinned (the one pinned vector is `\u0001`, whose digits have no case) | lowercase, e.g. `\u001f` | uppercase `\u001F` |
| `U+007F` (DEL) | **not** pinned | emitted raw | `\u007f` |
| `U+2028` / `U+2029` | **not** pinned | emitted raw | `\u2028` (some JSON writers escape these for JavaScript safety) |

Any of these appearing in a real `source` label, `authority` label or session id
would split two implementations that chose differently, and every receipt
carrying one would then disagree.

---

## 4. `-0`

**What it says.** Integers only, within ±9007199254740991.

**What it fails to say.** Whether `-0` is an integer literal, and what it
canonicalizes to.

**Chosen here.** Accepted and emitted as `0`.

**Equally reasonable.** Emitted as `-0` (preserving the literal), or refused as
not being in canonical form on input. All three are consistent with the text.

---

## 5. Which statuses exist — two checks `SPEC.md` names but never gives a status

**What it says.** §1: `verify_store` checks "signature, key id, location binding,
result re-digest, per-session `callIndex` sequence, and the `prevSignature`
chain". The intro says "A version 1 receipt does not verify here, and is not
accepted".

**What it fails to say.** The status string for the **key id** check and for the
**version** check. `corpus/README.md` says there is "one [vector] per status the
implementation can emit", yet neither of these has a vector, so neither has a
name an implementation could match.

**Chosen here.** `key-mismatch` when `keyId` is not `sha256(publicKey)[:16]` in
hex (probe **C**), and `unsupported-version` when `receiptVersion != "2"`
(probe **D**).

**Equally reasonable.** Any other spelling; or folding both into
`signature-mismatch`; or treating a version-1 receipt as `malformed`. Two
implementations will almost certainly not agree here, and the corpus cannot tell
them apart because it never exercises either path. **These two statuses are
untestable and unspecified — a conformance corpus that claims one vector per
status is missing two.**

Note also that §1's enumeration omits the **authority** check entirely, even
though `authority-mismatch` is a corpus status and §3 passes `authority` into
`verify_with_registry`.

---

## 6. One status per receipt, and the order the checks run in

**What it says.** §1 lists the checks in an order.

**What it fails to say.** Whether a receipt failing two checks reports one
finding or two, and whether §1's list order is the evaluation order.

**Chosen here.** One finding per receipt: the first failure in §1's stated
order — signature, key id, location binding, then result re-digest — with the
authority check inserted after location binding, since §1 does not place it.
Every corpus receipt fails at most one check, so nothing pins this.

**Equally reasonable.** Emitting every failed check as its own finding, or any
other evaluation order. A receipt that is both misfiled *and* has a missing
artifact reports `misfiled` here and could report `artifact-missing` elsewhere,
with both implementations passing the corpus.

Sub-case: "location binding" is read here as **two** bindings — the filename stem
must equal `callIndex`, *and* the receipt's `sessionId` must equal the directory
name. The corpus only exercises the first (`misfiled` moves a receipt within one
session). Dropping the second binding would matter: a genuine session could be
copied into a store under a different directory name whose seal happens to record
the same count, and nothing else would notice. Probe **A** shows this
implementation catching a renamed session directory; an implementation that only
checked the filename would report `ok` for all three receipts.

---

## 7. A broken sequence suppresses the chain check

**What it says.** §1 lists the `callIndex` sequence and the `prevSignature` chain
as two checks.

**What it fails to say.** How they interact.

**Chosen here.** The chain is checked only when the sequence of surviving
receipts is exactly `0..n-1`; a `sequence-broken` finding replaces the chain
check rather than accompanying it. Also: at most **one** `chain-broken` finding
per session, emitted at the first broken link.

**Why this is not a free choice.** `corpus/stores/sequence-broken.json` forces it.
That store holds receipts 0 and 2; receipt 2's `prevSignature` names receipt 1's
signature, and receipt 1 is gone, so the reconstructed chain `0 → 2` does not
link. A straightforward reading of §1 — two independent checks — yields both
`sequence-broken` **and** `chain-broken`, and because findings are compared as a
multiset, that extra finding **fails the vector**. Likewise
`corpus/stores/chain-broken.json` contains two broken links and pins exactly one
finding. Neither behaviour is derivable from `SPEC.md`; both are pinned by the
corpus. See "Where the corpus and SPEC.md disagree" below.

---

## 8. The store count the seal is compared against

**What it says.** §3: "store count `<` sealed count → `tail-rollback`", "store
count `>` sealed count → `count-exceeds-seal`". §2: `finalCount` is how many
receipts a session "finally held".

**What it fails to say.** What "store count" counts: receipt **files present**,
or receipts that **passed** verification, or the highest `callIndex` plus one.

**Chosen here.** Files present, regardless of whether they verified — pinned by
`corpus/stores/sequence-broken.json` (files `0.json` and `2.json`, `have: 2`) and
by `corpus/stores/malformed.json` (one unparseable file still counted, so no
count finding fires).

**Consequence worth noting.** Because a malformed file counts, a tail rollback can
be *disguised*: delete the last receipt and drop any junk file in its place, and
`tail-rollback` is replaced by `malformed` (probe **I**). The store is still
rejected — `ok` is false either way — but the diagnosis no longer names the
attack that happened, and §3's promise that the seal catches rollback is
narrower than it reads.

**Also unspecified: which files are receipts.** This implementation counts
directory entries ending in `.json`. An implementation that globs `*` would count
a stray `2.txt` as a receipt and report `malformed` for it; this one ignores it
and still reports `tail-rollback` (probe **J**). Two conforming implementations,
two different verdicts on the same store.

---

## 9. Duplicate seals for one session

**What it says.** §2: "Sealing a session that is already sealed is **refused** — a
session's `finalCount` can never be re-sealed to a smaller value."

**What it fails to say.** That rule binds the *gateway writing* the registry. A
verifier is handed a registry file; `SPEC.md` says nothing about what to do when
one arrives with two validly signed seals for one session — which a compromised
or merged registry could contain.

**Chosen here.** First seal wins; later seals for the same session are dropped.

**Equally reasonable.** Last wins, or the maximum `finalCount` wins (which is what
§2's "never re-sealed to a smaller value" reasoning would suggest), or treating a
duplicate as a finding in its own right. Probes **H** and **H'** show the same
two seals in the two possible orders producing `ok: true` and
`count-exceeds-seal` respectively — the verdict currently depends on line order
in a file the specification calls append-only.

---

## 10. Seals: what makes one loadable

**What it says.** §3 step 2: `load_seals` "**drops any seal whose signature does
not verify** under the public key".

**What it fails to say.** Whether anything else disqualifies a seal — in
particular whether a seal's `keyId` must match the verifier's key. The `keyId` is
*inside* the signed payload, so a seal can carry a foreign `keyId` and still
verify under our key.

**Chosen here.** Exactly what §3 says: signature only. A validly signed seal with
a foreign `keyId` is honoured (probe **K**). Lines that are not JSON, or that lack
a required member, or whose `finalCount` is not a non-negative integer, are
dropped — they are not seals.

**Equally reasonable.** Also requiring `keyId == sha256(publicKey)[:16]`, by
analogy with the receipt's key-id check that §1 does require.

---

## 11. Missing inputs

**What it says.** Nothing.

**Chosen here**, all as "still produce a verdict" (`CONTRACT.md` reserves non-zero
exit for "could not produce a verdict at all"):

- No `<root>/receipts` directory → zero sessions, so every seal yields
  `sealed-session-missing` (probe **N**).
- Registry file absent → no seals, so every session is `unregistered-session`
  (probe **M**). An empty registry file is already pinned by
  `corpus/stores/unregistered-session.json`; a *missing* one is not.
- An empty session directory → count 0; `ok` if sealed at 0 (probe **F**),
  `unregistered-session` if not sealed (probe **G**).

**Equally reasonable.** Exiting non-zero for a missing store root or a missing
registry, on the grounds that a verifier asked to check something that is not
there has not produced a verdict about anything.

---

## 12. §2a session-id tokens at verification time

**What it says.** §2a constrains a session id to `[A-Za-z0-9._-]{1,128}`, and
calls it load-bearing rather than hygiene, because an id that escaped the
receipts root would produce receipts verification could never enumerate.

**What it fails to say.** Whether a **verifier** re-checks the rule on the
directory names it enumerates.

**Chosen here.** No. Directory enumeration cannot yield `.`, `..` or a path
separator, so the escape §2a describes cannot arise on the read path.

**Equally reasonable.** Refusing, or flagging, a session directory whose name is
not a flat token, on the grounds that its presence is evidence the store was not
written by a conforming gateway. Probe **L** shows a session directory named
`a b` verified normally here (its receipts fail only because their `sessionId`
does not match the directory).

---

## 13. Finding order and the consequential `sequence-broken`

Both already recorded in `corpus/README.md`; confirmed from this side.

- **Order.** Not normative, compared as a multiset. This implementation emits
  sessions in directory-name order and receipts in filename string order, so it
  matches the reference's `0, 1, 10, 2, …` ordering by accident rather than by
  intent.
- **The second finding.** A receipt that fails is excluded from the
  reconstruction, so if the failing receipt is index 0 the session also reports
  `sequence-broken` (probes **B**, **C**, **D**, **E** all show it). Note the
  asymmetry this creates and that `corpus/README.md` does not mention: the same
  single defect produces one finding or two **depending on where in the session
  it sits**. `corpus/stores/misfiled.json` breaks the last receipt of three and
  reports no `sequence-broken`; `corpus/stores/authority-mismatch.json` breaks the
  first of two and does. If the second finding is meant to be informative, it is
  informative only about position.

---

# Where the corpus and `SPEC.md` disagree

Two places, both in §7's territory. In each, the corpus is not wrong so much as
*more specific than the document*, in a direction the document does not imply —
and because findings are compared as a multiset, an implementation that follows
`SPEC.md` literally **fails**.

1. **`corpus/stores/sequence-broken.json` expects no `chain-broken`.** §1 names
   the sequence check and the chain check as two of six independent checks. In
   that store, both are genuinely violated: receipts 0 and 2 are present, and
   receipt 2's `prevSignature` does not name receipt 0's signature. A literal
   reading of §1 emits two findings; the vector permits one. Either §1 should say
   that the chain is only reconstructed over a contiguous sequence, or the vector
   should expect both.

2. **`corpus/stores/chain-broken.json` expects one `chain-broken` for two broken
   links.** Receipt 1 is re-signed with a bogus `prevSignature`, which breaks
   link 0→1; and receipt 2 still names receipt 1's *original* signature, which
   breaks link 1→2 as well. The vector pins a single finding. §1 does not say
   that chain verification stops at the first break, and "one finding per broken
   link" is at least as natural a reading.

And one corpus documentation defect, harmless to behaviour but confusing to
exactly the reader the corpus is for — a second implementer:

3. **Two store vectors describe version 1 mechanics.**
   `corpus/stores/chain-broken.json` says "A receipt whose **prevHmac** is
   re-pointed"; `corpus/stores/forged-seal-is-dropped.json` says "a seal … whose
   **hmac** was not produced by the key". Version 2 has no `prevHmac` and no
   HMAC in either position — `SPEC.md`'s opening paragraphs say so explicitly.
   The notes are inherited from the acquisition-proxy vectors and were not
   updated with the format.
