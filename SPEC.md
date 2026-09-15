# Gateway specification

The gateway is the **hosted deployment shape** of the trustworthy-input-acquisition
line ([judgment-pack-evaluator-experiments](https://github.com/Judgment-Pack/judgment-pack-evaluator-experiments),
ADR-0002). It reuses the inline attestation format unchanged and adds exactly one
mechanism on top: a **sealed session registry** that closes the two residuals the
inline verify cannot catch on its own.

**This document is normative for receipt versions 2 and 3.** Version 3 (§1.2a)
adds to version 2 and changes nothing version 2 states: a receipt signed under
version 2 means afterwards exactly what it meant before, a version 3 verifier
verifies a version 2 store unchanged (§1.4), and the seal (§3) is the same record
under both. It began by deferring the
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

### 1.2 The receipt (version 2)

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

### 1.2a The receipt (version 3)

A version 2 receipt binds the bytes, the position in a session, the chain, and
two labels the operator chose. It does not say which system was asked, which
statement ran, which snapshot was read, through what, or for whom; its arguments
commitment is an equality oracle to every caller (§5); and it has no form for an
action a person asked for. Version 3 is version 2 with those members added. It
is the same canonical JSON object under the same rules (§1.1): the new members
are strings, integers, `null`, objects and arrays of strings, so nothing new
enters the canon domain.

Every member is required unless marked optional. A nullable member is present
as `null`, never absent: an absent member would let a receipt made with a
capability switched off read the same as one made before the member existed.
Every **structural** constraint this section states — a member's presence, its
type, an enumeration, the shape of an object, the form of a string — is a
condition of §1.4 order 1: a receipt that violates any of them is `malformed`,
before its version, key or signature is looked at. A **relational**
requirement — that `prevSignature` names the previous receipt's signature, that
a cited receipt exists, that a digest matches some bytes — is not an order-1
condition; each is checked at the stage §1.4 or §4 assigns it, and nowhere
else. `pageItems` is a producer's assertion about the page it attests: the
verifier checks its form and nothing about its correspondence to the artifact,
which a consumer checks for the item it uses by re-digesting that item (§5a).
Two forms recur and are named once:

- a **digest** is the string `"sha256:"` followed by exactly 64 lowercase
  hexadecimal characters; uppercase, another length, or another prefix is not a
  digest. `resultDigest`, `argumentsCommitment`, `tokenDigest`, `adapter.digest`,
  `statement`, `schema`, `recordDigest`, `packDigest`, `request`, and each element
  of `pageItems` are digests;
- a version 3 **signature** — the receipt's own and each `cites[*].signature` —
  is exactly 128 lowercase hexadecimal characters, the 64 bytes of an Ed25519
  signature; uppercase or another length is `malformed` here, where version 2
  left the case open and classed a wrong length as `signature-mismatch`.

| Member | Type |
|---|---|
| `receiptVersion` | the **string** `"3"` |
| `sessionId`, `callIndex`, `prevSignature`, `source`, `resultDigest`, `servedAt`, `authority`, `keyId`, `signature` | as in §1.2 |
| `kind` | the string `"acquisition"` or `"action"` |
| `argumentsCommitment` | a digest: a salted commitment (below) to the canonical arguments |
| `caller` | `{ "issuer": string, "subject": string, "tokenDigest": "sha256:" + hex }`, or `null` |
| `acquisition` | object (below); present exactly when `kind` is `"acquisition"` |
| `action` | object (below); present exactly when `kind` is `"action"` |

`argumentsDigest` does not exist in version 3.

**Commitments and their salts.** For each commitment a receipt carries, the
gateway draws 32 random bytes, that commitment's *salt*, and returns it to the
caller in the response of the operation that produced the receipt — for
`/acquire`, the acquire response (§6). A salt is never retained, never signed,
and never part of the store. A commitment to a value is `"sha256:"` + hex of
SHA-256 over `salt || label || canon(value)`, where `label` is `"args:"` for
`argumentsCommitment`, `"statement:"` for `acquisition.statement` and
`"request:"` for `action.request`. The salts of one receipt are independent: a
caller can reveal one committed value by handing over that value and its salt,
and the receipt's other commitments stay as closed as they were. A verifier
checks nothing about a commitment.

The disclosure boundary this fixes, stated as narrowly as it holds: a party
holding the store learns nothing about a committed value **from its
commitment**, since without the salt every candidate hashes to something equally
unrelated — what the retained artifact itself discloses is the source's affair,
and a source that echoes its arguments has disclosed them; a party able to call
`/acquire` cannot compare its own commitment with another receipt's, since the
salts differ, which is the oracle version 2 has (§5); the caller, who holds the
salts, can reveal a value to an auditor of its choosing, and only the caller
can. A caller that loses a salt has lost the ability to reveal that value.

**`caller`.** The identity that made the request, from a token the gateway
verified against an issuer it was configured to trust: the token's issuer and
subject, and the digest of the token bytes as presented. The token itself is
never stored and never signed into a receipt. A gateway configured with no
issuer records `null`. What a verified token proves is who asked, at the
gateway's boundary. It does not prove that they approved what was asked for.

**`acquisition`** — present when `kind` is `"acquisition"`:

| Member | Type | Meaning |
|---|---|---|
| `adapter` | `{ "name": string, "version": string, "digest": "sha256:" + hex }` | the program that fetched; for a connector image, the image digest |
| `shape` | `"airbyte"`, `"mcp"`, `"http"`, or `"command"` | which adapter shape served the call; `"command"` is a bare operator-configured command with no adapter — the version 2 posture, kept available and visible |
| `endpoint` | string or `null` | the host or URL the adapter connected to, as it would name it to an operator |
| `statement` | `"sha256:" + hex` or `null` | a commitment (above) to the query, resource path, or tool call |
| `snapshot` | string or `null` | what the source said about currency — a state bookmark, a transaction id, an object version, an ETag; `null` when the source offers nothing |
| `peerIdentity` | string or `null` | the identity the transport established, such as `"tls:sha256:" + hex` of the peer's certificate; `null` for a local process |
| `schema` | `"sha256:" + hex` or `null` | the discovered stream or resource schema, canonicalized and digested |
| `upstreamToken` | string or `null` | an integrity token the upstream itself produced, carried verbatim when one exists; `null` when the upstream vouches for nothing |
| `pageItems` | array of `"sha256:" + hex` — **optional** | for a page, the digest of each item's canonical bytes in order; absent for a single result |
| `observedAt` | string | when the adapter received the bytes, as the adapter recorded it; `servedAt` remains the gateway's own stamp. For the `"command"` shape, which records nothing, it is the gateway's own stamp of the moment it had read the source's output in full, never later than `servedAt` |

`upstreamToken` and `shape` are the honest-bounds members: a receipt never lets
a source that vouches for itself and a source that vouches for nothing read the
same, and never lets bytes attested through a bare command read as bytes whose
acquisition was recorded.

**Where the members come from.** For the `"command"` shape the gateway records
what it alone can: the command as its adapter, `null` for every member a
command cannot report, and its own `observedAt`. For every other shape the
gateway records what the adapter reported in the envelope it wrote on stdout
(§6, "Adapter sources"), with three exceptions: `shape` is what the operator
declared for the source, never what the adapter says; `statement` is the
gateway's own commitment (above) to the statement text the adapter reported,
whose salt the acquire response returns; and `pageItems` is computed by the
gateway over the items of the result it attests. An acquisition record of any
adapter shape is therefore the adapter's testimony under the gateway's
signature: what a compromised adapter can do is misreport its acquisition, as
it can misreport its bytes, and the receipt names the source it was configured
as. What it cannot do is sign — provided it cannot read the seed, which is the
separation SECURITY.md describes and the operator establishes: an adapter run
as the signer's own identity can read what the signer can, as any source can.
Only `statement` is committed; what an adapter writes into `endpoint`,
`snapshot`, `peerIdentity`, `upstreamToken` or the result itself is in the
receipt or the artifact in the clear.

**`action`** — present when `kind` is `"action"`. An action receipt records that
an executor was asked to perform something, by which authenticated identity,
citing which decision, and what the target answered. `resultDigest` is over the
target's response bytes, retained like any artifact.

| Member | Type | Meaning |
|---|---|---|
| `requester` | `{ "issuer": string, "subject": string, "tokenDigest": "sha256:" + hex }` | the authenticated identity that submitted the request; **never `null`** — a request with no authenticated requester is refused before any executor runs |
| `decision` | `{ "recordDigest": "sha256:" + hex, "packDigest": "sha256:" + hex }` | the decision record the requester says the action relies on, and the pack it says the decision was made under, by digest |
| `cites` | array of `{ "sessionId": flat token (§3a), "callIndex": non-negative integer, "signature": signature }` | the acquisition receipts the requester says the decision record relied on |
| `tool` | `{ "shape": string, "endpoint": string or `null`, "name": string }` | what was called, named as `acquisition` names its adapter |
| `request` | `"sha256:" + hex` | a commitment (above) to the request the executor sent |
| `adapter` | as in `acquisition` | the executor that performed it |
| `observedAt` | string | when the target answered |

`decision.packDigest` and `cites` are assertions the requester supplied. §4
checks that the cited receipts exist and that a decision record with the stated
digest exists; it does not compare the record's contents with either. A decision
record that itself carries a `cites` member of this same shape — a record the
runtime wrote with the citations its caller gave it — has those resolved by §4
step 7 on the record's own behalf, and that is the only member of a record §4
reads. An action receipt does not say the action was right, and it does
not say the identity approved it: it is lineage of a request and a response.

**What the signature covers** — `"judgment-pack-gateway/receipt/3:"` followed by
`canon` of the receipt object with **the receipt's own top-level `signature`
member removed and every other member retained** — every nested member
included, `action.cites[*].signature` among them, which is a cited value and not
this receipt's signature. Appending anything anywhere, inside `acquisition` or
`action` included, invalidates the signature. The prefix carries the version, so
a version 3 signature cannot be presented as a version 2 one or the reverse; the
seal's prefix is unchanged (§3).

### 1.3 Store layout

```
<root>/receipts/<sessionId>/<callIndex>.json   one canonical receipt, newline-terminated
<root>/artifacts/<hex>                          the retained bytes; <hex> is resultDigest's hex
```

The registry is a separate file: one canonical seal object per line, newline
separated.

A version 3 store has the same layout. Salts are not in it (§1.2a). Decision
records are not in it either: they are the runtime's own files, and a verifier
is handed their directory separately (§4). A store may hold receipts of both
versions across sessions; within one session every receipt is of one version,
and a session that mixes them is `chain-broken` (§1.4).

### 1.4 Verification statuses

Per receipt, the ladder below yields **at most one status**, taken at the first
failure in this order. (§4 steps 5 and 6 add findings of their own to a
version 3 action receipt that passed the ladder, beside its `ok`; those are not
statuses of the ladder and do not replace it.)

| Order | Status | Condition |
|---|---|---|
| 1 | `malformed` | unparseable, duplicate member names, missing `signature`, `callIndex` not an integer, `resultDigest` not of the stated form, or `signature` not hex; for version 3, **any** violation of a structural constraint §1.2a states — a member required absent, a member of another type than stated, a nullable member neither `null` nor of its stated shape, `kind` or `shape` outside its enumeration, the object for the kind missing or its sibling present, a digest or a signature not of its stated form, `pageItems` present and not an array of digests, `requester` `null`, `cites` not an array of objects of the stated shape — and never a relational one |
| 2 | `unsupported-version` | `receiptVersion` is neither `"2"` nor `"3"` |
| 3 | `key-mismatch` | `keyId` is not the verifier's own key id |
| 4 | `signature-mismatch` | the signature does not verify over the input §1.2 or §1.2a defines for the receipt's version |
| 5 | `misfiled` | the filename stem is not `callIndex`, **or** `sessionId` is not the directory name |
| 6 | `authority-mismatch` | `authority` is not the expected authority |
| 7 | `artifact-missing` | no artifact at `resultDigest`'s path |
| 8 | `artifact-mismatch` | the artifact re-digests to something else |
| — | `ok` | none of the above |

Both halves of `misfiled` are load-bearing: without the `sessionId`↔directory
binding, a genuine session could be copied into a store under a different
directory name whose seal happens to record the same count.

A finding carries `sessionId`, `status`, and the receipt's `callIndex` — except a
`malformed` finding, which carries `file`, the receipt's filename, in place of
`callIndex`: a receipt refused at order 1 has not established what its index is,
whatever the text claims, and this holds for a version 3 receipt refused for a
§1.2a violation as it does for one that never parsed. In every per-receipt
finding, `sessionId` is the name of the session directory the receipt was found
in, never the value the receipt claims: a `misfiled` receipt claiming another
session is reported under the directory that holds it, so a session-scoped
reading (§5a.1) sees every failure in the session it scopes to. Version 2 has
always reported both so; version 3 changes nothing here.

Per session, over the receipts that passed:

- if their `callIndex` values are not exactly `0..n-1`, the session reports
  **`sequence-broken`** and **the chain is not checked** — a chain cannot be
  reconstructed over a sequence with a hole;
- otherwise each `prevSignature` must name the previous receipt's `signature`,
  and each receipt's `receiptVersion` must equal the session head's
  (`callIndex` 0), and the **first** break of either kind, walking the passing
  receipts in index order, reports one **`chain-broken`** for the session — the
  session-level finding, with `callIndex` `null`, exactly as a `prevSignature`
  break does. A receipt that failed the ladder takes no part in this walk, and
  a session whose sequence is broken is not walked at all.

A receipt that fails is excluded from that reconstruction, so a failure at
`callIndex` 0 in a session where any other receipt passed also produces
`sequence-broken`. That second finding is a consequence of position, not
additional evidence. A session in which **no** receipt passed has an empty
passing set, which is `0..n-1` with `n` = 0: it is not broken, and the
session reports its failures and nothing about its sequence or chain.

The version of a receipt decides which structural checks order 1 applies and
which signing input order 4 uses; the two versions are otherwise verified by
the same steps, and a version 2 receipt verifies under a version 3 verifier
exactly as it did before. A verifier that knows version 2 alone does not verify
a version 3 receipt: it reports `malformed`, because the receipt lacks
`argumentsDigest`, or `unsupported-version`, according to which of its order-1
checks it reaches first — a refusal either way, never an acceptance. Version 2
receipts are relabelled `"3"` at their peril: they lack every member §1.2a
requires and fail at order 1, not at the signature.

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

The registry is an append-only file, one seal per line. A seal is appended on a line of its
own: a gateway that finds the registry's last line unterminated — an earlier seal written in
part, or whole but for its newline — ends that line before it writes the record, since a
record joined to it would make one line that is no seal (§4 drops it) and lose both. Sealing a session that is already sealed is **refused** — a session's
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
5. For each version 3 receipt of kind `"action"` whose ladder status is `ok`,
   each entry of `cites` must resolve: its `sessionId` must be **exactly** one
   of the session directory names the verifier enumerated (§4 step 3), its
   `callIndex` must be **exactly** the stem of one of that directory's `.json`
   files, and that file's `signature` member must be **the same string** as
   the cited one — all three compared as strings, never by asking the
   filesystem for the cited path, so a filesystem that folds case or
   normalizes names resolves nothing the enumeration does not → otherwise
   **`citation-unresolved`**. Nothing about the cited receipt's contents is
   read beyond its signature; whether it verifies is its own finding.
6. For each such action receipt, its `decision.recordDigest` must equal the
   SHA-256 of some **candidate** under the decision-record directory the
   verifier was given → otherwise **`decision-record-mismatch`**. The directory
   is walked recursively; symbolic links are not followed. Every regular file
   found is a candidate as its whole bytes. A file whose name ends in `.jsonl`
   additionally yields one candidate per line: the file's bytes are split on
   each `0x0A`; each piece has one trailing `0x0D` removed if present; an empty
   piece is not a candidate; the piece after the last `0x0A`, if non-empty, is
   a candidate. The verifier hashes candidates and compares; it interprets none
   of them. The directory's own outcomes follow §4.1's table: absent is an
   absent anchor, and every action receipt is then `decision-record-mismatch`;
   present and unreadable, in any of the forms the table lists, is no verdict.
   A verifier given no directory at all treats it as absent.
7. For each candidate step 6 enumerated — a regular file whole, or for a `.jsonl`
   file each line and **not** the file whole — that is one JSON object carrying a
   top-level `cites` member, the candidate is a **decision record that cites**, and
   each entry of `cites` must resolve exactly as step 5 resolves an action
   receipt's, by the same three string comparisons against the same enumeration →
   otherwise **`record-citation-unresolved`**. A `cites` member that is not an
   array of objects of the shape §1.2a gives `action.cites`, or that is given
   twice, → **`record-citation-malformed`**. Either is reported once per record, as
   `{recordDigest, status}` where `recordDigest` is `"sha256:"` + hex of the
   candidate's bytes, the same digest an action receipt would name it by. A
   candidate that is not one JSON object, or carries no `cites`, is not
   interpreted: the verifier reads a candidate for this member and for nothing
   else, and hashes it as before — a record's facts may carry what its writer
   chose, floats included, and the object is read as JSON for the one member
   while the member itself is held to the canonical domain. This is the join from
   the record's side; step 6 is the join from the action's side, and neither says
   the record cited the receipts the action did.

Steps 5 and 6 each report their finding once per action receipt, as
`{sessionId, callIndex, status}` with the action receipt's own session and
index, beside that receipt's `ok`; both may fire for one receipt, and they are
independent of each other and of every other finding. Step 7 reports once per
citing record, as `{recordDigest, status}`, independent of every other finding
and of whether any action receipt names that record.

`ok` is true only if the inline verify passed **and** no registry finding fired
**and** no citation, decision-record or record-citation finding fired.

The verifier must obtain the registry from the gateway (the key holder), **not** from
the untrusted store. That is the whole point: the anchor's authority comes from being
outside the store's reach and sealed under a key the store's holder does not have.

### 4.1 Absent and empty inputs

A verifier asked to check something that is partly not there still **produces a
verdict**; it does not refuse. Non-zero exit is reserved for being unable to reach
a verdict at all.

| Situation | Reading |
|---|---|
| `<root>` does not exist | zero sessions and no artifacts — judged against the registry like any other store, so every sealed session is `sealed-session-missing` |
| `<root>` exists but is not a directory | no verdict — the verifier refuses (non-zero exit); the evidence container is present and unreadable, not absent |
| `<root>/receipts` does not exist | zero sessions — every sealed session is then `sealed-session-missing` |
| `<root>/receipts` exists but is not a directory | no verdict — the verifier refuses (non-zero exit); the evidence is present and unreadable, not absent |
| `<root>/receipts` is a directory that cannot be read | no verdict — the verifier refuses (non-zero exit); the evidence is present and unreadable, not absent |
| the registry file does not exist | no seals load — every session in the store is then `unregistered-session` |
| the registry path exists but cannot be read, or any existing parent path component is not a directory, or the registry or a directory above it is a link that leads nowhere, or the path is spelled so that the platform could resolve it otherwise (below) | no verdict — the verifier refuses (non-zero exit); the anchor is present and unreadable, not absent |
| a session directory holding no receipts | a session with count 0, judged against its seal like any other |
| the decision-record directory (§4 step 6) does not exist, or the verifier was given none | absent — every version 3 action receipt that passed the ladder is `decision-record-mismatch`; an absent directory cannot make an action verify, it can only fail to excuse one |
| the decision-record path exists but is not a directory, or cannot be read, or any existing parent path component is not a directory, or it or a directory above it is a link that leads nowhere, or the path is spelled so that the platform could resolve it otherwise (below), or a directory or regular file under it cannot be read | no verdict — the verifier refuses (non-zero exit); the evidence is present and unreadable, not absent |

The registry and the decision-record directory are taken by their spelling, and a path the
platform could resolve to another file than the one its spelling names is refused before
anything is read — no verdict — and a gateway refuses to start on one, before it makes
anything:

- on every platform, a `..` after a named component: Linux and macOS step back from where that
  component leads, a link's target included, while a reading of the spelling steps back from
  the component;
- for the registry, which is a file, a path that ends in a separator;
- on Windows, a path in the `\\?\` or `\??\` namespace, which Windows takes literally, or in the
  `\\.\` namespace, which it reads as a device path; and a component — a UNC path's server and
  share included — that ends in a space or a period, which Windows trims, that holds a colon,
  which names a stream of a file, or that is a reserved device name (`CON`, `PRN`, `AUX`, `NUL`,
  `CONIN$`, `CONOUT$`, or `COM` or `LPT` with a digit), with or without an extension.

A leading `..`, a `.` component, a repeated separator and a trailing separator on the
decision-record directory name the same file either way, and are taken. The directories above
an input are the prefixes of its path as spelled, each cut before a separator. A name under the
decision-record directory that Windows would not read as spelled is a file under it that cannot
be read. Only an input the platform confirms is not there is absent: when a stat that follows
links finds nothing at a path, a look at the path itself must find nothing too, and any other
answer to that look — a link, or a failure — makes the input present and unreadable.

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
- Version 3's `caller` and `requester` record who asked, as a token verified at
  the gateway's boundary says; neither records that anyone **approved** anything,
  and an action receipt is lineage of a request and a response, never a statement
  that the action was right. Version 3's commitments close version 2's equality
  oracle for every party but the caller, who holds the salt, and open nothing
  to a party holding the store.
- The reference parses nothing nested deeper than **ten thousand levels** — the
  bound `encoding/json` applies on the way out — and refuses a deeper document as
  unparseable before it descends, so a source cannot make the gateway recurse
  through its whole output bound in brackets. A document inside the canon domain
  but past this bound is a divergence this reference accepts: no receipt, seal or
  argument the gateway produces comes near it.

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
- its chain holds: no `sequence-broken` or `chain-broken` finding names it;
- no decision record fails to cite: no `record-citation-unresolved` or
  `record-citation-malformed` finding fired **at all** (§4 step 7). A record
  finding names a record by `recordDigest` and no session, since one record may
  cite receipts of several sessions and a malformed one names none; a consumer
  scoped to a session therefore refuses on any record finding, whichever session
  it scopes to.

Session-scoping is a choice with a name, made deliberately in the consumer's code or
configuration. Silence means store-wide. The list above leans on an invariant of
this verifier's report: **every finding carries `status`; a receipt or session
finding carries `sessionId`, and a record finding carries `recordDigest` and no
`sessionId`.** A verifier extended with a finding that names no session must extend
this list with it, as step 7's is listed here, or the scoped check goes blind to it.

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
   *and* signature-checked under the pinned key (the coverage rule of §1.2 or
   §1.2a, according to the receipt's `receiptVersion`), or the
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
| POST   | `/acquire`  | `{session, source, arguments}` → runs the configured source, attests, chains, retains; returns `{result, receipt}` — `{result, receipt, salts}` for a version 3 receipt, below — where `receipt` is the complete receipt object of §1.2 — every member, `keyId` and `signature` included, the same object written under `receipts/<session>/<index>.json`. The response body is ordinary JSON, not the receipt's canonical form: a caller checking the signature canonicalizes the receipt per §1.1 first — a caller holding the binary has `gateway canon` for exactly that — and then applies the coverage rule of §1.2 or §1.2a according to the receipt's `receiptVersion`. No receipt is accepted from the caller. `session` must be a flat token (§3a) or the call is refused `400` before the source runs, and a sealed session is refused `400` before the source runs too — sealed by this gateway process, or, for a session this process does not hold in memory, sealed in the registry (§3) as §4 loads it: a seal whose `keyId` is the gateway's own and whose signature verifies under its public key, a missing or empty registry and any discarded line establishing no seal — so a seal stays final across a restart. For such a session, a registry that cannot be read (§4.1) is a refusal too, never taken for the absence of a seal; a session this process holds is judged by its own record of the seals it wrote, and a seal whose writing failed after the record may have reached the registry leaves that session sealed. |
| POST   | `/seal`     | `{session}` → seals the session's final count; returns the seal record. |

A gateway minting version 3 receipts answers `/acquire` with `{result, receipt,
salts}`: `salts` is an object with one member per commitment the receipt
carries, named by the commitment's label without its colon — `args` always, and
`statement` exactly when `acquisition.statement` is not `null` — each a 32-byte
salt in lowercase hex (§1.2a), returned here and nowhere else. Every `/acquire`
receipt is of kind
`"acquisition"`. `POST /act` mints one of kind `"action"` (the engine of
`docs/adr/0001-one-engine-four-processes.md`, described in
`docs/design/executor.md`): from an authenticated request naming a platform's
write tool, the decision record the write relies on and the receipts that
record relied on, after the engine has found the cited receipts in its own
store under its own key and the record under its decision-record directory —
the standard §4 applies, and no more. The format was specified before the
surface so that a verifier written then verifies what is minted now.
`gateway verify` takes `--decision-records <dir>` for §4 steps 5 and 6.
| GET    | `/verify`   | → `{ok, findings}` from `verify_with_registry`. |
| GET    | `/registry` | → the raw registry bytes, for a verifier to fetch the anchor from the key holder. |
| GET    | `/publickey`| → `{algorithm, keyId, publicKey, authority}`. Convenience only — a verifier that obtains the key here and then audits this same gateway has checked consistency, not authenticity (§5). |

A `source` is an operator-configured subprocess that reads the canonical arguments on
stdin and emits a JSON result on stdout. The gateway attaches no transport of its own
— it attests whatever bytes a configured source returns, which is exactly the inline
core's boundary: **proof of the bytes, not proof of their truth.**

### Adapter sources

`--source-shape NAME=airbyte|mcp|http` declares a configured source to be an adapter
of that shape (§1.2a). An adapter's stdout is not the result but an **envelope**: an
object whose members are exactly `acquisition`, `result` and, optionally, `page`.

- `result` is the value the gateway attests: `resultDigest` is over its canonical
  form, it is retained as the artifact, and it is what the acquire response returns
  as `result`.
- `acquisition` is an object whose members are exactly `adapter`, `endpoint`,
  `statement`, `snapshot`, `peerIdentity`, `schema`, `upstreamToken` and
  `observedAt`, each of the type and form §1.2a states for the receipt member of
  that name, except that `statement` is the statement text itself — the query,
  resource path or tool call — as a string, or `null`; `adapter` carries exactly
  `name`, `version` and `digest`; and `observedAt` is of the form
  `YYYY-MM-DDThh:mm:ssZ` — UTC, whole seconds, the form `servedAt` takes — which
  is what this gateway accepts from an adapter, beyond the string a verifier
  checks for. It carries neither `shape` nor `pageItems`. (A
  verifier tolerates a member it does not know at any depth, since a signed one is
  the signer's own; the signer, reading an envelope, tolerates nothing it did not
  ask for.)
- `page`, when present, is `true`, and `result` is then an array of items: the
  receipt carries `pageItems`, the digest of each item's canonical form, in order.

The gateway refuses an envelope that departs from this in any way — not an object,
a member missing or unlisted at either level, a member of another type or form,
`page` other than `true`, a page whose result is not an array — and the acquisition
fails with nothing minted and nothing retained. An adapter source requires version 3
receipts: a gateway asked for `--receipt-version 2` refuses to start with one
declared, and refuses the acquisition if one is configured in process. The envelope
keeps the contract of one request and one result: what an adapter reports rides
inside the result it was always allowed to write, and the gateway, not the adapter,
decides what of it is signed.

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

One question this specification does not settle, surfaced by building the
corpus and recorded in [`corpus/README.md`](corpus/README.md): the order of
findings, which is why they are compared as a multiset. The other question that
record raised — whether a receipt that fails verification is *required* to also
produce the `sequence-broken` that follows from its exclusion from the chain
reconstruction — is settled by §1.4: it is, and the vectors expect it.

The vectors are signed under a published test seed (`corpus/TEST-SEED`), which signs
nothing real and must never be used by a deployment. Verification consumes only
`corpus/TEST-PUBLIC-KEY` — running the corpus never hands the runner a secret,
which is the same property receipt version 2 gives a real verifier.

The version 3 store vectors live under `corpus/v3/stores/`. They are written
against §1.2a and §4 and are as frozen as the rest; `gateway conform` reads
both directories (`corpus/README.md`). A version 3 store vector may carry a
`decisionRecords` map beside `files`, materialized as the directory §4 step 6
names and handed to the implementation as the process contract's optional
fourth argument.
