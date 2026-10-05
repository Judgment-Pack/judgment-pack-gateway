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

**It is normative too for the witness statement (§8), version 1:** a record of another
kind, which a gateway run by a party other than a decision trail's operator signs over the
runtime's audit checkpoints. It is not a receipt, nothing in §1 to §7 changes for it, and
no receipt verifier reads one.

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
  `statement`, `schema`, `recordDigest`, `packDigest`, `request`, `policy`, and
  each element of `pageItems` are digests;
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
| `decision` | `{ "recordDigest": "sha256:" + hex, "packDigest": "sha256:" + hex, "recordBytes": "exact" }`, `recordBytes` **optional** | the decision record the requester says the action relies on, and the pack it says the decision was made under, by digest; `recordBytes`, how the gateway found the record (below) |
| `cites` | array of `{ "sessionId": flat token (§3a), "callIndex": non-negative integer, "signature": signature }` | the acquisition receipts the requester says the decision record relied on |
| `policy` | `"sha256:" + hex` — **optional** | the decision policy the gateway held the action to before it was sent, by digest (below); absent when its operator held the tool to none |
| `tool` | `{ "shape": string, "endpoint": string or `null`, "name": string }` | what was called, named as `acquisition` names its adapter |
| `request` | `"sha256:" + hex` | a commitment (above) to the request the executor sent |
| `adapter` | as in `acquisition` | the executor that performed it |
| `observedAt` | string | when the target answered |

**`decision.recordBytes`.** Present, it is the string `"exact"`: the gateway found
the record named by its **exact bytes** — a line of a `.jsonl` file taken as all
its bytes before its `0x0A`, a `0x0D` among them — and §4 finds it the same way
(step 6). The gateway sets it on an action through a tool whose decision policy
requires a signed record, since the digest a signature binds is of the bytes the
runtime wrote, and a line converted to CRLF is other bytes
(`docs/adr/0012-hold-a-write-to-a-signed-record.md`). Absent, the record is found
by step 6's reading, one trailing `0x0D` removed from a line, as before. It is
signed with every other member, so a reader cannot choose the reading after the
fact. A verifier written before the member tolerates it, as it tolerates any
signed member it does not know, and finds the record by step 6's reading: it can
answer `ok` for a record converted to CRLF that a verifier reading the member
reports `decision-record-mismatch` for.

`decision.packDigest` and `cites` are claims the requester supplied, recorded as
given. §4 checks that the cited receipts exist and that a decision record with
the stated digest exists (steps 5 and 6); when that record is a runtime
evaluation record, it compares the record's pack digest and citations with these
two (step 8), and reads nothing else of it. A decision record that itself
carries a `cites` member of this same shape — a record the runtime wrote with
the citations its caller gave it — has those resolved by §4 step 7 on the
record's own behalf. An action receipt does not say the action was right, and it
does not say the identity approved it: it is lineage of a request and a
response.

**What `decision` establishes.** Without `policy`, an action receipt
establishes no more than this: the gateway that minted it found a decision
record with the digest `decision.recordDigest` under its decision-record
directory, and the cited receipts in its store under its key, before the action
was sent (§6); §4 establishes both again against the store and the records it
is given, and step 8 that a runtime evaluation record states the pack and the
citations the receipt claims. It does not establish that the record permitted
the action, that the record's outcome is the one the action assumes, that the
record's inputs describe the object the action wrote, or that the target was
unchanged since the record was made. With `policy`, it establishes
in addition exactly the checks that policy names (below), as the gateway made
them before the action was sent, and no more. Those are checks of a record
found under the decision-record directory, and a record is found there by its
shape: unless the policy sets `requireSignedRecord`, they hold the action to
whatever record a writer of that directory put there, written by hand or not.
A gateway started from a configuration refuses to start while anyone but root,
its signer and the directory's owner could write a file into or beneath that
directory, or replace a directory on the way to it, as the owners and the
permission bits show then (`docs/design/engine-config.md`); that narrows who
such a writer can be when it starts, and holds nothing after.
With `requireSignedRecord`, the record was also signed, in its exact bytes, by
whoever holds one of the runtime keys the policy names, so a writer who cannot
use one of those keys cannot write a record the policy admits; it establishes
nothing against the holder of a named key, the operator among them, who can
sign any record. Nothing in a receipt closes the
interval between those checks and the target's commit: a precondition on the
target — a revision or an ETag compared on write — is the only thing that does,
and it is the target's, or its adapter's, to supply. A policy's `bind` stops an
action on another object than the one decided; it does not stop a concurrent
edit of that object.

**`policy`.** The gateway's operator may hold a write tool to a **decision
policy** in the gateway's configuration (`docs/design/engine-config.md`,
`docs/adr/0011-hold-a-write-to-its-decision.md`): an object whose members are
`outcomes`, the outcome ids a record may have decided, and optionally `packs`,
the pack digests it may have been decided under, `reviewed`, whether it must
carry `"reviewed": true`, `bind`, pairs of JSON pointers (RFC 6901), one
into the request's arguments and one into the record's `inputs.facts`, whose
values must be equal, and `requireSignedRecord`, the Ed25519 public keys of the
runtimes whose signature of the record it requires
(`docs/adr/0012-hold-a-write-to-a-signed-record.md`). Before an action through
such a tool is sent, the gateway requires the decision record to be a runtime
evaluation record (§4 step 8); when `requireSignedRecord` is given, and before
any other check of the record, a readable line of the runtime's signature
sidecar — `signatures.jsonl` in the directory of a file the record was found in
— signing the record's `trail`, its `sequence` and `decision.recordDigest`
under one of those keys, by the runtime's record-signature rule, with no
key-rotation line followed, the record then found by its exact bytes and the
receipt saying so in `decision.recordBytes` (above); its `pack.digest` to be
`decision.packDigest`, and
its citations to be `cites` as a
set; its `disposition` to be of kind `"outcome"`, its `outcomeId` among
`outcomes`, and its `handoff.state` `"none"`; its `pack.digest` to be among
`packs` when they are given; its `reviewed` to be `true` when `reviewed` is
`true`; and, for each pair of `bind`, both pointers to resolve and the two
values to have the same canonical form (§1.1) — a value outside the canonical
domain equals none. It refuses the request otherwise, with nothing sent and
nothing minted. `reviewed` holds the record to whatever reviewed-set lock was
current when it was written, not to particular bytes: a pack that is edited and
locked again yields records with `"reviewed": true` and a new pack digest, which
a policy without `packs` admits. `packs` is what holds a write to particular
reviewed packs. `policy` is then `"sha256:"` + hex of SHA-256 over `canon` of
the policy object as configured (§1.1) — for this object its RFC 8785 form too,
since its member names are the fixed ASCII names above and it holds no number.
The receipt carries the policy's digest and never the policy. A verifier checks
the member's form and nothing else: it holds no configuration to recompute the
digest against.

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
failure in this order. (§4 steps 5, 6 and 8 add findings of their own to a
version 3 action receipt that passed the ladder, beside its `ok`; those are not
statuses of the ladder and do not replace it.)

| Order | Status | Condition |
|---|---|---|
| 1 | `malformed` | unparseable, duplicate member names, missing `signature`, `callIndex` not an integer, `resultDigest` not of the stated form, or `signature` not hex; for version 3, **any** violation of a structural constraint §1.2a states — a member required absent, a member of another type than stated, a nullable member neither `null` nor of its stated shape, `kind` or `shape` outside its enumeration, the object for the kind missing or its sibling present, a digest or a signature not of its stated form, `pageItems` present and not an array of digests, `requester` `null`, `cites` not an array of objects of the stated shape, `policy` present and not a digest, `decision.recordBytes` present and not `"exact"` — and never a relational one |
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
backward to excuse a rollback. A session is already sealed when the registry holds a seal for
it that §4 step 2 loads — a JSON object whose `keyId` is the gateway's own and whose signature
verifies under its public key — and a line that names the session and is no such seal (a
signature that does not verify, a foreign `keyId`, a member missing) establishes no seal for
`/seal` either, as it establishes none for `/acquire` (§6): the gateway appends the new seal
beside that line, which stays where it is, and answers `200` with the seal record, and §4
step 2 loads the new seal, since it is the session's first seal that loads.

A gateway makes its registry, empty, when it starts without one — only where nothing is, never
through a link, and only for a store with no history — so that from then on the registry's
absence is never an empty registry to it. No lookup can prove an absence (§4.1): a device or a
network share that has gone away can answer as a missing file does. So once the gateway has
started, a registry that is not there is one it cannot read: an acquisition into a session it
does not hold (§6), a seal, `/registry` and `/verify` refuse it. A store that holds a session
has run before, and its registry may hold that session's seal, so a gateway whose store holds a
session and whose registry is not there refuses to start: the registry is to be restored, or,
by an operator who knows no session was ever sealed, made empty by hand. What remains cannot be
told apart: a registry and a session history lost or hidden together — a mount that is not
there yet, holding both — look like a fresh installation, and the gateway makes a fresh registry
for it.

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
   a candidate. For an action receipt whose `decision.recordBytes` is
   `"exact"`, the record is looked for under the **exact reading** instead: a
   `.jsonl` file's pieces are taken as they are, no `0x0D` removed, an empty
   piece again no candidate; every other candidate is the same under both
   readings. Each receipt is held to the reading it names, whatever reading
   another receipt over the same directory names. The verifier hashes
   candidates and compares; it interprets none of them. The directory's own outcomes follow §4.1's table: absent is an
   absent anchor, and every action receipt is then `decision-record-mismatch`;
   present and unreadable, in any of the forms the table lists, is no verdict.
   A verifier given no directory at all treats it as absent.
7. For each candidate step 6 enumerated under its first reading, one trailing
   `0x0D` removed — a regular file whole, or for a `.jsonl` file each line and
   **not** the file whole — that is one JSON object carrying a
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
   the record cited the receipts the action did; step 8 compares the two, for a
   record it understands.
8. For each such action receipt whose decision record step 6 found, the record —
   the candidate whose bytes hash to `decision.recordDigest`, a regular file
   whole or a line of a `.jsonl` file under the reading the receipt names (step
   6), never a `.jsonl` file whole — is compared
   with what the receipt claims of it when it is a **runtime evaluation record**:
   one JSON object — read as §1.1 reads a document, a member name given twice at
   any depth, a string that is not UTF-8 or that escapes a surrogate not one of a
   pair, and nesting past §5's bound each making it none, except that a number
   may take any form RFC 8259 gives one — whose `recordVersion` is the string
   `"1"`, whose `kind` is the string `"evaluation"`, and whose `pack` is an
   object whose `digest` is a digest (§1.2a). That is the record the
   judgment-pack runtime's audit trail writes of one pack evaluated on one facts
   document. Of such a record:
   - its `pack.digest` must be the receipt's `decision.packDigest` → otherwise
     **`decision-pack-mismatch`**;
   - its citations must be the receipt's `cites` as a set — each citation the
     triple of its `sessionId`, `callIndex` and `signature`, order and repetition
     aside — where a record with no `cites` member has none, and one whose `cites`
     is not an array of objects of the shape §1.2a gives `action.cites`, its
     members held to the canonical domain, matches no set → otherwise
     **`decision-cites-mismatch`**.

   A record step 6 found that is not a runtime evaluation record — not one JSON
   object, of another `recordVersion`, a graph composite, one without a pack
   digest, a `.jsonl` file whole, an opaque file — is not compared, and nothing
   is found of it: the report carries the **observation**
   `decision-record-not-compared` for the receipt (below). The verifier reads a
   record for these members and for nothing else.

Steps 5, 6 and 8 each report once per action receipt, as `{sessionId,
callIndex, status}` with the action receipt's own session and index, beside that
receipt's `ok`; any of them may fire for one receipt, step 8 both of its
findings, and each is independent of the others and of every other finding.
Step 7 reports once per citing record, as `{recordDigest, status}`, independent
of every other finding and of whether any action receipt names that record.

**Observations.** A report carries, beside `ok` and `findings`, a member
`observations` when there is anything the verifier says of a receipt without
failing it: an array of `{sessionId, callIndex, observation}`, with the
receipt's own session and index. The one observation this document names is
step 8's `decision-record-not-compared`. An observation is not a finding: it
never makes `ok` false, a consumer's verdict (§5a) does not read it, and a
report with none may leave the member out.

`ok` is true only if the inline verify passed **and** no registry finding fired
**and** no citation, decision-record, decision-pack, decision-cites or
record-citation finding fired.

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
| `<root>` is a directory that cannot be read | no verdict — the verifier refuses (non-zero exit); the evidence container is present and unreadable, not absent |
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
- for the registry, which is a file, an empty path or a path that ends in a separator;
- on Windows, a path in the `\\?\` or `\??\` namespace, which Windows takes literally, or in the
  `\\.\` namespace, which it reads as a device path; and a component — a UNC path's server and
  share included — that ends in a space or a period, which Windows trims, that holds a colon,
  which names a stream of a file, or that is a reserved device name (`CON`, `PRN`, `AUX`, `NUL`,
  `CONIN$`, `CONOUT$`, or `COM` or `LPT` followed by one of `0`–`9`, `¹`, `²`, `³`), with or
  without an extension.

A leading `..`, a `.` component and a repeated separator name the same file either way, and
are taken. A trailing separator on the decision-record directory is taken too; the walk below it
then follows a link at its last component, as the platform does, where without the separator the
walk stops at the link. The directories above an input are the prefixes of its path as spelled,
each cut before a separator. A name under the decision-record directory that Windows would not
read as spelled is a file under it that cannot be read.

For the registry and the decision-record directory, only an input the platform confirms is not
there is absent. The confirmation is the plain answer for a missing name in a directory the
walk has reached: `ENOENT`, or on Windows `ERROR_FILE_NOT_FOUND` — not `ERROR_PATH_NOT_FOUND`
or `ERROR_BAD_NETPATH`, which say a directory, a drive or a network share on the way cannot be
reached, and make an input under it present and unreadable. An input under a directory
confirmed missing is absent, and nothing below that directory is looked at. When a stat that
follows links finds nothing at a path, a look at the path itself must find nothing too, and any
other answer to that look — a link, or a failure — makes the input present and unreadable.

That confirmation concerns the namespace the filesystem shows, and no lookup proves more: a
device that has gone away can answer as a missing name does (Windows before 10 1909), and a
mount that is missing shows the empty directory beneath it. To a verifier an absent registry
fails closed every session the store still holds — each is `unregistered-session` — but a
registry and a session history lost or hidden together look like a genuinely empty store against
an empty registry, which verifies, and no classifier can tell the two apart: that takes an
expectation from outside what is read. To the gateway an absent registry could reopen a sealed
session, so the gateway makes its registry at start and takes any later absence for a registry
it cannot read (§3). It reads the registry through this classifier
before it seals into it; started from a configuration, it judges the registry and the
decision-record directory through it before it starts.

Each of these fails **closed** for what is still there: an absent anchor cannot make a
store's sessions verify, it can only fail to excuse them. A store that is genuinely empty
against an empty registry verifies, because there is nothing it contradicts — and so does a
store whose sessions were lost with its registry, which reads the same (above).

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
| POST   | `/acquire`  | `{session, source, arguments}` → runs the configured source, attests, chains, retains; returns `{result, receipt}` — `{result, receipt, salts}` for a version 3 receipt, below — where `receipt` is the complete receipt object of §1.2 — every member, `keyId` and `signature` included, the same object written under `receipts/<session>/<index>.json`. The response body is ordinary JSON, not the receipt's canonical form: a caller checking the signature canonicalizes the receipt per §1.1 first — a caller holding the binary has `gateway canon` for exactly that — and then applies the coverage rule of §1.2 or §1.2a according to the receipt's `receiptVersion`. No receipt is accepted from the caller. `session` must be a flat token (§3a) or the call is refused `400` before the source runs, and a sealed session is refused `400` before the source runs too — sealed by this gateway process, or, for a session this process does not hold in memory, sealed in the registry (§3) as §4 loads it: a seal whose `keyId` is the gateway's own and whose signature verifies under its public key, an empty registry and any discarded line establishing no seal — so a seal stays final across a restart. For such a session, a registry that cannot be read (§4.1) is a refusal too, never taken for the absence of a seal — and so is a registry that is not there, since the gateway made it when it started (§3); a session this process holds is judged by its own record of the seals it wrote, and a seal whose writing failed after the record may have reached the registry leaves that session sealed. |
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
the standard §4 applies — and, for a tool its operator holds to a decision
policy, after it has held the record and the request to that policy (§1.2a
`policy`). The format was specified before the surface so that a verifier
written then verifies what is minted now. `gateway verify` takes
`--decision-records <dir>` for §4 steps 5 to 8.
| GET    | `/verify`   | → `{ok, findings}` from `verify_with_registry`, and `observations` when §4 step 8 has any, against the registry the gateway made when it started (§3): a registry that is not there is no verdict here, never the absent registry of §4.1 that loads no seals. |
| GET    | `/registry` | → the raw registry bytes, for a verifier to fetch the anchor from the key holder. A registry that cannot be read (§4.1), or that is not there — the gateway made it when it started (§3) — is answered `500`, never as the empty body a verifier reads as no seals. |
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

### Witness endpoints

A gateway that is a witness (§8) answers three more endpoints. They are specified with the
statement, so that a deliverer and a reader can be written to them before the service is:
this reference does not serve them yet, and the configuration that makes a gateway a
witness comes with the service.

| Method | Path | Body / result |
|--------|------|---------------|
| POST | `/witness/checkpoints` | Submit. The body is `application/jsonl`: one or more checkpoint lines (§8.1) as `jpack audit checkpoint --since` prints them, each in its canonical form and ended by a newline, all of one trail, their sequences strictly increasing; at most 1 MiB (1048576 bytes), this gateway's request bound, and each line at most 4096 bytes, its newline not counted. A bearer token is required, and the trail must be registered to the token's issuer and subject (below). **Only the last line is signed**: the earlier lines are compared with what the witness holds, for conflicts, and otherwise discarded, and with them the evidence of what they said. `200`, `application/jsonl`: a `checkpoint` statement for the last line — the one already held for the same trail, sequence and digest, so that sending a checkpoint again gives the same statement, or a new one at the chain's next index. `409` with `reason` `"conflict"` and `statements`, two JSON strings each holding a statement's exact line: the `checkpoint` statement the witness holds at a line's sequence, and the `conflict` statement recording another digest offered for it — the first offered for that sequence, which acknowledges nothing of the digest just sent. `409` with `reason` `"below-head"`, with the head statement, when the last line's sequence is below the latest checkpoint statement's and not held. `409` with `reason` `"retired"`, with the retirement statement. `400` for a body out of shape, `401` without a valid token, `403` for a trail not registered or registered to another subject, `413` over a bound, and `429` over the submitter's rate or, for a trail it has not submitted before, over its number of trails. `503` when a statement signed could not be kept, after which the witness signs nothing more, for any trail, until it has restarted. |
| GET | `/witness/trails/{trail}/head` | The trail's last statement (§8.5), `application/jsonl`, exactly as the witness keeps it. `400` for a `{trail}` that is not 32 lowercase hexadecimal characters; `404` for a trail the witness holds nothing for, which reads as a trail never submitted (§8.8). |
| GET | `/witness/trails/{trail}/statements?from=<index>&limit=<n>` | The trail's statements from index `from` (0 when absent), at most `limit` of them (1 to 1000, 1000 when absent), in index order, `application/jsonl`, each exactly as the witness keeps it. A reader asks again from the next index until it reaches the head's. |

**Registration.** A trail is registered to exactly one issuer and subject before anything
is signed for it: by the witness's operator, by default, or, where that operator opts in,
by the first submission accepted for the trail — which lets any subject the witness allows
claim a trail whose identity it has learned. A registration is never in a statement and is
never served. A token establishes an issuer and a subject and nothing more: every deliverer
of one trail submits under the one subject registered for it, and the witness cannot tell
the trail's operator from a holder of the operator's credential (§8.8).

**Rate.** The witness's operator bounds each submitter's submissions, from 1 to 6000 a
minute, 60 by default, and the trails it may submit for, from 1 to 100000, 100 by default.

**Reads are open.** The two reads need no token, as `/registry` and `/publickey` need none:
a verifier holds no token. Naming a trail is what lets one read it, and no endpoint lists
trails; whoever holds one of a trail's checkpoints can therefore follow its continuing
activity (§8.8). The reference bounds no read. A witness reached from other hosts sits
behind the TLS-terminating front `docs/design/engine-config.md` requires for any other
host, and that front bounds reads.

## 7. Conformance

An implementation of this specification is checked against the frozen vectors in
[`corpus/`](corpus/README.md), never against another implementation's source. The
corpus is **frozen**: hand-maintained normative data, not output regenerated from
whichever implementation exists. Changing a vector is a specification change and
needs the same justification as changing this document. Three families:
**canon vectors** (a value → its exact canonical bytes, or a refusal); **store
vectors** (a complete store and registry → the expected `(ok, findings)`), with one
store vector per status this document names; and **witness vectors** (a trail, keys
and witness statements → a refusal or a reading, §8.6), with one vector or more per
refusal and finding §8 names.

`gateway conform` runs them, and `--impl CMD` drives any other implementation
through a small process contract, so an implementation in any language can answer
to the corpus without depending on this one. Findings are compared as a multiset: **order is not normative.** Observations (§4) are not compared.

One question this specification does not settle, surfaced by building the
corpus and recorded in [`corpus/README.md`](corpus/README.md): the order of
findings, which is why they are compared as a multiset. The other question that
record raised — whether a receipt that fails verification is *required* to also
produce the `sequence-broken` that follows from its exclusion from the chain
reconstruction — is settled by §1.4: it is, and the vectors expect it.

The vectors are signed under a published test seed (`corpus/TEST-SEED`), which signs
nothing real and must never be used by a deployment; a witness statement is signed under
it too, since a witness signs with the gateway's seed (§8.3). Verification consumes only
public keys — `corpus/TEST-PUBLIC-KEY`, and the keys a witness vector supplies — so
running the corpus never hands the runner a secret, which is the same property receipt
version 2 gives a real verifier.

The version 3 store vectors live under `corpus/v3/stores/`. They are written
against §1.2a and §4 and are as frozen as the rest; `gateway conform` reads
both directories (`corpus/README.md`). A version 3 store vector may carry a
`decisionRecords` map beside `files`, materialized as the directory §4 step 6
names and handed to the implementation as the process contract's optional
fourth argument.

The witness vectors live under `corpus/witness/`, each a reading of §8.6: the trail being
verified, the keys supplied, statements files and a head file, and the answer expected — a
refusal by its reason, or findings compared as a set of names, and, for a reading with
none, what §8.6 says it reports. `gateway conform` reads them, and drives any other
implementation through the process contract's `witness` command (`corpus/README.md`). The
runner refuses a corpus holding an entry it does not read and a vector of a family it does
not know, so no family of vectors lands in the corpus unread.

Beside them, `corpus/witness-recovery/` holds a witness's own storage: its log, marks and
registrations, and what its start-up checks, its repair and its writer must do with them,
by `docs/adr/0013-checkpoint-witness.md` §4. No reader reads that storage, so these vectors
are not in the process contract: `gateway conform` runs them against this reference's
witness, and under `--impl` reads them and holds them to their form and their counts
without running them.

## 8. The checkpoint witness

A **witness** is a gateway, run by a party other than a decision trail's operator, that
signs the judgment-pack runtime's audit checkpoints and serves what it signed to any
verifier who names the trail (`docs/adr/0013-checkpoint-witness.md`). What it signs is a
**witness statement**: a record of its own beside the seal (§3), not a receipt, under a
prefix of its own. Nothing a statement adds changes what a receipt, a seal or a registry
means, and no receipt verifier reads a statement.

What makes a gateway a witness is who holds its key, not its software. A gateway whose
key the trail's operator can use is no witness against that operator, and nothing in a
statement can show independence: the witness cannot know who runs it. A verifier decides
which witness keys it trusts, as it decides which time-stamping roots it trusts.

This section is normative for statement version 1: the checkpoint it covers (§8.1), its
members (§8.2), what its signature covers (§8.3), the key rule and the one equation a
reader holds a witness key and a signature to (§8.4), how statements chain per trail
(§8.5), how a reader reads a chain (§8.6) and within what bounds (§8.7), and what a
statement establishes (§8.8). The vectors under `corpus/witness/` hold each of these (§7).
The format and the reading are specified before the service, so that a reader written now
reads what a witness serves later. A witness's own storage — its log, its marks, its
registrations, the order in which it signs, keeps and publishes a statement, the checks it
makes before it starts and the repair they allow — is the witness's, not a reader's, and
is not specified here: `docs/adr/0013-checkpoint-witness.md` §4 states it, and this
reference keeps it in its core, held to the vectors under `corpus/witness-recovery/`
(§7). `gateway witness verify --log <file> --public-key <file> [--marks <file>]` applies
those checks, all but the registrations, to a copy of a witness's log, and gives its
verdict in its JSON as `gateway verify` does (§5a.2): exit `0` whenever it reached one.
The service that answers submissions and serves statements — the endpoints of §6 and the
configuration that makes a gateway a witness — follows in a later release. Until then
this reference serves no statement, and no command of it signs one.

### 8.1 The witnessed checkpoint

The witness signs a checkpoint as `jpack audit checkpoint` prints it, carried as an object
of exactly four members, each once:

| Member | Form |
|---|---|
| `checkpointVersion` | the string `"1"` |
| `trail` | 32 lowercase hexadecimal characters: the trail's identity |
| `sequence` | an integer from 1 to 2⁵³−2: the record's line number in the trail |
| `recordDigest` | a digest (§1.2a): the SHA-256 of the record line's exact bytes, without its newline |

Its canonical form (§1.1) is the checkpoint line without its newline, byte for byte: the
member names are ASCII and already in code-point order, and the values are hex strings, a
fixed string and an integer below 2⁵³, so the canonical form is also the RFC 8785 form the
runtime prints. The bytes inside a statement's signing input are therefore the bytes a
holder's checkpoint file holds, and their SHA-256 is what a time stamp of the checkpoint
imprints. A witness accepts a submitted checkpoint line only in that form and never
re-encodes one. A verifier holding the trail recomputes the checkpoint for a sequence N
from the trail's line N: the SHA-256 of its exact bytes, without the newline, is
`recordDigest`, and its `trail` member is `trail`.

### 8.2 The statement

Every member is required, and the set is closed: a statement with a member not listed
here is malformed, because a new member is a new `witnessVersion`. (A receipt verifier
tolerates a member it does not know; a statement reader refuses one, so that a reader
unaware of a new version refuses rather than skips.)

| Member | Form | Meaning |
|---|---|---|
| `witnessVersion` | the string `"1"` | this format |
| `kind` | `"checkpoint"`, `"conflict"` or `"retirement"` | §8.5 |
| `checkpoint` | the object of §8.1 | for `"checkpoint"`, the checkpoint witnessed; for `"conflict"`, a checkpoint offered and refused; for `"retirement"`, the trail's latest witnessed checkpoint, repeated |
| `index` | an integer from 0 to 2⁵³−2 | this statement's place in the witness's chain for `checkpoint.trail` |
| `prevSignature` | `null`, or 128 lowercase hexadecimal characters | the `signature` of the statement at `index` − 1 for the same trail; `null` at index 0 (§8.5) |
| `witnessedAt` | `YYYY-MM-DDThh:mm:ssZ`, a digit where each letter but `T` and `Z` stands: UTC, whole seconds, the form `servedAt` takes (§6) | the witness's clock when it signed |
| `keyId` | 32 lowercase hexadecimal characters, derived as §1.2 derives it | the witness's key |
| `signature` | 128 lowercase hexadecimal characters, the 64 bytes of an Ed25519 signature | §8.3 |

A statement is read by its JSON value, under §1.1's grammar: whitespace, the order of
members and the escapes in a string are its spelling, not the statement, and a member name
given twice, a string that is not UTF-8 or a lone surrogate make it malformed. Each form is
held on the value read. An integer is spelled in digits alone, with no sign, fraction or
exponent — `-0`, `1.0` and `1e0` are not integers here, as they are not in a checkpoint's
`sequence` when the runtime reads one — and a string is held to its form as its escapes
decode. Two statements with the same canonical bytes are one statement.

`witnessedAt` is held to its form and to nothing else: a reader compares it with no clock
and with no other statement's. A witness never states a time earlier than the previous
statement's for the trail — it takes the later of its clock and that time — and that is the
witness's rule, which a reader does not check.

A statement at index 7 and sequence 120, its hexadecimal elided, as a witness serves it:

```
{"checkpoint":{"checkpointVersion":"1","recordDigest":"sha256:…","sequence":120,"trail":"…"},"index":7,"keyId":"…","kind":"checkpoint","prevSignature":"…","signature":"…","witnessVersion":"1","witnessedAt":"2026-10-04T12:00:00Z"}
```

With its hexadecimal in full it is 608 bytes. A witness serves every statement as one line,
its canonical form, ended by a newline.

### 8.3 What the signature covers

`signature` = Ed25519, under the gateway's signing seed (§5) — the seed that signs its
receipts and seals, so a statement's `keyId` is the gateway's own — over
`"judgment-pack-gateway/witness/1:"` followed by `canon` of the statement with **its
top-level `signature` member removed and every other member retained**, the nested
`checkpoint` included. That is §1.2's rule: appending anything anywhere invalidates the
signature. The prefix is neither the receipt's nor the seal's, so none of the three can be
replayed as another. A party that wants the witness's role apart from its receipts runs a
second gateway with a seed of its own.

Every value of a statement that reads (§8.2) is an ASCII string, an integer below 2⁵³ or
`null`, so the signed bytes are exactly

```
judgment-pack-gateway/witness/1:{"checkpoint":{"checkpointVersion":"1","recordDigest":"<recordDigest>","sequence":<sequence>,"trail":"<trail>"},"index":<index>,"keyId":"<keyId>","kind":"<kind>","prevSignature":<null, or "<prevSignature>">,"witnessVersion":"1","witnessedAt":"<witnessedAt>"}
```

built from the values read, each integer in decimal digits. That is also their RFC 8785
form, so a reader without this gateway's `canon`, such as the runtime, builds them so.

### 8.4 The key rule and the equation

A reader never takes a witness key from a statement. It is given the keys it trusts, out
of band (§5), and holds each to the runtime's public-key rule before it reads anything
signed. 32 bytes are a key a reader may trust exactly when they are the canonical encoding
(RFC 8032 §5.1.2) of a point of the curve whose order does not divide 8. The encoding is
read as written, before anything reduces it: `y` is its low 255 bits, little-endian, and
its top bit is the sign of `x`. A key is refused when, taken in this order:

1. **it is not canonical** (`key-not-canonical`): `y` is p = 2²⁵⁵ − 19 or more, or `x` is 0
   (`y` is 1 or p − 1) and the sign bit is set. A lenient decoder, Go's `crypto/ed25519`
   among them, reads such an encoding as another key: `y` = p as `y` = 0, the all-zero key;
2. **it is of small order** (`key-small-order`): it is one of the eight points whose order
   divides 8, by their canonical encodings — every other encoding of them is refused by 1:

   ```
   0100000000000000000000000000000000000000000000000000000000000000
   ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f
   0000000000000000000000000000000000000000000000000000000000000000
   0000000000000000000000000000000000000000000000000000000000000080
   26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05
   26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85
   c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a
   c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa
   ```

   Under such a key a signature can be made without a private key — for most messages, `R`
   a point of small order and `S` zero verify — and the all-zero key, a plausible
   placeholder, is one;
3. **it is no point** (`key-not-on-curve`): (`y`² − 1) / (d·`y`² + 1) has no square root
   modulo p, so nothing verifies under it.

A key of mixed order — a point of prime order plus one of small order — is not refused,
since its order does not divide 8, and no key a seed derives is refused. This is the rule
the runtime's guide writes down ("Record signatures, exactly") and holds every public key
it reads to, and the rule `requireSignedRecord` holds a runtime key to here (§1.2a).

A signature is 64 bytes: `R`, the first 32, and `S`, the last 32 read as a little-endian
integer. It verifies under a key's 32 bytes `A` over the signed bytes `M` (§8.3) exactly
when `S` is below L = 2²⁵² + 27742317777372353535851937790883648493 and the canonical
encoding of [`S`]B − [h]A is `R`, byte for byte, B being the base point and h the SHA-512
of `R` ‖ `A` ‖ `M` read as a little-endian integer and reduced modulo L. That is RFC 8032's
check without the cofactor and with a canonical scalar, as Go's `crypto/ed25519` verifies.
The cofactored check RFC 8032 §5.1.7 also allows, [8][`S`]B = [8]`R` + [8][h]A, accepts
more — an `R` with a part of small order, and, under a key of mixed order, a signature that
holds only up to that part — and is not used. `R` is not otherwise decoded: an encoding of
it that is not canonical never verifies, and one of a point of small order verifies when
the equation holds.

### 8.5 The chain

A witness keeps one chain of statements per trail. Along it:

- `index` runs from 0 with no gap, and each statement's `prevSignature` is the `signature`
  of the statement before it, `null` at index 0. The last statement therefore commits to
  every one before it, and a witness that drops, reorders or alters a statement it served
  breaks the chain for anyone who holds a later one.
- The sequences of its `checkpoint` statements strictly increase. Its **latest witnessed
  checkpoint** is its last `checkpoint` statement, and coverage is always stated by that
  one: a `conflict` at sequence 100 after a checkpoint at 200 does not move coverage back
  to 100.
- A **`conflict`** statement records that a submitter the witness allowed for the trail
  offered another `recordDigest` for a sequence at which the witness holds a `checkpoint`
  statement. The first such offer is the evidence, and there is at most one per sequence.
  Since a witness holds only sequences it signed, a conflict's sequence is at or below the
  latest `checkpoint` statement's before it, and that is what a reader checks of it. That
  the sequence was held, and that no sequence has two conflicts, are the witness's rules,
  which a reader does not check.
- A **`retirement`** statement is the last of its chain: the witness accepts nothing more
  for the trail, and keeps and serves the chain as before. Its `checkpoint` repeats the
  latest witnessed checkpoint, all four members, so it names the trail and pins where the
  chain ended; a chain with no `checkpoint` statement has nothing to retire.
- The witness's **head** for a trail is the chain's last statement, of any kind.

A witness cannot check that a checkpoint extends the one before it: that needs the
records, which it never sees. A rewrite of a trail from sequence k on is caught by holding
the trail to an **earlier** statement whose sequence is k or above, which the rewritten
trail no longer matches — even when a later checkpoint of the rewritten trail was signed.
Whoever presents a chain can leave that statement out, so a chain is read from its first
statement and never late (§8.6), and the head, fetched from the witness, says how far the
chain reaches. The witness serves the latest statement it holds as the end of the chain,
not in place of it.

### 8.6 Reading a chain

A reading takes the identity of the trail being verified — for a reader holding the trail,
the `trail` its chained records carry; the witness keys the reader trusts, in an order; the
statements supplied, in files of statement lines; and, optionally, a **head** the reader
fetched from the witness, in a file of its own. A file's lines are its bytes up to each
`0x0A`, the piece after the last one included. A line that is empty, or holds only spaces,
tabs and carriage returns, is passed over; every other line is one statement as served
(§8.2), its surrounding JSON whitespace allowed. A head file holds exactly one statement
line.

Before any statement is read the reading is refused — no reading at all, never a reading
of part — by the first of these: more keys than §8.7 allows (`keys-over-bound`); a key the
key rule refuses, the keys taken in their order, with that key's reason (§8.4); the files
over §8.7's bound on bytes (`bytes-over-bound`); and the files over its bound on statements
(`statements-over-bound`). Otherwise:

1. **Each statement.** The statements of every file and the head are one set, whatever
   files they came in and in whatever order. Two with the same canonical bytes are one, and
   each statement is checked once, against, in this order: its form (§8.2), or
   **`witness-malformed`** — a head file of other than one statement line too; its
   signature, under the key its `keyId` names among those supplied, by §8.4's equation over
   §8.3's bytes, or **`witness-signature-invalid`**, a `keyId` that names no key supplied
   included; and its trail, which must be the trail being verified, or
   **`witness-trail-mismatch`**. A statement takes the first of these findings and no other.
   A statement that fails is never passed over, whatever it claims: it fails the reading.
2. **Equivocation.** Two statements that passed step 1, are of one index and differ are
   **`witness-equivocation`**: the witness signed two chains.
3. **The chain.** A set in which steps 1 and 2 found anything is not walked: the findings
   are those steps', and a hole a failed statement leaves is not reported. Otherwise the
   **chain** is the set, less a head whose index is more than one past the index of every
   other statement of the set. Taken in index order, it must begin at index 0 with
   `prevSignature` `null` and hold every index from there to its highest, each
   `prevSignature` after the first the `signature` of the statement before; each
   `checkpoint` statement's sequence must exceed the latest `checkpoint` statement's before
   it; each `conflict` statement must have a `checkpoint` statement before it and a sequence
   at or below the latest one's; and a `retirement` statement must have a `checkpoint`
   statement before it, repeat the latest one's checkpoint, all four members, and be the
   chain's last. Otherwise **`witness-chain-broken`**. A set that begins late is never read
   from where it begins, and a set of no statement does not begin at index 0.
4. **The head.** A head left out of the chain in step 3 is **`witness-head-unreached`**: the
   statements supplied do not reach it. A head at an index the chain holds is the chain's
   statement at that index, by its signature, since step 2 found no other; a head one index
   past every other statement was walked in step 3 as the chain's last. The chain may run
   past the head: statements the witness signed after the reader's fetch, supplied from
   elsewhere, are checked like the rest.

A reading with any finding is credited nothing. A reading with none is **current** when a
head was supplied, as of the reader's fetch of it — a signature does not say when it was
fetched — and **historical** when none was: it ends at the highest statement supplied and
says nothing of any statement after it. It reports the chain's highest index, the head's
index, the latest witnessed checkpoint's index, sequence and `witnessedAt`, the sequence of
each `conflict` statement in index order, and whether the chain is retired;
`corpus/README.md` gives the form `gateway conform` compares.

A reader that holds the trail then holds each `checkpoint` statement's checkpoint against
it as a holder's checkpoint is held: line N's exact bytes against the statement for
sequence N. That comparison, continuing a reading in steps from a continuation the
reader's own earlier reading saved, the coverage a credited chain gives a trail, and the
sentences a report states, are the runtime's verifier's
(`docs/adr/0013-checkpoint-witness.md` §6), and are not specified here.

### 8.7 Bounds

One reading takes at most **16** keys; statement files and a head file of at most
**67108864 bytes** (64 MiB) together; and at most **110000** statements, counted as the
lines step 1 would read — every line of every file, the head file's included, that is not
passed over — before two copies of one statement are one. Over any of them the reading is
refused before any statement is checked (§8.6), and is never truncated. The bytes are
bounded first, by the files' sizes, before any file is read. The statements are then
counted as the files are split into lines, the statements files in their order and the
head file last, and the reading is refused at the first line past the bound, keeping and
reading none of the lines after it: a file of many short lines costs a reader no more than
110000 statements do. Each statement costs one Ed25519 verification, under the one key its
`keyId` names, so the work of a reading is bounded by its statement count. A chain longer
than one reading takes is read in steps, each continuing from what the step before saved,
which is the runtime's (§8.6): 110000 statements are about 30 hours of a witness taking 60
submissions a minute, and about 12 years at one an hour.

### 8.8 What a statement establishes, and what it does not

| | Establishes | Does not establish |
|---|---|---|
| A `checkpoint` statement, verified under a key the verifier trusts | the key's holder was given this checkpoint and signed it as statement `index` of its chain for the trail, and states that it did so at `witnessedAt` | that the checkpoint names a real record; that it extends the one before; that the submitter was the trail's operator; that `witnessedAt` is true; anything against a witness that colludes, or whose key is stolen |
| The same, held against a trail copy | lines 1 to its sequence are the lines that existed when the witness signed, if the witness is independent of the operator | anything after that sequence; that this is the project's only trail; that the records are true, or that every decision was recorded |
| A chain read from index 0, every statement present and linked, up to the signature of a head the reader fetched from the witness | the reader holds every statement of the chain that head commits to, as the witness signed them: none is missing, out of order or altered, and none starts late | that the head is still the witness's head after the fetch; that the witness signed no second chain for the trail, for another audience; that it will serve these tomorrow |
| The same chain read only as far as it was supplied, with no head | the same, up to the highest statement supplied | anything about statements after it: the reading is historical |
| A `conflict` statement | a submitter the witness allowed for the trail offered another record for a sequence the witness held | which of the two is the trail's; who that submitter was, beyond the witness's own registration |
| A `retirement` statement | the witness accepts no more statements for the trail, and the chain ends there | why; whether the trail's operator went on under another trail |

A witness learns of a trail its identity, the sequences submitted — so how many lines the
trail had at each submission — the record digests at those sequences, when, and the
submitter it registered; never a record's contents, pack, inputs or outcome. Its reads are
open to anyone who names a trail (§6), so anyone who holds one of a trail's checkpoints can
follow its continuing activity — its sequences, the time of each statement, every conflict
— for as long as the witness serves it.

Against the trail's operator, a chain read from its first statement and held against a
trail copy establishes that no record up to the latest checkpoint statement's sequence was
edited, removed, inserted or moved since the witness signed the first statement covering
it; a copy cut short below that sequence fails; and a rewrite from any sequence at or below
an earlier statement's fails at that statement. It does not establish:

- anything against a witness that colludes, or whose key is stolen: it can sign any
  checkpoint at any time it states, and a second chain for a trail for another audience.
  Two statements of one trail and one index that differ, both verifying, prove that it
  signed two chains; a statement someone kept that the chain served lacks shows a second
  chain to whoever holds both. One witness gives no protection against collusion;
- who submitted: the witness cannot tell the trail's operator from a holder of the
  operator's credential, and a verifier cannot either. A credential stolen can have a
  checkpoint signed at a sequence no honest checkpoint will exceed, and that statement
  stays in the chain: the trail is then retired, not repaired;
- anything about an operator who stops submitting, about records after the latest
  checkpoint statement, or about a trail rewritten before its first submission;
- that the trail is the project's only one: a verifier must hold the trail identities it
  expects;
- that the witness keeps what it signed: a witness that loses or withholds its latest
  statements serves an older head that is internally consistent, and for a trail it holds
  nothing for it answers as for one never submitted. A statement of a higher index than the
  head served shows that the served view is not the whole one; it does not show whether the
  witness forgot or withholds;
- when anything happened: `witnessedAt` is the witness's clock, an upper bound on when it
  held the checkpoint as it states it, under no certificate policy, and it says nothing of
  when a record was made.
