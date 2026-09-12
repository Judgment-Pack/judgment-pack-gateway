# Design note: receipt version 3

**Status: design note, not normative.** [SPEC.md](../../SPEC.md) is normative for receipt
version 2 and says nothing about version 3. Nothing here binds an implementation until it is
written into `SPEC.md` with corpus vectors, and `SPEC.md` leads that change
([CONTRIBUTING.md](../../CONTRIBUTING.md#changing-specmd)). This note exists so the field list can
be argued about before anything is signed.

## Why a third version

A version 2 receipt binds the bytes, the position in a session, the chain, and two labels the
operator chose. It does not say which system was asked, which query ran, which snapshot was
read, through what, or for whom. An auditor asking any of those questions gets nothing from the
receipt. Four things want a format change at once, and [SECURITY.md](../../SECURITY.md) already
names one of them as out of scope for version 2:

1. **The acquisition record**: the system, the statement, the snapshot, the peer, the adapter.
2. **A salted arguments commitment**, closing the equality oracle SECURITY.md describes.
3. **A caller identity**, from a token the customer's identity provider issued.
4. **Two kinds of receipt**: an acquisition, and an action a person approved.

Page receipts over a corpus ride on the first: a page is one acquisition whose record lists the
digest of every item in it.

## The envelope

Everything version 2 states about canonical form (§1.1) is unchanged: integers only, strings
must be UTF-8, duplicate names refused, code-point member order, raw UTF-8 output. The new
members are all strings, integers, `null`, objects or arrays of strings, so nothing new enters
the canon domain and `corpus/canon.json` does not move.

| Member | Type | Change from version 2 |
|---|---|---|
| `receiptVersion` | the string `"3"` | value |
| `sessionId`, `callIndex`, `prevSignature`, `source`, `resultDigest`, `servedAt`, `authority`, `keyId`, `signature` | as in version 2 | none |
| `kind` | `"acquisition"` or `"action"` | new |
| `argumentsCommitment` | `"sha256:" + 64 lowercase hex` | replaces `argumentsDigest` |
| `caller` | object or `null` | new |
| `acquisition` | object; present exactly when `kind` is `"acquisition"` | new |
| `action` | object; present exactly when `kind` is `"action"` | new |

**What the signature covers** is the version 2 rule unchanged: the context prefix
`"judgment-pack-gateway/receipt/3:"` followed by `canon` of the receipt with the `signature`
member removed and every other member retained. Appending anything, at any depth, invalidates
the signature. The prefix moves with the version so a version 3 signature cannot be presented
as a version 2 one or the reverse.

### `argumentsCommitment`

`"sha256:"` + hex of SHA-256 over `salt || "args:" || canon(arguments)`, where `salt` is 32
bytes the gateway draws fresh for each receipt. The salt is retained in the store beside the
artifact, at `<root>/salts/<sessionId>/<callIndex>`, and is not part of the receipt. A verifier
checks nothing about the commitment. An auditor handed the salt and the arguments recomputes it
and learns whether these were the arguments; nobody else learns anything, including a party who
can call `/acquire` under the same key, which is the oracle version 2 has. The HMAC keying goes
with it: there is no longer a secret in the commitment, only a nonce.

### `caller`

```
{ "issuer": <string>, "subject": <string>, "tokenDigest": "sha256:" + hex }
```

The engine verifies a signed token from the identity provider named in its configuration
([engine-config.md](engine-config.md)) and records the issuer and subject it carried, with the
digest of the token bytes. The token itself is never stored and never signed into a receipt. When
the engine runs without an identity provider, `caller` is `null`, and the receipt says so rather
than omitting the member: an absent member would let an old receipt and a receipt made with
identity switched off read the same.

### `acquisition`

| Member | Type | Meaning |
|---|---|---|
| `adapter` | `{ "name": <string>, "version": <string>, "digest": "sha256:" + hex }` | the program that fetched; for a connector image, the image digest |
| `shape` | `"airbyte"`, `"mcp"`, `"http"`, or `"command"` | which adapter shape served the call; `"command"` is a bare `--source NAME=CMD` with no adapter, the version 2 case |
| `endpoint` | string or `null` | the host or URL the adapter connected to, as it would name it to an operator |
| `statement` | `"sha256:" + hex` or `null` | a salted commitment to the query, resource path, or tool call, made and retained exactly as `argumentsCommitment` is |
| `snapshot` | string or `null` | what the source said about currency: a state bookmark, a transaction id, an object version, an ETag; `null` when the source offers nothing |
| `peerIdentity` | string or `null` | the identity the transport established, such as `"tls:sha256:" + hex` of the peer certificate; `null` for a local process |
| `schema` | `"sha256:" + hex` or `null` | the discovered stream or resource schema, canonicalized and digested; what a derivation rule was applied against |
| `upstreamToken` | string or `null` | an integrity token the upstream itself produced, carried verbatim when it exists; `null` when the upstream vouches for nothing |
| `pageItems` | array of `"sha256:" + hex`, or absent | for a page, the digest of each item's canonical bytes in order; absent for a single result |
| `observedAt` | string | when the adapter received the bytes, as the adapter recorded it; `servedAt` remains the gateway's own stamp |

Two of these are the honest-bounds fields. `upstreamToken` distinguishes a source that can vouch
for itself from one that cannot, so a receipt never lets an object store's version id and a
warehouse's silence read the same. `shape: "command"` keeps the version 2 posture available
and visible: a bare command attests bytes and nothing about their acquisition, and a receipt
made that way says so.

### `action`

| Member | Type | Meaning |
|---|---|---|
| `approver` | `{ "issuer", "subject", "tokenDigest" }` | who approved, from a verified token; never `null` — an action with no approver is refused before any executor runs |
| `decision` | `{ "recordDigest": "sha256:" + hex, "packDigest": "sha256:" + hex }` | the decision record this action relies on, by digest, and the pack it was decided under |
| `cites` | array of `{ "sessionId", "callIndex", "signature" }` | the acquisition receipts the decision record cites, so the chain from facts to action is one hop per link |
| `tool` | `{ "shape", "endpoint", "name" }` | what was called, named as `acquisition` names its adapter |
| `request` | `"sha256:" + hex` | a salted commitment to the request the executor sent |
| `adapter` | as in `acquisition` | the executor that performed it |
| `observedAt` | string | when the target answered |

`resultDigest` on an action receipt is the digest of the target's response bytes, retained like
any artifact. The receipt records that an executor was asked, by whom, citing which decision,
and what the target answered. It does not say the action was right, and the verifier does not
check the decision record's contents — only that a record with that digest exists where the
engine's `verify` looks for it.

## Verification

The version 2 ladder (§1.4) holds, with two changes:

- `malformed` grows the structural checks the new members need: `kind` outside its two values,
  a `kind` whose object is missing or whose sibling object is present, a `caller` that is
  neither `null` nor the stated shape, a digest member not of its stated form, `pageItems` not
  an array of digests, an `approver` of `null`.
- `unsupported-version` fires for anything but `"2"` or `"3"`. **A version 3 verifier keeps
  verifying version 2 stores**, each version under its own structural rules and its own context
  prefix, so a receipt signed before the change means afterwards exactly what it meant before.
  Nothing re-signs; a store may hold both versions across sessions, never within one session.

Two findings are new, both per session, both after the chain check:

- `citation-unresolved`: an action receipt cites a receipt that is not in the store, or names
  a signature that is not that receipt's.
- `decision-record-missing`: an action receipt's `decision.recordDigest` is not present where
  the engine's configuration says decision records are kept.

Neither reads the cited receipt's contents or the decision record's contents. Whether the facts
justified the action is nobody's finding.

## Corpus impact

- `canon.json`: no change.
- `stores/`: one new vector per new status (`citation-unresolved`, `decision-record-missing`),
  one per new `malformed` condition, one version 2 store verified by the version 3 verifier,
  and one mixed store.
- `teeth_test.go`: a member appended inside `acquisition` must invalidate the signature; a
  version 2 receipt re-labelled `"3"` must fail `signature-mismatch`, not verify; an action
  receipt with `approver: null` must be `malformed`.
- `ed25519-vectors.json`: no change.

Every vector is hand-written against this note and `SPEC.md`, never generated from the
implementation, per [corpus/README.md](../../corpus/README.md).

## Open questions

1. Whether `pageItems` should be a flat list or a Merkle root plus a proof path per item. A
   flat list is simple and verifiable with `sha256` alone; a large page makes the receipt large.
   Decide from the first real corpus pull.
2. Whether `observedAt` should be constrained to a format. Version 2 leaves `servedAt` a free
   string; matching that is consistent, and a verifier compares nothing to a clock.
3. Whether `caller` should carry the token's audience. Recording it would let an auditor see
   which engine the token was minted for; omitting it keeps the member small.
4. Where the salts live when the store is copied for offline verification. A salt is not
   needed to verify and must not be needed; whether the snapshot ceremony (§5a) should carry
   them for the auditor's benefit is a consumer question.
