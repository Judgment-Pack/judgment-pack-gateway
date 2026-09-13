# Design note: receipt version 3

**Status: graduated into [SPEC.md §1.2a](../../SPEC.md), which is normative; this note is the
design record and is not.** Where the two differ, `SPEC.md` is right. The note is kept because it
carries the reasoning and the open questions; the specification carries the format. The
implementation follows the specification in its own change
([CONTRIBUTING.md](../../CONTRIBUTING.md#changing-specmd)).

## Why a third version

A version 2 receipt binds the bytes, the position in a session, the chain, and two labels the
operator chose. It does not say which system was asked, which query ran, which snapshot was
read, through what, or for whom. An auditor asking any of those questions gets nothing from the
receipt. Four things want a format change at once, and [SECURITY.md](../../SECURITY.md) already
names one of them as out of scope for version 2:

1. **The acquisition record**: the system, the statement, the snapshot, the peer, the adapter.
2. **A salted arguments commitment**, closing the equality oracle SECURITY.md describes.
3. **A caller identity**, from a token the customer's identity provider issued.
4. **Two kinds of receipt**: an acquisition, and an action an authenticated identity requested.

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
bytes the gateway draws fresh for each receipt and **returns to the caller in the acquire
response, beside the receipt**. The gateway retains no salt; the store carries commitments
only. A verifier checks nothing about the commitment.

The disclosure boundary, stated because version 2's was stated: a party holding the store
learns nothing about the arguments from a commitment, since without the salt every candidate
hashes to something equally unrelated — a store copied for offline verification does not carry
the material to guess with. A party who can call `/acquire` cannot compare its own commitment
with another receipt's, since the salts differ; that is the oracle version 2 has and this
closes. The caller, who holds the salt, can reveal the arguments to an auditor of its choosing
by handing over both, and only the caller can. The costs are the mirror of that: an auditor
without the caller's cooperation cannot learn the arguments from the store, which version 2
could not offer either, and a caller who loses the salt has lost the ability to reveal. The
HMAC keying goes with it: there is no secret in the commitment, only a nonce the caller keeps.

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
| `requester` | `{ "issuer", "subject", "tokenDigest" }` | the authenticated identity that submitted the action request, from a verified token; never `null` — a request with no authenticated requester is refused before any executor runs. A token proves who asked, not that they approved this action; see open question 6 |
| `decision` | `{ "recordDigest": "sha256:" + hex, "packDigest": "sha256:" + hex }` | the decision record the requester says this action relies on, by digest, and the pack it says the decision was made under |
| `cites` | array of `{ "sessionId", "callIndex", "signature" }` | the acquisition receipts the requester says the decision record cites. `decision.packDigest` and `cites` are assertions supplied with the request and recorded; the verifier checks the cited receipts exist and the record's bytes match `recordDigest`, and does not compare the record's contents with either — open question 5 |
| `tool` | `{ "shape", "endpoint", "name" }` | what was called, named as `acquisition` names its adapter |
| `request` | `"sha256:" + hex` | a salted commitment to the request the executor sent |
| `adapter` | as in `acquisition` | the executor that performed it |
| `observedAt` | string | when the target answered |

`resultDigest` on an action receipt is the digest of the target's response bytes, retained like
any artifact. The receipt records that an executor was asked, by which authenticated identity,
citing which decision, and what the target answered. It does not say the action was right, and
it does not say the identity approved it. The verifier hashes the decision record's bytes and
compares them with `recordDigest`; it interprets nothing inside the record.

## Verification

The version 2 ladder (§1.4) holds, with two changes:

- `malformed` grows the structural checks the new members need: `kind` outside its two values,
  a `kind` whose object is missing or whose sibling object is present, a `caller` that is
  neither `null` nor the stated shape, a digest member not of its stated form, `pageItems` not
  an array of digests, a `requester` of `null`.
- `unsupported-version` fires for anything but `"2"` or `"3"`. **A version 3 verifier keeps
  verifying version 2 stores**, each version under its own structural rules and its own context
  prefix, so a receipt signed before the change means afterwards exactly what it meant before.
  Nothing re-signs; a store may hold both versions across sessions, never within one session.

Two findings are new, both per session, both after the chain check:

- `citation-unresolved`: an action receipt cites a receipt that is not in the store, or names
  a signature that is not that receipt's.
- `decision-record-mismatch`: no file under the directory the engine's configuration names
  for decision records has bytes that re-digest to the action receipt's
  `decision.recordDigest`. A digest-shaped filename proves nothing; the verifier hashes the
  bytes it finds and compares.

Neither interprets the cited receipt's contents or the decision record's; the second hashes
bytes. Whether the record cites the same receipts the action does, whether it was decided under
the pack the action names, and whether the facts justified the action are not findings here
(open question 5).

Two more, per decision record, from the record's side of the join (§4 step 7): a candidate
under the decision-record directory that is one JSON object carrying a `cites` member of the
shape `action.cites` has — a record the runtime wrote with the citations its caller gave it —
is read for that member and for nothing else:

- `record-citation-unresolved`: one of the record's citations does not resolve as an action
  receipt's would.
- `record-citation-malformed`: the record's `cites` is not of the shape, or is given twice.

Reported as `{recordDigest, status}`, once per record, whether or not any action receipt names
it; a candidate that is not one JSON object, or carries no `cites`, is not interpreted at all.

## Corpus impact

- `canon.json`: no change.
- `stores/`: one new vector per new status (`citation-unresolved`, `decision-record-mismatch`,
  and from the record's side `record-citation-unresolved`, `record-citation-malformed`, with a
  record that cites and resolves),
  one per new `malformed` condition, one version 2 store verified by the version 3 verifier,
  and one mixed store.
- `teeth_test.go`: a member appended inside `acquisition` must invalidate the signature; a
  version 2 receipt re-labelled `"3"` must be `malformed`, because it lacks the version 3
  members and §1.4's order puts that check before the signature; a structurally valid version 3
  envelope carrying a signature made under the version 2 context prefix must fail
  `signature-mismatch`, which is what proves the prefixes separate; an action receipt with
  `requester: null` must be `malformed`.
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
4. Whether a caller should be able to deposit a salt with an auditor of record at acquire
   time, so that revealing does not depend on the caller still holding it. The store must
   never carry salts; anything else is a consumer arrangement.
5. Whether the verifier should read the decision record's own members — the runtime's audit
   record names the pack digest and, after the join, the receipts it relied on — and compare
   them with `decision.packDigest` and `cites`, reporting a mismatch. That would make the
   advertised chain checkable end to end at the cost of coupling this verifier to the
   runtime's record format and version. Until decided, both members are recorded assertions.
6. What evidence of *approval*, as distinct from authentication, an action receipt could carry.
   A token proves the requester's identity at the engine's boundary. Approval of this action
   would need a statement bound to the request commitment and the decision digest, signed by
   something the requester controls — a desk's own key, or a second token minted for exactly
   that statement. Nothing in this note supplies it, and the receipt does not claim it.
