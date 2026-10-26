# Gateway specification

The gateway is the **open-source implementation** of the trustworthy-input-acquisition
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

**It is normative too for the continuity statement (§3b), version 1:** the pair of
registry lines by which a gateway rotates its signing key, which a verifier follows from
the key it pinned. A registry that holds none is read exactly as before.

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
| `witness` | object (below) — **optional**, on either kind |

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
| `transport` | the string `"http"` — **optional** | present exactly when an `"mcp"` adapter reached a remote server over Streamable HTTP (below; §6); absent for a server reached over stdio and for every other shape |
| `server` | `{ "name": string, "version": string }` — **optional** | the name and version the remote server gave itself in its `initialize` answer; present exactly when `transport` is |

`upstreamToken` and `shape` are the honest-bounds members: a receipt never lets
a source that vouches for itself and a source that vouches for nothing read the
same, and never lets bytes attested through a bare command read as bytes whose
acquisition was recorded.

**A remote MCP server** (`docs/adr/0015-a-remote-mcp-server-as-a-source-and-executor.md`).
`transport` and `server` are present together or not at all, and only on shape
`"mcp"`; with them, `endpoint` and `peerIdentity` are held to the forms that follow.
`endpoint` is a string of at most 2048 characters, each from U+0021 to U+007E:
`"https://"` or `"http://"`; then an authority, which is a host, followed by `":"` and
a port or by nothing; then nothing, or `"/"` and a path. The host is a name — one or
more characters from `A` to `Z`, `a` to `z`, `0` to `9`, `-`, `.` and `_`, an IPv4
address in dotted decimal among them — or `"["`, an IPv6 address, and `"]"`. The IPv6
address is of the form RFC 3986 names `IPv6address`: eight groups of one to four
hexadecimal digits separated by `:`, where `::` may stand once for one or more groups
of zeros, and the last two groups may be written as an IPv4 address in dotted decimal,
each part from 0 to 255 with no leading zero; it has no zone. No host holds `@`, so no
user is named before it. The port is a decimal from 1 to 65535 with no leading zero;
`":"` with nothing after it is not one. The path holds no `?` and no `#`, and every
`%` in it is followed by exactly two hexadecimal digits; an `@` in the path names no
user, and is one of its characters. After `"http://"`, the host is a loopback address
written as one: an IPv4 address of `127.0.0.0/8` in dotted decimal, each part from 0
to 255 with no leading zero, or `[::1]`; a name is not one, `localhost` included,
since what a name resolves to is not in the text. This is the one form of a remote
server's URL: the adapter holds its `--url` to it before anything is sent, the gateway
an envelope's `endpoint` before anything is signed and a binding's URL before the
engine starts, and a verifier a receipt's.
`peerIdentity` is `"tls:sha256:"` followed by exactly 64 lowercase
hexadecimal characters after `"https://"`, and `null` after `"http://"`, where no
transport identity is established. A `transport` of another value, a `server` that is
not an object of a string `name` and a string `version`, one of the two without the
other, the two on another shape, or an `endpoint` or a `peerIdentity` out of these
forms, is `malformed`. A member of `server` beside those two is tolerated, as any
signed member a verifier does not know is. A verifier written before the members
tolerates them and holds them to nothing.

**What a remote acquisition establishes.** As every adapter record, it is the
adapter's testimony under the gateway's signature (below): that an endpoint at that
URL, presenting that TLS identity, answered that tool call — committed in
`statement` — with the bytes `resultDigest` names, at `observedAt`, under the
operator's credential, where one is configured; the record itself does not say whether
one was sent. It does not establish that the bytes are
true; that the tool read rather than wrote, which nothing at the client can tell;
that the server is honest, or the vendor's, or that the name and version it gave
itself are its own; or anything the session carried beyond the one call. The
credential is in no member, and neither is the session the server issued.

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
| `tool` | `{ "shape": string, "endpoint": string or `null`, "name": string, "transport": "http" }`, `transport` **optional** | what was called, named as `acquisition` names its adapter; for a write to a remote MCP server, `endpoint` is the server's URL and `transport` is `"http"` (below) |
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

**`tool.transport`** (`docs/adr/0015-a-remote-mcp-server-as-a-source-and-executor.md`,
amended for #268). Present, it is the string `"http"`: the executor reached a remote MCP
server over Streamable HTTP, as an acquisition's `transport` says of an adapter, and
`endpoint` is then a string held to the form "A remote MCP server" states above. Absent,
the write went over stdio, and `endpoint` is the platform's, a string or `null` held to
nothing more: the engine configuration takes a platform's endpoint as any non-empty
string, which can begin with `"https://"`, so the transport is read from this member and
never from the endpoint's spelling. A `transport` of another value, `transport` on a
`tool` whose `shape` is not `"mcp"`, or, with it, an `endpoint` that is `null` or out of
that form, is `malformed`. The member is signed with every other member; a write over
stdio carries none, so its receipt is the one it was before the member existed. A
verifier written before the member tolerates it, as it tolerates any signed member it
does not know, and holds the endpoint to nothing: it can answer `ok` for a receipt naming
a remote endpoint out of the form that a verifier reading the member reports `malformed`
for. The TLS identity the write's answer came under is in no member of the action
(ADR-0015, question 2).

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
directory, and the cited receipts in its store under its key, or a key its
registry says it rotated from (§3b), before the action was sent (§6); §4 establishes both again against the store and the records it
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
edit of that object. A policy that sets `closed` establishes that the request's
arguments were exactly those the policy names, each bound to the record or fixed
by the policy, at the moment of the check; not that the target interpreted them
as intended, and a policy that does not set it establishes nothing of an
argument it does not name. A policy's `shape` establishes that each value it
names was a container of the type it states, an array no longer than its bound;
it holds no container it does not name.

**`policy`.** The gateway's operator may hold a write tool to a **decision
policy** in the gateway's configuration (`docs/design/engine-config.md`,
`docs/adr/0011-hold-a-write-to-its-decision.md`): an object whose members are
`outcomes`, the outcome ids a record may have decided, and optionally `packs`,
the pack digests it may have been decided under, `reviewed`, whether it must
carry `"reviewed": true`, `bind`, pairs of JSON pointers (RFC 6901), one
into the request's arguments and one into the record's `inputs.facts`, whose
values must be equal, `fix`, pairs of a JSON pointer into the request's
arguments and a value the argument there must equal, `closed`, whether every
argument must be reached by a pointer of `bind` or `fix`
(`docs/adr/0016-a-policy-fixes-a-value-and-closes-the-argument-set.md`),
`shape`, entries of a JSON pointer into the request's arguments and the
container the value there must be, `{"pointer", "type": "object"}` or
`{"pointer", "type": "array", "maxLength"}`, `maxLength` an integer from 0 to
524288 (`docs/adr/0018-a-policy-holds-a-containers-shape.md`), and
`requireSignedRecord`, the Ed25519 public keys of the
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
`true`; for each pair of `bind`, both pointers to resolve and the two
values to have the same canonical form (§1.1) — a value outside the canonical
domain equals none; for each entry of `fix`, the argument at its pointer to be
present and to have the canonical form of the entry's value, the gateway
filling nothing in; for each entry of `shape`, the value at its pointer to be
present and to be an object, or an array of at most `maxLength` elements, as
the entry states; and, when `closed` is `true`, every member and element of
the arguments to be reached: covered by a pointer of `bind` or `fix`, which
covers the value it names and everything under it, or an object or array on the
way to a pointer of `bind`, `fix` or `shape`, or named by a pointer of `shape`,
each of whose members or elements is reached in turn — a pointer of `shape`
reaches its container and covers nothing under it — an array's element reached
by its index pointer or by a pointer covering the array. It refuses the request
otherwise, with nothing sent and nothing minted. `reviewed`
holds the record to whatever reviewed-set lock was current when it was written,
not to particular bytes: a pack that is edited and locked again yields records
with `"reviewed": true` and a new pack digest, which a policy without `packs`
admits. `packs` is what holds a write to particular
reviewed packs. `policy` is then `"sha256:"` + hex of SHA-256 over `canon` of
the policy object as configured (§1.1), every member of it included, `fix`,
`shape` and `closed` as much as the others. For a policy without `fix` that is
its RFC 8785 form too, since its member names are then the fixed ASCII names
above and its only numbers are a shape's `maxLength`, integers from 0 to 524288,
which RFC 8785 writes as `canon` does; a fixed value may hold integers and
member names of any script, and the digest is `canon`'s, whose order of names
outside the Basic Multilingual Plane is not RFC 8785's.
The receipt carries the policy's digest and never the policy. A verifier checks
the member's form and nothing else: it holds no configuration to recompute the
digest against.

**`witness`** — optional: the witness the gateway's operator named for a trail
(`docs/adr/0014-a-receipt-names-the-witness.md`), so that a verifier holding a
decision record and its receipts can find the checkpoint witness of §8 its trail
is registered with. A top-level object:

| Member | Form | Meaning |
|---|---|---|
| `origin` | `"https://"` or `"http://"`, a host in lowercase, `":"` and a port in decimal from 1 to 65535 with no leading zero, and nothing after it; at most 2048 characters | where the witness serves §6's paths, at its root |
| `keyId` | 32 lowercase hexadecimal characters, derived as §1.2 derives one | the witness's key: the `keyId` its statements carry (§8.2) |
| `trail` | 32 lowercase hexadecimal characters | the trail the gateway named the witness for |

A host is a name — labels of lowercase letters, digits and hyphens joined by single
dots, an IPv4 address among them — or an IPv6 address of lowercase hexadecimal and
colons in brackets. `"http://"` is the form only with a loopback address written as
one: an IPv4 address of `127.0.0.0/8` in dotted decimal, each part from 0 to 255 with
no leading zero, or `[::1]`. The member is signed with every other member, and the
time it names the witness at is the receipt's `servedAt`. The gateway sets it from its
operator's configuration (`docs/design/engine-config.md`, `witnessedBy`) and from
nothing a request carries: on an action receipt, when the record the action was found
on (§6, `/act`) is a runtime evaluation record (§4 step 8) whose `trail` is 32
lowercase hexadecimal characters and the configuration names a witness for that
trail, its `trail` being the record's; on an acquisition receipt, when the request
names a `trail` (§6) the configuration names a witness for. A seal (§3) never carries
it. It records no token, no digest of one, and no registration's issuer or subject: a
registration is served nowhere (§6), a receipt included. A receipt of a trail the
configuration names no witness for is the receipt it was before the member existed. A
verifier written before the member tolerates it, as it tolerates any signed member it
does not know, and reports no witness.

**What `witness` establishes.** On a receipt that verifies under the operator's
gateway key: that the holder of that key, minting the receipt at its `servedAt`, named
this origin and this key identifier for this trail. It does not establish that the
witness holds anything for the trail or registered it, that a checkpoint was
submitted, that the chain is countersigned, that the origin serves the key named, that
the witness is independent of the operator, who chose it, or anything about the
operator's honesty. On an action receipt whose record is compared (§4 step 8), it
establishes too that the action was minted on a record of that trail, and not where in
the trail the record is: the trail copy shows that. A receipt without the member
establishes nothing, and not that the trail has no witness. What a chain then read
establishes is §8.8's, under the key the reader used; with a key the origin served
rather than one the reader pinned, no independence beyond the operator's choice of
witness.

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
| 1 | `malformed` | unparseable, duplicate member names, missing `signature`, `callIndex` not an integer, `resultDigest` not of the stated form, or `signature` not hex; for version 3, **any** violation of a structural constraint §1.2a states — a member required absent, a member of another type than stated, a nullable member neither `null` nor of its stated shape, `kind` or `shape` outside its enumeration, the object for the kind missing or its sibling present, a digest or a signature not of its stated form, `pageItems` present and not an array of digests, `requester` `null`, `cites` not an array of objects of the stated shape, `policy` present and not a digest, `decision.recordBytes` present and not `"exact"`, `witness` present and not an object whose `origin`, `keyId` and `trail` are each of their stated forms — and never a relational one |
| 2 | `unsupported-version` | `receiptVersion` is neither `"2"` nor `"3"` |
| 3 | `key-mismatch` | `keyId` is not the key id of a key the verifier reached (§3b): the key it pinned, or a key a rotation it followed rotated to |
| 4 | `signature-mismatch` | the signature does not verify, under the key `keyId` names, over the input §1.2 or §1.2a defines for the receipt's version |
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
  each receipt's `receiptVersion` must equal the session head's
  (`callIndex` 0), and each receipt's key must be the key of the receipt before
  it or a key the walk of §3b reached after that one, and the **first** break of
  any of these kinds, walking the passing
  receipts in index order, reports one **`chain-broken`** for the session — the
  session-level finding, with `callIndex` `null`, exactly as a `prevSignature`
  break does. In a store whose registry holds no rotation statement every
  receipt that passed is under the one key pinned, and the third kind cannot
  arise. A receipt that failed the ladder takes no part in this walk, and
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
verifies under its public key, or, in a registry holding rotation statements, the key current at
its line in the gateway's own reading (§3b) — and a line that names the session and is no such seal (a
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

## 3b. Key rotation: the continuity statement

A gateway's signing key can be replaced without leaving what it signed before
unverifiable. A **rotation** is two registry lines, appended together: a
`key-rotation` statement, signed by the key rotated **from**, naming the key rotated
**to**; and a `key-continuation` statement, signed by the key rotated to, naming the key
it continues. Together they are the **continuity statement**. They take the shape of
the runtime's `key-rotation` line in its record-signature sidecar — a `kind`, the
signing key's `keyId`, the next key's 32 bytes as `next` — under a prefix of this
gateway's own; the runtime's line is still followed nowhere here (§1.2a, `policy`).
A verifier given the key it pinned (§5) follows the rotations from that key, each
under the key before it, and takes every later key from them (§4 step 2). A store
whose registry holds no rotation statement verifies exactly as it did before this
section existed.

| Member | Form | Statement |
|---|---|---|
| `kind` | `"key-rotation"` or `"key-continuation"` | both |
| `rotationVersion` | the string `"1"` | both |
| `rotation` | an integer from 1 to 2⁵³−2 | both: this rotation's ordinal in the registry, 1 for the first |
| `rotatedAt` | `YYYY-MM-DDThh:mm:ssZ`, the form of `witnessedAt` (§8.2) | both: the gateway's clock when it rotated, the same in the two |
| `keyId` | 32 lowercase hexadecimal characters | both: the key id (§1.2) of the key that signs the statement |
| `next` | 64 lowercase hexadecimal characters | `key-rotation`: the 32 bytes of the key rotated to |
| `nextKeyId` | 32 lowercase hexadecimal characters | `key-rotation`: the key id of `next` |
| `previous` | 64 lowercase hexadecimal characters | `key-continuation`: the 32 bytes of the key rotated from |
| `previousKeyId` | 32 lowercase hexadecimal characters | `key-continuation`: the key id of `previous` |
| `signature` | 128 lowercase hexadecimal characters, the 64 bytes of an Ed25519 signature | both |

A registry line is a **rotation statement** when §1.1's parser reads it as one JSON
object whose `kind` member is the string `"key-rotation"` or `"key-continuation"`. A
rotation statement is never a seal, and every other line is read as a seal is (§4 step
2), as before. A rotation statement **holds its form** when it has exactly the members
the table lists for its `kind`, each once and of its form — a member it does not list
is a new `rotationVersion`, as a new member of a witness statement is (§8.2) — and its
`nextKeyId` or `previousKeyId` is the key id of its `next` or `previous`.

**What the signature covers** — `"judgment-pack-gateway/rotation/1:"` followed by
`canon` of the statement with its top-level `signature` member removed and every other
member retained. Every value is an ASCII string or an integer below 2⁵³, so the signed
bytes are exactly

```
judgment-pack-gateway/rotation/1:{"keyId":"<keyId>","kind":"key-rotation","next":"<next>","nextKeyId":"<nextKeyId>","rotatedAt":"<rotatedAt>","rotation":<rotation>,"rotationVersion":"1"}
judgment-pack-gateway/rotation/1:{"keyId":"<keyId>","kind":"key-continuation","previous":"<previous>","previousKeyId":"<previousKeyId>","rotatedAt":"<rotatedAt>","rotation":<rotation>,"rotationVersion":"1"}
```

with `rotation` in decimal digits. The prefix is none of the receipt's, the seal's or
the witness statement's, so no rotation signature can be replayed as one of theirs, or
the reverse; `kind` is signed, so neither statement of a pair can be presented as the
other.

**Following the rotations.** The registry's **lines** are its bytes split at each
`0x0A`, the piece after the last one included. A verifier walks them in order, holding
a **current key** — the key it pinned, at the first line — and the number of
rotations **followed**, 0 at the first line. The keys **reached** are the pinned key
and every key a followed rotation rotated to. At each line:

- A line that is not a rotation statement is read as a seal, under the current key
  (§4 step 2).
- A `key-continuation` statement is **`rotation-forged`**: a continuation the current
  key did not name.
- A `key-rotation` statement is held to these, in order, and takes the first it fails:
  1. it holds its form — otherwise **`rotation-break`**;
  2. its `keyId` is the current key's, and its signature verifies under the current
     key by §8.4's equation — otherwise **`rotation-forged`**: a hop signed by a key
     the walk had not reached, or had moved on from;
  3. its `rotation` is one more than the rotations followed — otherwise
     **`rotation-order`**: an ordinal skipped or given again;
  4. `next` is a key §8.4's key rule accepts, and its key id is none of a key reached
     — otherwise **`rotation-key-refused`**: a key not canonical, of small order or no
     point, or a key the walk has held already, the current one included;
  5. the line after it is a `key-continuation` statement that holds its form, whose
     `rotation` and `rotatedAt` are the `key-rotation`'s, whose `previous` is the
     current key's 32 bytes, whose `keyId` is the `key-rotation`'s `nextKeyId`, and
     whose signature verifies under `next` by §8.4's equation — otherwise
     **`rotation-break`**: the reverse statement missing, or not the one the
     rotation names.

  When it fails none, the rotation is followed: `next` is the current key, the
  rotations followed are one more, and the walk goes on at the line after the
  `key-continuation`.

The first of these findings stops the walk: no later line is read as a rotation
statement or followed, and every later line that is not a rotation statement is read as
a seal under the current key, the last key reached. A registry reports at most one,
`{status, rotation}`, where `rotation` is one more than the rotations followed — the
ordinal of the rotation the walk could not take — and it names no session (§5a.1).

A seal therefore loads only under the key current at its line: a seal the key rotated
from signs after the rotation, and one a later key signs before it, loads nothing. A
receipt is not ordered against the registry: it is taken under any key reached (§1.4
order 3), and within a session a receipt's key is never one the walk reached before the
key of the receipt before it (§1.4, `chain-broken`), so a session runs forward through
a rotation and never back.

**Rotating.** `gateway rotate-key --seed <file> --registry <file>` rotates a gateway's
key, the gateway stopped. On Unix a gateway holds an exclusive lock on its registry
file (`flock`) for as long as it runs, taken once its registry is there and followed by
its own reading again under the lock; `rotate-key` takes the same lock for as long as it
writes, so it refuses while a gateway runs, and a gateway refuses to start while a
rotation is under way. Elsewhere no lock is held, and that the gateway is stopped is its
operator's to see to. `rotate-key` reads the seed, refusing a seed that is not there or
not a seed, since a key that cannot sign cannot name its successor; it refuses a rotation
already under way beside the seed — a next seed (`<seed>.next`) or a kept record
(`<seed>.rotation`) there — which only `--resume` (below) finishes; it reads the
registry, refusing one that is not there, and walks it as the gateway does (below),
refusing a walk that finds anything or ends at another key than the seed's; and it
refuses a seed already kept at the name the seed rotated from would take. Each refusal
writes nothing. It then makes the next seed, `<seed>.next`, made once and never
replaced; builds the record it will append — the two statements, the `key-rotation`
first, each on a line of its own, after a newline ending an unterminated last line as a
seal's writer ends it (§3) — and keeps it, durably, in `<seed>.rotation`, with the
registry's length and SHA-256 at the place the record goes; appends the record to the
registry in one append made durable, refusing, everything it made removed, when the
registry is no longer the bytes it walked; and only then switches the signer: the seed
is moved to `<seed>.rotated-<rotation>`, kept for its operator to destroy, the next seed
is moved to the seed's name, which the gateway signs with when it starts, and the kept
record is removed.

**A rotation that stops.** An append can stop part way, and a write can be torn: the
registry may then end in a part of the record from its first byte — a `key-rotation`
cut short, a `key-rotation` whole with no `key-continuation` after it, or a
`key-continuation` cut short. Until the kept record is removed the rotation is
**pending**: a gateway refuses to start while a next seed or a kept record lies beside
its seed, under either key, and `gateway rotate-key --resume --seed <file> --registry
<file>` finishes it, and nothing else does. `--resume` finds the two keys among the
seed, the next seed and the seed kept aside by the key ids the kept record names;
rebuilds the record from them and holds the kept one to it byte for byte; holds the
registry up to the kept length to the kept digest, and its walk to the key rotated
from; and then takes the registry from there as it finds it: the record whole is left
as it is; a part of the record from its first byte, and nothing more, is cut — the one
cut of a registry this reference makes, and only of bytes the record names — and the
record appended whole, durably; anything else is refused, nothing changed. It then makes
whatever of the switch is not made. Stopped before the record was kept, a rotation left
at most a next seed, which `--resume` removes when the registry's walk ends at the
seed's key: nothing of the rotation was appended. A `key-rotation` torn before its end
leaves no rotation statement in the registry, which then reads to a gateway under
either key as a registry with no rotation: only the next seed and the kept record
beside the seed refuse that start. A seed switched by hand, with them removed, starts a
gateway under a key no verifier pinning the first key reaches; the switch is never made
by hand.

**The gateway's own reading.** A gateway pins no key out of band for itself. It walks
its registry from the key its first rotation rotated from — the `previous` of the
registry's first `key-continuation` statement — or from its own key when the registry
holds no `key-continuation` statement, a `key-rotation` alone included, so that such a
registry is refused under the key rotated from (`rotation-break`) and under the key
rotated to (`rotation-forged`) alike. It refuses to start, and refuses to seal, to
acquire into a session it does not hold and to answer `/verify`, when that walk finds
anything or ends at another key than its own, and names `--resume` as what finishes a
rotation that stopped. What it loads so is what a verifier pinning that first key loads, so a
session sealed under a key it rotated from stays sealed (§3), and the receipts an action
cites are resolved under every key the walk reached (§6, `/act`).

**What a rotation establishes.** That the holder of the key rotated from named the key
rotated to, and the holder of that key accepted the succession, at the place in the
registry where the pair stands. It does not withdraw what the key rotated from signed
before: its receipts and its seals before the rotation verify as they did. It does not
establish when a receipt was made: a holder of a key rotated from — the key stolen, which
is a reason to rotate — can still sign receipts that read as signed before the rotation,
into any session, and only the seal's count bounds them (§2, §5). It stops that holder
from sealing, and from rotating, after the rotation. `rotatedAt` is the gateway's clock,
as `sealedAt` is.

## 4. Registry-anchored verification

`verify_with_registry(verify_store, store_root, key, registry_path, authority)`:

1. Runs `verify_store` (all per-receipt findings carry through unchanged).
2. Loads the seals, **dropping any seal whose `keyId` is not the verifier's own or
   whose signature does not verify** under the public key — the verifier's own
   key being, at each line, the current key of §3b's walk of the registry: the key
   it pinned, in a registry that holds no rotation statement. The walk's finding,
   when it has one, is the registry's (§3b). Both conditions are
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
     **`decision-cites-mismatch`**;
   - for a receipt carrying `witness`, its `trail` member must be the string
     `witness.trail` → otherwise **`decision-trail-mismatch`**, a record with
     no `trail` member included.

   A record step 6 found that is not a runtime evaluation record — not one JSON
   object, of another `recordVersion`, a graph composite, one without a pack
   digest, a `.jsonl` file whole, an opaque file — is not compared, and nothing
   is found of it: the report carries the **observation**
   `decision-record-not-compared` for the receipt (below). The verifier reads a
   record for these members and for nothing else.

Steps 5, 6 and 8 each report once per action receipt, as `{sessionId,
callIndex, status}` with the action receipt's own session and index, beside that
receipt's `ok`; any of them may fire for one receipt, step 8 each of its
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

**Witnesses.** A report carries, beside them, a member `witnesses` when a
receipt whose ladder status is `ok` carries `witness` (§1.2a): an array of the
distinct `{trail, origin, keyId}` those receipts name, each once, whatever
receipts name it; absent when none does. Like an observation it is never part of
`ok`, and unlike one the corpus compares it, as a set (§7). It is what the
receipts' signer named, not a reading of any witness: a reader takes it only from
a verdict it acts on (§5a.1), and reads a chain from it as §6 says ("Reading the
witness a receipt names").

**Rotations.** A report carries, beside them, a member `rotations` when the walk
of §3b followed at least one rotation: `{"count": n, "keyId": k}`, `n` the
rotations followed and `k` the key id of the last key reached; absent when it
followed none. It is never part of `ok`, and the corpus compares it whole (§7). A
verifier reports the rotations it followed before a rotation finding too.

`ok` is true only if the inline verify passed **and** no registry finding fired
**and** no rotation finding fired (§3b) **and** no citation, decision-record,
decision-pack, decision-cites, decision-trail or record-citation finding fired.

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
  out of scope here. Only the first key arrives so: a key the gateway rotated to
  (§3b) reaches a verifier in a continuity statement the key it pinned, or a key
  that key named, signed — never from a receipt, a seal or the store.
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
  (binds localhost), no access control on the HTTP surface beyond a witness's
  registrations (§6, "Witness endpoints"). This is a reference for
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
  it scopes to;
- the registry's rotations hold: no `rotation-break`, `rotation-forged`,
  `rotation-order` or `rotation-key-refused` finding fired **at all** (§3b). A
  rotation finding names the rotation the walk could not take and no session: the
  walk stops there, and what it would have reached afterwards is reached for no
  session.

Session-scoping is a choice with a name, made deliberately in the consumer's code or
configuration. Silence means store-wide. The list above leans on an invariant of
this verifier's report: **every finding carries `status`; a receipt or session
finding carries `sessionId`, a record finding carries `recordDigest` and no
`sessionId`, and a rotation finding carries `rotation` and neither.** A verifier extended with a finding that names no session must extend
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
| POST   | `/acquire`  | `{session, source, arguments, trail}`, `trail` optional → runs the configured source, attests, chains, retains; returns `{result, receipt}` — `{result, receipt, salts}` for a version 3 receipt, below — where `receipt` is the complete receipt object of §1.2 — every member, `keyId` and `signature` included, the same object written under `receipts/<session>/<index>.json`. The response body is ordinary JSON, not the receipt's canonical form: a caller checking the signature canonicalizes the receipt per §1.1 first — a caller holding the binary has `gateway canon` for exactly that — and then applies the coverage rule of §1.2 or §1.2a according to the receipt's `receiptVersion`. No receipt is accepted from the caller. `session` must be a flat token (§3a) or the call is refused `400` before the source runs, and a sealed session is refused `400` before the source runs too — sealed by this gateway process, or, for a session this process does not hold in memory, sealed in the registry (§3) as §4 loads it: a seal whose `keyId` is the gateway's own and whose signature verifies under its public key, an empty registry and any discarded line establishing no seal — so a seal stays final across a restart. For such a session, a registry that cannot be read (§4.1) is a refusal too, never taken for the absence of a seal — and so is a registry that is not there, since the gateway made it when it started (§3); a session this process holds is judged by its own record of the seals it wrote, and a seal whose writing failed after the record may have reached the registry leaves that session sealed. |
| POST   | `/seal`     | `{session}` → seals the session's final count; returns the seal record. |

A gateway minting version 3 receipts answers `/acquire` with `{result, receipt,
salts}`: `salts` is an object with one member per commitment the receipt
carries, named by the commitment's label without its colon — `args` always, and
`statement` exactly when `acquisition.statement` is not `null` — each a 32-byte
salt in lowercase hex (§1.2a), returned here and nowhere else. Every `/acquire`
receipt is of kind
`"acquisition"`. A request may name `trail`, a trail identity of 32 lowercase
hexadecimal characters, and nothing else in that member — null, another type or
another form is refused `400` — for a receipt that names the witness the gateway's
operator names for that trail (§1.2a, `witness`); a trail the configuration names
no witness for is refused `400` before the source runs. A request names a trail and
never a witness, an origin or a key: those are the configuration's. The trail is the
request's: a caller can name another trail than the record that will cite the
receipt, and the witness named is still the configuration's for the trail named,
which a reader holds to the record's own trail ("Reading the witness a receipt
names", below). `POST /act` mints one of kind `"action"` (the engine of
`docs/adr/0001-one-engine-four-processes.md`, described in
`docs/design/executor.md`): from an authenticated request naming a platform's
write tool, the decision record the write relies on and the receipts that
record relied on, after the engine has found the cited receipts in its own
store under a key its own reading of its registry reached (§3b) — its own, or
one it rotated from — and the record under its decision-record directory —
the standard §4 applies — and, for a tool its operator holds to a decision
policy, after it has held the record and the request to that policy (§1.2a
`policy`). For a write through a binding that names a remote server's URL, the
receipt's `action.tool` names that URL, as the platform's parameters resolved
it, as its `endpoint`, and carries `transport` `"http"`; for a write through a
server the adapter runs, it names the platform's endpoint, or `null`, and no
`transport` (§1.2a, `tool.transport`). When its operator names a witness for a trail (§1.2a, `witness`), the
gateway reads the found record's `trail` too, from the bytes whose digest matched,
whatever the tool, and names that trail's witness on the receipt. The format was specified before the surface so that a verifier
written then verifies what is minted now. `gateway verify` takes
`--decision-records <dir>` for §4 steps 5 to 8.
| GET    | `/verify`   | → `{ok, findings}` from `verify_with_registry`, and `observations` when §4 step 8 has any and `rotations` when the walk of §3b followed any, against the registry the gateway made when it started (§3): a registry that is not there is no verdict here, never the absent registry of §4.1 that loads no seals. The key it verifies from is the one its own reading of §3b starts at, taken from its registry — a reason more that this answer is not evidence (§5a.3). |
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
  `observedAt` — and, from a source declared `mcp` whose adapter reached a remote
  server, `transport` and `server` besides (below) — each of the type and form §1.2a
  states for the receipt member of that name, except that `statement` is the
  statement text itself — the query, resource path or tool call — as a string, or
  `null`; `adapter` carries exactly `name`, `version` and `digest`, and `server`
  exactly `name` and `version`; and `observedAt` is of the form
  `YYYY-MM-DDThh:mm:ssZ` — UTC, whole seconds, the form `servedAt` takes — which
  is what this gateway accepts from an adapter, beyond the string a verifier
  checks for. It carries neither `shape` nor `pageItems`. (A
  verifier tolerates a member it does not know at any depth, since a signed one is
  the signer's own; the signer, reading an envelope, tolerates nothing it did not
  ask for.)
- `page`, when present, is `true`, and `result` is then an array of items: the
  receipt carries `pageItems`, the digest of each item's canonical form, in order.

**Shape `mcp`, by transport.** `adapter-mcp` reaches its server over stdio — a pinned
image or a local command — or over Streamable HTTP at a URL the operator fixed
(`docs/adr/0015-a-remote-mcp-server-as-a-source-and-executor.md`). Over stdio the
envelope carries the eight members and no others: `adapter` names the image, or the
command with the version the server gave itself and the digest of its executable;
`endpoint` is the host the operator named, or `null`; `peerIdentity` is `null`. For a
remote server it carries the eight and `transport` and `server`: `adapter` names
`adapter-mcp` itself, with the digest of its own executable; `endpoint` is the URL as
configured, of the form §1.2a states; `peerIdentity` is the identity of the TLS peer whose answer carried the
tool's result, or `null` over plaintext loopback; `transport` is `"http"`; and
`server` is the name and version the server gave itself, each held to its form as
§1.2a states. In both, `statement` is the call, `snapshot` and `upstreamToken` are
`null`, and `schema` is the tool's declared output schema, digested, or `null`. The
credential the adapter sends a remote server is never in the envelope, and neither
is the session id the server issues: both are the adapter's alone. An envelope
whose `transport` and `server` depart from §1.2a's forms, or that carries them from a
source declared with another shape, is refused like any other departure.

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

A gateway that is a witness (§8) — an engine whose configuration carries a `witness` member
(`docs/design/engine-config.md`) — answers five more endpoints, a submission, two reads and two
acts of its operator (below, "Administration"), and a gateway that is not one serves no path
under `/witness/`. They are the signer's, on the same loopback address as every other
endpoint. Three of them — the submission, `/witness/checkpoints`, and the two reads under
`/witness/trails/{trail}/` — are the first meant to be reached from other hosts by other
parties: through the TLS-terminating front that address requires (`SECURITY.md`). A front for
other parties is to pass those three and `GET /publickey`, open already, which a reader with no
pinned key fetches and holds to the key identifier a receipt names (below, "Reading the witness a
receipt names"), and no other path of the signer. It keeps the operator's
two acts, `/witness/registrations` and `/witness/trails/{trail}/retirement`, on the operator's
side, as it keeps the signer's other endpoints: a submitter's token is a token of the
configured issuer, which the signer's other endpoints that take a token take as well, and the
operator's acts take any token the engine takes, or, where `witness.operators` is given, the
token of an operator it names (below, "Administration"), so a front that passes all of
`/witness/` lets an engine-audience token from another host administer the witness — any such
token without the list, and a named operator's with it.

| Method | Path | Body / result |
|--------|------|---------------|
| POST | `/witness/checkpoints` | Submit. The body is `application/jsonl`: one or more checkpoint lines (§8.1) as `jpack audit checkpoint --since` prints them, each in its canonical form and ended by a newline, all of one trail, their sequences strictly increasing; at most 1 MiB (1048576 bytes), this gateway's request bound, and each line at most 4096 bytes, its newline not counted. A bearer token is required, and the trail must be registered to the token's issuer and subject (below). **Only the last line is signed**: the earlier lines are compared with what the witness holds, for conflicts, and otherwise discarded, and with them the evidence of what they said. `200`, `application/jsonl`: a `checkpoint` statement for the last line — the one already held for the same trail, sequence and digest, so that sending a checkpoint again gives the same statement and appends nothing, or a new one at the chain's next index. `409` with `reason` `"conflict"` and `statements`, two JSON strings each holding a statement's exact line: the `checkpoint` statement the witness holds at a line's sequence, and the `conflict` statement recording another digest offered for it — the first offered for that sequence, made durable and marked when it is made, which acknowledges nothing of the digest just sent. `409` with `reason` `"below-head"`, with the head statement, when the last line's sequence is below the latest checkpoint statement's and not held. `409` with `reason` `"retired"`, with the retirement statement. `400` for a body out of shape, `401` without a valid token, `403` for a subject the witness does not allow, or a trail not registered or registered to another subject, `413` over a bound, `415` for a body of another type, and `429` over the submitter's rate or, for a trail that holds no statement yet, over its number of trails. `503` when a statement signed could not be kept, after which the witness signs nothing more, for any trail, until it has restarted. |
| GET | `/witness/trails/{trail}/head` | The trail's last statement (§8.5), `application/jsonl`, exactly as the witness keeps it. `400` for a `{trail}` that is not 32 lowercase hexadecimal characters; `404` for a trail the witness holds nothing for, which reads as a trail never submitted (§8.8). |
| GET | `/witness/trails/{trail}/statements?from=<index>&limit=<n>` | The trail's statements from index `from` (0 when absent), at most `limit` of them (1 to 1000, 1000 when absent), in index order, `application/jsonl`, each exactly as the witness keeps it; none, from an index past the head's. `400` for a `{trail}` or a query out of shape, `404` as for the head. A reader asks again from the next index until it reaches the head's. |
| POST | `/witness/registrations` | The operator registers a trail, or changes its registration (below, "Administration"). The body is `application/json`, an object of exactly `trail`, `issuer` and `subject`, each a string, at most 1 MiB: the issuer the configuration's `identity.issuer` and, where `submitters` is given, the subject one of them, since a registration no token could match is refused rather than kept. `200`, `application/json`: `{"trail", "issuer", "subject", "changedFrom"}`, `changedFrom` the `{"issuer", "subject"}` the trail was registered to before, when that was another, and `null` otherwise; a registration the same as the one the trail holds is answered alike, and appends nothing. Each string is UTF-8 text with no lone surrogate escape, refused rather than rewritten. `400` for a body out of shape or a registration no token could match, `401` without an engine-audience token or with a submitter's, or where no identity is configured, `403` for one of a caller `witness.operators` does not name, `413` over the bound, `415` for a body of another type, `503` when the witness is stopped. |
| POST | `/witness/trails/{trail}/retirement` | The operator retires the trail (below, "Administration"). No body. `200`, `application/jsonl`: the trail's `retirement` statement, the last of its chain, repeating its latest witnessed checkpoint, as the head serves it from then on. `409` with `reason` `"retired"`, with the retirement statement, for a trail retired already, and nothing is signed; `404` for a trail the witness holds no statement for. `400` for a `{trail}` out of shape or a request with a body, `401` without an engine-audience token or with a submitter's, or where no identity is configured, `403` for one of a caller `witness.operators` does not name, `503` when the witness is stopped. |

**Answers.** A statement is answered `200`, `Content-Type: application/jsonl`, each statement
its canonical form (§8.2) exactly as the witness keeps it, ended by a newline. A refusal is
`application/json`, `{"error": <a sentence>, "reason": <a word>}`, and a `409` carries
`statements` too. The sentence is the witness's own, but for a `401`'s, which is the token
check's reason as every endpoint of this gateway gives it; none repeats a token or a file's
name. Every answer states its `Content-Length` and carries
`Cache-Control: no-store`. The reasons:

| Status | `reason` | When |
|---|---|---|
| `400` | `malformed` | a path spelled with any percent-encoding, a `{trail}` out of shape, a query a read does not take or a submission or an operator's act any query, a body out of shape, a registration no token could match, a retirement with a body; a spelling the server would otherwise clean (`//`, `/./`, `/../`) or `/witness` without its slash, which the witness answers itself, never by a redirect |
| `401` | `unauthenticated` | a submission without a valid token, or an operator's act without a valid engine-audience token or with a submitter's (below), with `WWW-Authenticate: Bearer` |
| `403` | `not-a-submitter` | a subject the configuration's `submitters` does not name |
| `403` | `not-an-operator` | an operator's act under an engine-audience token whose issuer and subject the configuration's `operators`, where given, does not name (below) |
| `403` | `not-registered` | a trail not registered, or registered to another subject: one answer for both, so that a submitter learns nothing of another's registration; and, where the first submission registers, a submitter whose issuer and subject no registration line of 4096 bytes can hold |
| `404` | `not-found` | a path under `/witness/` that is no endpoint |
| `404` | `unknown-trail` | a trail the witness holds no statement for |
| `405` | `method` | a method the table above does not name for the path, with `Allow` |
| `409` | `conflict`, `below-head`, `retired` | as the table says, with `statements` |
| `409` | `index-bound` | a trail whose chain is at index 2⁵³−2, the largest a statement holds |
| `413` | `too-large` | a `Content-Length` over 1048576, a body over it, or a line over 4096 bytes |
| `415` | `media-type` | a submission whose `Content-Type` is not `application/jsonl`, or a registration whose is not `application/json` (their parameters are not read) |
| `429` | `rate` | a submitter over its rate, with `Retry-After` (below) |
| `429` | `trails` | a submitter over its number of trails (below) |
| `500` | `internal` | an answer the witness could not make; the reason is on the signer's standard error |
| `503` | `busy` | as many submissions in flight as the witness takes, or as it takes from one submitter, an operator's acts counted among them, or as many reads, with `Retry-After: 1` |
| `503` | `stopped` | a submission or an operator's act to a witness whose writer failed (below) |

**A submission, in order.** Everything that needs no body is decided before a byte of it is
read: the method; that there is no query; the bearer token, verified as every other endpoint
of this gateway verifies one (`docs/design/engine-config.md`, `identity`); the subject, when the
configuration names `submitters`; the submitter's rate; the type; a `Content-Length` over the
bound; and a place among the 32 submissions the witness takes in flight, at most 4 of them one
submitter's, so that a submitter sending slowly holds no more. The body is then read
through its bound a line at a time, and each line is held as it arrives — a checkpoint in its
canonical form, ended by a newline, of the first line's trail, its sequence above the line
before's — so the first line that fails ends the read, with at most a line's bound read past
it. Then, under the one writer lock that the witness's log and marks are written under
(ADR-0013 §4): a witness stopped is `503`; the registration is checked; a trail that holds no
statement is refused at the submitter's number of trails; where the first submission
registers, a trail registered to nobody is then registered to the submitter, appended and
synced before anything is signed for it; and the answer is the table's, a statement being
answered only once it is published: its line appended and synced, its mark appended and
synced. A second
submission of the same checkpoint while the first is in flight waits at the lock and is answered
with the statement the first made.

**Registration.** A trail is registered to exactly one issuer and subject before anything is
signed for it: by the witness's operator, by default, or, where that operator opts in, by the
first submission accepted for the trail — which lets any subject the witness allows claim a
trail whose identity it has learned. A registration is never in a statement, and no read or
submission serves it: only the operator's own act is answered with it. A token establishes an
issuer and a subject and nothing more: every deliverer of one trail submits under the one
subject registered for it, and the witness cannot tell the trail's operator from a holder of
the operator's credential (§8.8).

**Submission tokens.** A submission's token names the witness's audience (`witness.audience`),
not the engine's: the witness verifies it as every other endpoint verifies one — issuer, keys and
validity window alike — under that audience, and refuses a token that names the engine's audience
alone. A token that names the witness's audience, with or without the engine's, or that is of a
subject among `witness.submitters`, is refused `401` by every other token-checked endpoint of the
signer, `/seal` among them, and by the MCP transport, with "a token for the witness is refused
here": a submitter's credential opens the witness and nothing else.

**Administration.** On a running witness, its operator registers a trail, or changes its
registration, and retires a trail at the two endpoints the table names. Each takes an
operator's token: a token the signer's other token-checked endpoints take, verified as they
verify one, under the engine's audience (`identity.audience`), and, where the configuration
gives `witness.operators`, of an issuer and subject the list names. A token the engine takes of
a caller the list does not name is refused `403` `not-an-operator`, with "an operator named by
witness.operators is required here"; a list present and empty names no one, so no token
administers the running witness, and the commands (below, "The witness's operator's acts")
remain for a stopped one. Where the list is absent, the witness tells its operator from a
submitter by the token's audience and subject alone, so any such token is the operator's here,
as it is at `/seal`: whoever holds an engine-audience token of the configured issuer, of any
subject not among `witness.submitters`, can at these two paths retire any trail it names, which
nothing undoes, and register any trail to any subject the configuration allows, taking it from
the submitter it was registered to, who is then refused `not-registered`. A named operator's
token can do the same, and so can whoever holds it: the list says which callers may, not who
holds their credentials, and the signer's other endpoints, `/seal` among them, take any token
the engine takes as before. That is why a front for other parties does not pass the two paths,
with the list or without it (above). A submitter's token — one naming the witness's audience,
with or without the engine's, or of a subject among `witness.submitters` — cannot register or
retire anything: it is refused `401` with "a token for the witness is refused here", and a
submission refuses an operator's token in turn, since it names the engine's audience alone. No
operator may be among `witness.submitters`, so the two roles stay apart. Each act is decided,
before a byte of a body is read, on its method, its query, its token and, where the list is
given, whether it names the token's caller; then a
registration on its type and the length it states, and a retirement on its trail and on having
no body; then on a place among the submissions in flight, its caller counted by issuer and
subject as a submitter is there. No rate counts it: the submitter's rate (below) counts
submissions alone. It then writes under the one writer lock a submission writes under, and is
answered only once what it wrote is kept: a registration once its line is appended to the
registrations and synced, after which the next submission for the trail is judged by it — one
the same as the trail holds already, being kept already, appends nothing; a retirement once
its statement is durable and marked, and so published, after which a submission for the trail
is `409` `retired`. The retirement is the statement `gateway witness retire` signs over the same
files. A witness whose writer failed refuses both, `503` `stopped`, and a registration whose
append or sync fails stops the writer as a statement's does. Repair has no endpoint.

**Rate.** The witness's operator bounds each submitter — an issuer and a subject — to a number
of submissions a minute, from 1 to 6000, 60 by default: counted when each arrives, after its
token and before its body is read, whatever becomes of it, in windows of the witness clock's
whole minutes, the same for every submitter; past the bound a submission is `429` with
`Retry-After`, the seconds until the minute turns. One minute counts at most 65536
submitters, and one not yet counted in a minute that has counted that many is refused alike
until it turns. The operator bounds the trails each submitter submits for too, from 1 to
100000, 100 by default: counted as the trails registered to the submitter that hold a
statement and are not retired, so that a submission for a trail that holds none is `429` when
the submitter has that many, and registers nothing; a retirement gives its trail's place back.

**After a failure.** When a statement's append, its sync, its mark or the mark's sync fails, or
a registration's append or sync, where the first submission registers or the operator registers
on a running witness, the witness signs nothing more, for any trail, until it restarts and its
start-up checks pass (§8; ADR-0013 §4). That submission and every one after it is `503`, a
statement the witness holds and the head a line falls below included: a statement signed after
that head may have been made durable and marked, and is served after the restart. The reads go
on serving what was published. The signer's standard error says, once, which step failed.

**Reads are open.** The two reads need no token, as `/registry` and `/publickey` need none:
a verifier holds no token, and a read does not look at one. Naming a trail is what lets one
read it, and no endpoint lists trails; whoever holds one of a trail's checkpoints can
therefore follow its continuing activity (§8.8). A read serves only statements the witness
published, of a log its start-up checks passed, and never bytes a repair set aside or a
registration: a trail registered and not yet signed for is `404` as a trail never named is.
The reference bounds how many reads it answers at once, 64, past which a read is `503`, and how
long any answer of the witness's may take to be written: 30 seconds from the moment its request
is handled, after which it is abandoned. It bounds no reader's rate, since a read carries no
identity. A witness reached from other hosts sits behind the TLS-terminating front
`docs/design/engine-config.md` requires for any other host, and that front bounds reads.

**Retention.** A witness keeps every statement it signs for as long as it runs: this
reference prunes nothing and removes nothing, and serves a retired trail's chain as before. A
party that runs a witness publishes how long it keeps a trail; removing a trail's statements is
not something this reference does (ADR-0013, question 4).

**The witness's operator's acts.** `gateway witness register --config <engine.json> --trail
<id> --issuer <issuer> --subject <subject>` registers a trail, or changes its registration,
appended and synced and never served; the issuer must be the configuration's `identity.issuer`
and, where `submitters` is given, the subject one of them, since a registration no token can
match is refused rather than kept. `gateway witness retire --config <engine.json> --trail <id>`
signs the trail's retirement, the last statement of its chain, repeating its latest witnessed
checkpoint, made durable and marked like any statement, and prints its line; a trail retired
already is answered with its retirement, and nothing is signed. `gateway witness repair
--config <engine.json>` does what ADR-0013's three rules of recovery allow and nothing else,
and prints `{"outcome", "findings", "repaired", "starts"}`, exiting `0` when the witness can
then start and `1` when it cannot — when only a log copy that passes the checks against the
marks, or a new key, lets it go on. Each takes the witness's files as the witness does, each locked by what it is
and with exactly one name. A running witness holds them for as long as it runs, so an act on
a running witness says so, changes nothing and exits `1`; `register` and `retire` then name
the endpoint at which the running witness does the same ("Administration"), and repairing the
files alone takes a stop of the witness.

### Reading the witness a receipt names

A receipt may name the witness its trail is registered with (§1.2a, `witness`;
`docs/adr/0014-a-receipt-names-the-witness.md`). A verifier's report lists what the receipts
that passed name (§4, `witnesses`); a reader then reads the chain, after a verdict it acts on
(§5a.1), online, in these steps, which no vector holds — the corpus holds the member and the
report, and this surface has one implementation, held by its tests and an end-to-end scenario in
CI:

1. It takes each `{trail, origin, keyId}` whose trail is the record's; with none, "No receipt
   names a witness for this trail." Several, after a change of witness, are each read and
   reported apart.
2. It holds `origin` to `https`; to `http`, at a loopback address, only when the reader asks, for
   its own machine and for tests — otherwise **`witness-origin-refused`**, and nothing is read.
3. The key is the reader's pinned key whose identifier is `keyId`; otherwise the `publicKey` of
   `GET <origin>/publickey`, no redirect followed, held to §8.4's rule and to `keyId` — otherwise
   **`witness-key-not-named`**, and nothing from that origin is read. The report says which. The
   key is never the receipt's: a receipt names a key and carries none (§5).
4. It fetches `GET <origin>/witness/trails/{trail}/head`, held to its form — exactly one
   statement line of §8.2's form, ended by a newline — then `/witness/trails/{trail}/statements?from=`
   from index 0, or after this witness's own continuation, a page at a time until a page is
   short, each page statement lines of that form, within §8.7, with no token and no redirect.
   The form is all it holds: a signature, a key or a trail that is wrong is the runtime's
   finding, never the reader's.
5. It runs the runtime's reader, `jpack audit verify --trail <file> --witness-key <key> --witness
   <statements> --witness-head <head>`, with `--witness-resume`, `--witness-save` and
   `--require-countersigned-through` as the reader chooses, a continuation of each witness's own,
   by its `{trail, origin, keyId}`, so that after a change of witness one witness's continuation
   is never handed to another's reading. The runtime's report — `countersigned`, its `witness`
   section, its sentences — is the reading.

When the witness cannot be reached — no answer, a timeout — or answers outside its form — a
redirect, a status or a type a read does not take, a head or a page not of the form above — the
runtime reads, without a head, the statements the reader holds, under its pin, and the reading is
historical, as far as supplied; with no pin there is no key, and with none held nothing is read.
The reading says which: "The witness the receipts name could not be reached.", or that it
answered outside its form, and how. When it refuses a read — the head or any page of
statements, the first or a later one, answered as §6's "Answers" give a refusal — nothing is
read and nothing credited, the runtime is not run whatever the reader holds, and the refusal's
status, reason and sentence are given as it gave them, with the read it refused. A `404`
`unknown-trail` reads as a trail never submitted (§8.8): "The witness the receipts name holds
nothing for this trail." When it serves another key than the one named, the
reading is `witness-key-not-named`; statements of its own under the key named are
`witness-signature-invalid` to the runtime, the key named being the only one supplied. Two fixed
sentences join every reading: "The operator's gateway named this witness for this trail under its
own key at T; that is not a statement of the witness.", T each `servedAt` of the receipts naming
it; and, for a served key, "The key was served at an origin the operator's gateway named, so this
reading is as independent of the operator as the operator's choice of witness."

`gateway witness fetch --store <dir> --registry <file> --authority <label> --public-key <file>
[--decision-records <dir>] --record <file> --trail <file> --runtime <path> --out <dir>
[--witness-key <file>]... [--statements <file>]... [--allow-loopback]
[--require-countersigned-through <sequence>] [--witness-save <dir>] [--witness-resume <dir>]`
is this reference's reader: it verifies the store as `gateway verify` does, under the operator's
gateway key pinned out of band, refuses to read anything unless the verdict is `ok`, takes the
record's trail from the record (a runtime evaluation record, one line), writes what it fetched and
the key it used under `--out`, and prints `{trail, witnesses}`, each reading its `origin`, `keyId`,
`namedAt`, `key` (`"pinned"`, `"served"` or `null`), `outcome` (`read`, `unreachable`,
`answer-not-of-form`, `refused`, `witness-key-not-named` or `witness-origin-refused`), whether a
head was handed over, the witness's `refusal` as given (`at`, `status`, `reason`, `error`), the
name of its `continuation` in the directories `--witness-resume` and `--witness-save` name, the
sentences, and the runtime's `report` as it wrote it, with its `exit`. It
exits `0` whenever it gave a report, as `gateway verify` does (§5a.2). The runtime is named by its
path, version 0.28.0 or later.

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
to the corpus without depending on this one. Findings are compared as a multiset: **order is not normative.** Observations (§4) are not compared; witnesses (§4) are, as a set; rotations (§4) are, whole.

The store vectors of §3b's walk are signed under the test seed and under two further
keys, the keys rotated to, whose seeds `corpus/README.md` states as it states the
test seed's; they are verified from `corpus/TEST-PUBLIC-KEY` alone, as a verifier
verifies a rotated store from the one key it pinned.

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
reference keeps it in its core, on Unix, held to the vectors under `corpus/witness-recovery/`
(§7). `gateway witness verify --log <file> --public-key <file> [--marks <file>]` applies
those checks, all but the registrations, to a copy of a witness's log, and gives its
verdict in its JSON as `gateway verify` does (§5a.2): exit `0` whenever it reached one.
The service that answers submissions and serves statements is this reference's too: the
endpoints of §6, the configuration that makes a gateway a witness, and the witness's
operator's acts, `gateway witness register`, `retire` and `repair`, and, on a running witness,
`POST /witness/registrations` and `POST /witness/trails/{trail}/retirement` (§6, "Witness
endpoints").
A reader holds a statement to this section alone, whatever served it.

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
receipts and seals, so a statement's `keyId` is the gateway's own, and after a rotation
(§3b) the key rotated to — over
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
of band (§5) — or, for a key the witness's gateway rotated to, from a continuity
statement it followed from such a key (§3b, §8.5) — and holds each to the runtime's
public-key rule before it reads anything signed. 32 bytes are a key a reader may trust exactly when they are the canonical encoding
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

**A rotation.** When the witness's gateway rotates its key (§3b), the witness's chains go
on. For each trail, the first statement it signs after the rotation is at the next index,
names the last statement's `signature` as its `prevSignature`, and carries the key id of
the key rotated to: one chain, across the hop. This is not the new key of
`docs/adr/0013-checkpoint-witness.md` §4, rule 3, under which chains begin again at
index 0: a rotation is a succession the key rotated from signed. A reader (§8.6)
supplies the key rotated to beside the key it pinned, taking it only from continuity
statements it holds to §3b's walk from that key — the registry the witness's gateway
serves (§6) holds them — so that a key a walk refuses is never supplied; the reading is
unchanged, each statement checked under the key its `keyId` names among those
supplied. Such a reader holds no statement to the place of the hop: the holder of a
key rotated from can sign a statement it accepts at any index, and two statements at
one index that differ are still `witness-equivocation`. The witness's own checks — its
start-up checks and `gateway witness verify --registry <file>` — hold its log to the
walk: every statement under a key the walk reached, and none under a key it reached
before the key of a statement above it in the log, since after a rotation the witness
signs under the key rotated to alone; a statement that is not so is
`witness-signature-invalid`. Given a registry whose walk finds anything, `gateway
witness verify` refuses, `{"refused": <the walk's status>}`, before the log is read, and
a witness does not start.

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
