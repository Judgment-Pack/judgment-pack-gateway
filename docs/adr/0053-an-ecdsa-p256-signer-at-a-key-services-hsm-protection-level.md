---
status: proposed
date: 2026-11-20
deciders: maintainer
---

# An ECDSA P-256 signer at a key service's HSM protection level, beside Ed25519

## Context and problem statement

ADR-0050 signs with a Cloud KMS key version of `EC_SIGN_ED25519`, which the service offers only at its
software protection level (FIPS 140-2 Level 1). Its hardware protection level (Level 3, an HSM key)
holds elliptic-curve keys of P-256, P-384 and secp256k1 only. ADR-0050 left Level 3 as a later change,
because it needs a second signature algorithm in the format and in every verifier (#562). This record
fixes that signed format before anything is built. It is a design record, and nothing here is built yet.

**Decided by the maintainer on 2026-11-20.**

1. **Scope.** All of it ships in v0.38.0:
   - the gateway signs with a Cloud KMS `EC_SIGN_P256_SHA256` key version at the `HSM` protection level;
   - receipts, seals, rotation statements and key-history entries name the algorithm;
   - `gateway store rotate-key` and the file kind's rotation move a gateway from Ed25519 to P-256, and the
     key history records the move;
   - the Go verifier and verify-ts accept both algorithms;
   - `retention.acknowledgedBy` accepts P-256 keys;
   - the corpus gains verify-only P-256 vectors: a receipt, a seal, a rotation from Ed25519 and an
     acknowledgment line.

   Ed25519 stays the default, and nothing about it changes.
2. **The member.** A member names the algorithm on P-256 records only. When it is absent the record is
   Ed25519, so every Ed25519 record stays byte for byte what it is today. A verifier of an earlier release
   refuses a P-256 record and never reads it as valid.
3. **The signature.** It is fixed-width `r||s`: 64 bytes, written as 128 lowercase hexadecimal
   characters, low-S only. The signer normalizes it, and verifiers refuse a high-S signature and a DER one.
4. **The key id.** A P-256 key's `keyId` is the first 32 lowercase hexadecimal characters of SHA-256 over
   its 33-byte compressed point. A P-256 public key is published as that point, in 66 lowercase hexadecimal
   characters.

## Decision drivers

- **Ed25519 is unchanged.** Every record an Ed25519 key signs keeps its bytes, and every Ed25519 store
  verifies under v0.38.0 exactly as before.
- **The algorithm is signed.** Stripping or changing it invalidates the signature.
- **The record names its algorithm.** A verifier picks the algorithm from the record's `alg`, never from
  the length of a key alone. A compressed secp256k1 point is also 33 bytes, so length cannot tell the
  curves apart.
- **Earlier verifiers fail closed.** A verifier of an earlier release refuses every P-256 record. Its
  refusal is one of the findings it already reports, never a pass.
- **One encoding per signature.** A signature's bytes are named elsewhere: `prevSignature`,
  `sealSignature`, `receiptSignature`, `cites[*].signature`, and the acknowledgment's `sealSignature`. A
  second valid encoding of one signature, such as `(r, n − s)` or a DER form, would be a second name for
  one signed record, so it is refused.
- **ADR-0050's rules stand.** The gateway never holds the private key, and every signature is verified
  before anything is written with it.

## Considered options

1. **`alg` on P-256 records only.** This is the maintainer's decision (decision 2).
2. **P-256 everywhere**, replacing Ed25519.
3. **An algorithm member on every record**, Ed25519 records included.
4. **A separate signing prefix for each algorithm**, with no member.
5. **The algorithm taken from the key's form**, with no member and no prefix.

## Decision outcome

Option 1.

### 1. The member, and where it sits

**The member is `alg`, and its one value is the string `"ES256"`.** That is the JOSE name (RFC 7518
§3.4) for ECDSA over P-256 with SHA-256, and its signature form is exactly `r||s`, 64 bytes. Every
signature made here is a valid JOSE ES256 signature. This format is stricter than JOSE, because it also
requires low-S.

- **Where it sits.** `alg` is a top-level member of the record. It is present exactly when the key that
  signs the record is a P-256 key. When it is absent, the key is Ed25519.
- **Other values.** Any other value is refused, wherever the member sits. That includes `"EdDSA"`,
  `"Ed25519"`, `"es256"`, any other string, and a value that is not a string. This keeps one encoding for
  each record: an Ed25519 record never carries the member.

**Members that name another key.** Where a record names a key other than the one that signs it, a member
beside that key names the key's algorithm on the same rule. Only rotation statements do this:

- `nextAlg` sits beside a `key-rotation`'s `next`;
- `previousAlg` sits beside a `key-continuation`'s `previous`.

Each is present exactly when the key named is a P-256 key, and its value is then `"ES256"`. Each is inside
the signing input of the statement that carries it.

**Within the signing input, on every kind.** `alg` is signed on every kind. Every kind but one signs
everything except its signature, so `alg` is covered with no change to the signing input. The exception is
the seal of SPEC.md §3's form, which signs exactly four named members. A P-256 seal of that form signs five:
`alg`, `finalCount`, `keyId`, `sealedAt` and `sessionId`, under the same prefix. The table below lists every
kind.

**How a verifier picks the algorithm.** It reads the record's `alg` (absent means Ed25519), takes the key
its `keyId` names among the keys it holds, and verifies only when that key is of the algorithm `alg` names.
Otherwise it reports the kind's own key failure.

Each key a verifier holds carries the algorithm it was given with:

- the pin;
- a rotation's `nextAlg` or `previousAlg`;
- a key-history entry's `alg`;
- a `retention.acknowledgedBy` entry.

A key's length or form is then only checked against that algorithm. It never chooses the algorithm.

**Receipts of version 2.** They stay Ed25519 alone. A gateway configured for `ES256` mints version 3 only,
and a configuration that asks for version 2 beside it is refused. A version 2 receipt carries no `alg`: one
that holds the member, of any value, is refused as `malformed` (SPEC.md §1.2, §1.4 order 1), and it is never
verified as ES256. This is one reading for both rules: dispatch by `alg` (above) never reaches a version 2
receipt. It tightens v0.37.0, which tolerates the member as one it does not know; no gateway has written a
version 2 receipt holding it.

### 2. The signed record kinds, and how the list was derived

**How the list was derived.** The list comes from the code, not from memory:

1. Every string literal of the form `judgment-pack-gateway/<name>/<n>:` in the gateway module's non-test
   Go was listed. There are 21 distinct prefixes, plus `action-intent/1`, which is built by concatenation in
   `go/action_execution.go:17`.
2. Each was sorted by its call site into one of two groups:
   - fed to a signature, through `signingKey.signVerified`, `ed25519.Sign` or `ed25519.Verify`;
   - fed only to `sha256.Sum256` or an HMAC key, which makes it a digest or key domain and not a signature.
3. Every call of `signVerified`, `ed25519.Sign` and `ed25519.Verify` was then listed, to find what is signed
   under a key other than the gateway's own.
4. verify-ts's prefix literals were checked against the result, and they match.

The digest and key domains are `arguments-key/2`, `seal-scope/1` and `/2`, `session-label/1`,
`action-intent/1` and `action-recovery/1`. They are not signatures and do not change.

**Kinds the gateway's key signs, and kinds another key signs:**

| Kind | Prefix | Signed at | Signing input | Where `alg` sits |
|---|---|---|---|---|
| Receipt of version 3: an acquisition's, and an action's from `/act` | `receipt/3:` | `go/store.go:184` | everything but `signature` | top level, signed |
| Seal of §3's form | `seal/2:` | `go/store.go:470` | four named members (`go/verify.go:256`) | top level; the P-256 input names five members, `alg` among them |
| Seal of version 2 and of version 3 | `seal-version/2:`, `/3:` | `go/store.go:510` | everything but `signature` | top level, signed; eight members instead of seven |
| Seal after an interruption, versions 1 to 3 | `seal-after-interruption/1:` to `/3:` | `go/store.go:575` | everything but `signature` | top level, signed |
| Key-rotation and key-continuation statements | `rotation/1:` | `go/rotate_serving.go:46` and `:52`; `go/rotate_key.go:235` (the seed only) | everything but `signature` | `alg` names the statement's signer; `nextAlg` or `previousAlg` names the key the statement names; all signed |
| Store continuation | `store-continuation/1:` | `go/store_continuation.go:185` | everything but `signature` | top level, signed |
| Artifact-removal record | `artifact-removal/1:` | `go/remove_artifact.go:470` | everything but `signature` | top level, signed |
| Session-removal and scope-removal records | `session-removal/1:`, `scope-removal/1:` | `go/remove_scope.go:459` and `:490` | everything but `signature` | top level, signed |
| Descriptor statement | `descriptor-statement/1:` | `go/descriptor_provenance.go:80` | everything but `signature` | top level, signed |
| Retention acknowledgment line (signed by the acknowledging log's key, read by `gateway retain`) | `retention-ack/1:` | outside the gateway; `go/retain.go:674` is the tests' and the documentation's helper | everything but `signature` | top level, signed |
| Witness statement | `witness/1:` | `go/witness_log.go:1207` | | none: the seed signs it, always Ed25519, and it is refused beside `signingKeyVersion` (`go/engine.go:909`) |
| Delegation statement (SPEC.md §11) | `judgment-pack/delegation/1:` | the delegating host | | none: the host's key, not the gateway's |
| Runtime record signature (ADR-0012) | `judgment-pack-runtime/record-signature/1:` | the runtime | | none: the runtime's key |

**The key-history answer.** The `/publickey/history` answer (SPEC.md §3e) is not signed itself. It carries
the rotation statements above, and its entries gain `alg` (decision 8).

### 3. What a verifier of v0.37.0 does

Both verifiers of v0.37.0 hold every kind but two to its exact members. Those two, the receipt and the seal
of §3's form, tolerate a member they do not know. So the refusal comes about in one of two ways:

- **An exact-member kind** refuses `alg`, `nextAlg` or `previousAlg` as a member it does not list.
- **A tolerant kind** refuses through its key id. A P-256 record's `keyId` names a key that no walk of
  v0.37.0 can reach.

Neither path reads a P-256 record as valid.

| Kind | Go verifier of v0.37.0 | verify-ts of v0.37.0 | Outcome |
|---|---|---|---|
| `key-rotation` naming a P-256 `next` | `isLowerHexOfLen(namedHex, 64)` fails, and exact members refuse `nextAlg` (`go/rotation.go:88-107`) | `hex64` and exact members (`verify-ts/src/rotation.ts:78-85`) | `rotation-break` (`go/rotation.go:313`); the walk stops at the last Ed25519 key |
| `key-continuation` carrying `alg` | exact members (`go/rotation.go:88`) | exact members | `rotation-break` |
| Receipt of version 3 carrying `alg` | tolerated as a member, but its `keyId` names no reached key (`go/verify.go:1434-1442`) | the same (`verify-ts/src/verify.ts:635-640`) | `key-mismatch` |
| Seal of §3's form carrying `alg` | `loadSeal` tolerates members, but the `keyId` is not the current key's (`go/rotation.go:381`) | the same (`verify-ts/src/verify.ts:798`) | loads nothing; the session is `unregistered-session` |
| Seal of version 2 or 3, and seal after an interruption | exact members (`go/rotation.go:424`, `:461`) | exact members | loads nothing |
| Store continuation | exact members (`go/store_continuation.go:82`) | exact members (`verify-ts/src/verify.ts:1811`) | the continuation does not load: a §3d finding |
| Artifact-, session- and scope-removal records | exact members (`go/retention.go:222`, `:259`, `:399`) | exact members (`verify-ts/src/verify.ts:424`, `:484`) | the record does not load: `artifact-missing` or `sealed-session-missing` |
| Descriptor statement | exact members (`go/descriptor_provenance.go:122`) | exact members (`verify-ts/src/descriptors.ts:36`) | the statement fails |
| Acknowledgment line | exact members (`go/retain.go:191`), and `acknowledgedBy` takes 64-hex strings only (`go/retain.go:106`) | not read | refused with "does not hold exactly an acknowledgment's members" |
| Key-history answer with a P-256 entry | exact members and a 64-hex `publicKey` (`go/key_history.go:33`, `:239`) | not read | refused |

**Pins.** A verifier of v0.37.0 cannot pin a P-256 key at all. `gateway verify` takes 32 raw bytes on
standard input (`go/main.go:299-312`), and verify-ts builds every key as an Ed25519 key
(`verify-ts/src/rotation.ts:38`).

**No panic.** Go's `ed25519.Verify` panics on a key that is not 32 bytes. Every call site of v0.37.0 holds
keys that are 32 bytes, from the pin or from a 64-hex member checked first, so a P-256 record cannot reach
the call.

**So nothing more is needed in an earlier release.** Its refusals are its existing findings, which name
neither the algorithm nor `alg`, because it does not know them. The build must keep the panic in mind:
every call of `ed25519.Verify` in v0.38.0 is reached only after `alg` has been read and the key's algorithm
checked to be Ed25519. Seven sites call it today with no length check of their own (`go/rotation.go:384`,
`:597`, `:692`; `go/verify.go:1450`; `go/retention.go:185`; `go/descriptor_provenance.go:151`;
`go/retain.go:221`). The build routes every one through one verify-by-algorithm function, which holds the
key's algorithm to `alg` and the key's length to that algorithm before any library call; no other
signature check remains.

**An earlier gateway.** It refuses a version-40 configuration by its version (`go/engine.go:479`,
"unsupported engineVersion"). Started on a store or registry that holds P-256 records:

- its own walk stops at the rotation with `rotation-break`, so it does not start (SPEC.md §3b, "The
  gateway's own reading");
- on a store that a P-256 key signed from its first receipt, `heldUnderAnotherKey` refuses the start
  (`go/key_service_signer.go:406`).

### 4. The signature, the key and the key id

- **The key.** A P-256 public key is its compressed SEC 1 point: the byte `02` or `03`, which gives the
  parity of y, followed by the 32 bytes of x, big-endian. That is 33 bytes, written as 66 lowercase
  hexadecimal characters. It holds the key rule when:
  - its first byte is `02` or `03`;
  - x < p;
  - x³ − 3x + b is a square modulo p, so the point exists.

  The uncompressed form (`04`) is refused, and so is any other length. The curve's cofactor is 1, so a
  point that exists has order n, and there is no small-order case to refuse.
- **The key id.** It is the first 32 lowercase hexadecimal characters of SHA-256 over those 33 bytes. Keys
  of the two algorithms hash preimages of different lengths. A walk still refuses a key whose id it has
  already reached, whichever algorithm that key is.
- **The signature.** It is `r||s`: each a 32-byte unsigned big-endian integer, 64 bytes in all, written as
  128 lowercase hexadecimal characters. It verifies when:
  - 1 ≤ r ≤ n − 1;
  - 1 ≤ s ≤ (n − 1)/2, the low-S rule (n is odd, so (n − 1)/2 is ⌊n/2⌋);
  - ECDSA verification of SHA-256 over the kind's signing input holds under the key (FIPS 186-5).

  A high-S signature does not verify. A DER signature is 70 to 72 bytes, so it is not of the form, and it
  fails at each kind's existing check of the signature's form. For example, it is `malformed` in a
  version 3 receipt, whose signature must be exactly 128 lowercase hexadecimal characters (SPEC.md §1.2a).
- **Lowercase on every kind.** A P-256 signature is checked as 128 lowercase hexadecimal characters on
  every kind. Where a kind accepts either case today (the §3 seal's signature, `go/rotation.go:369`;
  verify-ts's `signed`), the build adds the lowercase check for P-256 records. An Ed25519 §3 seal stays
  lenient, unchanged, so no Ed25519 store verifies differently.
- **Signatures are not reproducible.** Two ES256 signings of one input differ. Nothing in the format makes
  a signature again in order to compare it with one made before. `gateway rotate-key --resume` rebuilds a
  record and compares it byte for byte, but only for the seed's records, which are Ed25519. The build must
  keep it so.

### 5. The key service

**At start**, the public key is read once, as in ADR-0050. For a key of `ES256` the answer must:

- name the version asked;
- answer the algorithm `EC_SIGN_P256_SHA256`;
- answer the protection level `HSM`;
- carry a PEM whose CRC32C is the one answered;
- hold in that PEM one SubjectPublicKeyInfo of `id-ecPublicKey` on `prime256v1`, with an uncompressed point
  that is on the curve.

The gateway then compresses the point (§4), derives the `keyId` from the compressed point, and holds the
compressed point to `signingPublicKey`. Anything else is ADR-0050's fixed sentence for a public key, and
the gateway does not start.

**Signing.** `asymmetricSign` is asked with `digest.sha256`, the SHA-256 of the signing input, and
`digestCrc32c`. The service hashes nothing for this algorithm, and the signing input does not leave the
gateway. The answer must:

- name the version;
- report `verifiedDigestCrc32c: true`;
- carry a signature of at most 72 bytes whose CRC32C is the one answered.

**The DER answer is turned into `r||s`:**

1. Parse it strictly: one SEQUENCE of two INTEGERs, minimally encoded and positive, with no byte after it.
2. Hold each integer to 1 ≤ v ≤ n − 1.
3. Where s > (n − 1)/2, replace s with n − s.
4. Left-pad each integer to 32 bytes.

**Verified before return.** `signingKey.signVerified` then verifies the 64 bytes under the key read at
start, by the same check a verifier makes, low-S included, before anything is written with them. A
signature that fails is ADR-0050's "does not verify" sentence, and nothing is minted. ADR-0050's
deadlines, latch, token, host and failure sentences apply unchanged.

### 6. Engine configuration version 40

**Recommended: a new member, `signingKeyAlgorithm`.** Its absence means Ed25519, as before, and its one
value is `"ES256"`. It is taken from version 40 and only beside `signingKeyVersion`. Beside the seed alone
it is refused by name, because the seed stays Ed25519.

**What `signingPublicKey` holds** follows the member:

- 64 lowercase hexadecimal characters when the member is absent, as in ADR-0050;
- 66, the compressed point, when it is `"ES256"`.

Each form is refused under the other.

**Each half is held to the other.** The service's answered algorithm is held to the member:

- `EC_SIGN_P256_SHA256` for `"ES256"`;
- `EC_SIGN_ED25519` otherwise.

So a version name mistyped onto another key in the ring is refused, with a sentence that names neither key.

**Why not take the algorithm from the service's answer, held only to `signingPublicKey`'s length.** Three
reasons:

- **The configuration should name the algorithm.** It then states what the gateway's records will carry,
  just as `signingPublicKey` states their key. The start learns the format it mints from the operator,
  not from a remote answer.
- **The pin then binds both the key and the algorithm.** A 33-byte compressed point can be valid on P-256
  and on secp256k1 alike, so its length is not an algorithm (driver 3).
- **Every surface reads it in one place.** The SIGHUP rotation, `/posture` and the start line read the
  algorithm where the operator wrote it.

**The cost** is one more member to keep in step. A pair that is out of step is refused at load, before the
service is asked.

**Beside the member:**

- `receiptVersion` `"2"` is refused, because an `ES256` gateway mints version 3 only.
- `witness` is refused, as `signingKeyVersion` already is.
- On the file kind, the SIGHUP rotation (ADR-0050, decision 3(a)) takes three members:
  - `signingKeyVersion`;
  - `signingPublicKey`;
  - `signingKeyAlgorithm`.
- `gateway store rotate-key` gains `--from-key-algorithm ES256`, beside `--from-key-version` and
  `--from-public-key`. When it is absent, the key rotated from is Ed25519.
- `keyServiceSignerVersion`'s neighbour constant, `p256SignerVersion = "40"`, is the one to renumber if
  another version lands first.

**An earlier gateway** refuses a version-40 file by its version (§3 above).

**The protection level is checked, not only documented.** For `ES256` the start refuses, by name, any
answered protection level but `HSM`. An Ed25519 key version keeps the software level ADR-0050 gives it.

- `SOFTWARE` is refused, because a P-256 key at that level buys nothing over ADR-0050's Ed25519 key and
  still costs every verifier a second algorithm;
- `EXTERNAL` and `EXTERNAL_VPC` are refused, because they are not this decision's Level 3.

Each refusal names the level the service answered and the one required.

The start line and `/posture` name the algorithm and the protection level. The level is the service's own
report, read over the pinned TLS connection. It is not attested here, and no record carries it, so a
verifier cannot tell it from a receipt (see "What is not established").

### 7. Rotation across algorithms

The two statements of a rotation (SPEC.md §3b) are each signed under their own key's algorithm. Each
statement's `alg` names its signer's algorithm.

**Ed25519 to P-256.**

| Statement | Signed by | Carries | Also carries | Carries no |
|---|---|---|---|---|
| `key-rotation` | the Ed25519 key, the seed or an Ed25519 key version | `next` (66 hex), `nextAlg: "ES256"` and `nextKeyId` | | `alg` |
| `key-continuation` | the P-256 key version | `alg: "ES256"` | `previous` (64 hex) and `previousKeyId` | `previousAlg` |

**P-256 to P-256.** Both statements carry `alg`. The `key-rotation` carries `nextAlg`, and the
`key-continuation` carries `previousAlg`.

**Back to Ed25519.** The format also allows a rotation from P-256 back to Ed25519, by the same rule, and
the gateway does not refuse it, since refusing it would block a rollback. `store rotate-key` (and the
filesystem kind's rotation) prints one stderr line naming the step as a move from an HSM key to a key
that is not one. The key history records it as it records any rotation: the new entry carries no `alg`.

**The walk.** §3b's five checks stay, with the algorithm added to each:

1. **Form (`rotation-break`).** The statement holds its form, with the optional members above.
2. **Signer (`rotation-forged`).** The `key-rotation`'s `alg` is the current key's algorithm, and its
   signature verifies by it.
3. **Order (`rotation-order`).** Unchanged.
4. **The key named (`rotation-key-refused`).** `next` holds the key rule of the algorithm `nextAlg`
   names, and its key id is none of a key reached, whatever that key's algorithm.
5. **The pair (`rotation-break`).** The `key-continuation`'s `alg` is the `key-rotation`'s `nextAlg`, both
   absent or both `"ES256"`. Its `previous` and `previousAlg` are the current key's bytes and algorithm,
   and its signature verifies under `next` by that algorithm.

A key reached carries its algorithm from then on. **The gateway's own reading** starts at the first
`key-continuation`'s `previous`, with its `previousAlg`.

**Signing the statements.** `rotationRecordSigned` signs the forward statement through the current signer
and the reverse statement through the next. Each signature is verified under its own key's algorithm
before the append, as ADR-0050 orders. `gateway rotate-key`, with the gateway stopped, stays seed to seed,
Ed25519 only.

**`heldUnderAnotherKey`.** It is unchanged in meaning. It compares the `keyId` of each record, and of the
first receipt of each series, with the keys the walk reached. A key reached is now an (algorithm, key)
pair, and the gateway's own key is compared as a pair too. A store signed under Ed25519 and restarted
under an `ES256` configuration is therefore refused at start until it is rotated, as ADR-0050 already
refuses one key moved to another.

**The key history's order rules** follow the walk, entry by entry (decision 8).

### 8. The key history and `/publickey`

**Key-history entries** (ADR-0052, SPEC.md §3e) gain an optional `alg`:

- It is present exactly when the entry's key is P-256, and its value is then `"ES256"`.
- The entry's `publicKey` is then the 66-character compressed point, and its `keyId` the P-256 key id.

`keyHistoryVersion` stays `"1"`. A history of Ed25519 keys alone is byte for byte what it is today, and so
are the carried `.key-history` bytes and every `keyHistoryDigest` that names them. A consumer of v0.37.0
refuses a history holding a P-256 entry (§3 above).

**A consumer's check with mixed algorithms** is §3e's check, with five additions:

- Each entry's key holds the key rule of the entry's algorithm.
- Each later entry's `keyRotation` has an `alg` that is the entry before's `alg`, and verifies under the
  entry before's key by that algorithm.
- That `keyRotation`'s `nextAlg` is this entry's `alg`.
- This entry's `keyContinuation` has an `alg` that is this entry's `alg`, and a `previousAlg` that is the
  entry before's `alg`.
- Key ids are never repeated, across both algorithms.

The time and order rules (`validFrom`, `validTo`, `rotatedAt` never going back) are unchanged.

**`/publickey`** answers `{algorithm, keyId, publicKey, authority}`, as today:

- For an Ed25519 key the answer is byte for byte today's, `"algorithm": "ed25519"`.
- For a P-256 key it is `"algorithm": "ES256"`, with the 66-character compressed point and the P-256 key
  id.

The value is the record's `alg` value, so a consumer reads one name for the algorithm everywhere. The
existing lowercase Ed25519 value stays as it is.

**`/publickey/history`** answers every key, of either algorithm, in the order the walk reached them.

### 9. `retention.acknowledgedBy`, and the acknowledgment line

**The explicit form `{"alg": "ES256", "key": "<66 hexadecimal characters>"}`** for a P-256 key. A string
of 64 lowercase hexadecimal characters stays an Ed25519 key, as before. Each case, with its sentence
(each begins `engine configuration: retention.acknowledgedBy[<i>]`):

| Version | Entry | Result |
|---|---|---|
| 38, 39 | a string of 64 lowercase hex | an Ed25519 key, as today |
| 38, 39 | any object | refused: "is an Ed25519 public key, 64 lowercase hexadecimal characters" (today's sentence) |
| 40 | a string of 64 lowercase hex | an Ed25519 key |
| 40 | `{"alg": "ES256", "key": <66 lowercase hex>}`, nothing else | a P-256 key, held to §4's key rule; a key off the rule: "is not a sound P-256 public key" |
| 40 | an object without `alg` (`{"key": "<64 hex>"}`), with another `alg`, or with any other member | refused: "is an Ed25519 public key of 64 lowercase hexadecimal characters, or {\"alg\": \"ES256\", \"key\": <66 lowercase hexadecimal characters>}" |
| 40 | a string of 66 hex, or of any other form | refused, the same sentence |

The object form is required for a P-256 key at version 40; an Ed25519 key never takes it, since it has no
`alg` value.

A bare string of 66 hexadecimal characters is refused at version 40 with a sentence naming the object
form. Taking it would pick the algorithm from the key's length, which driver 3 refuses, and a compressed
secp256k1 key would read as P-256.

An earlier gateway refuses the object form already. It refuses the file's version, and before that its
check refuses an element that is not a string (`go/retain.go:106`).

**The list** holds one to four distinct keys, of either algorithm. Each is held to its own algorithm's key
rule.

**An acknowledgment line under a P-256 key:**

- It carries `alg: "ES256"` among its members, inside what `retention-ack/1:` signs.
- Its `keyId` is the P-256 key id of the listed key.
- Its signature is `r||s`, low-S, in 128 lowercase hexadecimal characters.
- The key its `keyId` names must be listed with that algorithm.

These lines are refused:

- a line whose `alg` names an algorithm that its key id's listed key is not of;
- a P-256 signature with no `alg`;
- a high-S signature;
- a DER signature.

Each is refused with today's sentences: "does not verify under retention.acknowledgedBy, key …" for a
signature, and "is not of an acknowledgment's form" for a form. Its `sealSignature` names a seal's
signature of either algorithm, in 128 lowercase hexadecimal characters as before. The `retain` journal
entry's key id is unchanged in form.

### 10. The seed

**The seed stays Ed25519, and P-256 is the key service's alone.**

- `gateway keygen`, the seed file and `gateway rotate-key` are unchanged.
- `argumentsKey` is still derived from the seed (SPEC.md §1.2). An `ES256` gateway still requires the
  seed, which signs nothing.
- The witness's checkpoints are still signed by the seed's Ed25519 key, and `witness` is still refused
  beside `signingKeyVersion`.

### 11. The corpus

**The family.** The new vectors are a family of their own, `corpus/p256/stores/*.json`, read by the store
runner and the process contract as they are:

- Each vector but one pins `TEST-PUBLIC-KEY`, which is Ed25519, and reaches the P-256 test key through a
  rotation in its registry. `CMD verify`'s standard input stays the 32-byte Ed25519 key for those.
- **The pin of a P-256 key.** The process contract gains one optional option:
  `CMD verify [--public-key-alg ES256] ...`, given first. With it, standard input is the 66 lowercase
  hexadecimal characters of the compressed point, exactly; without it, standard input is the 32 raw bytes
  of an Ed25519 key, as today. The runner passes the option exactly when a vector gives
  `"publicKeyAlg": "ES256"`, and the key is then `TEST-P256-PUBLIC-KEY`, published beside
  `TEST-PUBLIC-KEY`. An implementation that does not take the option gives no verdict, and the runner
  reports that vector as `store <name>: no verdict under --public-key-alg:`, as it does for
  `--ordinary-seals-only`. `gateway verify` takes the same option, and verify-ts takes the pin as
  `{alg, key}` beside today's 32-byte key. The vector `p256-pinned-from-first-receipt` holds a store
  signed by the P-256 test key from its first receipt, with no rotation, and expects `ok` under that pin.
- The P-256 test key comes from a fixed synthetic scalar, the 32 bytes `01` repeated. That scalar is
  published beside `TEST-SEED` as `TEST-P256-SCALAR`, for building vectors alone.
- The signatures are made once, by an implementation independent of this repository, and frozen. They are
  verify-only: no test signs them again.
- `p256-vectors.json` sits beside `ed25519-vectors.json`. It carries ECDSA P-256 SHA-256 signature
  vectors from that independent implementation, with the high-S twin of each.

**Vectors that verify:**

| Vector | Holds | Expected |
|---|---|---|
| `p256-rotation-from-ed25519` | the rotation of §7, nothing else | `ok`; `rotations` reports one rotation |
| `p256-receipt-sealed` | the rotation, one version 3 receipt carrying `alg`, and its seal of §3's form signed over the five members | `ok` |
| `p256-scoped-seal` | the rotation, receipts of a scope identifier, and a version 3 seal carrying `alg` | `ok` |

**Refusal vectors:**

| Vector | Holds | Expected |
|---|---|---|
| `p256-receipt-high-s` | the receipt with s replaced by n − s | `signature-mismatch` |
| `p256-v2-receipt-with-alg` | an Ed25519 version 2 receipt that holds `alg: "ES256"`, signed over it | `malformed` |
| `p256-receipt-der` | the receipt with its signature as DER, 140 to 144 hexadecimal characters | `malformed` (version 3's signature form) |
| `p256-receipt-unknown-alg` | `alg: "ES384"`, re-signed | `malformed` |
| `p256-receipt-alg-on-ed25519-key` | `alg: "ES256"` beside the `keyId` of `TEST-PUBLIC-KEY`, signed by the P-256 key | `key-mismatch` |
| `p256-receipt-no-alg` | a P-256 signature and key id, with no `alg` | `key-mismatch` |
| `p256-seal-alg-stripped` | the seal signed over five members, with `alg` removed | loads nothing; `unregistered-session` |
| `p256-rotation-next-alg-missing` | a `next` of 66 characters with no `nextAlg` | `rotation-break` |
| `p256-rotation-continuation-high-s` | the `key-continuation`'s s replaced by n − s | `rotation-break` |
| `p256-rotation-next-off-curve` | a `next` whose x has no point | `rotation-key-refused` |
| `p256-rotation-next-uncompressed` | a `next` of 130 characters | `rotation-break` |

**The acknowledgment line** is read by no verifier, only by `gateway retain`. Its vectors are therefore a
family of their own, `corpus/retention-ack/*.json`. Each holds an `acknowledgedBy` list, one line, and
`expected`: accepted, or the refusal sentence. `gateway conform` runs them in process, with no
process-contract command. The family has six vectors:

- one valid P-256 line;
- one high-S line;
- one DER line;
- one line with an unknown `alg`;
- one line with `alg` on a key listed as Ed25519;
- one P-256 signature with no `alg`.

### Consequences

- **Good:** a gateway can sign with a Level 3 HSM key, and every Ed25519 store, record, configuration and
  verifier is unchanged.
- **Good:** the algorithm is inside every signature, and one record has one encoding.
- **Good:** an earlier verifier, Go or TypeScript, refuses a P-256 store with findings it already reports,
  and needs no release.
- **Bad:** there are two signature algorithms in both verifiers. The P-256 curve and the low-S rule must be
  carried in each, and the corpus must arbitrate between them.
- **Bad:** an earlier verifier's refusal does not name the cause. It reports `rotation-break` or
  `key-mismatch`, not "a P-256 record", so its operator must learn from the release notes that a newer
  verifier is needed.
- **Bad:** the seal of §3's form gains a second signing input, five members beside four. A verifier must
  choose between them by `alg`.
- **Bad:** each signing is still one call to the service, and an HSM key's latency and quota may be higher
  than a software key's (ADR-0050, "Latency and deadlines").

### What the release notes must say

- An earlier verifier, Go or TypeScript, refuses a P-256 store with `rotation-break`, `key-mismatch` or
  a record that loads nothing, never naming P-256; a newer verifier is needed.
- `/publickey` answers `"algorithm": "ES256"` for a P-256 key, beside `"ed25519"`; a consumer that matches
  the value breaks.
- A consumer of v0.37.0 refuses a whole `/publickey/history` that holds a P-256 entry.
- The pin of a P-256 key: `gateway verify --public-key-alg ES256` with the 66-hex point; verify-ts's
  `{alg, key}`.
- A version 2 receipt holding `alg` is now `malformed`.
- No record or option lets a relying party require ES256 after a rotation, and the protection level is
  not attested.
- A rotation from an HSM key back to a non-HSM key is allowed and named on stderr.

### What is not established

- **Requiring ES256.** No record and no verifier option lets a relying party require that a store is signed
  by ES256 after a rotation: a later rotation back to Ed25519 (§7) verifies, with only the stderr line at
  the gateway to show it. Nor is the protection level attested to a verifier (below).
- **`data` versus `digest`.** Whether the service also accepts `data` for `EC_SIGN_P256_SHA256` is not
  established. `digest` is the documented form for ECDSA keys, and is what this record fixes.
- **High-S from the service.** Whether the service ever answers a high-S signature is not established. The
  normalization makes the answer to that question irrelevant.
- **The protection level.** It is the service's own report. The service's key attestation for HSM keys is
  not read or checked in v0.38.0, and no record lets a verifier tell an HSM key from a software one.
  Reading the attestation at start is a possible later step.
- **The HSM's latency and quota** under the gateway's lock are not measured.
- **Low-S in the libraries.** Neither Go's `crypto/ecdsa` nor Node's `crypto.verify` enforces low-S, so
  both verifiers must check it explicitly. Go's `ecdsa.Verify` takes `(r, s)`. verify-ts must call
  `crypto.verify` with `'sha256'` named explicitly and `dsaEncoding: "ieee-p1363"`, and check the
  KeyObject's `asymmetricKeyType` against `alg` (`"ec"`, curve P-256, for `ES256`; `"ed25519"` otherwise)
  before verifying. Neither is built yet.
- **Not changed by this record:** the corpus README's process contract, `docs/design/engine-config.md` and
  `docs/postgresql-store.md`. Each changes with the build.

### Options not taken

- **P-256 everywhere.** It would change every Ed25519 record, the seed, the witness and every verifier,
  and it would leave every store signed before unreadable to an earlier verifier. Nothing asks for it, and
  the HSM need is the key service's alone.
- **An algorithm member on every record.** An `"EdDSA"` on Ed25519 records would break their byte
  identity. Every exact-member kind would then refuse them at an earlier verifier: every Ed25519 store
  written by v0.38.0 would fail under v0.37.0, for no gain in what is signed.
- **A separate signing prefix for each algorithm.** For example `receipt-es256/3:`, with no member. The
  prefix is not in the record, so a verifier would have to choose it from the key, which is the key's form
  again (driver 3). It would also double every prefix the format defines. Domain separation between the
  algorithms is not needed: their keys and key ids differ, and `alg` is signed.
- **The algorithm from the key's form.** A 33-byte point does not name its curve, and secp256k1 is one of
  the service's HSM algorithms too. Decision 2 also asks for a member.

This record supersedes nothing. It extends ADR-0050's signer, configuration and start; ADR-0052's
key-history entry; and ADR-0048's `retention.acknowledgedBy`.
