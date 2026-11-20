---
status: proposed
date: 2026-11-19
deciders: maintainer
---

# An external signer in a key service, and a rotation while serving

## Context and problem statement

The gateway signs with a seed file on disk, and `gateway rotate-key` needs the gateway stopped (#431). An operator who keeps signing keys in a key service, where the private key never leaves the service, cannot use it. Receipts and every verifier are Ed25519 (SPEC.md §1.2), and Cloud KMS offers Ed25519 (`EC_SIGN_ED25519`) only at its software protection level: its hardware elliptic-curve algorithms are P-256, P-384 and secp256k1.

## Decision drivers

- No specification change: receipts, seals, the registry and every verifier stay as they are.
- The gateway never holds the private key, and nothing is minted unsigned.
- A refusal is a refusal: a key service that does not sign fails the acquisition closed with a fixed sentence.
- Each receipt is under exactly one key version, and a receipt under any earlier version verifies from the registry alone.
- No outbound host is named by configuration (ADR-0043, ADR-0045).

## Considered options

- **Ed25519 from a key-service key at its software protection level (FIPS 140-2 Level 1).** No specification change.
- **ECDSA P-256 at the hardware protection level (Level 3).** This needs a second receipt signature algorithm: a new Core specVersion, P-256 in every verifier, and a registry that records the algorithm for each key version.
- **The seed as today, protected on disk.** This answers neither ask.

## Decision outcome

Chosen option: Ed25519 at the software protection level, because it needs no specification change, and because the key is still created in the service, cannot be exported, and every signing is an access-checked, audited call.

**The protection level is stated plainly: the key is at Cloud KMS's software protection level, FIPS 140-2 Level 1.** It is held by the service's software, not by a hardware security module. Level 3 (an HSM key) is available in Cloud KMS only for ECDSA P-256 and the other elliptic curves named above, not for Ed25519. Moving to it is a later change: it needs a specification change and a second receipt signature algorithm in every verifier.

### The signer

A signer (`go/signer.go`) signs with one Ed25519 key. It has two kinds:

- the seed file, which signs byte for byte as before (`ed25519.Sign`, which is deterministic);
- the key service (`go/key_service_signer.go`): Cloud KMS `asymmetricSign` for one `EC_SIGN_ED25519` key version.

Every signature is held to the signer's key (`signingKey.signVerified`) before anything is written with it. The store and the registry writer share one `signerHolder`. A receipt or a seal reads it once, and is signed and names its `keyId` under what it read.

| Signing site | Signer |
|---|---|
| Receipt (`store.stampInto`) | either kind |
| Seal, in each of its three forms (`registryWriter`) | either kind |
| Descriptor statement at the serving start (`store.retainDescriptorCapture`) | either kind |
| Rotation statements while serving (`rotationRecordSigned`, `registryWriter.rotateTo`) | either kind, forward by the current key and reverse by the next |
| `gateway rotate-key`, the gateway stopped | seed only. With a key service, the registry's walk ends at the service's key, so the command refuses (`engineWalk`). A key-service rotation is `rotateTo`. |
| `gateway remove-artifact`, `remove-scope`, `seal-open` (both kinds), `export`, and `connect`'s descriptor capture, the gateway stopped | either kind. Given `--config`, each builds the signer from the configuration (`commandSigner`) and signs through it; `export` names its key. Given `--store`/`--seed`/`--registry`, the seed signs, and history under a key the registry's walk did not reach is refused (`heldUnderAnotherKey`), so the seed never signs over a store a key service signs for. |
| `gateway store remove-scope` (PostgreSQL, flags only) | seed only, and refused over a registry holding records under a key its walk did not reach |
| The PostgreSQL kind | either kind. The start lease and the instances' rows name the signer's key (`instanceForKey`). |
| Witness checkpoints | refused beside `signingKeyVersion` at configuration |

The seed stays required when a key service signs. It keys the arguments commitment (`argumentsKey`, SPEC.md §1.2) and signs nothing.

### Configuration

`signingKeyVersion` is a member of engine configuration version 36 (version 35 is the receipt sink's, ADR-0049; `keyServiceSignerVersion` is the one constant to renumber). It holds one key version's resource name in a closed form:

```
projects/<project>/locations/<location>/keyRings/<ring>/cryptoKeys/<key>/cryptoKeyVersions/<n>
```

Under an earlier version the member is refused by name. Out of form, it is refused before the service is asked.

`signingPublicKey`, also a version-36 member, pins the key version's public key beside its name, as the runtime pins a seed's expected public key: 64 lowercase hexadecimal characters. It is required whenever `signingKeyVersion` is set, and given only beside it: `signingKeyVersion` without it is refused by name at configuration load, with a fixed sentence. The pair is new in version 36, so requiring the pin now costs no configuration anything, where requiring it later would break one. A key version that answers another public key signs nothing, at the start, at a rotation and in every command, and the refusal names neither key.

### At start

The public key is read once (`GET /v1/<version>/publicKey`) and checked:

- the answer names the version asked;
- the algorithm is `EC_SIGN_ED25519`;
- the PEM's CRC32C is the one answered;
- the PEM holds one SubjectPublicKeyInfo of an Ed25519 key.

Anything else is a fixed sentence, and the gateway does not start. The `keyId` is derived from that key, and held to `signingPublicKey`. As at the seed's key, the registry's walk must end at it, so a key version the registry rotated from refuses the start.

The key is also held to the history (`heldUnderAnotherKey`), at a key service's start and at a seed's alike. A registry record other than a rotation, or the first receipt of any series in the store (a series holding none is passed over, never the ones after it), under a `keyId` the walk did not reach refuses the start. A seed-signed store restarted with `signingKeyVersion`, a store a key service signed for restarted under the seed, or a mistyped version naming another key in the ring, therefore does not start; the move is a rotation (below). So a history under key B, then a start under seed A, then B again, never leaves a store mixed without a rotation: the start under A is refused. The start line names the version, the protection level and the `keyId`.

### The calls

- **The API host is built in.** It is `https://cloudkms.googleapis.com`, and no configuration member, flag or environment variable names it. The client uses TLS 1.2 or later against the system roots, dials that host and port alone, goes through no proxy, follows no redirect, and reads at most 64 KiB of any answer.
- **The access token is the gateway's own.** It comes from the metadata server at its fixed link-local IP literal, asked with `Metadata-Flavor: Google`, and the answer is taken only with that header once. The client follows the rules of `adapters/internal/metadataclient`. The gateway module holds a copy of those rules, because it imports no other module's package. The token is kept until 60 seconds before it expires.
- **A signature is asked for with `asymmetricSign`.** The request carries `data` and `dataCrc32c`. The answer must name the version asked, report `verifiedDataCrc32c`, and carry a 64-byte signature whose CRC32C is the one answered. The signature is then verified under the public key read at start.

### Failure

- **Each failure has one fixed sentence**, and none repeats a value the service answered:
  - a service that cannot be reached;
  - a service that refuses, which includes any status but 200 and a redirect;
  - no access token from the metadata server;
  - an answer that cannot be taken;
  - a signature that does not verify under the gateway's key.
- **Nothing is minted unsigned, and nothing is written before the signature verifies.**
  - The receipt is signed before its session is made.
  - On the acquisition path, the payload's digest is taken from the bytes, and the payload is retained only after the signature verifies (`stampOwningAfter`).
  - A seal is signed and verified before it is appended.
  - The action path retains its result artifact before its stamp, as it does today. The artifact is content-addressed and cited by nothing until a receipt is written.
- **A 429 or 503 from the key service is not ADR-0029's throttled answer.** ADR-0029 classifies a source's own answer. The key service is the gateway's own, and the source did answer. The acquisition fails with the refusal sentence, and the caller may try again, since nothing was minted.

### Latency and deadlines

- **Calls.** Each receipt and each seal is one `asymmetricSign` call. The metadata server is asked about once an hour.
- **Deadline.** One signing, with the token request when one is needed, is bounded by 5 seconds, and derives from the service's lifetime: a stop cancels a signing that waits.
- **Latch.** After a signing fails, every signing fails at once with the same sentence for 2 seconds, asking the service nothing. A service that is down costs one deadline, not one for each acquisition queued on the lock, so a stop is not starved behind them.
- **The access token.** It is at most 16 KiB, of the RFC 6750 token form, and its answered life is at most 86400 seconds.
- **Effect on the acquisition.** Signing follows the source's answer, so an acquisition takes at most the source's own deadline plus 5 seconds. The source's deadline is unchanged.
- **Effect on other calls.** Signing runs under the service's lock, which orders a session's receipts. Other acquisitions and seals wait while a signing waits, so throughput under a key service is bounded by the service's latency. Moving the signing out of the lock needs ordering for each session, which is a later change.

### Rotation while serving

`registryWriter.rotateTo` takes the switching hold that every seal also takes. It then:

1. walks the registry to the current key;
2. signs the rotation record (SPEC.md §3b): the key-rotation statement by the current key version and the key-continuation statement by the next. With one key in the service, both are calls to the service, and each signature is verified;
3. reads the record back, with the registry before it, as a walk to the next key;
4. appends the record;
5. switches the holder, and only then.

**The switch point** is the return of the append:

- A receipt begun before the switch is wholly under the earlier version, `keyId` and signature both, even when it is written after the record. It verifies, because the walk reaches that key.
- A receipt begun after the switch is under the next version.
- A refusal before the append changes nothing.
- An append that fails, whether or not a byte of it may be written, does not switch, and the gateway stops (exit 1, the reason on the standard error). It does not serve on: acquisitions under a registry that may hold part of a rotation could never be sealed.

**A rotation whose append failed.** A key-service rotation writes no `<seed>.next` and no kept record, so `gateway rotate-key --resume` does not settle it. The operator reads the registry's end and settles it so:

- **The rotation's two statements are whole** at the registry's end, the walk ending at the next key: start with the new configuration, the one naming the next key version.
- **Nothing of the record was appended, or a `key-rotation` torn before its end:** the registry reads, under either key, as one with no rotation (SPEC.md §3b, "A rotation that stops"; a torn last line loads nothing, §3). Start with the old configuration, the key rotated from, and send SIGHUP again to rotate.
- **Any other part of the record**, a `key-rotation` whole with no `key-continuation` after it or a `key-continuation` cut short: the walk refuses the start under either key. Cut that part of the record, from its first byte and nothing more (the one cut of a registry SPEC.md §3b makes, and only of bytes the record names), then start with the old configuration and send SIGHUP again to rotate. No other bytes of the registry are cut.
- On a log that several instances append to, `rotateTo` refuses.

**Decision 3(a): the trigger.**

- **File kind: a rotation without stopping, at SIGHUP.** The operator writes the next version into `signingKeyVersion` and its key into `signingPublicKey`, and sends SIGHUP. The gateway reads the configuration again under its own checks, takes those two members only, reads and checks the next public key as at the start, and calls `rotateTo`. The outcome is one line on the standard error. A refusal before the append changes nothing; an append that failed stops the gateway, settled as above. After a rotation, a restart starts under the next version. A gateway serving as a witness refuses SIGHUP rotation with a fixed sentence, even where the configuration read again no longer names `witness`: its checkpoints are signed by the seed's key. The same path moves a gateway from its seed to the key service: the forward statement is signed by the seed and the reverse by the service.
- **PostgreSQL kind: stop every instance, rotate, start.** SIGHUP rotation is refused there with a fixed sentence, because instances on one database must sign under one key version, and an instance whose key version differs from the instances serving is refused at start by name; the sentence names the rolling-deploy case. A coordinated live rotation across instances is #537.
- **What a verifier does across the rotation.** Receipts and seals before the rotation record verify under the old key, and those after it under the new. The record is signed forward by the old key (the key-rotation statement) and in reverse by the new (the key-continuation statement), so a verifier that pinned the first key follows it from the registry alone.

### Old keys

**A receipt under any earlier version verifies from the registry alone.** The verifier pins the first key and follows the rotation lines of SPEC.md §3b. Each line names the `keyId` rotated from and the public key rotated to, so the registry holds every version's public key. A version can be disabled or destroyed in the service once nothing more is to be signed with it.

**A verifier learns which version signed a receipt** from the receipt's `keyId` and the rotation line that introduced that key. The service's version name is in neither the receipt nor the registry. The operator maps a `keyId` to a version from the start line or from the version's public key.

### Consequences

- **Good:** the private key never reaches the gateway's host; every signing is access-checked and audited by the service, and removing the gateway identity's permission stops signing at once.
- **Good:** receipts, seals and verifiers are unchanged, and the seed kind signs byte for byte as before.
- **Bad:** whoever controls the compute's identity can ask the service to sign as the gateway, as ADR-0043 and ADR-0045 already state for their calls.
- **Bad:** the key is at the software protection level, FIPS 140-2 Level 1, not Level 3. Level 3 / HSM (ECDSA P-256) is a later change needing a spec change and a second receipt algorithm in the verifiers.
- **Bad:** a key service's latency is added to every acquisition and seal, and while one signing waits, the others wait for it.
- **Bad:** the witness is not yet built for a key service, and refuses beside it; on the PostgreSQL kind a rotation stops every instance (#537).
