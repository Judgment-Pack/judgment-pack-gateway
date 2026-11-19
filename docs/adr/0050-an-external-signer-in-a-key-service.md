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

Chosen option: Ed25519 at the software protection level, because it needs no specification change, and because the key is still created in the service, cannot be exported, and every signing is an access-checked, audited call. The trade-off is stated: the key is held by the service's software (Level 1), not by a hardware module (Level 3). ECDSA P-256 at Level 3 is left for a later ADR.

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
| `gateway remove-artifact`, `remove-scope`, `seal-open`, `export`, and `connect`'s descriptor capture, the gateway stopped | seed only. They refuse a configuration naming `signingKeyVersion` with a fixed sentence (`refuseUnderKeyService`) until each is built for a key service. |
| Witness checkpoints; the PostgreSQL kind (its start lease and instances name the seed's key) | refused beside `signingKeyVersion` at configuration |

The seed stays required when a key service signs. It keys the arguments commitment (`argumentsKey`, SPEC.md §1.2) and signs nothing.

### Configuration

`signingKeyVersion` is a member of engine configuration version 36 (version 35 is reserved for #505, ADR-0049; `keyServiceSignerVersion` is the one constant to renumber). It holds one key version's resource name in a closed form:

```
projects/<project>/locations/<location>/keyRings/<ring>/cryptoKeys/<key>/cryptoKeyVersions/<n>
```

Under an earlier version the member is refused by name. Out of form, it is refused before the service is asked.

### At start

The public key is read once (`GET /v1/<version>/publicKey`) and checked:

- the answer names the version asked;
- the algorithm is `EC_SIGN_ED25519`;
- the PEM's CRC32C is the one answered;
- the PEM holds one SubjectPublicKeyInfo of an Ed25519 key.

Anything else is a fixed sentence, and the gateway does not start. The `keyId` is derived from that key. As at the seed's key, the registry's walk must end at it, so a key version the registry rotated from refuses the start. The start line names the version, the protection level and the `keyId`.

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
- **Deadline.** One signing, with the token request when one is needed, is bounded by 5 seconds.
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
- An append that fails after a byte may be written does not switch. The gateway is then to be stopped and the registry settled as `gateway rotate-key --resume` settles a torn append.
- On a log that several instances append to, `rotateTo` refuses.

**Not built here (#431 remains open for it):** the operator's trigger. The plan:

1. The operator writes the next version into `signingKeyVersion`.
2. A signal makes the gateway re-read that one member under the configuration's own trust checks, read and check the next public key, and call `rotateTo`.
3. A restart then starts under the next version.

The same path moves a gateway from its seed to the service: the forward statement is signed by the seed and the reverse by the service.

### Old keys

**A receipt under any earlier version verifies from the registry alone.** The verifier pins the first key and follows the rotation lines of SPEC.md §3b. Each line names the `keyId` rotated from and the public key rotated to, so the registry holds every version's public key. A version can be disabled or destroyed in the service once nothing more is to be signed with it.

**A verifier learns which version signed a receipt** from the receipt's `keyId` and the rotation line that introduced that key. The service's version name is in neither the receipt nor the registry. The operator maps a `keyId` to a version from the start line or from the version's public key.

### Consequences

- **Good:** the private key never reaches the gateway's host; every signing is access-checked and audited by the service, and removing the gateway identity's permission stops signing at once.
- **Good:** receipts, seals and verifiers are unchanged, and the seed kind signs byte for byte as before.
- **Bad:** whoever controls the compute's identity can ask the service to sign as the gateway, as ADR-0043 and ADR-0045 already state for their calls.
- **Bad:** the key is protected at Level 1, not Level 3.
- **Bad:** a key service's latency is added to every acquisition and seal, and while one signing waits, the others wait for it.
- **Bad:** the operator commands that run with the gateway stopped, the PostgreSQL kind and the witness are not yet built for a key service, and they refuse.
