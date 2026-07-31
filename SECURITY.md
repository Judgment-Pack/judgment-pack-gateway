# Security policy

## Support status

This is a **reference gateway**, not a hardened deployment. It is pre-1.0, provides no security,
compatibility, or support service-level guarantee, binds localhost, has no authentication or
authorization on its HTTP surface, and runs as a single operator holding a single signing identity.
It must not be used as the sole control for consequential production decisions, and a `/verify` that
answers `ok` must not be read as a statement that the underlying facts are true — see
[Security boundary](#security-boundary).

## Reporting a vulnerability

Do not open a public issue for a vulnerability that could forge a receipt or a seal, cause
verification to miss a session the gateway actually attested, escape the receipt or artifact store,
disclose or recover the signing key, bypass a fail-closed refusal, or otherwise make the gateway
answer `ok` for a store that is not faithful.

Use this repository's [private vulnerability reporting](https://github.com/Judgment-Pack/judgment-pack-gateway/security/advisories/new)
(Security → Report a vulnerability). If that is unavailable, open a minimal non-sensitive issue
asking a maintainer to establish a private channel. Include:

- a minimal synthetic reproduction;
- the affected endpoint or module and the commit;
- expected and actual behaviour;
- likely impact; and
- any suggested mitigation.

Never include real keys, receipts, source responses, credentials, or proprietary data in a report.
Synthetic fixtures only.

## Security boundary

The ceiling is **byte-lineage, not truth**. Everything below describes what the gateway proves and,
more importantly, what it does not.

**The key is the trust root.** The signing key lives in the service. Its disclosure forges
everything — every receipt, every seal, retroactively. There is no defence against a compromised
gateway, and none is claimed.

**Verification is asymmetric** (receipt version 2). Receipts and seals are Ed25519 signatures, so
checking one requires only the **public** key. A verifier gains no power to forge by being able to
verify, and needs no trust relationship with the operator beyond holding the right public key. This
replaced an HMAC format in which anyone who could verify could also forge; that format is gone rather
than deprecated, so the symmetric caveat does not survive in a legacy path.

**But the public key itself must arrive out of band.** Fetching a gateway's public key from that same
gateway and then verifying its store proves *internal consistency*, not authenticity — an impostor
serves its own key and its own store, and both agree. The public key has to be pinned through a
channel that does not depend on the party being audited. Nothing in this repository establishes that
channel; a receipt carries a `keyId`, never a key, precisely so that an implementation cannot
accidentally trust the key a store hands it.

**The signature implementation is reference arithmetic, not production crypto.** `ed25519.py` is
pure-Python Ed25519 on big integers: **not constant time**, and it must not hold a key that matters.
It exists so the reference can specify and demonstrate signed receipts while staying
standard-library-only. A deployment signs with a vetted implementation — Go's standard library has
`crypto/ed25519`, which is one more reason the deployable belongs in Go. Correctness is checked
against RFC 8032's published vector and against vectors frozen from the `cryptography` package, so
the arithmetic answers to an independent implementation rather than to itself.

**A seed and a public key are both 32 bytes**, so no length check distinguishes them. Passing one
where the other belongs is not refused — it silently becomes a *different identity*, whose receipts
fail verification with `key-mismatch`. The gateway prints its `keyId` on startup so an operator can
confirm which identity is live.

**An attestation is not an authentication of the source.** A receipt proves the bytes the gateway
retained are the bytes it attested, under a *caller-configured authority label*. It does not prove
that a genuinely-named upstream produced them. A validly attested but fabricated, incomplete, stale,
or misleading source response yields a valid receipt.

**The caller is outside the trust boundary.** A client supplies a session id, a source name, and
arguments — never a receipt. The gateway produces every receipt, which is what keeps a model or agent
structurally out of the proof path: a caller can assert anything, but it cannot manufacture the
gateway's HMAC.

Because the caller is untrusted, its inputs are constrained where they reach the filesystem. A session
id names a directory under the store and a verifier **discovers** sessions by enumerating that
directory, so session ids are restricted to a flat token
([`SPEC.md` §2a](SPEC.md)) at the HTTP boundary, at `Registry.seal`, and again at `Store.stamp`. A
value that escaped the receipts root would produce genuinely signed receipts that verification could
never enumerate — `/verify` would answer `ok` for a store missing sessions the gateway itself signed,
silently voiding the coverage guarantee in [`SPEC.md` §3](SPEC.md). Treat any input that can steer
where the gateway writes as a vulnerability in this class, not as a configuration mistake.

**Sources are operator-configured subprocesses.** The gateway executes what the operator configures
and attests whatever bytes come back. It attaches no transport, authentication, or schema of its own.
Configuring an untrusted command is equivalent to running it.

**The registry closes replay and rollback only relative to a verifier that trusts the gateway's
registry over the store.** The anchor must be fetched from the key holder, not from the store being
checked. A verifier that reads both from the same untrusted place gets no guarantee.

**Not in scope for this reference:** availability or HA, authenticated transport, access control,
multi-tenancy, key rotation or custody, rate limiting, and resistance to a local attacker who can
concurrently rename or replace store ancestors. Run it from a directory whose ownership and write
permissions you control.
