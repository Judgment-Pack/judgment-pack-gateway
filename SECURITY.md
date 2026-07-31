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

**Verification is symmetric.** A receipt and a seal are HMACs, so verifying one requires the same key
that mints one: anyone who can verify can also forge. The verifier must therefore be a party the
operator already trusts with the key. Separating those two roles needs asymmetric signatures, which
this reference does not implement.

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
