# Gateway specification

The gateway is the **hosted deployment shape** of the trustworthy-input-acquisition
line ([judgment-pack-evaluator-experiments](https://github.com/Judgment-Pack/judgment-pack-evaluator-experiments),
ADR-0002). It reuses the inline attestation format unchanged and adds exactly one
mechanism on top: a **sealed session registry** that closes the two residuals the
inline verify cannot catch on its own.

This document specifies only what the gateway adds. The attestation format —
canonicalization, receipts, the chain, and per-receipt verification — is specified
by the acquisition-proxy
([`acquisition-proxy/SPEC.md`](https://github.com/Judgment-Pack/judgment-pack-evaluator-experiments/blob/main/acquisition-proxy/SPEC.md))
and re-implemented here in [`attest.py`](attest.py) with no format change: a receipt
this gateway issues verifies the same way an inline receipt does.

## 1. What the inline verify cannot catch

`attest.verify_store` checks every receipt against the key: HMAC, location binding,
result re-digest, per-session `callIndex` sequence, and the `prevHmac` chain. That
makes a store *internally* consistent-or-not. Two attacks leave a store internally
consistent yet not faithful:

- **Whole-session replay.** A genuine session — every receipt validly chained and
  HMAC'd under the real key — copied verbatim into another store passes
  `verify_store` there too. Nothing inside a session says *which store it belongs
  to* or *that it is current*.
- **Final-tail rollback.** Deleting the last *k* receipts of a session leaves a
  shorter prefix `0..n-k-1` that is still a valid chain. `verify_store` cannot know
  the session once had more, because the evidence that it did was in the deleted
  receipts.

Both require an anchor **outside** the store: a record of which sessions exist and
how many receipts each finally held, kept by the party that did the attesting and
not forgeable by whoever holds the store.

## 2. The seal

When a session closes, the gateway seals it. A seal is one append-only record:

```
{ "sessionId": <string>, "finalCount": <integer>, "sealedAt": <string>, "hmac": <hex> }
```

`hmac` = HMAC-SHA256, under the gateway key, over `b"seal:" + canon({sessionId,
finalCount, sealedAt})`, where `canon` is the acquisition-proxy canonicalization
(sorted keys, compact, integer-only number domain). The `seal:` prefix domain-
separates a seal HMAC from a receipt HMAC so neither can be replayed as the other.

The registry ([`registry.py`](registry.py)) is an append-only file, one seal per
line. Sealing a session that is already sealed is **refused** — a session's
`finalCount` can never be re-sealed to a smaller value, so a seal cannot be walked
backward to excuse a rollback.

## 3. Registry-anchored verification

`verify_with_registry(verify_store, store_root, key, registry_path, authority)`:

1. Runs `verify_store` (all per-receipt findings carry through unchanged).
2. Loads the seals via `load_seals`, which **drops any seal whose HMAC does not
   verify** under the key. A seal forged by someone without the key is discarded, so
   a store cannot be excused by a forged registry.
3. For each session present in the store:
   - not in the loaded seals → **`unregistered-session`** (whole-session replay, or
     a session forged without the key).
   - store count `<` sealed count → **`tail-rollback`**.
   - store count `>` sealed count → **`count-exceeds-seal`** (receipts beyond the
     seal; a seal is a high-water mark).
4. For each sealed session **absent** from the store → **`sealed-session-missing`**
   (a whole sealed session deleted).

`ok` is true only if the inline verify passed **and** no registry finding fired.

The verifier must obtain the registry from the gateway (the key holder), **not** from
the untrusted store. That is the whole point: the anchor's authority comes from being
outside the store's reach and sealed under a key the store's holder does not have.

## 4. Trust boundary and honest bounds

- The gateway holds **one protected signing identity** (the key). It lives in the
  service, never in a client or a downstream consumer. A client calls `/acquire` and
  **cannot supply a receipt** — the gateway produces every receipt. This is what
  removes the model/agent from the proof path: a caller can lie about facts, but it
  cannot manufacture the gateway's HMAC.
- Same bounds as the inline core, carried forward unchanged: an HMAC receipt is a
  **keyed integrity proof under a caller-configured authority**, not an asymmetric
  signature and not proof that a genuinely-named source returned the bytes (the
  recorded `source`/`authority` is an operator-configured label, not an
  authenticated origin). The seal inherits exactly this: it proves *this key holder
  sealed this count*, not *this count is true of the world*.
- The registry closes whole-session replay and tail rollback **relative to a
  verifier that trusts the gateway's registry over the store**. It does not defend a
  compromised gateway (key disclosure forges anything), and it is a single-identity,
  single-operator reference — not a multi-tenant or federated trust root.
- Scope not claimed: no availability/HA guarantees, no authenticated transport
  (binds localhost), no access control on the HTTP surface. This is a reference for
  self-hosting a trust root and for demonstrating the mechanism, not a hardened
  public deployment.

## 5. HTTP surface (reference)

Localhost, JSON, standard library only.

| Method | Path        | Body / result |
|--------|-------------|---------------|
| POST   | `/acquire`  | `{session, source, arguments}` → runs the configured source, attests, chains, retains; returns `{result, receipt}`. No receipt is accepted from the caller. |
| POST   | `/seal`     | `{session}` → seals the session's final count; returns the seal record. |
| GET    | `/verify`   | → `{ok, findings}` from `verify_with_registry`. |
| GET    | `/registry` | → the raw registry bytes, for a verifier to fetch the anchor from the key holder. |

A `source` is an operator-configured subprocess that reads the canonical arguments on
stdin and emits a JSON result on stdout. The gateway attaches no transport of its own
— it attests whatever bytes a configured source returns, which is exactly the inline
core's boundary: **proof of the bytes, not proof of their truth.**
