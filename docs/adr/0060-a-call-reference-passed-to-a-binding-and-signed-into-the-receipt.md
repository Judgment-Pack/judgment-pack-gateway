---
status: proposed
date: 2026-11-23
deciders: maintainer
---

# A binding that opts in receives a per-call reference in the MCP request's `_meta`, and the receipt signs the same reference

> **Summary.**
>
> - **Chosen:** for each call through a binding that opts in, the gateway draws `callRef`, 32
>   random bytes as lowercase hex, before it calls the binding. The binding receives it with the
>   session identifier in the `tools/call` request's `_meta`, as
>   `{"judgment-pack/callRef": …, "judgment-pack/sessionId": …}`. The receipt carries `callRef`
>   inside its signed bytes.
> - **Opt-in per binding:** `callReference: true` on the binding, off by default. An off binding
>   gets byte-for-byte the request it gets today, and its receipt carries no `callRef`.
> - **Engine version:** the next after the refusal journal's, in merge order (49 if the refusal
>   journal lands first). A verifier that does not know `callRef` refuses a receipt carrying it.

## Context and problem statement

A tool server reached through a binding keeps its own record of the calls it answers. That record
cannot name the receipt a call belongs to, so the two records can be joined only by time and
arguments, which is ambiguous when one session makes the same call twice (#605).

## Decision drivers

- The binding's record must name exactly one receipt, and the receipt must bind the reference, so
  that the join does not rest on the binding's word alone.
- Concurrent calls in one session must not share a reference, and the reference must not depend on
  the order in which they finish.
- A binding that has not opted in must see no change at all.
- Nothing secret reaches the binding.

## Considered options

1. The session identifier and the call index in `_meta`.
2. A per-call random reference drawn before dispatch, signed into the receipt (chosen).
3. A signed reference in `_meta` itself.

## Decision outcome

Chosen option 2, because it needs no index known before dispatch, and the receipt's signature
already binds whatever the receipt carries.

- **The reference.** The gateway draws `callRef` before it calls the binding, from the operating
  system's random source, once per call. A failed draw refuses the call before the binding is
  called, as any other failure before dispatch does. Two calls, concurrent or not, never share one.
- **What the binding receives.** In the `tools/call` request's `params._meta`, exactly the two
  members `judgment-pack/callRef` and `judgment-pack/sessionId`. Never the arguments salt, the
  caller's token, any scope key or salt, nor any other member. `_meta` itself is unsigned: the
  receipt is the evidence.
- **The receipt.** A version 3 receipt of a call through an opted-in binding carries `callRef`
  in its core, inside the signed bytes. The dry-run preview carries none (no binding is called).
- **Configuration.** A binding member `callReference`, boolean, default `false`. It is the operator's
  opt-in for that binding alone; a binding the operator did not author receives the reference only
  when the operator sets it.
- **Readers.** The Go and TypeScript verifiers read `callRef` (64 lowercase hex characters) and refuse
  any other form. A reader from before this release refuses a receipt carrying it, as it refuses any
  member it does not know; the release notes say so.
- **Specification.** A spec PR for v0.6.1 states the member, the `_meta` names and the opt-in, with a
  conformance vector: one receipt with `callRef` and one without.

### Tests

- Off: the request bytes the binding receives are unchanged, and the receipt has no `callRef`.
- On: the `callRef` in `_meta` equals the receipt's, and `sessionId` equals the receipt's.
- Two concurrent calls in one session receive distinct references, each in its own receipt.
- A binding without the opt-in, beside one with it in the same engine, receives nothing.
- `_meta` carries exactly the two members.
- A verifier refuses a malformed `callRef`.

### Consequences

- Good, because the binding's record names one receipt, and the receipt's signature binds the name.
- Good, because an off binding and its receipts are unchanged, byte for byte.
- Bad, because a receipt carrying `callRef` is refused by older verifiers until they upgrade.
- Bad, because the reference is visible to the binding before the receipt exists; a call that fails
  after dispatch leaves a reference in the binding's record with no receipt. That is expected: the
  binding's record then names a call the gateway did not complete.

## Open questions

- None for this release. Whether a later release also sends a signed reference in `_meta` (option 3)
  is left to a follow-up if a binding asks to verify it without the receipt.
