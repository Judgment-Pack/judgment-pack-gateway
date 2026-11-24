---
status: accepted with conditions, 2026-11-23
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
> - **Engine version:** 49, the engine version after the refusal journal's (48), assigned at
>   merge. `callReference: true` is refused at configuration load below it, or where the
>   receipt version is below 3. A verifier that does not know `callRef` refuses a receipt carrying it.

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
- **The version gate.** `callReference: true` is refused at configuration load, with a sentence
  naming the binding, where the engine configuration version is below this release's, or where the
  receipt version is below 3. The gateway never starts with an opt-in it would not honour, so a
  receipt never goes out without the `callRef` the operator asked for.
- **The session identifier is not a capability.** Knowing a session identifier lets no one continue,
  append to, seal or read a session. From engine version 39 (`labelsVersion`,
  `go/session_labels.go:45`), always on for every engine this release accepts with the opt-in
  (`go/main.go:954`), a request names its session by a **label** in its scope's namespace. The
  gateway mints the identifier and resolves only labels: on `/acquire` (`go/serve.go:1399-1401`),
  on `/act` (`go/act.go:79-89`) and on `/seal` (`go/serve.go:3098-3101`,
  `go/session_labels.go:427`). An identifier sent as a label is just another label, which names a
  fresh session of its own. No HTTP route serves a receipt by its session identifier, and `/act`'s
  `cites` name a receipt by its signature as well (`go/act.go:190`), which the binding is never
  sent. Seals, which carry the identifier, are already public on `/registry`. The label is never
  sent to the binding. Sessions are not keyed by the authenticated caller: a caller who knows a
  session's **label**, and reaches its scope, can continue it, which is why the label stays with the
  caller and only the minted identifier goes out.
- **Readers.** The Go and TypeScript verifiers read `callRef` (64 lowercase hex characters) and refuse
  any other form. A reader from before this release refuses a receipt carrying it, as it refuses any
  member it does not know; the release notes say so.
- **Specification.** A spec PR for v0.6.1 states the member, the `_meta` names and the opt-in, with a
  conformance vector: one receipt with `callRef` and one without.

### Tests

- The gate: `callReference: true` with an engine version below this release's, and with receipt
  version 2, each refused at load, naming the binding; the same configuration at this release's
  version with version 3 receipts starts.
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

## Amendment of 2026-11-23: the maintainer's rulings on the build's questions

- **Readers (corrects the Summary's last sentence, the Readers ruling and the third
  Consequence).** A verifier from before this release accepts a receipt carrying `callRef` and
  ignores the member: it tolerates any signed member it does not know (SPEC.md §1.2a), and the
  signature, over every member, still verifies. It does not check the member's form; a reader of
  this release does, and refuses any form but 64 lowercase hex characters. No older verifier
  refuses such a receipt, and the release notes say so.
- **"A binding member `callReference`"** means the member of the engine configuration's
  platform entry that names the binding (`platforms.<name>.callReference`): the operator's file,
  gated by the engine configuration version. The binding document carries no such member.
- **A claimed `/act` key.** An action attempt another request claimed is sent by that request:
  this one sends nothing, so its uncertain receipt carries no `callRef`, and the binding never
  saw a reference from it, so there is nothing to join.
- **An opt-in on a source that is not an MCP server** is refused at start, and the refusal names
  the platform.
- **Receipts below version 3 (as built, 2026-11-23).** The Decision's refusal of an opt-in whose
  receipt version is below 3 is not built: only an engine configuration's platform sets
  `callReference`, and an engine's receipts are always version 3, so the refusal could never
  answer. A test holds the engine's receipt version at 3 instead. `gateway serve
  --receipt-version 2` takes no platform, so no opt-in reaches it.
- **The transport.** The gateway hands adapter-mcp the reference and the session identifier in
  `ADAPTER_MCP_CALL_REF` and `ADAPTER_MCP_SESSION_ID`, for that call alone; the adapter takes
  both out of its environment before it starts the server, which learns them only from `_meta`.
  A platform's `environment` may not set either name.
- **A read-back** sends the session identifier its own receipt names: the action's for the
  read-back an uncertain action makes at once, and the reconciling request's for a later one,
  whose receipt cites the action by its session, index and signature.
