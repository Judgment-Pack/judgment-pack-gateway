---
status: proposed
date: 2026-11-19
deciders: maintainer
---

# A receipt is delivered to one configured sink, and acknowledged by its digest, before `/acquire` answers; a receipt not acknowledged is held, and the session goes no further until it is

## Context and problem statement

Receipts are kept in the gateway's own store (SPEC.md §1.3). An operator who keeps its audit
record in an external log reads them back out after the fact, and nothing shows that every
receipt reached the log (issue #505). The ask is a forwarding hook:
- each receipt, with its payload's digest (the payload itself only when configured), is
  delivered to a configured external sink before `/acquire` answers;
- delivery is at least once, and in order within a session, and the sink deduplicates by
  receipt digest;
- a sink that is unavailable or does not acknowledge refuses the acquisition with a fixed
  sentence: nothing is answered unforwarded, and an unacknowledged receipt is never counted as
  delivered;
- the sink is fixed in the configuration, plain HTTP only at loopback, and the retry, ordering
  and deadline rules are stated.

`/acquire` stamps a receipt into the store under the gateway's lock (`go/serve.go`,
`acquireWithScope`; `go/store.go`, `stampInto`) and then answers it. The store is where a
receipt exists: once written at its index it is never replaced, and the session's seal counts
it. So a receipt is minted before anything can be delivered, and a failed delivery leaves a
receipt in the store that the caller was not given.

## Decision drivers

- Nothing is answered to a caller that the sink has not acknowledged.
- A receipt in the store is never replaced, and never minted twice at one index: the sink
  is sent the stored bytes, the same bytes every time.
- The sink is not trusted for verification. Receipts verify against the gateway's key and
  registry as before, with or without it.
- A failure is one sentence and one code, in the style of ADR-0029: nothing the sink said
  reaches the caller.
- Every send is bounded in time and size, and a failing sink costs the caller a stated time.
- No delivery is made while the gateway's lock is held, so a slow sink never holds up another
  session.
- A configuration without the member serves byte for byte as before. No receipt, seal,
  registry or corpus change.

## Considered options

### What happens to a receipt minted and not acknowledged

1. **Keep it, held, and deliver it again before the session's next acquisition runs its
   source and before the session is sealed.** While it is not acknowledged, both are refused
   with the fixed sentence.
2. **Refuse the session for good.** A short outage of the sink would end every open session,
   and the caller could not finish one it had begun.
3. **Answer the receipt anyway, marked unforwarded.** That breaks the ask's first rule.
4. **Deliver before writing the receipt to the store.** A lost acknowledgment would leave the
   sink holding a receipt the store does not, and the index would then be minted again under
   another signature: two receipts of one index, one of them in no store.

### What acknowledges a delivery

- **K1. A body that names the receipt digest, read to a bound.** It is minimal, and a sink
  that acknowledges another receipt, or answers a proxy's page, is not taken for one.
- **K2. Any `2xx`.** A redirect target, a captive page or a misrouted endpoint would count as
  delivery.
- **K3. A signed acknowledgment under a key the operator pins.** It is stronger. But HTTPS
  already authenticates the sink, and a key adds a second trust root that the ask does not
  name. It can be added under a later version if an operator needs it.

## Decision outcome

Chosen: option 1 and K1.

1. **The sink.** A new optional member `receiptSink`, from engine configuration version 35
   (`receiptSinkVersion`): `{"url": …, "payload": true | false}`, where `payload` is optional
   and defaults to `false`. A file of an earlier version with the member is refused by name.
   The url:
   - is 1 to 2048 bytes, absolute, and carries no user, query or fragment;
   - is `https`, or plain `http` only to a loopback address written as one: an IPv4 address
     in 127.0.0.0/8, or `[::1]`. A name is refused for plain http, `localhost` included, so a
     plain-http sink is reached without anything being resolved. The dial is held to a
     loopback peer as well.

   For `https`, the host name is resolved by the system resolver when the transport opens a
   connection: at the first delivery, and again whenever no kept connection is open. It is
   never resolved at load, and no result is cached by the gateway. Further rules:
   - no proxy is taken from the environment;
   - TLS verifies the certificate for the url's host against the system roots;
   - a redirect is not followed. It is an answer that is not an acknowledgment.

   A refusal at load repeats no value of the url.
2. **The delivery request.** `POST` to the url, `Content-Type: application/json`. The body is
   the canonical JSON (SPEC.md §1.1) of an object with exactly these members:
   - `deliveryVersion`: `"1"`;
   - `payloadDigest`: the receipt's `resultDigest`;
   - `receipt`: the stored receipt, whole;
   - `receiptDigest`: `sha256:` and the lowercase hexadecimal SHA-256 of the receipt's
     canonical bytes, which are the line under `receipts/` without its line feed;
   - `payload`: the result as answered. It is present only with `payload: true`, and never
     for a source that keeps no payload (ADR-0028): what the gateway does not keep is not kept
     at the sink either.
3. **The acknowledgment.** A `200` whose body is exactly `{"acknowledged":"<receiptDigest>"}`,
   optionally followed by one line feed. At most 512 bytes are read. Anything else is not an
   acknowledgment: another status, a redirect, another digest, another member, other
   whitespace, or a body past the bound.
4. **Before the answer.** The receipt is written to the store as before, then held for the
   sink in the same hold of the gateway's lock that stamped it. It is delivered after that
   lock is released, while the session's admission is still held, which a seal waits for.
   `/acquire` answers only once the sink has acknowledged this receipt and every earlier
   receipt of the session.
5. **Order and at least once.** A session's held receipts are delivered oldest first, one
   delivery at a time for the session. A receipt is sent, in the same bytes, until it is
   acknowledged. The sink deduplicates by `receiptDigest`: a duplicate arises where it kept a
   receipt and its acknowledgment was lost. No order holds across sessions.
6. **The refusal.** The answer is `503` with the body `{"error": "receipt not forwarded: the
   receipt sink did not acknowledge a receipt of this session; nothing was answered, and the
   receipt is held to be delivered again before the session's next acquisition or seal",
   "code": "receipt_not_forwarded"}`. It carries no `Retry-After`, nothing of the receipt or
   the result, and nothing of the sink's answer. It is the one refused acquisition after which
   a receipt is in the store. The session is begun, and the receipt takes its `callIndex`.
7. **A held receipt (option 1).** Every held receipt of the session is delivered again before
   the session's next acquisition proceeds: before the delegation counts, the grant is asked,
   or the source runs. The same happens before the session is sealed, for a caller that
   reaches the session's scope (ADR-0037). While one is not acknowledged:
   - the acquisition is refused with the sentence, its source is not run, and nothing is
     minted;
   - `/act` is refused with the sentence, its executor is not started, and nothing is
     minted;
   - the seal is refused with the sentence. The seal also checks, under its own hold of the
     lock, that nothing is held, so a receipt minted after its delivery refuses it too.

   A held receipt is never answered. The caller that was refused learns of it only from the
   store or the seal's count.
8. **Retries and deadlines.**
   - Each receipt is sent at most three times in one call: the first send and two more.
   - The waits between sends are 250 ms, then 500 ms.
   - Each send is bounded as a whole by 5 seconds: the connection, TLS, the request, the
     answer's headers and its body.

   A call that finds another delivery of the session in flight waits for it for at most one
   send's deadline (5 seconds), or until its context ends, and is then refused with the
   sentence; the requests queued behind a failing sink therefore end together.

   A call stops at the first receipt that is not acknowledged. A failing sink therefore costs
   one call at most 15.75 seconds of sending, after at most 5 seconds waiting for another call
   of the same session to end its delivery: 20.75 seconds in all. A working sink costs up to 5 seconds for each receipt the
   call delivers: those held, which are at most the session's acquisitions in flight at once,
   and its own.

   The delivery time is not taken from the source's timeout. That timeout bounds the source's
   run alone, which has ended when delivery begins, and the delivery time is added to the
   acquisition's. A caller's own deadline should allow for the source's timeout plus 16
   seconds. A stop of the gateway ends a delivery in flight, which is then refused.
9. **What is forwarded.** Receipts minted by `/acquire` alone, including those of the MCP
   front and of an action's read-back, which take the same path. Other records are unchanged
   and not forwarded:
   - an action's receipt minted by `/act`;
   - a seal;
   - a registry line;
   - a removal record.
10. **Versioning.** Engine configuration version 35 adds the member. No receipt, seal or
    registry form changes, and no conformance vector is added.

### Consequences

- Good: no caller holds a receipt that the configured log has not acknowledged. The log learns
  of each receipt before the caller does.
- Good: the sink is sent only stored bytes, which it can check against the gateway's pinned
  public key. A sink, or anyone posting to it, cannot pass off a receipt the gateway did not
  sign.
- Bad: an unavailable sink stops every acquisition of every session. That is the ask, and a
  lever on availability for whoever controls the sink.
- Neutral: a held receipt lives in the process's memory, and is in the store as well. A
  session left open by a stop or a crash is not sealed past it: when `receiptSink` is
  configured, `gateway seal-open` and the start's `sealOpenAtStart` first deliver each
  receipt the store holds of the session, oldest first, and seal it only when the sink has
  acknowledged them all. The sink deduplicates by digest, so receipts it had acknowledged are
  acknowledged again. A session whose receipts are not all acknowledged stays open and is
  named, with the fixed sentence; once one delivery fails the sink is not asked about the
  sessions after it, which are named as well. A stored receipt is delivered with its payload
  where the configuration asks for it and the store still holds one. The command reads the
  sink from `--config`; one given with `--store` and the other flags names none. A session
  is held by one live instance (ADR-0035), so a held receipt is never in the memory of an
  instance that does not serve the session, and the instance that finds it open after the
  holder has stopped delivers from the store.
- Later change: forwarding action receipts and seals. Neither is forwarded in this version;
  doing so is a new `deliveryVersion`, and a follow-up issue.
- Bad: the acknowledgment is the sink's word. A sink that acknowledges and then drops a
  receipt loses it, and the gateway cannot tell.
- Bad: one sink serves every scope identifier. It learns every scope's receipts and, with
  them, each session's scope salt (ADR-0042; SECURITY.md).
- Neutral: a refused acquisition now leaves a receipt in the store. SPEC.md §6 says so beside
  the other answers.

## More information

- SPEC.md §6a, "Receipt forwarding"; `docs/design/engine-config.md`, "A receipt sink (engine
  version 35)"; SECURITY.md, "The receipt sink".
- `go/receipt_sink.go`; tests in `go/receipt_sink_test.go`.
- ADR-0029 (a fixed sentence for a failure class); ADR-0028 (payloads not kept); ADR-0037 and
  ADR-0041 (scope reach); ADR-0042 (the scope salt).
