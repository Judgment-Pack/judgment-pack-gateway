# Durable read operations

Status: implemented locally; material-decision review and release pending.
Material-decision impact: public-surface, documented-claim, security.
Receipt/canonicalization format impact: none. SPEC.md and corpus are unchanged.

A client can detach from a long source read using the HTTP control plane:

```
POST /operations
{"id":"<32 lowercase hex characters>","source":"live","arguments":{"tool":"lookup","arguments":{}},"deadline":"<absolute RFC3339 time>"}
GET /operations/<id>
POST /operations/<id>/cancel
```

The deadline must be in the next seven days on first admission. The source's
configured `--source-timeout` (still 30 seconds by default) and its adapter's
own timeout remain effective and can end the call sooner. Operators can configure
source timeouts up to seven days. Set the MCP adapter timeout lower than the
Gateway source timeout, allowing its documented cleanup margin.

Each response has `id`, `state`, and `deadline`, optionally `reason` and
`response`. POST returns 202 while queued/running, otherwise 200. An identical
POST is idempotent and also advances an unstarted queued intent if capacity is
available. GET only reads state. Four asynchronous source processes can be active
per Gateway instance. Clients poll with bounded requests and backoff, retaining
the same ID and exact request through lost connections.

On completion, `response` is the ordinary `{result,receipt,salts}` acquisition
response, for the **original arguments**, using session `async.<id>` and call
index zero. A pending handle or status is not signed evidence. Consumers still
verify the full receipt, digest and original argument commitment against their
trusted pins; ID equality alone proves none of that. The session is sealed after
the acquisition, but consumers must not infer successful registry verification
merely from receiving the response.

## Persistence and failure semantics

`<store>/operations/<id>/request.json` is exclusively persisted before a source
can start. An exclusive immutable `claim` then fences source invocation across
processes. The completed original response is persisted in `result.json` before
being exposed. Request arguments and returned commitment salts require private
0700 directories/0600 files, outside the public receipt corpus.

Claim files are **never reclaimed**. A process that finds another owner's claim
without a retained completion returns `needs-attention`, with no source call.
This includes a crash after an external service accepted work but before a local
result was committed. Unclaimed queued intents can be started by a later
identical POST. Completed responses survive restarts and are returned byte-for-
byte at the response-object level. Do not delete operation records while their
IDs might be retried; no automatic retention/pruning is provided yet.

Durable operations currently require Unix (Linux/macOS) directory synchronization.
Other platforms refuse the operations API before admission; synchronous acquisition
remains available. Directory links and the exclusive claim are synced before a
provider call is started; a sync failure leaves the claim unreclaimed.

Use one instance per async store. A second instance can read a completed response
but treats the first instance's active claim as uncertain; it must not assume
that the remote operation stopped. This design deliberately avoids expiring
leases that could replay non-idempotent or costly provider calls.

With configured identity, operations belong to issuer+subject. Renewing a token
for that principal does not change operation identity; the original token digest
remains attached to the original acquisition. Different principals cannot read
or cancel the retained result. Changed requests/principals get 409 on POST;
unauthorized inspection gets 404. Without identity, the existing local signer
access boundary applies. Provider credentials are never part of the request.

Cancellation writes a durable tombstone and asks the source context/process to
stop. Another process's source observes the tombstone on its next check. The
provider may continue remotely. A tombstone takes precedence over every late
result, which cannot be presented as a successful completion. Deadline expiry and
provider/adapter errors do not become negative evidence. They require explicit
client handling; uncertain calls are never retried automatically.

This first control-plane implementation keeps a source process alive during its
call. It is not a provider-native asynchronous job adapter and cannot reconnect
to arbitrary remote work after that process disappears. Provider-native handles,
callback authentication, reconciliation and safe retries need a later adapter
contract. None of those guarantees is implied by `/operations`.

## Checks

The operation tests exercise real child processes behind barriers, identical and
conflicting submissions, immutable claims from previous owners, restart replay
of retained proof/salts, unclaimed intent recovery, and cancellation precedence.
Runner's cross-repository MCP integration test restarts Runner during a live
Gateway/adapter call and checks a single acquisition and evaluation. Ordinary
Gateway conformance and existing synchronous tests remain required.
