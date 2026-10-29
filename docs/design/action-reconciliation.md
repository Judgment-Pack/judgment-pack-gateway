# Action identity and uncertain outcomes

Implementation contract for #316. This document describes the candidate behavior;
the feature is not released until its receipt readers, native checks and review
records pass. It extends the executor without relaxing its authorization ladder.

## Identity before a write

Engine version 14 requires `actionKey` on `/act`. The key is 64 lowercase hex
characters chosen once by the caller for the intended action and reused across
transport retries. Older configurations keep their request shape; callers can
opt into the keyed path explicitly. An unkeyed legacy request makes no new replay
claim. The key is not an authorization credential or a lease fencing check.

The journal namespace binds the gateway authority, authenticated issuer and subject,
and action key. It excludes the access-token digest and session identifier so a
renewed authentication token or fresh post-restart session cannot cause another
dispatch. A retained fingerprint binds the platform, tool, canonical effective
arguments, decision, citations, pinned binding and recovery declaration. Reusing a
key for different content is an `action-key-conflict` refusal. A new key denotes a
new action; callers must not invent one merely because an answer was lost.

All existing requester, session, citation, record, descriptor and effect-policy
checks still run. The gateway reserves the key durably before dispatch, after
authorization. A journal failure refuses the write. A reservation is never removed
to make a retry possible. A partial or corrupt reservation is uncertainty, not
absence. Directory, file and final-name durability are required before a result
is relied on; a platform unable to provide that guarantee refuses the keyed path.

Only the creator of the reservation may dispatch the mutation. Concurrent repeats
and repeats after restart may return retained evidence or perform the declared
read-back, but never repeat the mutation. A completed response is retained with
its receipt and salts; a repeat returns that evidence without a new effect.
The operator must preserve the journal with the store. Restoring receipts without
the corresponding journal does not preserve dispatch history.

## Target support belongs to a pinned binding

A write binding declares recovery separately for each allowed write tool. An
idempotency argument is an exact argument member carrying the action key; the
gateway inserts it before the effect-policy check and refuses a conflicting
caller value. It does not place a generic header on unrelated services and assume
the service honors it. A closed argument policy must admit the inserted member.

A read-back declaration names an allowed read tool from the platform's live
operation, its argument mapping, and the result members that report the action key
and outcome. Arguments may refer only to the recorded action key, original action
arguments or pinned literal values. A result establishes `committed` only when it
reports the same key and the declared committed outcome. An absent result,
eventually consistent view, timeout, malformed result or mismatched key establishes
no absence of a commit. It is recorded as unknown and never authorizes a resend.

The declaration is the binding owner's claim about the target contract. Tool
annotations, a brand name, HTTP method or a successful tools/list response are not
evidence of idempotency. Registration approval pins the declaration with the
binding and the read tool's descriptor. The read-back uses the live source's user,
credentials, sandbox and allowlist, not the write source's broader credentials.

Current support inventory:

| Surface | Existing write path | Evidence that may be claimed |
| --- | --- | --- |
| `databricks` binding | Operator-owned function over remote MCP | No generic idempotency or read-back guarantee; an explicit pinned function contract is required |
| `azure-devops` binding | Remote work-item, comment and link tools | No declared action-key deduplication or correlated read-back contract; uncertain mutation is not retried |
| Drive storage protocol | Personal `files-prepare` / `files-commit`, outside `/act` | Its existing durable plan prevents repeating a mutation; `files-status` is a local journal read, not a target reconciliation receipt |

There is no shipped Drive write binding. This change must not invent one or claim
that its separate storage protocol mints action receipts. Its existing uncertainty
refusal remains in force. Adding an authenticated Drive action binding would need
its own bounded target contract rather than repurposing a personal storage grant.

## Evidence after dispatch

The action receipt records the key and whether an executor response was obtained
or the outcome is uncertain. An uncertain receipt's retained result is a gateway
uncertainty record, explicitly not a target response or proof that the write was
sent. A crash can occur before sending, after committing, or before persisting the
response. The journal therefore treats every reserved but unsettled action alike.

Read-back produces a separate acquisition receipt whose reconciliation member
names the action receipt, key, recovery-contract digest and observed outcome.
Both readers validate these members and the referenced action. The receipt proves
what the target reported under the gateway's signature; it does not make an
untrusted or stale target truthful. Existing receipts without these members retain
their original meaning and canonical form.

If a process dies before it can mint the uncertain action receipt, a later request
must use a fresh session and the same key and approved content. It first records
that uncertainty, then the read-back receipt. It cannot revive the old session or
send the write again. Failure to persist either receipt remains uncertainty, with
the original reservation retained. Unsupported read-back gives the named
`action-reconciliation-unavailable` refusal and no second mutation.

## Required evidence

- A fixed target commits and drops its response; a repeated action produces a
  correlated read-back receipt and the target observes exactly one mutation.
- Concurrent same-key requests, a renewed access token and a fresh session after
  restart cannot dispatch the action twice. A different payload under the same
  key is refused before calling either target operation.
- Failures at reservation write/sync, after dispatch, during receipt retention and
  during response retention leave conservative durable state. A malformed,
  oversized, linked or partial journal cannot be mistaken for a missing action.
- Unsupported binding recovery and mismatched or missing read-back evidence never
  authorize a retry. Read-back cannot select an undeclared tool, change source
  identity, bypass snapshot approval or use mutation credentials.
- Handwritten receipt vectors cover each member and refusal in both Go and
  TypeScript; verifier removal controls catch omitted correlation checks.
- Store export excludes private journal material; backup/restart documentation
  identifies the state required to retain the no-repeat guarantee.

No automatic mutation retry is introduced. Target idempotency is additional
defense when supported, not a substitute for the gateway's durable reservation.
