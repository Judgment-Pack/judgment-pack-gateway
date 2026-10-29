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
dispatch. A retained fingerprint binds the approved identity: the platform, tool,
canonical effective arguments, decision, citations, pinned binding, recovery
declaration and decision policy, and for the write and read-back sources their
binding, endpoint, transport, command line without install paths (keeping the
descriptor and executable approval pins), signed descriptor provenance and the
digest of the sandbox policy bytes the launch is bound to. Where the programs are
installed (the adapter, the runtime client, the credentials file, the sandbox
helper, policy and workspace paths, the configuration's copies of approvals), the
platform's environment and the OS user are left out, so an upgrade into another
directory or an added environment variable does not strand a key. Reusing a key for
different content is an `action-key-conflict` refusal. A new key denotes a new
action; callers must not invent one merely because an answer was lost, and must
never send a conflicting key's write again under a new key.

What does change the identity, and so strands a pending key with
`action-key-conflict`: a new binding pin, a recaptured descriptor or executable
approval, another sandbox policy, moving an opted-in deployment from engine
version 12 to 13 (which adds the sandbox), or another endpoint. Settle pending
keys (each answered from the journal, or read back) before such a change.

All existing requester, session, citation, record, descriptor and effect-policy
checks still run. The gateway reserves the key durably before dispatch, after
authorization. A journal failure refuses the write. A reservation is never removed
to make a retry possible. A partial or corrupt reservation is uncertainty, not
absence. Directory, file and final-name durability are required before a result
is relied on; a platform unable to provide that guarantee refuses the keyed path.

Dispatch takes a second exclusive transition: the gateway creates
`dispatch-<n>.json` in the reservation, synced, immediately before starting the
write program, and only that marker's creator may send the mutation. A program
that was never started (not found, refused before its start, or the start itself
failed) is answered with a synced `not-dispatched-<n>.json`; the request is refused
as `action-not-dispatched`, nothing is receipted, and the same request under the
same key may claim attempt `n+1`. A reservation without any marker, left by a crash
before dispatch, is likewise taken over by the next request. A marker without its
answer means dispatch may have begun: it is recorded as uncertain and never
dispatched again. A refusal by the sandbox helper after it started is not proof
that the adapter never ran, and stays uncertain. Concurrent repeats and repeats
after restart may return retained evidence, dispatch a freed attempt or perform the
declared read-back, but never repeat a mutation that may have been sent. Within one
process, requests under one key run one at a time; different keys run concurrently.
A replayed response, a conflict and an invalid entry are answered before admission
and open no session. On the implemented keyed path, Unix filesystems must support successful file and
directory synchronization. Other hosts refuse keyed dispatch; this is not a
cross-platform durability claim.

A completed response is retained with
its receipt and salts; a repeat returns that evidence without a new effect.
The operator must preserve the journal with the store. Restoring receipts without
the corresponding journal does not preserve dispatch history.

## Target support belongs to a pinned binding

Binding version 3 requires `actionRecovery`, covering every write tool with a
contract or explicit null for unsupported recovery. A write binding declares recovery separately for each allowed write tool. An
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
Both readers validate these members and the referenced action, and require the
read-back to be the action platform's `<platform>/live` MCP acquisition. Both
report every uncertain action as an observation beside `ok`: `action-uncertain`,
`action-committed` or `action-mismatch` (SPEC.md §1.2b). A reader before this
release returns `ok` for an uncertain action and says nothing of its delivery. The receipt proves
what the target reported under the gateway's signature; it does not make an
untrusted or stale target truthful. Existing receipts without these members retain
their original meaning and canonical form.

If a process dies before it can mint the uncertain action receipt, a later request
must use a fresh session and the same key and approved content. It first records
that uncertainty, then the read-back receipt. It cannot revive the old session or
send the write again. Failure to persist either receipt remains uncertainty, with
the original reservation retained. Unsupported read-back returns HTTP 409 with the retained uncertain action and the named
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

## Known limits

- **A damaged journal entry needs an operator.** A partial or unreadable intent,
  marker or response refuses its key for good: it never grants dispatch. Before
  removing such an entry, the operator checks at the target whether the write
  happened and records what was found; removing it re-enables dispatch under that
  key.
- **The journal grows with every key.** Each key keeps a directory holding its
  intent, markers and full retained response. There is no retention policy yet;
  removing a settled entry loses the replay of its response.
- **The receipt a journal entry cites is synced best-effort.** After a power loss
  the journal can name a receipt the store lost; that key then refuses as
  `action-journal-invalid` instead of replaying. Nothing is sent twice.
- **The key is scoped to the authority and the authenticated issuer and subject.**
  A takeover that authenticates as another subject reaches another reservation,
  and so does every key after the configured issuer string or the authority
  changes, even for the same subject: settle pending keys first. The agent's
  run-owned jobs settle this scope before adopting reconciliation (#352).
- **A key records at most 16 attempts that were never started.** A retry loop
  through an outage exhausts it (`action-journal-exhausted`). Every attempt was
  answered as not dispatched, so nothing was sent: the client may send the write
  under a new key, or an operator may remove that key's entry once the cause is
  fixed.
- **The identity keeps this release's derived command line.** The adapter command
  line, less its install paths, is part of the identity, so a later release that
  adds or reorders a derived flag turns pending keys into conflicts. Reconcile or
  drain pending uncertain keys before upgrading.
