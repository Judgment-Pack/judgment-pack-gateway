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
and action key; under a delegation, the authority, the delegation's subject, its
root actor and the issuing host instead (SPEC.md §11.8). It excludes the access-token digest and session identifier so a
renewed authentication token or fresh post-restart session cannot cause another
dispatch. A retained fingerprint binds the approved identity: the platform, tool,
canonical effective arguments, decision, citations, pinned binding, recovery
declaration and decision policy, and for the write and read-back sources their
binding, endpoint, transport, tools, signed descriptor provenance, the digest of
the sandbox policy bytes the launch is bound to, and the fields the configuration
approves each source to run, read from the configuration by name: the pinned
image, the remote URL and its fixed headers, or the customer command; the
server's own arguments; the platform endpoint; the descriptor and
owner-declaration approval pins with the operation, platform and binding they
approve; and the sandbox selector. The adapter command line a release derives from
those fields is not part of it, so a release that adds, renames or reorders a
derived flag does not strand a key reserved under this identity, version 2 (#355). Where the programs are installed (the
adapter, the runtime client, the credentials file, the sandbox helper, policy and
workspace paths, the configuration's copies of approvals), the platform's
environment and the OS user are left out too, so an upgrade into another
directory or an added environment variable does not strand a key. A field a later
release adds to the approval is bound only where it is set, so the identity of a
source that does not set it stays as it was; a change to what an existing field
means is a new identity version. Reusing a key for different content is an
`action-key-conflict` refusal. A new key denotes a new action; callers must not
invent one merely because an answer was lost, and must never send a conflicting
key's write again under a new key.

What does change the identity, and so strands a pending key with
`action-key-conflict`: a new binding pin, a recaptured descriptor or executable
approval, another sandbox policy, moving an opted-in deployment from engine
version 12 to 13 (which adds the sandbox), or another endpoint. Settle pending
keys (each answered from the journal, or read back) before such a change.

**Identity versions.** A reservation's `intent.json` records the identity version
it was made under: `{"journalVersion":"2","identityVersion":"2","fingerprint":…}`.
Version 1 is v0.23.0's, which recorded no `identityVersion` and bound the derived
command line without install paths in place of the named fields. A reservation
recorded under version 1 is held to the request's version 1 identity, computed
beside version 2 as v0.23.0 computed it, so under this release a key v0.23.0
reserved keeps answering: a replay, a read-back or a freed attempt, as before. It
stays version 1 for good (see Known limits). Each version is
compared only with its own computation, and the two are hashed under different
domains. An identity version this release does not read (one a later release
wrote, after a downgrade) refuses as `action-journal-invalid` and never grants
dispatch.

All existing requester, session, citation, record, descriptor and effect-policy
checks still run. The gateway reserves the key durably before dispatch, after
authorization. A journal failure refuses the write. A reservation is never removed
to make a retry possible. A partial or corrupt reservation is uncertainty, not
absence. Directory, file and final-name durability are required before a result
is relied on; a platform unable to provide that guarantee refuses the keyed path.
The action record (`action.json`) cites the receipt the request just stamped. The
store links that receipt, its session and the retained result under a
best-effort directory sync, so before the record is written the gateway syncs,
strictly, the result's directory (`artifacts/`), the session's directory and
`receipts/`; the store directory's own entries were synced when the journal was
opened, and each file's bytes before it was linked (#352 L4). If that fails, the
record is not written and the request fails; the dispatch marker then has no
answer, so the next request under the key records uncertainty and reads back.

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

## Operating the journal

The journal is `actions/` in the store: one private directory per key, named by
the key's namespace. The namespace is the lowercase hex SHA-256 of
`judgment-pack-gateway/action-key/1:` followed by the canonical JSON (SPEC.md
§1.1) of `{"authority", "issuer", "key", "subject"}`: the gateway authority, the
caller's authenticated issuer and subject, and the action key. An entry holds:

| File | Written | Bound |
| --- | --- | --- |
| `intent.json` | when the key is reserved | 1 KiB |
| `dispatch-<n>.json` | immediately before the write program is started, attempt `n` | 1 KiB each, `n` ≤ 16 |
| `not-dispatched-<n>.json` | when attempt `n`'s program was never started | 1 KiB each |
| `action.json` | after the receipt is stamped: the response, its receipt and salts | 16 MiB |

No file is ever rewritten. An entry is at most 16 MiB and 33 KiB, and in
practice about the size of its response. The gateway sets no bound on the number
of entries: there is one for every key every caller has used.

**Under a delegation** (SPEC.md §11.8) the namespace is the SHA-256 of
`judgment-pack-gateway/delegated-action-key/1:` and the canonical JSON of
`{"authority", "key", "scope"}`, the scope being `{"host", "rootActor", "sub"}`:
the issuing host, the chain's root actor and its subject, never the transport
token. Such an entry holds one file more, `scope.json`, that scope, written before
`intent.json` and held to on every later open (a missing or other scope is
`action-journal-invalid`), and its `dispatch-<n>.json` records the receipt's
`delegation` member beside the attempt (16 KiB). A second kind of entry,
named by `judgment-pack-gateway/delegated-action-subject/1:` and
`{"authority", "host", "key", "sub"}`, holds only `scope.json`: the scope the
subject first reserved the key in, so another root actor of the same subject is
refused (`action-key-scope-conflict`). Compaction treats the two together: a
subject entry is removed with the reservation it names, and never on its own
while that reservation is kept.

**The journal and the dispatch history.** The history of what was dispatched is
the store's: every action receipt, with its delivery key and outcome, and every
read-back receipt. The journal entry is what refuses a second dispatch under a
key, and `action.json` is the only server-side copy of the salts that open its
receipt's commitments. Removing an entry therefore loses no receipt. It
re-enables dispatch under that key, and it loses the replay of the response and
the salts unless the entry is kept elsewhere.

### Retention

Keep an entry for as long as a client may retry under its key. The operator sets
that retention period: at least the longest time any client keeps retrying one
write (a workflow platform's retry window, an agent's run lease), and longer
where an operator wants replays served. Within it, no entry is removed. Back up
`actions/` with the store; a restored store without its journal re-enables
dispatch for every key.

### Compaction

The gateway does not compact the journal itself. An operator compacts it
offline, without losing dispatch history:

1. Stop every gateway process that serves the store. The per-key lock holds one
   process only, and the journal's exclusive creation does not guard against a
   removal while a request is in flight.
2. Back up the store with `actions/`.
3. Classify each entry:
   - **Never sent:** no `action.json`, and every `dispatch-<n>.json` has a
     complete, readable `not-dispatched-<n>.json`, as the gateway itself
     requires (including an entry with no marker, and a key refused as
     `action-journal-exhausted`). It may be removed at any time: a retry
     dispatches it, as it would have.
   - **Answered:** `action.json` whose receipt's `action.delivery.outcome` is
     `response`. It may be removed once its receipt's `servedAt` is older than the
     retention period.
   - **Uncertain:** `action.json` whose outcome is `uncertain`. It may be removed
     once the retention period has passed and the target has been checked (a
     read-back receipt reporting `committed`, or the operator's own check,
     recorded as below).
   - **Begun without a record:** a `dispatch-<n>.json` without a readable answer
     and no `action.json`. Keep it: the next request under the key records
     uncertainty and reads back, and the entry is then uncertain.
   - **Does not read:** keep it, and follow the procedure for a damaged entry.
4. Move each entry to be removed to an archive outside the store, whole, and
   record one line per entry: the namespace, the receipt it cites, its outcome,
   the reason, and the date. The archive keeps the salts and the evidence that
   the key was used.
5. Restart the gateway. A client that retries a removed key sends the write
   again; the retention period is what makes that safe.

### A damaged entry

A key whose entry does not read (a missing or malformed `intent.json`, an
`action.json` that is partial or does not verify against the store, an identity
version this release does not read) is refused for good, as
`action-journal-invalid`, and never grants dispatch. A partial or unreadable
marker or answer is not refused: it counts as a dispatch that may have begun, and
the key is answered as uncertain and read back. To resolve a refused key:

1. **Find the entry** from the refused request's authority, issuer, subject and
   key (the namespace above). Stop the gateway processes serving the store, and
   copy the entry out whole before anything else.
2. **Read what is there,** without editing it:
   - an `identityVersion` this release does not read was written by a later
     release: upgrade again rather than remove it;
   - `action.json` present: the write was dispatched, or its uncertainty
     recorded. Find the receipt it cites (`receipt.sessionId`,
     `receipt.callIndex`) under `receipts/` and verify the store (`gateway
     verify`). A receipt the store lost, or one that does not verify, means the
     record cannot be served, not that nothing was sent;
   - a `dispatch-<n>.json` without its `not-dispatched-<n>.json`: the write may
     have been sent;
   - only `intent.json` and answered markers: nothing was sent.
3. **Check at the target** whether the write under that key took effect: the
   declared read-back tool with the key, or the target's own records.
4. **Decide:**
   - it took effect, or it cannot be told: keep the entry. The key stays refused,
     and the client treats the write as done or unknown. Never send that write
     again under a new key;
   - it provably did not take effect, and nothing under the key is in flight:
     move the entry to the archive. The next request under the key dispatches it.
5. **Record** the namespace, the files found and what each held, the receipts
   involved, how the target was checked and what it showed, the decision, and who
   made it and when. Keep the record with the archived entry.

## Known limits

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
- **Keys v0.23.0 reserved keep identity version 1 for good.** No journal file is
  rewritten, so their reservations never become version 2. Version 1 is computed
  from the adapter command line the running release derives, which in this
  release is v0.23.0's. Under a later release that changes a derived flag, every
  key v0.23.0 reserved answers `action-key-conflict`: a pending one is not read
  back, and a settled one no longer replays its response. Nothing is sent again.
  Settling a key first does not avoid this; only a release that keeps the
  version 1 computation does. Keys reserved under version 2 are not affected.
  (Writing a version 2 companion record when a version 1 reservation matches was
  considered and left out: it would cover only the keys a client retries under
  this release, and it adds a journal file with its own partial-write state.)
- **The owner-declaration pin is a digest of a document the release composes.**
  Version 2 binds the owner-declaration pin, which is the digest of the
  declaration file this release writes from the binding's owner declarations
  (its declaration version, platform, binding, operation and tools). Its inputs
  are bound already by the binding pin, but a release that changes how that
  document is composed changes version 2 for every key with owner declarations;
  such a release is a change of identity and must say so.
- **The remote bearer member is not bound by name.** Version 1 bound
  `--bearer=`; version 2 has no member for it. This admits nothing unapproved:
  the member's name comes only from the pinned binding, whose digest version 2
  binds, so another bearer member is another binding pin and another identity.
- **The gateway does not compact the journal.** Compaction is the offline
  procedure above; the gateway bounds each entry, not their number.
