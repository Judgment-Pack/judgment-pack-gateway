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
The gateway syncs rather than checking the citation on restart because a citation
found broken would still need an answer, and no journal file may be rewritten to
give one: the key would stay refused. The record itself appears whole or not at
all: its bytes are made durable under a staging directory in the entry and the name
is then linked, so a crash mid-write leaves the marker unanswered, not a partial
record that refuses the key for good. A reservation, and a subject record under a
delegation, likewise appear whole, by renaming a staging directory onto the entry's
name. So does a dispatch marker under a delegation, since a retry mints its receipt
from it and a torn one would refuse the key. A dispatch marker under no delegation and
a not-dispatched answer stay written in place: one that is partial reads as a dispatch
that may have begun, which is conservative.

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

## Holding a key across a takeover (#352 M6)

A run's lease can pass to a worker that authenticates as someone else. Under the
scope above that worker reaches a new reservation, and the write goes out a second
time. An agent's idempotency identity holds no principal, and a lease is nothing a
gateway can verify, so the agent presents neither. It presents the same key with
`keyScope: "authority"`, and `reconcile: true` when it is asking rather than sending
(agent ADR-0025). SPEC.md §1.2b is the contract; this is how it is kept.

**The first scope.** `actions/index/<sha256>.json`, one private file per key, holds
`{"indexVersion":"1","authority","key","reservation","scope"}`. `scope` is the
`{issuer, subject}` a request authenticated as, or a delegated request's scope
(§11.8). `reservation` names its journal entry, because an entry does not hold its
key and an operator needs to tell an indexed one. A request sending `keyScope`
creates it before reserving; a request sending neither member only reads it, and with
no record does nothing it did not do before. It appears whole or not at all, and only
one scope can create it, across processes. Any other scope then gets
`action-key-scope-conflict` before anything is reserved or sent. The file's name hashes
the key alone and the record names the authority, so a changed authority string finds
the record and answers a conflict: hashing it into the name would make the record
disappear, and the key read as never seen.

**What it proves.** The same subject, not the same owner. The gateway holds no lease,
so two workers authenticated as one subject are one scope, and it cannot tell a
legitimate takeover from any other request of that subject. What makes that safe is the
agent's key, which hashes the run and a random operation: a key is reachable only by
what holds it. A takeover by another subject gets one mutation, or its outcome stays
unknown.

**A close and a dispatch are one name.** A reconciling request that would answer that
nothing was dispatched closes the key first, by creating the next attempt's
`dispatch-<n>.json` recording `{"attempt": n, "closed": true, "closedAt": …}`. That is the
name a dispatch of that attempt would create, and both are exclusive, so exactly one
wins, across processes and with no window between a read and a claim:

- the dispatch won: the close finds a marker with no answer, which may have begun, and
  the request is answered as any request finding one is: uncertainty, then the read-back;
- the close won: the dispatch's claim finds it, and refuses as `action-key-closed`.

Only then does it answer `action-key-not-dispatched`, with the marker and the first scope
durable. A request that finds a close another made syncs it too, since its maker may
have died first. For a key never seen, the reservation appears with the close already
in it. A close opens no session and mints no receipt, so the marker is its only record.
A close is read before `action.json`, and again before uncertainty is recorded: a
request that found a marker whose owner then answered it may arrive after a close at
the next attempt, and every attempt before a close was answered, so nothing was sent.

| A reconciling request finds | It answers |
| --- | --- |
| A first scope another's | `action-key-scope-conflict` |
| A first scope and no reservation | `action-key-outcome-unknown`: a first request may be on its way, or the entry was removed |
| No first scope, no reservation | Closes; `action-key-not-dispatched` (`action-key-actor-only` to a sender other than the actor) |
| A close | `action-key-not-dispatched`, again |
| `action.json` | Its evidence, or the read-back |
| A marker with no answer | Uncertainty, then the read-back |
| Nothing begun, a freed attempt included | Closes; `action-key-not-dispatched` (`action-key-actor-only` to a sender other than the actor) |
| All 16 attempts answered | `action-journal-exhausted` |

It never dispatches: the approval it would dispatch under may have expired. A process
that dies in any of this leaves one of these states, each of them answered truthfully:

| Dies after | Same scope, plain | Same scope, reconciling | Another scope |
| --- | --- | --- | --- |
| The first scope, before the reservation | Reserves, and dispatches once | `action-key-outcome-unknown` | `action-key-scope-conflict` |
| The reservation, before the marker | Dispatches once | Closes | `action-key-scope-conflict` |
| The marker, torn or whole | Uncertainty, read-back | Uncertainty, read-back | `action-key-scope-conflict` |
| The write, before `action.json` | Uncertainty, read-back | Uncertainty, read-back | `action-key-scope-conflict` |
| A close's marker, before its first scope, no answer given | `action-key-closed` | `action-key-not-dispatched` | Takes the key: nothing false was said, and the closer's retry is then `action-key-scope-conflict` |
| A close's first scope, before its answer | `action-key-closed` | `action-key-not-dispatched` | `action-key-scope-conflict` |

**Under a delegation** (§11.8) a request sends no `keyScope`: its scope is its chain's. A
request on a delegated key is held to a first-scope record where one exists, and creates
one only by a closing reconcile, which is the actor's alone: the actor must hold the
subject record, so another root actor's reservation is not closed over, and its leaf
must name the write. A sender other than the actor never closes and never creates.

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
- A reconcile inside the window between a reservation and its marker, across two
  processes, closes it and the dispatch is refused; the reverse order leaves the
  dispatch and no close. A late first request after a close sends nothing. A takeover by
  another subject, plain or reconciling, sends nothing. Each crash point above restarts
  into the answer its table gives, and a torn record refuses no key.

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
| `dispatch-<n>.json` | immediately before the write program is started, attempt `n`; or a close, recording `closed` | 1 KiB each, `n` ≤ 16 |
| `not-dispatched-<n>.json` | when attempt `n`'s program was never started | 1 KiB each |
| `action.json` | after the receipt is stamped: the response, its receipt and salts | 16 MiB |

No file is ever rewritten. An entry is at most 16 MiB and 33 KiB, and in
practice about the size of its response. The gateway sets no bound on the number
of entries: there is one for every key every caller has used. A directory named
`.staging-*`, in `actions/`, an entry or `actions/index/`, is what a crash left while
making a record durable: nothing reads it, and it may be removed while the gateway
processes are stopped.

`actions/index/<sha256>.json` is a key's first scope: at most 16 KiB, in practice a few
hundred bytes, one for every key a request sent with `keyScope`, or a reconciling
request closed. An entry a record's `reservation` names is an **indexed entry**. Its name
is the lowercase hex SHA-256 of `judgment-pack-gateway/action-key-index/1:` followed by
the canonical JSON of `{"key"}`.

**Under a delegation** (SPEC.md §11.8) the namespace is the SHA-256 of
`judgment-pack-gateway/delegated-action-key/1:` and the canonical JSON of
`{"authority", "key", "scope"}`, the scope being `{"host", "rootActor", "sub"}`:
the issuing host, the chain's root actor and its subject, never the transport
token. Such an entry holds one file more, `scope.json`, that scope, written before
`intent.json` and held to on every later open (a missing or other scope is
`action-journal-invalid`), and its `dispatch-<n>.json` records the receipt's
`delegation` member and the dispatching credential's digest beside the attempt (16 KiB). A second kind of entry,
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
where an operator wants replays served. For a client that sends `keyScope` it is
also at least the whole life of the longest job it starts, because that client may
reconcile at any point in it. Within it, no entry is removed. Back up
`actions/`, with `actions/index/` in it, with the store; a restored store without its
journal re-enables dispatch for every key and can answer that nothing was sent.

How far it grows, as defined limits. Before compaction: for each key, at most 16 KiB of
first scope, 33 KiB of entry and 16 MiB of response. After compaction: an unindexed key
is gone, and an indexed key stays for good at most 49 KiB, in practice a few small files.
The retained first scope and closed entries are what cannot be compacted, so they are what
grows with the number of keys. The gateway does not enforce these limits or the retention
period: it counts neither.

### Compaction

The gateway does not compact the journal itself. An operator compacts it
offline, without losing dispatch history:

1. Stop every gateway process that serves the store. The per-key lock holds one
   process only, and the journal's exclusive creation does not guard against a
   removal while a request is in flight.
2. Back up the store with `actions/`.
3. Keep `actions/index/` whole: nothing below removes a file from it. List the indexed
   entries: every `reservation` its records name. Then classify each entry in this order:
   - **Closed:** a `dispatch-<n>.json` recording `"closed": true`. Keep it whole, for
     good. Removing it would make an answer of `action-key-not-dispatched` false.
   - **Indexed:** keep it, except that its `action.json`, the only large file, may go once
     it is past the retention period, by the rule for its outcome below. Keep its
     `intent.json` and markers. What stays then answers as a dispatch that may have
     begun: an uncertain record and a read-back, never a send. Keep an indexed entry
     with no marker too: removing it would answer `action-key-outcome-unknown` for good.
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
   the key was used. For an indexed entry, move its `action.json` alone, and record
   the same line.
5. Restart the gateway. A client that retries a removed key sends the write
   again; the retention period is what makes that safe. A client that retries an
   indexed key whose `action.json` went sends nothing again, and is no longer served
   the response: its uncertain record and read-back are all it gets.

### A damaged entry

A key whose entry does not read (a missing or malformed `intent.json`, an
`action.json` that is partial or does not verify against the store, an identity
version this release does not read) is refused for good, as
`action-journal-invalid`, and never grants dispatch. This release's crashes do not leave
these: a reservation and a record appear whole, and a citation is durable before a
record names it. What is left is damage, an older release's crash, or a restore. A partial
or unreadable marker or answer is not refused: it counts as a dispatch that may have begun, and
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
   - a `dispatch-<n>.json` recording `"closed": true`: nothing was sent, and a client
     was told so;
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

**A damaged first-scope record.** An `actions/index/` file that does not read, or a
directory that is not private, refuses every request on its key, or on every key, as
`action-journal-invalid`, sending the members or not. Restore that one file from the
last backup that holds it; a first scope is never rewritten, so any backup holding it holds
it as it was. With no backup, write nothing: the key stays refused, and the client treats
its write as unknown. Removing the record lets another scope take the key and send, so an
operator who does that has first checked the target as above, and records it the same way.

**A closed or indexed entry that does not read** follows the same steps. An indexed entry is
removed only if the write provably did not take effect; `action-key-outcome-unknown` then
answers a reconciling request for good, and a plain request in its first scope dispatches.
A closed entry is not removed at all: a client was told that nothing would be sent, and may
have acted on that.

## Known limits

- **A key that sends neither member is scoped to the authority and the authenticated
  issuer and subject.** A takeover that authenticates as another subject reaches another
  reservation and sends again, and so does every such key after the configured issuer
  string or the authority changes, even for the same subject: settle pending keys first.
  This is §1.2b's rule, unchanged. A client whose takeover may change subject sends
  `keyScope`.
- **A first scope proves the same subject, not the same owner.** See above. It does not
  distinguish two workers of one subject, and it verifies nothing about a lease.
- **A first scope is held from the first request that sends the member.** A key another
  subject reserved without it has a reservation the record cannot see, since a namespace
  hashes its subject: a closing reconcile then answers for its own scope alone. An unflagged
  request of another subject in flight when a close lands is the same case. A key under a
  delegation has a first-scope record only if a closing reconcile made one, so an
  undelegated request sending `keyScope` does not find a delegated reservation that has none.
  A client flags from its first send: the agent does, and no earlier gateway accepted the
  member. The scopes do not meet otherwise: a key hashes the run and a random operation.
- **Absence is only as good as the journal.** A store restored without `actions/`, or a
  closing reconcile after an entry was removed with its first scope too, finds nothing
  and answers that nothing was sent. No gateway can tell.
- **A changed issuer string or authority strands a flagged key.** It answers
  `action-key-scope-conflict`, or fails at the citations first, and its outcome stays
  unknown: nothing is sent. Settle pending keys first.
- **`action-key-scope-conflict` says that a key exists.** It reaches only a holder of the key
  (SPEC.md §11.8's table says nothing in its other refusals).
- **A key whose 16 attempts were all answered is not closed.** A reconciling request answers
  `action-journal-exhausted`, which an agent reads as unknown. Nothing can be sent under it.
- **A delegated dispatch that lost its attempt to a close has been counted.** Its admission
  came before the marker, so one call of the leaf's limit is spent, with nothing sent.
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
  procedure above; the gateway bounds each entry, not their number, and enforces neither
  the retention period nor the growth limits it states.
