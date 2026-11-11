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
`{"indexVersion":"1","authority","key","reservation","scope"}`, and under a delegation
`subjectRecord` too. `scope` is the `{issuer, subject}` a request authenticated as, or a
delegated request's scope (§11.8). `reservation` and `subjectRecord` name its journal
entries, because an entry does not hold its key and an operator needs to tell which are
indexed. A request sending `keyScope` creates it before reserving, and so does a delegated
run's actor, whose leaf names the write, sending no member. An undelegated request sending
neither member only reads it. It appears whole or not at all, and only one scope can
create it, across processes. Any other scope then gets `action-key-scope-conflict` before
anything new is reserved or sent. The record is one store's. The file's name hashes the key
alone and the record names the authority, so a changed authority string finds the record
and answers a conflict: hashing it into the name would make the record disappear, and the
key read as never seen.

**It takes nothing a scope holds.** A scope that reserved the key before the record existed
keeps that reservation: it is answered from it, with its retained answer, its salts and
its read-back, whatever members it sends. A request of it that would dispatch or close is
refused as `action-key-scope-conflict`, and leaves the entry as it was. `action.json` is the
only server-side copy of the salts that open a receipt's commitments, so another requester
holding a key must not be able to take that from its holder.

**What it proves.** The same subject, not the same owner. The gateway holds no lease, so two
workers authenticated as one subject are one scope, and it cannot tell a legitimate takeover
from any other request of that subject. A takeover by another subject gets one mutation, or
its outcome stays unknown. The key is no secret and a first scope is no authorization: the
key is not a credential, a receipt carries it as `action.delivery.key`, and a client may
derive it from what it intends. Anyone who passes the action ladder and holds a key no record
names can take it, which denies that key to others and sends nothing. The agent's protection
is that its key hashes a run and a random operation, and that it flags from its first send.

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
| A first scope another's, no reservation of its own | `action-key-scope-conflict` |
| A first scope and no reservation | `action-key-outcome-unknown`: a first request may be on its way, the first was refused or died before its reservation, or the entry was removed or not restored. It never closes here: see [a key answering unknown](#a-key-answering-action-key-outcome-unknown). A sender other than the actor is told `action-key-actor-only` |
| No first scope, no reservation | Closes; `action-key-not-dispatched` (`action-key-actor-only` to a sender other than the actor) |
| Its reservation is for other content | `action-key-conflict` |
| A close | `action-key-not-dispatched`, again (`action-key-scope-conflict` if the first scope is another's) |
| `action.json` | First holds the first scope, if it may. Its evidence, or the read-back |
| A marker with no answer, or one above a free attempt | First holds the first scope, if it may. Uncertainty, then the read-back. Above a free attempt under a delegation, no marker can mint a receipt: `action-journal-invalid`, or `action-key-actor-only` to another sender |
| All 16 attempts answered | `action-journal-exhausted` |
| Nothing begun, a freed attempt included | First holds the first scope, if it may. Closes; `action-key-not-dispatched` (`action-key-actor-only` to a sender other than the actor; `action-key-scope-conflict` if the first scope is another's) |

A request reconciles in a session this process may mint into: after a restart, a fresh one,
or the `session` step refuses it, and an agent reads that as unknown.

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

**Under a delegation** (§11.8) a request sends no `keyScope`: its scope is its chain's. The
actor's first reservation creates the first-scope record, and so does its closing reconcile,
when its leaf names the write. It takes the subject record too, which holds against another
root actor of that subject if the first-scope record is ever lost. A leaf that does not
name the write's source and tool reaches nothing by its key and takes nothing: before any
first scope is read it is refused, as `action-key-unauthenticated` if it is reconciling or its
scope holds a reservation, and otherwise as its admission would be, leaving no reservation
bound to its content. A leaf that names them and that its own scope check would still refuse
(the effect, or a limit this gateway does not know) could never dispatch, so its plain request with
no reservation in its scope is refused the same way, and leaves nothing. For what the key lookup
answers it is not held to the effect (spec #284 NC1): it reads what its scope holds, and its
reconcile closes as the actor's does. A request the issuing host refuses at admission does take
both records and the reservation first, so it can deny a key. A sender other than the actor is
compared with the record, and never closes and never creates.

## Target support belongs to a pinned binding

Binding version 3 requires `actionRecovery`, covering every write tool with a
contract or explicit null for unsupported recovery. A write binding declares recovery separately for each allowed write tool. An
idempotency argument is an exact argument member carrying the action key; the
gateway inserts it before the effect-policy check and refuses a conflicting
caller value. It does not place a generic header on unrelated services and assume
the service honors it. A closed decision policy reaches the inserted member as the
gateway's: that one top-level member while it holds the key, and nothing else by it;
a request with no action key is given no member, and one it sends is refused as any
other unreached argument. A policy of the tool that binds, fixes or shapes the member,
or a value under it, is refused when the configuration is read, since the member holds
the action key, which no policy decides.

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
  another subject, plain or reconciling, delegated or not, sends nothing and leaves the key's
  holder its answer. Each crash point above restarts into the answer its table gives, and a torn
  record refuses no key. The compaction procedure followed to the letter, from the journal
  alone, leaves no false answer and no second mutation under a first scope.

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
practice about the size of its response; a delegated one is at most 16 MiB and 289 KiB
(below). The gateway sets no bound on the number of entries: there is one for every key
every caller has used. A directory named
`.staging-*`, in `actions/`, an entry or `actions/index/`, is what a crash left while
making a record durable: nothing reads it, and it may be removed while the gateway
processes are stopped.

`actions/index/<sha256>.json` is a key's first scope: at most 16 KiB, in practice a few
hundred bytes, one for every key a request sent with `keyScope`, a delegated actor reserved,
or a reconciling request closed. An entry a record's `reservation` names is an **indexed
entry**, and one its `subjectRecord` names is that key's subject record, so the entries of a
key pair from the journal alone. Its name is the lowercase hex SHA-256 of
`judgment-pack-gateway/action-key-index/1:` followed by the canonical JSON of `{"key"}`.

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
refused (`action-key-scope-conflict`) even with the first-scope record lost. Compaction
keeps it for good: it holds no response, and nothing is gained by removing it.

**The journal and the dispatch history.** The history of what was dispatched is
the store's: every action receipt, with its delivery key and outcome, and every
read-back receipt. The journal entry is what refuses a second dispatch under a
key, and `action.json` is the only server-side copy of the salts that open its
receipt's commitments. Removing an entry therefore loses no receipt. It
re-enables dispatch under that key, and it loses the replay of the response and
the salts unless the entry is kept elsewhere.

### Retention

Keep a response for as long as a client may retry under its key. The operator sets
that retention period: at least the longest time any client keeps retrying one
write (a workflow platform's retry window, an agent's run lease), and longer
where an operator wants replays served. For a client that may reconcile, one that sends
`keyScope` or a delegated run, it is also at least the whole life of the longest job it
starts, because it may ask at any point in it. Within the period, no entry holding a
`action.json` or a marker with no answer is touched. Back up `actions/`, with
`actions/index/` in it, with the store; a restored store without its journal re-enables
dispatch for every key and can answer that nothing was sent.

How far it grows, as defined limits, per key:

| Key | Before compaction | After compaction, for good |
| --- | --- | --- |
| Undelegated, no record | 33 KiB and a 16 MiB response | Nothing, once classified below as removable. Closed, begun and damaged entries stay |
| Undelegated, with a record | 16 KiB of record, 33 KiB and a 16 MiB response | 49 KiB |
| Delegated | 16 KiB of record, 16 KiB of subject record, 289 KiB and a 16 MiB response | 321 KiB |

Those are bounds; in practice a key is a few small files. What cannot be compacted grows with
the number of keys. The gateway does not enforce these limits or the retention period: it
counts neither. `actions/index/` is one flat directory, and its behaviour at millions of files
has not been measured.

### Compaction

The journal is compacted offline, without losing dispatch history, by this procedure.
`gateway journal compact --store <dir> --archive <dir> --retention <duration>` does its
steps 3 and 4 (below, "The command"); stopping the gateway processes, the backup and the
restart stay the operator's.

1. Stop every gateway process that serves the store. The per-key lock holds one
   process only, and the journal's exclusive creation does not guard against a
   removal while a request is in flight. A gateway holds a shared lock (`flock(2)`) on the
   store's directory from before it builds its service until it stops, under either serve
   command, and the command takes it exclusive: the command is refused as
   `action-journal-held` while any gateway holds it, and a gateway is refused its start as
   `action-journal-held` while a compaction holds it, before it makes anything in the store.
   A store that is not there yet is locked once the start has made it. The lock is
   advisory, and as good as the filesystem's `flock(2)`: a gateway of v0.24.0 or earlier
   takes none.
2. Back up the store with `actions/`.
3. Keep `actions/index/` whole: nothing below removes a file from it. List what its records
   name: every `reservation` and every `subjectRecord`. A directory named `.staging-*` is no
   entry, and may be removed. Then classify each other entry, reading only the journal: the
   first of these that fits is its class.
   - **Closed:** a `dispatch-<n>.json` recording `"closed": true`. Keep it whole, for
     good. Removing it would make an answer of `action-key-not-dispatched` false.
   - **Subject record:** named by a `subjectRecord`, or holding only `scope.json`. Keep it,
     for good.
   - **Indexed:** named by a `reservation`, or holding `scope.json`, which is a delegated
     reservation. Keep it, except that its `action.json`, the only large file, may go once
     it is past the retention period, by the rule for its outcome below. Keep its
     `intent.json`, `scope.json` and markers. What stays then answers as a dispatch that may
     have begun: an uncertain record and a read-back, never a send. Keep an indexed entry
     with no marker too: removing it would answer `action-key-outcome-unknown` for good.
   - **Does not read:** an `intent.json` or an `action.json` that is not complete JSON, or
     none of the former. Keep it, and follow the procedure for a damaged entry.
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
4. Move each entry to be removed to an archive outside the store, whole, and
   record one line per entry: the namespace, the receipt it cites, its outcome,
   the reason, and the date. The archive keeps the salts and the evidence that
   the key was used. For an indexed entry, move its `action.json` alone, and record
   the same line.
5. Restart the gateway. A client that retries a removed key sends the write
   again; the retention period is what makes that safe. A client that retries an
   indexed key whose `action.json` went sends nothing again, and is no longer served
   the response: its uncertain record and read-back are all it gets.

**The command.** `gateway journal compact` reads only the journal, as step 3 does, and
refuses (exit 1, `journal compact: ` and the refusal) where it cannot follow it as written:

- **It never takes a journal it cannot read as empty.** A store that is not a directory or
  holds no `actions/` is `action-journal-unavailable`; an `actions/` or `actions/index/` that
  is not a private directory is `action-journal-invalid`, and one that cannot be listed is
  `action-journal-unavailable`. Anything in `actions/index/` but a `.staging-*` directory that is
  not a first-scope record reading as the gateway writes one, under the name of its own key, is
  `action-journal-invalid`: an entry it names would be read as no key's. Each of these refuses
  before anything moves.
- **It reads each entry more strictly than the gateway.** An entry that is not a private
  directory, holds a file the gateway does not write (a `.staging-*` directory aside), has no
  `intent.json` or one that does not read as this journal version and an identity version this
  release reads, holds a `not-dispatched-<n>.json` without its marker or a marker above a
  missing one, or holds an `action.json` that is not an action receipt with a delivery whose
  key, authority and requester (for a delegated entry, its `scope.json`) hash to the entry's
  name, does not read, and is kept.
- **It keeps every uncertain entry,** indexed or not, and every begun one: the check at the
  target is the operator's, and an uncertain entry the operator has checked is moved by hand,
  as in step 4.
- **It moves** an entry that never sent; an answered one whose receipt's `servedAt` is longer
  ago than the retention period when it runs (a receipt served exactly the period ago stays);
  and an indexed entry's `action.json` by the same rule. The retention period is a duration of
  whole seconds, at least one (`720h`). It removes nothing from `actions/index/`, no
  `.staging-*` directory and no receipt, and deletes nothing.
- **The archive** is a private directory outside the store, on the journal's filesystem, so
  that a move is a rename and never a copy and a removal; it is made at `0700` when it is not
  there, and another compaction holding it refuses (`action-journal-archive`). An archive that
  is the store, is inside it or holds it refuses; the directories along each path are compared
  as files, not by their names, so a name that differs only in case, on a filesystem that
  ignores case, or a second mount of the store does not pass for outside it. Each retirement
  is `<archive>/<namespace>.<n>`, `n` the first number from 1 that no retirement of the
  namespace holds: a private directory holding `entry`, the entry whole, or `action.json`, an
  indexed entry's, and `retirement.json`.
- **`retirement.json`** is step 4's line, as canonical JSON: `recordVersion` (`"1"`), `store`,
  `namespace`, `class` (`never-sent`, `answered` or `indexed`), `moved` (`entry` or
  `action.json`), `receipt` (`sessionId` and `callIndex`; null for an entry that never sent),
  `outcome`, `servedAt`, `retentionSeconds` and `archivedAt`. The receipt is not verified
  against the store: it stays under `receipts/`, and its copy moves with the entry.
- It prints a line for each name in `actions/` but the index, `retired` or `kept` and why, a
  `finished` line for each retirement it finishes (below), and a last line of counts.

**A compaction that stops**, killed or refused part way, is run again with the same
`--archive`: a rerun finishes only the retirements staged in the archive it is given. Each
retirement is made durable in an order no crash breaks: a staging directory `.staging-*` in
the archive, then the record in it, then the move, each durable before the next, and only
then its final name.
A rerun first names every staging directory of the archive that holds what was moved beside
its record, and leaves one that moved nothing as it is, inert. A gateway that serves between
the two is answered as the journal then stands. What is moved is what was read: an entry
replaced since stops the compaction, and is read again on the rerun. The move is made by
path, into the staging directory its record was made durable in: one replaced since stops
the compaction before the move.

### A damaged entry

A key whose entry does not read (a missing or malformed `intent.json`, an
`action.json` that is partial or does not verify against the store, an identity
version this release does not read) is refused for good, as
`action-journal-invalid`, and never grants dispatch. This release's crashes do not leave
these: a reservation and a record appear whole, and a citation is durable before a
record names it. What is left is damage, an older release's crash, or a restore. A partial
or unreadable marker or answer under no delegation is not refused: it counts as a dispatch
that may have begun, and the key is answered as uncertain and read back. Under a delegation a
partial marker is refused too, as `action-journal-invalid`: a retry mints its receipt from it
(§11.7), and a crash does not leave one. To resolve a refused key:

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
last backup that holds it, at mode `0600` under a directory at `0700`: anything wider stays
refused until `chmod`. A first scope is never rewritten, so any backup holding it holds it as
it was. With no backup, write nothing: the key stays refused, and the client treats its write
as unknown. Removing the record lets another scope take the key and send, so an operator who
does that has first checked the target as above, and records it the same way.

**A damaged subject record.** A `scope.json` in a subject record that does not read refuses
the run's own actor, and a re-issued delegation, as `action-journal-invalid`, plain and reconciling,
though the first scope and the reservation are fine; the subject, the issuing host and an operator
are still answered. Find it by the `subjectRecord` of the key's first-scope record. Stop the gateway
processes serving the store, and copy it out. Restore that one file from a backup, at mode
`0600`. With no backup, if the key's first-scope record reads and names this scope, move the
subject record to the archive whole: the actor's next request writes it again, and the first scope
goes on refusing every other scope. If the first-scope record is gone too, keep it: it is then
all that holds the key against another root actor of that subject. Record it as above.

**A closed or indexed entry that does not read** follows the same steps. An indexed entry is
removed only if the write provably did not take effect; `action-key-outcome-unknown` then
answers a reconciling request for good, and a plain request in its first scope dispatches.
A closed entry is not removed at all: a client was told that nothing would be sent, and may
have acted on that.

### A key answering `action-key-outcome-unknown`

A first scope with no reservation: a first request refused or killed after its record and
before its reservation (a full disk is enough, with nothing sent), or a reservation removed by
hand or not restored. The gateway cannot tell these apart, so it never closes here: a close
after a partial restore would answer `action-key-not-dispatched` over a write that was sent,
which is the one answer this design must never give falsely. The answer stands until someone
acts, and a client that only reconciles, as an agent's host does, never moves it on its own.

1. **Find it.** The record names the key and the `reservation`; that entry is not there. Stop
   every gateway process serving the store, so that no first request is in flight.
2. **Check at the target** whether the write under that key took effect: the declared read-back
   tool with the key, or the target's own records. Check the backups too: an entry that exists
   in one was reserved, and may have been dispatched.
3. **Decide:**
   - it took effect, or it cannot be told: keep the record. The answer stays unknown for good,
     another scope stays refused, and the client treats the write as done or unknown;
   - it provably did not take effect, and the client still wants it: keep the record. A plain
     request in the first scope, with the same content, dispatches once;
   - it provably did not take effect, and it is to be closed: move the record alone to the
     archive. The next reconciling request is the first this key has seen, and closes it, and
     `action-key-not-dispatched` is then as true as the check at the target was.
4. **Record** the key, how the target was checked and what it showed, the decision, and who made
   it and when. That check, not the gateway, is what such a close rests on.

## Known limits

- **A key that sends neither member is scoped to the authority and the authenticated
  issuer and subject.** A takeover that authenticates as another subject reaches another
  reservation and sends again, and so does every such key after the configured issuer
  string or the authority changes, even for the same subject: settle pending keys first.
  This is §1.2b's rule, unchanged, on a key no record names. A client whose takeover may
  change subject sends `keyScope`.
- **Another requester holding a key no record names can take it.** A key is no secret. That
  denies the key to others and sends nothing, and it takes nothing the holder already reserved.
  Its answer, `action-key-not-dispatched`, speaks for its own scope: if another subject dispatched
  under that key with no member, it is told nothing of that. The holder's request that would have
  dispatched a freed attempt is then refused, and it may send the write under a new key only once it
  knows nothing was sent.
- **A first scope proves the same subject, not the same owner.** See above. It does not
  distinguish two workers of one subject, and it verifies nothing about a lease.
- **A first scope is held from the first request that sends `keyScope` and passes the action
  ladder, reconciling or not, or a delegated actor's first request whose leaf names the write.**
  A key another subject reserved before that has a reservation the record cannot see, since a
  namespace hashes its subject: a closing reconcile then answers for its own scope alone, and a
  first request of the record's scope sends. An unflagged request of another subject in flight when
  a close lands is the same case. A client flags from its first send: the agent does, and no earlier
  gateway accepted the member.
- **Absence is only as good as the journal, and the journal is one store's.** A store restored
  without `actions/`, a closing reconcile after an entry was removed with its first scope too, and
  a second store under the same authority, a standby or a move to a fresh store, each find
  nothing and answer that nothing was sent. No gateway can tell. A client reconciles at the store
  that took its first send.
- **A key answering `action-key-outcome-unknown` stays there until an operator acts:** see above.
  A client that only reconciles strands with nothing sent, in the narrow window of a first
  request refused or killed between its record and its reservation.
- **A changed issuer string or authority strands a flagged key.** It answers
  `action-key-scope-conflict`, or fails at the citations first, and its outcome stays
  unknown: nothing is sent. Settle pending keys first.
- **`action-key-scope-conflict` says that a key exists.** It reaches only a holder of the key
  (SPEC.md §11.8's table says nothing in its other refusals).
- **A key whose 16 attempts were all answered is not closed.** A reconciling request answers
  `action-journal-exhausted`, which an agent reads as unknown. Nothing can be sent under it.
- **A plain request does not look above a free attempt.** With a lower marker lost to damage and a
  higher one not recording a close, it may dispatch at the free attempt, as it did before this
  release. No crash leaves this: each marker is durable before the next can exist. A reconciling
  request does look, and does not close there.
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
- **The gateway does not compact the journal while it serves.** Compaction is the offline
  procedure above, by `gateway journal compact` with every gateway process stopped; the
  gateway bounds each entry, not their number, and enforces neither the retention period
  nor the growth limits it states.
- **The store lock keeps out the gateways that take it.** A gateway of v0.24.0 or earlier
  serving the store does not hold it, and a compaction beside one is not refused; a network
  filesystem's `flock(2)` may not exclude across hosts. Stopping every gateway process stays
  step 1 of the procedure. The compaction's moves are made by path, each checked just before
  and after it against what it holds; a process that ignores the lock and replaces a directory
  between the check and the move is not kept out.
