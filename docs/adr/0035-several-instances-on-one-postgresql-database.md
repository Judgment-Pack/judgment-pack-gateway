---
status: accepted
date: 2026-11-15
deciders: maintainer
---

# Several gateway instances on one PostgreSQL database: a hand-over between instances first, then each session held by the instance that minted it, beside one registry chain

## Context and problem statement

A deployment in service mode runs the gateway as more than one instance against one PostgreSQL
database: for availability, for load, and so that a roll-out can start the new instance before it
stops the old one (issue #386). Neither kind allows it today. The filesystem kind holds the
registry by a `flock(2)` lock for as long as the gateway runs (README.md, "One gateway per store
and registry"); the PostgreSQL kind holds the database by one start lease (ADR-0032, decision 4;
`docs/postgresql-store.md`, "One instance per database"), so a second start ends with
`start-lease-held`. ADR-0031, decision 10, recorded why: parts of the gateway assume they are the
one writer. This record lists those assumptions in the code, sets out four ways past them, and
recommends an order. Nothing of it is built.

### What assumes one writer

Line numbers are of `go/` at commit 5f88992.

**(a) Chained and signed structures.**

1. A session's chain is the memory of the process that mints into it: `sessionState` holds the
   next `callIndex`, the `prevSignature` the next receipt chains to, `sealed`, and the
   acquisitions in flight (`serve.go:37-59`); the stamp reads and moves them under the service's
   lock (`serve.go:1263-1267`, `1320-1337`). SPEC.md states it normatively: a session an earlier
   process left open "is not continued from the store, whose last receipts may have been taken
   away (§2)" (§6, `/acquire`; §3c, first paragraph).
2. Admission takes up a session this process does not hold only where the store holds no receipt
   in it (`serve.go:1898-1909`, `open_sessions.go:88-103`). The refusal says the session "was left
   open by an earlier process" (`open_sessions.go:45`), which a live instance beside it is not.
3. The database already decides which writer takes an index: a series' name is one across scopes
   (`store_pg.go:533-535`), and an entry is inserted once at its series and index, a second insert
   answered `taken` (`store_pg.go:554-562`). Two instances that admit one new session each run
   their source; the first stamp takes index 0, and the second fails after its source ran.
4. A seal is made from the holder's count, refused while that process has an acquisition in
   flight, and refused for a session the process does not hold (`serve.go:1951-1998`). An
   acquisition in flight on another instance is not seen; by (3), its stamp fails at index 0, so
   it adds no receipt past the seal.
5. A seal is read, checked and appended in three steps: the log is read and walked, a session
   already sealed is refused, and only then is the record appended (`store.go:308-364`). The
   append's advisory lock is taken inside the append alone (`store_pg.go:672`), so two writers
   sealing one session at once could both append (ADR-0031, decision 10); today only the holder
   of (4) seals. Schema version 4 keeps the log one chain whoever appends. Without the lease, two
   starts on an empty database would both make the registry, and the second's create, refused
   `taken` (`store_pg.go:768-781`), would fail that start.
6. The key in force: the start walks the registry and refuses a walk that does not end at its own
   key (`store.go:250`); a seal loads only under the key current at its line (SPEC.md §3b), and a
   receipt is held to the verifier's expected `authority` (§1.4, `authority-mismatch`). Nothing
   holds two instances to one seed or one authority: an instance under another seed reads the
   other's seals as lines that do not load, and starts.

**(b) State held in memory.**

1. The sessions, and the lock that orders admission, stamp and seal (`serve.go:290-291`). The
   admission question across scopes runs "under the service's lock" (`docs/postgresql-store.md`,
   "Scope identifiers"), which holds one process.
2. The seals a process wrote are judged by its map; the registry is read only for a session it
   does not hold (`serve.go:1869-1884`).
3. The admission gate, which SIGUSR1 closes and SIGUSR2 reopens (`serve.go:292-298`,
   `main.go:537-539`), and the stop, which cancels every source in flight (`serve.go:274-279`).
4. The sealed tokens of token steps, per source and scope identifier (`token_step.go:214-226`):
   each instance obtains its own.
5. Delegation (SPEC.md §11): the bound credentials and the DPoP proofs seen within the window
   (`delegation_credential.go:63-65`, `465-471`), "in memory only" (§11.3). A credential is bound
   at one instance, another answers `credential-mismatch`, and a revocation reaches the instance
   it is sent to. The admission read, made at every dispatch against the issuing host, is not in
   memory.
6. The scope views, opened at the start for the scope identifiers the configuration names
   (`serve.go:446-456`), each identifier recorded once whoever records it
   (`store_pg_scopes.go:43-61`, `ON CONFLICT DO NOTHING`).

No rate or throttle state is kept (ADR-0029: the gateway keeps no cursor). The paths the
PostgreSQL kind refuses keep one-writer state of their own and stay refused: the witness's files
(§8), the action journal and its key locks (`serve.go:1384-1386`), and descriptor provenance's
keys, walked once at the start (`serve.go:511-518`).

**(c) Operational.**

1. The start lease: one row of `gateway.start_lease`, taken before anything is written
   (`main.go:618-646`), renewed, and held by every write as its last statement
   (`store_pg_lease.go:86-121`, `335-347`).
2. The filesystem kind's registry lock (`registry_lock_unix.go:24-50`, `rotate_key.go:138-163`,
   `main.go:511`): a lock on one host, which no test takes on a network filesystem.
3. Migrations: a start refuses a schema other than its binary's; `gateway store migrate` may run
   beside a serving instance, which does not check again; migration 4 is to run with every
   instance stopped (`docs/postgresql-store.md`, "The migration command", "What the run-time
   login may do").
4. Key rotation: refused with the PostgreSQL kind (`main.go:567-579`); on the filesystem kind
   made with the gateway stopped, under the registry lock (SPEC.md §3b, "Rotating").
5. The export: one snapshot of every scope, taking no lease (`store_pg_scopes.go:233`). It runs
   beside a serving instance already.
6. `gateway store remove-scope` takes the start lease to know that no instance serves
   (`store_remove_scope.go:375-400`).
7. `gateway seal-open` and `sealOpenAtStart` are refused with the PostgreSQL kind
   (`seal_open.go:259`, `storage_kind.go:130-132`): a session an instance left open when it
   stopped has no seal on this kind, after a roll-out or after a crash. (Built since, the third
   step, gateway #466: both seal on this kind under the start lease, `docs/postgresql-store.md`,
   "Sealing the sessions an instance left open".)

So the one-writer rule now guards four things: a session's chain and count (a1 to a4), the
registry's one seal per session (a5), one key and one authority (a6), and the operations that need
no instance serving (c1, c3, c4, c6).

### What a verifier reads

Both verifiers (`go/verify.go`, `verify-ts/src/verify.ts`) read the layout of SPEC.md §1.3 and one
registry. They hold receipts to one pinned key and the keys its rotations reach, to one authority,
and to a contiguous chain per session, and hold each session to its first loadable seal. Neither
reads a receipt's `servedAt` or a seal's `sealedAt` for order. The verdict on a store written by
one instance must not change under any option.

## Decision drivers

- Every verdict on a store written by one instance stays what it is, and no record changes form.
- A session's receipts are never continued from a chain or count the store hands back (SPEC.md
  §2, §6), and the registry holds one seal per session.
- No write of an instance commits after it lost the right to write, as decided by the database's
  clock (ADR-0032, decision 4).
- Every instance on one database signs with one key under one authority; a start that would not
  is refused.
- A call the instance it reached cannot serve is refused by name before its source runs, never
  served from an empty memory.
- The run-time login gains no DELETE, and no table but documents and the lease rows becomes
  changeable by it (ADR-0031, decision 6).
- The smallest step that lets a roll-out overlap comes first.

## Considered options

Each option says what changes in SPEC.md, in both verifiers and in the corpus's vectors; the
schema, the start's checks and what an operator configures; how it fails when an instance dies
mid-session, when clocks differ and when a lock is lost; what bounds its throughput; and its size.

### A. One chain, any instance writes into any session

Every instance mints into every session. The next `callIndex` and `prevSignature` are read from the
database under a lock per session (a transaction advisory lock keyed on the session, since a row
lock needs UPDATE); each acquisition in flight is a row with a lease by the database's clock; a
seal counts the entries under the same lock once no live reservation holds the session.

- SPEC.md: §6 (`/acquire`, `/seal`) and §3c's first paragraph change, since a session is continued
  from the store; §2 and §5 then rest the count a seal signs on the database's privileges (no
  DELETE for the run-time login) rather than on the minting process's memory. An ordinary seal of
  a count read back from the database says what §3c lets only a seal after an interruption say:
  either every ordinary seal's meaning changes, for one-instance stores too, or a new seal kind is
  added.
- Verifiers and vectors: none for an unchanged seal form; for a new seal kind, both verifiers,
  `--ordinary-seals-only`, and new store vectors.
- Schema: a session head and a reservation table the run-time login changes, against ADR-0031,
  decision 6; or the contract's documents and leases, with a lease's expiry moved to the database's
  clock (ADR-0031, decision 9).
- Start: one key and one authority across instances; a lease per instance.
- Operator: any router, no affinity. A delegated run reaches any instance, so its binding and the
  DPoP window move into the database; a binding at every instance would accept one proof once at
  each.
- An instance dying mid-session: its reservation keeps the session from being sealed one lease
  longer, and the next call continues the chain on another instance. Clocks: one session's
  receipts carry several instances' clocks, out of time order. A lost lock: the session's lock is
  the transaction's and ends with it; a write fenced on a lost lease writes nothing.
- Throughput: every receipt takes the session's lock and two more statements; calls of one session
  serialize in the database.
- Size: **large**.

### B. One chain per instance, the verifier joins them

Each instance has a stable identifier the operator names and seals into a registry log of its own
(`gateway.logs` holds a log per name). A session stays with the instance that minted it, since its
chain is still in memory, so B needs C's affinity as well.

- SPEC.md: §1.3 (a registry per instance), §3 (one seal per session across the logs), §3b (a walk
  per log), §4 and §4.1 (a set of registries, each absent or unreadable on its own), §6 `/registry`
  (which log it serves).
- Verifiers and vectors: both verifiers join the logs; a new finding for a session sealed in two
  logs; new store vectors with two logs, and with one withheld.
- The anchor: a verifier finds a deleted sealed session (`sealed-session-missing`) only from a seal
  in a log it holds, so a withheld log hides the deletion of every session sealed there. The set of
  logs must then be anchored itself, by a record in a chain every instance appends to: the one
  chain this option removes.
- Schema: a log per instance name; the export writes several registries. Start: one live instance
  per name.
- Failures: as C. Throughput: it removes the one append lock, held for one short insert per seal,
  which bounds nothing measured.
- Size: **large**.

### C. Each session held by the instance that minted it, one registry chain

Instances serve beside one another. A session stays with the instance whose stamp took its index 0,
as the database's keys already decide (a3); the registry stays one chain, appended under the lock
it has (a5).

- Built: schema version 6 puts one row per instance in place of the start lease's one row (its
  identifier, key id and authority, its renewal and expiry by the database's clock), and each
  instance's writes are fenced on its own row as they are now. A series records the instance that
  holds it and is made at admission rather than at the stamp, so a second instance is refused
  before its source runs; a series that holds no receipt is taken up by its holder, or by another
  instance once the holder's row has expired. A call into a session another live instance holds is
  refused by a sentence of its own, not as "left open by an earlier process". The registry's
  already-sealed check is made in the append's transaction, under its lock, so one seal per session
  holds without the argument from (a3) and (a4); a start that finds the registry made since its read
  goes on. `gateway store remove-scope`, and a migration that rewrites a table, hold a row that
  refuses a start, and are refused while any instance's row is live.
- SPEC.md: no verification step, record or finding changes. "An earlier process" in §6 (`/acquire`,
  `/seal`) and §3c becomes "another process", and §6 gains the answer to a session another live
  instance holds.
- Verifiers and vectors: none. A store written by several instances has the form of one written by
  one.
- Start: refused for a key id or an authority other than a live instance's, and for a schema other
  than the binary's (as now); one instance in the one-instance mode and an instance in this mode
  refuse each other.
- Operator: an opt-in member (a later engine configuration version than D's 25), one instance per database staying
  the default; a router, or the caller, that sends every call of a session to the instance that
  answered its first (the session is a member of the body, not a header); one seed, authority and
  set of sources on every instance; `connections` + 1 per instance in the server's connection
  budget; a delegated run kept to the instance that bound its credential.
- An instance dying mid-session: its sessions stay open and every other instance refuses them, as a
  restart leaves them now; they read `unregistered-session`, observed `session-open`, until sealed
  after an interruption (the third step, below). A lost lease stops the instance
  (`start-lease-lost`, as now). Clocks: leases are the database's; receipt and seal times are each
  instance's, one clock per session; seals in the registry need not be in time order, and no
  verifier reads them for it.
- Throughput: acquisitions scale with instances across sessions; one session's calls serialize in
  one process, as now; seals serialize on the append lock; each new session asks every recorded
  scope (2N + 5 statements), on whichever instance admits it.
- Size: **medium**.

### D. One writer, with an orderly hand-over

The start lease stays. A start configured to wait polls the lease's row up to a bound instead of
being refused at once; a stop by SIGTERM closes the admission gate, waits for the acquisitions in
flight up to a bound, and then releases the lease, so the waiting instance takes it within one poll.

- SPEC.md, verifiers, vectors and schema: none.
- Start: waits for the lease where configured, and is refused as now at the bound. Operator: the
  wait and the drain bounds; an orchestrator that replaces the instance, or one that surges with a
  readiness check the waiting instance passes (question 3).
- An instance dying mid-session: its lease expires within 45 seconds of its last renewal (as now)
  and the waiting instance takes it; its sessions are left open, as now. Clocks: the database's
  alone. A lost lease: as now.
- Throughput: one instance. It gives no load sharing, and no availability past the 45-second
  takeover.
- Size: **small**.

## Decision outcome

Decided on 2026-11-15 by the maintainer: **D first, then the third step, then C** (question 1's recommended order). The third step: a seal after
an interruption (SPEC.md §3c) on the PostgreSQL kind, for the sessions of an instance that stopped,
made by a command (`sealedVia: "command"`) and by a start (`"start"`), once the instance's lease has
expired. It adds no record form. A and B are not recommended. Because:

- D meets the roll-out need of #386 with no change to a record, the schema or a verifier, and keeps
  every guarantee of ADR-0032.
- C shares the load and keeps serving through the loss of an instance without changing a
  verification step: it builds on what the database already decides (a3) and on the rule SPEC.md
  already states, that a session is never continued from the store. The reference Runner's
  PostgreSQL design has the same shape (its D3, D18 and D19): leases on the database's clock, every
  write fenced, and what one host holds refused on another.
- The third step serves D and C alike: on this kind a session an instance leaves open has no seal
  today (c7), and every roll-out leaves one for each session open at the stop.
- A changes what an ordinary seal establishes, or adds a seal kind, for every store; B removes the
  anchor against whole-session deletion unless the set of logs is anchored in a shared chain. Each
  changes SPEC.md, both verifiers and the corpus, for what C gives without.

The filesystem kind stays one instance per store and registry (README.md), its lock unchanged.

### Consequences

- Good, because no step changes a record, a finding or a vector: a store written by one instance
  reads to every verifier as it does today, and one written by several under C reads as one
  written by one.
- Good, because every write stays fenced by the database's clock, and a call an instance cannot
  serve is refused by name before its source runs.
- Bad, because under C the caller, or its router, keeps a session to one instance; a call that
  reaches another is refused, not forwarded.
- Bad, because an instance that stops leaves its open sessions unsealed until the third step seals
  them, and that seal says what §3c says of every such seal: its count was read from the store.
- Bad, because the seed is on every host that runs an instance (SPEC.md §5: one protected signing
  identity).
- Bad, because a delegated run's credential is bound at one instance and revoked there; the
  admission read still refuses a revoked delegation at every instance.
- Revisit when a router cannot keep a session to one instance, when key rotation reaches the
  PostgreSQL kind (with several instances, every instance stopped, as `rotate-key` requires on the
  filesystem kind), or when the registry's append lock is measured as a bound.

## Questions for the maintainer

Each with this record's recommendation first. Question 1 is answered (D, then the third step, then C). Questions 2 to 12 are taken at their recommended answers when the step they bear on is built, unless the maintainer answers otherwise on that step's issue.

1. The order: D, then the third step, then C (recommended); D, then C, then the third step; C alone.
2. D's wait: a member of `storage` at a new engine configuration version, as `connections` is
   (recommended); a flag of `serve --config`.
3. D's waiting instance: listens and answers `503` until it holds the lease, so a surge roll-out
   sees it ready (recommended); does not listen until it holds the lease, for a replace roll-out.
4. A stop by SIGTERM: closes the gate and waits for acquisitions in flight up to the operation's
   bound (recommended); cancels them, as now.
5. C: opt-in by a configuration member, one instance staying the default (recommended); several
   instances by default once built.
6. C: how a session's calls reach its instance: the caller keeps to the instance that answered its
   first call (recommended, no new surface); a request header repeating `session`, for a router;
   the gateway forwards to the holder.
7. C: what another instance answers: `409` with a fixed sentence naming no instance (recommended);
   `421`; the `400` of a session left open, as now.
8. C: the start refuses a key id or an authority other than a live instance's (recommended); it
   refuses as well a set of sources or scope identifiers other than theirs.
9. C: a delegation credential stays bound at one instance (recommended); bindings and the DPoP
   window move into the database.
10. C: a migration runs with every instance stopped, as migration 4 requires (recommended); a
    migration that only adds may run beside instances of the earlier release.
11. The third step at a start under C: seals the sessions whose holder's lease has expired
    (recommended); runs only with every instance stopped.
12. The filesystem kind stays one instance per store and registry (recommended); it takes several
    as well, which needs its lock tested on a network filesystem.

## More information

- Issue #386; ADR-0031, decisions 4, 6, 9 and 10; ADR-0032, decision 4; ADR-0033, decision 3;
  ADR-0034, option 1 (the removal's hold on the start lease).
- SPEC.md §2, §3, §3b, §3c, §4, §5, §6 (`/acquire`, `/seal`, `/registry`), §11.3, §11.4.
- `docs/postgresql-store.md`, "One instance per database" and "Scope identifiers"; README.md, "One
  gateway per store and registry".
- The reference Runner's PostgreSQL design (`docs/design/store-postgresql.md` in its repository):
  D3 (a lease per claim, on the database's clock), D13 (one lock per journal write), D17 (a row
  version per trigger), D18 (a claim per occurrence), D19 (what each host keeps, refused on
  another) and D20 (a stated bound for decisions on wall clocks). No decision of C, or of D, reads
  another instance's wall clock, so D20's bound has no counterpart here.
