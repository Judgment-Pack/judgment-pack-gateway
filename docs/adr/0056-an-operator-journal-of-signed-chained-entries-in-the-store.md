---
status: accepted
date: 2026-11-22
deciders: maintainer
---

# An operator journal: one signed, chained entry for each operator command, kept in the store and held by `gateway verify` to the records and seals it names

> **Summary.**
>
> - **Chosen: J1**, a new append-only journal in the store. On the filesystem kind it is
>   `<root>/journals/operator.jsonl`. On the PostgreSQL kind it is the log named `journal/operator` in
>   `gateway.logs` and `gateway.log_records`, which an export writes as `store/journals/operator.jsonl`.
>   No schema version is needed.
> - **The envelope**, the same for every journal: `journal`, `journalVersion: "1"`, `ordinal`,
>   `previous`, `at`, `keyId`, `alg` (optional), `body` and `signature`. It is signed through the
>   configured signer over `"judgment-pack-gateway/journal-entry/1:"`.
> - **The operator journal's bodies:** `retain`, `remove-scope`, `remove-artifact`, `seal-open`,
>   `store-rotate` and `store-continued`. The `retain` body holds `acknowledgments` (the file's SHA-256)
>   and `acknowledgedBy` (the key ids).
> - **New findings of `gateway verify`:** `journal-entry-forged`, `journal-order`,
>   `journal-entry-missing` and `journal-entry-mismatch`. There is also `journal-missing`, which is
>   reported only under the new option `--require-journal <name>`.
> - **New observation:** `journal-from`.
> - **New engine constant:** `operatorJournalVersion`, the first engine configuration version whose
>   commands begin a journal. The maintainer assigns its number in merge order.
> - **Unchanged:** every receipt, seal, removal record, rotation statement, store continuation and
>   key-history form, and every report on a store that holds no journal, byte for byte.

## Acceptance

The maintainer accepted this record with these answers, each folded into the body below.

1. **`--require-journal <name>` ships in the build's pull request** (section 6).
2. **A staged entry left at start is named on stderr, and the gateway serves** (section 5). The next run
   of the same command commits the staged entry or replaces it, and never writes a second one beside
   it. `gateway verify --require-journal operator` reports a staged, uncommitted entry as
   `journal-entry-missing` until it commits (section 6). The case has a vector.
3. **No journal `rotate-key` now.** An entry's `keyId` follows the store signer's key history, so an
   entry signed under a key since rotated from is checked through the key history (ADR-0055).
4. **`retain` records the configured key ids** in `acknowledgedBy`, as the stderr summary prints them.
5. **An export by scope carries no journal.** Its entries name other scopes, so carrying them would
   disclose across scopes. A projection of the journal by scope is issue #588.

The open item, what an older reader does with an export that holds the journal, is answered in
section 7: a reader of v0.38.0 refuses it.

## Context and problem statement

ADR-0048 (decision 2) says the call's summary holds the SHA-256 of the acknowledgment file and the
acknowledging key's id. That summary is how a removal is traced to the acknowledgments that allowed it,
because no record in the store names them (R1). No operator command writes a journal on main, so since
#535 both values go to stderr alone:

- the summary is built at `go/retain.go:414-416`;
- it is added to the call's notes at `go/retain.go:581-583`.

An operator who does not capture stderr loses the link. Issue #543 asks for an entry that is durable and
signed, for each of the six commands run with the gateway stopped:

- `retain` and `store retain`;
- `remove-scope` (and `store remove-scope`);
- `remove-artifact`;
- `seal-open`;
- `store rotate`.

`gateway verify` must report an entry that has been altered.

The journal named "the action journal" (`go/action_journal.go`) is not such a journal:
- it is the private record behind `/act`'s action keys, and it is unsigned;
- it exists on the filesystem kind alone (`openActionJournal`, `go/action_journal.go:46-49`);
- it is left out of every export (SPEC.md §1.2b, "Store export omits private action journals");
- `go/journal_compact.go` compacts it.

A later refusal journal is planned to build on this record. So the placement, the signing and the
envelope are decided here once, for any journal, and the operator journal adds only its bodies and the
rule that holds them to the store.

## Decision drivers

- **The record is durable and signed.** After the command, the digest and the key id can be read back
  from the store on both kinds, under the key in force, through the configured signer (ADR-0050,
  ADR-0053).
- **An entry is not changed, dropped or reordered unseen.** An altered entry, a gap, a reordering, and a
  change the journal should name but does not are each a finding, never a pass.
- **Nothing that verifies today changes.** No record changes form, no corpus vector moves, and a store
  with no journal (every store of v0.38.0 and earlier) verifies byte for byte as today.
- **The journal and its change are atomic, or recover to atomic.** A crash never leaves a change that
  looks journaled when it is not. A rerun, which is already how every one of these commands finishes,
  closes the gap.
- **The journal never crosses a store.** As with receipts (SPEC.md §3d), a store rotated away from keeps
  its own journal. It is verified with its own registry, and it is deleted whole with its store.
- **The design is reusable.** A later journal reuses the placement, the envelope, the signing and the
  envelope's findings, and adds only its own body.
- **The run-time login gains no DELETE or UPDATE** (ADR-0031, decision 6).

## Considered options

### Where the entries live

- **J1. A new append-only journal in the store:** a file of lines on the filesystem kind, and a named
  log on the PostgreSQL kind.
- **J2. Entries in the removal file**, as a new record kind in `artifact-removals.jsonl` and
  `gateway.removal_records`.
- **J3. Entries in the registry**, as a new registry line kind.
- **J4. Entries in the action journal** (`<root>/actions/`).

### How an entry is bound to its change

- **B1. Byte ranges and digests.** Each entry names the bytes its call appended to the removal file, as
  an offset, a length and a SHA-256. It names the seals its call appended to the registry as a count and
  a SHA-256. `gateway verify` tiles the removal file with the ranges and partitions the command seals
  among the entries. This is §3d's line-count-and-digest pattern, kept free of positions where serving
  seals interleave.
- **B2. A list of the records and seals by signature.** It is exact, but an entry grows with every
  session removed. A retention call removes any number of sessions, so the entry could not be held to a
  line bound.
- **B3. A digest over the call's records, grouped by `removedAt` and `removedBy`.** It is fragile: two
  calls in one second under one label collide, and the seals carry no label.

### When the entry is written

- **W1. After the change.** A crash leaves a change with no entry. A rerun can rebuild the entry, but
  `retain`'s rerun reads its own acknowledgment file, so the first run's digest would be lost.
- **W2. Before the change, as a write-ahead entry.** A crash leaves an entry with no change. An ES256
  signature cannot be made again to the same bytes (ADR-0053, decision 4), so a rerun cannot re-make the
  change the entry names.
- **W3. In the change's own transaction on the PostgreSQL kind. On the filesystem kind, staged before
  the change and committed after it.** For the commands whose seals are not known in advance, the entry
  is written after the seals, and a rerun names the seals it completes.

## Decision outcome

**Chosen: J1, B1 and W3.**
- **J1** is the only placement that every one of the six commands can write on both kinds. It is the
  only one that adds nothing to what an existing reader reads, and the only one a refusal journal can
  reuse.
- **B1** keeps an entry within a fixed bound, however many sessions the call removed. It ties each byte
  a journaled command appends to exactly one entry.
- **W3** is atomic where the kind has transactions. Where it has none, it keeps the first run's own
  entry, `retain`'s digest included.

### Why not J2

- **The run-time role holds SELECT alone on `gateway.removal_records`** (`go/store_pg_migrate.go:474`).
  `seal-open` on the PostgreSQL kind runs as the run-time login, under the start lease
  (`go/seal_open_pg.go:9-17`), so it could not write there.
- **The file is the removal records §4 step 4 reads.** To every verifier, an entry of another kind would
  be a line that loads nothing (SPEC.md §1.3a, "Loading"). A refusal journal does not belong in it.

### Why not J3

- **The registry is read by everything:** every verifier, every start, the key history's walk (§3e) and
  a store continuation's digest (§3d). On the PostgreSQL kind it is one chain for every instance (#471).
- **An older verifier reads an unknown registry line silently.** It reads it as a seal that loads
  nothing (SPEC.md §3d, "Older verifiers"). The registry would grow for no seal's reason.

### Why not J4

The action journal is unsigned, exists on the filesystem kind alone, is left out of exports and is
compacted (see the context). It is keyed by action key, not by call.

### 1. Where a journal sits (reusable)

| Kind | Place | Written by |
|---|---|---|
| Filesystem | `<root>/journals/<journal>.jsonl`, one entry per line, each followed by `0x0A`; created `0600` in a directory `0700`, synced before its directory | an append, then a sync, under the registry's hold |
| Filesystem, staged | `<root>/journals/<journal>.pending`, at most one entry, created exclusively and synced | the removal commands alone (§4 below) |
| PostgreSQL | the log named `journal/<journal>` in `gateway.logs` and `gateway.log_records`, each record one entry and its `0x0A` | `pgLogAppendAtEnd` (`go/store_pg.go:692-696`) under the log's append lock, in the caller's transaction |
| Export | `store/journals/<journal>.jsonl`, the log's bytes or the file's, whole | `gateway export`; `gateway export --scope` writes none (below) |

The PostgreSQL kind needs **no migration and no grant**:
- the run-time role already holds SELECT and INSERT on `logs` and `log_records`, and nothing else
  (`go/store_pg_migrate.go:468-469`);
- from schema version 4, each log is one chain with no gap and no overlap, whoever writes it
  (`go/store_pg/migrations/0004_log_chain.sql`).

So a journal there is append-only against the run-time login, as the registry is. The owner writes
`journal/operator` in the transaction of `store retain`, `store remove-scope` and `store rotate`'s new
database. The run-time login writes it for `seal-open` and for `store rotate`'s old database, fenced on
the start lease as their seals are.

A journal's name is 1 to 32 characters, each a lowercase letter or `-`. This record names one journal,
`operator`.

An export by scope writes no journal. An entry names the bytes of the whole removal file and registry,
which a cut by scope does not hold, and its entries name other scopes, so carrying them would disclose
across scopes. A projection of the journal by scope is issue #588.

### 2. The envelope (reusable)

| Member | Form | Statement |
|---|---|---|
| `journal` | a journal's name | the journal the entry is in; it must be the name of the file or log that holds it |
| `journalVersion` | the string `"1"` | the envelope's form |
| `ordinal` | an integer from 0 to 2⁵³−1 | the entry's place: the first entry is 0, and each later entry is one more than the entry before it |
| `previous` | 64 lowercase hexadecimal characters; absent at ordinal 0 | the SHA-256 of the line of the entry before, without its `0x0A` |
| `at` | `YYYY-MM-DDThh:mm:ssZ`, the form of `rotatedAt` | the writer's clock when it signed |
| `keyId` | 32 lowercase hexadecimal characters | the key in force, which signs the entry |
| `alg` | optional: the string `"ES256"` | present exactly when the key in force is a P-256 key (SPEC.md §1.5) |
| `body` | one JSON object holding a string `kind` | the journal's own; each kind holds exactly its own members |
| `signature` | 128 lowercase hexadecimal characters | Ed25519, or ES256 where `alg` is present, over `"judgment-pack-gateway/journal-entry/1:"` and `canon` of the entry without `signature` |

- **Line bound.** An entry's line is at most 4096 bytes, its `0x0A` not counted, as with removal records.
  A writer refuses to write a longer one, and nothing changes.
- **One prefix for every journal.** The prefix is one for all journals: `journal` and `body.kind` are
  inside the signed bytes, so no entry is read as another journal's. The prefix is also no other kind's,
  so an entry is never read as a receipt, a seal or a record (ADR-0053, decision 2's table gains one
  row).

### 3. Signing, and an entry across key and store rotations (reusable)

- **The configured signer signs each entry.** It is the key in force: a key service's key version the
  configuration names, held to `signingPublicKey`, or else the seed's. The entry is signed through
  `commandSigner` and `signingKey.signVerified`, exactly as the call's removal records are
  (`go/retain.go:556-560`, `go/signer.go:85`). An entry is Ed25519 or ES256 as ADR-0053 allows, with
  `alg` on ADR-0053's rule.
- **What loads.** An entry loads only when:
  - its `keyId` names a key that §3b's walk of the store's own registry reached;
  - its signature verifies under that key;
  - its key is the key of the entry before it, or a key the walk reached after that key.
- **Across a `rotate-key`.** Entries signed before the rotation keep verifying, because the walk still
  reaches their key.
- **Across a `store rotate`.** An entry stays in the store it was written in, and that store is verified
  with its own registry and pin (SPEC.md §3d, "each store is verified on its own"). So an entry made
  before the rotation verifies after it exactly as the old store's removal records do. It is never read
  in the new store.
- **The link between journals.** The new store's journal begins with a `store-continued` entry. That
  entry names the old journal's length and SHA-256, as the continuation names the old registry. An
  archived old store can then be matched to the new one. When the old store is deleted under retention,
  its journal goes with it, which is what ADR-0048 lets the operator do.

### 4. The operator journal's bodies

Every operator body holds:
- `kind`;
- `registryFrom`, the registry's length in bytes when the call began, before its own appends;
- `removalFrom`, the removal file's length in bytes when the call began.

On the PostgreSQL kind, both lengths are of the bytes an export writes: each record and its `0x0A`, in
order. The kinds and their other members:

| `kind` | Written by | Its other members, and no others |
|---|---|---|
| `retain` | `retain`, `store retain` | `by`; `scope`, present exactly when `--scope` was given; `acknowledgments`, the SHA-256 of the acknowledgment file read (64 hex); `acknowledgedBy`, the key ids `retention.acknowledgedBy` lists, in its order (1 to 4); `sessions`, the sessions removed; `removalBytes`; `removalDigest` |
| `remove-scope` | `remove-scope`, `store remove-scope` | `by`; `scope`; `removalBytes`; `removalDigest` |
| `remove-artifact` | `remove-artifact` | `by`; `removalBytes`; `removalDigest` |
| `seal-open` | `seal-open` | `seals`; `sealDigest`; `delivered`, `true` where each session's receipts went to the configured sink first, `false` under `--no-sink` |
| `store-rotate` | `store rotate`, in the store rotated **from** | `seals`; `sealDigest`; `delivered` |
| `store-continued` | `store rotate`, in the store rotated **to**, as ordinal 0 | `continuation`, the SHA-256 of the new registry's first line without its `0x0A` (the mark's digest, §3d); `previousJournalBytes`; `previousJournalDigest`, the SHA-256 of the old journal's bytes, whole (of no bytes where the old store holds none) |

- **`removalBytes` and `removalDigest`.** `removalBytes` is the number of bytes the call appended to the
  removal file, and `removalDigest` is their SHA-256. These bytes include the `0x0A` that closes a torn
  last line, which `appendRemovals` writes (`go/remove_artifact.go:552-553`).
- **`seals` and `sealDigest`.** `seals` is the number of seals the call appended to the registry, and
  `sealDigest` is the SHA-256 of those lines, each with its `0x0A`, in order.
- **Counts and digests.** Every count is an integer from 0 to 2⁵³−1. A digest of no bytes is the SHA-256
  of nothing.
- **`by`** is the call's label, of `--by`'s form.
- **Which commands append.** On main, only `retain`, `remove-scope` and `remove-artifact` append to the
  removal file (`appendRemovals`, `go/remove_artifact.go:531`). The serving gateway never does.
- **Writing no entry.** A call that refuses, or that changes nothing ("nothing was removed", nothing
  sealed), writes no entry.
- **`rotate-key` is not journaled.** Its rotation statements are signed registry lines already (§3b).
  An entry's `keyId` follows the store signer's key history, so an entry signed under a key a
  `rotate-key` later rotated from is checked through that history (ADR-0055).
- **The start's seals.** The start's `--seal-open-at-start` seals carry `sealedVia: "start"` and are not
  an operator command's. No entry names them.

### 5. Order and atomicity, on both kinds

| Command | Filesystem kind | PostgreSQL kind |
|---|---|---|
| `retain`, `remove-scope`, `remove-artifact` | 1. Sign the records and the entry naming their bytes. 2. Stage the entry in `operator.pending`. 3. Append the records and sync (today's step). 4. Append the entry to the journal, sync, and remove the pending file. 5. Remove the files (today's step). | The entry is appended to `journal/operator` in the transaction that inserts the records and removes the rows (`go/store_retain.go:199-457`), so the two commit together or not at all. |
| `seal-open` | After the last seal, appended and synced. | After the last seal, in its own transaction, fenced on the start lease. |
| `store rotate` | In the old store, a `store-rotate` entry after its seals and before the new store is made. In the new store, the `store-continued` entry, written before the new registry is renamed into place. | In the old database, a `store-rotate` entry after its seals, as the run-time login. In the new database, `store-continued` is written in the migration's transaction that makes the registry and the key-history row (`go/store_rotate_pg.go:340-399`). |

**After a crash:**

- **Settling a staged entry.** Every journaled command first settles a staged entry, under its hold and
  before its own work. There are three cases:
  - The removal file's bytes past the journal's covered end are exactly the range the staged entry names,
    by length and digest, and the entry follows the journal's last entry. The command appends the staged
    entry and removes the pending file. The entry is the first run's own, with its signature, so
    `retain`'s digest is kept.
  - There are no such bytes, apart from a torn tail. The call appended nothing, so the command removes the
    pending file, and nothing changes.
  - Anything else. The command is refused, and nothing changes: *an interrupted operator command left a
    journal entry the store does not match (journal-pending)*.
- **Seals with no entry.** A crash after a call's seals and before its entry leaves command seals that no
  entry names. The next `seal-open` or `store rotate` names them first in its own `seals`. Until then,
  `gateway verify` reports `journal-entry-missing`. That is true: the store holds a change that no entry
  names.
- **A rerun of `store rotate`.** If the rerun finds the new registry already made, it holds the
  `store-continued` entry to that registry's first line. Where the entry is missing, the rerun writes it,
  as it does for the carried key history (ADR-0052). A `store-rotate` entry already in the old journal
  is not written again.
- **What the start does.** The start reads no journal, and serving appends nothing to the removal file,
  so a staged entry does not stop a start. The start names the staged entry on stderr, and serves.
- **The next run.** The next journaled command, the same command's rerun first of all, settles the staged
  entry as above: it commits it or removes it, and then writes its own entry only for what it changes
  itself. So a rerun never writes a second entry beside the staged one for the same bytes.
- **What verify says meanwhile.** Until the staged entry commits, `gateway verify` reports the journal
  `journal-entry-missing`, with or without `--require-journal` (section 6).

### 6. What `gateway verify` reports

Step 9 is added to SPEC.md §4, and it runs on each journal the store holds. A journal reports at most
one finding, as `{status, journal, ordinal}`. It is the first finding in this order, and the verdict
then fails.

1. **`journal-entry-forged`.** A complete line, one that ends in `0x0A`, does not load. That is, one of
   these is true:
   - the line is over the bound;
   - it is not one JSON object with exactly the envelope's members, each once and of its form;
   - its `body` is not of a kind with exactly that kind's members;
   - its `journal` is not the name of the file or log that holds it;
   - its key is not one the walk reached;
   - its signature does not verify.

   A torn last piece, with no `0x0A` after it, is not an entry and is no finding.
2. **`journal-order`.** One of these is true:
   - an entry's `ordinal` is not its place;
   - its `previous` is not the SHA-256 of the line before it;
   - it holds `previous` at ordinal 0;
   - its key is earlier in the walk than the key of the entry before it.

   This finding is what makes removing the first entry, removing one in the middle, or reordering entries
   show.
3. **`journal-entry-mismatch`.** An entry names something the store does not hold:
   - a removal range whose bytes are not of its digest, or that runs past the file;
   - a `removalFrom` short of the end of the ranges before it;
   - a `registryFrom` past the registry's length, or less than the entry before's;
   - seals beyond the command seals that remain, or seals not of its digest;
   - a `store-continued` entry that is not ordinal 0, or not the digest of a continuation at the
     registry's first line.
4. **`journal-entry-missing`.** The store holds a change that no entry names:
   - bytes of the removal file, past the first entry's `removalFrom`, that no range covers;
   - a command seal at or after the first entry's `registryFrom` that no entry takes.

   - a staged entry, `<journal>.pending` on the filesystem kind, that has not been committed, whether or
     not the journal's file is there.

   This finding is what makes removing the last entries show. The ordinal reported is the one the next
   entry would take. A command seal is a registry line that §1.1's parser reads as one JSON object of
   `kind` `"seal-after-interruption"` and `sealedVia` `"command"`, whether or not it loads.

A journal with no finding is reported as the observation `journal-from`,
`{observation, journal, registryFrom, removalFrom}`, which gives the first entry's values.

**Made before the journal, or an entry removed.** The verifier tells the two apart as follows:

- **Before the first entry.** Bytes of the removal file before the first entry's `removalFrom`, and
  command seals before its `registryFrom`, were written before the journal began, and need no entry.
- **After it.** Every journaled change must be covered. A removed first entry or middle entry is
  `journal-order`. A removed last entry, whose call changed anything a verifier can see, is
  `journal-entry-missing`.
- **The journal removed whole.** A journal removed whole, with every entry in it, cannot be told from the
  store alone from one never begun. Only the reader can know the store was written under a journal. So
  **`gateway verify --require-journal <name>`** (given at most once for each name, after `--artifacts`)
  reports **`journal-missing`**, `{status, journal}`, for a store that holds no such journal while it
  holds a removal record or a command seal.
- **The same in `gateway conform`.** The process contract accepts the option as `verify` does.
- **Stores without journals.** With no journal and no option, nothing is reported of journals, so a
  store of v0.38.0 or earlier gives exactly today's report.

In a verdict by scope (`--scope`), journal findings name no session. They stand in the verdict as the
registry's walk does.

### 7. Compatibility and the engine version

- **The engine constant.**

  ```go
  // operatorJournalVersion is the first engine configuration version whose
  // journaled commands begin the operator journal (ADR-0056). The maintainer
  // assigns the number in merge order.
  const operatorJournalVersion = /* assigned at merge */
  ```

- **When a command writes an entry.** It writes one when its configuration is of that version or later,
  or when the store already holds an operator journal. A journal once begun is never skipped, whatever a
  configuration says, and whether the command is given a configuration or flags. A configuration of an
  earlier version, on a store with no journal, writes none, as today. So a store is exactly as v0.38.0
  left it until the operator raises the version, and rolling back before then is safe.
- **Rolling back after the journal has begun.** A command of v0.38.0 or earlier makes its change with no
  entry, which this version reports as `journal-entry-missing`. The upgrade notes say so: roll back
  commands only with the version lowered on a store that holds no journal.
- **Older verifiers.** A verifier of v0.38.0, in Go and TypeScript, reads only `receipts/` and the removal
  file (`go/verify.go:1134-1146`), so it passes `journals/` over, as it passes `labels/` over. It reports
  nothing of a journal, so a journaled store is `ok` to it where it is `ok` here, and a forged or missing
  journal goes unreported. It refuses `--require-journal` as a usage error and gives no verdict.
- **Older readers of an export.** A reader of v0.38.0 refuses an export that holds
  `store/journals/operator.jsonl`. Its `gateway export --check` answers
  `manifest: a file is not one an export writes: "store/journals/operator.jsonl"`, because the manifest's
  file check (`go/export.go:793` at tag v0.38.0) admits only the paths `exportPathWritten` names
  (`:857-880`), and no journal path is among them. It is a refusal, never a silent pass, and the release
  notes say so. An export of a store with no journal is unchanged, and an older reader reads it as
  before. A test holds the refusal (`TestOperatorJournalExportOlderReaderRefuses`).
- **`retain`'s stderr summary stays as it is.**

### 8. Reuse by later journals

This section is the contract. A later journal reuses sections 1, 2 and 3 unchanged. The first expected
reuse is the refusal journal: its entries are this envelope with `journal: "refusal"`, in
`journals/refusal.jsonl` and the log `journal/refusal`.

- **Placement.** `journals/<name>.jsonl`, the log `journal/<name>`, and the export path.
- **The envelope.** The envelope, its prefix and its line bound.
- **Signing.** The configured signer, and the load rule against the walk.
- **The findings and observation.** `journal-entry-forged`, `journal-order` and `journal-from`, the
  at-most-one-finding rule, and `--require-journal`.

The later journal adds only these:

1. **Its name.**
2. **Its body kinds**, each with exactly its members.
3. **Its rule against the store, if it has one**, and the cases in which that rule reports
   `journal-entry-mismatch` or `journal-entry-missing`. A journal with no such rule reports neither.
4. **The engine version from which it is written.**
5. **Who writes it, and in which transaction.**

A journal the serving gateway writes, with several instances on one database (ADR-0035), takes the log's
append lock and reads its last entry for `previous` in the same transaction. One chain therefore holds
however many instances write it. That later record decides whether its rate allows one key-service
signature for each entry.

### Consequences

- **Good:** `retain`'s acknowledgment digest and key ids can be read back from the store on both kinds.
  On the filesystem kind they are in the file. On the PostgreSQL kind they are in `gateway export`.
- **Good:** every byte a journaled command appends is tied to one signed entry. Altering, reordering,
  dropping or omitting an entry is a finding.
- **Good:** no record changes form, no schema version and no grant is needed, and no current vector
  moves.
- **Good:** a later journal adds a name and a body, not a format.
- **Bad:** the filesystem kind's removal commands gain a staged file and a settle step.
- **Bad:** between a crash and its rerun, the store verifies `journal-entry-missing`.
- **Bad:** a journal removed whole is caught only under `--require-journal`.
- **Bad:** the journal is the key holder's statement, as a seal is. The holder of the key can write any
  entry. The journal shows what the key holder said each call did, not that the operator meant it.
- **Bad:** on the PostgreSQL kind, as with the registry, the run-time login can append to the journal,
  though not change it.
- **Revisit when** an operator command is added that changes the store, or a reader needs an entry from
  a store rotated away from that was deleted.

## More information

### Build plan: one pull request, due in the release after this record's acceptance

**Files:**
- `go/operator_journal.go`: the envelope, signing, loading and the chain; the filesystem log and
  pending file; settling.
- `go/operator_journal_pg.go`: the log `journal/operator` appended in a caller's transaction.
- Edits to:
  - `go/retain.go`, `go/store_retain.go`, `go/remove_scope.go`, `go/store_remove_scope.go` and
    `go/remove_artifact.go`;
  - `go/seal_open.go` and `go/seal_open_pg.go`;
  - `go/store_rotate.go` and `go/store_rotate_pg.go`;
  - `go/verify.go` (step 9, `--require-journal`), `go/export.go` (path, manifest and reader), and
    `go/engine.go` (`operatorJournalVersion`);
  - `verify-ts/src/verify.ts`, for the same reading;
  - SPEC.md, `docs/postgresql-store.md`, `docs/design/engine-config.md` and `corpus/README.md`.

**Tests, one or more for each entry kind on each storage kind that has the command:**

| Entry kind | Filesystem kind | PostgreSQL kind |
|---|---|---|
| `retain` | the digest and key ids read back from `journals/operator.jsonl`; a crash after staging, and one after the records, each settled; the kept entry is the first run's | read back through `gateway export`; a failure injected before COMMIT leaves neither the records nor the entry |
| `remove-scope` | the entry's range is the records' bytes | the same, in one transaction |
| `remove-artifact` | the range with a torn tail closed by the call | (no command on this kind) |
| `seal-open` | `delivered` true and false; seals left by a crash named by the next run | as the run-time login, fenced; a lost lease writes no entry |
| `store-rotate` and `store-continued` | old store and new; rerun after each step | old database as the run-time login; new database in the migration's transaction |

**Tests in `go/operator_journal_test.go`, for verify:**
- each of the five findings, and `journal-from`;
- a torn last line, which is no finding;
- a store without a journal, whose report is byte-identical to today's;
- the engine-version gate, including a store that already holds a journal under an earlier version.

**Corpus vectors, in `corpus/stores`**, run by both verifiers:
- a journal that holds;
- a journal entry forged;
- the order broken at the head and in the middle;
- a missing tail, and a missing command seal;
- a range mismatch, and a continuation mismatch;
- a journal missing under `--require-journal`;
- a staged, uncommitted entry under `--require-journal`, reported `journal-entry-missing`.

**Mutation checks**, each in a scratch copy, each to fail a named test:
1. Skip the entry's signature check.
2. Accept a `keyId` the walk did not reach.
3. Drop the `previous` check.
4. Let the first ordinal be other than 0.
5. Drop the tail coverage check of the removal file.
6. Count command seals without matching `sealDigest`.
7. On the PostgreSQL kind, commit the entry in a transaction of its own.
8. Commit a staged entry whose range the file does not hold.
9. Write no entry under an earlier version where the store holds a journal.
10. Leave `acknowledgments` out of `retain`'s signed body.

### SPEC.md sentences to add

**§1.3, in the layout block:**

```
<root>/journals/<journal>.jsonl                 optional: one journal entry per line (§3f)
```

**§3f, a new section titled "The journals".** It opens with:

> A store may hold journals: append-only files of entries, each signed by the key in force, one chain
> per journal, in `<root>/journals/<journal>.jsonl` (on the PostgreSQL kind the log
> `journal/<journal>`, written by `gateway export` as that path). An entry is one canonical JSON object
> of exactly the members of the table of ADR-0056, section 2, on one line of at most 4096 bytes, its
> `0x0A` not counted, signed over `"judgment-pack-gateway/journal-entry/1:"` and `canon` of the entry
> without `signature`. It loads when its `keyId` names a key the walk of §3b reached, its signature
> verifies under that key, and its key is the entry before's or one the walk reached after it. The
> operator journal, `operator`, holds one entry for each call of `retain`, `store retain`,
> `remove-scope`, `store remove-scope`, `remove-artifact`, `seal-open` and `store rotate` that changed
> the store, of the kinds of ADR-0056, section 4.

The two tables of sections 2 and 4, and the four checks of section 6, follow it word for word.

**§4, a new step 9:**

> 9. For each journal the store holds (§3f), at most one finding, `{status, journal, ordinal}`, the first
>    of `journal-entry-forged`, `journal-order`, `journal-entry-mismatch` and `journal-entry-missing`;
>    otherwise the observation `journal-from`. A store that holds no journal is reported nothing of one,
>    unless `--require-journal <name>` is given and it holds a removal record or a command seal: then
>    `journal-missing`, `{status, journal}`.

**§4.1, in the table:** "`journals/<journal>.jsonl` absent: no journal; anything there that is not a
regular file: not read, no journal".

**§6, one sentence in each command's paragraph:** "The call's entry in the operator journal (§3f) is
written as ADR-0056, section 5, sets out."

### Related

Issue #543 and #535. ADR-0048 (decision 2, R1, S2), ADR-0050, ADR-0052, ADR-0053 (decisions 1, 2 and 4),
ADR-0031 (decision 6), ADR-0034 and ADR-0035. SPEC.md §1.3, §1.3a, §3b, §3c, §3d, §3e, §4 and §4.1.
