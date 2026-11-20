---
status: accepted, 2026-11-19
date: 2026-11-19
deciders: maintainer
---

# Retention and store rotation: a sealed session removed only after a pinned audit log acknowledges its seal and a window has passed, under ADR-0034's session-removal record; a store rotated by an operator's command, the new chain naming the old one's tail

## Context and problem statement

Issue #504 asks for a design note covering four things:
- a configurable retention window, so that a session is removed only once an external audit
  log has acknowledged its receipts and the window has passed;
- a scheduled store rotation;
- an export by scope before removal;
- what an operator runs to retire one scope identifier.

Its premise is that a retired scope's sessions cannot be removed without breaking verification
for the others. On main that is no longer so:
- `gateway remove-scope`, and `gateway store remove-scope` on the PostgreSQL kind, remove
  every session of one scope identifier (ADR-0034). Each sealed session gets a signed
  `session-removal` record, which §4 step 4 reads, so the session reads as `session-removed`
  and every other scope verifies as before (SPEC.md §1.3a, "A removed session").
- `gateway export --scope` writes one scope's sessions alone (ADR-0042, decisions 6 to 9).

What is missing is narrower:
1. Removing sessions by age within a scope that lives on. Today the only removal takes a scope
   whole.
2. A gate on that removal: an acknowledgment from outside the gateway that the session is
   kept elsewhere.
3. A way to let go of what a removal keeps. The seals of removed sessions, and the removal
   records with their session ids and scope identifier, stay in the store for as long as the
   store exists (ADR-0034, consequences).

This record sets out the options for each and the form chosen. Nothing of it is built yet; the build is #535.

## Decision drivers

- After any removal or rotation, every receipt left verifies as before. A removal reads as a
  removal and never as damage, under a key the registry's walk reaches.
- A session is never removed unless an acknowledgment the operator chose to trust covers its
  seal. A session never acknowledged is never removed by retention, however old it is.
- No receipt, seal or existing record changes form. A store with none of the new statements
  verifies as today, byte for byte, and every corpus vector stands.
- The gateway does nothing on a timer that changes its store. Every removal and rotation is a
  command the operator runs, with the gateway stopped, as `remove-artifact` and `remove-scope`
  are. A schedule is the operator's scheduler running that command.
- The PostgreSQL kind's run-time login gains no DELETE (ADR-0031, decision 6).
- Retiring one scope identifier stays a short, stated sequence of commands that exist.

## Considered options

### What acknowledges a session

- **A1. A signed acknowledgment under a key the operator pins.** The external log, or the
  operator's shipper on its behalf, signs one line per session it holds: the `sessionId`, the
  seal's `sealSignature` and `finalCount`, and the time it acknowledged them. The signature is
  Ed25519 under a prefix of its own, `judgment-pack-gateway/retention-ack/1:`. The gateway's
  configuration pins the public key (`retention.acknowledgedBy`). The removal command reads a
  file of such lines, and acts only on sessions whose seal a valid line names exactly.
- **A2. A §8 witness statement.** A witness signs the runtime's audit checkpoints, which are a
  decision trail's, not a gateway session's seal (SPEC.md §8, §8.8). Reusing it would stretch
  what a statement means, and a gateway with no witness could not retain.
- **A3. An unsigned list from the operator.** This is simplest, but the gate is then the
  operator's word alone, and a mistaken list removes sessions no log holds.

### What a retention removal writes

- **R1. ADR-0034's `session-removal` record alone, one per session, and no record for the
  call.** The record names the session and its seal, and §4 step 4 already reads it. No SPEC
  change, no verifier change and no new vector is needed for the reading. The call's summary
  goes to its output and to the action journal, as for any operator command. The scope
  identifier is the session's own, which the record requires (SPEC.md §1.3a, `scope`).
- **R2. A new call record, `retention-removal`, beside the session records.** It would be
  readable by people, but a verifier that loads `artifact-removals.jsonl` holds each line to a
  known kind and form. An older verifier would then refuse the file, as one of v0.32.0
  refuses a ten-member `session-removal` record. That is a SPEC change for no reading gain.
- **R3. The acknowledgment's digest inside the session record.** It binds the gate to the
  record, but it changes the record's form, and so the verifiers and the corpus.

### How the store is let go of

- **S1. No rotation.** Retention removes sessions, and the store keeps the seals and the
  removal records forever. A seal line is a few hundred bytes, so size alone rarely forces
  more. But the session ids and scope identifiers they hold never go.
- **S2. Rotation by an operator's command; the new registry's first line names the old one's
  tail.** `gateway store rotate`, with the gateway stopped:
  1. It seals every open session in the old store, as after an interruption (§3c).
  2. It starts a new store and registry.
  3. It writes as the new registry's first line a `store-continuation` statement, signed by
     the key in force under a prefix of its own. The statement names the old registry's line
     count, the SHA-256 of its bytes, whole, and the key id in force.
  4. It marks the old store rotated away from, outside the old registry's bytes, and every
     later start, removal or key rotation on the old store refuses it by the mark's name
     (SPEC.md §3d).

  A verifier given the new store alone reports the observation `continues-from`, which is no
  finding: the old store may have been removed under retention. A verifier given both
  (`--previous <registry>`, the old store's registry, once per run) checks that the statement
  names the old registry's tail exactly, and fails the pair when it does not. A sequence of
  stores is verified pairwise: each store in its own run, each with the registry of the one
  before it. One run over the whole sequence is #544. Once every session of an old store is past
  retention and acknowledged, the operator deletes the old store whole: seals, records and
  all. This is a SPEC change: a new registry line kind, read where rotation statements are
  read (§3b).
- **S3. Rotation with no link between stores.** Each store verifies alone, and the operator
  keeps a list of them. Nothing shows that a store is the one that followed another, or that
  none was dropped between two.

### Sessions of no scope identifier

A `session-removal` record requires a `scope` (SPEC.md §1.3a). A session of no scope
identifier cannot be removed under R1 without a SPEC change. Under S2 it goes when its whole
store does.

## Decision outcome

Chosen by the maintainer on 2026-11-19: **A1, R1 and S2**, as recommended.
- **A1** makes the gate a signature the gateway checks, under a key the operator chose to trust.
- **R1** reuses a record §4 already reads, so retention needs no SPEC change.
- **S2** is the only option that lets go of what a removal keeps, and shows that no store was
  dropped from the sequence.

The narrowest form, to be built in a later milestone:

1. **Configuration.** A `retention` member: `window` (a duration) and `acknowledgedBy` (an
   Ed25519 public key, 64 hexadecimal characters). It needs an engine configuration version
   of its own when built. With no `retention` member, nothing is removed by age, as today.
2. **`gateway retain --acknowledgments <file> [--scope <identifier>] --by <label>`**, the gateway
   stopped. It removes each sealed session that meets all four conditions:
   - it is of a scope identifier, the one `--scope` names if given;
   - a valid acknowledgment line names its seal exactly;
   - `window` has passed since the later of the seal's time and the acknowledgment's time.
   - no receipt left in the store cites it.

   It writes ADR-0034's `session-removal` record for each, durably, before any file or row
   goes. It refuses by name:
   - a session an acknowledgment names that the store does not hold, or holds under another
     seal;
   - an acknowledgment that does not verify;
   - an acknowledgment whose time is earlier than the seal's time, or later than the command's
     clock;
   - a session of no scope identifier.

   It never removes an open session. On the PostgreSQL kind it is `gateway store retain`, as
   the migration login acting as the owner, under the start lease, as `store remove-scope` is.
   Its action journal entry holds the SHA-256 of the acknowledgment file it read and the
   acknowledging key's id, so the call can be traced to the acknowledgments it acted on, though
   no record in the store names them (R1).
3. **`gateway store rotate`**, the gateway stopped, as S2 sets out. On the PostgreSQL kind a
   rotation starts **a new database**, or a new schema where the migration login can own one,
   and the old one is dropped whole once past retention. It cannot be a new instance on the
   same database (ADR-0035): from schema version 6 every instance on a database shares one
   registry chain (#471, option C), so a new instance starts no new registry and leaves no old
   store to delete whole.
4. **The verifiers, SPEC.md and the corpus**, in one change, for S2 alone:
   - the `store-continuation` line and `--previous`;
   - vectors for a pair that links, a pair that does not, and a new store read alone.

**Proposed defaults, with their reasons:**
- **No retention and no rotation unless configured.** Removal is irreversible, so it is never
  a default.
- **When retention is configured, a minimum window of 7 days, with 30 recommended.** That
  leaves time to find an acknowledgment that was wrong, and to restore from an export, before
  anything goes. A shorter window is refused at load.
- **Rotation monthly, by the operator's scheduler.** It runs stop, then `store rotate`, then
  start. With a 30-day window this keeps about two stores live.
- **An acknowledgment file is read whole, and bounded** (a line under 4096 bytes and a count
  the build states), as removal records are.

**How a verifier crosses a rotation.** It verifies each store on its own, as today. Given the
registry of the store before with `--previous`, one per run, it also checks that store's
`store-continuation` against it; a sequence is crossed one link at a time. A verdict over the sequence is `ok` only when every store is `ok` and every
link holds. A receipt is never read across stores: a session lives in one store, since the
rotation seals what was open.

**Retiring one scope identifier, with what exists today and what this adds:**
1. `gateway export --scope <id>`, kept where the operator keeps exports. Verify it with
   `gateway verify --scope <id>` on the restored copy.
2. `gateway remove-scope --scope <id> --by <label>` (or `gateway store remove-scope`), the
   gateway stopped.
3. With this record built, the removal records and seals that name the identifier go when
   their store is rotated out and past retention.

### Consequences

- Good, because a retained session reads as `session-removed` to every verifier of v0.29.0 or
  later, with no SPEC change for retention.
- Good, because the gate is a signature under a key the operator pins, and a session never
  acknowledged stays.
- Good, because rotation is the first way to let go of a removed session's seal and the
  identifiers its records keep.
- Bad, because rotation is a SPEC change. A verifier written before it reads a
  `store-continuation` line as an unknown registry line, and the build has to state what each
  older verifier does with it before it ships.
- Bad, because an acknowledgment is the external log's statement, not proof that the log keeps
  what it acknowledged. A log that acknowledges and then loses a session's receipts loses them.
- Bad, because a session of no scope identifier can be let go of only with its whole store.
- Bad, because a mixed-scope session on the filesystem kind is still refused whole (ADR-0034).
- Bad, because on the PostgreSQL kind a rotation needs a database, or a schema, per store, which
  the operator provisions. Dropping the old one does not remove its rows from the write-ahead
  log, backups or replicas, which the operator's own retention governs.
- Revisit when an external log can prove that it holds a session's receipts, not only state
  that it does, or when a seal and its removal can name no scope.

## More information

- Store rotation implemented in #535 (part B), on the filesystem kind: `gateway store rotate`, the
  `store-continuation` line and `gateway verify --previous` (SPEC.md §3d).
- PostgreSQL kind built in #535 (part C): `gateway store rotate --config` with the migration
  login's connection to a new database, taken as `gateway store migrate` takes it, the start
  lease of the old database taken first. The form is a new database, not a schema: every
  statement and the start's checks name the schema `gateway`, so a new database holds the schema,
  row security and grants of a fresh migration unchanged, where a schema of another name would be
  carried into every statement and into the configuration. The run-time role holds on the new
  database what `grants.sql` gives it on every migration, and nothing more; on the old one the
  command uses the run-time login alone, for the lease and the seals. The line is §3d's, byte for
  byte, and `gateway verify --previous` reads this kind through `gateway export --config`.

- Issue #504; ADR-0034 (removal of one scope identifier), ADR-0042 (export and verify by
  scope), ADR-0035 (several instances on one database) and #471 (one registry chain per
  database, schema version 6), ADR-0031, decision 6.
- SPEC.md §1.3a ("A removed session"), §3c (sealing after an interruption), §3b (rotation
  statements), §4 step 4, §8.8 (what a witness statement establishes).
