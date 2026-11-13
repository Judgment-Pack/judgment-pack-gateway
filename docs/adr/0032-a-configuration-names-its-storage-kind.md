---
status: proposed
date: 2026-11-13
deciders: maintainer
---

# A configuration names its storage kind, its connection string by reference, and one instance holds a database by a start lease

## Context and problem statement

ADR-0031 added a second storage kind on PostgreSQL behind the store contract and recorded, in its
decision 2, how a configuration would select it; it left the selection, the migration command and
the rule for more than one gateway on one database to a later change (issue #430). This is that
change. Three things must be decided: how the configuration names the kind without the
connection string ever being written in it; what the kind refuses that the filesystem kind does,
since parts of the gateway read the store on disk and not through the contract; and how one
gateway instance, and only one, serves a database.

## Decision drivers

- A configuration without the new member runs as it does today, byte for byte.
- The connection string is a secret: it appears in no configuration, line, error, report,
  receipt or export.
- What reads the store on disk is refused by name under the second kind, never served from an
  empty directory in the store's place.
- The run-time login cannot change the schema; the start checks the schema and changes nothing.
- Two instances on one database are not safe yet (ADR-0031, decision 10), so a second one must be
  refused, and a crashed one must not hold the database for ever.

## Considered options

- For selection: a `storage` member in a new configuration version (chosen); the connection
  string in the configuration; a command-line flag.
- For the second instance: a start lease row decided by the database's clock, with every write
  fenced on it (chosen); a session-level advisory lock held by one connection for the instance's
  life; the operator's word alone.

## Decision outcome

1. **Engine configuration version 24** adds the optional `storage` member:
   `{"kind":"postgresql","connection":{"file":<absolute path>} | {"environment":<NAME>},
   "connections":1..64, "operationSeconds":1..600}`. With it, `store` and `registry` are not
   given, and either beside it is refused by name; without it both are required as before, and
   the filesystem kind runs unchanged. `storage` in a file of version 23 or earlier is refused by
   name. A file is held as the seed's file is; a variable is read at the start and removed from the
   process's environment, so no program the gateway starts inherits it. `gateway mcp` is denied
   the file and refuses an environment that holds the variable.

2. **What reads the store on disk is refused** with the error `storage-kind-unsupported`, naming
   what was asked for, at the configuration's load or at the command, before anything is read:
   `witness`, `sealOpenAtStart`, a platform's `write` (and `/act`), `descriptorStatements`,
   descriptor provenance and a descriptor capture, a platform's `scope`, `/verify`, `gateway
   seal-open --config`, `gateway remove-artifact --config`, and a key rotation under way. The
   list is derived from the code paths that open the store's directory, each with a test that it
   is refused and reads no empty directory (`docs/postgresql-store.md`, "Not available with this
   kind yet").

3. **`gateway store migrate`** takes the migration login's connection string by reference, the
   owner role and the run-time role; it refuses a login that is either role, so the run-time
   login cannot migrate; it is idempotent, refuses a schema newer than the binary, and prints the
   versions applied, the schema's version and the migrations' digest, never the string. The
   start's check (ADR-0031, decision 8) stays the gate at the start.

4. **One instance per database, by a start lease.** Schema version 2 adds `gateway.start_lease`,
   one row: the holder, an identifier the instance draws at its start, and the expiry by the
   database's clock (`clock_timestamp()` in the statement, so instances on different hosts agree
   on one clock). The start takes the row where it is absent or expired, before it writes
   anything, and is refused with `start-lease-held`, naming the holder, while it is live. The
   instance renews it every 10 seconds, each renewal running the lease 30 seconds from that
   moment and bounded by 10 seconds; a renewal that finds the lease gone, or failures that leave
   less than one interval certainly held, stop the instance with `start-lease-lost`. Every write
   transaction first holds the row, unexpired and its own, `FOR KEY SHARE`; the holder is a unique
   key, so a takeover, which changes it, waits for such a write to end, while a renewal, which
   changes only the expiry, does not wait on the instance's own writes. A clean stop removes the
   row. Several live instances remain unsupported: the lease decides which one serves.

5. **ADR-0031, decision 9, amended**: the start lease's expiry is the database's clock, as that
   decision anticipated for more than one gateway; receipt and seal times stay the gateway's, and
   a store-contract lease still expires by the clock the gateway gives the kind.

### Consequences

- Good, because a configuration of version 23 or earlier, or of 24 without `storage`, loads and
  runs as before; the corpus, the vectors and the filesystem kind's bytes are unchanged.
- Good, because the connection string has one way in, by reference, and a test greps every
  stream and file a run produces for a marker password.
- Good, because a second instance is refused while the first lives, a crashed one's lease expires
  within 30 seconds of its last renewal, and a write after the lease is gone fails rather than
  landing beside another instance's.
- Bad, because a share of the gateway is not available with this kind yet (decision 2); each
  refusal names what to do instead where there is something.
- Bad, because the periods are constants of this version, not configuration; a write that holds
  the lease's row delays a takeover by up to that write's deadline (`operationSeconds`).
- Bad, because the end-to-end check in CI drives the binary for the migration and the export, and
  serves in the test's process: `serve --config` takes a platform whose source runs as a user of
  its own, which only a start as root switches to.
- Revisit when a second instance must serve one database (the registry's seal decided in the
  database, ADR-0031, decision 10), or when the periods need to be the operator's.

## More information

- Decisions open to the maintainer, each with this change's recommendation first:
  - The member's name: `storage` (recommended: `store` already names the filesystem path, so
    reusing it would make one member two types across versions), or `store` as ADR-0031, decision
    2 wrote it.
  - The lease's periods: constants, 30 and 10 seconds (recommended until an operator needs
    otherwise), or configuration members.
  - The end-to-end check through `serve --config`: in the test's process for the serving
    (recommended for this change), or a job that runs the binary as root with a source user.
- `docs/postgresql-store.md` is the operator's page; `docs/design/engine-config.md`, "The
  storage kind (engine version 24)", is the configuration reference.
