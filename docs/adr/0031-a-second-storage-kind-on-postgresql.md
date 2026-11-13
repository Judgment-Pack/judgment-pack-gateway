---
status: proposed
date: 2026-11-13
deciders: maintainer
---

# A second storage kind on PostgreSQL, behind the store contract, with each scope identifier's rows kept apart by row security

## Context and problem statement

The gateway keeps its durable state behind a store contract with one storage kind that a
gateway runs on, the filesystem (`docs/design/store-contract.md`). Service mode needs a second
kind: a database several gateways can reach, whose backup is the operator's, and in which the
rows of one scope identifier (ADR-0026) are not another's to read or write (issue #430). The
core links the standard library alone (ADR-0001, the CI steps "No third-party modules" and
"Every core dependency resolves into the standard library"), so how the core speaks to a
database is itself a decision, and so are the conditions the database is held to: its roles, its
schema's migrations, its row security, and what is and is not safe with more than one gateway.

## Decision drivers

- The filesystem kind stays the default, and its behaviour and bytes are unchanged; every frozen
  vector and the conformance suite are unchanged.
- The second kind passes the same conformance suite, every corpus store exports from it byte for
  byte, and one scenario run on both kinds holds the same bytes.
- The core links nothing but the standard library.
- The login the gateway runs as holds table privileges and nothing more: it makes, changes or
  drops nothing in the database, and changes or removes no row of an append-only table.
- A transaction that names one scope identifier sees and writes only that scope's rows, whatever
  path a statement takes to them; one that names none sees none of them.
- The connection string is a secret: it is never in a stored configuration version, a log line,
  an error or a receipt.
- No time the gateway signs or decides on is the database's.
- A condition the database does not meet is a refusal at the start, never a silent pass.

## Considered options

For the client the core speaks PostgreSQL through:

- **A client in the core, of the standard library alone** (`go/pgwire.go`): the protocol's
  version 3.0, its extended query form with every value bound, SCRAM-SHA-256 and TLS. Licence:
  the repository's own. Maintenance: the project's, over a protocol that has been stable since
  PostgreSQL 7.4; it reads only what the kind uses. Dependency weight: none. Third-party notices:
  unchanged, the core still links the standard library alone.
- **pgx** in the core. Licence: MIT. Maintenance: active, with regular releases. Dependency
  weight: the driver and its own modules (a pool, the service and password file readers, and
  modules of `golang.org/x`). Notices: the core's notice that it links the standard library alone
  would no longer hold, the two CI steps above would refuse it, and the notices tooling would have
  to start listing the core's modules.
- **lib/pq** in the core. Licence: MIT. Maintenance: in maintenance mode by its own statement,
  with fixes but no new work. Dependency weight: none beyond itself. Notices: as for pgx, the core
  would link a module that is not the standard library's.
- **A driver in an adapter process** speaking a store protocol to the core: the adapters' module
  may link third-party code. Licence and notices: the adapters' as now. But every store operation
  would cross a process boundary, and the row security that keeps scopes apart would be enforced
  by another process than the one that signs; a second protocol to specify and test.

## Decision outcome

Chosen option: "a client in the core, of the standard library alone", because it keeps the
core's one dependency rule and the security claim built on it (ADR-0001) without an exception,
and the kind needs a small part of the protocol: bound statements, a simple query for the
migration files the binary carries, SCRAM-SHA-256 and TLS. Choosing a driver instead is open to
the maintainer (below).

1. **The client** (`go/pgwire.go`). A connection string is a `postgresql://` URL naming a host, a
   user and a database, with `sslmode=verify-full` (the default) or, to a loopback host alone,
   `disable`, and no parameter but `sslrootcert` and `connect_timeout`; any other parameter is
   refused, never ignored. The login is SCRAM-SHA-256 alone: a server that asks for a password in
   the clear or by MD5 is refused before the password leaves the gateway, and one that admits a
   login the connection string gives a password for without the exchange, or whose final
   signature is not the one the password's verifier makes, is refused. Every value is bound as a
   parameter in the binary format; the simple query form runs only the schema files the binary
   carries. A value is bounded (64 MiB) and so is a message. A parsed connection string prints as
   a fixed phrase, and every error is a fixed sentence naming its class or SQLSTATE, quoting
   nothing of the host, port, user, database, password or the server's text.

2. **Selecting the kind in configuration** is not in this change; the decision recorded for it is
   this. A new engine configuration version adds a `store` member naming the kind; without it the
   filesystem kind runs as now and the bytes are unchanged. For the PostgreSQL kind the member
   names the connection string by reference only, a file (held, as the seed's file is, to its mode
   and owner) or an environment variable, and the stored configuration version keeps the
   reference, never the string. The kind's bounds (below) are members of it with these defaults.

3. **Pool bounds.** A kind holds at most 4 connections unless configured otherwise, and never more
   than 64. Each operation has one deadline, 30 seconds unless configured otherwise (1 second to
   10 minutes), that bounds the wait for a connection, the statements and the commit; the
   transaction's `statement_timeout` and `lock_timeout` are set to it. A connection that failed,
   or is not idle when its operation ends, is closed and never handed out again.

4. **Isolation by operation.** Every operation is one transaction.
   - Writes run at READ COMMITTED, READ WRITE. Each is one statement, an append's after its lock,
     whose atomicity a constraint, a row lock or the append's lock decides: a blob is inserted or found there (its key is its digest); a series is
     made or found there; an entry is inserted under the primary key of its series and index, so a
     second create at the index is refused as taken; a document is replaced by an UPDATE whose
     WHERE names the revision read, so a concurrent writer waits on the row lock and then finds
     the revision gone (a conflict); an append holds a transaction advisory lock to its commit and
     then inserts its record at the log's end, which the statement after the lock reads as the last
     append committed it. So a record commits only after the one it follows, a reader never sees a
     record past one not yet committed, and no append loses the end to another and is refused or
     tried again. The primary key of the log and the record's start still refuses a second record
     at one offset, from any writer that did not take the lock. The log's head row cannot be locked
     instead: a row lock needs UPDATE, which the run-time login does not hold.
   - Single reads run at READ COMMITTED, READ ONLY.
   - Reading the log, and a snapshot, run at REPEATABLE READ, READ ONLY: the log's head and its
     records, and every space a snapshot lists, are of one snapshot of the database, so the cut is
     a state the kind was in. An entry's and a blob's bytes are read when the cut asks for them;
     neither is ever changed once made.
   - SERIALIZABLE is not used: no operation reads one row to decide a write to another beyond
     what a constraint or the append's lock decides, so it would add serialization failures and
     protect nothing. No operation is tried again: a write at READ COMMITTED and a read-only
     transaction at REPEATABLE READ never fail to serialize, and a failure of any other kind is the
     operation's fault, never a success.
   - Every transaction sets `synchronous_commit` on for itself, so a commit the server answered is
     durable whatever a role or a database set. A commit answered with ROLLBACK, as the server
     answers the commit of a failed transaction, is a failure. A commit whose answer never came is
     a durability fault that may have been kept: an append answers it as written and committing,
     as the filesystem kind answers a sync that failed after the write.

5. **Scope identifiers and row security.** The rows of blobs, series, entries and documents carry
   their scope as `scope:` and the identifier, or as `none` for no scope; no row holds the empty
   string. Each of those tables has row security enabled and forced and one policy, for every
   command and every role: `scope = current_setting('gateway.scope', true)`. The kind sets
   `gateway.scope` to the same form for each transaction alone (`set_config(..., true)`, as `SET
   LOCAL` does), on every transaction, and names the scope in every statement besides. The rule for
   rows of no scope: they are seen and written only by a transaction that sets `none`, and a
   transaction of a scope never sees one. A transaction that sets no scope sees no row and writes
   none: the setting reads as NULL on a connection that never set it and as the empty string on
   one whose earlier transaction set it for itself, and neither matches a row. Being transaction
   local, the setting holds under a pooler that hands a connection over between transactions. A view of the kind is of one scope or of
   none (`inScope`); its leases are documents of its scope. The seal registry's log and the
   secrets carry no scope: the registry is one chain, as its seals name no scope (ADR-0026). A
   series' name is one across scopes, as SPEC.md §1.3's layout names a session once. Nothing is
   counted across scopes: the schema has no sequence and no identity column, and a document's
   revision is 128 random bits.

6. **Roles.** The operator makes three roles before the first migration, and nothing the gateway
   runs makes or changes a role:
   - an **owner**, which cannot log in, owns the schema and its tables, and holds no attribute
     past an ordinary role's (no SUPERUSER, BYPASSRLS, CREATEROLE, CREATEDB or REPLICATION);
   - a **migration login**, a member of the owner WITH INHERIT FALSE, SET TRUE: it reaches the
     owner's privileges only by SET ROLE, which the migration does for its own transaction;
   - a **run-time login**, which holds exactly the table privileges the schema's grants give and
     reaches no other role.
   Append-only by privilege: the run-time login holds SELECT and INSERT on blobs, series, entries,
   the log and its records, and secrets; SELECT, INSERT, UPDATE and DELETE on documents alone;
   SELECT on the migrations' record. It holds no TRUNCATE, REFERENCES or TRIGGER, no CREATE on any
   schema, and no TEMPORARY on the database. No function is defined, SECURITY DEFINER or not.

7. **Migrations.** The schema is plain SQL files, `go/store_pg/migrations/NNNN_name.sql` numbered
   from 1 with no gap, and `go/store_pg/grants.sql`, carried in the binary and recorded by digest
   in `go/store_pg/SHA256SUMS`; a binary whose files do not match the record does not load them. The
   migration runs as the migration login, in one transaction, after SET ROLE to the owner and under
   a transaction advisory lock: it applies every version not applied yet, records each with its
   file's digest in `gateway.schema_migrations`, and runs the grants, which take back what the
   owner gave the run-time role and give exactly the privileges above, so a second run ends where
   the first did. Row security is forced on the owner too and the migration sets no scope, so it
   sets `row_security` off for its transaction: a statement of a migration that reads or changes
   rows of a scoped table fails, and the migration with it, rather than changing no row. A
   migration that changes rows lifts the forcing for the tables it changes and restores it, in its
   own transaction; the kind's start refuses a table it was not restored on. The files make no role, grant nothing but in `grants.sql`, define no function,
   create no sequence, and set nothing on a role, a database or the server. A version recorded
   with another digest than its file's, or one the binary does not carry, refuses the migration
   and the kind's start alike: a migration is never changed once applied; a change is a new file.

8. **The kind's start** holds the database to these conditions and does not open otherwise: a
   server of PostgreSQL 16 or later with a UTF-8 database; a run-time login with none of the
   attributes above, not reaching the owner or such a role, with no CREATE on the database or any
   schema and no TEMPORARY; every migration applied and matching; on each table exactly the
   privileges above, by table and by column; the schema holding the store's tables and their
   indexes alone, with no view, sequence, function, trigger, rule or type beside them; row
   security enabled and forced on every table with a scope column, and on each exactly the
   scope's policy.

9. **Time.** Receipt and seal times are the gateway's, never the database's. A lease's expiry is
   another clock and is decided apart: in this change it is the clock the gateway gives the kind
   (`store_leases.go`), the one the conformance suite moves by hand, which is sound for the one
   gateway this change supports; a lease's fencing token is counted in its document and holds
   whatever the clocks say. With more than one gateway, expiry decided on each gateway's clock
   holds only while the clocks agree within the lease's margin, so the change that supports them
   decides expiry with the database's clock in the statement (below). No statement the kind sends
   or schema file it carries names one of the database's clock functions (a test).

10. **More than one gateway on one database.** Safe now: every contract operation is atomic in the
    database, so two gateways on one database lose no write, never take one index of a series or
    one offset of the log twice, and replace a document only at the revision read; a lease's
    fencing token holds across them. Not safe yet, and so not supported by this change: the
    registry's writer reads the log to find a session not yet sealed and then appends, so two
    gateways sealing one session at once could both append its seal; a lease's expiry is decided
    on each gateway's clock; the registry's start asks whether the store holds any session before
    it makes an empty registry, and a view of the kind sees one scope's sessions, or those of no
    scope, never every scope's; and the state outside the contract (the signing seed and its
    rotation files, the action journal, the removal records, descriptor snapshots, the witness's
    files) is on each gateway's own disk. The configuration that selects the kind takes a lease of no scope at start
    and refuses to start while another gateway holds it, until the registry's seal is decided in
    the database.

### Consequences

- Good, because the core still links the standard library alone, and the third-party notices and
  their tooling are unchanged.
- Good, because the conformance suite, every corpus store vector and a scenario run on both kinds
  hold the second kind to the bytes of the first, with nothing in the suite or the corpus changed.
- Good, because every condition the kind runs under is checked at its start and has a test that
  fails when the condition is removed, on a server in CI pinned by digest.
- Bad, because the project now maintains a database client: the protocol's login, its framing and
  TLS are the project's code to keep correct, and a password is used as written, without SASLprep,
  so a password outside printable ASCII may fail to log in (it fails closed).
- Bad, because row security keyed on a setting is not a boundary against the run-time login
  itself: that login may set `gateway.scope` to any value in a transaction of its own. It keeps
  apart what the gateway does; it does not keep a compromised gateway from another scope's rows.
  Nor is a lease's document kept from being rewritten by the database: the kind's document space
  refuses it (`leaseDocumentsReserved`), and the run-time login, which may replace any document of
  its scope, could rewrite one by a statement of its own.
- Bad, because a series' name is one across scopes: a scope asking to make a series another scope
  holds learns that the name is taken, though nothing of its rows.
- Bad, because the kind is not selectable yet: this change adds the kind, its schema and its
  conditions, and the configuration that selects it is the next.
- Revisit when sessions are bound to one scope identifier (ADR-0026's "Bad" list), when a second
  gateway must seal on one database, or when the maintainer prefers a driver to the client.

## More information

- Decisions open to the maintainer, each with this change's recommendation first:
  - The client: the in-tree client (recommended); pgx or lib/pq in the core, with an exception to
    the core's dependency rule; a driver in an adapter process.
  - The boundary between scopes: row security keyed on the transaction's setting, as here
    (recommended for this change); one run-time login per scope identifier with the policy keyed
    on `current_user`, so that the database itself keeps a login to its scope (a pool per scope,
    and roles made per scope by the operator).
  - Binding a session to one scope identifier: this kind keeps a series of the scope that made it,
    and a scope's view does not see another's; binding every session to one scope on every kind
    is a change to ADR-0026 and to SPEC.md (recommended before service mode is offered).
  - An export across scopes: an export login holding SELECT under a policy that admits every
    scope (recommended), or an export per scope, which leaves out the seals counting the other
    scopes' receipts.
  - Removing one scope's rows (#434): the run-time login holds no DELETE on append-only tables;
    the removal would run as a login of its own, or as the owner through a migration-like step.
  - A lease's expiry with more than one gateway: decided in the statement by the database's clock
    (recommended, with the conformance suite's lease cases given a way to move that clock, such as
    an offset the test sets for its transactions), or kept on the gateway's clock with a stated
    bound on the clocks' disagreement.
  - The registry's start with scopes: whether any session is held, asked of every scope, by a
    statement on the series' names under a policy of its own for a login meant for it
    (recommended), or the registry made by the operator's migration before the first start.
- `docs/postgresql-store.md` is the operator's page: the roles to make, the migration, what the
  run-time login may do, backup and restore, and what is not supported.
- `docs/design/store-contract.md` describes the contract and the filesystem kind; its list of
  what a kind must pass now runs on this kind too.
- Not changed: SPEC.md; the frozen corpus; the filesystem kind and its bytes; the verifier, which
  reads SPEC.md §1.3's layout, so it reads a store of this kind through its export.
