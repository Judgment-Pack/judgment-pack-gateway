# The PostgreSQL storage kind

Status: **selectable, one instance per database.** A second storage kind behind the store
contract ([docs/design/store-contract.md](design/store-contract.md)), held to the same
conformance suite and corpus as the filesystem kind
([ADR-0031](adr/0031-a-second-storage-kind-on-postgresql.md)). An engine configuration of version
24 selects it with its `storage` member
([ADR-0032](adr/0032-a-configuration-names-its-storage-kind.md)); `gateway store migrate` makes
and raises its schema. The filesystem kind stays the default: a configuration without `storage`
runs as before, and nothing about it changes. This page is what the kind asks of a database and of
the operator who runs one.

## The server

- PostgreSQL 16 is the major version the kind is tested on: CI runs the tests against
  `postgres:16-alpine` (PostgreSQL 16.15) pinned by digest
  `sha256:721873c34ceb9f8d8fc265984940dc982404c105f19ad51be9fdc5970a6080ea`. The kind does not
  start on a server older than 16, or on a database whose encoding is not UTF-8. The version is
  the `server_version_num` the server answers to a query on each connection: the checks that
  depend on PostgreSQL 17 (`MAINTAIN`, `transaction_timeout`) use it, and the start is refused,
  naming both, when it disagrees with the `server_version` the server reported at the login.
- Logins use SCRAM-SHA-256 (`password_encryption = scram-sha-256`, the default since
  PostgreSQL 14, and `scram-sha-256` in `pg_hba.conf` for the gateway's logins). The gateway
  refuses a server that asks for a password in the clear or by MD5, before it sends the password,
  and one that admits a login with a password without the exchange.
- A password is used as written, without SASLprep: use printable ASCII. Other passwords may fail
  to log in; they never log in as another password would.

## The connection string

A `postgresql://` URL naming the host, an optional port, the user, the password and the database:

```text
postgresql://gateway_runtime:<password>@db.example.internal:5432/gateway_store?sslmode=verify-full&sslrootcert=/etc/gateway/db-ca.pem
```

- `sslmode` is `verify-full` (the default: TLS 1.2 or later, with the server's certificate checked
  against `sslrootcert`, or the system's roots without it, and against the host name) or
  `disable`, which is accepted only for a loopback host: a literal loopback address such as
  `127.0.0.1` or `[::1]`, or `localhost`. Under `disable` the gateway also checks the address the
  connection reached, and closes it, with nothing sent, unless that is a loopback address: a
  resolver need not answer `localhost` with one. `connect_timeout` is in seconds, 1 to 300, and 10
  without it. Any other parameter is refused, not ignored.
- The password is required: a connection string without one, or with one that is empty or only
  spaces, is refused. A login without a password makes no SCRAM exchange, so the server proves nothing of itself by it,
  and under `disable` nothing else would.
- The connection string is a secret. The gateway never prints it: not in an error, a log line, a
  receipt, the start's lines or `gateway store migrate`'s report. A configuration names it only by
  reference, a file or an environment variable ("Selecting the kind", below).
- An error the server reports reaches the gateway's messages as its SQLSTATE alone. The server's
  message, detail and hint are not kept: the server quotes a statement's values there.

## Before the first start

The operator makes three roles and the database. Nothing the gateway runs makes or changes a role,
or stores a setting on a role or a database. The names here are examples:

```sql
-- the owner of the schema and its tables; it cannot log in
CREATE ROLE gateway_owner NOLOGIN;
-- the migration login: it reaches the owner's privileges only by SET ROLE
CREATE ROLE gateway_migrate LOGIN PASSWORD '<a password>';
GRANT gateway_owner TO gateway_migrate WITH INHERIT FALSE, SET TRUE;
-- the run-time login the gateway runs as
CREATE ROLE gateway_runtime LOGIN PASSWORD '<another password>';

CREATE DATABASE gateway_store OWNER gateway_owner ENCODING 'UTF8' TEMPLATE template0;
REVOKE ALL ON DATABASE gateway_store FROM PUBLIC;
GRANT CONNECT ON DATABASE gateway_store TO gateway_migrate, gateway_runtime;
```

An administrator that is not a superuser, one that holds CREATEROLE and CREATEDB and nothing more,
makes the same, with two differences. It makes the database for the owner only when it may SET
ROLE to the owner, and it gives the database's privileges as the owner: a REVOKE by a role that
neither owns the database nor is a superuser takes nothing back, with a warning and no error, and
PUBLIC keeps TEMPORARY, which the kind's start then refuses.

```sql
GRANT gateway_owner TO CURRENT_USER WITH INHERIT FALSE, SET TRUE;
CREATE DATABASE gateway_store OWNER gateway_owner ENCODING 'UTF8' TEMPLATE template0;
SET ROLE gateway_owner;
REVOKE ALL ON DATABASE gateway_store FROM PUBLIC;
GRANT CONNECT ON DATABASE gateway_store TO gateway_migrate, gateway_runtime;
RESET ROLE;
```

The migration and the kind's start refuse roles outside these conditions:

- the owner cannot log in; neither the owner nor the run-time login is a superuser or holds
  BYPASSRLS, CREATEROLE, CREATEDB or REPLICATION;
- the migration login is neither of the two, is no superuser and holds no BYPASSRLS, is a member
  of the owner with INHERIT FALSE and SET TRUE, and so holds the owner's privileges only after SET
  ROLE;
- the run-time login reaches neither the owner nor any role with such an attribute, holds no CREATE
  or TEMPORARY on the database and no CREATE on any schema, and holds on the schema's tables exactly
  what the grants below give.

## Selecting the kind

A version-24 engine configuration names the kind in `storage`, in place of `store` and
`registry`, which are then not given:

```json
{
  "engineVersion": "24",
  "authority": "gateway:example",
  "seed": "/var/lib/engine/gateway.seed",
  "storage": {
    "kind": "postgresql",
    "connection": { "file": "/run/secrets/gateway-store-url" },
    "connections": 4,
    "operationSeconds": 30
  },
  "decisionRecords": "/var/lib/engine/decisions",
  "listen": "127.0.0.1:8787",
  "catalog": "/usr/local/share/engine/catalog",
  "platforms": { "...": "..." }
}
```

- `kind` is `postgresql`; nothing else is accepted.
- `connection` names the run-time login's connection string by one reference: `file`, an
  absolute path, held as the seed's file is (the gateway's user's, readable by no one else, in
  directories no one else may write, links on the way to it included; at most 4096 bytes; held
  so by the start, `gateway store migrate` and `gateway export --config` alike), or `environment`, a variable's name
  (capital letters, digits and `_`, not starting with a digit), which the start reads and then
  removes from its own environment, so no program it starts inherits it. Both, neither, or the
  string itself are refused.
- `connections`, 1 to 64, 4 without it; `operationSeconds`, 1 to 600, 30 without it: the pool's
  bound and each operation's deadline (ADR-0031, decision 3). An instance holds one connection
  more, its start lease's own ("One instance per database"): `connections` + 1 in all.
- `store` or `registry` beside `storage` is refused by name, and so is `storage` in a
  configuration of version 23 or earlier.
- `gateway mcp` under such a configuration is denied the connection file, and refuses to start if
  its environment holds the connection variable.

The start prints, on standard error, which reference the string was read from, never the string:

```text
start: storage: the PostgreSQL storage kind keeps the store and the registry; its connection string was read from the file /run/secrets/gateway-store-url
start: gateway instance instance-<32 hex> holds the start lease, which runs 30s from each renewal by the database's clock and is renewed every 10s
```

## TLS

`sslmode=verify-full` (the default) or `sslmode=disable` ("The connection string", above).
`disable` is accepted only for a loopback host, and the check is made twice: on the host the string
names, before the dial, and on the address the connection reached, after it, so a name that
resolves off loopback is closed with nothing sent. No other mode (`require`, `verify-ca`,
`prefer`, `allow`) is accepted.

## Not available with this kind yet

What reads or writes the filesystem store directly, and not through the store contract, is refused
with the error `storage-kind-unsupported`, naming what was asked for, at the configuration's load
or at the command, before anything is read; none of them reads an empty directory in the store's
place:

| Asked for | Where it is refused | Why |
|---|---|---|
| `witness` | the configuration's load | its files are beside the registry on disk |
| `sealOpenAtStart` | the configuration's load | it reads the sessions on disk |
| a platform's `write: true`; `/act` | the configuration's load; `/act` answers 501 | an action keeps its journal and evidence on disk |
| a platform's `descriptorStatements`; descriptor provenance; a descriptor capture by `gateway connect` | the load; the start; `connect` before any adapter is asked | the signed snapshot is read from the store on disk (`gateway connect --no-descriptors` connects a platform without one) |
| `/verify` | answers 501 | it verifies the store on disk: export the store and verify the export |
| `gateway seal-open --config`, `gateway remove-artifact --config`, `gateway remove-scope --config` | the command | they read the sessions, and keep removal records, on disk; on this kind `gateway store remove-scope` removes a scope identifier's rows ("Removing one scope identifier's rows") |
| `gateway rotate-key` | the start refuses a rotation under way beside the seed | the rotation keeps the registry at a path |

`gateway verify` takes a store directory and a registry file: it reads an export of this kind
(`gateway export --config`), never the database.

## One instance per database

One gateway instance serves a database at a time, and the database says which, by a start lease:
the one row of `gateway.start_lease`, which holds the instance's identifier, drawn at its start,
when it last renewed the lease and when the lease expires, both by the database's clock. A lease
runs at most ten minutes from its renewal; the row refuses any later expiry, and infinity.

- **The start** takes the lease where there is none or it has expired, before it writes anything.
  While another instance's lease is live the start is refused, and exits 1, with
  `start-lease-held`, the other instance's identifier and how many seconds its lease runs; or,
  where the configuration gives `startWaitSeconds`, it waits for the lease ("Handing over to a new
  instance", below). It reads the row first and takes it only where it expired, and then without
  waiting: a start that is refused holds nothing the running instance waits for, however its
  connection ends.
- **While it serves**, the instance renews the lease every 10 seconds on a connection of its own,
  never one of the pool's; each renewal runs the lease 30 seconds from the renewal's statement by
  the database's clock and is bounded by 5 seconds, opening that connection again where it failed.
  A renewal that finds the lease taken or expired stops the instance, and so does a failure that
  leaves less than one renewal's interval of the lease certainly held: it stops serving and exits
  1 with `start-lease-lost`.
- **Every write** of the instance holds the lease's row, as its last statement before its commit,
  `FOR KEY SHARE`, and only where the row is its own with more than 11 seconds of the lease left
  by the database's clock, read once the row is held; otherwise the write fails with
  `start-lease-lost` and writes nothing. A renewal does not wait on the instance's own writes.
- **A stop** (SIGINT or SIGTERM; an interrupt on Windows) drains the instance and then expires
  the lease. From the signal on, each acquisition is answered `503`, with `Retry-After: 10` and
  the error `this gateway instance is stopping and admits nothing more; …`, and nothing more is
  admitted; a seal and the routes that read are still answered. The acquisitions admitted before
  the signal finish, for at most the operation's time limit (`operationSeconds`, 30 seconds
  without it); a source still running then is killed, and its acquisition fails as at any stop.
  The instance then stops listening, answers the requests still open, and sets the lease's expiry
  to the database's now, so the next start, or a waiting one, takes it at once. The lease is
  renewed until then. A second signal ends the process at once, undrained: its lease then expires
  as a crashed instance's does.

**The sessions are bounded.** Every session the instance opens is ended by the server once it sits
idle within a transaction for 10 seconds (`idle_in_transaction_session_timeout`, set at the
session's start and in every transaction); every statement and every lock wait is bounded by the
operation's deadline (`statement_timeout`, `lock_timeout`), and, from PostgreSQL 17, so is every
transaction (`transaction_timeout`). The start checks that the server holds these as set, and is
refused otherwise. The client probes a quiet connection after 5 seconds, every 5 seconds, three
times (TCP keepalive). A paused, partitioned or crashed instance therefore holds no row or lock
past those bounds.

**The timing**, from the moment the last renewal that took effect was sent, at 0 s:

| When | What |
|---|---|
| 10 s, 20 s | the next renewals are sent; each ends within 5 s |
| 11 s before the expiry (19 s to 24 s) on | less than 11 s of the lease is left; every write fails at its last statement |
| 20 s to 25 s | when both renewals failed, the instance stops serving, with at least 5 s of the lease left |
| 30 s to 35 s | the lease expires, 30 s from that renewal's statement by the database's clock |
| at most 45 s | a second instance is admitted: from the expiry on, or, when a later renewal stopped between its statement and its commit, once the server ended that session, within 10 s more |

No write of the old instance commits after a second instance took the lease. A write passes its
last statement only with more than 11 seconds of the lease left, and its commit is sent within
the 10 seconds the server allows an idle transaction, or the server ends the session and the
write with it. Until the write's transaction ends it holds the row, and a takeover, which would
wait for it, is refused at once instead: `start-lease-held`, naming the old instance, and "start
again". A write whose statements outlast the lease fails at that last statement and writes
nothing; a write whose last statement waited for the row reads the clock once it holds it.

The periods are constants of this version. The lease decides which instance serves; it does not
make several instances safe, which is not supported (ADR-0031, decision 10;
[ADR-0035](adr/0035-several-instances-on-one-postgresql-database.md) sets out the steps towards
it, of which the hand-over below is the first).

**Handing over to a new instance** (an upgrade, a move to another host). The new instance is
started before the old one is stopped, and waits for the old one's lease. Its configuration, at
engine version 25, gives the wait in the `storage` member:

```json
"storage": {
  "kind": "postgresql",
  "connection": { "file": "/run/secrets/gateway-store-url" },
  "startWaitSeconds": 300
}
```

`startWaitSeconds`, 1 to 3600, is how long a start that finds another instance's lease live waits
for it; without the member the start is refused at once, as above. Then:

1. Start the new instance. It listens on its address at once and answers every request, on every
   route, `503` with `Retry-After: 10` and one fixed body,
   `{"error":"this gateway instance is not serving yet: it serves once it holds the database's start lease, which another instance holds; send the request again"}`,
   while it reads the lease's row every renewal interval (10 seconds). It reads the row and takes
   it only where it is not live by the database's clock: while it waits it holds no row, takes no
   lock past one read, and writes nothing. It holds connections all the same, so the server's
   connection budget takes both instances, `connections` + 1 each, for the hand-over. A readiness
   check that wants a `200` holds it not ready until it serves; one that wants a listener finds it
   ready at once.
2. Stop the old instance with SIGTERM. It drains and releases the lease ("A stop", above).
3. The new instance takes the lease at its next read, within 10 seconds of the release, makes the
   start's checks again (the server's bounds, the run-time login's privileges, the schema's
   version, the registry's walk), and serves on the listener it bound, which it never closed: a
   caller who connects meanwhile waits for its answer and is not refused.

A caller meets `503`, with `Retry-After`, from the old instance from its signal on and from the new
one until it serves, and nothing else: the window is the drain (at most `operationSeconds`), at
most one renewal interval, and the start's checks. Give the orchestrator's grace period for a stop
more than `operationSeconds` and 15 seconds, or it kills the old instance in its drain and the
hand-over waits for the lease to expire.

If the old instance does not release its lease (its host is gone, a kill, a second signal), the
waiting instance takes it once it expired, within 45 seconds of the old instance's last renewal
("The timing", above). If the wait runs out first, the start is refused as one that does not wait:
exit 1, `start-lease-held`, naming the holder; the listener is closed. A stop signal while it
waits ends the start, exit 0, having held nothing. A start that finds the lease held names the
holder: do not remove the row by hand while that instance may be running.

What a hand-over does not do:

- **It does not carry open sessions over.** A session open on the old instance at its stop stays
  open: the new instance does not continue it (a call into it is refused as a session an earlier
  process left open, SPEC.md §6), and this kind makes no seal after an interruption yet
  (`gateway seal-open` and `sealOpenAtStart` are refused, "Not available with this kind yet"). It
  reads `unregistered-session`, observed `session-open`, to a verifier. Seal a session before the
  stop where it can be; a caller whose session the stop left open opens a new one on the new
  instance. A later step seals such sessions (ADR-0035, "Decision outcome").
- **It does not compare keys or authorities.** The start does not hold the new instance to the
  old one's seed or authority: the database records neither (the lease's row holds the
  instance's identifier and its times, and nothing else), and the registry's walk holds a key
  only to the registry's rotations. Give both instances one seed and one authority: seals and
  receipts made under another key do not verify under the key a verifier pins.
- **It does not migrate.** When the new version carries a migration, the new binary refuses the
  database's earlier schema at its start, before it waits. Stop the old instance with SIGTERM and
  wait for it to exit, run `gateway store migrate`, then start the new instance: every instance is
  stopped while a migration runs. A start that waited checks the schema again once it holds the
  lease, and is refused where it is no longer its binary's.

## The migration command

```text
gateway store migrate (--connection-file <path> | --connection-env <NAME>) --owner <role> --runtime <role> [--timeout <seconds>]
```

The command takes the **migration login's** connection string, by one reference, held as the
configuration's is; `--owner` and `--runtime` name the owner role and the run-time role. It is the
only way the schema changes: the gateway's start checks the schema and changes nothing. The
run-time login cannot migrate: the command refuses it, as it refuses any login that is the owner or
the run-time role, before anything is applied. It prints, as canonical JSON, what it did, and no
part of the connection string:

```json
{"applied":[1,2,3,4,5],"migrations":"sha256:…","schemaVersion":5}
```

A second run applies nothing (`"applied":[]`). A schema newer than the binary's migrations is
refused, by the command and by the start alike. `--timeout` bounds the run, connection included:
1 to 3600 seconds, 300 without it. Exit 0 on success, 1 on a refusal or failure, 2 on a usage
error. The command may run while the gateway serves: the running instance does not check the
schema again, and its next start does.

## The migration

The schema is plain SQL that the binary carries: `go/store_pg/migrations/NNNN_name.sql`, numbered
from 1 with no gap, and `go/store_pg/grants.sql`, each recorded by digest in
`go/store_pg/SHA256SUMS`. The migration runs as the migration login, in one transaction, under a
transaction advisory lock, so one migration runs at a time:

1. SET ROLE to the owner, for the transaction alone;
2. refuse a schema the owner does not own, a version recorded with a digest other than its file's
   (a migration is never changed once applied: a change is a new file), and a version this binary
   does not carry;
3. apply every version not applied yet and record each with its digest in
   `gateway.schema_migrations`;
4. run the grants, which take back what the owner gave the run-time login and grant exactly what
   is listed below.

A second run applies nothing and changes nothing. The migration's transaction sets `row_security`
off: row security is forced on the owner too, and a migration sets no scope, so a statement that
reads or changes rows of a scoped table would otherwise see none and change none, without an
error. With it off, such a statement fails and the migration with it. A migration that changes rows
lifts the forcing for the tables it changes and restores it in its own transaction, and the kind's
start refuses a table it was not restored on.

## What the run-time login may do

| Table | Privileges | Rows a transaction sees and writes |
|---|---|---|
| `gateway.blobs` (the retained artifacts) | SELECT, INSERT | its scope's |
| `gateway.series` (the sessions) | SELECT, INSERT | its scope's |
| `gateway.entries` (the receipts) | SELECT, INSERT | its scope's |
| `gateway.documents` (documents and leases) | SELECT, INSERT, UPDATE, DELETE | its scope's |
| `gateway.logs`, `gateway.log_records` (the seal registry) | SELECT, INSERT | every one: the registry is one chain |
| `gateway.secrets` | SELECT, INSERT | every one |
| `gateway.schema_migrations` | SELECT | every one |
| `gateway.start_lease` (one row: the instance that serves) | SELECT, INSERT, UPDATE | every one: it carries no scope |
| `gateway.scope_identifiers` (schema version 3: the scope identifiers recorded) | SELECT, INSERT | no scope's: every row is of no scope |
| `gateway.removal_records` (schema version 5: the removal records) | SELECT | no scope's: every row is of no scope |

Append-only by privilege: nothing but a document and the start lease's row is changed once written,
and nothing but a document is removed; a scope identifier, once recorded, stays, and a removal
record is the run-time login's to read alone. Rows leave otherwise only by `gateway store
remove-scope`, as the migration login acting as the owner ("Removing one scope identifier's
rows"), which changes none of these privileges. The login holds no
TRUNCATE, REFERENCES or TRIGGER (nor, from PostgreSQL 17, MAINTAIN), and makes, changes and drops
no table, schema, policy or other object in a schema. No function is defined in the schema. An
append to the registry takes a transaction advisory lock (`pg_advisory_xact_lock`, which every role
may call unless the operator took it back); the migration takes another. Both keys are constants of
the schema, so leave them to the gateway in this database.

The registry's records are one chain by the schema too (schema version 4): no two records start or
stop at one offset, and each starts where another stops, or at 0. A record inserted without the
lock, by the run-time login or any other writer, is refused unless it is at the log's end, so the
log is never left with a record over committed bytes or past a gap. The migration to version 4
checks the records already there: a store whose log is not one chain is refused it, with nothing
changed, and the kind's start then refuses the store as behind its migrations.

Migration 4 rewrites the table `gateway.log_records` (it adds a stored column) and builds an index
on it, under a lock that admits no other reader or writer of the table until it commits. A serving
instance's reads and appends of the registry wait for it, and are refused once they have waited
the operation's bound. Run it with every instance stopped.

When migration 4 is refused because the log is not one chain, the kind never wrote such a log (it
appends at the log's end alone, under the lock), so something else changed `gateway.log_records`.
These two queries, as the owner, name the records where the chain breaks: a record that starts
where no record stops (a gap), and an offset where two records stop (an overlap).

```sql
SELECT log, start, stop FROM gateway.log_records r WHERE start <> 0
  AND NOT EXISTS (SELECT 1 FROM gateway.log_records p WHERE p.log = r.log AND p.stop = r.start);
SELECT log, stop, count(*) FROM gateway.log_records GROUP BY log, stop HAVING count(*) > 1;
```

Do not change the records by hand to make the chain: the registry is what a verifier holds every
session's seal to. Find what wrote them, and restore the database from a copy made before.

The kind's start refuses a database where any of this differs: a privilege more or less, by table
or by column; a table, view, sequence, function, trigger, rule or type beside the store's; row
security not enabled and forced on a scoped table, or a policy other than the scope's; a column,
constraint or index of the store's tables other than the migrations made it, or one beside them.
The start reads each column (its type, collation, NOT NULL, default or generation), constraint and
index as the server prints its definition, and compares it with the list the binary carries for
its schema (`go/store_pg_definitions.go`), which the CI job holds to what the pinned server prints
for a database the migrations made. A table's storage parameters, and whether it is logged, are
not compared.

What every role may do in a database it connects to, the run-time login may do too, and the
gateway does none of it: create a large object, which stays in the database until it is unlinked;
`LISTEN` and `NOTIFY`; take a session advisory lock, which a session holds until it ends, so one
held on the registry's key makes every append wait and fail at the lock timeout; and set
`row_security` off for its own session, after which its statements on a scoped table fail rather
than read past the policy. Whoever holds the run-time login's password can do these; keep it to the
gateway.

## Scope identifiers

A platform fixed to a scope identifier (its `scope`, engine configuration version 20,
[ADR-0026](adr/0026-a-scope-identifier-fixed-on-a-platform.md)) is served by this kind as by the
filesystem kind: each `/acquire` repeats the identifier, and the receipt carries it in its `scope`
member. What this kind adds is where the rows are kept
([ADR-0033](adr/0033-a-platform-fixed-to-a-scope-identifier-on-the-postgresql-kind.md)).

**How the scope is set.** Rows of the scoped tables hold their scope as `scope:` and the scope
identifier, or `none` for no scope. Each scoped table has row security enabled and forced and one
policy, for every command and role: `scope = current_setting('gateway.scope', true)`. The start,
once it holds the start lease, opens the kind's view of each scope identifier a platform is fixed
to; a source of that platform keeps its payloads and receipts through that view, and a source of
no scope through the view of no scope. Every transaction of a view sets `gateway.scope` to the
view's form for itself alone (`set_config(…, true)`), and names its scope in every statement
besides.

**How it maps to records.** For a source fixed to the scope identifier `scope-a`:

| Record | Where | Row's `scope` |
|---|---|---|
| the payload (a retained artifact) | `gateway.blobs` | `scope:scope-a` |
| the session | `gateway.series` | `scope:scope-a` |
| each receipt, whose `scope` member is `scope-a` | `gateway.entries` | `scope:scope-a` |
| the identifier itself | `gateway.scope_identifiers`, `identifier` | `none` |
| a seal of the session | `gateway.log_records` | none: the registry carries no scope |

A source of no scope writes rows of `none`, and its receipts carry no `scope` member, as before.
The kind keeps the removal records of `gateway store remove-scope` alone, as rows of no scope
("Removing one scope identifier's rows"): `gateway remove-artifact` is refused with it ("Not
available with this kind yet").

- **Rows of no scope** are reached by the value `none`, which a transaction sets as a scope's
  transaction sets its own: a transaction of a scope identifier never sees one, and a transaction
  of no scope sees no scope's row.
- **A transaction that sets no scope** sees no row and writes none, whether the setting was never
  set on its connection or was set by an earlier transaction for itself: a pooled connection
  carries no scope from one transaction to the next.
- **A session's receipts are of one scope.** A session's name is one across scopes: a scope
  cannot make a session another scope holds, and learns that the name is taken. An acquisition
  into a session that holds the receipts of another scope, or of none, is refused `400` before its
  source runs: `session <id> holds the receipts of a scope other than this source's (another
  scope identifier, or none): with the PostgreSQL storage kind a session's receipts are of one
  scope, so acquire into a new session`. The refusal names neither scope. (The filesystem kind
  keeps one layout for every scope and takes such an acquisition.)
- **The record of the scope identifiers** (`gateway.scope_identifiers`, schema version 3) holds each
  scope identifier a start has opened a view for, written by that start before the view writes
  anything, never changed, and removed only with the scope's rows by `gateway store
  remove-scope`. Its rows are of no scope, so no scope's transaction reads
  another's identifier from it. What must reach every scope's rows reads it and then each scope in
  its turn, in one transaction whose every statement is of one scope, the setting changed between
  statements for the transaction alone: the export, the start's question whether the store holds a
  session before it makes an empty registry, and an acquisition's or a seal's question whether a
  session of its name is held in some scope, which asks its own scope first (below). No statement is
  admitted to the rows of two scopes at once, and no login, policy or function admits every scope.
- **What a session this process does not hold costs.** An acquisition into such a session, and a
  seal of one, ask the scope of the source first (of no scope for a seal), in one transaction of
  four statements, its begin and commit among them: a session of that scope, with receipts or none,
  is answered there, however many scope identifiers are recorded. A name that scope does not hold,
  which is every new session's, is then looked for in no scope and in every other identifier
  recorded, in the same transaction, two statements each (2N + 5 statements for an acquisition with
  N identifiers recorded), so that a name another scope holds is refused. The question is asked
  under the service's lock, so other acquisitions, releases and seals wait for it, and an
  identifier leaves the record only by a removal, which no instance serves beside. Measured on the test container (PostgreSQL 16 on loopback, one
  connection, 31 admissions each), a new session's admission took a median of about 100 ms with 100
  identifiers recorded (205 statements) and about 1 s with 1,000 (2,005 statements); an admission
  into a session of the source's own scope took about 2 ms at either.
- **The registry** is one chain across scopes: its tables carry no scope column, and every view
  reads the whole registry. Its lines are seals (SPEC.md §3, §3c): a session's id, its count of
  receipts, its time, the key's identifier and a signature. None carries a receipt, a payload, an
  argument or a scope identifier, so a seal of a scoped session is a line of no scope. A gateway
  of one scope reads every seal: the ids and counts of every scope's sealed sessions, and nothing
  more of their rows. `gateway verify` reads the chain from an export, which holds every line.
  Whether a seal names its scope is issue #442.
- **The export** reads every scope recorded, whichever scopes the configuration names now, and
  writes the layout of SPEC.md §1.3 the filesystem kind writes: a session once, under its name; a
  payload two scopes hold alike once, its bytes read from each and compared, and refused where
  they differ; documents of no scope alone, since an export writes none.
- Row security keeps apart what the gateway does. It is not a boundary against the run-time login
  itself, which may set `gateway.scope` as it likes in a transaction of its own; a login per scope
  identifier is an open decision (ADR-0031).

## Removing one scope identifier's rows

```text
gateway store remove-scope (--connection-file <path> | --connection-env <NAME>) --owner <role> --runtime <role> --seed <file> --scope <identifier> --by <label> [--timeout <seconds>]
```

The command removes every row of one scope identifier, its sessions (`gateway.series`), receipts
(`gateway.entries`), payloads (`gateway.blobs`) and documents, and its row of
`gateway.scope_identifiers`, and records the removal, in one transaction
([ADR-0034](adr/0034-removing-one-scope-identifiers-records.md)). It takes the migration login's
connection string as `gateway store migrate` does, never printed, and the gateway's seed file, by
which the records are signed.

- **Who removes.** The migration login, by SET ROLE to the owner for the transaction alone: the
  owner holds DELETE as the tables' owner. No role, grant or function is added for it; the
  run-time login's privileges do not change, and it holds no DELETE on a table but
  `gateway.documents` (a test pins its grants before and after a removal).
- **What it holds.** The migration's advisory lock, so no migration runs beside it, and the start
  lease, taken as a start takes it: while an instance serves, the command is refused
  (`start-lease-held: a gateway instance serves the database, … stop the gateway, then remove`)
  and nothing changes; a start while it runs waits for it or is refused. The lease is expired
  again before the commit. A schema not at the binary's version is refused (migrate first), and
  so is a store with no registry yet.
- **Row security stays forced.** The scope's rows are read and removed with `gateway.scope` set
  to the scope's form, and the scope named in every DELETE besides; each DELETE's count is held
  to the count read, and the transaction rolls back where one differs. The records and the
  identifier's row are written with it set to `none`.
- **The records.** Those of the filesystem kind's `gateway remove-scope` (SPEC.md §1.3a, §6): a
  `session-removal` record for each sealed session of the scope and one `scope-removal` record
  for the call, signed by the seed's key, which is to be the key the registry's walk ends at, and
  each read back as a verifier reads it before it is kept. They are rows of
  `gateway.removal_records` (schema version 5), of no scope, one for each line of the removal
  file, which the run-time role may read and not write. `gateway export --config` writes them as
  the export's `store/artifact-removals.jsonl`, and the export verifies, each removed sealed
  session observed `session-removed`. The command prints each record kept, as its line, and on
  stderr what it removed, by counts.
- **All or nothing.** The rows, the identifier's row and the records commit together or not at
  all. A second run finds nothing of the scope and keeps no record; a scope identifier recorded
  with no row is removed from the record, and no record is kept.
- **What cannot arise here.** A session's receipts are of one scope on this kind, and nothing
  that cites a receipt (`/act`, descriptor statements) is available with it, so the filesystem
  kind's refusals of a session of mixed scopes and of a receipt that cites a removed one do not
  arise.
- **What remains** is stated in README.md, "What a removal of a scope identifier leaves": on this
  kind, besides, the removed rows' bytes in the database's own files until the server's vacuum
  reuses their space, and in its write-ahead log and the base backups the operator keeps.

Exit 0 on success, 1 on a refusal or failure, 2 on a usage error. A gateway started again on the
store serves as before; a platform fixed to the removed scope identifier records it again at its
start and begins anew.

## Time

Receipt and seal times are the gateway's, never the database's. A lease of the store contract
(`store_leases.go`) expires by the gateway's clock. The start lease alone expires by the
database's clock: its statements read `clock_timestamp()`, and no other statement the gateway
sends, or schema file it carries, reads the database's clock (a test).

## Backup and restore

The database's backup and restore are the operator's, with PostgreSQL's own tools. Restore into a
database made as above, with the same roles; the kind's start holds a restored database to every
condition on this page. A verifier reads a store of this kind through its export, which writes the
layout it reads; the export of a store holds the same bytes as the filesystem kind's for
the same work, of no scope and of scope identifiers alike (a test).

## Not supported

- what "Not available with this kind yet" lists;
- moving a store from one kind to the other;
- more than one live gateway instance on one database: the start lease refuses a second ("One
  instance per database");
- passwords outside printable ASCII;
- connection poolers: the settings the gateway makes are transaction local, which a pooler in
  transaction mode keeps, but no pooler is tested;
- a server older than PostgreSQL 16, a schema named other than `gateway`, and any connection
  parameter not named above.

## Testing

The kind's tests take a server from the environment:

- `GATEWAY_TEST_POSTGRES_DSN`: the `postgresql://` URL of a login that may make roles and
  databases. Each test makes its own three roles and database, with names and passwords drawn at
  random, and drops them when it ends. Without it the tests skip and say why.
- `GATEWAY_TEST_POSTGRES_REQUIRED`: when set, a test that would skip fails instead. The CI job
  `postgresql` sets it and runs the tests twice against the pinned image in a service container,
  with synthetic credentials: as a superuser, failing if any test skipped, and as a login that may
  make roles and databases and nothing more (CREATEROLE, CREATEDB). Four cases need a superuser to
  set up -- BYPASSRLS on the run-time login, for the migration and for the start, a setting of
  `gateway.scope` stored on the run-time role, and an index of the store's marked not valid -- and
  the second run skips those four, by one
  message, and fails on any other skip (ADR-0031, "Consequences").

Locally, one throwaway container from the same image, on loopback, kept for every run and removed
with its volumes at the end. Its data directory is a tmpfs, so the image's data volume is never
made on disk; `-v` on the removal removes any anonymous volume all the same:

```sh
docker run --rm -d --name gateway-pg-test -p 127.0.0.1:55432:5432 \
  --tmpfs /var/lib/postgresql/data \
  -e POSTGRES_USER=gateway_test_admin -e POSTGRES_PASSWORD=synthetic-password \
  -e POSTGRES_DB=gateway_test_admin \
  postgres@sha256:721873c34ceb9f8d8fc265984940dc982404c105f19ad51be9fdc5970a6080ea
cd go
GATEWAY_TEST_POSTGRES_DSN='postgresql://gateway_test_admin:synthetic-password@127.0.0.1:55432/gateway_test_admin?sslmode=disable' \
GATEWAY_TEST_POSTGRES_REQUIRED=1 \
  go test -count=1 -run '^(TestStoreKindsConform|TestPostgres.*|TestAPostgres.*|TestThePostgres.*|TestEveryCorpusStoreExportsFromThePostgresKindByteForByte)$' .
docker rm -f -v gateway-pg-test
```

The CI job also runs `scripts/checks/storage-scenario.sh`: this commit's binary migrates the kind
and exports, checks and verifies what a start on it wrote; the binary's export of the same calls on
the filesystem kind is held to it, the same files, each artifact byte for byte and every other file
byte for byte but for the values each run writes afresh (the times, the salted arguments
commitment, the signatures, and the manifest's digests of the files that hold them); and a store a
configuration without storage wrote is exported by this binary and by main's, byte for byte alike.
