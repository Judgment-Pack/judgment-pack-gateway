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
  start on a server older than 16, or on a database whose encoding is not UTF-8.
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
  directories no one else may write; at most 4096 bytes), or `environment`, a variable's name
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
| a platform's `scope` | the configuration's load | the kind is served as the view of no scope |
| `/verify` | answers 501 | it verifies the store on disk: export the store and verify the export |
| `gateway seal-open --config`, `gateway remove-artifact --config` | the command | they read the sessions, and keep removal records, on disk |
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
  `start-lease-held`, the other instance's identifier and how many seconds its lease runs. It
  reads the row first and takes it only where it expired, and then without waiting: a start that
  is refused holds nothing the running instance waits for, however its connection ends.
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
- **A clean stop** (SIGINT or SIGTERM) expires the lease, so the next start is admitted at once.

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
make several instances safe, which is not supported (ADR-0031, decision 10).

**Replacing an instance** (an upgrade, a move to another host) is a rolling replacement in this
order:

1. stop the old instance with SIGTERM and wait for it to exit: it releases the lease;
2. run `gateway store migrate` if the new version carries a migration;
3. start the new instance.

If the old instance cannot be stopped cleanly (its host is gone), the new start is refused until
the old lease expires and its sessions are ended, within 45 seconds of its last renewal; start it
again then. A start that finds the lease held
names the holder: do not remove the row by hand while that instance may be running.

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
{"applied":[1,2],"migrations":"sha256:…","schemaVersion":2}
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

Append-only by privilege: nothing but a document and the start lease's row is changed once
written, and nothing but a document is removed. The login
holds no TRUNCATE, REFERENCES or TRIGGER, and makes, changes and drops nothing. No function is
defined in the schema. An append to the registry takes a transaction advisory lock
(`pg_advisory_xact_lock`, which every role may call unless the operator took it back); the
migration takes another. Both keys are constants of the schema, so leave them to the gateway in
this database.

The kind's start refuses a database where any of this differs: a privilege more or less, by table
or by column; a table, view, sequence, function, trigger, rule or type beside the store's; row
security not enabled and forced on a scoped table, or a policy other than the scope's.

## Scope identifiers

Rows of the scoped tables hold their scope as `scope:` and the scope identifier, or `none` for no
scope. Each scoped table has row security enabled and forced and one policy, for every command and
role: `scope = current_setting('gateway.scope', true)`. The gateway sets `gateway.scope` for each
transaction alone, and names its scope in every statement besides.

- A transaction that sets no scope sees no row and writes none, whether the setting was never set
  on its connection or was set by an earlier transaction for itself.
- A session's name is one across scopes: a scope cannot make a session another scope holds, and
  learns that the name is taken.
- Row security keeps apart what the gateway does. It is not a boundary against the run-time login
  itself, which may set `gateway.scope` as it likes in a transaction of its own; a login per scope
  identifier is an open decision (ADR-0031).

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
the same work (a test).

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
  make roles and databases and nothing more (CREATEROLE, CREATEDB). Three cases need a superuser to
  set up -- BYPASSRLS on the run-time login, for the migration and for the start, and a setting of
  `gateway.scope` stored on the run-time role -- and the second run skips those three, by one
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
and exports, checks and verifies what a start on it wrote, and a store a configuration without
storage wrote is exported by this binary and by main's, byte for byte alike.
