# The PostgreSQL storage kind

Status: **not selectable yet.** This version adds a second storage kind behind the store contract
([docs/design/store-contract.md](design/store-contract.md)), its schema, and the conditions it runs
under, and holds it to the same conformance suite and corpus as the filesystem kind. The engine
configuration that selects it, and the command that runs its migration, come in a later change
([ADR-0031](adr/0031-a-second-storage-kind-on-postgresql.md), decision 2). The filesystem kind
stays the default, and nothing about it changes. This page is what the kind asks of a database
and of the operator who runs one.

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
  `disable`, which is accepted only for a loopback host. `connect_timeout` is in seconds, 1 to 300,
  and 10 without it. Any other parameter is refused, not ignored.
- The connection string is a secret. The gateway never prints it: not in an error, a log line or a
  receipt, and a stored engine configuration will name it only by reference, a file or an
  environment variable (ADR-0031, decision 2).

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

The migration and the kind's start refuse roles outside these conditions:

- the owner cannot log in; neither the owner nor the run-time login is a superuser or holds
  BYPASSRLS, CREATEROLE, CREATEDB or REPLICATION;
- the migration login is neither of the two, is no superuser and holds no BYPASSRLS, is a member
  of the owner with INHERIT FALSE and SET TRUE, and so holds the owner's privileges only after SET
  ROLE;
- the run-time login reaches neither the owner nor any role with such an attribute, holds no CREATE
  or TEMPORARY on the database and no CREATE on any schema, and holds on the schema's tables exactly
  what the grants below give.

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

Append-only by privilege: nothing but a document is changed or removed once written. The login
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

Receipt and seal times are the gateway's, never the database's: no statement the gateway sends
reads the database's clock. In this version a lease expires by the gateway's clock.

## Backup and restore

The database's backup and restore are the operator's, with PostgreSQL's own tools. Restore into a
database made as above, with the same roles; the kind's start holds a restored database to every
condition on this page. A verifier reads a store of this kind through its export, which writes the
layout it reads; the export of a store holds the same bytes as the filesystem kind's for
the same work (a test).

## Not supported

- selecting the kind in an engine configuration (a later change);
- moving a store from one kind to the other;
- more than one gateway on one database (ADR-0031, decision 10);
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
  `postgresql` sets it, runs the tests against the pinned image in a service container with
  synthetic credentials, and fails if any test skipped.

Locally, a throwaway container from the same image, on loopback:

```sh
docker run --rm -d --name gateway-pg-test -p 127.0.0.1:55432:5432 \
  -e POSTGRES_USER=gateway_test_admin -e POSTGRES_PASSWORD=synthetic-password \
  -e POSTGRES_DB=gateway_test_admin \
  postgres@sha256:721873c34ceb9f8d8fc265984940dc982404c105f19ad51be9fdc5970a6080ea
cd go
GATEWAY_TEST_POSTGRES_DSN='postgresql://gateway_test_admin:synthetic-password@127.0.0.1:55432/gateway_test_admin?sslmode=disable' \
GATEWAY_TEST_POSTGRES_REQUIRED=1 \
  go test -count=1 -run '^(TestStoreKindsConform|TestPostgres.*|TestAPostgres.*|TestThePostgres.*|TestEveryCorpusStoreExportsFromThePostgresKindByteForByte)$' .
docker rm -f gateway-pg-test
```
