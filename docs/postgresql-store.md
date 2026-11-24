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
| a platform's `write: true`; `/act` | the configuration's load; `/act` answers 501 | an action keeps its journal and evidence on disk |
| a platform's `descriptorStatements`; descriptor provenance; a descriptor capture by `gateway connect` | the load; the start; `connect` before any adapter is asked | the signed snapshot is read from the store on disk (`gateway connect --no-descriptors` connects a platform without one) |
| `/verify` | answers 501 | it verifies the store on disk: export the store and verify the export |
| `gateway remove-artifact --config`, `gateway remove-scope --config` | the command | they keep removal records, and remove files, on disk; on this kind `gateway store remove-scope` removes a scope identifier's rows ("Removing one scope identifier's rows"), and `gateway store retain` an acknowledged session's ("Retention by acknowledgment") |
| `gateway rotate-key` | the start refuses a rotation under way beside the seed | the rotation keeps the registry at a path; on this kind `gateway store rotate-key` rotates the key, every instance stopped ("Rotating the signing key") |

`gateway verify` takes a store directory and a registry file: it reads an export of this kind
(`gateway export --config`), never the database.

Schema version 10 (migration 0010) makes the journals' table of ADR-0056, `gateway.journal_records`:
a row per entry, keyed by the journal's name and the entry's ordinal, each row after the first
naming the one before it through a foreign key, so the database admits a row only at the end of its
journal's chain, and each row's line of 1 to 4096 bytes with no `0x0A`. The run-time login may read
and insert rows, and never update, delete or truncate them; the start refuses a login that may.

The operator journal on this kind is the rows of `gateway.journal_records` under the name
`operator`, each entry the filesystem kind's, with the same envelope, signer and chain:

- `gateway store retain` and `gateway store remove-scope` insert their entry, as the owner, in the
  transaction that inserts their removal records and removes the rows, so the entry and the change
  commit together or not at all;
- `gateway seal-open`, and `gateway store rotate` in the database rotated from, insert theirs after
  the last seal, as the run-time login, in a transaction of its own fenced on the start lease. A stop
  between the seals and the entry leaves command seals that no entry names, which `gateway verify`
  reports as `journal-entry-missing` until the next `seal-open` or `store rotate` names them;
- `gateway store rotate` begins the journal of the database rotated to with its `store-continued`
  entry, in the migration's transaction that makes the new registry. A rerun holds an entry there to
  the new registry, and writes it again where it is not there.

The refusal journals (ADR-0059) are rows of the same table, one journal per configured scope, each
under its `refusal-` name (24 letters after it, within the table's CHECK on a name of 1 to 32
characters). Each journal's key is kept in `gateway.secrets`, and its forwarding cursor in
`gateway.documents`, a document of no scope. `gateway store remove-scope` deletes all three for the
scope it removes, as the owner, in its own transaction. A scope that holds no row has its journal
removed too where the journal holds entries, under an operator entry naming no removal record
(`removalBytes` 0) and the journal by `refusalJournalBytes` and `refusalJournalDigest`. A key beside
no entry stays, and a scope holding neither is left as it was (ADR-0059, as built 2026-11-24). The refusal journals need no migration past
0010. Schema version 12 (below) is the last of this release.

An entry's lengths are of the bytes an export writes. `gateway export` writes the rows, in ordinal
order, each line and its `0x0A`, as `store/journals/operator.jsonl`, the path of the filesystem
kind's file, and `gateway verify` reads the export as it reads a store of that kind. An export by
scope carries no journal.

Migration 0010 is one-way. A gateway whose migrations end at version 9 (v0.39.0 and earlier)
refuses a database at schema version 10, by its start and by its `gateway store migrate` alike: "a
gateway older than its schema does not run on it". Stop every instance and back the database up
before `gateway store migrate` applies it; going back to v0.39.0 or earlier means restoring that
backup.

Schema version 11 (migration 0011, [ADR-0061](adr/0061-request-limits-counted-together-by-the-instances-of-one-database.md))
makes `gateway.limit_rates`, a row for each scope whose request rate the instances count together
(`limits.shared`, engine version 51): the scope's form and the bucket's time, in microseconds of
the database's clock. Row security is forced under the scope policy. The run-time login may read,
insert and update its scope's row, and never delete one. Migration 0011 is one-way as 0010 is: a
v0.40.0 gateway refuses a database at schema version 11. Stop every instance and back the database
up before `gateway store migrate` applies it.

Schema version 12 (migration 0012, [ADR-0062](adr/0062-postgresql-instances-of-one-database-answer-one-key-history-version.md))
adds `key_history` to `gateway.start_lease`: the version of the key history the row's instance
answers, `"1"` or `"2"`, default `"1"`. The instances serving one database at once answer one
version ("Several instances on one database"). A row from before reads `"1"`. The grants are
unchanged.

## One instance per database

One gateway instance serves a database at a time, unless the configuration says otherwise
("Several instances on one database", below), and the database says which, by a start lease: a
row of `gateway.start_lease` for each instance that has served it (schema version 6), which holds
the instance's identifier, drawn at its start, its mode, the key id it signs under and the
authority it names, when it last renewed the lease and when the lease expires, both by the
database's clock. An instance takes the row of an instance whose lease has expired, or a new one;
no row is removed. A lease runs at most ten minutes from its renewal; the row refuses any later
expiry, and infinity.

- **The start** takes the lease where no other is live, before it writes anything. The takes run
  one at a time, under a transaction advisory lock. While another instance's lease is live the
  start is refused, and exits 1, with
  `start-lease-held`, the other instance's identifier and how many seconds its lease runs; or,
  where the configuration gives `startWaitSeconds`, it waits for the lease ("Handing over to a new
  instance", below). It reads the row first and takes it only where it expired, and then without
  waiting: a start that is refused holds nothing the running instance waits for, however its
  connection ends.
- **From the take until the release**, through the rest of the start and while it serves, the
  instance renews the lease every 10 seconds on a connection of its own, never one of the pool's; each renewal runs the lease 30 seconds from the renewal's statement by
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
  renewed until then. From the first signal on, a second one ends the process at once, undrained:
  during the drain, and also while a start waits for the lease or makes its checks; a lease it
  held then expires as a crashed instance's does.

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

The periods are constants of this version. In this mode the lease decides which instance serves;
several instances serve one database only in the mode of their own ("Several instances on one
database", below; ADR-0031, decision 10;
[ADR-0035](adr/0035-several-instances-on-one-postgresql-database.md), option C).

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
for it; without the member the start is refused at once, as above. Within that time it also reads
the lease again past a failure that is the database's for the moment: a connection that broke or
could not be made (a failover, a reset), a server shutting down, not yet accepting connections or
at its connection limit, a serialization failure or a deadlock. It says each such failure, and once
the database answers it makes the start's checks again on fresh connections, as after any wait;
when the time runs out the start is refused with the last failure, exit 1. Any other failure, and
every failure of a start without the member, ends the start at once. Then:

1. Start the new instance. It listens on its address at once and answers every request, on every
   route, `503` with `Retry-After: 10` and one fixed body,
   `{"error":"this gateway instance is not serving yet: it serves once it holds the database's start lease, which another instance holds; send the request again"}`,
   while it reads the lease's row every renewal interval (10 seconds). It reads the row and takes
   it only where it is not live by the database's clock: while it waits it holds no row, takes no
   lock past one read, and writes nothing. It holds connections all the same, so the server's
   connection budget takes both instances, `connections` + 1 each, for the hand-over. A readiness
   check that wants a `200` holds it not ready until it serves; one that wants a listener finds it
   ready at once.

   Where its address is in use, as it is when the new instance runs on the old one's host with the
   same `listen`, it says so and waits for the lease without listening: nothing answers on its
   behalf, and the old instance goes on answering at that address. Any other failure to bind ends
   the start, exit 1.
2. Stop the old instance with SIGTERM. It drains and releases the lease ("A stop", above); it stops
   listening before it releases the lease.
3. The new instance takes the lease at its next read, within 10 seconds of the release, makes the
   start's checks again (the server's bounds, the run-time login's privileges, the schema's
   version, the registry's walk), and serves. On its own address it serves on the listener it
   bound, which it never closed: a caller who connects meanwhile waits for its answer and is not
   refused. On the old instance's address it binds the address once it holds the lease; from the
   old instance's stop of listening until then a caller's connection is refused. A bind that fails
   then, the address taken by another program meanwhile, ends the start, exit 1, and releases the
   lease.

A caller meets `503`, with `Retry-After`, from the old instance from its signal on and, on an
address of its own, from the new one until it serves, and nothing else; on the old instance's
address, the old instance's `503`s and then, until the new one serves, a refused connection. The
window is the drain (at most `operationSeconds`), at
most one renewal interval, and the start's checks. Give the orchestrator's grace period for a stop
more than `operationSeconds` and 20 seconds, or it may kill the old instance before it released the
lease and the hand-over waits for the lease to expire. The stop's longest run is the drain
(`operationSeconds`), then at most 15 seconds for the requests still open to be answered (a
source's 5-second wait to end and 10 seconds more), then at most 5 seconds for the release.

If the old instance does not release its lease (its host is gone, a kill, a second signal), the
waiting instance takes it once it expired, within 45 seconds of the old instance's last renewal
("The timing", above). If the wait runs out first, the start is refused as one that does not wait:
exit 1, `start-lease-held`, naming the holder; the listener is closed. A stop signal while it
waits ends the start, exit 0, having held nothing. A start that finds the lease held names the
holder: do not remove the row by hand while that instance may be running.

What a hand-over does not do:

- **It does not carry open sessions over.** A session open on the old instance at its stop, or
  at its crash, stays open: the new instance does not continue it (a call into it is refused as a
  session another process left open, SPEC.md §6), and a caller whose session the stop left
  open opens a new one on the new instance. Such a session is sealed after the interruption
  (SPEC.md §3c) by the new instance's start where its configuration sets `sealOpenAtStart`, or
  by `gateway seal-open --config` once the instance's lease has expired ("Sealing the sessions an
  instance left open", below); until then it reads `unregistered-session`, observed `session-open`, to a
  verifier. Seal a session before the stop where it can be: a seal of §3's form says the count
  is the minting instance's own.
- **It does not compare keys or authorities.** In the one-instance mode the start does not hold
  the new instance to the old one's seed or authority: it takes a row only once no other is live,
  and compares nothing with an expired one; the registry's walk holds a key only to the
  registry's rotations. Give both instances one seed and one authority: seals and receipts made
  under another key do not verify under the key a verifier pins.
- **It does not migrate.** When the new version carries a migration, the new binary refuses the
  database's earlier schema at its start, before it waits. Stop the old instance with SIGTERM and
  wait for it to exit, run `gateway store migrate`, then start the new instance: every instance is
  stopped while a migration runs, and the command is refused while any instance's lease is live.
  A start that waited checks the schema again once it holds the lease, and is refused where it is
  no longer its binary's.

## Several instances on one database

Instances serve one database beside one another where each one's configuration, at engine
version 26, says so in the `storage` member
([ADR-0035](adr/0035-several-instances-on-one-postgresql-database.md), option C):

```json
"storage": {
  "kind": "postgresql",
  "connection": { "file": "/run/secrets/gateway-store-url" },
  "instances": "several"
}
```

`instances` is `"one"` (the default: one instance per database, as above) or `"several"`. Each
instance takes its own row of the start lease and renews it, and every write of it is fenced on
its own row, as above. A gateway keeps a session's count and chain in memory, so a session is
served by one instance: **the instance that admitted its first call holds it**. That instance
records itself as the session's holder when it admits the call, before the source runs.

- **Route a session to its instance.** A router, or the caller, sends every call of a session --
  its acquisitions and its seal -- to the instance that answered its first call. The session is a
  member of the request's body, not a header. Another instance answers such a call `409`, before
  the source runs, with one fixed sentence that names no instance:
  `session <id> is held by another gateway instance serving this database: a session is served by
  the instance that admitted its first call, so send its calls and its seal to that instance, or
  acquire into a new session`. It is not forwarded.
- **One seed, one authority, one engine version's reading of sessions, one set of sources** on
  every instance. A start in this mode is refused, `instance-mismatch`, where an instance whose
  lease is live signs under another key id, names another authority, or reads the session a
  request names otherwise: by label from engine version 39, by id before it ("Session labels"),
  or answers another version of the key history (`"2"` where its configuration sets
  `keyHistoryVersion: "2"` or the carried history is of version `"2"`, `"1"` otherwise; schema
  version 12, [ADR-0062](adr/0062-postgresql-instances-of-one-database-answer-one-key-history-version.md)); it is refused, `start-lease-held`, beside a live instance of the
  one-instance mode, and an instance of the one-instance mode is refused beside one of this mode.
  The comparison is with live instances alone: once every instance has stopped and its lease has
  run out, a start is compared with none, as in the one-instance mode. A key changed then is still
  refused, by the start's walk of the registry, unless the registry's rotations end at it
  (`gateway store rotate-key`, "Rotating the signing key"); an authority changed then is not, so keep one authority for the
  database's life. The sources are not compared: give every instance the same ones, or a session's
  later calls may meet a source its holder lacks.
- **Connections:** `connections` + 1 for each instance in the server's connection budget.
- **Delegated runs:** a delegation's credential is bound, and revoked, at the instance that bound
  it; keep a delegated run's calls to that instance. The admission read still refuses a revoked
  delegation at every instance.
- **An instance that stops or dies** leaves its sessions as one instance's stop leaves them. While
  its lease is live, every other instance answers a call into them, or a seal of them, `409`.
  Once it has expired, a session that holds no receipt is taken up by the next instance a call
  reaches -- after every write of the old instance has ended, or failed at its fence -- and one
  that holds receipts is refused as one another process left open, `400`, until it is sealed
  after the interruption ("Sealing the sessions an instance left open", below). Two instances that
  take up one session at once are not both admitted: the second is answered `409`. A stopping
  instance's `503` says so: another instance serves the call sent again once this one has
  stopped, unless the call's session holds receipts already, which no other instance continues,
  so the caller acquires into a new session.
- **The registry** stays one chain: a seal is judged against the registry in the append's own
  transaction, under its lock, so no session is sealed twice. An instance keeps its walk of the
  registry from its start on, and a seal reads and walks there only what was appended since the
  instance last read it: the transaction and the lock's hold stay short whatever the registry's
  size (the start still reads and walks the whole registry, outside any transaction, as before).
  The registry is append-only to the run-time login (below), so what the instance walked stays as
  it was; its last line is found again in its place before what follows is read, and a registry
  that is not the one the instance read -- a database restored under it, or one that lost its last
  commits to a failover -- is read and walked whole again. A start that finds the registry made by
  another instance since its read goes on with it, and so does one that finds no registry and then
  a session in the store, once a second read finds the registry another instance made meanwhile;
  where that read finds none, the start is refused as ever.
- **A migration, and `gateway store remove-scope`,** run with every instance stopped: each holds the
  start lease's lock and every row of it, and is refused while any instance's lease is live.
- **No instance older than v0.31.0 runs beside one of v0.31.0, or after it.** v0.31.0 seals a
  session of a scope identifier with a seal of version 2 (SPEC.md §3, "A seal of version 2"),
  which a gateway of v0.30.0 or earlier does not read: to it the session is still open, and its
  `gateway seal-open`, or its start with `sealOpenAtStart`, seals the session again in the earlier
  form, after which a v0.31.0 verifier reports the session `seal-conflict`, and keeps reporting
  it. Nothing refuses the older instance: the schema is the same, and no start compares
  versions. So stop every instance of v0.30.0 or earlier, and wait for each to
  exit, before the first v0.31.0 instance serves; once a seal of version 2 is in the registry,
  never start an older instance on the database, nor run an older `gateway seal-open` against it.
  The upgrade is one-way. The same holds again for the seal of version 3 (SPEC.md §3, "A seal of
  version 3"; ADR-0042), which v0.31.0 and v0.32.0 do not read: stop every instance of them before
  the first instance of the release that brings it serves, and never start them on the database
  afterwards.
- **Throughput:** acquisitions scale with instances across sessions; one session's calls serialise
  in its instance; seals serialise on the registry's append. A take-up stalls its instance: it
  waits for every write of the stopped instance that still holds that instance's row -- at most
  the 10 seconds the server allows an idle transaction, and never past `operationSeconds` -- and
  the instance judges a session it does not hold under the lock every admission and seal of it
  takes, so its other admissions and seals wait behind the take-up for that time. The lock is
  kept so that no two calls of one instance judge one session at once: released for the wait, a
  second call into the session could find the first's take-up or receipt and be refused `409` or
  `400` for a session its own instance holds.

- **Request limits counted together** (`limits.shared`, engine version 51; ADR-0061). Without the
  member each instance counts its own limits (ADR-0057). With it, each scope's rate is leased from
  its row of `gateway.limit_rates` in batches of b = ceil(rpm/600), 1 to 64 and at most the burst,
  by one statement on a connection of the instance's own, never the pool's, at a low-water mark
  of b/2. The lease takes the row `NOWAIT`: a held row fails at once, and that scope alone is tried
  again after 50 ms. No request sends a statement or waits for a row. Over any window W the
  instances admit at most B + ceil(W/T) + N·b (B the burst, T the interval, N the instances), and
  never more than the rate over time: at 6000 a minute (T = 10 ms, b = 10) with a burst of 50 on
  three instances, at most 50 + 100 + 30 = 180 in any one second. In flight
  and per caller each instance holds ceil(limit/N), with N the live rows of `gateway.start_lease`
  counted by the start beside its lease (a count that fails fails the start) and every 10 seconds
  after (a later count that fails keeps the last N), at most cap + N − 1 in all. Where a refill
  fails other than by a held row, or
  gets no answer within 2 seconds, or a scope's refill waits more than 4 seconds with its batch
  spent, each instance counts the rate alone at ceil(limit/N), from its own bucket carried over from
  its last spell alone, until a probe, tried every second, leases every limited scope's batch, one
  scope after another, all within 4 seconds, and `/posture` says the shared count is unavailable
  and why. With many limited scopes that sum can keep an instance alone (at 25 ms a lease, about
  160 scopes). The instances still sharing do not know of one counting alone, so while k of N
  count alone a window W admits up to B + ceil(W/T) + N·b + k·(ceil(B/N) + ceil(W/T_N)), T_N the
  interval of ceil(rpm/N): about k/N of the rate more, for as long as it lasts. Treat a lasting
  fallback, on any instance's `/posture`, as an alert condition. The gateway-wide cap
  (`beforeScope`) stays each instance's own. A refill is a write fenced on the instance's start
  lease. Enabling `limits.shared`, or changing a limit value, is a stop-all change: the start
  lease does not compare them between instances, so stop every instance, change the
  configuration, and start them.

The filesystem kind stays one instance per store and registry.

## Sealing the sessions an instance left open

A session an instance minted into and did not seal before it stopped -- at a hand-over, by a
second signal, or at a crash -- is sealed with the seal made after an interruption (SPEC.md §3c;
ADR-0035, the third step), as on the filesystem kind: no new record, its `finalCount` the
receipts the store holds in the session, its `headSignature` the last one's signature, and a
verifier observes it `sealed-after-interruption` (or, with `--ordinary-seals-only`, finds it).

- **At the start**, with `sealOpenAtStart: true` (engine version 17 or later; with `storage`,
  24 or later): once the start holds the start lease and has walked the registry, and before it
  serves -- a start that waits for the lease answers `503` until then -- it seals each such
  session, `sealedVia: "start"`, and writes each seal on stderr as `start: sealed after an
  interruption: <registry line>`.
- **By the command**, `gateway seal-open --config <engine.json> (--session <id> | --all)`,
  `sealedVia: "command"`, each seal printed as its registry line. It connects as the run-time
  login, as `serve` does, and takes the start lease as a start of its configuration's mode does:
  in the one-instance mode, while an instance's lease is live, it is refused at once, exit 1,
  `start-lease-held` and `stop the gateway, then seal`; it does not wait, whatever
  `startWaitSeconds` says. It renews the lease while it runs, every seal
  it appends is fenced on it as an instance's writes are, and it releases the lease at its end.
  A second run finds nothing to seal: `seal-open: no session in the store is left open; nothing
  was sealed`, exit 0.

Each session records the instance that holds it, and only a session whose holder's lease has
expired is sealed (ADR-0035, question 11). Where instances serve beside one another, the start and
the command pass over, with `--all`, every session a live instance holds, and refuse one named:
`session <id> is held by another gateway instance serving this database, whose start lease is
live; it is not sealed`. Before a session is read, the expired row of each instance that held one
is held `FOR UPDATE`, so no write of that instance commits after the read, and the read sees who
holds the session again in its own snapshot. In the one-instance mode no instance but the start
or the command is live.

What is read, and where. Nothing read is written anywhere, and no file is made. The scope
identifiers recorded and the removal records are read in a transaction of no scope; each scope's
series names -- of no scope first, then of each identifier in byte order -- in a transaction of
that scope alone ("Scope identifiers"). A series' name is the key of its table, so no two scopes
hold one session. A session a seal closes already is not read past its name; nor is a series whose
name no session id is (SPEC.md §3a), which is named, `the store's series "<name>" is not named as
a session is (SPEC.md §3a); it is not sealed`, and the rest judged, as the filesystem kind names
such a directory. Each other session is read in one transaction of its own scope: its receipts,
held in the process's memory, and, for each payload a receipt names, whether that scope holds
bytes under the name and the SHA-256 of those bytes, which the database computes -- the payload's
bytes do not leave it. A session of no receipt is read so, and found to hold none. Each session is
then judged by the verifier's own ladder, as `gateway seal-open` judges a store on disk: what is
sealed is what `gateway verify` of an export observes `session-open` -- receipts every one of
which has ladder status `ok`, in sequence and chained. The payload step reads what the session's
own scope holds and nothing else: a payload another scope holds under the same name does not stand
in for one this scope lacks (`artifact-missing`) or holds with other bytes (`artifact-mismatch`).
A receipt that names descriptor provenance, which this kind does not admit, is judged not whole. A
session that is not whole is named with what verification finds of it and left open, and the rest
are sealed (exit 1 for the command); a session that cannot be read stops the command, and the
start, with nothing sealed. Seals are appended to the registry by its one serialised append, each
judged in the append's transaction and refused where the registry holds a seal for its session
already; a session another instance's start sealed since it was judged is passed over by `--all`.

## Upgrading from v0.29.0

v0.30.0 carries schema version 6. The step to it is made with every instance stopped; the orderly
hand-over ("Handing over to a new instance") does not carry it, since `gateway store migrate` is
refused while any instance's lease is live and a v0.30.0 instance refuses a database at schema
version 5. In this order:

1. Stop every instance and wait for each to exit.
2. Back the database up. Migration 6 is one-way: it drops `gateway.start_lease` and makes it again,
   empty, in its new form (a row for each instance), and records from then on the instance that
   holds each session.
   A v0.29.0 binary refuses a database at schema version 6, by its start and by its
   `gateway store migrate` alike: "a gateway older than its schema does not run on it". Going back
   to v0.29.0 means restoring that backup.
3. Run `gateway store migrate` as the migration login (`{"applied":[6],…,"schemaVersion":6}`).
4. Start the v0.30.0 instances.

A configuration of engine version 25 or earlier keeps the one-instance mode: one instance per
database, as before. To go from one instance to several, give every instance v0.30.0 and a
configuration of engine version 26 with `"instances": "several"` ("Several instances on one
database"), each with the same seed and authority. The two modes refuse each other on one
database: an instance of the several-instances mode is refused, `start-lease-held`, while an
instance of the one-instance mode serves it, and the other way round. So stop the instance of the
one-instance mode before the first instance of the several-instances mode serves, and stop every
instance of that mode before going back to one.

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
{"applied":[1,2,3,4,5,6,7,8],"migrations":"sha256:…","schemaVersion":8}
```

A second run applies nothing (`"applied":[]`). A schema newer than the binary's migrations is
refused, by the command and by the start alike. `--timeout` bounds the run, connection included:
1 to 3600 seconds, 300 without it. Exit 0 on success, 1 on a refusal or failure, 2 on a usage
error. Run it with every instance stopped: migration 4 locks and rewrites `gateway.log_records`
("The migration"), and migration 6 makes `gateway.start_lease` again; a running instance does not
check the schema again, and an instance of a binary older than the schema refuses the store at its
next start. A store that holds a start lease (schema version 2 or later) is migrated only with
every row of the lease held and none live: the command is refused, `start-lease-held`, while any
instance's lease is live.

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
| `gateway.series` (the sessions; from schema version 6, the instance that made each) | SELECT, INSERT | its scope's |
| `gateway.series_holders` (schema version 6: the instance that took up a session) | SELECT, INSERT | its scope's |
| `gateway.entries` (the receipts) | SELECT, INSERT | its scope's |
| `gateway.documents` (documents and leases) | SELECT, INSERT, UPDATE, DELETE | its scope's |
| `gateway.logs`, `gateway.log_records` (the seal registry) | SELECT, INSERT | every one: the registry is one chain |
| `gateway.secrets` | SELECT, INSERT | every one |
| `gateway.schema_migrations` | SELECT | every one |
| `gateway.start_lease` (a row for each instance) | SELECT, INSERT, UPDATE | every one: it carries no scope |
| `gateway.scope_identifiers` (schema version 3: the scope identifiers recorded) | SELECT, INSERT | no scope's: every row is of no scope |
| `gateway.removal_records` (schema version 5: the removal records) | SELECT | no scope's: every row is of no scope |
| `gateway.rotated` (schema version 7: the mark of a store rotated away from) | SELECT, INSERT | every one: it carries no scope, and holds one row at most |
| `gateway.key_history` (schema version 8: the key history a store rotation carried into the database) | SELECT | every one: it carries no scope, and holds one row at most |
| `gateway.session_labels` (schema version 9: each session label and the session id minted for it) | SELECT, INSERT | its namespace's: the scope it is of, or none |
| `gateway.journal_records` (schema version 10: the journals' entries, a row each) | SELECT, INSERT | every one: it carries no scope, and a row is admitted only at the end of its journal's chain |
| `gateway.limit_rates` (schema version 11: a scope's shared request rate, ADR-0061) | SELECT, INSERT, UPDATE | its scope's |

Append-only by privilege: nothing but a document, the start lease's rows and a scope's shared rate are changed once written,
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
not compared. `gateway store migrate` compares the same definitions before it commits: a server
that prints one otherwise (the list is read from PostgreSQL 16) rolls the migration back, and the
store stays at the version it was, rather than migrated and refused by every start.

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

**Whose scope it is.** The view an acquisition opens is the source's scope identifier, taken
only once the request names it and the caller's verified identity reaches it (engine
configuration version 27, `identity.callerScopes`;
[ADR-0037](adr/0037-a-caller-is-held-to-the-scope-identifiers-its-token-and-the-configuration-allow.md)):
a caller of one scope identifier that names another is refused before any transaction of that
scope opens, and leaves no row in its view, and a seal of a session of a scope the caller does
not reach is answered as one the gateway does not hold. Where `callerScopes` is `"unchecked"`,
or no `identity` is configured, the view is the one the request names, as before; the start and
`/posture` say so.

**How it maps to records.** For a source fixed to the scope identifier `scope-a`:

| Record | Where | Row's `scope` |
|---|---|---|
| the payload (a retained artifact) | `gateway.blobs` | `scope:scope-a` |
| the session | `gateway.series` | `scope:scope-a` |
| an instance's take-up of the session (several instances) | `gateway.series_holders` | `scope:scope-a` |
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
  scope identifier, or none): a session's receipts are of one scope, so acquire into a new
  session`. The refusal names neither scope. The filesystem kind refuses such an acquisition
  alike (ADR-0036), and an `/act` into a scoped session is refused on either kind.
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
  receipts, its time, the key's identifier and a signature, and, for a session of a scope
  identifier, `sealVersion` `"3"` and `scopeDigest`, the identifier's SHA-256 digest over the
  session's scope salt, which its receipts carry and no registry row does (ADR-0042; SPEC.md §3,
  "A seal of version 3"), or, for a seal an earlier release wrote, `sealVersion` `"2"` and the
  identifier's digest in the session (ADR-0036, decision 9), never the identifier. None
  carries a receipt, a payload, an argument or a scope identifier, so a gateway of one scope reads
  the ids, counts and digests of every scope's sealed sessions and no other scope's identifier,
  which `gateway.scope_identifiers` keeps from it. A digest of version 3 tests no guessed
  identifier without the salt; one of version 2 is not a secret: one who guesses an identifier
  can digest it in a session's id and test it. When a scope's rows are removed its
  seals stay, digests of rows no longer held: the chain needs every line. `gateway verify` reads
  the chain from an export, which holds every line. `gateway export --scope` holds the rotation
  statements and the scope's lines alone, which walk from the pinned key as the whole chain does,
  and `gateway verify --scope` cuts a verdict by one scope (SPEC.md §4, §5a).
- **The export** reads every scope recorded, whichever scopes the configuration names now, and
  writes the layout of SPEC.md §1.3 the filesystem kind writes: a session once, under its name; a
  payload two scopes hold alike once, its bytes read from each and compared, and refused where
  they differ; documents of no scope alone, since an export writes none.
- Row security keeps apart what the gateway does. It is not a boundary against the run-time login
  itself, which may set `gateway.scope` as it likes in a transaction of its own; a login per scope
  identifier is an open decision (ADR-0031).

## Removing one scope identifier's rows

```text
gateway store remove-scope (--connection-file <path> | --connection-env <NAME>) --owner <role> --runtime <role> (--seed <file> | --config <engine.json>) --scope <identifier> --by <label> [--timeout <seconds>]
```

The command removes every row of one scope identifier, its sessions (`gateway.series`, and their
take-ups, `gateway.series_holders`), receipts
(`gateway.entries`), payloads (`gateway.blobs`), documents and shared request rate
(`gateway.limit_rates`, schema version 11), and its row of
`gateway.scope_identifiers`, and records the removal, in one transaction
([ADR-0034](adr/0034-removing-one-scope-identifiers-records.md)). It takes the migration login's
connection string as `gateway store migrate` does, never printed. The records are signed by the
key in force. Given `--config`, that is the key service's key version the configuration names,
held to `signingPublicKey`, or else the configuration's seed (ADR-0050). Given `--seed`, it is that
seed's key, and a registry under a key service's key is refused.

- **Who removes.** The migration login, by SET ROLE to the owner for the transaction alone: the
  owner holds DELETE as the tables' owner. No role, grant or function is added for it; the
  run-time login's privileges do not change, and it holds no DELETE on a table but
  `gateway.documents` (a test pins its grants before and after a removal).
- **What it holds.** The migration's advisory lock, so no migration runs beside it, and the start
  lease's lock and every row of the lease, to its commit: while any instance's lease is live, the
  command is refused (`start-lease-held: a gateway instance serves the database, … stop the
  gateway, then remove`) and nothing changes; a start while it runs waits for it or is refused. A schema not at the binary's version is refused (migrate first), and
  so is a store with no registry yet.
- **Row security stays forced.** The scope's rows are read and removed with `gateway.scope` set
  to the scope's form, and the scope named in every DELETE besides; each DELETE's count is held
  to the count read, and the transaction rolls back where one differs. Every session label of
  the scope's namespace goes (schema version 9), first, before the receipts, and where the scope
  holds labels and no session, as a label minted for a source that failed leaves, the labels go
  alone, with no record, since no session is removed. The records and the
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
- **An export beside it.** The command takes no lock an export holds. An export reads the
  records in its cut's snapshot, with the rows, and reads each receipt's and payload's bytes
  afterwards: one the cut listed and the read finds gone was removed after the snapshot, and the
  export stops with an error and exit status 1, before its manifest, so nothing is left as a
  finished export. Export again once the removal is done.
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

## Rotating the store

```text
gateway store rotate --config <engine.json> (--connection-file <path> | --connection-env <NAME>) --owner <role> --runtime <role> [--timeout <seconds>]
```

A rotation lets the store go by starting another
([ADR-0048](adr/0048-retention-by-acknowledgment-and-store-rotation.md), decision 3; SPEC.md §3d).
On this kind the new store is **a new database**, which the operator makes as in "Before the first
start", for the same roles. It is never a new instance on the same database: every instance on one
database shares one registry chain ("Several instances on one database"). `--config` names the old
store, the seed and the authority, as `gateway seal-open --config` takes them. The connection flags
name the migration login on the new database, as `gateway store migrate` takes them, never printed.
`--timeout` bounds each of the command's two transactions there (default 300 seconds).

- **The old database.** The command reaches it by the configuration's run-time login alone. It
  takes the start lease first, in the one-instance mode whatever `storage.instances` says, and
  holds it to its end. It seals every session left open, as `gateway seal-open --all` does
  ("Sealing the sessions an instance left open"), each seal fenced on the lease. Nothing else is
  written there.
- **The new database.** Before anything is sealed, the migrations are run there in a transaction
  that is rolled back at its end, and the database is held to hold no store. Once the seals are
  appended, the migrations run again. In the same transaction, under the migration's lock, the
  command checks the database again, reads the old registry again under the lease, and makes the
  registry holding the store continuation alone, with the key history it names in
  `gateway.key_history`. The migration, the registry and the history commit together or not at
  all.
- **The key history.** SPEC.md §3e's history of the old database, as its instances answer
  `GET /publickey/history`: its registry's, with what was carried into it in its turn, so a second
  rotation carries the whole history on. The continuation names its bytes by `keyHistoryDigest`.
  It is the one row of `gateway.key_history` (schema version 8), which the owner writes and the
  run-time role reads alone, and every instance on the new database answers it with the walk of
  the registry they share. A row missing or changed by the owner is answered `500`, never as a
  shorter history. The row holds a history of either version (SPEC.md §3e; ADR-0055) with no
  schema change: a row of version `"2"` is answered as version `"2"` by every instance, whatever
  its configuration says, and the rotation writes version `"2"` where its `--config` holds
  `keyHistoryVersion: "2"` or the old row is of version `"2"`. `gateway export --config` does not write it beside the exported registry.
- **The grants.** The run-time role holds on the new database what `grants.sql` gives it on every
  migration, and nothing more (a test compares them with the old database's).
- **The line.** SPEC.md §3d's `store-continuation`, signed by the seed's key, naming the old
  registry's line count and the SHA-256 of its bytes, whole, as the registry stands after the seals.
  The command prints each seal appended, then that line.
- **Verifying the pair.** Export each database with `gateway export --config` and verify the new
  export with `gateway verify --previous <old export>/registry`. The old export is to be taken
  after the rotation, before any instance serves the old database again. An instance started there
  later appends to its registry, and the link to that registry no longer holds (a test).

It is refused, with exit status 1, by name:

- while any instance's start lease on the old database is live (`start-lease-held: …; stop the
  gateway, then rotate`). Nothing is sealed, and the new database is not migrated.
- when the new database cannot be migrated, or holds a store: a registry (`it holds a registry`),
  a key history carried, a row of the start lease, a secret, or a row of no scope, the scope identifiers recorded among
  them (`it holds rows of a store`). The old database itself, or a database a rotation already
  made, is refused so. Nothing is changed. The check reads the scoped tables as rows of no scope
  only, and every store a gateway made holds a registry and rows of the start lease, which are of no
  scope: only a database built by hand, holding scoped rows alone, gets past it.
- when a session left open cannot be sealed, or the old registry is not there. The new database
  is not migrated.
- when the old registry changed after it was read under the lease, when the lease is lost or is
  held for no more than a write's margin by the time the new database's transaction is to commit,
  or when that transaction fails. The seals appended stay in the old registry, and a run again into
  an empty database rotates the store. When the COMMIT itself does not answer, the command says the
  store *may have rotated; rerun to check*: a run again into a new database that holds more than
  a registry is refused (`it holds a registry`), into one that holds the continuation of the old
  registry alone writes the mark below and nothing else, and into an empty one rotates the store.
  The run into one holding the continuation alone holds its key history first: a row there that
  is not the bytes the continuation names is refused, and nothing is changed or marked; a row
  missing is written, in a transaction of the migration login, only where the history made is the
  one named.

The mark (SPEC.md §3d) is the one row of `gateway.rotated` (schema version 7): the hexadecimal
SHA-256 of the continuation line and the time it was written. The command writes it last, as the
run-time login, under the start lease and fenced as every write is, once the new database's
transaction is committed; a mark that fails to write is said so, and a run again writes it.
Until it is written the old database is not marked, so keep every instance stopped until the run
again has marked it. The mark fails to write when the lease is lost first. If an instance starts on
the old database before the run again, its registry grows past the one the continuation names. The
run again is then refused (`it holds a registry`), and the new database must be dropped by the
operator and made again empty before a rotation into it. A
start on the old database reads the row before the start lease's rows and is refused by name,
*the store was rotated away from (store-rotated:...)*; so is every command that takes the lease,
`seal-open` and a second `store rotate` among them. `gateway store remove-scope`, which holds the
lease's rows without taking a row, is refused by the same sentence, since a removal appended to
the old registry would break the link the new store names. `grants.sql`
gives the run-time role SELECT and INSERT on the table and nothing else, and the key admits one
row: a run-time login can only mark its own store rotated, which it could already cause by
holding the lease. Removing the mark is the owner's alone. A database at an older schema version
is refused by this release's open until it is migrated (`apply the store's migrations`).

A rotation shuts the old store for good, so what it holds for a receipt sink is delivered first.
With a `receiptSink` in the configuration, the receipts of each session left open are delivered
before it is sealed, as `seal-open --config` delivers them; with `receiptSink.seals`, each seal
held for the sink, pending forwarding, is delivered first too, and each seal the rotation appends
after it. A session the sink does not acknowledge, or a seal it does not, refuses the rotation:
*a session left open was not sealed, or its seal is held for the receipt sink, so the store is
not rotated*. A seal held whose marker the rotation would not deliver, the configuration's sink
taking no seals, refuses it before anything is sealed: *a seal is held for the receipt sink,
pending forwarding, of session ...; deliver it first with gateway seal-open --config, or by the
gateway's start, then rotate*, and nothing is sealed. Neither refusal migrates the new database or
marks the old one.

Exit 2 on a usage error: `--new-store` and `--new-registry` are the filesystem kind's, and the
migration login's flags are refused beside a configuration of that kind, as `--no-sink` is. Dropping the old database
once it is past retention is the operator's, with PostgreSQL's own tools. Its rows stay in the
write-ahead log, base backups and replicas under the operator's own retention.

## Rotating the signing key

```text
gateway store rotate-key --config <engine.json> (--connection-file <path> | --connection-env <NAME>) --owner <role> --runtime <role> [--from-key-version <name> --from-public-key <hex> [--from-key-algorithm ES256]] [--timeout <seconds>]
```

On this kind the gateway's signing key is rotated with every instance stopped
([ADR-0050](adr/0050-an-external-signer-in-a-key-service.md), decision 3(a); SPEC.md §3b). SIGHUP
rotation is refused here, and `gateway rotate-key` needs a file registry. The command moves a store
from the seed to a key service's key version, or from one key version to the next:

1. Stop every instance.
2. Seal every session left open, under the key in force: `gateway seal-open --config <the
   configuration naming it> --all` ("Sealing the sessions an instance left open"). A session that
   holds a receipt is never continued by a later instance, and its seal under the key rotated from
   bounds what that key signed in it.
3. Write the next key version into `signingKeyVersion` and its public key into `signingPublicKey`
   (engine version 36).
4. Run the command with that configuration.
5. Start every instance under it.

- **The keys.** The next key is the configuration's `signingKeyVersion`, held to
  `signingPublicKey` and read as at the start. The key rotated from is named apart, since the
  configuration now names the next one. With neither `--from-key-version` nor `--from-public-key`
  it is the seed's key, from the configuration's `seed`. With both it is that key version, held to
  that public key. The pair is given together or not at all, as `signingKeyVersion` and
  `signingPublicKey` are. A configuration naming no `signingKeyVersion` is refused: a rotation on
  this kind is to a key service.
- **Across algorithms** (engine version 40, ADR-0053). The next key's algorithm is the
  configuration's `signingKeyAlgorithm`. A key rotated from that is a P-256 key version is named
  with `--from-key-algorithm ES256` beside `--from-key-version`, and its `--from-public-key` is then
  the 66-character compressed point; without the option the key rotated from is Ed25519. Ed25519 to
  P-256, P-256 to P-256 and P-256 back to Ed25519 are each one rotation: the `key-rotation` names
  the next key's algorithm in `nextAlg`, the `key-continuation` the previous key's in `previousAlg`,
  and each statement a P-256 key signs carries `alg`. A move from the HSM key back to an Ed25519 key
  is allowed, so that a rollback of the key is never blocked, and is named on one line of the
  standard error; the key history records it as any rotation. It rolls back the key, to an Ed25519
  key version of the key service, not to the seed, and it needs v0.38.0: it does not roll back the
  binary. Once the registry holds a rotation into P-256, a v0.37.0 gateway refuses the store
  (`rotation-break`) and never starts on it again, even after this rotation back (docs/releases/v0.38.0.md,
  "Rollback").
- **How it runs.** The connection is the migration login's. The command acts as the owner, in one
  transaction that holds the migration's lock and every row of the start lease, as `gateway store
  retain` does. In that transaction it reads the registry under the log's append lock, as every
  append reads it, and walks it. It appends SPEC.md §3b's `key-rotation`, signed by the key rotated
  from and naming the next key, and the `key-continuation`, signed by the next key and naming the
  previous one. Each signature is verified before anything is written. It then reads the registry
  back and walks it to the next key, and only then commits. It prints the two statements, and
  names the rotation on the standard error.
- **After it.** Every instance starts under the next key and is admitted beside the others: the
  rows of the start lease are compared only while they are live. `GET /publickey/history` lists
  every key the walk reaches. The store's earlier receipts and seals verify under the key they
  name, from the seed's key, as `gateway verify` follows the rotation. A start under the key
  rotated from is refused by the registry's walk.
- **A COMMIT that did not answer.** The record commits whole or not at all, so no part of it is
  left in the registry. The command says *the key may have rotated: rerun to check*. Run it again
  with the same keys. Where the record is whole, the walk ending at the next key by a rotation from
  the key rotated from, it says *the registry's walk already ends at this rotation, ... which may be an earlier run's: nothing
  was changed* (exit 0). Where nothing
  was kept, it rotates.

It is refused, with exit status 1 and nothing changed:

- while an instance serves, by the start lease's sentence: *stop the gateway, then rotate-key*;
- on a database rotated away from, by the store rotation's sentence;
- when the next key is the key in force: *the next key, key id ..., is the key in force already*;
- when the walk ends at another key than the key rotated from, or the registry or a session's first
  receipt is under a key the walk did not reach;
- while a session that holds a receipt is open: *session ... holds a receipt and is not sealed*;
- when a signature does not verify, or the record would not walk to the next key: a rotation back
  to a key the registry rotated from is refused so.
- when this host's clock stamps the rotation before the key history's last rotation, the
  registry's or the one a store rotation carried in: *the rotation's rotatedAt ... is before the key
  history's last rotation ...; correct this host's clock and run again*. The registry is
  append-only, so such a record would leave `/publickey/history` refusing the history for good
  (SPEC.md §3e). A rotation in the same second as the last one is taken.

Exit 2 on a usage error. A configuration of the filesystem kind is one: its key is rotated by
`gateway rotate-key` (the seed) or by SIGHUP (a key service). A coordinated rotation while
instances serve is #537.

## Retention by acknowledgment

`gateway store retain (--connection-file <path> | --connection-env <NAME>) --owner <role>
--runtime <role> --config <engine.json> --acknowledgments <file> [--scope <identifier>] --by
<label> [--timeout <seconds>]` is `gateway retain` on this kind (docs/design/engine-config.md,
"Retention by acknowledgment"). The connection is the migration login's; the configuration
gives the `retention` member and the seed. It runs as the migration login acting as the owner,
in one transaction that holds the migration's lock and the start lease, as `gateway store
remove-scope` does, so a gateway serving the database refuses it. For each session it removes
it deletes the session's label (schema version 9), first, then its receipts, its holders and
its row, and the payloads of its scope that no other receipt or document of the scope names,
and keeps a `session-removal` record in the same transaction. A session of no scope identifier is refused: it goes only with its whole
database. A database rotated away from is refused by the rotation's sentence, *the store was
rotated away from (store-rotated:...)*, since a removal appended to its registry would break the
link the new store names. The run-time role's privileges do not change.

## Session labels

From engine configuration version 39 the `session` a request names is a label in its scope's
namespace, mapped to a session id the gateway mints (docs/design/engine-config.md, "Session
labels"; ADR-0051). On this kind a label is a row of `gateway.session_labels` (migration
`0009_session_labels.sql`, schema version 9):

- **The table.** `scope` (as `gateway.series` holds it: `none`, or `scope:` and the identifier),
  `label` (of the session id form) and `series` (the minted id, 32 lowercase hexadecimal
  characters). The primary key is `(scope, label)`, and `series` is unique. No key references
  `gateway.series`: the row is written before the session's first receipt, so it may name a
  series that is not there yet. Row security is the policy of every scoped table: an instance
  reads and writes a namespace's labels through the view of its scope alone, so no statement
  reads another scope's labels.
- **The first use.** The instance inserts the row `ON CONFLICT (scope, label) DO NOTHING` and,
  where another request or another instance recorded the label first, reads the row there in the
  same transaction. Every instance on one database agrees on one id for a label, without the
  start lease or a lock of its own. An acquisition records a label it minted only once it is
  admitted, immediately before its source starts: a call refused before then leaves no label.
- **The grants.** The run-time role holds SELECT and INSERT ("What the run-time login may do"):
  a label is never changed. `gateway store remove-scope` and `gateway store retain`, as the
  migration login acting as the owner, delete the labels of the sessions they remove, first,
  before the receipts, in their one transaction ("Removing one scope identifier's rows",
  "Retention by acknowledgment"). A removed label is free, and its next use mints a new id.
- **The start lease.** Migration 9 adds the column `labels boolean NOT NULL DEFAULT false` to
  `gateway.start_lease`. Each instance records in its row whether its configuration is of version
  39 or later. An instance with labels on is refused beside one with them off, either way round,
  by name (`instance-mismatch`), as one under another key id is ("Several instances on one
  database"). `gateway seal-open --config` records its configuration's, so it is admitted beside
  the instances of its version.
- **The start at version 39** refuses while the database holds a session open that no label
  names, of any scope, naming `gateway seal-open --all`. A session an instance at version 39 left
  open is named by its label, and does not refuse a start.
- **`gateway sessions --config <engine.json> (--scope <identifier> | --no-scope) [--label
  <label>]`** reads one namespace's labels through the run-time login the configuration names,
  with the gateway running or stopped, and writes nothing.
- **What is not carried.** `gateway export` carries no labels, and `gateway store rotate` starts
  the new database with none.

**Upgrading to version 39.** Every instance moves together:

1. Stop every instance.
2. Run `gateway seal-open --config <engine.json> --all`, which seals each session left open.
3. Run `gateway store migrate` with the migration login, naming the run-time role. It applies
   `0009_session_labels.sql` and the grants, and moves the schema to version 9. A binary that ships
   no migration 9 does not serve a database migrated to it.
4. Raise `engineVersion` to `"39"` in every instance's configuration, and start them all.

Going back needs the same: every instance stopped and every session sealed first. An older engine
on schema version 9 passes `gateway.session_labels` over.

## Time

Receipt and seal times are the gateway's, never the database's. A lease of the store contract
(`store_leases.go`) expires by the gateway's clock. The start lease alone expires by the
database's clock: its statements read `clock_timestamp()`, and no other statement the gateway
sends, or schema file it carries, reads the database's clock (a test).

The start lease assumes the database host's clock does not step backward: keep it synchronized and
slewed, not stepped. A row is never removed, and the seal of a stopped instance's sessions holds
that instance's expired row without changing it. Were the clock to step back past an expired row's
expiry, that instance's renewal and its fence would pass again, if it had only paused: it could
append receipts to a session sealed after the interruption. Nothing is lost silently: a verifier
reports such a session's receipts past its seal, and the paused instance's own seal of it is refused
as already sealed.

## Backup and restore

The database's backup and restore are the operator's, with PostgreSQL's own tools. Restore into a
database made as above, with the same roles; the kind's start holds a restored database to every
condition on this page. A verifier reads a store of this kind through its export, which writes the
layout it reads; the export of a store holds the same bytes as the filesystem kind's for
the same work, of no scope and of scope identifiers alike (a test).

## Not supported

- what "Not available with this kind yet" lists;
- moving a store from one kind to the other;
- more than one live gateway instance on one database in the one-instance mode, the default: the
  start lease refuses a second ("One instance per database"); instances serve one database beside
  one another in the several-instances mode alone ("Several instances on one database");
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
  `postgresql` sets it and runs the tests twice, in two legs side by side, each against the pinned
  image in a service container of its own, with synthetic credentials: as a superuser
  (`postgresql · superuser`), failing if any test skipped, and as a login that may make roles and
  databases and nothing more, CREATEROLE and CREATEDB (`postgresql · non-superuser`). Four cases need a superuser to
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
