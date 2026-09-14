# catalog

The bindings the engine ships: one file per platform, `<platform>.json`, in the shape
[docs/design/engine-config.md](../docs/design/engine-config.md) states. A configuration
pins the file it uses by digest — `gateway connect` computes the pin when it writes the
platform entry — so a catalog update never silently changes what a running engine reaches.

Every image is pinned by the digest of its manifest index, as the registry served it on
the date recorded here; every licence is copied from the artifact's own statement for that
version, never assumed. `go test ./...` in `go/` holds each file to its shape and to its
file name.

## postgres

| Operation | Artifact | Pinned | Licence | Where the licence is stated |
|---|---|---|---|---|
| `history` | `airbyte/source-postgres:3.8.5` | index digest `a36f1528…ded125`, read from Docker Hub 2026-09-13 | ELv2 | `airbyte-integrations/connectors/source-postgres/metadata.yaml` in the airbytehq/airbyte repository at the commit where `dockerImageTag` is `3.8.5` (`4e38cca211`, 2026-08-26): `license: ELv2` |
| `live` | `bytebase/dbhub:1.2.3` with `--transport stdio` | index digest `8fbdf3f5…9f5db`, read from Docker Hub 2026-09-14 | MIT | `LICENSE` in the bytebase/dbhub repository |
| `write` | the same server, the same arguments | the same digest | MIT | the same |

The `live` entry carries no `probe`: this server connects to the database as it starts and
exits before answering the handshake when it cannot (a wrong password ends it with
"Configuration source: environment variable" on stderr, and the adapter reports "the server
ended before answering initialize"), so the handshake itself establishes the connection —
the opposite of the previous server, `crystaldba/postgres-mcp`, which started and listed its
tools whether or not it could reach the database. Both of this server's tools take
arguments (`search_objects` requires an `object_type`), so no probe could be named even if
one were needed. The server's `execute_sql` answers a query as **JSON text** — a text content
item holding `{"success": true, "data": {"statements": [{"sql", "rows", "count"}], "source_id"}}`,
rows as objects keyed by column — which is why it replaced the previous server, whose
`execute_sql` answered with Python's rendering of a list of dictionaries and left no
published rule to derive facts by ([docs/design/both-paths-agreement.md](../docs/design/both-paths-agreement.md)).

The server takes its connection string from the environment variable `DSN`, so both
credentials files are `{"DSN": "postgresql://…"}`, an object of strings. **What holds the
`live` operation to reading is the role the operator names in that connection string**, not
the server: this server's own read-only switch is a `[[tools]]` entry in a `dbhub.toml` it
reads from a path, and a binding hands a server an environment and arguments, never a file.
The `live` role must hold `SELECT` alone — that is what holds it to reading — and should
carry `default_transaction_read_only = on` (set on the role with `ALTER ROLE … SET`) as a
guard on top, one a session may lift with `BEGIN READ WRITE` and a connection-string
`options=` setting cannot set at all, since the driver does not carry it. The both-paths
test's live fixtures were captured through such a role, its fresh fetch runs both operations
through one, and an `UPDATE` through it is refused by Postgres — "cannot execute UPDATE in a
read-only transaction" under the default, "permission denied for table city" once the session
lifts it — which the server reports as an error result and the adapter as a failed
acquisition. The `write` file
names a role that may write. The connector's `history` file is the configuration its `spec`
describes (`host`, `port` as a number, `database`, `username`, `password`, `ssl_mode` as an
object, `replication_method` as an object, `schemas` as a list). A platform names one file
per operation, the `write` file only when the platform sets `write: true`. The `write` entry
is derived only for such a platform, as `<platform>/write`, and only the executor runs it
(`docs/design/executor.md`); `/acquire` never names it.

**The golden records.** The both-paths agreement test (`adapters/agreement`) fetches one row
of the World sample database (`ghusta/postgres-world-db:2.15.1`, `city` where `id = 1`), and
one row of a table it adds holding 2^53 + 1, through both operations and holds the facts each
yields to byte identity under the rule the design note states: the history path takes the connector's record, the live path asks the
database to render the row as JSON and hand it over as text (`SELECT to_jsonb(c)::text …`),
so that the typing on both sides is Postgres's own and not a driver's. A plain `SELECT`
through this server renders the `bigint` columns as strings (the Node driver's default for
64-bit integers), and the same row then differs from the connector's on `id` and
`population`; a `to_jsonb` column without the cast is parsed into JavaScript numbers, and an
integer past 2^53 comes back rounded, where the connector and the text-carried rendering both
keep the spelling. Both captures are kept as fixtures, as the reasons for the rule.

ELv2 (the Elastic License 2.0) forbids providing the connector to third parties as a
managed service; an operator hosting the engine for others should read it before enabling
the history operation, which is why the licence is in the binding at all.
