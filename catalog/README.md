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
| `live` | `crystaldba/postgres-mcp:0.3.0` with `--access-mode=restricted` | index digest `dbbd3468…b6e6b`, read from Docker Hub 2026-09-13 | MIT | `LICENSE` in the crystaldba/postgres-mcp repository |
| `write` | the same server with `--access-mode=unrestricted` | the same digest | MIT | the same |

The `live` entry names the server's read tools — schemas, objects, object details, SQL
under the server's restricted mode, query plans — and not its workload-analysis tools,
which read `pg_stat_statements` and are an operator's, not a decision's. The two operations
read different files: the server takes its connection string from the environment
variable `DATABASE_URI`, so the `live` credentials file is `{"DATABASE_URI":
"postgresql://…"}`, an object of strings; the connector's `history` file is the
configuration its `spec` describes (`host`, `port` as a number, `database`, `username`,
`password`, `ssl_mode` as an object, …). A platform names one file per operation. The `write` entry is stated and not derived: nothing runs it until an
executor exists.

ELv2 (the Elastic License 2.0) forbids providing the connector to third parties as a
managed service; an operator hosting the engine for others should read it before enabling
the history operation, which is why the licence is in the binding at all.
