# The both-paths agreement

[ADR-0001](../adr/0001-one-engine-four-processes.md) point 4 promises that a record reached
through the engine's two shapes — history through a connector, live through an MCP server —
derives to byte-identical facts, and that a golden record per platform is checked both ways.
This note states the rule by which a shape's envelope yields a record's facts, records what
the first golden record showed, and describes the test that holds the shipped binding to it
(`adapters/agreement`). It is a design note; the binding (`catalog/`) and the test govern
the artifacts and the words here follow them.

## Why the agreement matters

The two shapes exist because each is good at one thing: the connector protocol pages and
bookmarks, so history comes through it; a vendor maintains its MCP server, so live reads and
writes go through that. A pack, though, sees facts, not shapes. If the same row yields
different facts by the door it came through, a rule behaves differently on history than at
decision time and nothing in the ledgers says so: the receipts are honest about the bytes,
and the bytes differ. The agreement is what lets a replay against history stand for what a
live evaluation would do.

## The rule

Facts are the canonical form (`SPEC.md` §1.1, numbers past the canon domain carried as
text) of one JSON object per record, keyed by column. Each shape yields that object thus:

- **history** (`airbyte`): the envelope's result is the page's records as the connector
  emitted them, each already canonical; the record is the one whose key member equals the
  requested key, and its facts are that record's canonical bytes.
- **live** (`mcp`, DBHub's `execute_sql`): the query asks the database to render the row as
  JSON — `SELECT to_jsonb(c) AS record FROM <table> c WHERE <key>` — and the envelope's
  result is the server's answer, one text content item holding JSON with one statement, one
  row, one member `record`; the facts are that object's canonical bytes.

The rule's one substantive choice is `to_jsonb`. A plain `SELECT` through the same server
renders every `bigint` as a string, because the Node driver the server uses hands 64-bit
integers back as text by default, and the World database's `id` and `population` then differ
from the connector's record on exactly those two members while every other member agrees.
Asking Postgres to render the row makes the typing on the live side the database's own — the
same authority the connector's record derives from — and the two agree byte for byte. The
plain-`SELECT` capture is kept as a fixture (`live-driver-typed.json`) with a test that holds
it to differing on those two members and no other, so the rule's reason stays pinned to
evidence and the day a driver stops doing this is noticed.

## The golden record

The postgres platform's golden record is the World sample database
(`ghusta/postgres-world-db:2.15.1`, pinned by index digest in the test), table `city`, `id = 1`:

```json
{"country_code":"AFG","district":"Kabol","id":1,"local_name":null,"name":"Kabul","population":1780000}
```

Six members, five types the platform draws — `bigint`, `text`, `character(3)`, a null —
and no float, no timestamp, no array: the least room for two paths to disagree on rendering,
which is what a first golden record should have. The row was fetched through both shapes as
the engine runs them, by the two adapter binaries the adapters module builds, against the
database in the container runtime, under a role Postgres holds to reading; the envelopes are
the fixtures under `adapters/agreement/testdata/postgres/`, each carrying the adapter's
digest, which the test holds to the shipped binding's pins.

## What the first capture found, besides the rule

- **The Airbyte-shaped adapter configured an unpageable read.** It chose incremental sync
  whenever the connector offered it and named a cursor only when the connector offered a
  default one; `city` has no timestamp or serial column, the connector offers incremental
  sync for it all the same, and configured incremental without a cursor it refuses the read
  outright. The adapter now chooses incremental only when a default cursor exists, and reads
  full refresh otherwise; the connector's resumable full refresh still checkpoints, so the
  page is still bookmarked. A unit test holds the choice.
- **The previous live server could not serve the rule at all.** `crystaldba/postgres-mcp`
  answers `execute_sql` with Python's rendering of a list of dictionaries — single quotes,
  `None`, `Decimal(...)` — which no published rule turns back into facts. The binding now
  names DBHub (`bytebase/dbhub`), which answers JSON text and connects to the database as it
  starts, so the handshake itself establishes the connection and the binding carries no
  probe (`catalog/README.md` says how each of these was verified).
- **Read-only moved from the server to the role.** DBHub's own read-only switch is a
  `dbhub.toml` entry the server reads from a path; a binding hands a server an environment
  and arguments and never a file, so what holds the live operation to reading is the role
  the operator names in the connection string: `SELECT` alone, and
  `default_transaction_read_only = on` set on the role, which a connection string cannot
  undo (a connection-string `options=` setting was tried first and the driver did not carry
  it). The fresh-fetch test writes through that role and requires Postgres's refusal.

## The test

`adapters/agreement`:

- **Offline, always**: the fixtures derive to the same facts through both rules, and to the
  golden record; the fixtures were captured under the artifacts the binding pins (their
  adapter digests are compared with `catalog/postgres.json`); the driver-typed capture
  differs from the connector's record on `id` and `population` and on nothing else; the
  derivations refuse an absent key, an ambiguous key, an answer without the rendered
  record, an error result and an envelope without an adapter digest.
- **With a container runtime** (`AGREEMENT_RUNTIME=docker`, the CI job "both paths agree"):
  a World database is started from the pinned image, the reading role is created, the
  golden record is fetched both ways through the adapters as the engine runs them, a write
  through the reading role is required to fail as Postgres's refusal, and the fresh facts
  are held to each other, to the golden record, and to the fixtures' facts.

## What this establishes, and what it does not

It establishes ADR-0001's point 4 for one platform and one record: under the stated rule the
two shapes agree, and the rule's one choice is justified by a kept counterexample. It does
not establish agreement for types the golden record lacks — floats, timestamps, arrays,
composite types — each of which is a rendering question the connector and `to_jsonb` may
answer differently; the second golden record should be a Sakila row, which has them. It is
not the two-back-end bar of the spec's RFC 0003, which asks two runtimes with different back
ends to resolve the same *references*; these adapters acquire bytes for operator-named
sources and resolve no pack reference, as [RFC 0014](https://github.com/Judgment-Pack/judgment-pack-spec/blob/main/rfcs/0014-lineage-record-and-action-binding.md)
Unresolved 5 already says, and nothing here changes that.
