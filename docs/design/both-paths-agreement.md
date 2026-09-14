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
  JSON and to hand it over as text — `SELECT to_jsonb(c)::text AS record FROM <table> c WHERE
  <key>` — and the envelope's result is the server's answer, one text content item holding
  JSON with one statement, one row, one member `record` holding that text; the facts are the
  canonical bytes of the object the text holds.

Every object on the way — the tool result, the server's answer, its statement, its row — is
read by its members' exact names, each of its type, nothing unknown tolerated and a duplicate
refused, as the signer reads an envelope; the answer's echoed SQL must be the SQL the recorded
statement names; and the envelope itself is read as the signer reads it — in the canon domain,
no duplicate member anywhere, exactly §6's members in §1.2a's forms — before either derivation
reads it, with the statement, a JSON text inside a string the envelope's check does not look
into, checked for duplicates on its own.

The rule's one substantive choice is that the database renders the row, as text, and the
choice has two reasons, each pinned to a kept capture through the same server:

- A plain `SELECT` renders every `bigint` as a string, because the Node driver the server
  uses hands 64-bit integers back as text by default, and the World database's `id` and
  `population` then differ from the connector's record on exactly those two members while
  every other member agrees (`live-driver-typed.json`; the test holds the two rows to the
  same member names and to differing on those two and no other).
- A `to_jsonb` column without the cast is parsed by the driver into JavaScript numbers, so an
  integer past 2^53 comes back rounded: `9007199254740993` arrives as `9007199254740992`,
  where the same value carried as text keeps the database's spelling
  (`live-jsonb-past-2p53.json`, `live-text-past-2p53.json`). The canon carries an integer
  past its domain as a string of that spelling, and so does the connector's record of the
  same row (`history-past-2p53.json`), so the text path agrees where the JSON path cannot;
  that row is the platform's second golden record, below.

Asking Postgres to render the row, and carrying the rendering as text, makes the typing on the
live side the database's own — the same authority the connector's record derives from — with
no driver between. The fresh-fetch test runs both counterexamples again, so the day a driver
stops typing or stops rounding is noticed and the note revised.

What "byte-identical" means here is identity under the canon rule (`SPEC.md` §1.1): a number
the domain admits is spelled canonically, and one past it — a fraction, an exponent, an integer
past ±(2^53−1) — is carried as a string of its literal. The rule preserves spellings, not
types: a numeric `1.5` and a string `"1.5"` derive to the same facts, and `1.0` and `1e0` to
different ones. The golden record has no such member; the second golden record should.

## The golden records

The postgres platform's golden record is the World sample database
(`ghusta/postgres-world-db:2.15.1`, pinned by index digest in the test), table `city`, `id = 1`:

```json
{"country_code":"AFG","district":"Kabol","id":1,"local_name":null,"name":"Kabul","population":1780000}
```

Its second is a one-row table the test adds to that database, `past (n bigint)` holding
2^53 + 1, the first integer the canon domain does not admit:

```json
{"n":"9007199254740993"}
```

Both shapes carry the value as text spelled as the database spelled it, and agree.

Six members, five types the platform draws — `bigint`, `text`, `character(3)`, a null —
and no float, no timestamp, no array: the least room for two paths to disagree on rendering,
which is what a first golden record should have. The row was fetched through both shapes by
the two adapter binaries the adapters module builds, against the database in the container
runtime, under a role Postgres holds to reading; the envelopes are the fixtures under
`adapters/agreement/testdata/postgres/`, each carrying the adapter's digest and its
statement, which the test holds to the shipped binding's pins and to the query or stream the
rule names.

## What the first capture found, besides the rule

- **The Airbyte-shaped adapter configured an unreadable stream.** It chose incremental sync
  whenever the connector offered it and named a cursor only when the connector offered a
  default one; `city` has no timestamp or serial column, the connector offers incremental
  sync for it all the same, and configured incremental without a cursor it refuses the read
  outright. The adapter now chooses incremental when a cursor exists to bookmark by — one the
  connector names as the default, or one the connector defines itself
  (`source_defined_cursor`, which `source-postgres` sets in its xmin mode while naming no
  field) — and reads full refresh otherwise; the connector's resumable full refresh still
  checkpoints, so the page is still bookmarked. A unit test holds the choice over the
  serialized catalog, and the fresh-fetch test reads the stream in xmin mode and holds that
  read to incremental.
- **The previous live server could not serve the rule at all.** `crystaldba/postgres-mcp`
  answers `execute_sql` with Python's rendering of a list of dictionaries — single quotes,
  `None`, `Decimal(...)` — which no published rule turns back into facts. The binding now
  names DBHub (`bytebase/dbhub`), which answers JSON text and connects to the database as it
  starts, so the handshake itself establishes the connection and the binding carries no
  probe (`catalog/README.md` says how each of these was verified).
- **Read-only moved from the server to the role.** DBHub's own read-only switch is a
  `dbhub.toml` entry the server reads from a path; a binding hands a server an environment
  and arguments and never a file, so what holds the live operation to reading is the role
  the operator names in the connection string, and what holds it is the role's privileges:
  `SELECT` alone. `default_transaction_read_only = on`, set on the role, is a guard on top —
  a session may lift it (`BEGIN READ WRITE`), and a connection-string `options=` setting is
  not carried by the driver at all — not the enforcement. The fresh-fetch test writes through
  that role twice: a bare `UPDATE` is refused by the transaction default, and one inside
  `BEGIN READ WRITE` is refused by the privileges.

## The test

`adapters/agreement`:

- **Offline, always**: the fixtures derive to the same facts through both rules, and to the
  golden records; every fixture was captured under the artifact the binding pins for its
  operation (adapter digests compared with `catalog/postgres.json`) and records the statement
  the rule names (compared member by member); the driver-typed capture has the connector's
  member names and differs on `id` and `population` and on nothing else; the past-2^53
  captures derive as the note says; the derivations refuse an absent key, an ambiguous key, a
  history result that is not a page, an answer without the rendered record, a well-formed
  answer marked as an error, a `success` that is not `true` however its case is spelled, an
  answer to other SQL than the statement records, a duplicate member (under an escape too, in
  the result, the answer or the statement), an extra row member, a member of the wrong type
  (`messages`, `source_id`, `count`, `isError`, `structuredContent`), a count or statement
  count other than one, a record that is not an object, a number past the canon domain
  anywhere the signer would see it, and an envelope with a member §6 does not name, without
  one it does, with `page` other than `true` or `page` over a result that is not an array,
  with a `schema` that is not a digest, or with an `observedAt` that is not an instant of
  §6's form; and they accept what the server may add (`messages`) and what §6 permits (an
  empty adapter version).
- **With a container runtime** (`AGREEMENT_RUNTIME=docker`, the CI job "both paths agree"):
  a World database is started from the pinned image (its removal, volume included,
  registered before it starts; every deadline derived from the test's own with time left to
  remove it), the reading role and the `past` table are created, both golden records are
  fetched both ways through the adapter implementations — the package functions the binaries
  call, against real containers — the two writes above are required to fail as the tool's
  own refusals (an acquisition that also failed to stop its server is not one), the fresh
  facts are held to each other, to the golden records and to the fixtures', the fresh stream
  schema digest to the fixture's, the two counterexamples are fetched again and held to what
  the fixtures show, and the stream is read once more in xmin mode and held to incremental.

## What this establishes, and what it does not

It establishes ADR-0001's point 4 for one platform and two records: under the stated rule
the two shapes agree, at the canon domain's edge too, and the rule's one choice is justified
by two kept counterexamples. It does not establish agreement for types the golden records
lack — floats, numerics, timestamps, arrays, composite types — each of which is a rendering
question the connector and `to_jsonb` may answer differently; the next golden record should
be a Sakila row, which has several of these. It exercises the adapter implementations, not
the binaries' command lines or the signer's subprocess boundary, which the adapters' own
tests and the fixtures' provenance cover. It is
not the two-back-end bar of the spec's RFC 0003, which asks two runtimes with different back
ends to resolve the same *references*; these adapters acquire bytes for operator-named
sources and resolve no pack reference, as [RFC 0014](https://github.com/Judgment-Pack/judgment-pack-spec/blob/main/rfcs/0014-lineage-record-and-action-binding.md)
Unresolved 5 already says, and nothing here changes that.
