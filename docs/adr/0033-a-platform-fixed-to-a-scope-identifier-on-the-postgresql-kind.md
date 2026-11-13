---
status: proposed
date: 2026-11-13
deciders: maintainer
---

# A platform fixed to a scope identifier is served on the PostgreSQL kind, each scope's rows kept apart by the database and read across scopes one scope at a time

## Context and problem statement

ADR-0026 fixes a platform to a scope identifier, and its receipts carry the identifier. ADR-0031
gave the PostgreSQL kind a view of each scope identifier, its rows kept apart by row security, and
ADR-0032 made the kind selectable but refused a platform's `scope` beside it, since the gateway
served the kind as the view of no scope alone (issue #430). Three things stood in the way: the
gateway did not open a scope's view for a scoped source; what must reach every scope's rows (the
export, and the start's question whether the store holds a session) could reach only one; and a
session could be begun by one scope and continued by another, whose stamp the kind cannot make,
since a session's name is one across scopes and a view sees only its own scope's series.

## Decision drivers

- No second meaning of scope: the identifier the receipt carries (ADR-0026) is the one the rows
  hold, through the view the conformance suite already runs (`inScope`).
- The database holds one scope's rows apart from another's (issue #430, condition f): every
  statement of the gateway is of one scope, set for its transaction alone, and the owner is held
  to the same policy.
- No new role for the operator to make, no policy other than the scope's, no function, trigger
  or view in the schema.
- An export of the kind is byte for byte what the filesystem kind exports of the same receipts,
  so the verifier reads it unchanged.
- A configuration without `storage`, and the filesystem kind's bytes, are unchanged.

## Considered options

- Reaching every scope's rows: one transaction whose statements each set one scope recorded in a
  table of no scope (chosen); an export login with a policy admitting every scope (ADR-0031's
  recommendation); a function that runs as the owner.
- Knowing which scopes hold rows: a record the start writes (chosen); the configuration's scopes
  at the time of the export; a scan of the rows by a role past row security.
- A session held by another scope: refused before the source runs (chosen); the stamp failing
  after the source ran.

## Decision outcome

1. **A platform's `scope` is taken with `storage`.** The start, once it holds the start lease,
   opens the kind's view of each scope identifier a source is fixed to, and a scoped source
   retains its payload and stamps its receipt through that view, so their rows hold `scope:` and
   the identifier; a source of no scope writes rows of `none` as before. A view is a copy of the
   kind made after the lease is taken, so its writes are fenced on the lease as the kind's are.

2. **Schema version 3 records the scope identifiers** in `gateway.scope_identifiers`: one row of
   no scope (its `scope` column holds `none` alone) for each identifier a start opened a view for,
   written by that start, in a transaction of no scope, before the view writes anything; an
   identifier recorded already is kept as it is. The run-time role holds SELECT and INSERT on it
   alone; the table has row security enabled and forced and the scope's one policy, so a
   transaction of a scope identifier reads no identifier from it, another scope's or its own. The
   migration adds the table and copies nothing: a store at schema version 2 holds rows of no scope
   alone, since `scope` beside `storage` was refused until this version. No trigger, function or
   view is added.

3. **Every scope's rows are read one scope at a time.** The export, the start's question whether
   the store holds a session before it makes an empty registry, and an acquisition's or a seal's
   question whether a session of its name is held in some scope run as the run-time login in one
   transaction: it reads the record in the transaction's setting of `none`, then for each
   identifier sets `gateway.scope` with `set_config(…, true)` and makes that scope's statements.
   An acquisition's or a seal's question asks its own scope first (the source's, or no scope for a
   seal), in that transaction's own setting, and reads the record and the other scopes only for a
   name its scope does not hold (#446): a session of its own scope costs the same statements
   however many identifiers are recorded, and a new session's still asks every scope, two
   statements each (docs/postgresql-store.md, "Scope identifiers", gives the measured cost).
   The export's transaction is at REPEATABLE READ, so every scope is read in one snapshot. No
   statement is admitted to the rows of two scopes at once, and no login, policy or function
   admits every scope. An export reads every scope recorded, whatever the configuration names now.

4. **A session's receipts are of one scope on this kind.** An acquisition into a session that
   holds the receipts of another scope, or of none, in this process or left in the store, is
   refused `400` before its source runs, by one sentence that names neither scope. The filesystem
   kind keeps one layout for every scope and is unchanged.

5. **The registry is one chain, of no scope.** Its tables carry no scope column, and every view
   reads it whole. Its lines are seals (SPEC.md §3, §3c): a session's id, its count, its time,
   the key's identifier and a signature. None carries a receipt, a payload, an argument or a scope
   identifier, so no line carries scoped data; a gateway of one scope reads the ids and counts of
   every scope's sealed sessions, and `gateway verify` reads the chain from an export, which holds
   every line. When a scope's rows are removed (condition h, its own issue) its seals stay: the chain
   needs every line, and a seal holds none of the scope's rows. Whether a seal names its scope is
   issue #442; this change adds no member to a seal or a receipt.

6. **The export's layout is the filesystem kind's.** The cut is every scope's rows: a session once,
   under its name, which the series' key holds to one scope; a payload two scopes hold alike once,
   its bytes read from each and compared, and refused (`unreadable`) where they differ, as is one
   series' name held by two scopes; the log and the documents of no scope. The kind keeps no
   removal record (`gateway remove-artifact` stays refused).

7. **Versions.** No engine version is added, by the rule ADR-0024 applied (its decision 7): no
   member is added, and every gateway before this one refuses `scope` beside `storage` by name,
   so it refuses such a file rather than reading it otherwise. The schema version is 3; a gateway of this version refuses a database at version 2
   until `gateway store migrate` runs, and a gateway of version 2 refuses one at version 3.
   SPEC.md, the receipt, the seal and the corpus are unchanged.

### Consequences

- Good, because the database holds every statement of the gateway to one scope, the owner too,
  with the one policy of every scoped table, and nothing the operator makes is added.
- Good, because the export of scoped stores is held byte for byte to the filesystem kind's, by a
  service's run and by every corpus store vector spread across scope identifiers.
- Bad, because row security keyed on a setting is still no boundary against the run-time login
  itself (ADR-0031, "Consequences"): that login reads the record and may set any scope.
- Bad, because the registry discloses across scopes the ids and counts of sealed sessions; session
  ids are the caller's, so a caller should give them no meaning another scope must not learn.
- Bad, because a session's receipts are of one scope on this kind and of any on the filesystem
  kind, until #442 decides it for both.
- Bad, because an identifier, once recorded, stays: a scope dropped from the configuration is still
  exported, as its rows are still held, and only the removal of its rows (condition h) may remove
  it.
- Revisit when a login per scope identifier is chosen (ADR-0031, "More information"), when #442
  binds sessions or seals to a scope, or when condition h removes a scope's rows.

## More information

- Amends ADR-0031: decision 10's "a view of the kind sees one scope's sessions, never every
  scope's" for the start's question, and the open decisions "An export across scopes" and "The
  registry's start with scopes", each answered by decision 3 here, by neither option listed there.
- Amends ADR-0032, decision 2: a platform's `scope` is no longer refused.
- `docs/postgresql-store.md`, "Scope identifiers", is the operator's page; `go/store_pg_scopes.go`
  holds the record and the reads across scopes; `go/store_pg_scopes_test.go` and the corpus test
  in `go/store_pg_test.go` hold them on a server.
