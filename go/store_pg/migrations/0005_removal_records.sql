-- The PostgreSQL storage kind, schema version 5: the removal records
-- (SPEC.md §1.3a, "A removed session"; docs/postgresql-store.md, "Removing
-- one scope identifier's rows";
-- docs/adr/0034-removing-one-scope-identifiers-records.md).
--
-- One row for each line of the store's removal file, as a store of the
-- filesystem kind holds it in artifact-removals.jsonl: the signed records
-- gateway store remove-scope appends, as the migration login acting as the
-- owner role, in the transaction that removes a scope identifier's rows and
-- its row of gateway.scope_identifiers. `ordinal` is a line's place in the
-- file, from 0, and `line` its bytes without the line feed, within the
-- file's bound. A row is never changed or removed; grants.sql gives the
-- run-time role SELECT on the table alone, by which an export writes the
-- file.
--
-- The records name scope identifiers and sessions, so a row is of no scope,
-- as a row of gateway.scope_identifiers is: its column `scope` holds 'none'
-- alone, and the table's row security, the same policy as every scoped
-- table's, admits its rows to a transaction that sets no scope's 'none',
-- and to no transaction of a scope identifier. Nothing is copied into the
-- table, and no row of another table is read or changed.

CREATE TABLE gateway.removal_records (
    scope   text COLLATE "C" NOT NULL CHECK (scope = 'none'),
    ordinal bigint PRIMARY KEY CHECK (ordinal >= 0),
    line    bytea NOT NULL CHECK (octet_length(line) BETWEEN 1 AND 4095)
);

ALTER TABLE gateway.removal_records ENABLE ROW LEVEL SECURITY;
ALTER TABLE gateway.removal_records FORCE ROW LEVEL SECURITY;
CREATE POLICY scope_of_the_transaction ON gateway.removal_records
    USING (scope = pg_catalog.current_setting('gateway.scope', true))
    WITH CHECK (scope = pg_catalog.current_setting('gateway.scope', true));
