-- The PostgreSQL storage kind, schema version 3: the scope identifiers the
-- kind keeps rows of (docs/postgresql-store.md, "Scope identifiers";
-- docs/adr/0033-a-platform-fixed-to-a-scope-identifier-on-the-postgresql-kind.md).
--
-- One row for each scope identifier a gateway has opened a view of the kind
-- for: made by the gateway's start, before any row of that scope is
-- written, and never changed or removed (grants.sql gives the run-time role
-- SELECT and INSERT on it alone). An export reads it to reach the rows of
-- every scope, one scope at a time in one snapshot, and the start reads it
-- to ask every scope whether it holds a session.
--
-- The identifier is held as the scoped tables hold a scope: 'scope:' and
-- the identifier. The row itself is of no scope: its column `scope` holds
-- 'none' alone, so the table's row security, the same policy as every
-- scoped table's, admits its rows to a transaction that sets no scope's
-- 'none', and to no transaction of a scope identifier: a scope learns no
-- other scope's identifier from it.
--
-- A store at schema version 2 holds rows of no scope alone: a configuration
-- that fixed a platform to a scope identifier was refused with this kind
-- before this version. Nothing is copied into the table, and no row of
-- another table is read or changed.

CREATE TABLE gateway.scope_identifiers (
    scope      text COLLATE "C" NOT NULL CHECK (scope = 'none'),
    identifier text COLLATE "C" PRIMARY KEY CHECK (substr(identifier, 1, 6) = 'scope:' AND octet_length(identifier) BETWEEN 7 AND 134)
);

ALTER TABLE gateway.scope_identifiers ENABLE ROW LEVEL SECURITY;
ALTER TABLE gateway.scope_identifiers FORCE ROW LEVEL SECURITY;
CREATE POLICY scope_of_the_transaction ON gateway.scope_identifiers
    USING (scope = pg_catalog.current_setting('gateway.scope', true))
    WITH CHECK (scope = pg_catalog.current_setting('gateway.scope', true));
