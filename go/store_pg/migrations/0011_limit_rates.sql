-- The PostgreSQL storage kind, schema version 11: the shared request rate
-- of each limited scope, counted together by the instances serving one
-- database (limits.shared, engineVersion 51;
-- docs/adr/0061-request-limits-counted-together-by-the-instances-of-one-database.md;
-- issue #593).
--
-- A row is one scope's bucket: its theoretical arrival time, in whole
-- microseconds of the database's clock since the epoch. An instance leases
-- a batch of requests from it by one statement that moves the time on by
-- the batch (sharedRateLease, limits_shared.go); nothing else reads or
-- writes it. A row carries the scope it counts, as the store's scoped
-- tables do, so row security is enabled and forced and the scope's policy
-- holds it: a transaction reads and writes the row of its own scope alone.
-- The run-time role's privileges are those grants.sql gives: SELECT, INSERT
-- and UPDATE, and no DELETE or TRUNCATE. gateway store remove-scope removes
-- a scope's row with its other rows. No other table is changed.

CREATE TABLE gateway.limit_rates (
    scope text COLLATE "C" NOT NULL CHECK (scope = 'none' OR (substr(scope, 1, 6) = 'scope:' AND octet_length(scope) BETWEEN 7 AND 134)),
    tat   bigint NOT NULL,
    PRIMARY KEY (scope)
);

ALTER TABLE gateway.limit_rates ENABLE ROW LEVEL SECURITY;
ALTER TABLE gateway.limit_rates FORCE ROW LEVEL SECURITY;
CREATE POLICY scope_of_the_transaction ON gateway.limit_rates
    USING (scope = pg_catalog.current_setting('gateway.scope', true))
    WITH CHECK (scope = pg_catalog.current_setting('gateway.scope', true));
