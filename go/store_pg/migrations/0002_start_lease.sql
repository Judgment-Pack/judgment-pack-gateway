-- The PostgreSQL storage kind, schema version 2: the start lease
-- (docs/postgresql-store.md, "One instance per database";
-- docs/adr/0032-a-configuration-names-its-storage-kind.md).
--
-- One row at most: the gateway instance that serves the database, by an
-- identifier it draws at its start, when it last renewed its lease and
-- when the lease expires, both by the database's clock. An instance takes
-- the row only where it is not there or has expired, renews it while it
-- runs, and expires it when it stops cleanly; the row is never removed.
-- Every write transaction the instance makes holds the row, its own and
-- unexpired with room to spare, FOR KEY SHARE as its last statement before
-- its commit, so no write commits beside another instance's. The holder is
-- unique, a key, so a takeover (which changes it) is refused at once while
-- a write holds the row, and a renewal (which changes only the times) is
-- not. A lease runs at most ten minutes from its renewal, so no value
-- (infinity, say) holds the database past that. The row is of no scope and
-- the table carries none, so no row security applies.
-- The run-time role is given SELECT, INSERT and UPDATE on it by
-- grants.sql, and not DELETE.

CREATE TABLE gateway.start_lease (
    singleton boolean PRIMARY KEY DEFAULT true CHECK (singleton),
    holder    text COLLATE "C" NOT NULL UNIQUE CHECK (holder ~ '^instance-[0-9a-f]{32}$'),
    renewed   timestamptz NOT NULL,
    expires   timestamptz NOT NULL,
    CHECK (pg_catalog.isfinite(renewed) AND pg_catalog.isfinite(expires)
        AND expires >= renewed AND expires <= renewed + interval '10 minutes')
);
