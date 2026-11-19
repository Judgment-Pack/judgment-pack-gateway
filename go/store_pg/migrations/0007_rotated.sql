-- The PostgreSQL storage kind, schema version 7: the mark of a store rotated
-- away from (SPEC.md §3d; docs/postgresql-store.md, "Rotating the store").
--
-- One row at most, written by gateway store rotate as the run-time login,
-- under the start lease and fenced as every write of the gateway is, once
-- the new database's registry, the continuation alone, is committed:
-- `continuation` is the lowercase hexadecimal SHA-256 of that line without
-- its line feed, and `rotated_at` the time the row was written. A start
-- that finds the row refuses by name before it takes the lease, and so does
-- every command that takes it. grants.sql gives the run-time role SELECT
-- and INSERT on the table alone: the row is never changed or removed, and a
-- second one is refused by the key, which holds true alone.

CREATE TABLE gateway.rotated (
    singleton    boolean PRIMARY KEY DEFAULT true CHECK (singleton),
    continuation text COLLATE "C" NOT NULL CHECK (continuation ~ '^[0-9a-f]{64}$'),
    rotated_at   timestamptz NOT NULL CHECK (pg_catalog.isfinite(rotated_at))
);
