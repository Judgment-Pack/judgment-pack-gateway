-- The PostgreSQL storage kind, schema version 2: the start lease
-- (docs/postgresql-store.md, "One instance per database";
-- docs/adr/0032-a-configuration-names-its-storage-kind.md).
--
-- One row at most: the gateway instance that serves the database, by an
-- identifier it draws at its start, and when its lease expires by the
-- database's clock. An instance takes the row only where it is not there or
-- has expired, renews it while it runs, and removes it when it stops
-- cleanly; every write transaction it makes first holds the row, unexpired
-- and its own, FOR KEY SHARE, so a write after the lease is gone fails.
-- The holder is unique, a key, so a takeover (which changes it) waits for
-- a write that holds the row to end, while a renewal (which changes only
-- the expiry) does not. The row is of no scope and the table carries
-- none, so no row security applies.
-- The run-time role is given SELECT, INSERT, UPDATE and DELETE on it by
-- grants.sql; it holds nothing else that changes rows in place.

CREATE TABLE gateway.start_lease (
    singleton boolean PRIMARY KEY DEFAULT true CHECK (singleton),
    holder    text COLLATE "C" NOT NULL UNIQUE CHECK (holder ~ '^instance-[0-9a-f]{32}$'),
    expires   timestamptz NOT NULL
);
