-- The PostgreSQL storage kind, schema version 8: the key history a store
-- rotation carried into the database (SPEC.md §3e; ADR-0052;
-- docs/postgresql-store.md, "Rotating the store").
--
-- One row at most, written by gateway store rotate as the owner, in the
-- migration's transaction that makes the registry holding the store
-- continuation alone, so the two commit together or not at all: `history`
-- is the exact bytes of the old store's answer to GET /publickey/history,
-- whose lowercase hexadecimal SHA-256 the continuation names as its
-- keyHistoryDigest. Every instance on the database reads the row to answer
-- the key history. grants.sql gives the run-time role SELECT on the table
-- alone: the gateway never writes, changes or removes the row, and a second
-- one is refused by the key, which holds true alone.

CREATE TABLE gateway.key_history (
    singleton boolean PRIMARY KEY DEFAULT true CHECK (singleton),
    history   bytea NOT NULL CHECK (pg_catalog.octet_length(history) > 0)
);
