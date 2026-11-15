-- The PostgreSQL storage kind, schema version 4: the seal registry's records
-- held to one chain by the schema (docs/postgresql-store.md, "What the
-- run-time login may do"; docs/adr/0031-a-second-storage-kind-on-postgresql.md,
-- decision 4; issue #440).
--
-- An append takes the log's lock and inserts its record at the log's end,
-- but the run-time login may insert a record of its own without the lock.
-- Before this version the primary key refused a second record at one start
-- alone, so a record that overlapped committed bytes, or left a gap, could
-- be inserted, and the log could then no longer be read whole.
--
-- From this version no two records of the log stop at one offset, and each
-- record starts where another stops, but the record at offset 0, which
-- follows none: `follows` is its start, or NULL at 0, and a foreign key is
-- not checked on a NULL column. With the primary key on (log, start), every
-- record then follows the one before it from offset 0, with no gap and no
-- overlap, whoever writes it, and a record is admitted only at the log's
-- end.
--
-- Adding the column computes it for every record there, and the two
-- constraints are checked on them: a store whose log is not one chain is
-- refused this migration, and with it nothing is changed. The log carries
-- no scope, so no row security applies to it. No other table is changed,
-- and the run-time role's privileges are those grants.sql gives.

ALTER TABLE gateway.log_records
    ADD COLUMN follows bigint GENERATED ALWAYS AS (NULLIF(start, 0)) STORED,
    ADD CONSTRAINT log_records_log_stop_key UNIQUE (log, stop),
    ADD CONSTRAINT log_records_log_follows_fkey FOREIGN KEY (log, follows) REFERENCES gateway.log_records (log, stop);
