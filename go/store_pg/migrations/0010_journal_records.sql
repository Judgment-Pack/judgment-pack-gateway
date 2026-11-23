-- The PostgreSQL storage kind, schema version 10: the store's journals
-- (docs/adr/0056-an-operator-journal-of-signed-chained-entries-in-the-store.md,
-- "Amendment (2026-11-22)", A; issue #543).
--
-- A journal is one chain of signed entries, each a line of canonical JSON
-- without its 0x0A. The table holds every journal, a row for each entry,
-- keyed by the journal's name and the entry's ordinal. The registry stays
-- the one log of gateway.logs, whose CHECK is not changed.
--
-- The chain rule is the log's (schema version 4), keyed by ordinal where the
-- log is keyed by offset: the primary key admits one row at an ordinal, and
-- each row but the one at ordinal 0 follows, through the foreign key, the
-- row at the ordinal before it. The row at 0 follows none: `follows` is
-- NULL there, and a foreign key is not checked on a NULL column. So each
-- journal is one chain from ordinal 0, with no gap and no second row at an
-- ordinal, whoever writes it, and a row is admitted only at its end.
--
-- A journal's name is 1 to 32 characters, each a lowercase letter or `-`,
-- the envelope's rule. A row's line is 1 to 4096 bytes with no 0x0A, the
-- envelope's bound. The signatures and the `previous` digests are not the
-- schema's to hold: gateway verify holds them. The table carries no scope,
-- so no row security applies to it. The run-time role's privileges are
-- those grants.sql gives: SELECT and INSERT, and no UPDATE, DELETE or
-- TRUNCATE. No other table is changed.

CREATE TABLE gateway.journal_records (
    journal text COLLATE "C" NOT NULL CHECK (journal ~ '^[a-z-]{1,32}$'),
    ordinal bigint NOT NULL CHECK (ordinal >= 0),
    line    bytea NOT NULL
            CHECK (octet_length(line) BETWEEN 1 AND 4096 AND position('\x0a'::bytea IN line) = 0),
    follows bigint GENERATED ALWAYS AS (NULLIF(ordinal, 0) - 1) STORED,
    PRIMARY KEY (journal, ordinal),
    FOREIGN KEY (journal, follows) REFERENCES gateway.journal_records (journal, ordinal)
);
