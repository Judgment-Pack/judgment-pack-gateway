-- The PostgreSQL storage kind, schema version 12: the key history each
-- instance answers (ADR-0062; docs/postgresql-store.md, "Several instances
-- on one database").
--
-- Each row of the start lease records the version of the key history its
-- instance answers at /publickey/history (ADR-0055 §4): "2" where its
-- engine configuration sets keyHistoryVersion "2" or the history carried
-- into the database is of version "2", and otherwise "1". The instances
-- serving one database at once answer one version: an instance answering
-- one is refused beside one answering the other, either way round
-- (admitBeside). A row of an earlier version reads "1", the version every
-- instance before engine version 42 answers.

ALTER TABLE gateway.start_lease ADD COLUMN key_history text COLLATE "C" NOT NULL DEFAULT '1'
    CHECK (key_history IN ('1', '2'));
