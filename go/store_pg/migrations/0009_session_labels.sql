-- The PostgreSQL storage kind, schema version 9: session labels (ADR-0051;
-- docs/postgresql-store.md, "Session labels").
--
-- From engine configuration version 39 the session a request names is a
-- label in its scope's namespace, mapped to a session id the gateway mints
-- on the label's first use there. A row of gateway.session_labels is that
-- mapping: the namespace, as gateway.series holds a scope ('none', or
-- 'scope:' and the identifier), the label, of the session id form, and the
-- series the gateway minted for it, 32 lowercase hexadecimal characters.
-- The primary key (scope, label) admits one session for a label in its
-- namespace, so two instances that record one label at once agree on one
-- id: each inserts ON CONFLICT (scope, label) DO NOTHING and reads the row
-- that is there. A minted id names one label alone (UNIQUE). The row is
-- written before the series' first entry, so it may name a series that is
-- not there yet; no key references gateway.series. Row security is the
-- policy of every scoped table: a transaction reads and writes the rows of
-- the scope it sets alone. grants.sql gives the run-time role SELECT and
-- INSERT on it alone: a label is never changed, and removed only by gateway
-- store remove-scope and gateway store retain, as the owner, with the
-- sessions they remove.
--
-- Each row of the start lease records whether its instance reads sessions by
-- label (labels: an engine configuration of version 39 or later). The
-- instances serving one database at once read them one way: an instance
-- with labels on is refused beside one with them off, either way round
-- (admitBeside). A row of an earlier version reads false.

CREATE TABLE gateway.session_labels (
    scope  text COLLATE "C" NOT NULL CHECK (scope = 'none' OR (substr(scope, 1, 6) = 'scope:' AND octet_length(scope) BETWEEN 7 AND 134)),
    label  text COLLATE "C" NOT NULL CHECK (label ~ '^[A-Za-z0-9._-]{1,128}$' AND label <> '.' AND label <> '..'),
    series text COLLATE "C" NOT NULL UNIQUE CHECK (series ~ '^[0-9a-f]{32}$'),
    PRIMARY KEY (scope, label)
);

ALTER TABLE gateway.session_labels ENABLE ROW LEVEL SECURITY;
ALTER TABLE gateway.session_labels FORCE ROW LEVEL SECURITY;
CREATE POLICY scope_of_the_transaction ON gateway.session_labels
    USING (scope = pg_catalog.current_setting('gateway.scope', true))
    WITH CHECK (scope = pg_catalog.current_setting('gateway.scope', true));

ALTER TABLE gateway.start_lease ADD COLUMN labels boolean NOT NULL DEFAULT false;
