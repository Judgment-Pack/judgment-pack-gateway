-- The PostgreSQL storage kind, schema version 1: the store contract's spaces
-- (docs/design/store-contract.md, docs/adr/0031-a-second-storage-kind-on-postgresql.md,
-- docs/postgresql-store.md).
--
-- `gateway store-migrate` runs this file once, as the migration login after
-- SET ROLE to the owner role, in the transaction that records its digest in
-- gateway.schema_migrations. Every object it makes is the owner role's. It
-- creates no role, grants nothing (grants.sql does, to the run-time role
-- named), defines no function, and sets no role or database setting.
--
-- Rows of the tables that carry a column `scope` are each of one scope
-- identifier, or of none (the empty string: an identifier is never empty).
-- Row-level security, enabled and forced, admits to a transaction only the
-- rows of the scope its setting `gateway.scope` names, set per transaction
-- by the kind; a transaction that set none sees and writes only rows of no
-- scope. No table here holds a sequence or an identity column: nothing is
-- counted across scopes.

CREATE SCHEMA gateway;
REVOKE ALL ON SCHEMA gateway FROM PUBLIC;

-- The migrations applied, each by its file's digest.
CREATE TABLE gateway.schema_migrations (
    version integer PRIMARY KEY CHECK (version >= 1),
    name    text COLLATE "C" NOT NULL,
    digest  text COLLATE "C" NOT NULL CHECK (digest ~ '^sha256:[0-9a-f]{64}$')
);

-- Immutable content-addressed blobs: the retained artifacts. Never changed
-- once made; the run-time role holds no UPDATE or DELETE on it.
CREATE TABLE gateway.blobs (
    scope text COLLATE "C" NOT NULL CHECK (octet_length(scope) <= 128),
    name  text COLLATE "C" NOT NULL CHECK (name ~ '^sha256:[0-9a-f]{64}$'),
    data  bytea NOT NULL,
    PRIMARY KEY (scope, name)
);

-- Series of indexed entries: the sessions and their receipts. A session's
-- name is one across scopes, as the verifier's layout names it (SPEC.md
-- §1.3), and the session is of the scope that made it; its entries are of
-- that scope. Neither is changed once made.
CREATE TABLE gateway.series (
    scope text COLLATE "C" NOT NULL CHECK (octet_length(scope) <= 128),
    name  text COLLATE "C" NOT NULL CHECK (octet_length(name) BETWEEN 1 AND 255),
    PRIMARY KEY (name),
    UNIQUE (scope, name)
);

CREATE TABLE gateway.entries (
    scope  text COLLATE "C" NOT NULL,
    series text COLLATE "C" NOT NULL,
    name   text COLLATE "C" NOT NULL CHECK (octet_length(name) BETWEEN 1 AND 255),
    data   bytea NOT NULL,
    PRIMARY KEY (series, name),
    FOREIGN KEY (scope, series) REFERENCES gateway.series (scope, name)
);

-- The append-only log: the seal registry, one chain across scopes. It
-- carries no scope identifier. A record is the bytes one append wrote, at
-- the offset the log had reached; records are never changed or removed.
CREATE TABLE gateway.logs (
    name text COLLATE "C" PRIMARY KEY CHECK (name IN ('registry'))
);

CREATE TABLE gateway.log_records (
    log   text COLLATE "C" NOT NULL REFERENCES gateway.logs (name),
    start bigint NOT NULL CHECK (start >= 0),
    data  bytea NOT NULL CHECK (octet_length(data) > 0),
    stop  bigint GENERATED ALWAYS AS (start + octet_length(data)) STORED,
    PRIMARY KEY (log, start)
);

-- Versioned documents, replaced by compare-and-set against a revision; a
-- lease is a document, of the scope that took it.
CREATE TABLE gateway.documents (
    scope    text COLLATE "C" NOT NULL CHECK (octet_length(scope) <= 128),
    name     text COLLATE "C" NOT NULL CHECK (octet_length(name) BETWEEN 1 AND 255),
    revision text COLLATE "C" NOT NULL CHECK (revision ~ '^[0-9a-f]{32}$'),
    data     bytea NOT NULL,
    PRIMARY KEY (scope, name)
);

-- Secrets, each made once and never replaced. No engine configuration
-- keeps one here in this version: the signing seed stays where its
-- configuration names it.
CREATE TABLE gateway.secrets (
    name  text COLLATE "C" PRIMARY KEY CHECK (octet_length(name) BETWEEN 1 AND 255),
    value bytea NOT NULL
);

ALTER TABLE gateway.blobs ENABLE ROW LEVEL SECURITY;
ALTER TABLE gateway.blobs FORCE ROW LEVEL SECURITY;
CREATE POLICY scope_of_the_transaction ON gateway.blobs
    USING (scope = COALESCE(pg_catalog.current_setting('gateway.scope', true), ''))
    WITH CHECK (scope = COALESCE(pg_catalog.current_setting('gateway.scope', true), ''));

ALTER TABLE gateway.series ENABLE ROW LEVEL SECURITY;
ALTER TABLE gateway.series FORCE ROW LEVEL SECURITY;
CREATE POLICY scope_of_the_transaction ON gateway.series
    USING (scope = COALESCE(pg_catalog.current_setting('gateway.scope', true), ''))
    WITH CHECK (scope = COALESCE(pg_catalog.current_setting('gateway.scope', true), ''));

ALTER TABLE gateway.entries ENABLE ROW LEVEL SECURITY;
ALTER TABLE gateway.entries FORCE ROW LEVEL SECURITY;
CREATE POLICY scope_of_the_transaction ON gateway.entries
    USING (scope = COALESCE(pg_catalog.current_setting('gateway.scope', true), ''))
    WITH CHECK (scope = COALESCE(pg_catalog.current_setting('gateway.scope', true), ''));

ALTER TABLE gateway.documents ENABLE ROW LEVEL SECURITY;
ALTER TABLE gateway.documents FORCE ROW LEVEL SECURITY;
CREATE POLICY scope_of_the_transaction ON gateway.documents
    USING (scope = COALESCE(pg_catalog.current_setting('gateway.scope', true), ''))
    WITH CHECK (scope = COALESCE(pg_catalog.current_setting('gateway.scope', true), ''));
