-- The run-time role's privileges on the PostgreSQL storage kind's schema
-- (docs/postgresql-store.md, "What the run-time login may do").
--
-- The migration (migratePostgres) runs this file on every run, after the schema's
-- migrations, as the owner role, with the setting gateway.runtime_role
-- naming the run-time role for this transaction alone. It first takes back
-- what the owner granted that role, then grants exactly this, so a second
-- run ends where the first did. It creates no role and defines no function:
-- the block below is anonymous and leaves nothing behind.
--
-- Append-only by privilege: blobs, series, entries, logs, log_records,
-- secrets, the scope identifiers (schema version 3) and the series' holders
-- (schema version 6) are SELECT and INSERT alone. Documents alone are
-- replaced and removed, and the start lease's rows (schema version 2, a row
-- for each instance from version 6) are taken, renewed and released. The
-- removal records (schema version 5) are SELECT alone: the migration login,
-- acting as the owner, appends them, and the run-time role reads them for
-- an export. The key history a store rotation carried into the database
-- (schema version 8) is SELECT alone: the migration login, acting as the
-- owner, writes it with the registry's first line. The session labels
-- (schema version 9) are SELECT and INSERT: the migration login, acting as
-- the owner, removes them with the sessions they name. The start lease's
-- column labels (schema version 9) is written and read under the table's
-- grant. The journals (schema version 10) are SELECT and INSERT: the owner
-- appends the operator journal with the removals, and the run-time role
-- with its seals; no row of one is changed or removed. The shared request
-- rates (schema version 11) are SELECT, INSERT and UPDATE: an instance
-- makes a scope's row and leases batches from it; the migration login,
-- acting as the owner, removes it with the scope's other rows. Nothing is
-- TRUNCATE, REFERENCES, TRIGGER or DDL.

DO $grants$
DECLARE
    runtime text := pg_catalog.current_setting('gateway.runtime_role');
BEGIN
    EXECUTE pg_catalog.format('REVOKE ALL ON ALL TABLES IN SCHEMA gateway FROM %I', runtime);
    EXECUTE pg_catalog.format('REVOKE ALL ON SCHEMA gateway FROM %I', runtime);
    EXECUTE pg_catalog.format('GRANT USAGE ON SCHEMA gateway TO %I', runtime);
    EXECUTE pg_catalog.format('GRANT SELECT ON gateway.schema_migrations TO %I', runtime);
    EXECUTE pg_catalog.format('GRANT SELECT, INSERT ON gateway.blobs, gateway.series, gateway.entries, gateway.logs, gateway.log_records, gateway.secrets, gateway.scope_identifiers, gateway.series_holders, gateway.session_labels, gateway.journal_records TO %I', runtime);
    EXECUTE pg_catalog.format('GRANT SELECT, INSERT, UPDATE, DELETE ON gateway.documents TO %I', runtime);
    EXECUTE pg_catalog.format('GRANT SELECT, INSERT, UPDATE ON gateway.start_lease TO %I', runtime);
    EXECUTE pg_catalog.format('GRANT SELECT ON gateway.removal_records TO %I', runtime);
    EXECUTE pg_catalog.format('GRANT SELECT, INSERT ON gateway.rotated TO %I', runtime);
    EXECUTE pg_catalog.format('GRANT SELECT ON gateway.key_history TO %I', runtime);
    EXECUTE pg_catalog.format('GRANT SELECT, INSERT, UPDATE ON gateway.limit_rates TO %I', runtime);
END
$grants$;
