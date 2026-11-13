-- The run-time role's privileges on the PostgreSQL storage kind's schema
-- (docs/postgresql-store.md, "What the run-time login may do").
--
-- `gateway store-migrate` runs this file on every run, after the schema's
-- migrations, as the owner role, with the setting gateway.runtime_role
-- naming the run-time role for this transaction alone. It first takes back
-- what the owner granted that role, then grants exactly this, so a second
-- run ends where the first did. It creates no role and defines no function:
-- the block below is anonymous and leaves nothing behind.
--
-- Append-only by privilege: blobs, series, entries, logs, log_records and
-- secrets are SELECT and INSERT alone. Documents alone are replaced and
-- removed. Nothing is TRUNCATE, REFERENCES, TRIGGER or DDL.

DO $grants$
DECLARE
    runtime text := pg_catalog.current_setting('gateway.runtime_role');
BEGIN
    EXECUTE pg_catalog.format('REVOKE ALL ON ALL TABLES IN SCHEMA gateway FROM %I', runtime);
    EXECUTE pg_catalog.format('REVOKE ALL ON SCHEMA gateway FROM %I', runtime);
    EXECUTE pg_catalog.format('GRANT USAGE ON SCHEMA gateway TO %I', runtime);
    EXECUTE pg_catalog.format('GRANT SELECT ON gateway.schema_migrations TO %I', runtime);
    EXECUTE pg_catalog.format('GRANT SELECT, INSERT ON gateway.blobs, gateway.series, gateway.entries, gateway.logs, gateway.log_records, gateway.secrets TO %I', runtime);
    EXECUTE pg_catalog.format('GRANT SELECT, INSERT, UPDATE, DELETE ON gateway.documents TO %I', runtime);
END
$grants$;
