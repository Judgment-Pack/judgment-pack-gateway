-- The PostgreSQL storage kind, schema version 6: a row of the start lease for
-- each gateway instance, and the instance that holds each session
-- (docs/postgresql-store.md, "Several instances on one database";
-- docs/adr/0035-several-instances-on-one-postgresql-database.md, option C).
--
-- The start lease (schema version 2) held one row: the one instance that
-- served the database. From this version it holds a row for each instance
-- that has served it, by the identifier the instance draws at its start: its
-- mode (several, true where the configuration lets instances serve beside one
-- another, false for the one instance a database is served by otherwise), the
-- key id it signs under and the authority it names, and when it last renewed
-- its row and when the row expires, both by the database's clock. An instance
-- takes a row at its start -- one whose instance's row has expired, by a
-- change of its holder, or a new one -- renews it while it runs, and expires
-- it when it stops cleanly; no row is removed. Every write transaction of an
-- instance holds its own row, unexpired with room to spare, FOR KEY SHARE as
-- its last statement before its commit, as before. The rows are of no scope
-- and the table carries none, so no row security applies. grants.sql gives
-- the run-time role SELECT, INSERT and UPDATE on it, and not DELETE, as
-- before.
--
-- The migration runs with every instance stopped: gateway store migrate holds
-- every row of the lease and is refused while one is live, so the row of the
-- earlier version, expired, is all the table holds, and the table is made
-- again in its new form, empty.
--
-- A session's series records the instance that made it (holder), at the
-- admission of its first call, before the source runs; NULL for a series
-- made before this version, or by a view that holds no lease. A series that
-- holds no receipt is taken up by another instance once its holder's row has
-- expired: a row of gateway.series_holders, at the next turn, names the
-- instance that took it up, and the instance that holds a series is the one
-- its last turn names, or its own holder where none does. The primary key
-- (series, turn) admits one instance at a turn, so two instances that take up
-- one series at once are not both admitted. A row is never changed or
-- removed but by gateway store remove-scope, with the series it names; it
-- carries the series' scope, under the same policy as every scoped table's.
-- grants.sql gives the run-time role SELECT and INSERT on it alone, so no
-- table but the documents and the start lease becomes changeable.

DROP TABLE gateway.start_lease;

CREATE TABLE gateway.start_lease (
    holder    text COLLATE "C" PRIMARY KEY CHECK (holder ~ '^instance-[0-9a-f]{32}$'),
    several   boolean NOT NULL,
    key_id    text COLLATE "C" NOT NULL CHECK (key_id ~ '^[0-9a-f]{32}$'),
    authority text COLLATE "C" NOT NULL CHECK (octet_length(authority) >= 1),
    renewed   timestamptz NOT NULL,
    expires   timestamptz NOT NULL,
    CHECK (pg_catalog.isfinite(renewed) AND pg_catalog.isfinite(expires)
        AND expires >= renewed AND expires <= renewed + interval '10 minutes')
);

ALTER TABLE gateway.series
    ADD COLUMN holder text COLLATE "C" CHECK (holder ~ '^instance-[0-9a-f]{32}$');

CREATE TABLE gateway.series_holders (
    scope  text COLLATE "C" NOT NULL,
    series text COLLATE "C" NOT NULL,
    turn   bigint NOT NULL CHECK (turn >= 1),
    holder text COLLATE "C" NOT NULL CHECK (holder ~ '^instance-[0-9a-f]{32}$'),
    PRIMARY KEY (series, turn),
    FOREIGN KEY (scope, series) REFERENCES gateway.series (scope, name)
);

ALTER TABLE gateway.series_holders ENABLE ROW LEVEL SECURITY;
ALTER TABLE gateway.series_holders FORCE ROW LEVEL SECURITY;
CREATE POLICY scope_of_the_transaction ON gateway.series_holders
    USING (scope = pg_catalog.current_setting('gateway.scope', true))
    WITH CHECK (scope = pg_catalog.current_setting('gateway.scope', true));
