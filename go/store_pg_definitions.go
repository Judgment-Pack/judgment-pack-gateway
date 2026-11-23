package main

// The definitions the PostgreSQL storage kind's start holds the schema's
// tables to (#440): every column, constraint and index of the store's
// tables, as the server prints each under the search path the kind sets
// (pg_catalog alone), against the list below, which this binary carries
// for the schema its migrations make. A primary key, a check or a foreign
// key dropped or changed, a column changed, or an index or a column made
// beside them refuses the start, as a table beside the store's does.
//
// The list is what PostgreSQL 16 prints for a database the migrations
// made, read from the server at the image the CI job runs, and held to it
// there by TestThePostgresSchemaDefinitionsAreTheOnesTheBinaryCarries,
// which prints the server's list where the two differ. A new migration
// that changes a definition changes this list in the same change.
//
// A column's NOT NULL is read from the column (pg_attribute.attnotnull)
// and not as a constraint: a server from PostgreSQL 18 also records it in
// pg_constraint, of the type 'n', and those rows are left out. The list is
// tested on PostgreSQL 16 alone; a server that prints a definition
// otherwise has its start refused, as a schema changed would.

import (
	"errors"
	"fmt"
)

// pgDefinition is one column, constraint or index of a table of the schema
// and its definition as the server prints it.
type pgDefinition struct {
	table, kind, name, definition string
}

// pgDefinitions are the definitions the schema's migrations make, by
// table, kind and name.
var pgDefinitions = []pgDefinition{
	{"blobs", "column", "data", `bytea NOT NULL`},
	{"blobs", "column", "name", `text COLLATE pg_catalog."C" NOT NULL`},
	{"blobs", "column", "scope", `text COLLATE pg_catalog."C" NOT NULL`},
	{"blobs", "constraint", "blobs_name_check", `CHECK ((name ~ '^sha256:[0-9a-f]{64}$'::text))`},
	{"blobs", "constraint", "blobs_pkey", `PRIMARY KEY (scope, name)`},
	{"blobs", "constraint", "blobs_scope_check", `CHECK (((scope = 'none'::text) OR ((substr(scope, 1, 6) = 'scope:'::text) AND ((octet_length(scope) >= 7) AND (octet_length(scope) <= 134)))))`},
	{"blobs", "index", "blobs_pkey", `CREATE UNIQUE INDEX blobs_pkey ON gateway.blobs USING btree (scope, name)`},
	{"documents", "column", "data", `bytea NOT NULL`},
	{"documents", "column", "name", `text COLLATE pg_catalog."C" NOT NULL`},
	{"documents", "column", "revision", `text COLLATE pg_catalog."C" NOT NULL`},
	{"documents", "column", "scope", `text COLLATE pg_catalog."C" NOT NULL`},
	{"documents", "constraint", "documents_name_check", `CHECK (((octet_length(name) >= 1) AND (octet_length(name) <= 255)))`},
	{"documents", "constraint", "documents_pkey", `PRIMARY KEY (scope, name)`},
	{"documents", "constraint", "documents_revision_check", `CHECK ((revision ~ '^[0-9a-f]{32}$'::text))`},
	{"documents", "constraint", "documents_scope_check", `CHECK (((scope = 'none'::text) OR ((substr(scope, 1, 6) = 'scope:'::text) AND ((octet_length(scope) >= 7) AND (octet_length(scope) <= 134)))))`},
	{"documents", "index", "documents_pkey", `CREATE UNIQUE INDEX documents_pkey ON gateway.documents USING btree (scope, name)`},
	{"entries", "column", "data", `bytea NOT NULL`},
	{"entries", "column", "name", `text COLLATE pg_catalog."C" NOT NULL`},
	{"entries", "column", "scope", `text COLLATE pg_catalog."C" NOT NULL`},
	{"entries", "column", "series", `text COLLATE pg_catalog."C" NOT NULL`},
	{"entries", "constraint", "entries_name_check", `CHECK (((octet_length(name) >= 1) AND (octet_length(name) <= 255)))`},
	{"entries", "constraint", "entries_pkey", `PRIMARY KEY (series, name)`},
	{"entries", "constraint", "entries_scope_series_fkey", `FOREIGN KEY (scope, series) REFERENCES gateway.series(scope, name)`},
	{"entries", "index", "entries_pkey", `CREATE UNIQUE INDEX entries_pkey ON gateway.entries USING btree (series, name)`},
	{"journal_records", "column", "follows", `bigint GENERATED ALWAYS AS (NULLIF(ordinal, 0) - 1) STORED`},
	{"journal_records", "column", "journal", `text COLLATE pg_catalog."C" NOT NULL`},
	{"journal_records", "column", "line", `bytea NOT NULL`},
	{"journal_records", "column", "ordinal", `bigint NOT NULL`},
	{"journal_records", "constraint", "journal_records_journal_check", `CHECK ((journal ~ '^[a-z-]{1,32}$'::text))`},
	{"journal_records", "constraint", "journal_records_journal_follows_fkey", `FOREIGN KEY (journal, follows) REFERENCES gateway.journal_records(journal, ordinal)`},
	{"journal_records", "constraint", "journal_records_line_check", `CHECK ((((octet_length(line) >= 1) AND (octet_length(line) <= 4096)) AND (POSITION(('\x0a'::bytea) IN (line)) = 0)))`},
	{"journal_records", "constraint", "journal_records_ordinal_check", `CHECK ((ordinal >= 0))`},
	{"journal_records", "constraint", "journal_records_pkey", `PRIMARY KEY (journal, ordinal)`},
	{"journal_records", "index", "journal_records_pkey", `CREATE UNIQUE INDEX journal_records_pkey ON gateway.journal_records USING btree (journal, ordinal)`},
	{"key_history", "column", "history", `bytea NOT NULL`},
	{"key_history", "column", "singleton", `boolean NOT NULL DEFAULT true`},
	{"key_history", "constraint", "key_history_history_check", `CHECK ((octet_length(history) > 0))`},
	{"key_history", "constraint", "key_history_pkey", `PRIMARY KEY (singleton)`},
	{"key_history", "constraint", "key_history_singleton_check", `CHECK (singleton)`},
	{"key_history", "index", "key_history_pkey", `CREATE UNIQUE INDEX key_history_pkey ON gateway.key_history USING btree (singleton)`},
	{"log_records", "column", "data", `bytea NOT NULL`},
	{"log_records", "column", "follows", `bigint GENERATED ALWAYS AS NULLIF(start, 0) STORED`},
	{"log_records", "column", "log", `text COLLATE pg_catalog."C" NOT NULL`},
	{"log_records", "column", "start", `bigint NOT NULL`},
	{"log_records", "column", "stop", `bigint GENERATED ALWAYS AS (start + octet_length(data)) STORED`},
	{"log_records", "constraint", "log_records_data_check", `CHECK ((octet_length(data) > 0))`},
	{"log_records", "constraint", "log_records_log_fkey", `FOREIGN KEY (log) REFERENCES gateway.logs(name)`},
	{"log_records", "constraint", "log_records_log_follows_fkey", `FOREIGN KEY (log, follows) REFERENCES gateway.log_records(log, stop)`},
	{"log_records", "constraint", "log_records_log_stop_key", `UNIQUE (log, stop)`},
	{"log_records", "constraint", "log_records_pkey", `PRIMARY KEY (log, start)`},
	{"log_records", "constraint", "log_records_start_check", `CHECK ((start >= 0))`},
	{"log_records", "index", "log_records_log_stop_key", `CREATE UNIQUE INDEX log_records_log_stop_key ON gateway.log_records USING btree (log, stop)`},
	{"log_records", "index", "log_records_pkey", `CREATE UNIQUE INDEX log_records_pkey ON gateway.log_records USING btree (log, start)`},
	{"logs", "column", "name", `text COLLATE pg_catalog."C" NOT NULL`},
	{"logs", "constraint", "logs_name_check", `CHECK ((name = 'registry'::text))`},
	{"logs", "constraint", "logs_pkey", `PRIMARY KEY (name)`},
	{"logs", "index", "logs_pkey", `CREATE UNIQUE INDEX logs_pkey ON gateway.logs USING btree (name)`},
	{"removal_records", "column", "line", `bytea NOT NULL`},
	{"removal_records", "column", "ordinal", `bigint NOT NULL`},
	{"removal_records", "column", "scope", `text COLLATE pg_catalog."C" NOT NULL`},
	{"removal_records", "constraint", "removal_records_line_check", `CHECK (((octet_length(line) >= 1) AND (octet_length(line) <= 4095)))`},
	{"removal_records", "constraint", "removal_records_ordinal_check", `CHECK ((ordinal >= 0))`},
	{"removal_records", "constraint", "removal_records_pkey", `PRIMARY KEY (ordinal)`},
	{"removal_records", "constraint", "removal_records_scope_check", `CHECK ((scope = 'none'::text))`},
	{"removal_records", "index", "removal_records_pkey", `CREATE UNIQUE INDEX removal_records_pkey ON gateway.removal_records USING btree (ordinal)`},
	{"rotated", "column", "continuation", `text COLLATE pg_catalog."C" NOT NULL`},
	{"rotated", "column", "rotated_at", `timestamp with time zone NOT NULL`},
	{"rotated", "column", "singleton", `boolean NOT NULL DEFAULT true`},
	{"rotated", "constraint", "rotated_continuation_check", `CHECK ((continuation ~ '^[0-9a-f]{64}$'::text))`},
	{"rotated", "constraint", "rotated_pkey", `PRIMARY KEY (singleton)`},
	{"rotated", "constraint", "rotated_rotated_at_check", `CHECK (isfinite(rotated_at))`},
	{"rotated", "constraint", "rotated_singleton_check", `CHECK (singleton)`},
	{"rotated", "index", "rotated_pkey", `CREATE UNIQUE INDEX rotated_pkey ON gateway.rotated USING btree (singleton)`},
	{"schema_migrations", "column", "digest", `text COLLATE pg_catalog."C" NOT NULL`},
	{"schema_migrations", "column", "name", `text COLLATE pg_catalog."C" NOT NULL`},
	{"schema_migrations", "column", "version", `integer NOT NULL`},
	{"schema_migrations", "constraint", "schema_migrations_digest_check", `CHECK ((digest ~ '^sha256:[0-9a-f]{64}$'::text))`},
	{"schema_migrations", "constraint", "schema_migrations_pkey", `PRIMARY KEY (version)`},
	{"schema_migrations", "constraint", "schema_migrations_version_check", `CHECK ((version >= 1))`},
	{"schema_migrations", "index", "schema_migrations_pkey", `CREATE UNIQUE INDEX schema_migrations_pkey ON gateway.schema_migrations USING btree (version)`},
	{"scope_identifiers", "column", "identifier", `text COLLATE pg_catalog."C" NOT NULL`},
	{"scope_identifiers", "column", "scope", `text COLLATE pg_catalog."C" NOT NULL`},
	{"scope_identifiers", "constraint", "scope_identifiers_identifier_check", `CHECK (((substr(identifier, 1, 6) = 'scope:'::text) AND ((octet_length(identifier) >= 7) AND (octet_length(identifier) <= 134))))`},
	{"scope_identifiers", "constraint", "scope_identifiers_pkey", `PRIMARY KEY (identifier)`},
	{"scope_identifiers", "constraint", "scope_identifiers_scope_check", `CHECK ((scope = 'none'::text))`},
	{"scope_identifiers", "index", "scope_identifiers_pkey", `CREATE UNIQUE INDEX scope_identifiers_pkey ON gateway.scope_identifiers USING btree (identifier)`},
	{"secrets", "column", "name", `text COLLATE pg_catalog."C" NOT NULL`},
	{"secrets", "column", "value", `bytea NOT NULL`},
	{"secrets", "constraint", "secrets_name_check", `CHECK (((octet_length(name) >= 1) AND (octet_length(name) <= 255)))`},
	{"secrets", "constraint", "secrets_pkey", `PRIMARY KEY (name)`},
	{"secrets", "index", "secrets_pkey", `CREATE UNIQUE INDEX secrets_pkey ON gateway.secrets USING btree (name)`},
	{"series", "column", "holder", `text COLLATE pg_catalog."C"`},
	{"series", "column", "name", `text COLLATE pg_catalog."C" NOT NULL`},
	{"series", "column", "scope", `text COLLATE pg_catalog."C" NOT NULL`},
	{"series", "constraint", "series_holder_check", `CHECK ((holder ~ '^instance-[0-9a-f]{32}$'::text))`},
	{"series", "constraint", "series_name_check", `CHECK (((octet_length(name) >= 1) AND (octet_length(name) <= 255)))`},
	{"series", "constraint", "series_pkey", `PRIMARY KEY (name)`},
	{"series", "constraint", "series_scope_check", `CHECK (((scope = 'none'::text) OR ((substr(scope, 1, 6) = 'scope:'::text) AND ((octet_length(scope) >= 7) AND (octet_length(scope) <= 134)))))`},
	{"series", "constraint", "series_scope_name_key", `UNIQUE (scope, name)`},
	{"series", "index", "series_pkey", `CREATE UNIQUE INDEX series_pkey ON gateway.series USING btree (name)`},
	{"series", "index", "series_scope_name_key", `CREATE UNIQUE INDEX series_scope_name_key ON gateway.series USING btree (scope, name)`},
	{"series_holders", "column", "holder", `text COLLATE pg_catalog."C" NOT NULL`},
	{"series_holders", "column", "scope", `text COLLATE pg_catalog."C" NOT NULL`},
	{"series_holders", "column", "series", `text COLLATE pg_catalog."C" NOT NULL`},
	{"series_holders", "column", "turn", `bigint NOT NULL`},
	{"series_holders", "constraint", "series_holders_holder_check", `CHECK ((holder ~ '^instance-[0-9a-f]{32}$'::text))`},
	{"series_holders", "constraint", "series_holders_pkey", `PRIMARY KEY (series, turn)`},
	{"series_holders", "constraint", "series_holders_scope_series_fkey", `FOREIGN KEY (scope, series) REFERENCES gateway.series(scope, name)`},
	{"series_holders", "constraint", "series_holders_turn_check", `CHECK ((turn >= 1))`},
	{"series_holders", "index", "series_holders_pkey", `CREATE UNIQUE INDEX series_holders_pkey ON gateway.series_holders USING btree (series, turn)`},
	{"session_labels", "column", "label", `text COLLATE pg_catalog."C" NOT NULL`},
	{"session_labels", "column", "scope", `text COLLATE pg_catalog."C" NOT NULL`},
	{"session_labels", "column", "series", `text COLLATE pg_catalog."C" NOT NULL`},
	{"session_labels", "constraint", "session_labels_label_check", `CHECK (((label ~ '^[A-Za-z0-9._-]{1,128}$'::text) AND (label <> '.'::text) AND (label <> '..'::text)))`},
	{"session_labels", "constraint", "session_labels_pkey", `PRIMARY KEY (scope, label)`},
	{"session_labels", "constraint", "session_labels_scope_check", `CHECK (((scope = 'none'::text) OR ((substr(scope, 1, 6) = 'scope:'::text) AND ((octet_length(scope) >= 7) AND (octet_length(scope) <= 134)))))`},
	{"session_labels", "constraint", "session_labels_series_check", `CHECK ((series ~ '^[0-9a-f]{32}$'::text))`},
	{"session_labels", "constraint", "session_labels_series_key", `UNIQUE (series)`},
	{"session_labels", "index", "session_labels_pkey", `CREATE UNIQUE INDEX session_labels_pkey ON gateway.session_labels USING btree (scope, label)`},
	{"session_labels", "index", "session_labels_series_key", `CREATE UNIQUE INDEX session_labels_series_key ON gateway.session_labels USING btree (series)`},
	{"start_lease", "column", "authority", `text COLLATE pg_catalog."C" NOT NULL`},
	{"start_lease", "column", "expires", `timestamp with time zone NOT NULL`},
	{"start_lease", "column", "holder", `text COLLATE pg_catalog."C" NOT NULL`},
	{"start_lease", "column", "key_id", `text COLLATE pg_catalog."C" NOT NULL`},
	{"start_lease", "column", "labels", `boolean NOT NULL DEFAULT false`},
	{"start_lease", "column", "renewed", `timestamp with time zone NOT NULL`},
	{"start_lease", "column", "several", `boolean NOT NULL`},
	{"start_lease", "constraint", "start_lease_authority_check", `CHECK ((octet_length(authority) >= 1))`},
	{"start_lease", "constraint", "start_lease_check", `CHECK ((isfinite(renewed) AND isfinite(expires) AND (expires >= renewed) AND (expires <= (renewed + '00:10:00'::interval))))`},
	{"start_lease", "constraint", "start_lease_holder_check", `CHECK ((holder ~ '^instance-[0-9a-f]{32}$'::text))`},
	{"start_lease", "constraint", "start_lease_key_id_check", `CHECK ((key_id ~ '^[0-9a-f]{32}$'::text))`},
	{"start_lease", "constraint", "start_lease_pkey", `PRIMARY KEY (holder)`},
	{"start_lease", "index", "start_lease_pkey", `CREATE UNIQUE INDEX start_lease_pkey ON gateway.start_lease USING btree (holder)`},
}

// pgDefinitionsQuery reads every column, constraint and index of the
// schema's tables, as pgDefinitions lists them. A column is its type, its
// collation named with its schema (a collation of the same name in another
// schema may compare otherwise, and an index prints no collation that is
// its column's), NOT NULL, and its default or generation; an index that is
// not valid, ready and live is marked so.
const pgDefinitionsQuery = `SELECT c.relname, 'column', a.attname,
	pg_catalog.format_type(a.atttypid, a.atttypmod)
	|| CASE WHEN a.attcollation = 0 THEN '' ELSE ' COLLATE ' || pg_catalog.quote_ident(ln.nspname) || '.' || pg_catalog.quote_ident(l.collname) END
	|| CASE WHEN a.attnotnull THEN ' NOT NULL' ELSE '' END
	|| CASE WHEN d.adbin IS NULL THEN ''
		WHEN a.attgenerated = 's' THEN ' GENERATED ALWAYS AS ' || pg_catalog.pg_get_expr(d.adbin, d.adrelid) || ' STORED'
		WHEN a.attgenerated = '' THEN ' DEFAULT ' || pg_catalog.pg_get_expr(d.adbin, d.adrelid)
		ELSE ' GENERATED ' || a.attgenerated::text || ' ' || pg_catalog.pg_get_expr(d.adbin, d.adrelid) END
	|| CASE WHEN a.attidentity = '' THEN '' ELSE ' IDENTITY ' || a.attidentity::text END
	FROM pg_catalog.pg_attribute a JOIN pg_catalog.pg_class c ON c.oid = a.attrelid
	JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
	LEFT JOIN pg_catalog.pg_collation l ON l.oid = a.attcollation
	LEFT JOIN pg_catalog.pg_namespace ln ON ln.oid = l.collnamespace
	LEFT JOIN pg_catalog.pg_attrdef d ON d.adrelid = a.attrelid AND d.adnum = a.attnum
	WHERE n.nspname = 'gateway' AND c.relkind = 'r' AND a.attnum > 0 AND NOT a.attisdropped
UNION ALL
SELECT c.relname, 'constraint', k.conname, pg_catalog.pg_get_constraintdef(k.oid)
	FROM pg_catalog.pg_constraint k JOIN pg_catalog.pg_class c ON c.oid = k.conrelid
	JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
	WHERE n.nspname = 'gateway' AND k.contype <> 'n'
UNION ALL
SELECT c.relname, 'index', i.relname, pg_catalog.pg_get_indexdef(x.indexrelid)
	|| CASE WHEN x.indisvalid AND x.indisready AND x.indislive THEN '' ELSE ' (not valid)' END
	FROM pg_catalog.pg_index x JOIN pg_catalog.pg_class i ON i.oid = x.indexrelid
	JOIN pg_catalog.pg_class c ON c.oid = x.indrelid
	JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
	WHERE n.nspname = 'gateway'`

// pgDefinitionsOf reads the schema's definitions in a transaction of the
// kind, whose search path is pg_catalog alone.
func pgDefinitionsOf(tx pgTx) ([]pgDefinition, error) {
	rows, err := tx.exec(pgDefinitionsQuery)
	if err != nil {
		return nil, err
	}
	held := make([]pgDefinition, 0, len(rows.rows))
	for _, row := range rows.rows {
		if len(row) != 4 || row[3] == nil {
			return nil, errors.New("store: the schema's definitions did not read")
		}
		held = append(held, pgDefinition{string(row[0]), string(row[1]), string(row[2]), string(row[3])})
	}
	return held, nil
}

// pgDefinitionsHold holds what the schema holds to pgDefinitions: each of
// them there, as printed, and nothing beside them. A refusal names the
// table, the kind and the name, and quotes the definition this binary
// carries, never the definition the server prints.
func pgDefinitionsHold(held []pgDefinition) error {
	type key struct{ table, kind, name string }
	read := make(map[key]string, len(held))
	for _, d := range held {
		k := key{d.table, d.kind, d.name}
		if _, twice := read[k]; twice {
			return fmt.Errorf("store: gateway.%s holds the %s %s twice", d.table, d.kind, d.name)
		}
		read[k] = d.definition
	}
	made := make(map[key]bool, len(pgDefinitions))
	for _, d := range pgDefinitions {
		k := key{d.table, d.kind, d.name}
		made[k] = true
		got, ok := read[k]
		if !ok {
			return fmt.Errorf("store: gateway.%s holds no %s %s; the store's migrations make it as %s", d.table, d.kind, d.name, d.definition)
		}
		if got != d.definition {
			return fmt.Errorf("store: the %s %s of gateway.%s is not the one the store's migrations make, %s", d.kind, d.name, d.table, d.definition)
		}
	}
	for _, d := range held {
		if !made[key{d.table, d.kind, d.name}] {
			return fmt.Errorf("store: gateway.%s holds the %s %s, which the store's migrations do not make", d.table, d.kind, d.name)
		}
	}
	return nil
}
