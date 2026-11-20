package main

// `gateway store retain` (ADR-0048, A1 and R1; gateway #535): retention by
// signed acknowledgment on the PostgreSQL storage kind. It is gateway retain
// (retain.go) over rows: run as the migration login acting as the owner role,
// in one transaction that holds the migration's lock and the start lease, as
// gateway store remove-scope is (store_remove_scope.go), so a gateway serving
// the database refuses it. Each session it removes gets ADR-0034's
// session-removal record, kept in the same transaction, and nothing else.

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"
)

const storeRetainUsage = `  gateway store retain (--connection-file <path> | --connection-env <NAME>) --owner <role> --runtime <role> --config <engine.json> --acknowledgments <file> [--scope <identifier>] --by <label> [--timeout <seconds>]
Removes, the gateway stopped, the rows of each sealed session of a scope
identifier whose seal an acknowledgment names exactly, once the configuration's
retention.window has passed since the later of the seal's time and the
acknowledgment's, as the migration login acting as the owner role, under the
migration's lock and the start lease. A session-removal record for each is kept
in the same transaction, signed by the key in force (signingKeyVersion, else the seed). It refuses as
gateway retain does, and nothing is removed.`

func cmdStoreRetain(args []string, stdout, stderr io.Writer) int {
	return cmdStoreRetainAt(args, stdout, stderr, nowStamp, time.Now)
}

func cmdStoreRetainAt(args []string, stdout, stderr io.Writer, stamp func() string, now func() time.Time) int {
	const command = "store retain"
	usage := "usage:\n" + storeRetainUsage
	flags, code := storeFlags(args, []string{"--connection-file", "--connection-env", "--owner", "--runtime", "--config", "--acknowledgments", "--scope", "--by", "--timeout"}, command, usage, stderr)
	if code != 0 {
		return code
	}
	if flags["--config"] == "" || flags["--acknowledgments"] == "" || flags["--by"] == "" {
		fmt.Fprintln(stderr, usage)
		return 2
	}
	if scope, given := flags["--scope"]; given && !isScopeIdentifier(scope) {
		fmt.Fprintf(stderr, "%s: --scope is a scope identifier: %s\n%s\n", command, scopeForm, usage)
		return 2
	}
	if !isScopeIdentifier(flags["--by"]) {
		fmt.Fprintf(stderr, "%s: --by is a label of the form of a scope identifier: %s\n%s\n", command, scopeForm, usage)
		return 2
	}
	timeout, ok := storeTimeout(flags, command, usage, stderr)
	if !ok {
		return 2
	}
	spec, code := storeConnectionSpec(flags, command, stderr)
	if code != 0 {
		return code
	}
	o := retainOptions{config: flags["--config"], acks: flags["--acknowledgments"], scope: flags["--scope"], by: flags["--by"]}
	out, err := storeRetain(spec, pgRoles{owner: flags["--owner"], runtime: flags["--runtime"]}, o, timeout, stamp, now().UTC())
	for _, record := range out.appended {
		fmt.Fprintf(stdout, "%s\n", canon(record))
	}
	for _, note := range out.notes {
		fmt.Fprintln(stderr, command+":", note)
	}
	for _, refusal := range out.refused {
		fmt.Fprintln(stderr, command+":", refusal)
	}
	if err != nil {
		fmt.Fprintln(stderr, command+":", err)
		return 1
	}
	if len(out.refused) > 0 {
		return 1
	}
	return 0
}

func storeRetain(spec *storageSpec, roles pgRoles, o retainOptions, timeout time.Duration, stamp func() string, now time.Time) (removalOutcome, error) {
	cfg, err := retainConfig(o.config)
	if err != nil {
		return removalOutcome{}, err
	}
	if cfg.storage == nil {
		return removalOutcome{}, errors.New("the engine configuration names the filesystem kind; gateway retain removes its files")
	}
	acks, sum, refused, err := readRetentionAcks(o.acks, cfg.retention)
	if err != nil {
		return removalOutcome{}, fmt.Errorf("%v; nothing was removed", err)
	}
	if len(refused) > 0 {
		return removalOutcome{refused: append(refused, "nothing was removed")}, nil
	}
	seed, err := loadSeed(cfg.seed)
	if err != nil {
		return removalOutcome{}, fmt.Errorf("seed: %w", err)
	}
	dsn, err := storageConnection(spec)
	if err != nil {
		return removalOutcome{}, err
	}
	// the key in force signs the records: the key service's key version the
	// configuration names, held to signingPublicKey, or else the seed's
	// (ADR-0050); the instances are held before the registry is read
	sig, err := commandSigner(cfg.signingKeyVersion, cfg.signingPublicKey, seed)
	if err != nil {
		return removalOutcome{}, err
	}
	out, err := retainRows(dsn, roles, o, cfg.retention, acks, newSigningKey(sig), timeout, stamp, now)
	if err == nil && len(out.refused) == 0 {
		out.notes = append(out.notes, retentionSummary(out.removed, sum, cfg.retention.keyIDs))
	}
	return out, err
}

// pgRetainEntry is one receipt row the call read.
type pgRetainEntry struct {
	row, series string
	data        []byte
}

func retainRows(dsn pgDSN, roles pgRoles, o retainOptions, cfg *retentionConfig, acks []retentionAck, priv *signingKey,
	timeout time.Duration, stamp func() string, now time.Time) (out removalOutcome, err error) {
	if !pgRoleName(roles.owner) || !pgRoleName(roles.runtime) {
		return out, errors.New("store: a role's name is 1 to 63 bytes with no NUL and no double quote")
	}
	if roles.owner == roles.runtime {
		return out, errors.New("store: the owner role and the run-time role are two roles")
	}
	deadline := time.Now().Add(timeout)
	c, err := pgConnect(dsn, deadline)
	if err != nil {
		return out, err
	}
	defer c.close()
	if err := c.conn.SetDeadline(deadline); err != nil {
		return out, pgTransport(err)
	}
	if _, err := c.exec(`SELECT pg_catalog.set_config('search_path', 'pg_catalog', false)`); err != nil {
		return out, err
	}
	if err := pgServerHolds(c); err != nil {
		return out, err
	}
	if err := pgMigrationRolesHold(c, roles); err != nil {
		return out, err
	}
	failed := func(err error) (removalOutcome, error) {
		if !c.broken {
			c.exec("ROLLBACK")
		}
		return removalOutcome{}, fmt.Errorf("%v; nothing was removed", err)
	}
	refuse := func(notes, refused []string) (removalOutcome, error) {
		if !c.broken {
			c.exec("ROLLBACK")
		}
		return removalOutcome{notes: notes, refused: append(refused, "nothing was removed")}, nil
	}
	inScope := func(row string) error {
		_, err := c.exec(`SELECT pg_catalog.set_config('gateway.scope', $1, true)`, row)
		return err
	}
	if _, err := c.exec("BEGIN ISOLATION LEVEL READ COMMITTED READ WRITE"); err != nil {
		return out, err
	}
	if _, err := c.exec(`SELECT pg_catalog.set_config('role', $1, true),
		pg_catalog.set_config('search_path', 'pg_catalog', true),
		pg_catalog.set_config('gateway.scope', $2, true),
		pg_catalog.pg_advisory_xact_lock($3)`, roles.owner, pgNoScope, int64(pgMigrationLock)); err != nil {
		return failed(err)
	}
	set := pgShippedMigrations()
	recorded, err := pgAppliedMigrations(c, roles.owner)
	if err != nil {
		return failed(err)
	}
	if err := pgRecordedMatch(recorded, set); err != nil {
		return failed(err)
	}
	if len(recorded) != len(set.versions) {
		return failed(fmt.Errorf("store: the database's schema is at version %d and this gateway's is %d; gateway store migrate raises it first", len(recorded), len(set.versions)))
	}
	if err := pgHoldEveryInstance(c, "retain"); err != nil {
		return failed(err)
	}
	// a database rotated away from takes nothing more: a removal appended
	// to its registry would break the link the new store names (ADR-0048)
	if err := pgRefuseRotated(c); err != nil {
		return failed(err)
	}
	tx := pgTx{c}
	data, present, err := pgLog{name: "registry"}.readTx(tx, 0)
	if err != nil {
		return failed(err)
	}
	if !present {
		return failed(errors.New("the registry is not there; a gateway makes it when it starts, and its walk names the key the records are signed under"))
	}
	walk, err := engineWalk(data, priv.public)
	if err != nil {
		return failed(err)
	}
	// the key in force signs here: a registry holding records under a key
	// the walk did not reach, the seed's or a key service's, is refused
	// (ADR-0050)
	if err := heldUnderAnotherKey(data, walk.keys, priv.public, nil); err != nil {
		return failed(err)
	}
	file, next, err := pgRemovalFile(tx)
	if err != nil {
		return failed(err)
	}
	loaded, _, _ := scanRecords(bytes.NewReader(file), walk.keys)
	ret := &retention{removals: loaded.artifacts, sessions: loaded.sessions}

	// Every row scope there is -- no scope, and each identifier recorded --
	// and the sessions and receipts of each, read under its row security.
	ids, err := tx.exec(`SELECT identifier FROM gateway.scope_identifiers ORDER BY identifier`)
	if err != nil {
		return failed(err)
	}
	rowScopes := []string{pgNoScope}
	for _, r := range ids.rows {
		rowScopes = append(rowScopes, string(r[0]))
	}
	seriesRow := map[string]string{}
	var entries []pgRetainEntry
	for _, row := range rowScopes {
		if err := inScope(row); err != nil {
			return failed(err)
		}
		series, err := tx.exec(`SELECT name FROM gateway.series WHERE scope = $1`, row)
		if err != nil {
			return failed(err)
		}
		for _, s := range series.rows {
			seriesRow[string(s[0])] = row
		}
		rows, err := tx.exec(`SELECT series, data FROM gateway.entries WHERE scope = $1 ORDER BY series, name`, row)
		if err != nil {
			return failed(err)
		}
		for _, e := range rows.rows {
			entries = append(entries, pgRetainEntry{row: row, series: string(e[0]), data: e[1]})
		}
	}
	choice := chooseRetained(acks, walk, cfg, now, o.scope, removedUnder(ret), func(session string) retentionHold {
		row, held := seriesRow[session]
		if !held {
			return retentionHold{}
		}
		if row == pgNoScope {
			return retentionHold{held: true}
		}
		return retentionHold{held: true, scope: strings.TrimPrefix(row, pgScopePrefix)}
	})
	if len(choice.refused) > 0 {
		return refuse(choice.notes, choice.refused)
	}
	out.notes = choice.notes
	if len(choice.take) == 0 && len(choice.finish) == 0 {
		if !c.broken {
			c.exec("ROLLBACK")
		}
		out.notes = append(out.notes, "no session is past retention under an acknowledgment; nothing was removed")
		return out, nil
	}
	// gone is every session the call removes: those it records now, and
	// those recorded already whose rows a run cut off left (finish)
	gone := map[string]string{}
	for session, scope := range choice.take {
		gone[session] = scope
	}
	for session, scope := range choice.finish {
		gone[session] = scope
	}
	sessions := make([]string, 0, len(gone))
	for session := range gone {
		sessions = append(sessions, session)
	}
	sort.Strings(sessions)

	// A receipt left in the store that names a session the call would
	// remove may cite it: its citation would no longer resolve. Its bytes
	// are judged by what they spell, which refuses where a citation would.
	var refused []string
	for _, e := range entries {
		if _, taken := gone[e.series]; taken {
			continue
		}
		for _, session := range sessions {
			if bytes.Contains(e.data, append([]byte(`"sessionId":`), canon(vString(session))...)) {
				refused = append(refused, fmt.Sprintf("a receipt of session %s names session %s, which the call would remove; its citation would no longer resolve", e.series, session))
				break
			}
		}
	}
	if len(refused) > 0 {
		return refuse(out.notes, refused)
	}

	var lines [][]byte
	var receipts, payloads int64
	for _, session := range sessions {
		s := walk.seals[session]
		row := seriesRow[session]
		if err := inScope(row); err != nil {
			return failed(err)
		}
		// a session recorded as removed already has its rows removed and no
		// record signed again
		if _, finish := choice.finish[session]; !finish {
			var salt string
			if s.salted {
				if salt, err = pgSeriesSalt(tx, row, session); err != nil {
					return failed(err)
				}
			}
			record, line, err := signedSessionRemoval(priv, walk.keys, session, s, choice.take[session], salt, o.by, stamp())
			if err != nil {
				return failed(err)
			}
			lines = append(lines, line)
			out.appended = append(out.appended, record)
		}

		// the payloads only this session's receipts name, in its scope
		digests := map[string]bool{}
		var held int64
		for _, e := range entries {
			if e.series != session {
				continue
			}
			held++
			if v, err := parseJSON(e.data); err == nil {
				if obj, ok := v.(*vObject); ok {
					if d, ok := memberString(obj, "resultDigest"); ok && strings.HasPrefix(d, "sha256:") {
						digests[d] = true
					}
				}
			}
		}
		done, err := c.exec(`DELETE FROM gateway.entries WHERE scope = $1 AND series = $2`, row, session)
		if err != nil {
			return failed(err)
		}
		if done.tag != fmt.Sprintf("DELETE %d", held) {
			return failed(errors.New("the session's rows changed while they were removed"))
		}
		receipts += held
		if _, err := c.exec(`DELETE FROM gateway.series_holders WHERE scope = $1 AND series = $2`, row, session); err != nil {
			return failed(err)
		}
		if done, err = c.exec(`DELETE FROM gateway.series WHERE scope = $1 AND name = $2`, row, session); err != nil {
			return failed(err)
		}
		if done.tag != "DELETE 1" {
			return failed(errors.New("the session's rows changed while they were removed"))
		}
		names := make([]string, 0, len(digests))
		for d := range digests {
			names = append(names, d)
		}
		sort.Strings(names)
		for _, digest := range names {
			hexSum := []byte(strings.TrimPrefix(digest, "sha256:"))
			shared := false
			for _, e := range entries {
				if e.row == row && e.series != session && bytes.Contains(e.data, hexSum) {
					if _, taken := gone[e.series]; !taken || e.series > session {
						shared = true
						break
					}
				}
			}
			if !shared {
				doc, err := tx.exec(`SELECT count(*)::int8 FROM gateway.documents WHERE scope = $1 AND pg_catalog.position(data, pg_catalog.convert_to($2, 'UTF8')) > 0`, row, string(hexSum))
				if err != nil {
					return failed(err)
				}
				if n, ok := pgInt8(doc.rows[0][0]); !ok || n > 0 {
					shared = true
				}
			}
			if shared {
				continue
			}
			gone, err := c.exec(`DELETE FROM gateway.blobs WHERE scope = $1 AND name = $2`, row, digest)
			if err != nil {
				return failed(err)
			}
			if gone.tag == "DELETE 1" {
				payloads++
			}
		}
	}
	if err := inScope(pgNoScope); err != nil {
		return failed(err)
	}
	for _, line := range lines {
		if _, err := c.exec(`INSERT INTO gateway.removal_records (scope, ordinal, line) VALUES ($1, $2, $3)`, pgNoScope, next, bytes.TrimSuffix(line, []byte{'\n'})); err != nil {
			return failed(err)
		}
		next++
	}
	done, err := c.exec("COMMIT")
	if err != nil {
		return removalOutcome{}, fmt.Errorf("the commit's answer did not arrive, so whether the removal was made is not known: %v; a second run removes what is left", err)
	}
	if done.tag != "COMMIT" {
		return removalOutcome{}, errors.New("the database rolled the removal back; nothing was removed")
	}
	out.removed = len(sessions)
	out.notes = append(out.notes, fmt.Sprintf("removed %d session(s), holding %d receipt(s), and %d payload(s)", out.removed, receipts, payloads))
	return out, nil
}
