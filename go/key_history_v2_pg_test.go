package main

import (
	"crypto/ed25519"
	"os"
	"regexp"
	"strings"
	"testing"
)

// gateway store rotate --config on the PostgreSQL kind, with the member,
// writes a version 2 history to the new database's gateway.key_history,
// the bytes its continuation names, which the new database answers as
// version 2 with the member absent.
func TestAPostgresStoreRotationWithTheMemberCarriesAVersion2Row(t *testing.T) {
	db := newPgTestDB(t)
	db.migrate(t)
	dir := tempDirAt(t, 0o700)
	config, cfg := sealOpenPgConfig(t, db, dir, "engine.json", false, "")
	// a gateway's start makes the registry, under version 1
	_, stop := pgServeWith(t, cfg, dir, testSeed)
	stop()
	text := readFile(t, config)
	opted := regexp.MustCompile(`"engineVersion":"[0-9]+"`).ReplaceAllString(text, `"engineVersion":"`+keyHistoryV2Version+`","keyHistoryVersion":"2"`)
	if opted == text {
		t.Fatal("the configuration names no engineVersion")
	}
	if err := os.WriteFile(config, []byte(opted), 0o600); err != nil {
		t.Fatal(err)
	}
	target := pgTestDBBeside(t, db)
	if code, stdout, stderr := rotatePg(t, config, target, dir); code != 0 {
		t.Fatalf("exit %d\nstdout %q\nstderr %q", code, stdout, stderr)
	}
	row, present, err := target.open(t, nil).carriedKeyHistory()
	if err != nil || !present || !strings.HasPrefix(string(row), `{"keyHistoryVersion":"2","stores":[{"keys":[`) {
		t.Fatalf("the row: %v %v %s", err, present, row)
	}
	own := edKey(ed25519.NewKeyFromSeed(testSeed).Public().(ed25519.PublicKey))
	doc, err := walkKeyHistory([]byte(pgRegistryOf(t, target)), own, row, true, "")
	if err != nil {
		t.Fatal(err)
	}
	checked, err := checkKeyHistoryOf(doc, &own, keyHistoryVersion2)
	if err != nil || checked.version != keyHistoryVersion2 || strings.Count(string(doc), `"continuation":`) != 1 {
		t.Fatalf("the new database's history: %v\n%s", err, doc)
	}
}
