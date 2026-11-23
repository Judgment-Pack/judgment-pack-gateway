package main

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// The dry-run is read from actScopeVersion alone (ADR-0054, decisions 2 and
// 3), set by engineServeOptions from the configuration's version, so a
// rollback of the file below 43 is a gateway that refuses a dry-run by name
// and never sends it as a write. Each configuration is loaded from its text,
// and its gateway built from what the configuration gives. Its platform
// derives no write source, so at 43 the dry-run passes the members and the
// dry-run step and is refused at the platform's, after both.
func TestADryRunIsReadFromItsEngineVersionAlone(t *testing.T) {
	catalog := catalogWith(t, map[string]string{"postgres": postgresBinding})
	ref := "postgres@" + digestOf(postgresBinding)
	body := `{"session":"dry-version","platform":"warehouse","tool":"execute","arguments":{"sql":"update t set s = 1"},` +
		`"decision":{"recordDigest":"sha256:` + strings.Repeat("a", 64) + `","packDigest":"sha256:` + strings.Repeat("b", 64) + `"},` +
		`"cites":[],"actionKey":"` + strings.Repeat("c", 64) + `","dryRun":true}`
	for _, c := range []struct {
		version string
		read    bool
	}{{keyHistoryV2Version, false}, {actScopeVersion, true}} {
		text := strings.Replace(engineJSON(t, catalog, "", platformJSON(t, "warehouse", ref, "engine-warehouse", `,"write":true`)), `"engineVersion":"1"`, `"engineVersion":"`+c.version+`"`, 1)
		cfg, err := parseEngineConfig([]byte(text))
		if err != nil {
			t.Fatalf("version %s: %v", c.version, err)
		}
		service, err := buildService(cfg.store, testSeed, cfg.authority, cfg.registry, engineServeOptions(cfg, map[string]sourceSpec{}, nil))
		if err != nil {
			t.Fatal(err)
		}
		issuer := newIssuer(t)
		id := identityFor(t, issuer)
		service.identity = &id
		server := httptest.NewServer(service.handler())
		status, out := authed(t, server, "/act", body, issuer.mint(t, "ec-1", nil, goodClaims(time.Now())))
		server.Close()
		named := strings.Contains(fmt.Sprint(out["error"]), "dryRun")
		if !c.read && (status != http.StatusBadRequest || !named) {
			t.Fatalf("version %s: %d %v, want the member refused by name", c.version, status, out)
		}
		if c.read && (named || out["refusedAt"] != "platform") {
			t.Fatalf("version %s: %d %v, want the dry-run read and refused at the platform", c.version, status, out)
		}
	}
}
