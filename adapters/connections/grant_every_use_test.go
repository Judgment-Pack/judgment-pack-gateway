//go:build linux || darwin

package connections

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"sync/atomic"
	"testing"
	"time"
)

// Review findings H1, H2, M1, M2 and L4 on #360: every use of a grant's
// credential passes the grant's check, not only an acquisition.

// providerCalls counts every request the Drive broker's provider is sent.
func providerCalls(t *testing.T, b *Broker) *atomic.Int32 {
	t.Helper()
	count := &atomic.Int32{}
	inner := b.provider.client.Transport
	b.provider.client.Transport = testTransportFunc(func(r *http.Request) (*http.Response, error) {
		count.Add(1)
		return inner.RoundTrip(r)
	})
	return count
}

// H1: a grant past its idle bound is revoked at its next use of any kind:
// a search reaches no provider, and a Databricks or Azure DevOps connection
// test is refused before its credential is sent.
func TestIdleExpiryGatesEveryUse(t *testing.T) {
	now := grantT0
	atClock(t, &now)
	b, _, dir, _ := driveGrant(t)
	calls := providerCalls(t, b)
	if _, err := grantOp(t, dir, "alice", "", "set-idle-expiry", map[string]any{"provider": "google-drive", "connection": "google-drive", "idleExpiry": 60_000}); err != nil {
		t.Fatal(err)
	}
	now = grantT0.Add(61 * time.Second)
	if _, err := b.Handle(context.Background(), "search", []byte(`{"query":"policy"}`)); err != ErrGrantIdle {
		t.Fatalf("a search 61 s into a 60 s bound: %v", err)
	}
	if n := calls.Load(); n != 1 {
		// The one request is the revocation the expiry asks Google for.
		t.Fatalf("the provider was sent %d requests", n)
	}
	held := true
	b.store.locked(func(v *state) error { held = v.Connection != nil; return nil })
	if held {
		t.Fatal("the expired grant's credential was kept")
	}
	if row := rowOf(t, mustReport(t, dir), "google-drive", "google-drive", "revoked"); row.Revocation.Reason != revokedIdle {
		t.Fatalf("%+v", row)
	}

	_, dbb, c, ddir := dbFixture(t, dbTokenFields())
	ado, err := OpenAzureDevOpsStore(ddir, "test")
	if err != nil {
		t.Fatal(err)
	}
	defer ado.Close()
	adob := NewAzureDevOps(ado, false)
	defer adob.Close()
	if err := adoConfigure(adob, adoTokenFields()); err != nil {
		t.Fatal(err)
	}
	a := adoConnection(t, ado, "board")
	now = grantT0
	for _, k := range [][2]string{{"databricks", "lake"}, {"azure-devops", "board"}} {
		if _, err := grantOp(t, ddir, "test", "", "set-idle-expiry", map[string]any{"provider": k[0], "connection": k[1], "idleExpiry": 60_000}); err != nil {
			t.Fatal(err)
		}
	}
	now = grantT0.Add(61 * time.Second)
	if _, err := dbb.Handle(context.Background(), "test", mustJSON(map[string]string{"id": c.ID, "revision": c.Revision})); err != ErrGrantIdle {
		t.Fatalf("a Databricks test past the bound: %v", err)
	}
	if bytesContain(dbState(t, ddir), dbPAT) {
		t.Fatal("the Databricks credential was kept")
	}
	if _, err := adob.Handle(context.Background(), "test", mustJSON(map[string]string{"id": a.ID, "revision": a.Revision})); err != ErrGrantIdle {
		t.Fatalf("an Azure DevOps test past the bound: %v", err)
	}
}

// H2: a grant whose owner the issuing host has removed serves no use of
// any kind: a search makes the owner read and is refused before the
// provider is reached, and the same owner's grant in another provider's
// custody is refused at its own next use, a connection test.
func TestOwnerRemovalGatesEveryUse(t *testing.T) {
	b, _, dir, _ := driveGrant(t)
	calls := providerCalls(t, b)
	standing := `{"standing":"removed"}`
	asked, cfg := ownerHost(t, &standing, quarantineRemoval)
	if _, err := grantOp(t, dir, "alice", "", "owner-reads", cfg); err != nil {
		t.Fatal(err)
	}
	db, err := OpenDatabricksStore(dir, "alice")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	dbb := NewDatabricks(db, false)
	defer dbb.Close()
	if err := dbConfigure(dbb, dbTokenFields()); err != nil {
		t.Fatal(err)
	}
	for _, k := range [][2]string{{"google-drive", "google-drive"}, {"databricks", "lake"}} {
		if _, err := grantOp(t, dir, "alice", "", "set-owner", map[string]any{"provider": k[0], "connection": k[1], "owner": owner, "ownerHost": "desk"}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := b.Handle(context.Background(), "search", []byte(`{"query":"policy"}`)); err != ErrOwnerRemoved {
		t.Fatalf("a search by a removed owner's grant: %v", err)
	}
	if calls.Load() != 0 || asked.Load() != 1 {
		t.Fatalf("provider requests %d, owner reads %d", calls.Load(), asked.Load())
	}
	rowOf(t, mustReport(t, dir), "google-drive", "google-drive", "quarantined")
	c := dbConnection(t, db, "lake")
	if _, err := dbb.Handle(context.Background(), "test", mustJSON(map[string]string{"id": c.ID, "revision": c.Revision})); err != ErrOwnerRemoved {
		t.Fatalf("the owner's Databricks grant at a connection test: %v", err)
	}
	if asked.Load() != 2 {
		t.Fatalf("owner reads %d", asked.Load())
	}
	rowOf(t, mustReport(t, dir), "databricks", "lake", "quarantined")
}

// M2 (MX1, MX2): the production owner-read client follows no redirect and
// takes no status but 200, whatever the answer says.
func TestOwnerReadProductionClientFailsClosed(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/redirect":
			http.Redirect(w, r, "/ok", http.StatusFound)
		case "/temporary":
			http.Redirect(w, r, "/ok", http.StatusTemporaryRedirect)
		case "/created":
			w.WriteHeader(http.StatusCreated)
			io.WriteString(w, `{"standing":"current"}`)
		case "/accepted":
			w.WriteHeader(http.StatusAccepted)
			io.WriteString(w, `{"standing":"removed"}`)
		case "/ok":
			io.WriteString(w, `{"standing":"current"}`)
		}
	}))
	defer server.Close()
	pool := x509.NewCertPool()
	pool.AddCert(server.Certificate())
	production := ownerReadClient
	ownerReadClient = func() *http.Client {
		// The production client, its redirect and status rules untouched,
		// trusting only the stand-in's certificate.
		c := production()
		c.Transport.(*http.Transport).TLSClientConfig = &tls.Config{RootCAs: pool}
		return c
	}
	defer func() { ownerReadClient = production }()
	s := testStore(t, "reads")
	for path, want := range map[string]string{"/ok": ownerCurrent, "/redirect": ownerUnknown, "/temporary": ownerUnknown, "/created": ownerUnknown, "/accepted": ownerUnknown} {
		cfg := ownerReads{Version: 1, Removal: revokedRemoval, Hosts: []ownerReadHost{{Host: "desk", URL: server.URL + path, Credential: "owner-read-credential"}}}
		if err := s.locked(func(*state) error { return s.write(ownerReadsDocument, cfg) }); err != nil {
			t.Fatal(err)
		}
		u, _ := url.Parse(server.URL + path)
		if got := s.ownerStanding(context.Background(), "desk", owner); got != want {
			t.Errorf("%s: %s, not %s", u.Path, got, want)
		}
	}
}

// M2 (MX3): a last use or a creation time the record cannot be read for is
// taken as expired.
func TestUnreadableGrantTimeIsExpired(t *testing.T) {
	bound := int64(3_600_000)
	for _, since := range []string{"", "yesterday", "2026-10-30T12:00:00Z", "2026-10-30T12:00:00.0000Z", "2026-13-30T12:00:00.000Z"} {
		r := grantRecord{CreatedAt: grantTime(grantT0), IdleExpiry: &bound}
		last := since
		r.LastUsedAt = &last
		if !idleExpired(r, grantT0) {
			t.Errorf("a last use of %q was not taken as expired", since)
		}
		r = grantRecord{CreatedAt: since, IdleExpiry: &bound}
		if !idleExpired(r, grantT0) {
			t.Errorf("a creation of %q was not taken as expired", since)
		}
	}
	r := grantRecord{CreatedAt: grantTime(grantT0), IdleExpiry: &bound}
	if idleExpired(r, grantT0.Add(time.Minute)) {
		t.Fatal("a readable creation time within its bound was expired")
	}
}

// M1: Databricks declares the narrowest scope for each operation. all-apis,
// which a service principal with no scope asks for, is admitted and
// reported as wider than needed; a narrow scope granted is the one taken as
// used; all-apis is never taken as used by a managed MCP server.
func TestDatabricksAllAPIsIsReportedWiderThanNeeded(t *testing.T) {
	for _, k := range []struct {
		scope      string
		used       []string
		wider      bool
		unusedWant []string
	}{
		{"", []string{"all-apis"}, true, []string{}},
		{"all-apis sql", []string{"sql"}, true, []string{"all-apis"}},
		{"sql unity-catalog", []string{"sql"}, false, []string{"unity-catalog"}},
	} {
		fields := dbPrincipalFields()
		if k.scope != "" {
			fields["scope"] = k.scope
		}
		s, _, _, dir := dbFixture(t, fields)
		if _, err := s.grantUse(context.Background(), databricksProvider(), "lake", "statement"); err != nil {
			t.Fatalf("%q: %v", k.scope, err)
		}
		row := rowOf(t, mustReportOf(t, dir, "test"), "databricks", "lake", "active")
		used := []string{}
		for _, u := range row.Scopes.Used {
			used = append(used, u.Scope)
		}
		if !slices.Equal(used, k.used) || hasFinding(row, "wider-than-needed") != k.wider || len(row.Excess) != 0 || !slices.Equal(row.Scopes.Unused, k.unusedWant) {
			t.Errorf("%q: used %v, unused %v, findings %+v", k.scope, used, row.Scopes.Unused, row.Findings)
		}
		if !slices.Equal(row.Scopes.Required, []string{"sql", "unity-catalog"}) {
			t.Errorf("%q: required %v", k.scope, row.Scopes.Required)
		}
	}
	// A managed MCP server's call under all-apis alone records no scope used.
	fields := dbPrincipalFields()
	s, _, _, dir := dbFixture(t, fields)
	if _, err := s.grantUse(context.Background(), databricksProvider(), "lake", "mcp:genie"); err != nil {
		t.Fatal(err)
	}
	if row := rowOf(t, mustReportOf(t, dir, "test"), "databricks", "lake", "active"); len(row.Scopes.Used) != 0 || row.LastUsedAt == nil {
		t.Fatalf("an MCP call taken as using all-apis: %+v", row.Scopes)
	}
}

func mustReportOf(t *testing.T, dir, principal string) []grantRow {
	rows, _ := grantReport(t, dir, principal)
	return rows
}

// L4: a quarantine made while a service principal's token is minted, after
// the acquisition's check, refuses the acquisition before it is sent.
func TestQuarantineDuringMintRefusesBeforeDispatch(t *testing.T) {
	s, _, c, dir := dbFixture(t, dbPrincipalFields())
	if _, err := grantOp(t, dir, "test", "", "set-owner", map[string]any{"provider": "databricks", "connection": "lake", "owner": owner, "ownerHost": "desk"}); err != nil {
		t.Fatal(err)
	}
	standing := `{"standing":"current"}`
	_, cfg := ownerHost(t, &standing, quarantineRemoval)
	if _, err := grantOp(t, dir, "test", "", "owner-reads", cfg); err != nil {
		t.Fatal(err)
	}
	f := newDBFake(t)
	f.setToken(func(w http.ResponseWriter, r *http.Request, form url.Values) {
		if _, err := GrantOperation(context.Background(), dir, "test", "", "remove-owner", mustJSON(map[string]any{"owner": owner, "ownerHost": "desk", "removal": "quarantine"})); err != nil {
			t.Error(err)
		}
		io.WriteString(w, `{"access_token":"`+dbMinted+`","token_type":"Bearer","expires_in":3600,"scope":"all-apis"}`)
	})
	if _, err := databricksAcquire(context.Background(), s, dbStatementRead(c, "SELECT 1"), f.provider()); err != ErrGrantQuarantined {
		t.Fatalf("an acquisition quarantined during its mint: %v", err)
	}
	if f.mints.Load() != 1 || f.api.Load() != 0 {
		t.Fatalf("mints %d, API requests %d", f.mints.Load(), f.api.Load())
	}
}
