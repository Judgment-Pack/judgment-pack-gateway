//go:build linux || darwin

package connections

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// The connection grant (#357): least privilege at connect, drift, granted
// against used, owner, idle expiry, owner removal and provider revocation.

var grantT0 = time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC)

// atClock sets the grant clock for the test.
func atClock(t *testing.T, at *time.Time) {
	t.Helper()
	before := grantClock
	grantClock = func() time.Time { return *at }
	t.Cleanup(func() { grantClock = before })
}

// custodyDir is the custody root a store was opened under.
func custodyDir(s *Store, namespace bool) string {
	d := filepath.Dir(s.root.Name())
	if namespace {
		d = filepath.Dir(d)
	}
	return d
}

func grantOp(t *testing.T, dir, principal, provider, op string, request any) (map[string]any, error) {
	t.Helper()
	var raw []byte
	if request != nil {
		raw, _ = json.Marshal(request)
	}
	out, err := GrantOperation(context.Background(), dir, principal, provider, op, raw)
	if err != nil {
		return nil, err
	}
	b, _ := json.Marshal(out)
	var m map[string]any
	if json.Unmarshal(b, &m) != nil {
		t.Fatalf("an answer that is not an object: %s", b)
	}
	return m, nil
}

type grantRow struct {
	Provider   string            `json:"provider"`
	Connection string            `json:"connection"`
	Owner      *PrincipalRef     `json:"owner"`
	Scopes     GrantReportScopes `json:"scopes"`
	Excess     []string          `json:"excess"`
	LastUsedAt *string           `json:"lastUsedAt"`
	IdleExpiry *int64            `json:"idleExpiry"`
	Idle       string            `json:"idle"`
	State      string            `json:"state"`
	Revocation *GrantRevocation  `json:"revocation"`
	Findings   []GrantFinding    `json:"findings"`
}

func grantReport(t *testing.T, dir, principal string) ([]grantRow, []byte) {
	t.Helper()
	out, err := GrantOperation(context.Background(), dir, principal, "", "report", nil)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(out)
	var r struct {
		Version     int        `json:"version"`
		Connections []grantRow `json:"connections"`
	}
	if json.Unmarshal(raw, &r) != nil || r.Version != 1 {
		t.Fatalf("report: %s", raw)
	}
	return r.Connections, raw
}

func rowOf(t *testing.T, rows []grantRow, provider, connection, state string) grantRow {
	t.Helper()
	for i := len(rows) - 1; i >= 0; i-- {
		if rows[i].Provider == provider && rows[i].Connection == connection && rows[i].State == state {
			return rows[i]
		}
	}
	t.Fatalf("no %s grant %s/%s in %+v", state, provider, connection, rows)
	return grantRow{}
}

func hasFinding(r grantRow, code string) bool {
	return slices.ContainsFunc(r.Findings, func(f GrantFinding) bool { return f.Code == code })
}

// driveGrant is a Drive broker connected, with the custody root, and its
// provider used for revocations.
func driveGrant(t *testing.T) (*Broker, *atomic.Int32, string, chosen) {
	t.Helper()
	b, count, _ := testBroker(t)
	before := grantProviderFor
	grantProviderFor = func(kind string) provider {
		if kind == "google-drive" {
			return b.provider
		}
		return before(kind)
	}
	t.Cleanup(func() { grantProviderFor = before })
	r := choose(t, b, "file-A", "file-B")
	if r.State != "complete" {
		t.Fatalf("%+v", r)
	}
	return b, count, custodyDir(b.store, false), r
}

func driveRead(b *Broker, sel Selection) error {
	_, err := b.provider.read(context.Background(), b.store, mustJSON(ReadRequest{sel.Grant, sel.FileID}))
	return err
}

var owner = PrincipalRef{Kind: "person", Issuer: "https://issuer.example", Subject: "subject-1"}

// A grant made before grants recorded an owner is used as before, and the
// report says it has none; its granted and used scopes are recorded from
// the read, with the time of its last use.
func TestGrantWithoutOwnerIsUsedAndReported(t *testing.T) {
	now := grantT0
	atClock(t, &now)
	b, count, dir, r := driveGrant(t)
	if err := driveRead(b, r.Selections[0]); err != nil {
		t.Fatal(err)
	}
	if count.Load() == 0 {
		t.Fatal("the file was not read")
	}
	rows, _ := grantReport(t, dir, "alice")
	row := rowOf(t, rows, "google-drive", "google-drive", "active")
	if row.Owner != nil || !hasFinding(row, "owner-missing") {
		t.Fatalf("a grant without an owner record: %+v", row)
	}
	if !slices.Equal(row.Scopes.Required, []string{driveScope}) || !slices.Equal(row.Scopes.Granted, []string{driveScope}) || len(row.Scopes.Used) != 1 || row.Scopes.Used[0].Scope != driveScope || row.Scopes.Used[0].LastUsedAt != grantTime(now) || len(row.Scopes.Unused) != 0 {
		t.Fatalf("scopes: %+v", row.Scopes)
	}
	if row.LastUsedAt == nil || *row.LastUsedAt != "2026-10-30T12:00:00.000Z" || row.Idle != idleStateNone {
		t.Fatalf("last use: %+v", row)
	}
}

// A connection whose service principal asks for a scope its operations do
// not declare is refused at connect, the scope named, and a connection
// saved by an earlier release that holds one is refused at use and
// reported, with the scopes granted and not used listed.
func TestExcessScopeRefusedAtConnectAndUseAndUnusedListed(t *testing.T) {
	fields := dbPrincipalFields()
	fields["scope"] = "sql jobs"
	dir := t.TempDir()
	os.Chmod(dir, 0700)
	s, err := OpenDatabricksStore(dir, "test")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	b := NewDatabricks(s, false)
	defer b.Close()
	if err := dbConfigure(b, fields); err == nil || err.Error() != "excess-scope: jobs" {
		t.Fatalf("a service principal asking for jobs: %v", err)
	}
	fields["scope"] = "sql unity-catalog"
	if err := dbConfigure(b, fields); err != nil {
		t.Fatal(err)
	}
	p := databricksProvider()
	if err := s.grantUse(context.Background(), p, "lake", "statement"); err != nil {
		t.Fatal(err)
	}
	rows, raw := grantReport(t, dir, "test")
	row := rowOf(t, rows, "databricks", "lake", "active")
	if !slices.Equal(row.Scopes.Granted, []string{"sql", "unity-catalog"}) || len(row.Scopes.Used) != 1 || row.Scopes.Used[0].Scope != "sql" || !slices.Equal(row.Scopes.Unused, []string{"unity-catalog"}) || !hasFinding(row, "unused-scopes") {
		t.Fatalf("granted against used: %+v", row.Scopes)
	}
	if strings.Contains(string(raw), dbSecret) || strings.Contains(string(raw), dbClient) || strings.Contains(string(raw), dir) {
		t.Fatalf("the report repeats a credential, an identity or a path: %s", raw)
	}
	// An earlier release saved a connection asking for more.
	if err := s.locked(func(v *state) error {
		v.Databricks.Connections[0].Scope = "all-apis jobs"
		return s.write("state.json", v)
	}); err != nil {
		t.Fatal(err)
	}
	if err := s.grantUse(context.Background(), p, "lake", "statement"); err == nil || err.Error() != "excess-scope: jobs" {
		t.Fatalf("a connection holding jobs at use: %v", err)
	}
	rows, _ = grantReport(t, dir, "test")
	row = rowOf(t, rows, "databricks", "lake", "active")
	if !slices.Equal(row.Excess, []string{"jobs"}) || !hasFinding(row, "excess-scope") {
		t.Fatalf("the excess is not reported: %+v", row)
	}
}

// A personal access token's scopes are not read: the report says so, and
// lists no unused scope it cannot know.
func TestUnreadableScopesAreReported(t *testing.T) {
	s, _, _, dir := dbFixture(t, dbTokenFields())
	if err := s.grantUse(context.Background(), databricksProvider(), "lake", "statement"); err != nil {
		t.Fatal(err)
	}
	rows, raw := grantReport(t, dir, "test")
	row := rowOf(t, rows, "databricks", "lake", "active")
	if row.Scopes.Granted != nil || row.Scopes.Unused != nil || len(row.Scopes.Used) != 0 || !hasFinding(row, "scopes-unreadable") || row.LastUsedAt == nil {
		t.Fatalf("%+v", row)
	}
	if !strings.Contains(string(raw), `"granted":null`) || strings.Contains(string(raw), dbPAT) {
		t.Fatalf("%s", raw)
	}
}

// A renewal that says the token holds a scope added since (drift) is
// refused by name, recorded, and reported; the file is not asked for.
func TestDriftDetectedAtRenewal(t *testing.T) {
	b, count, dir, r := driveGrant(t)
	if err := b.store.locked(func(v *state) error { v.Connection.Expires = 1; return b.store.write("state.json", v) }); err != nil {
		t.Fatal(err)
	}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, `{"access_token":"wider","expires_in":3600,"token_type":"Bearer","scope":"https://www.googleapis.com/auth/drive https://www.googleapis.com/auth/gmail.readonly"}`)
	}))
	defer server.Close()
	b.provider.token = server.URL
	b.provider.client = server.Client()
	if err := driveRead(b, r.Selections[0]); err == nil || err.Error() != "excess-scope: "+gmailScope {
		t.Fatalf("a read under a token of more scopes: %v", err)
	}
	if count.Load() != 0 {
		t.Fatal("the file was asked for under the wider token")
	}
	rows, _ := grantReport(t, dir, "alice")
	row := rowOf(t, rows, "google-drive", "google-drive", "active")
	if !slices.Equal(row.Excess, []string{gmailScope}) || !slices.Contains(row.Scopes.Granted, gmailScope) || !hasFinding(row, "excess-scope") {
		t.Fatalf("drift is not recorded: %+v", row)
	}
	// It stays refused at the next use, before any renewal.
	if err := driveRead(b, r.Selections[1]); err == nil || !IsExcessScope(err) {
		t.Fatalf("the next use: %v", err)
	}
}

// A grant idle for exactly its bound is revoked at its next use: the
// credential is deleted, the provider asked to revoke it, and the record
// says why. One a millisecond short of it is used.
func TestIdleExpiryAtEqualTime(t *testing.T) {
	now := grantT0
	atClock(t, &now)
	b, count, dir, r := driveGrant(t)
	idle := int64(60_000)
	if _, err := grantOp(t, dir, "alice", "google-drive", "set-idle-expiry", map[string]any{"provider": "google-drive", "connection": "google-drive", "idleExpiry": idle}); err != nil {
		t.Fatal(err)
	}
	now = grantT0.Add(59_999 * time.Millisecond)
	if err := driveRead(b, r.Selections[0]); err != nil {
		t.Fatalf("a millisecond before the bound: %v", err)
	}
	used := count.Load()
	now = now.Add(time.Duration(idle) * time.Millisecond)
	if err := driveRead(b, r.Selections[1]); err != ErrGrantIdle {
		t.Fatalf("at the bound: %v", err)
	}
	if count.Load() != used {
		t.Fatal("the file was read through an expired grant")
	}
	if err := b.store.locked(func(v *state) error {
		if v.Connection != nil {
			t.Error("the credential was kept")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	rows, raw := grantReport(t, dir, "alice")
	row := rowOf(t, rows, "google-drive", "google-drive", "revoked")
	if row.Revocation == nil || row.Revocation.Reason != revokedIdle || !row.Revocation.ProviderRevoked || hasFinding(row, providerGrantMayPersist) {
		t.Fatalf("%+v", row)
	}
	if strings.Contains(string(raw), "google-access-private") || strings.Contains(string(raw), "google-refresh-private") || strings.Contains(string(raw), "person@example.test") || strings.Contains(string(raw), dir) {
		t.Fatalf("the report repeats a token, an account or a path: %s", raw)
	}
}

// A grant never used is measured from its creation; the report says when
// its idle expiry is reached, and a sweep revokes it. A provider without a
// revocation endpoint reports that the grant may persist there.
func TestSweepRevokesIdleGrantAndReportsProviderGrantMayPersist(t *testing.T) {
	now := grantT0
	atClock(t, &now)
	s, _, _, dir := dbFixture(t, dbTokenFields())
	if _, err := grantOp(t, dir, "test", "databricks", "set-idle-expiry", map[string]any{"provider": "databricks", "connection": "lake", "idleExpiry": 1000}); err != nil {
		t.Fatal(err)
	}
	now = now.Add(time.Second)
	rows, _ := grantReport(t, dir, "test")
	if row := rowOf(t, rows, "databricks", "lake", "active"); row.Idle != idleStateExpired || !hasFinding(row, "idle-expired") {
		t.Fatalf("%+v", row)
	}
	out, err := grantOp(t, dir, "test", "", "sweep", map[string]any{})
	if err != nil {
		t.Fatal(err)
	}
	if b, _ := json.Marshal(out); !strings.Contains(string(b), `{"connection":"lake","outcome":"idle-expired","provider":"databricks"}`) {
		t.Fatalf("%s", b)
	}
	rows, _ = grantReport(t, dir, "test")
	row := rowOf(t, rows, "databricks", "lake", "revoked")
	if row.Revocation.ProviderRevoked || row.Revocation.Report != providerGrantMayPersist || !hasFinding(row, providerGrantMayPersist) {
		t.Fatalf("%+v", row)
	}
	if bytesContain(dbState(t, dir), dbPAT) {
		t.Fatal("the credential was kept")
	}
	if err := s.grantUse(context.Background(), databricksProvider(), "lake", "statement"); err != ErrConnect {
		t.Fatalf("a revoked grant: %v", err)
	}
}

func bytesContain(b []byte, s string) bool { return strings.Contains(string(b), s) }

// The owner is recorded once; a second owner is refused.
func TestOwnerRecordedOnce(t *testing.T) {
	_, _, dir, _ := driveGrant(t)
	set := map[string]any{"provider": "google-drive", "connection": "google-drive", "owner": owner, "ownerHost": "desk"}
	if _, err := grantOp(t, dir, "alice", "", "set-owner", set); err != nil {
		t.Fatal(err)
	}
	other := owner
	other.Subject = "subject-2"
	set["owner"] = other
	if _, err := grantOp(t, dir, "alice", "", "set-owner", set); err != ErrOwnerRecorded {
		t.Fatalf("a second owner: %v", err)
	}
	for _, bad := range []map[string]any{
		{"provider": "google-drive", "connection": "google-drive", "owner": PrincipalRef{"agent", "i", "s"}, "ownerHost": "desk"},
		{"provider": "google-drive", "connection": "google-drive", "owner": owner, "ownerHost": ".."},
		{"provider": "aws-s3", "connection": "x", "owner": owner, "ownerHost": "desk"},
		{"provider": "google-drive", "connection": "google-drive", "owner": owner},
	} {
		if _, err := grantOp(t, dir, "alice", "", "set-owner", bad); err != ErrRequest {
			t.Errorf("%v: %v", bad, err)
		}
	}
	if _, err := grantOp(t, dir, "alice", "", "set-owner", map[string]any{"provider": "google-drive", "connection": "absent", "owner": owner, "ownerHost": "desk"}); err != ErrGrantUnknown {
		t.Fatalf("an absent connection: %v", err)
	}
}

// Removing the owner revokes every grant it owns, the provider asked to
// revoke it, or, as the operator chooses, quarantines it: a quarantined
// grant keeps its credential and admits no call, not even a search. A
// pending file change's journal is kept either way.
func TestOwnerRemovalRevokesOrQuarantines(t *testing.T) {
	for _, removal := range []string{revokedRemoval, quarantineRemoval} {
		t.Run(removal, func(t *testing.T) {
			b, count, dir, r := driveGrant(t)
			if err := b.store.put("storage-intent.json", []byte(`{"pending":true}`)); err != nil {
				t.Fatal(err)
			}
			if _, err := grantOp(t, dir, "alice", "", "set-owner", map[string]any{"provider": "google-drive", "connection": "google-drive", "owner": owner, "ownerHost": "desk"}); err != nil {
				t.Fatal(err)
			}
			other := owner
			other.Subject = "subject-2"
			if out, err := grantOp(t, dir, "alice", "", "remove-owner", map[string]any{"owner": other, "ownerHost": "desk", "removal": removal}); err != nil || len(out["connections"].([]any)) != 0 {
				t.Fatalf("another owner's removal: %v %v", out, err)
			}
			out, err := grantOp(t, dir, "alice", "", "remove-owner", map[string]any{"owner": owner, "ownerHost": "desk", "removal": removal})
			if err != nil || len(out["connections"].([]any)) != 1 {
				t.Fatalf("%v %v", out, err)
			}
			before := count.Load()
			err = driveRead(b, r.Selections[0])
			held := false
			b.store.locked(func(v *state) error { held = v.Connection != nil; return nil })
			rows, _ := grantReport(t, dir, "alice")
			switch removal {
			case revokedRemoval:
				if err != ErrGrant && err != ErrConnect || held {
					t.Fatalf("a read after revocation: %v, credential held %v", err, held)
				}
				row := rowOf(t, rows, "google-drive", "google-drive", "revoked")
				if row.Revocation.Reason != revokedOwnerRemoved || !row.Revocation.ProviderRevoked {
					t.Fatalf("%+v", row)
				}
			case quarantineRemoval:
				if err != ErrGrantQuarantined || !held {
					t.Fatalf("a read after quarantine: %v, credential held %v", err, held)
				}
				if _, err := b.Handle(context.Background(), "search", []byte(`{"query":"policy"}`)); err != ErrGrantQuarantined {
					t.Fatalf("a search through a quarantined grant: %v", err)
				}
				row := rowOf(t, rows, "google-drive", "google-drive", "quarantined")
				if !hasFinding(row, "quarantined") {
					t.Fatalf("%+v", row)
				}
				// It leaves quarantine by revocation.
				if _, err := grantOp(t, dir, "alice", "", "revoke", map[string]any{"provider": "google-drive", "connection": "google-drive"}); err != nil {
					t.Fatal(err)
				}
				rowOf(t, mustReport(t, dir), "google-drive", "google-drive", "revoked")
			}
			if count.Load() != before {
				t.Fatal("the file was read")
			}
			if raw, err := b.store.read("storage-intent.json"); err != nil || string(raw) != `{"pending":true}` {
				t.Fatalf("the pending change's journal: %q %v", raw, err)
			}
		})
	}
}

func mustReport(t *testing.T, dir string) []grantRow {
	rows, _ := grantReport(t, dir, "alice")
	return rows
}

// ownerHost is an issuing host answering the owner read with standing, and
// the configuration that names it.
func ownerHost(t *testing.T, standing *string, removal string) (*atomic.Int32, map[string]any) {
	t.Helper()
	asked := &atomic.Int32{}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		asked.Add(1)
		var q struct {
			Host  string       `json:"host"`
			Owner PrincipalRef `json:"owner"`
		}
		if r.Method != "POST" || r.Header.Get("Authorization") != "Bearer owner-read-credential" || json.NewDecoder(r.Body).Decode(&q) != nil || q.Host != "desk" || q.Owner != owner {
			http.Error(w, "refused", 403)
			return
		}
		io.WriteString(w, *standing)
	}))
	t.Cleanup(server.Close)
	before := ownerReadClient
	ownerReadClient = func() *http.Client {
		c := server.Client()
		c.Timeout = ownerReadTimeout
		c.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
		return c
	}
	t.Cleanup(func() { ownerReadClient = before })
	return asked, map[string]any{"version": 1, "removal": removal, "hosts": []map[string]string{{"host": "desk", "url": server.URL + "/standing", "credential": "owner-read-credential"}}}
}

// Before every use of a grant with an owner the owner read is made: a
// current owner admits the read; a removed one refuses it as owner-removed
// and applies the operator's removal; a host that does not answer, answers
// otherwise, or is not configured refuses as owner-unknown.
func TestOwnerReadAtEachUse(t *testing.T) {
	b, count, dir, r := driveGrant(t)
	standing := `{"standing":"current"}`
	asked, cfg := ownerHost(t, &standing, quarantineRemoval)
	if _, err := grantOp(t, dir, "alice", "", "set-owner", map[string]any{"provider": "google-drive", "connection": "google-drive", "owner": owner, "ownerHost": "desk"}); err != nil {
		t.Fatal(err)
	}
	// No owner read is configured: unknown.
	if err := driveRead(b, r.Selections[0]); err != ErrOwnerUnknown {
		t.Fatalf("with no owner read configured: %v", err)
	}
	out, err := grantOp(t, dir, "alice", "", "owner-reads", cfg)
	if err != nil {
		t.Fatal(err)
	}
	if raw, _ := json.Marshal(out); strings.Contains(string(raw), "owner-read-credential") || strings.Contains(string(raw), "https://") {
		t.Fatalf("the answer repeats the configuration's address or credential: %s", raw)
	}
	r = choose(t, b, "file-A", "file-B")
	if err := driveRead(b, r.Selections[0]); err != nil || asked.Load() != 1 {
		t.Fatalf("a current owner: %v, %d reads", err, asked.Load())
	}
	for _, reply := range []string{`{"standing":"suspended"}`, `{"standing":"current","extra":1}`, `not json`, strings.Repeat(" ", ownerReplyBytes+1)} {
		standing = reply
		before := count.Load()
		if err := driveRead(b, r.Selections[1]); err != ErrOwnerUnknown || count.Load() != before {
			t.Fatalf("an answer %.40q: %v", reply, err)
		}
		r = choose(t, b, "file-A", "file-B")
	}
	standing = `{"standing":"removed"}`
	if err := driveRead(b, r.Selections[0]); err != ErrOwnerRemoved {
		t.Fatalf("a removed owner: %v", err)
	}
	rows, raw := grantReport(t, dir, "alice")
	rowOf(t, rows, "google-drive", "google-drive", "quarantined")
	if strings.Contains(string(raw), "owner-read-credential") {
		t.Fatalf("%s", raw)
	}
	if err := driveRead(b, r.Selections[1]); err != ErrGrantQuarantined {
		t.Fatalf("after the removal: %v", err)
	}
}

// The sweep makes the owner read for every live grant with an owner, and
// applies a removal it learns of; an unanswered read changes nothing.
func TestSweepOwnerRead(t *testing.T) {
	_, _, dir, _ := driveGrant(t)
	standing := `{"standing":"current"}`
	_, cfg := ownerHost(t, &standing, revokedRemoval)
	if _, err := grantOp(t, dir, "alice", "", "owner-reads", cfg); err != nil {
		t.Fatal(err)
	}
	if _, err := grantOp(t, dir, "alice", "", "set-owner", map[string]any{"provider": "google-drive", "connection": "google-drive", "owner": owner, "ownerHost": "desk"}); err != nil {
		t.Fatal(err)
	}
	for _, k := range []struct{ standing, outcome, state string }{
		{`{"standing":"current"}`, "current", "active"},
		{`{}`, "owner-unknown", "active"},
		{`{"standing":"removed"}`, "owner-removed", "revoked"},
	} {
		standing = k.standing
		out, err := grantOp(t, dir, "alice", "", "sweep", nil)
		if raw, _ := json.Marshal(out); err != nil || !strings.Contains(string(raw), `"outcome":"`+k.outcome+`"`) {
			t.Fatalf("%s: %s %v", k.standing, raw, err)
		}
		rowOf(t, mustReport(t, dir), "google-drive", "google-drive", k.state)
	}
}

// A provider that offers revocation and does not confirm it leaves the
// report saying the grant may persist there.
func TestUnconfirmedRevocationReportsGrantMayPersist(t *testing.T) {
	b, _, dir, _ := driveGrant(t)
	failing := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Error(w, "no", 500) }))
	defer failing.Close()
	b.provider.revoke, b.provider.client = failing.URL, failing.Client()
	out, err := grantOp(t, dir, "alice", "", "revoke", map[string]any{"provider": "google-drive", "connection": "google-drive"})
	if err != nil {
		t.Fatal(err)
	}
	if raw, _ := json.Marshal(out); !strings.Contains(string(raw), `"report":"provider-grant-may-persist"`) {
		t.Fatalf("%s", raw)
	}
	row := rowOf(t, mustReport(t, dir), "google-drive", "google-drive", "revoked")
	if row.Revocation.ProviderRevoked || !hasFinding(row, providerGrantMayPersist) {
		t.Fatalf("%+v", row)
	}
}

// A disconnect revokes the grant record, and a connection made again is a
// new grant, of no owner.
func TestDisconnectRevokesRecordAndReconnectIsANewGrant(t *testing.T) {
	b, _, dir, _ := driveGrant(t)
	if _, err := grantOp(t, dir, "alice", "", "set-owner", map[string]any{"provider": "google-drive", "connection": "google-drive", "owner": owner, "ownerHost": "desk"}); err != nil {
		t.Fatal(err)
	}
	if _, err := b.Handle(context.Background(), "disconnect", []byte(`{}`)); err != nil {
		t.Fatal(err)
	}
	row := rowOf(t, mustReport(t, dir), "google-drive", "google-drive", "revoked")
	if row.Revocation.Reason != revokedDisconnected || !row.Revocation.ProviderRevoked {
		t.Fatalf("%+v", row)
	}
	choose(t, b, "file-A")
	fresh := rowOf(t, mustReport(t, dir), "google-drive", "google-drive", "active")
	if fresh.Owner != nil {
		t.Fatalf("a new grant took the earlier one's owner: %+v", fresh)
	}
}

// Malformed operator requests are refused, and nothing is written.
func TestGrantOperationRefusesMalformedRequests(t *testing.T) {
	_, _, dir, _ := driveGrant(t)
	for op, raw := range map[string]string{
		"report":          `{"x":1}`,
		"set-idle-expiry": `{"provider":"google-drive","connection":"google-drive","idleExpiry":0}`,
		"remove-owner":    `{"owner":{"kind":"person","issuer":"","subject":"s"},"ownerHost":"desk"}`,
		"owner-reads":     `{"version":1,"removal":"revoke","hosts":[{"host":"desk","url":"http://plain.example","credential":"owner-read-credential"}]}`,
		"sweep":           `[]`,
		"unknown":         `{}`,
	} {
		if _, err := GrantOperation(context.Background(), dir, "alice", "", op, []byte(raw)); err != ErrRequest {
			t.Errorf("%s %s: %v", op, raw, err)
		}
	}
	if _, err := GrantOperation(context.Background(), dir, "alice", "aws-s3", "report", nil); err != ErrRequest {
		t.Errorf("a provider without grants: %v", err)
	}
	if _, err := GrantOperation(context.Background(), "relative", "alice", "", "report", nil); err != ErrRequest {
		t.Errorf("a relative custody: %v", err)
	}
}

// A quarantined Databricks or Azure DevOps grant is refused before its
// credential is read, at a read and at a connection test alike, and its
// owner's removal reaches both providers' custody under the principal.
func TestQuarantinedNamedConnectionsAdmitNoCall(t *testing.T) {
	dir := t.TempDir()
	os.Chmod(dir, 0700)
	db, err := OpenDatabricksStore(dir, "test")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	dbb := NewDatabricks(db, false)
	defer dbb.Close()
	if err := dbConfigure(dbb, dbTokenFields()); err != nil {
		t.Fatal(err)
	}
	ado, err := OpenAzureDevOpsStore(dir, "test")
	if err != nil {
		t.Fatal(err)
	}
	defer ado.Close()
	adob := NewAzureDevOps(ado, false)
	defer adob.Close()
	if err := adoConfigure(adob, adoTokenFields()); err != nil {
		t.Fatal(err)
	}
	for _, k := range [][2]string{{"databricks", "lake"}, {"azure-devops", "board"}} {
		if _, err := grantOp(t, dir, "test", "", "set-owner", map[string]any{"provider": k[0], "connection": k[1], "owner": owner, "ownerHost": "desk"}); err != nil {
			t.Fatal(err)
		}
	}
	out, err := grantOp(t, dir, "test", "", "remove-owner", map[string]any{"owner": owner, "ownerHost": "desk", "removal": "quarantine"})
	if err != nil || len(out["connections"].([]any)) != 2 {
		t.Fatalf("%v %v", out, err)
	}
	c := dbConnection(t, db, "lake")
	if _, err := databricksSnapshot(db, c.ID, c.Revision); err != ErrGrantQuarantined {
		t.Fatalf("a Databricks read: %v", err)
	}
	if _, err := dbb.Handle(context.Background(), "test", mustJSON(map[string]string{"id": c.ID, "revision": c.Revision})); err != ErrGrantQuarantined {
		t.Fatalf("a Databricks test: %v", err)
	}
	a := adoConnection(t, ado, "board")
	if _, _, err := azureDevOpsSnapshot(ado, a.ID, a.Revision); err != ErrGrantQuarantined {
		t.Fatalf("an Azure DevOps read: %v", err)
	}
	if !bytesContain(dbState(t, dir), dbPAT) || !bytesContain(adoState(t, dir), adoPAT) {
		t.Fatal("a quarantined grant's credential was deleted")
	}
	rows, raw := grantReport(t, dir, "test")
	rowOf(t, rows, "databricks", "lake", "quarantined")
	rowOf(t, rows, "azure-devops", "board", "quarantined")
	if bytesContain(raw, dbPAT) || bytesContain(raw, adoPAT) || bytesContain(raw, dir) {
		t.Fatalf("%s", raw)
	}
}
