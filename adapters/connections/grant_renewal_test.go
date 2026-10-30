//go:build linux || darwin

package connections

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"
)

// N6a: the state is read again once a token is held after a renewal, on
// every renewal path: another process's renewal taken in place of a failed
// one, and Notion's.

// ownedQuarantinable gives the grant an owner whose issuing host answers
// current, so that a removal can quarantine it.
func ownedQuarantinable(t *testing.T, dir, principal, provider, connection string) {
	t.Helper()
	standing := `{"standing":"current"}`
	_, cfg := ownerHost(t, &standing, quarantineRemoval)
	if _, err := grantOp(t, dir, principal, "", "owner-reads", cfg); err != nil {
		t.Fatal(err)
	}
	if _, err := grantOp(t, dir, principal, "", "set-owner", map[string]any{"provider": provider, "connection": connection, "owner": owner, "ownerHost": "desk"}); err != nil {
		t.Fatal(err)
	}
}

func quarantine(t *testing.T, dir, principal string) {
	if _, err := GrantOperation(context.Background(), dir, principal, "", "remove-owner", mustJSON(map[string]any{"owner": owner, "ownerHost": "desk", "removal": "quarantine"})); err != nil {
		t.Error(err)
	}
}

func TestQuarantineDuringAnotherProcessRenewalRefusesTheCall(t *testing.T) {
	b, count, dir, r := driveGrant(t)
	ownedQuarantinable(t, dir, "alice", "google-drive", "google-drive")
	if err := b.store.locked(func(v *state) error { v.Connection.Expires = 1; return b.store.write("state.json", v) }); err != nil {
		t.Fatal(err)
	}
	// This renewal fails: another process renewed first, and the grant is
	// quarantined meanwhile.
	renewal := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := b.store.locked(func(v *state) error {
			v.Connection.Access, v.Connection.Refresh, v.Connection.Expires = "google-access-private", "renewed-elsewhere", time.Now().Add(time.Hour).Unix()
			if err := b.store.write("state.json", v); err != nil {
				return err
			}
			return b.store.recordConsent(v.Connection, driveScope)
		}); err != nil {
			t.Error(err)
		}
		quarantine(t, dir, "alice")
		http.Error(w, `{"error":"invalid_grant"}`, 400)
	}))
	defer renewal.Close()
	b.provider.token = renewal.URL
	inner := b.provider.client
	b.provider.client = &http.Client{Transport: testTransportFunc(func(req *http.Request) (*http.Response, error) {
		if req.URL.Host == renewal.Listener.Addr().String() {
			return renewal.Client().Transport.RoundTrip(req)
		}
		return inner.Transport.RoundTrip(req)
	}), CheckRedirect: inner.CheckRedirect}
	if err := driveRead(b, r.Selections[0]); err != ErrGrantQuarantined {
		t.Fatalf("a read whose renewal another process made while the grant was quarantined: %v", err)
	}
	if count.Load() != 0 {
		t.Fatal("the file was asked for")
	}
}

func TestQuarantineDuringNotionRenewalRefusesTheCall(t *testing.T) {
	b, _ := notionFixture(t)
	connectNotion(t, b)
	dir := filepath.Dir(filepath.Dir(b.store.root.Name()))
	ownedQuarantinable(t, dir, "test-person", "notion", "notion")
	b.store.locked(func(v *state) error { v.Connection.Expires = 1; return b.store.write("state.json", v) })
	client, c, epoch, err := b.connectedSnapshot()
	if err != nil {
		t.Fatal(err)
	}
	b.provider.client.Transport = testTransportFunc(func(r *http.Request) (*http.Response, error) {
		quarantine(t, dir, "test-person")
		return testReply(200, `{"access_token":"notion-renewed","refresh_token":"notion-refresh-renewed","expires_in":3600,"token_type":"Bearer"}`), nil
	})
	if _, err := b.provider.access(context.Background(), b.store, client, c, epoch); err != ErrGrantQuarantined {
		t.Fatalf("a Notion renewal during which the grant was quarantined: %v", err)
	}
}
