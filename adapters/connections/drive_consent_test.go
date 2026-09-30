//go:build linux || darwin

package connections

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"
)

// counted is a broker whose every request of the provider is counted, and
// answered as the broker of the other tests answers.
func counted(t *testing.T) (*Broker, *int) {
	t.Helper()
	b, _, _ := testBroker(t)
	n := new(int)
	inner := b.provider.client.Transport
	b.provider.client = &http.Client{Transport: pausedTransport(func(r *http.Request) (*http.Response, error) {
		*n++
		if r.URL.Path == "/files" {
			return fakeResponse(r, []byte(`{"files":[]}`)), nil
		}
		if r.URL.Path == "/files/generateIds" {
			return fakeResponse(r, []byte(`{"ids":["file-new"]}`)), nil
		}
		return inner.RoundTrip(r)
	})}
	return b, n
}

// everyUse asks of a connection everything that needs the provider, and
// gives what each was answered.
func everyUse(t *testing.T, b *Broker) map[string]error {
	t.Helper()
	out := map[string]error{}
	_, out["search"] = b.Handle(context.Background(), "search", []byte(`{"query":"words"}`))
	_, out["files-list"] = b.Handle(context.Background(), "files-list", mustJSON(StorageQuery{}))
	var c credential
	var epoch string
	b.store.locked(func(v *state) error { c, epoch = *v.Connection, v.Epoch; return nil })
	_, out["files-prepare"] = b.Handle(context.Background(), "files-prepare", mustJSON(StorageChange{Context: storageContext(c, epoch), Action: "create", Name: "a.txt", MediaType: "text/plain", Content: "YQ=="}))
	picked, e := b.Handle(context.Background(), "select", mustJSON(map[string]any{"resourceIds": []string{"file-A"}, "selectionContext": epoch}))
	if e != nil {
		t.Fatal(e)
	}
	_, out["read"] = b.provider.read(context.Background(), b.store, mustJSON(ReadRequest{picked.([]SourceSelection)[0].Grant, "file-A"}))
	return out
}

// A connection made through the consent has it recorded what the consent
// was for, beside the state, and the state is what it was.
func TestConsentIsRecordedBesideTheState(t *testing.T) {
	b, _ := counted(t)
	if r := finish(t, b, start(t, b, "connect"), nil); r.State != "complete" {
		t.Fatal(r)
	}
	raw, e := b.store.read("consent.json")
	var kept map[string]string
	if e != nil || json.Unmarshal(raw, &kept) != nil || len(kept) != 3 || kept["scope"] != "https://www.googleapis.com/auth/drive" || kept["grant"] != digest([]byte("google-refresh-private")) {
		t.Fatalf("the record is %v, %v", len(kept), e)
	}
	b.store.locked(func(v *state) error {
		if kept["connection"] != v.Connection.ID {
			t.Error("the record is of another connection")
		}
		return nil
	})
	raw, _ = b.store.read("state.json")
	var written struct {
		Connection map[string]any `json:"connection"`
	}
	if json.Unmarshal(raw, &written) != nil || len(written.Connection) != 5 {
		t.Errorf("the state's connection has %d members, and an earlier release reads five", len(written.Connection))
	}
	for use, e := range everyUse(t, b) {
		if e != nil {
			t.Errorf("%s under a recorded consent: %v", use, e)
		}
	}
}

// A connection without a record of a consent for the whole Drive is asked
// for again from its first use, whatever its token, and the provider is
// asked nothing under it.
func TestConnectionWithoutARecordedConsentIsAskedForAgain(t *testing.T) {
	for name, unrecord := range map[string]func(b *Broker){
		"made before the record, no record at all": func(b *Broker) { b.store.root.Remove("consent.json") },
		"a record of another scope": func(b *Broker) {
			b.store.locked(func(v *state) error {
				return b.store.recordConsent(v.Connection, "https://www.googleapis.com/auth/drive.file")
			})
		},
		"a record of no scope": func(b *Broker) {
			b.store.locked(func(v *state) error { return b.store.recordConsent(v.Connection, "") })
		},
		"a record of another connection": func(b *Broker) {
			b.store.write("consent.json", consent{"another", digest([]byte("google-refresh-private")), driveScope})
		},
		"a record of another consent of this connection": func(b *Broker) {
			b.store.locked(func(v *state) error {
				return b.store.write("consent.json", consent{v.Connection.ID, digest([]byte("an-earlier-refresh-token")), driveScope})
			})
		},
		"a record that is no JSON": func(b *Broker) { b.store.write("consent.json", "drive") },
		"a record of this consent with a member not known": func(b *Broker) {
			b.store.locked(func(v *state) error {
				return b.store.write("consent.json", map[string]string{"connection": v.Connection.ID, "grant": digest([]byte(v.Connection.Refresh)), "scope": driveScope, "more": "x"})
			})
		},
		"a record of this consent with a member named in another case": func(b *Broker) {
			b.store.locked(func(v *state) error {
				return b.store.write("consent.json", map[string]string{"connection": v.Connection.ID, "grant": digest([]byte(v.Connection.Refresh)), "Scope": driveScope})
			})
		},
		"a token that a consent gave since": func(b *Broker) {
			b.store.locked(func(v *state) error { v.Connection.Refresh = "narrow-refresh"; return b.store.write("state.json", v) })
		},
	} {
		for _, expired := range []bool{false, true} {
			b, asked := counted(t)
			if r := finish(t, b, start(t, b, "connect"), nil); r.State != "complete" {
				t.Fatal(r)
			}
			unrecord(b)
			if expired {
				b.store.locked(func(v *state) error { v.Connection.Expires = 1; return b.store.write("state.json", v) })
			}
			before := *asked
			for use, e := range everyUse(t, b) {
				if e != ErrRevoked {
					t.Errorf("%s, expired %v: %s was answered %v", name, expired, use, e)
				}
			}
			if *asked != before {
				t.Errorf("%s, expired %v: the provider was asked %d times", name, expired, *asked-before)
			}
			status, e := b.Handle(context.Background(), "status", nil)
			if e != nil || status.(Status).State != "connected" {
				t.Errorf("%s: status says %v", name, status)
			}
			// To connect again is what puts it right.
			if r := finish(t, b, start(t, b, "connect"), nil); r.State != "complete" {
				t.Fatalf("%s: connecting again: %+v", name, r)
			}
			for use, e := range everyUse(t, b) {
				if e != nil {
					t.Errorf("%s: %s after connecting again: %v", name, use, e)
				}
			}
		}
	}
}

// A renewal that does not say what scope its token is of is taken for a
// connection whose consent is recorded. A renewal that gives another refresh
// token leaves the record in step with it.
func TestRenewalKeepsTheRecordInStep(t *testing.T) {
	for name, reply := range map[string]string{
		"a renewal that names no scope":              `{"access_token":"renewed","expires_in":3600,"token_type":"Bearer"}`,
		"a renewal that gives another refresh token": `{"access_token":"renewed","refresh_token":"another-refresh","expires_in":3600,"token_type":"Bearer","scope":"https://www.googleapis.com/auth/drive"}`,
	} {
		b, _, _ := testBroker(t)
		if r := finish(t, b, start(t, b, "connect"), nil); r.State != "complete" {
			t.Fatal(r)
		}
		b.store.locked(func(v *state) error { v.Connection.Expires = 1; return b.store.write("state.json", v) })
		inner := b.provider.client.Transport
		var tokens []string
		b.provider.client = &http.Client{Transport: pausedTransport(func(r *http.Request) (*http.Response, error) {
			if r.URL.Path == "/token" {
				return fakeResponse(r, []byte(reply)), nil
			}
			if r.URL.Path == "/files" {
				tokens = append(tokens, r.Header.Get("Authorization"))
				return fakeResponse(r, []byte(`{"files":[]}`)), nil
			}
			return inner.RoundTrip(r)
		})}
		for i := 0; i < 2; i++ {
			if _, e := b.Handle(context.Background(), "search", []byte(`{"query":"words"}`)); e != nil {
				t.Fatalf("%s, search %d: %v", name, i+1, e)
			}
		}
		if len(tokens) != 2 || tokens[0] != "Bearer renewed" || tokens[1] != "Bearer renewed" {
			t.Errorf("%s: Drive was asked under %v", name, tokens)
		}
		b.store.locked(func(v *state) error {
			if b.store.consentedScope(*v.Connection) != driveScope || v.Connection.Expires < time.Now().Unix() {
				t.Errorf("%s: the record is not of the connection as it is kept", name)
			}
			return nil
		})
	}
}

// To disconnect removes the record with the connection.
func TestDisconnectRemovesTheRecord(t *testing.T) {
	b, _ := counted(t)
	if r := finish(t, b, start(t, b, "connect"), nil); r.State != "complete" {
		t.Fatal(r)
	}
	if _, e := b.Handle(context.Background(), "disconnect", nil); e != nil {
		t.Fatal(e)
	}
	if _, e := b.store.read("consent.json"); e == nil {
		t.Error("the record of a connection that is gone is kept")
	}
}
