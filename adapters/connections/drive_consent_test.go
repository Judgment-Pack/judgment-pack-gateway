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
	_, out["files-read"] = b.Handle(context.Background(), "files-read", mustJSON(map[string]string{"id": "file-A", "revision": "7", "context": storageContext(c, epoch)}))
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
	if e != nil || json.Unmarshal(raw, &kept) != nil || len(kept) != 4 || kept["scope"] != "https://www.googleapis.com/auth/drive" || kept["grant"] != digest([]byte("google-refresh-private")) || kept["token"] != digest([]byte("google-access-private")) {
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
			b.store.write("consent.json", consent{"another", digest([]byte("google-refresh-private")), digest([]byte("google-access-private")), driveScope})
		},
		"a record of another consent of this connection": func(b *Broker) {
			b.store.locked(func(v *state) error {
				return b.store.write("consent.json", consent{v.Connection.ID, digest([]byte("an-earlier-refresh-token")), digest([]byte(v.Connection.Access)), driveScope})
			})
		},
		"a record that is no JSON": func(b *Broker) { b.store.write("consent.json", "drive") },
		"a record of this consent with a member not known": func(b *Broker) {
			b.store.locked(func(v *state) error {
				return b.store.write("consent.json", map[string]string{"connection": v.Connection.ID, "grant": digest([]byte(v.Connection.Refresh)), "token": digest([]byte(v.Connection.Access)), "scope": driveScope, "more": "x"})
			})
		},
		"a record of this consent with a member named in another case": func(b *Broker) {
			b.store.locked(func(v *state) error {
				return b.store.write("consent.json", map[string]string{"connection": v.Connection.ID, "grant": digest([]byte(v.Connection.Refresh)), "token": digest([]byte(v.Connection.Access)), "Scope": driveScope})
			})
		},
		"a token that a consent gave since": func(b *Broker) {
			b.store.locked(func(v *state) error { v.Connection.Refresh = "narrow-refresh"; return b.store.write("state.json", v) })
		},
		"an access token another put in its place, the refresh token kept": func(b *Broker) {
			b.store.locked(func(v *state) error {
				v.Connection.Access = "of-another-consent"
				return b.store.write("state.json", v)
			})
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
			if b.store.consentedScope(*v.Connection) != driveScope || v.Connection.Expires < time.Now().Unix() || v.Connection.Access != "renewed" {
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

// A process that holds a snapshot of the connection from before another
// process renewed or remade it is not refused for that: what is held now is
// looked at, and used where its consent is recorded.
func TestSnapshotOfAnEarlierConsentTakesWhatIsHeldNow(t *testing.T) {
	b, _ := counted(t)
	if r := finish(t, b, start(t, b, "connect"), nil); r.State != "complete" {
		t.Fatal(r)
	}
	var stale credential
	var client Client
	var epoch string
	b.store.locked(func(v *state) error { stale, client, epoch = *v.Connection, v.Client, v.Epoch; return nil })
	// Another process renewed the token and was given another refresh token.
	b.store.locked(func(v *state) error {
		v.Connection.Access, v.Connection.Refresh = "renewed-elsewhere", "rotated-elsewhere"
		v.Connection.Expires = time.Now().Add(time.Hour).Unix()
		if e := b.store.write("state.json", v); e != nil {
			return e
		}
		return b.store.recordConsent(v.Connection, driveScope)
	})
	if token, e := b.provider.access(context.Background(), b.store, client, stale, epoch); e != nil || token != "renewed-elsewhere" {
		t.Errorf("under a stale snapshot: %q, %v", token, e)
	}
	// Another process connected again, and its consent was for less.
	b.store.locked(func(v *state) error {
		return b.store.recordConsent(v.Connection, "https://www.googleapis.com/auth/drive.file")
	})
	if _, e := b.provider.access(context.Background(), b.store, client, stale, epoch); e != ErrRevoked {
		t.Errorf("under a stale snapshot of a connection whose consent is now for less: %v", e)
	}
	// Another process disconnected and connected another account, whose
	// consent is recorded. The stale snapshot is not that connection.
	b.store.locked(func(v *state) error {
		v.Connection = &credential{ID: randomID(), Account: account{ID: "account-B"}, Access: "other-access", Refresh: "other-refresh", Expires: time.Now().Add(time.Hour).Unix()}
		if e := b.store.write("state.json", v); e != nil {
			return e
		}
		return b.store.recordConsent(v.Connection, driveScope)
	})
	if token, e := b.provider.access(context.Background(), b.store, client, stale, epoch); e != ErrCanceled || token != "" {
		t.Errorf("under a stale snapshot, with another connection in place: %q, %v", token, e)
	}
	// Another process disconnected.
	b.store.locked(func(v *state) error { v.Connection = nil; v.Epoch = randomID(); return b.store.write("state.json", v) })
	if _, e := b.provider.access(context.Background(), b.store, client, stale, epoch); e != ErrCanceled {
		t.Errorf("under a stale snapshot of a connection that is gone: %v", e)
	}
}

// A consent that gives no refresh token of its own keeps the earlier one only
// where that one is recorded as of the whole Drive. A connection made before
// the record, consenting again, is refused where Google gives no refresh
// token, and connects where it does.
func TestReconnectKeepsAnEarlierRefreshTokenOnlyWhereItIsRecorded(t *testing.T) {
	for name, example := range map[string]struct {
		recorded bool
		refresh  string
		state    string
	}{
		"recorded, and no refresh token given":     {true, "", "complete"},
		"not recorded, and no refresh token given": {false, "", "failed"},
		"not recorded, and a refresh token given":  {false, "a-new-refresh", "complete"},
	} {
		b, _ := counted(t)
		if r := finish(t, b, start(t, b, "connect"), nil); r.State != "complete" {
			t.Fatal(r)
		}
		if !example.recorded {
			b.store.root.Remove("consent.json")
		}
		inner := b.provider.client.Transport
		reply := map[string]any{"access_token": "again", "expires_in": 3600, "token_type": "Bearer", "scope": driveScope}
		if example.refresh != "" {
			reply["refresh_token"] = example.refresh
		}
		raw, _ := json.Marshal(reply)
		// Drive answers under the new token what the other tests' Drive
		// answers under the first.
		b.provider.client = &http.Client{Transport: pausedTransport(func(r *http.Request) (*http.Response, error) {
			switch {
			case r.URL.Path == "/token":
				return fakeResponse(r, raw), nil
			case r.URL.Path == "/about":
				return fakeResponse(r, []byte(`{"user":{"permissionId":"account-A","emailAddress":"person@example.test","displayName":"Person"}}`)), nil
			case r.URL.Path == "/files/file-A" && r.URL.Query().Get("alt") == "media":
				return fakeResponse(r, []byte("A test policy document.")), nil
			case r.URL.Path == "/files/file-A":
				return fakeResponse(r, []byte(`{"id":"file-A","name":"policy.txt","mimeType":"text/plain","version":"7","size":"23","capabilities":{"canDownload":true}}`)), nil
			}
			return inner.RoundTrip(r)
		})}
		r := finish(t, b, start(t, b, "connect"), nil)
		if r.State != example.state || (r.State == "failed" && r.Error != "reconnect-required") {
			t.Errorf("%s: %+v", name, r)
		}
		b.store.locked(func(v *state) error {
			switch {
			case r.State == "complete" && (v.Connection.Access != "again" || b.store.consentedScope(*v.Connection) != driveScope):
				t.Errorf("%s: the connection is not as the consent gave it, or is not recorded", name)
			case r.State == "complete" && example.refresh != "" && v.Connection.Refresh != example.refresh:
				t.Errorf("%s: the refresh token given was not kept", name)
			case r.State == "complete" && example.refresh == "" && v.Connection.Refresh != "google-refresh-private":
				t.Errorf("%s: the earlier refresh token was not kept", name)
			case r.State == "failed" && v.Connection.Access != "google-access-private":
				t.Errorf("%s: a refused consent changed the connection", name)
			}
			return nil
		})
		for use, e := range everyUse(t, b) {
			if r.State == "complete" && e != nil || r.State == "failed" && e != ErrRevoked {
				t.Errorf("%s: %s afterwards: %v", name, use, e)
			}
		}
	}
}

// A renewal that finds another process's newer token in place uses it only
// where that token's consent is recorded: one written without its record, as
// by a process that ended between the two writes, is refused.
func TestRenewalTakesAnotherProcessTokenOnlyWhereItIsRecorded(t *testing.T) {
	for name, recorded := range map[string]bool{"the other process recorded its token": true, "the other process ended before recording it": false} {
		b, _ := counted(t)
		if r := finish(t, b, start(t, b, "connect"), nil); r.State != "complete" {
			t.Fatal(r)
		}
		b.store.locked(func(v *state) error { v.Connection.Expires = 1; return b.store.write("state.json", v) })
		inner := b.provider.client.Transport
		b.provider.client = &http.Client{Transport: pausedTransport(func(r *http.Request) (*http.Response, error) {
			if r.URL.Path == "/token" {
				// While this renewal is with Google, another process renews.
				b.store.locked(func(v *state) error {
					v.Connection.Access, v.Connection.Expires = "of-the-other", time.Now().Add(time.Hour).Unix()
					if e := b.store.write("state.json", v); e != nil {
						return e
					}
					if recorded {
						return b.store.recordConsent(v.Connection, driveScope)
					}
					return nil
				})
				return fakeResponse(r, []byte(`{"access_token":"of-this-one","expires_in":3600,"token_type":"Bearer","scope":"https://www.googleapis.com/auth/drive"}`)), nil
			}
			return inner.RoundTrip(r)
		})}
		var c credential
		var client Client
		var epoch string
		b.store.locked(func(v *state) error { c, client, epoch = *v.Connection, v.Client, v.Epoch; return nil })
		token, e := b.provider.access(context.Background(), b.store, client, c, epoch)
		if recorded && (e != nil || token != "of-the-other") || !recorded && (e != ErrRevoked || token != "") {
			t.Errorf("%s: %q, %v", name, token, e)
		}
		b.store.locked(func(v *state) error {
			if v.Connection.Access != "of-the-other" {
				t.Errorf("%s: the other process's token was written over", name)
			}
			return nil
		})
	}
}

// A commit that finds the connection without a record of its consent asks
// Drive nothing, and leaves the plan prepared for a commit after the person
// connects again.
func TestCommitWithoutARecordedConsentLeavesThePlanPrepared(t *testing.T) {
	b, asked := counted(t)
	if r := finish(t, b, start(t, b, "connect"), nil); r.State != "complete" {
		t.Fatal(r)
	}
	var c credential
	var epoch string
	b.store.locked(func(v *state) error { c, epoch = *v.Connection, v.Epoch; return nil })
	plan, e := b.Handle(context.Background(), "files-prepare", mustJSON(StorageChange{Context: storageContext(c, epoch), Action: "create", Name: "a.txt", MediaType: "text/plain", Content: "YQ=="}))
	if e != nil {
		t.Fatal(e)
	}
	b.store.root.Remove("consent.json")
	before := *asked
	if _, e := b.Handle(context.Background(), "files-commit", mustJSON(map[string]string{"id": plan.(StoragePlan).ID})); e != ErrRevoked {
		t.Errorf("the commit was answered %v", e)
	}
	if *asked != before {
		t.Error("the commit asked Drive")
	}
	if status, e := b.Handle(context.Background(), "files-status", mustJSON(map[string]string{"id": plan.(StoragePlan).ID})); e != nil || status.(StoragePlan).State != "prepared" {
		t.Errorf("the plan is %+v, %v", status, e)
	}
}

// A renewal that Google refuses, because another process's renewal was given
// another refresh token in the meantime, takes what that process holds where
// it is good and recorded. Refused for any other reason, it is refused.
func TestRenewalRefusedAfterAnotherProcessRenewedTakesItsToken(t *testing.T) {
	for name, example := range map[string]struct {
		other    func(v *state) error
		recorded bool
		token    string
		err      error
	}{
		"another renewed, with another refresh token": {func(v *state) error {
			v.Connection.Access, v.Connection.Refresh, v.Connection.Expires = "of-the-other", "rotated", time.Now().Add(time.Hour).Unix()
			return nil
		}, true, "of-the-other", nil},
		"another renewed, and did not record it": {func(v *state) error {
			v.Connection.Access, v.Connection.Refresh, v.Connection.Expires = "of-the-other", "rotated", time.Now().Add(time.Hour).Unix()
			return nil
		}, false, "", ErrRevoked},
		"another renewed, but its token has run out": {func(v *state) error {
			v.Connection.Access, v.Connection.Refresh, v.Connection.Expires = "of-the-other", "rotated", 1
			return nil
		}, true, "", ErrRevoked},
		"no one renewed: Google refused the token": {func(v *state) error { return nil }, true, "", ErrRevoked},
		"another renewed, with the same refresh token": {func(v *state) error {
			v.Connection.Access, v.Connection.Expires = "of-the-other", time.Now().Add(time.Hour).Unix()
			return nil
		}, true, "of-the-other", nil},
		"another connected another account": {func(v *state) error {
			v.Connection = &credential{ID: randomID(), Account: account{ID: "account-B"}, Access: "of-another-account", Refresh: "other", Expires: time.Now().Add(time.Hour).Unix()}
			return nil
		}, true, "", ErrRevoked},
		"another disconnected": {func(v *state) error { v.Connection = nil; v.Epoch = randomID(); return nil }, false, "", ErrRevoked},
	} {
		b, _ := counted(t)
		if r := finish(t, b, start(t, b, "connect"), nil); r.State != "complete" {
			t.Fatal(r)
		}
		b.store.locked(func(v *state) error { v.Connection.Expires = 1; return b.store.write("state.json", v) })
		inner := b.provider.client.Transport
		b.provider.client = &http.Client{Transport: pausedTransport(func(r *http.Request) (*http.Response, error) {
			if r.URL.Path == "/token" {
				b.store.locked(func(v *state) error {
					if e := example.other(v); e != nil {
						return e
					}
					if e := b.store.write("state.json", v); e != nil {
						return e
					}
					if example.recorded && v.Connection != nil {
						return b.store.recordConsent(v.Connection, driveScope)
					}
					return nil
				})
				res := fakeResponse(r, []byte(`{"error":"invalid_grant"}`))
				res.StatusCode = 400
				return res, nil
			}
			return inner.RoundTrip(r)
		})}
		var c credential
		var client Client
		var epoch string
		b.store.locked(func(v *state) error { c, client, epoch = *v.Connection, v.Client, v.Epoch; return nil })
		token, e := b.provider.access(context.Background(), b.store, client, c, epoch)
		if e != example.err || token != example.token {
			t.Errorf("%s: %q, %v", name, token, e)
		}
	}
}
