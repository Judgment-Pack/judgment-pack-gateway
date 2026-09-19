//go:build linux || darwin

package connections

import (
	"context"
	"net/url"
	"testing"
)

func TestPublisherClientAllowsOAuthWithoutConfigure(t *testing.T) {
	for _, gmail := range []bool{false, true} {
		t.Run(map[bool]string{false: "drive", true: "gmail"}[gmail], func(t *testing.T) {
			s := testStore(t, "publisher-test")
			if err := s.EnsureClient(Client{"publisher.apps.googleusercontent.com", "publisher-secret"}); err != nil {
				t.Fatal(err)
			}
			b := New(s, false)
			if gmail {
				b = NewGmail(s, false)
			}
			defer b.Close()
			status, err := b.Handle(context.Background(), "status", nil)
			if err != nil || status.(Status).State != "not-connected" {
				t.Fatal("publisher default did not become connectable")
			}
			f := start(t, b, "connect")
			u, err := url.Parse(f.URL)
			if err != nil {
				t.Fatal(err)
			}
			q := u.Query()
			if u.Host != "accounts.google.com" || q.Get("client_id") != "publisher.apps.googleusercontent.com" || q.Get("client_secret") != "" || q.Get("code_challenge_method") != "S256" || q.Get("scope") != b.provider.scope() {
				t.Fatal("publisher authorization changed its Google/PKCE/scope boundary or exposed a secret")
			}
			before, err := s.read("state.json")
			if err != nil {
				t.Fatal(err)
			}
			// A later build must not silently switch an installed registration or
			// invalidate a flow opened by another companion.
			if err := s.EnsureClient(Client{"upgrade.apps.googleusercontent.com", "different"}); err != nil {
				t.Fatal(err)
			}
			after, err := s.read("state.json")
			if err != nil || string(before) != string(after) {
				t.Fatal("existing client or epoch was replaced")
			}
		})
	}
}

func TestPublisherClientPreservesExistingConsentAndConfiguration(t *testing.T) {
	b, _, _ := testBroker(t)
	finish(t, b, start(t, b, "pick"), url.Values{"picked_file_ids": {"file-A"}})
	before, err := b.store.read("state.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := b.store.EnsureClient(Client{"publisher.apps.googleusercontent.com", "publisher-secret"}); err != nil {
		t.Fatal(err)
	}
	after, err := b.store.read("state.json")
	if err != nil || string(before) != string(after) {
		t.Fatal("existing registration or account tokens changed")
	}
}

func TestPublisherClientDoesNotRepairInvalidPrivateState(t *testing.T) {
	s := testStore(t, "publisher-test")
	if err := s.write("state.json", map[string]any{"unknown": "state"}); err != nil {
		t.Fatal(err)
	}
	if err := s.EnsureClient(Client{"publisher.apps.googleusercontent.com", "publisher-secret"}); err != ErrStorage {
		t.Fatal("invalid private state was overwritten")
	}
	if err := s.EnsureClient(Client{"invalid", "private"}); err != ErrRequest {
		t.Fatal("invalid publisher client was accepted")
	}
}

func TestPublisherClientDoesNotClearPersistedPolicy(t *testing.T) {
	s := testStore(t, "publisher-test")
	if err := s.write("state.json", state{Disabled: true}); err != nil {
		t.Fatal(err)
	}
	if err := s.EnsureClient(Client{"publisher.apps.googleusercontent.com", ""}); err != nil {
		t.Fatal(err)
	}
	if err := s.locked(func(v *state) error {
		if !v.Disabled {
			t.Fatal("publisher registration cleared operator policy")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	b := New(s, true)
	defer b.Close()
	status, err := b.Handle(context.Background(), "status", nil)
	if err != nil || status.(Status).State != "blocked" {
		t.Fatal("publisher default bypassed disabled connections")
	}
	if _, err := b.Handle(context.Background(), "connect", nil); err != ErrPolicy {
		t.Fatal("disabled publisher connection started OAuth")
	}
}
