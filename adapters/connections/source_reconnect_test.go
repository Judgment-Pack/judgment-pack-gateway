//go:build linux || darwin

package connections

import (
	"context"
	"net/http"
	"path/filepath"
	"testing"
	"time"
)

// Exercise actual connect -> token exchange -> account verification -> callback
// commit. Identical provider tokens on both consents ensure invalidation cannot
// accidentally depend on token-byte changes rather than interactive reconsent.
func TestSourceBindingsAreRevokedByActualSameAccountReconnect(t *testing.T) {
	b, _, _ := testBroker(t)
	selected := choose(t, b, "file-A")
	if selected.State != "complete" {
		t.Fatal(selected)
	}
	body := sourceBindBody(t, b, randomID())
	out, err := b.Handle(context.Background(), "source-bind", mustJSON(body))
	if err != nil {
		t.Fatal(err)
	}
	binding := out.(SourceBinding)
	_, before, epoch, err := b.connectedSnapshot()
	if err != nil {
		t.Fatal(err)
	}
	if result := finish(t, b, start(t, b, "connect"), nil); result.State != "complete" {
		t.Fatal(result)
	}
	_, after, afterEpoch, err := b.connectedSnapshot()
	if err != nil || before.ID != after.ID || epoch != afterEpoch || before.Refresh != after.Refresh {
		t.Fatal("reconsent changed legacy picker/storage identity", after, afterEpoch, err)
	}
	if out, err := b.Handle(context.Background(), "source-observe", mustJSON(map[string]string{"bindingId": binding.BindingID})); out != nil || err != ErrSourceBinding {
		t.Fatal("old recurring grant survived real callback", out, err)
	}
	recovered, err := b.Handle(context.Background(), "source-bind", mustJSON(body))
	if err != nil || recovered.(SourceBinding).BindingID != binding.BindingID || recovered.(SourceBinding).State != "revoked" {
		t.Fatal("uncertain retry restored old consent", recovered, err)
	}
	listed, err := b.Handle(context.Background(), "source-bindings", []byte(`{}`))
	if err != nil || len(listed.(SourceBindings).Bindings) != 1 || listed.(SourceBindings).Bindings[0].State != "revoked" {
		t.Fatal(listed, err)
	}
	// Existing picker grants and storage reads retain their established
	// same-account reconsent behavior; only recurring authority is invalidated.
	if _, err := b.provider.read(context.Background(), b.store, mustJSON(ReadRequest{selected.Selections[0].Grant, "file-A"})); err != nil {
		t.Fatal("one-use picker grant regressed", err)
	}
	if _, err := b.Handle(context.Background(), "files-read", mustJSON(map[string]string{"id": "file-A", "revision": "7", "context": storageContext(before, epoch)})); err != nil {
		t.Fatal("existing storage context regressed", err)
	}
	fresh := bindSource(t, b)
	if fresh.BindingID == binding.BindingID || fresh.State != "active" {
		t.Fatal(fresh)
	}
	observeSource(t, b, fresh.BindingID)
}

func TestSourceObservationInFlightFailsAfterActualSameAccountCallback(t *testing.T) {
	b, _, _ := testBroker(t)
	if result := finish(t, b, start(t, b, "connect"), nil); result.State != "complete" {
		t.Fatal(result)
	}
	binding := bindSource(t, b)
	s, err := OpenStore(filepath.Dir(b.store.root.Name()), "alice")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	reader := New(s, false)
	defer reader.Close()
	reader.provider = b.provider
	entered, release := make(chan struct{}), make(chan struct{})
	prior := reader.provider.client.Transport
	reader.provider.client = &http.Client{Transport: sourceTransport(func(r *http.Request) (*http.Response, error) {
		if r.URL.Query().Get("alt") == "media" {
			close(entered)
			<-release
		}
		return prior.RoundTrip(r)
	})}
	type result struct {
		out any
		err error
	}
	done := make(chan result, 1)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	go func() {
		out, err := reader.Handle(ctx, "source-observe", mustJSON(map[string]string{"bindingId": binding.BindingID}))
		done <- result{out, err}
	}()
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("read did not reach provider I/O")
	}
	completed := finish(t, b, start(t, b, "connect"), nil)
	close(release)
	if completed.State != "complete" {
		t.Fatal(completed)
	}
	select {
	case result := <-done:
		if result.out != nil || result.err != ErrSourceBinding {
			t.Fatal("in-flight old consent survived actual callback", result)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("read did not finish")
	}
}

func TestSourceBindingSurvivesOrdinaryAccessTokenRefresh(t *testing.T) {
	b, _, _ := sourceBroker(t)
	binding := bindSource(t, b)
	if err := b.store.locked(func(v *state) error { v.Connection.Expires = 0; return b.store.write("state.json", v) }); err != nil {
		t.Fatal(err)
	}
	b.provider.client.Transport = sourceTransport(func(r *http.Request) (*http.Response, error) {
		if r.Method == "POST" {
			return sourceReply(200, `{"access_token":"renewed-access","refresh_token":"renewed-refresh","expires_in":3600,"token_type":"Bearer"}`), nil
		}
		if r.Header.Get("Authorization") != "Bearer renewed-access" {
			t.Error("renewed token not used")
		}
		if r.URL.Query().Get("alt") == "media" {
			return sourceReply(200, "A test policy document."), nil
		}
		return sourceReply(200, `{"id":"file-A","name":"policy.txt","mimeType":"text/plain","version":"7","size":"23","capabilities":{"canDownload":true}}`), nil
	})
	observeSource(t, b, binding.BindingID)
	listed, err := b.Handle(context.Background(), "source-bindings", []byte(`{}`))
	if err != nil || len(listed.(SourceBindings).Bindings) != 1 || listed.(SourceBindings).Bindings[0].State != "active" {
		t.Fatal("routine refresh revoked recurring consent", listed, err)
	}
}
