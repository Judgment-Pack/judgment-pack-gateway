//go:build linux || darwin

package connections

import (
	"context"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"
)

// Adapted from independent G1/G2 reproductions recorded on PR #139.
type pausedTransport func(*http.Request) (*http.Response, error)

func (f pausedTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func fakeResponse(r *http.Request, data []byte) *http.Response {
	return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(string(data))), ContentLength: int64(len(data)), Request: r}
}

func TestDisconnectInvalidatesOtherCompanionsPendingAuthorization(t *testing.T) {
	b, _, _ := testBroker(t)
	f := start(t, b, "pick")
	entered, release := make(chan struct{}), make(chan struct{})
	original := b.provider.client.Transport
	b.provider.client = &http.Client{Transport: pausedTransport(func(r *http.Request) (*http.Response, error) {
		if r.URL.Path == "/token" {
			close(entered)
			<-release
		}
		return original.RoundTrip(r)
	})}
	completed := make(chan FlowResult, 1)
	go func() { completed <- finish(t, b, f, url.Values{"picked_file_ids": {"file-A"}}) }()
	<-entered
	other := New(b.store, false)
	other.provider = b.provider
	t.Cleanup(other.Close)
	result, err := other.Handle(context.Background(), "disconnect", nil)
	close(release)
	finished := <-completed
	if err != nil || !result.(map[string]bool)["disconnected"] {
		t.Fatal(result, err)
	}
	status, err := other.Handle(context.Background(), "status", nil)
	if err != nil {
		t.Fatal(err)
	}
	if finished.State == "complete" || status.(Status).State == "connected" {
		t.Fatalf("disconnect reported %v, but earlier flow completed as %s, minted %d grants, and status became %s", result, finished.State, len(finished.Selections), status.(Status).State)
	}
}

func TestDisconnectRemainsAvailableDuringRefresh(t *testing.T) {
	b, _, _ := testBroker(t)
	f := finish(t, b, start(t, b, "pick"), url.Values{"picked_file_ids": {"file-A"}})
	if err := b.store.locked(func(v *state) error { v.Connection.Expires = 1; return b.store.write("state.json", v) }); err != nil {
		t.Fatal(err)
	}
	entered, release, done := make(chan struct{}), make(chan struct{}), make(chan error, 1)
	original := b.provider.client.Transport
	p := b.provider
	p.client = &http.Client{Transport: pausedTransport(func(r *http.Request) (*http.Response, error) {
		if r.URL.Path == "/token" {
			close(entered)
			<-release
		}
		return original.RoundTrip(r)
	})}
	go func() {
		_, err := p.read(context.Background(), b.store, mustJSON(ReadRequest{f.Selections[0].Grant, "file-A"}))
		done <- err
	}()
	<-entered
	started := time.Now()
	result, err := b.Handle(context.Background(), "disconnect", nil)
	elapsed := time.Since(started)
	close(release)
	readErr := <-done
	var stillConnected bool
	if e := b.store.locked(func(v *state) error { stillConnected = v.Connection != nil; return nil }); e != nil {
		t.Fatal(e)
	}
	if err != nil || stillConnected || readErr != ErrCanceled {
		t.Fatalf("disconnect after %v: result=%v error=%v; subsequent read error=%v; stillConnected=%v", elapsed, result, err, readErr, stillConnected)
	}
}
