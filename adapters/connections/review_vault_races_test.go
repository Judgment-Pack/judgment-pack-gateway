//go:build linux || darwin

package connections

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type changingNote struct {
	*os.File
	change func()
}

func (f *changingNote) Read(b []byte) (int, error) {
	n, e := f.File.Read(b)
	if f.change != nil {
		f.change()
		f.change = nil
	}
	return n, e
}

func TestVaultReadRejectsAnOverlappingEdit(t *testing.T) {
	name := filepath.Join(t.TempDir(), "note.md")
	if err := os.WriteFile(name, []byte("before"), 0600); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(name)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	changed := &changingNote{File: f, change: func() {
		if err := os.WriteFile(name, []byte("after!"), 0600); err != nil {
			t.Fatal(err)
		}
		stamp := time.Now().Add(time.Hour)
		if err := os.Chtimes(name, stamp, stamp); err != nil {
			t.Fatal(err)
		}
	}}
	if out, _, err := readVaultFile(changed, MaxFileBytes); err != ErrChanged || len(out) != 0 {
		t.Fatal("overlapping edit accepted", err)
	}
}

func TestVaultReadRefusesInVaultSymlinkComponents(t *testing.T) {
	vault, b, s := probeVault(t)
	os.WriteFile(filepath.Join(vault, "note.md"), []byte("body"), 0600)
	os.WriteFile(filepath.Join(vault, ".obsidian", "secret.md"), []byte("hidden"), 0600)
	os.Symlink(".obsidian", filepath.Join(vault, "visible"))
	b.Handle(context.Background(), "configure", mustJSON(map[string]string{"path": vault}))
	selection, err := grantFor(t, b, "visible/secret.md")
	if err != nil {
		t.Fatal(err)
	}
	if raw, err := ReadObsidian(context.Background(), s, mustJSON(selection)); err == nil || len(raw) != 0 {
		t.Fatal("in-vault symlink followed")
	}
}

func TestVaultReadRechecksDisconnectBeforePublishing(t *testing.T) {
	vault, b, s := probeVault(t)
	os.WriteFile(filepath.Join(vault, "note.md"), []byte("body"), 0600)
	b.Handle(context.Background(), "configure", mustJSON(map[string]string{"path": vault}))
	selection, err := grantFor(t, b, "note.md")
	if err != nil {
		t.Fatal(err)
	}
	snapshot := func(ctx context.Context, provider, id, title, url string, data []byte, statement any, endpoint string) ([]byte, error) {
		if _, err := b.Handle(ctx, "disconnect", []byte(`{}`)); err != nil {
			t.Fatal(err)
		}
		return sourceDocument(ctx, provider, id, title, url, data, statement, endpoint)
	}
	if raw, err := readObsidian(context.Background(), s, mustJSON(selection), snapshot); err != ErrCanceled || len(raw) != 0 {
		t.Fatal("disconnected result published", err)
	}
}

func TestCallbackCannotExchangeTwiceWhileFirstRequestRuns(t *testing.T) {
	b, _ := notionFixture(t)
	base := b.provider.client.Transport
	entered, release := make(chan struct{}), make(chan struct{})
	b.provider.client.Transport = testTransportFunc(func(r *http.Request) (*http.Response, error) {
		if r.URL.Path == "/token" {
			select {
			case <-entered:
			default:
				close(entered)
			}
			<-release
		}
		return base.RoundTrip(r)
	})
	v, err := b.Handle(context.Background(), "connect", []byte(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse(v.(FlowResult).URL)
	q := u.Query()
	f := b.active
	target := q.Get("redirect_uri") + "?" + url.Values{"state": {q.Get("state")}, "code": {"fixture-code"}}.Encode()
	done := make(chan struct{})
	defer func() { close(release); <-done }()
	go func() {
		defer close(done)
		r := httptest.NewRequest("GET", target, nil)
		b.callback(context.Background(), f, httptest.NewRecorder(), r)
	}()
	<-entered
	// A malformed code makes this second callback finish immediately even if
	// consumed is removed, isolating single-use from the final flow-state check.
	second := httptest.NewRecorder()
	r := httptest.NewRequest("GET", strings.Replace(target, "code=fixture-code", "code=", 1), nil)
	b.callback(context.Background(), f, second, r)
	if second.Code != 400 || !strings.Contains(second.Body.String(), "Authorization expired") {
		t.Fatal("callback consumed twice")
	}
}
