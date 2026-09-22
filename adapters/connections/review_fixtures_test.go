//go:build linux || darwin

package connections

// Regression fixtures adapted from the independent review of 5346eb6. Synthetic data only.

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// rotatingToken is a provider that rotates the refresh token on every use and
// refuses a superseded one, which is what "rotating refresh tokens" means.
type rotatingToken struct {
	mu      sync.Mutex
	valid   string
	n       int
	refused int
	hook    func(n int, r *http.Request) error // runs after rotation, before the reply
}

func (p *rotatingToken) RoundTrip(r *http.Request) (*http.Response, error) {
	if r.URL.Path != "/token" {
		return nil, ErrProvider
	}
	raw, _ := io.ReadAll(r.Body)
	form, _ := url.ParseQuery(string(raw))
	p.mu.Lock()
	if form.Get("refresh_token") != p.valid {
		p.refused++
		p.mu.Unlock()
		return testReply(400, `{"error":"invalid_grant"}`), nil
	}
	p.n++
	n := p.n
	p.valid = fmt.Sprintf("rotated-refresh-%d", n)
	reply := fmt.Sprintf(`{"access_token":"rotated-access-%d","refresh_token":"%s","expires_in":3600,"token_type":"Bearer","scope":"default"}`, n, p.valid)
	p.mu.Unlock()
	if p.hook != nil {
		if err := p.hook(n, r); err != nil {
			return nil, err
		}
	}
	return testReply(200, reply), nil
}

func expire(t *testing.T, b *Broker) {
	t.Helper()
	if err := b.store.locked(func(v *state) error { v.Connection.Expires = 1; return b.store.write("state.json", v) }); err != nil {
		t.Fatal(err)
	}
}
func connected(b *Broker) (ok bool, refresh string) {
	b.store.locked(func(v *state) error {
		if v.Connection != nil {
			ok, refresh = true, v.Connection.Refresh
		}
		return nil
	})
	return
}

// Control: with a truly rotating provider and no interruption, eight workers
// holding the same stale snapshot must produce exactly one refresh.
func TestReviewRotationControl(t *testing.T) {
	b, _ := notionFixture(t)
	connectNotion(t, b)
	expire(t, b)
	client, c, epoch, _ := b.connectedSnapshot()
	p := &rotatingToken{valid: "notion-private-refresh"}
	b.provider.client.Transport = p
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := b.provider.access(context.Background(), b.store, client, c, epoch); err != nil {
				t.Errorf("worker: %v", err)
			}
		}()
	}
	wg.Wait()
	ok, refresh := connected(b)
	t.Logf("CONTROL rotations=%d refused=%d connected=%v stored=%q", p.n, p.refused, ok, refresh)
	if p.n != 1 || p.refused != 0 || !ok || refresh != "rotated-refresh-1" {
		t.Fatal("control failed: rotation is not serialized even without interruption")
	}
}

func probeVault(t *testing.T) (string, *Broker, *Store) {
	t.Helper()
	vault := t.TempDir()
	os.Mkdir(filepath.Join(vault, ".obsidian"), 0700)
	dir := t.TempDir()
	os.Chmod(dir, 0700)
	s, err := OpenObsidianStore(dir, "test-person")
	if err != nil {
		t.Fatal(err)
	}
	b := NewObsidian(s, false)
	t.Cleanup(func() { b.Close(); s.Close() })
	return vault, b, s
}
func grantFor(t *testing.T, b *Broker, id string) (SourceSelection, error) {
	t.Helper()
	v, err := b.Handle(context.Background(), "search", []byte(`{"query":""}`))
	if err != nil {
		t.Fatal(err)
	}
	got, err := b.Handle(context.Background(), "select", mustJSON(map[string]any{"resourceIds": []string{id}, "selectionContext": v.(SourceSearch).SelectionContext}))
	if err != nil {
		return SourceSelection{}, err
	}
	return got.([]SourceSelection)[0], nil
}

func TestReviewObsidianConfinement(t *testing.T) {
	vault, b, s := probeVault(t)
	outside := t.TempDir()
	os.WriteFile(filepath.Join(outside, "secret.md"), []byte("OUTSIDE-SECRET"), 0600)
	os.WriteFile(filepath.Join(vault, "ok.md"), []byte("fine"), 0600)
	os.WriteFile(filepath.Join(vault, ".hidden.md"), []byte("HIDDEN-FILE"), 0600)
	os.Mkdir(filepath.Join(vault, ".trash"), 0700)
	os.WriteFile(filepath.Join(vault, ".trash", "gone.md"), []byte("TRASHED"), 0600)
	os.Mkdir(filepath.Join(vault, "sub"), 0700)
	os.Symlink(filepath.Join(outside, "secret.md"), filepath.Join(vault, "link.md"))
	os.Symlink(outside, filepath.Join(vault, "dirlink"))
	os.Symlink(filepath.Join(vault, ".obsidian"), filepath.Join(vault, "sub", "cfg"))
	os.WriteFile(filepath.Join(vault, ".obsidian", "workspace.md"), []byte("CONFIG"), 0600)
	if _, err := b.Handle(context.Background(), "configure", mustJSON(map[string]string{"path": vault})); err != nil {
		t.Fatal(err)
	}
	for _, q := range []string{"", "secret", "hidden", "trashed", "config"} {
		v, err := b.Handle(context.Background(), "search", mustJSON(map[string]string{"query": q}))
		if err != nil {
			t.Fatal(err)
		}
		for _, item := range v.(SourceSearch).Items {
			if item.ID != "ok.md" {
				t.Errorf("search %q surfaced %q", q, item.ID)
			}
			if strings.Contains(item.URL+item.Description+item.Title, vault) {
				t.Errorf("absolute path in result: %+v", item)
			}
		}
	}
	for _, id := range []string{"link.md", "dirlink/secret.md", "sub/cfg/workspace.md"} {
		sel, err := grantFor(t, b, id)
		if err != nil {
			t.Logf("select %q refused: %v", id, err)
			continue
		}
		raw, err := ReadObsidian(context.Background(), s, mustJSON(sel))
		if err == nil {
			t.Errorf("READ THROUGH SYMLINK %q: %d bytes", id, len(raw))
		} else {
			t.Logf("read %q refused: %v", id, err)
		}
	}
	for _, id := range []string{".hidden.md", ".trash/gone.md", ".obsidian/workspace.md", "ok.md/../.hidden.md", "sub/../.hidden.md", "ok.md:stream.md", "OK.MD/", "./ok.md"} {
		if _, err := grantFor(t, b, id); err == nil {
			t.Errorf("select accepted %q", id)
		}
	}
	// A FIFO must not hang a read.
	if err := mkfifo(filepath.Join(vault, "pipe.md")); err == nil {
		sel, err := grantFor(t, b, "pipe.md")
		if err == nil {
			done := make(chan error, 1)
			go func() { _, e := ReadObsidian(context.Background(), s, mustJSON(sel)); done <- e }()
			select {
			case e := <-done:
				t.Logf("fifo read refused: %v", e)
			case <-time.After(3 * time.Second):
				t.Error("FIFO read hung")
			}
		}
	}
}

func TestReviewObsidianReadBudget(t *testing.T) {
	if testing.Short() {
		t.Skip()
	}
	vault, b, _ := probeVault(t)
	block := []byte(strings.Repeat("filler text without the word\n", 36158)) // ~1 MiB
	for i := 0; i < 40; i++ {
		os.WriteFile(filepath.Join(vault, fmt.Sprintf("n%02d.md", i)), block, 0600)
	}
	if _, err := b.Handle(context.Background(), "configure", mustJSON(map[string]string{"path": vault})); err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	v, err := b.Handle(context.Background(), "search", []byte(`{"query":"zzz-needle"}`))
	if err != nil {
		t.Fatal(err)
	}
	r := v.(SourceSearch)
	t.Logf("40 x %d bytes, no match: items=%d more=%v in %v", len(block), len(r.Items), r.More, time.Since(start))
	if !r.More {
		t.Error("budget exhausted silently: more=false after an incomplete search")
	}
}
