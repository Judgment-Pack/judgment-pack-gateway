//go:build linux || darwin

package connections

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Regression cases from the independent Codex clean-room review.
func TestStorageDriveStatusDoesNotRefresh(t *testing.T) {
	s := testStore(t, "cr-drive-status")
	calls := 0
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.WriteHeader(503)
	}))
	defer srv.Close()
	b := New(s, false)
	defer b.Close()
	b.provider.client = srv.Client()
	b.provider.token = srv.URL
	s.locked(func(v *state) error {
		v.Epoch = "epoch"
		v.Connection = &credential{ID: "connection", Refresh: "refresh", Access: "expired", Expires: time.Now().Add(-time.Hour).Unix()}
		return s.write("state.json", v)
	})
	id := randomID()
	if err := s.writeStorageIntent(storageIntent{Plan: StoragePlan{ID: id, State: "completed"}, Connection: "connection", Epoch: "epoch"}); err != nil {
		t.Fatal(err)
	}
	out, err := b.Handle(context.Background(), "files-status", mustJSON(map[string]string{"id": id}))
	if err != nil || out == nil || calls != 0 {
		t.Fatalf("local status must not contact provider: out=%v err=%v calls=%d", out, err, calls)
	}
	t.Logf("local completed status available; provider requests=%d", calls)
}

func TestStorageCorruptPriorClaimIsPreserved(t *testing.T) {
	b, vault := storageVaultFixture(t)
	q := change("create", "", "", "old")
	q.Name = "old.txt"
	old := storageCall[StoragePlan](t, b, "files-prepare", q)
	intent, err := b.store.readStorageIntent()
	if err != nil {
		t.Fatal(err)
	}
	intent.Plan.State = "executing"
	if err = b.store.writeStorageIntent(intent); err != nil {
		t.Fatal(err)
	}
	// An unreadable durable claim must not be treated as proof of no execution.
	f, err := b.store.root.OpenFile("storage-intent.json", os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.Write([]byte(`{"plan":`)); err != nil {
		t.Fatal(err)
	}
	f.Close()
	if _, err = b.store.readStorageIntent(); !errors.Is(err, ErrStorage) {
		t.Fatal(err)
	}
	q.Name = "new.txt"
	_, err = b.Handle(context.Background(), "files-prepare", storageJSON(t, b, "files-prepare", q))
	if err != ErrStorage {
		t.Fatalf("corrupt record replaced: %v", err)
	}
	if _, err = os.Stat(filepath.Join(vault, "new.txt")); !os.IsNotExist(err) {
		t.Fatal("new file exists", err)
	}
	_ = old

}

func TestStorageDeleteRejectsSameStatReplacement(t *testing.T) {
	b, vault := storageVaultFixture(t)
	name := filepath.Join(vault, "chosen.txt")
	if err := os.WriteFile(name, []byte("old content"), 0600); err != nil {
		t.Fatal(err)
	}
	st, _ := os.Stat(name)
	page := storageCall[StoragePage](t, b, "files-list", StorageQuery{})
	if _, err := b.Handle(context.Background(), "files-prepare", storageJSON(t, b, "files-prepare", StorageChange{Action: "delete", ID: "chosen.txt", Revision: page.Items[0].Revision})); err != ErrChanged {
		t.Fatal("metadata-only delete admitted", err)
	}
	read := storageCall[StorageRead](t, b, "files-read", map[string]string{"id": "chosen.txt", "revision": page.Items[0].Revision})
	plan := storageCall[StoragePlan](t, b, "files-prepare", StorageChange{Action: "delete", ID: "chosen.txt", Revision: read.File.Revision})
	replacement := filepath.Join(vault, "replacement.txt")
	if err := os.WriteFile(replacement, []byte("NEW CONTENT"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(replacement, st.ModTime(), st.ModTime()); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(replacement, name); err != nil {
		t.Fatal(err)
	}
	done := storageCall[StoragePlan](t, b, "files-commit", map[string]string{"id": plan.ID, "confirmation": "chosen.txt"})
	data, err := os.ReadFile(name)
	if err != nil || done.State != "refused" || done.Error != "source-changed" || string(data) != "NEW CONTENT" {
		t.Fatalf("done=%+v data=%q err=%v", done, data, err)
	}
	t.Log("replacement remains untouched")
}

func TestStorageS3RejectsHeaderSecretReflection(t *testing.T) {
	f := testS3(t)
	f.configure()
	f.hook = func(w http.ResponseWriter, r *http.Request) bool {
		if r.Method != "HEAD" {
			return false
		}
		w.Header().Set("ETag", `"safe-etag"`)
		w.Header().Set("Content-Length", "1")
		w.Header().Set("Content-Type", f.cfg.SecretKey)
		return true
	}
	// Prepare returns no metadata, but read does; valid GET data remains harmless.
	f.mu.Lock()
	f.data["policies/cr.txt"] = []byte("x")
	f.mu.Unlock()
	f.hook = func(w http.ResponseWriter, r *http.Request) bool {
		if !strings.HasSuffix(r.URL.Path, "/policies/cr.txt") {
			return false
		}
		w.Header().Set("ETag", `"safe-etag"`)
		w.Header().Set("Content-Length", "1")
		w.Header().Set("Content-Type", f.cfg.SecretKey)
		if r.Method == "GET" {
			io.WriteString(w, "x")
		}
		return true
	}
	_, err := f.broker.Handle(context.Background(), "files-read", storageJSON(t, f.broker, "files-read", map[string]string{"id": "policies/cr.txt", "revision": `"safe-etag"`}))
	if err != ErrProvider {
		t.Fatal("reflected credential metadata admitted", err)
	}
}

func TestStorageUncertainPlanBlocksNewPrepareWithoutHostHint(t *testing.T) {
	b, _ := storageVaultFixture(t)
	q := change("create", "", "", "data")
	q.Name = "one.txt"
	storageCall[StoragePlan](t, b, "files-prepare", q)
	intent, err := b.store.readStorageIntent()
	if err != nil {
		t.Fatal(err)
	}
	intent.Plan.State = "needs-attention"
	if err = b.store.writeStorageIntent(intent); err != nil {
		t.Fatal(err)
	}
	q.Name = "two.txt"
	if _, err = b.Handle(context.Background(), "files-prepare", storageJSON(t, b, "files-prepare", q)); err != Error("operation-uncertain") {
		t.Fatal("uncertain operation replaced", err)
	}
}
