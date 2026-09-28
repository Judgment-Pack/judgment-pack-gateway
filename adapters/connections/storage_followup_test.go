//go:build linux || darwin

package connections

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestStorageFollowupDriveRefreshCannotCrossPlanExpiry(t *testing.T) {
	s := testStore(t, "followup-expiry")
	b := New(s, false)
	defer b.Close()
	deadline := time.Now().Add(2 * time.Second).Truncate(time.Second)
	writes := 0
	var wroteAt time.Time
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/token" {
			time.Sleep(time.Until(deadline) + 100*time.Millisecond)
			io.WriteString(w, `{"access_token":"fresh-token","expires_in":3600,"token_type":"Bearer"}`)
			return
		}
		writes++
		wroteAt = time.Now()
		io.WriteString(w, `{"id":"reserved-file"}`)
	}))
	defer srv.Close()
	b.provider.client = srv.Client()
	b.provider.token = srv.URL + "/token"
	b.provider.api = srv.URL + "/drive/v3"
	if err := s.locked(func(v *state) error {
		v.Epoch = "epoch"
		v.Connection = &credential{ID: "connection", Access: "expired", Refresh: "refresh", Expires: time.Now().Add(-time.Hour).Unix()}
		return s.write("state.json", v)
	}); err != nil {
		t.Fatal(err)
	}
	id := randomID()
	intent := storageIntent{Plan: StoragePlan{ID: id, State: "prepared", Expires: deadline.UTC().Format(time.RFC3339)}, Connection: "connection", Epoch: "epoch", Change: StorageChange{Action: "create", ID: "reserved-file", Name: "file.txt", MediaType: "text/plain"}}
	if err := s.writeStorageIntent(intent); err != nil {
		t.Fatal(err)
	}
	out, err := b.Handle(context.Background(), "files-commit", mustJSON(map[string]string{"id": id}))
	if err != ErrGrant || out != nil || writes != 0 {
		t.Fatalf("out=%v err=%v writes=%d at=%v deadline=%v", out, err, writes, wroteAt, deadline)
	}
	t.Log("expired plan refused before provider mutation")
}

func TestStorageFollowupDriveAllStoredStatesOffline(t *testing.T) {
	s := testStore(t, "followup-status")
	b := New(s, false)
	defer b.Close()
	s.locked(func(v *state) error {
		v.Epoch = "epoch"
		v.Connection = &credential{ID: "connection", Access: "expired", Expires: 1}
		return s.write("state.json", v)
	})
	for _, state := range []string{"prepared", "executing", "completed", "refused", "needs-attention"} {
		for _, method := range []string{"files-status", "files-commit"} {
			if state == "prepared" && method == "files-commit" {
				continue
			}
			id := randomID()
			if err := s.writeStorageIntent(storageIntent{Plan: StoragePlan{ID: id, State: state}, Connection: "connection", Epoch: "epoch"}); err != nil {
				t.Fatal(err)
			}
			out, err := b.Handle(context.Background(), method, mustJSON(map[string]string{"id": id}))
			if err != nil || out == nil {
				t.Fatalf("%s %s: out=%v err=%v", state, method, out, err)
			}
		}
	}
}

func TestStorageFollowupMalformedRecordVariantsBlockPrepare(t *testing.T) {
	for _, kind := range []string{"json", "invalid-state", "directory", "dangling-symlink"} {
		t.Run(kind, func(t *testing.T) {
			b, _ := storageVaultFixture(t)
			var err error
			switch kind {
			case "json":
				f, e := b.store.root.Create("storage-intent.json")
				if e != nil {
					t.Fatal(e)
				}
				f.Chmod(0600)
				_, err = f.Write([]byte(`{"plan":`))
				f.Close()
			case "invalid-state":
				err = b.store.writeStorageIntent(storageIntent{Plan: StoragePlan{ID: randomID(), State: "garbage"}, Connection: "connection", Epoch: "epoch"})
			case "directory":
				err = b.store.root.Mkdir("storage-intent.json", 0700)
			case "dangling-symlink":
				err = b.store.root.Symlink("absent-target", "storage-intent.json")
			}
			if err != nil {
				t.Fatal(err)
			}
			q := change("create", "", "", "body")
			q.Name = "new.txt"
			if _, err = b.Handle(context.Background(), "files-prepare", storageJSON(t, b, "files-prepare", q)); err != ErrStorage {
				t.Fatalf("%s admitted: %v", kind, err)
			}
		})
	}
}

func TestStorageFollowupLegacyStatPlanAndLargeFile(t *testing.T) {
	b, vault := storageVaultFixture(t)
	os.WriteFile(filepath.Join(vault, "file.txt"), []byte("original"), 0600)
	large, err := os.Create(filepath.Join(vault, "large.bin"))
	if err != nil {
		t.Fatal(err)
	}
	large.Truncate(MaxFileBytes + 1)
	large.Close()
	page := storageCall[StoragePage](t, b, "files-list", StorageQuery{})
	var file StorageFile
	for _, item := range page.Items {
		if item.ID == "large.bin" && (item.Deletable || item.Editable) {
			t.Fatal("large local file offered mutation")
		}
		if item.ID == "file.txt" {
			file = item
		}
	}
	_, c, epoch, err := b.connectedSnapshot()
	if err != nil {
		t.Fatal(err)
	}
	id := randomID()
	intent := storageIntent{Plan: StoragePlan{ID: id, State: "prepared", Expires: time.Now().Add(time.Minute).UTC().Format(time.RFC3339), Confirmation: "file.txt"}, Connection: c.ID, Epoch: epoch, Change: StorageChange{Action: "delete", ID: "file.txt", Name: "file.txt", Revision: file.Revision}}
	if err = b.store.writeStorageIntent(intent); err != nil {
		t.Fatal(err)
	}
	out := storageCall[StoragePlan](t, b, "files-commit", map[string]string{"id": id, "confirmation": "file.txt"})
	if out.State != "refused" {
		t.Fatal(out)
	}
	data, err := os.ReadFile(filepath.Join(vault, "file.txt"))
	if err != nil || string(data) != "original" {
		t.Fatal(string(data), err)
	}
}

func TestStorageFollowupS3ETagCredentialReflectionRefused(t *testing.T) {
	f := testS3(t)
	f.configure()
	tag := `"` + f.cfg.AccessKey + `"`
	f.hook = func(w http.ResponseWriter, r *http.Request) bool {
		if r.Method != "HEAD" {
			return false
		}
		w.Header().Set("ETag", tag)
		w.Header().Set("Content-Length", "1")
		w.Header().Set("Content-Type", "text/plain")
		return true
	}
	_, err := f.broker.Handle(context.Background(), "files-read", storageJSON(t, f.broker, "files-read", map[string]string{"id": "policies/a.txt", "revision": tag}))
	if err != ErrProvider {
		t.Fatal(err)
	}
	if _, err := (driveStorageMeta{ID: "id", Name: "name", Version: "1", MediaType: strings.Repeat("a", 120) + "/b"}).file(); err == nil {
		t.Fatal("oversized Drive MIME admitted")
	}
}
