//go:build linux || darwin

package connections

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"mime"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func storageCall[T any](t *testing.T, b *Broker, method string, q any) T {
	t.Helper()
	v, e := b.Handle(context.Background(), method, storageJSON(t, b, method, q))
	if e != nil {
		t.Fatalf("%s: %v", method, e)
	}
	raw, _ := json.Marshal(v)
	var out T
	if e = json.Unmarshal(raw, &out); e != nil {
		t.Fatal(e)
	}
	return out
}
func storageVaultFixture(t *testing.T) (*Broker, string) {
	t.Helper()
	vault := filepath.Join(t.TempDir(), "vault")
	os.MkdirAll(filepath.Join(vault, ".obsidian"), 0700)
	s := testStore(t, "storage")
	b := NewObsidian(s, false)
	t.Cleanup(b.Close)
	storageCall[map[string]bool](t, b, "configure", map[string]string{"path": vault})
	return b, vault
}
func change(action, id, revision, body string) StorageChange {
	return StorageChange{Action: action, ID: id, Revision: revision, MediaType: "text/plain", Content: base64.StdEncoding.EncodeToString([]byte(body))}
}
func TestStorageLocalRevisionConsentAndSingleUse(t *testing.T) {
	b, vault := storageVaultFixture(t)
	create := change("create", "", "", "first")
	create.Name = "policy.txt"
	p := storageCall[StoragePlan](t, b, "files-prepare", create)
	if _, e := os.Stat(filepath.Join(vault, "policy.txt")); !os.IsNotExist(e) {
		t.Fatal("prepare wrote file")
	}
	done := storageCall[StoragePlan](t, b, "files-commit", map[string]string{"id": p.ID})
	if done.State != "completed" {
		t.Fatal(done)
	}
	storageCall[StoragePlan](t, b, "files-commit", map[string]string{"id": p.ID})
	page := storageCall[StoragePage](t, b, "files-list", StorageQuery{})
	if len(page.Items) != 1 || !strings.HasPrefix(page.Items[0].Revision, "stat:") {
		t.Fatal(page)
	}
	read := storageCall[StorageRead](t, b, "files-read", map[string]string{"id": page.Items[0].ID, "revision": page.Items[0].Revision})
	if read.Content != create.Content {
		t.Fatal("wrong bytes")
	}
	update := change("update", "policy.txt", read.File.Revision, "second")
	p = storageCall[StoragePlan](t, b, "files-prepare", update)
	os.WriteFile(filepath.Join(vault, "policy.txt"), []byte("other editor"), 0600)
	done = storageCall[StoragePlan](t, b, "files-commit", map[string]string{"id": p.ID})
	if done.State != "refused" || done.Error != "source-changed" {
		t.Fatal(done)
	}
	update.Revision = digest([]byte("other editor"))
	p = storageCall[StoragePlan](t, b, "files-prepare", update)
	done = storageCall[StoragePlan](t, b, "files-commit", map[string]string{"id": p.ID})
	if done.State != "completed" {
		t.Fatal(done)
	}
	backup, e := os.ReadFile(filepath.Join(vault, ".jpack-history", p.ID))
	if e != nil || string(backup) != "other editor" {
		t.Fatal("backup absent", e)
	}
	p = storageCall[StoragePlan](t, b, "files-prepare", StorageChange{Action: "delete", ID: "policy.txt", Revision: digest([]byte("second"))})
	for _, confirmation := range []string{"", "Yes", "wrong.txt"} {
		if _, e := b.Handle(context.Background(), "files-commit", mustJSON(map[string]string{"id": p.ID, "confirmation": confirmation})); e != Error("confirmation-required") {
			t.Fatal("deletion lacked exact consent", e)
		}
	}
	if _, e := os.Stat(filepath.Join(vault, "policy.txt")); e != nil {
		t.Fatal("deleted before consent")
	}
	done = storageCall[StoragePlan](t, b, "files-commit", map[string]string{"id": p.ID, "confirmation": "policy.txt"})
	if done.State != "completed" || done.Effect != "trash" {
		t.Fatal(done)
	}
	data, e := os.ReadFile(filepath.Join(vault, ".jpack-trash", p.ID+"-policy.txt"))
	if e != nil || string(data) != "second" {
		t.Fatal("trash not retained")
	}
	again := NewObsidian(b.store, false)
	defer again.Close()
	done = storageCall[StoragePlan](t, again, "files-commit", map[string]string{"id": p.ID, "confirmation": "policy.txt"})
	if done.State != "completed" {
		t.Fatal("completed replay")
	}
}
func TestStorageBoundedBrowseAndUnsafePaths(t *testing.T) {
	b, vault := storageVaultFixture(t)
	for i := range 60 {
		os.WriteFile(filepath.Join(vault, "note-"+strconv.Itoa(i)+".txt"), []byte("text"), 0600)
	}
	page := storageCall[StoragePage](t, b, "files-list", StorageQuery{})
	if len(page.Items) != StoragePageItems || page.NextPageToken == "" {
		t.Fatal("unbounded list", page)
	}
	if _, e := b.Handle(context.Background(), "files-list", mustJSON(StorageQuery{Query: "changed", PageToken: page.NextPageToken})); e != ErrGrant {
		t.Fatal("cursor changed query", e)
	}
	outside := filepath.Join(t.TempDir(), "secret.txt")
	os.WriteFile(outside, []byte("secret"), 0600)
	os.Symlink(outside, filepath.Join(vault, "link.txt"))
	for _, id := range []string{"../secret.txt", ".obsidian/settings.json", "link.txt", "/etc/passwd"} {
		if _, e := b.Handle(context.Background(), "files-read", mustJSON(map[string]string{"id": id, "revision": "revision"})); e == nil {
			t.Fatal("unsafe read", id)
		}
	}
	for _, name := range []string{"../bad", ".hidden", "nested/name"} {
		q := change("create", "", "", "bad")
		q.Name = name
		if _, e := b.Handle(context.Background(), "files-prepare", mustJSON(q)); e == nil {
			t.Fatal("unsafe create", name)
		}
	}
	query := StorageQuery{Query: "no match"}
	page = storageCall[StoragePage](t, b, "files-list", query)
	if len(page.Items) != 0 {
		t.Fatal(page)
	}
}
func TestStorageClaimExpiryAndConnectionBinding(t *testing.T) {
	b, vault := storageVaultFixture(t)
	q := change("create", "", "", "value")
	q.Name = "test.txt"
	p := storageCall[StoragePlan](t, b, "files-prepare", q)
	b.store.locked(func(v *state) error {
		i, e := b.store.readStorageIntent()
		if e != nil {
			return e
		}
		i.Plan.Expires = time.Now().Add(-time.Minute).UTC().Format(time.RFC3339)
		return b.store.writeStorageIntent(i)
	})
	if _, e := b.Handle(context.Background(), "files-commit", mustJSON(map[string]string{"id": p.ID})); e != ErrGrant {
		t.Fatal("expired claim admitted", e)
	}
	p = storageCall[StoragePlan](t, b, "files-prepare", q)
	b.store.locked(func(v *state) error {
		i, e := b.store.readStorageIntent()
		if e != nil {
			return e
		}
		i.Plan.State = "executing"
		return b.store.writeStorageIntent(i)
	})
	again := NewObsidian(b.store, false)
	defer again.Close()
	done := storageCall[StoragePlan](t, again, "files-commit", map[string]string{"id": p.ID})
	if done.State != "needs-attention" {
		t.Fatal(done)
	}
	if _, e := os.Stat(filepath.Join(vault, q.Name)); !os.IsNotExist(e) {
		t.Fatal("uncertain call repeated")
	}
	storageCall[map[string]bool](t, b, "disconnect", struct{}{})
	storageCall[map[string]bool](t, b, "configure", map[string]string{"path": vault})
	if _, e := b.Handle(context.Background(), "files-commit", mustJSON(map[string]string{"id": p.ID})); e != ErrGrant {
		t.Fatal("claim crossed reconnect", e)
	}
}
func TestStorageDriveQueryAndConditionalTrash(t *testing.T) {
	s := testStore(t, "drive-storage")
	s.locked(func(v *state) error {
		v.Epoch = "epoch"
		v.Connection = &credential{ID: "connection", Access: "private-token", Expires: time.Now().Add(time.Hour).Unix()}
		return s.write("state.json", v)
	})
	writes := 0
	etag := "\"revision-1\""
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer private-token" {
			t.Error("missing credential")
		}
		if r.Method == "GET" && r.URL.Path == "/files" {
			if r.URL.Query().Get("pageSize") != "24" || r.URL.Query().Get("q") != "trashed = false and fullText contains 'owner\\'s'" {
				t.Error("query not bounded/escaped", r.URL.RawQuery)
			}
			io.WriteString(w, `{"files":[],"nextPageToken":"vendor-secret-cursor"}`)
			return
		}
		if r.Method == "GET" {
			w.Header().Set("ETag", etag)
			io.WriteString(w, `{"id":"file-A","name":"policy.txt","mimeType":"text/plain","version":"1","size":"3","capabilities":{"canDownload":true,"canEdit":true,"canTrash":true}}`)
			return
		}
		writes++
		if r.Method != "PATCH" || r.Header.Get("If-Match") != "\"revision-1\"" {
			t.Error("mutation lacks precondition")
		}
		raw, _ := io.ReadAll(r.Body)
		if string(raw) != `{"trashed":true}` {
			t.Error("expected trash")
		}
		io.WriteString(w, `{"id":"file-A"}`)
	}))
	defer server.Close()
	b := New(s, false)
	b.provider.api = server.URL
	b.provider.client = server.Client()
	defer b.Close()
	page := storageCall[StoragePage](t, b, "files-list", StorageQuery{Query: "owner's"})
	if page.NextPageToken == "vendor-secret-cursor" || !opaque.MatchString(page.NextPageToken) {
		t.Fatal("upstream cursor leaked")
	}
	p := storageCall[StoragePlan](t, b, "files-prepare", StorageChange{Action: "delete", ID: "file-A", Revision: "1"})
	if writes != 0 {
		t.Fatal("prepare mutated")
	}
	if _, e := b.Handle(context.Background(), "files-commit", mustJSON(map[string]string{"id": p.ID, "confirmation": "Yes"})); e == nil {
		t.Fatal("delete no consent")
	}
	done := storageCall[StoragePlan](t, b, "files-commit", map[string]string{"id": p.ID, "confirmation": "policy.txt"})
	if done.State != "completed" || writes != 1 {
		t.Fatal(done, writes)
	}
	storageCall[StoragePlan](t, b, "files-commit", map[string]string{"id": p.ID, "confirmation": "policy.txt"})
	if writes != 1 {
		t.Fatal("mutation repeated")
	}
}

func TestStorageS3ConditionalMutationsAndAmbiguity(t *testing.T) {
	f := testS3(t)
	f.configure()
	var writes int
	f.hook = func(w http.ResponseWriter, r *http.Request) bool {
		if r.URL.Query().Get("list-type") != "" {
			return false
		}
		key := strings.TrimPrefix(r.URL.Path, "/"+f.cfg.Bucket+"/")
		f.mu.Lock()
		defer f.mu.Unlock()
		if r.Method == "HEAD" {
			if _, ok := f.data[key]; !ok {
				w.WriteHeader(404)
				return true
			}
			w.Header().Set("ETag", f.tag(key))
			w.Header().Set("Content-Length", strconv.Itoa(len(f.data[key])))
			w.Header().Set("Content-Type", "text/plain")
			return true
		}
		if r.Method != "PUT" && r.Method != "DELETE" {
			return false
		}
		writes++
		_, exists := f.data[key]
		if r.Header.Get("If-None-Match") == "*" {
			if exists {
				w.WriteHeader(412)
				return true
			}
		} else if !exists || r.Header.Get("If-Match") != f.tag(key) {
			w.WriteHeader(412)
			return true
		}
		if r.Method == "DELETE" {
			delete(f.data, key)
			w.WriteHeader(204)
			return true
		}
		f.data[key], _ = io.ReadAll(r.Body)
		if key == "policies/uncertain.txt" {
			w.WriteHeader(503)
		} else {
			w.WriteHeader(200)
		}
		return true
	}
	q := change("create", "", "", "original")
	q.Name = "new.txt"
	p := storageCall[StoragePlan](t, f.broker, "files-prepare", q)
	if writes != 0 {
		t.Fatal("prepare mutated")
	}
	done := storageCall[StoragePlan](t, f.broker, "files-commit", map[string]string{"id": p.ID})
	if done.State != "completed" {
		t.Fatal(done)
	}
	storageCall[StoragePlan](t, f.broker, "files-commit", map[string]string{"id": p.ID})
	if writes != 1 {
		t.Fatal("mutation replayed")
	}
	p = storageCall[StoragePlan](t, f.broker, "files-prepare", q)
	done = storageCall[StoragePlan](t, f.broker, "files-commit", map[string]string{"id": p.ID})
	if done.State != "refused" {
		t.Fatal("create overwrote", done)
	}
	read := storageCall[StorageRead](t, f.broker, "files-read", map[string]string{"id": "policies/new.txt", "revision": f.tag("policies/new.txt")})
	q = change("update", read.File.ID, read.File.Revision, "replacement")
	p = storageCall[StoragePlan](t, f.broker, "files-prepare", q)
	f.mu.Lock()
	f.data[q.ID] = []byte("other editor")
	f.mu.Unlock()
	done = storageCall[StoragePlan](t, f.broker, "files-commit", map[string]string{"id": p.ID})
	if done.State != "refused" {
		t.Fatal("stale update admitted", done)
	}
	q.Revision = f.tag(q.ID)
	p = storageCall[StoragePlan](t, f.broker, "files-prepare", q)
	done = storageCall[StoragePlan](t, f.broker, "files-commit", map[string]string{"id": p.ID})
	if done.State != "completed" {
		t.Fatal(done)
	}
	p = storageCall[StoragePlan](t, f.broker, "files-prepare", StorageChange{Action: "delete", ID: q.ID, Revision: f.tag(q.ID)})
	if _, err := f.broker.Handle(context.Background(), "files-commit", mustJSON(map[string]string{"id": p.ID, "confirmation": "new.txt"})); err != Error("confirmation-required") {
		t.Fatal(err)
	}
	done = storageCall[StoragePlan](t, f.broker, "files-commit", map[string]string{"id": p.ID, "confirmation": "policies/new.txt"})
	if done.State != "completed" || done.Effect != "delete" {
		t.Fatal(done)
	}
	q = change("create", "", "", "maybe written")
	q.Name = "uncertain.txt"
	p = storageCall[StoragePlan](t, f.broker, "files-prepare", q)
	done = storageCall[StoragePlan](t, f.broker, "files-commit", map[string]string{"id": p.ID})
	if done.State != "needs-attention" {
		t.Fatal(done)
	}
	before := writes
	storageCall[StoragePlan](t, f.broker, "files-commit", map[string]string{"id": p.ID})
	storageCall[StoragePlan](t, f.broker, "files-status", map[string]string{"id": p.ID})
	if writes != before {
		t.Fatal("uncertain write retried")
	}
}
func TestStorageReconfiguredVaultCannotReceiveOldClaim(t *testing.T) {
	b, _ := storageVaultFixture(t)
	q := change("create", "", "", "old connection")
	q.Name = "target.txt"
	storageCall[StoragePlan](t, b, "files-prepare", q)
	intent, err := b.store.readStorageIntent()
	if err != nil {
		t.Fatal(err)
	}
	storageCall[map[string]bool](t, b, "disconnect", map[string]string{})
	next := filepath.Join(t.TempDir(), "next")
	os.MkdirAll(filepath.Join(next, ".obsidian"), 0700)
	storageCall[map[string]bool](t, b, "configure", map[string]string{"path": next})
	if _, err = b.storageApply(context.Background(), intent, ""); err != ErrCanceled {
		t.Fatal("old claim rebound", err)
	}
	if _, err = os.Stat(filepath.Join(next, "target.txt")); !os.IsNotExist(err) {
		t.Fatal("wrote new connection")
	}
}

func TestStorageDriveUploadsAndMissingVersionLock(t *testing.T) {
	s := testStore(t, "drive-upload")
	s.locked(func(v *state) error {
		v.Epoch = "epoch"
		v.Connection = &credential{ID: "connection", Access: "private-token", Expires: time.Now().Add(time.Hour).Unix()}
		return s.write("state.json", v)
	})
	var writes int
	etag := `"etag-1"`
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer private-token" {
			t.Error("missing access token")
		}
		if r.Method == "GET" {
			if strings.HasSuffix(r.URL.Path, "/generateIds") {
				io.WriteString(w, `{"ids":["new-file"]}`)
				return
			}
			if etag != "" {
				w.Header().Set("ETag", etag)
			}
			io.WriteString(w, `{"id":"existing-file","name":"notes.txt","mimeType":"text/plain","version":"1","size":"3","capabilities":{"canEdit":true,"canDownload":true,"canTrash":true}}`)
			return
		}
		writes++
		if !strings.HasPrefix(r.URL.Path, "/upload/drive/v3/files") || r.URL.Query().Get("uploadType") != "multipart" {
			t.Error("wrong upload endpoint")
		}
		media, params, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
		if err != nil || media != "multipart/related" {
			t.Error("wrong multipart")
			w.WriteHeader(400)
			return
		}
		reader := multipart.NewReader(r.Body, params["boundary"])
		meta, err := reader.NextPart()
		if err != nil {
			t.Error(err)
			return
		}
		var m map[string]any
		json.NewDecoder(meta).Decode(&m)
		data, err := reader.NextPart()
		if err != nil {
			t.Error(err)
			return
		}
		raw, _ := io.ReadAll(data)
		if string(raw) != "new résumé" || data.Header.Get("Content-Type") != "text/plain" || m["name"] != "notes.txt" {
			t.Error("wrong upload bytes or metadata")
		}
		if r.Method == "POST" {
			if m["id"] != "new-file" {
				t.Error("unreserved ID")
			}
			io.WriteString(w, `{"id":"new-file"}`)
		} else {
			if r.Method != "PATCH" || r.Header.Get("If-Match") != `"etag-1"` {
				t.Error("update lacks condition")
			}
			io.WriteString(w, `{"id":"existing-file"}`)
		}
	}))
	defer server.Close()
	b := New(s, false)
	b.provider.api = server.URL + "/drive/v3"
	b.provider.client = server.Client()
	defer b.Close()
	q := change("create", "", "", "new résumé")
	q.Name = "notes.txt"
	p := storageCall[StoragePlan](t, b, "files-prepare", q)
	if writes != 0 {
		t.Fatal("prepare uploaded")
	}
	done := storageCall[StoragePlan](t, b, "files-commit", map[string]string{"id": p.ID})
	if done.State != "completed" || writes != 1 {
		t.Fatal(done, writes)
	}
	q = change("update", "existing-file", "1", "new résumé")
	p = storageCall[StoragePlan](t, b, "files-prepare", q)
	done = storageCall[StoragePlan](t, b, "files-commit", map[string]string{"id": p.ID})
	if done.State != "completed" || writes != 2 {
		t.Fatal(done, writes)
	}
	etag = ""
	if _, err := b.Handle(context.Background(), "files-prepare", storageJSON(t, b, "files-prepare", q)); err != Error("conditional-write-unavailable") {
		t.Fatal("unguarded update allowed", err)
	}
	if writes != 2 {
		t.Fatal("unguarded mutation")
	}
	for _, media := range []string{"text/plain\r\nX-Header: bad", "text/\tplain", "application/vnd.google-apps.document", "text/plain; charset=utf8"} {
		q.MediaType = media
		if _, err := b.Handle(context.Background(), "files-prepare", storageJSON(t, b, "files-prepare", q)); err != ErrUnsupported {
			t.Fatal("unsafe media", media, err)
		}
	}
}

func storageJSON(t *testing.T, b *Broker, method string, q any) []byte {
	t.Helper()
	raw := mustJSON(q)
	if method != "files-read" && method != "files-prepare" {
		return raw
	}
	var data map[string]any
	if err := json.Unmarshal(raw, &data); err != nil {
		t.Fatal(err)
	}
	if value, _ := data["context"].(string); value == "" {
		_, c, epoch, err := b.connectedSnapshot()
		if err != nil {
			t.Fatal(err)
		}
		data["context"] = storageContext(c, epoch)
	}
	return mustJSON(data)
}
func TestStorageSelectionCannotRebindAfterReconnect(t *testing.T) {
	b, vault := storageVaultFixture(t)
	os.WriteFile(filepath.Join(vault, "same.txt"), []byte("same"), 0600)
	page := storageCall[StoragePage](t, b, "files-list", StorageQuery{})
	selected := page.Items[0]
	read := storageCall[StorageRead](t, b, "files-read", map[string]string{"id": selected.ID, "revision": selected.Revision, "context": selected.Context})
	storageCall[map[string]bool](t, b, "disconnect", map[string]string{})
	next := filepath.Join(t.TempDir(), "next")
	os.MkdirAll(filepath.Join(next, ".obsidian"), 0700)
	os.WriteFile(filepath.Join(next, "same.txt"), []byte("same"), 0600)
	storageCall[map[string]bool](t, b, "configure", map[string]string{"path": next})
	q := change("update", read.File.ID, read.File.Revision, "wrong location")
	q.Context = read.File.Context
	if _, err := b.Handle(context.Background(), "files-prepare", mustJSON(q)); err != ErrChanged {
		t.Fatal("old read rebound", err)
	}
	q = change("create", "", "", "wrong location")
	q.Name = "new.txt"
	q.Context = page.Context
	if _, err := b.Handle(context.Background(), "files-prepare", mustJSON(q)); err != ErrChanged {
		t.Fatal("old destination rebound", err)
	}
	if _, err := b.Handle(context.Background(), "files-read", mustJSON(map[string]string{"id": read.File.ID, "revision": read.File.Revision, "context": read.File.Context})); err != ErrChanged {
		t.Fatal("old selection rebound", err)
	}
	q.Context = ""
	if _, err := b.Handle(context.Background(), "files-prepare", mustJSON(q)); err != ErrChanged {
		t.Fatal("unbound destination accepted", err)
	}
}
