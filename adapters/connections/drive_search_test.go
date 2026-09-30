//go:build linux || darwin

package connections

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// driveSearched is a connected broker whose Drive answers a listing with
// files, and keeps what each listing asked.
func driveSearched(t *testing.T, files string, status int) (*Broker, *[]url.Values) {
	t.Helper()
	b, _, _ := testBroker(t)
	if r := finish(t, b, start(t, b, "connect"), nil); r.State != "complete" {
		t.Fatal(r)
	}
	asked := &[]url.Values{}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" || r.URL.Path != "/files" || r.Header.Get("Authorization") != "Bearer google-access-private" {
			t.Error("not a listing under the connection's token:", r.Method, r.URL.Path)
		}
		*asked = append(*asked, r.URL.Query())
		w.WriteHeader(status)
		io.WriteString(w, files)
	}))
	t.Cleanup(server.Close)
	b.provider.api = server.URL
	b.provider.client = server.Client()
	return b, asked
}

func searchDrive(t *testing.T, b *Broker, query string) (SourceSearch, error) {
	t.Helper()
	v, e := b.Handle(context.Background(), "search", mustJSON(map[string]string{"query": query}))
	if e != nil {
		return SourceSearch{}, e
	}
	return v.(SourceSearch), nil
}

func TestDriveSearchIsOfTheWholeDriveAndOfWhatCanBeRead(t *testing.T) {
	b, asked := driveSearched(t, `{"files":[{"id":"file-A","name":"policy.txt","mimeType":"text/plain"},{"id":"doc-B","name":"Plan","mimeType":"application/vnd.google-apps.document"}]}`, 200)
	found, e := searchDrive(t, b, "owner's \\ plan")
	if e != nil {
		t.Fatal(e)
	}
	if len(*asked) != 1 {
		t.Fatal("one search asked Drive", len(*asked), "times")
	}
	q := (*asked)[0]
	want := "trashed = false and (mimeType = 'application/pdf' or mimeType = 'text/plain' or mimeType = 'text/markdown' or mimeType = 'text/csv' or mimeType = 'application/json' or mimeType = 'application/vnd.google-apps.document' or mimeType = 'application/vnd.google-apps.spreadsheet' or mimeType = 'application/vnd.google-apps.presentation') and fullText contains 'owner\\'s \\\\ plan'"
	if q.Get("q") != want {
		t.Errorf("the search asked\n%s\nand not\n%s", q.Get("q"), want)
	}
	if q.Has("orderBy") {
		t.Error("a search by words asked for an order, which Drive refuses:", q.Get("orderBy"))
	}
	if q.Get("pageSize") != "20" || q.Get("spaces") != "drive" || q.Get("fields") != "nextPageToken,incompleteSearch,files(id,name,mimeType)" || q.Has("pageToken") || q.Has("corpora") {
		t.Error("the search is not bounded as the contract says:", q.Encode())
	}
	if len(found.Items) != 2 || found.Items[0] != (SourcePreview{ID: "file-A", Title: "policy.txt", URL: "https://drive.google.com/open?id=file-A", Description: "text/plain"}) || found.Items[1].ID != "doc-B" || found.More {
		t.Errorf("%+v", found)
	}
	var epoch string
	b.store.locked(func(v *state) error { epoch = v.Epoch; return nil })
	if found.SelectionContext != epoch {
		t.Error("the search gave a context that a selection does not take")
	}
}

func TestDriveSearchWithoutWordsIsOfWhatChangedLast(t *testing.T) {
	b, asked := driveSearched(t, `{"files":[],"nextPageToken":"more"}`, 200)
	for _, query := range []string{"", "  \t "} {
		found, e := searchDrive(t, b, query)
		if e != nil {
			t.Fatal(e)
		}
		if len(found.Items) != 0 || found.Items == nil || !found.More {
			t.Errorf("%+v", found)
		}
	}
	for _, q := range *asked {
		if strings.Contains(q.Get("q"), "fullText") || q.Get("orderBy") != "modifiedTime desc" {
			t.Error("a search without words asked", q.Encode())
		}
	}
}

func TestDriveSearchGivesNothingItCannotStandBehind(t *testing.T) {
	for name, example := range map[string]struct {
		files string
		items int
		err   error
	}{
		"a folder and a file of a kind that is not read": {`{"files":[{"id":"folder-A","name":"Folder","mimeType":"application/vnd.google-apps.folder"},{"id":"zip-A","name":"a.zip","mimeType":"application/zip"},{"id":"file-A","name":"a.txt","mimeType":"text/plain"}]}`, 1, nil},
		"an ID that is no ID":                            {`{"files":[{"id":"../state.json","name":"a.txt","mimeType":"text/plain"}]}`, 0, nil},
		"one file twice":                                 {`{"files":[{"id":"file-A","name":"a.txt","mimeType":"text/plain"},{"id":"file-A","name":"b.txt","mimeType":"text/plain"}]}`, 1, nil},
		"more files than were asked for":                 {`{"files":[` + strings.TrimSuffix(strings.Repeat(`{"id":"file-A","name":"a.txt","mimeType":"text/plain"},`, 21), ",") + `]}`, 0, ErrProvider},
		"a name that holds the token":                    {`{"files":[{"id":"file-A","name":"google-access-private","mimeType":"text/plain"}]}`, 0, ErrProvider},
		"a name that holds the token, escaped":           {`{"files":[{"id":"file-A","name":"\u0067oogle-access-private","mimeType":"text/plain"}]}`, 0, ErrProvider},
		"an answer that is no JSON":                      {`<html>`, 0, ErrProvider},
		"a search that did not look everywhere":          {`{"files":[],"incompleteSearch":true}`, 0, nil},
	} {
		b, _ := driveSearched(t, example.files, 200)
		found, e := searchDrive(t, b, "words")
		if e != example.err || len(found.Items) != example.items {
			t.Errorf("%s: %d items and %v", name, len(found.Items), e)
		}
		if name == "a search that did not look everywhere" && !found.More {
			t.Errorf("%s: it is not said that there may be more", name)
		}
	}
}

func TestDriveSearchShowsANameAsText(t *testing.T) {
	long := strings.Repeat("é", 200)
	names, _ := json.Marshal([]map[string]string{
		{"id": "a", "name": "line\none\ttwo‮gnp.exe", "mimeType": "text/plain"},
		{"id": "b", "name": long, "mimeType": "text/plain"},
		{"id": "c", "name": " ⁦ ", "mimeType": "text/plain"},
	})
	b, _ := driveSearched(t, `{"files":`+string(names)+`}`, 200)
	found, e := searchDrive(t, b, "words")
	if e != nil || len(found.Items) != 3 {
		t.Fatal(found, e)
	}
	if found.Items[0].Title != "line one two gnp.exe" {
		t.Errorf("a name's controls and turning marks were shown: %q", found.Items[0].Title)
	}
	if got := []rune(found.Items[1].Title); len(got) != 128 {
		t.Errorf("a long name was shown in %d characters", len(got))
	}
	if found.Items[2].Title != "c" {
		t.Errorf("a name of nothing to show was shown as %q", found.Items[2].Title)
	}
}

func TestDriveSearchRefusals(t *testing.T) {
	b, asked := driveSearched(t, `{"files":[]}`, 200)
	for _, raw := range []string{`{"query":"a\nb"}`, `{"query":"` + strings.Repeat("a", 1025) + `"}`, `{"query":"a","pageToken":"x"}`, `{"Query":"a"}`, `{"query":"a","query":"b"}`, `[]`} {
		if _, e := b.Handle(context.Background(), "search", []byte(raw)); e != ErrRequest {
			t.Errorf("%.40s: %v", raw, e)
		}
	}
	if len(*asked) != 0 {
		t.Error("a refused search asked Drive")
	}
	for status, want := range map[int]error{401: ErrRevoked, 403: ErrProvider, 500: ErrProvider} {
		b, _ := driveSearched(t, `{"files":[]}`, status)
		if _, e := searchDrive(t, b, "words"); e != want {
			t.Errorf("Drive answered %d and the search %v", status, e)
		}
	}
	b, asked = driveSearched(t, `{"files":[]}`, 200)
	if _, e := b.Handle(context.Background(), "disconnect", nil); e != nil {
		t.Fatal(e)
	}
	before := len(*asked)
	if _, e := searchDrive(t, b, "words"); e != ErrConnect {
		t.Errorf("a search with no connection: %v", e)
	}
	if len(*asked) != before {
		t.Error("a search with no connection asked Drive")
	}
	b, _ = driveSearched(t, `{"files":[]}`, 200)
	b.disabled = true
	if _, e := b.Handle(context.Background(), "search", []byte(`{"query":"words"}`)); e != ErrPolicy {
		t.Errorf("a search of a blocked connection: %v", e)
	}
}

// A connection that ends while Drive is answering gives none of the answer.
func TestDriveSearchGivesNothingOfAConnectionThatEnded(t *testing.T) {
	b, _ := driveSearched(t, `{"files":[{"id":"file-A","name":"a.txt","mimeType":"text/plain"}]}`, 200)
	inner := b.provider.client.Transport
	b.provider.client = &http.Client{Transport: pausedTransport(func(r *http.Request) (*http.Response, error) {
		res, e := inner.RoundTrip(r)
		if r.URL.Path == "/files" {
			b.store.locked(func(v *state) error { v.Epoch = randomID(); return b.store.write("state.json", v) })
		}
		return res, e
	})}
	if found, e := searchDrive(t, b, "words"); e != ErrCanceled || len(found.Items) != 0 {
		t.Errorf("%+v, %v", found, e)
	}
}

func TestDriveSelectionIsOfTheConnectionThatWasSearched(t *testing.T) {
	b, _ := driveSearched(t, `{"files":[{"id":"file-A","name":"a.txt","mimeType":"text/plain"}]}`, 200)
	found, e := searchDrive(t, b, "words")
	if e != nil {
		t.Fatal(e)
	}
	choose := func(ids []string, under string) (any, error) {
		return b.Handle(context.Background(), "select", mustJSON(map[string]any{"resourceIds": ids, "selectionContext": under}))
	}
	v, e := choose([]string{"file-A", "file-B"}, found.SelectionContext)
	if e != nil || len(v.([]SourceSelection)) != 2 || v.([]SourceSelection)[0].ResourceID != "file-A" || !opaque.MatchString(v.([]SourceSelection)[0].Grant) {
		t.Fatal(v, e)
	}
	for name, ids := range map[string][]string{"no file": {}, "five files": {"a", "b", "c", "d", "e"}, "one file twice": {"a", "a"}, "an ID that is no ID": {"../state.json"}} {
		if _, e := choose(ids, found.SelectionContext); e != ErrRequest {
			t.Errorf("%s: %v", name, e)
		}
	}
	if _, e := choose([]string{"file-A"}, strings.Repeat("0", 64)); e != ErrRequest {
		t.Errorf("a selection under another context: %v", e)
	}
	if _, e := b.Handle(context.Background(), "disconnect", nil); e != nil {
		t.Fatal(e)
	}
	if _, e := choose([]string{"file-A"}, found.SelectionContext); e != ErrConnect {
		t.Errorf("a selection after the connection ended: %v", e)
	}
}

// The consent that is asked is for the whole Drive, and Google's own chooser
// of files is asked for in no part of it.
func TestConsentAsksForTheWholeDriveAndForNoChooser(t *testing.T) {
	b, _, _ := testBroker(t)
	u, _ := url.Parse(start(t, b, "connect").URL)
	q := u.Query()
	if q.Get("scope") != "https://www.googleapis.com/auth/drive" || q.Get("include_granted_scopes") != "false" || q.Get("prompt") != "consent" || q.Get("access_type") != "offline" {
		t.Error("the consent asks", q.Encode())
	}
	for _, name := range []string{"trigger_onepick", "allow_multiple", "mimetypes", "picked_file_ids"} {
		if q.Has(name) {
			t.Error("the consent asks Google's chooser for", name)
		}
	}
	if _, e := b.Handle(context.Background(), "pick", []byte(`{}`)); e != ErrRequest {
		t.Errorf("pick: %v", e)
	}
}

// A listing of the storage controls says that it is of the account's files.
func TestDriveListingSaysItIsOfTheAccount(t *testing.T) {
	b, _ := driveSearched(t, `{"files":[]}`, 200)
	page, e := b.Handle(context.Background(), "files-list", mustJSON(StorageQuery{}))
	if e != nil || page.(StoragePage).Scope != "account-files" {
		t.Errorf("%+v, %v", page, e)
	}
}
