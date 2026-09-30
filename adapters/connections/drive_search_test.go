//go:build linux || darwin

package connections

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
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

// found is a file as Drive says it, of a kind and a size that is read.
func foundFile(id, name string) map[string]any {
	return map[string]any{"id": id, "name": name, "mimeType": "text/plain", "size": "3", "capabilities": map[string]bool{"canDownload": true}}
}
func listing(files ...map[string]any) string {
	raw, _ := json.Marshal(map[string]any{"files": files})
	return string(raw)
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
	b, asked := driveSearched(t, listing(foundFile("file-A", "policy.txt"), map[string]any{"id": "doc-B", "name": "Plan", "mimeType": "application/vnd.google-apps.document", "capabilities": map[string]bool{"canDownload": true}}), 200)
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
	if q.Get("pageSize") != "20" || q.Get("spaces") != "drive" || q.Get("fields") != "nextPageToken,incompleteSearch,files(id,name,mimeType,size,capabilities(canDownload))" || q.Has("pageToken") || q.Has("corpora") || q.Get("supportsAllDrives") != "true" || q.Get("includeItemsFromAllDrives") != "true" || len(q) != 6 {
		t.Error("the search is not asked as the contract says:", q.Encode())
	}
	if len(found.Items) != 2 || found.Items[0] != (SourcePreview{ID: "file-A", Title: "policy.txt", URL: "https://drive.google.com/open?id=file-A", Description: "text/plain"}) || found.Items[1] != (SourcePreview{ID: "doc-B", Title: "Plan", URL: "https://drive.google.com/open?id=doc-B", Description: "application/vnd.google-apps.document"}) || found.More {
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
	if len(*asked) != 2 {
		t.Fatal("two searches asked Drive", len(*asked), "times")
	}
	for _, q := range *asked {
		if strings.Contains(q.Get("q"), "fullText") || q.Get("orderBy") != "modifiedTime desc" {
			t.Error("a search without words asked", q.Encode())
		}
	}
}

// A search gives the files Drive gave, in the order Drive gave them, and as
// many as twenty.
func TestDriveSearchGivesWhatDriveGaveInItsOrder(t *testing.T) {
	var files []map[string]any
	var ids []string
	for _, letter := range "TSRQPONMLKJIHGFEDCBA" {
		ids = append(ids, "file-"+string(letter))
		files = append(files, foundFile("file-"+string(letter), string(letter)+".txt"))
	}
	b, _ := driveSearched(t, listing(files...), 200)
	found, e := searchDrive(t, b, "words")
	if e != nil || len(found.Items) != 20 {
		t.Fatal(len(found.Items), e)
	}
	for i, item := range found.Items {
		if item.ID != ids[i] {
			t.Fatalf("the item at %d is %s, and Drive gave %s there", i, item.ID, ids[i])
		}
	}
}

func TestDriveSearchGivesNothingItCannotStandBehind(t *testing.T) {
	with := func(file map[string]any, member string, value any) map[string]any {
		file[member] = value
		return file
	}
	for name, example := range map[string]struct {
		files string
		items []string
		err   error
	}{
		"a folder and a file of a kind that is not read": {listing(with(foundFile("folder-A", "Folder"), "mimeType", "application/vnd.google-apps.folder"), with(foundFile("zip-A", "a.zip"), "mimeType", "application/zip"), foundFile("file-A", "a.txt")), []string{"file-A"}, nil},
		"an ID that is no ID":                            {listing(foundFile("../state.json", "a.txt"), foundFile("file-B", "b.txt")), []string{"file-B"}, nil},
		"one file twice":                                 {listing(foundFile("file-A", "a.txt"), foundFile("file-A", "b.txt")), []string{"file-A"}, nil},
		"more files than were asked for":                 {`{"files":[` + strings.TrimSuffix(strings.Repeat(`{"id":"file-A","name":"a.txt","mimeType":"text/plain","size":"3","capabilities":{"canDownload":true}},`, 21), ",") + `]}`, nil, ErrProvider},
		"a name that holds the token":                    {listing(foundFile("file-A", "google-access-private")), nil, ErrProvider},
		"a name that holds the token, escaped":           {`{"files":[{"id":"file-A","name":"\u0067oogle-access-private","mimeType":"text/plain","size":"3","capabilities":{"canDownload":true}}]}`, nil, ErrProvider},
		"an answer that is no JSON":                      {`<html>`, nil, ErrProvider},
		"a further page whose mark is too long":          {`{"files":[],"nextPageToken":"` + strings.Repeat("n", 4097) + `"}`, nil, ErrProvider},
		"a search that did not look everywhere":          {`{"files":[],"incompleteSearch":true}`, nil, nil},
		"a file with no name":                            {listing(foundFile("file-A", ""), foundFile("file-B", "b.txt")), []string{"file-B"}, nil},
		"a name with a line end in it":                   {listing(foundFile("file-A", "line\none"), foundFile("file-B", "b.txt")), []string{"file-B"}, nil},
		"a name with a tab in it":                        {listing(foundFile("file-A", "one\ttwo"), foundFile("file-B", "b.txt")), []string{"file-B"}, nil},
		"a name with a delete in it":                     {listing(foundFile("file-A", "one\x7ftwo"), foundFile("file-B", "b.txt")), []string{"file-B"}, nil},
		"a name of more than 250 bytes":                  {listing(foundFile("file-A", strings.Repeat("é", 126)), foundFile("file-B", strings.Repeat("é", 125))), []string{"file-B"}, nil},
		"a file that may not be downloaded":              {listing(with(foundFile("file-A", "a.txt"), "capabilities", map[string]bool{"canDownload": false}), foundFile("file-B", "b.txt")), []string{"file-B"}, nil},
		"a file of which no capability is said":          {listing(map[string]any{"id": "file-A", "name": "a.txt", "mimeType": "text/plain", "size": "3"}, foundFile("file-B", "b.txt")), []string{"file-B"}, nil},
		"a file of no bytes":                             {listing(with(foundFile("file-A", "a.txt"), "size", "0"), foundFile("file-B", "b.txt")), []string{"file-B"}, nil},
		"a file of more than four mebibytes":             {listing(with(foundFile("file-A", "a.txt"), "size", "4194305"), with(foundFile("file-B", "b.txt"), "size", "4194304")), []string{"file-B"}, nil},
		"a file whose size is no number":                 {listing(with(foundFile("file-A", "a.txt"), "size", "3 bytes"), foundFile("file-B", "b.txt")), []string{"file-B"}, nil},
		"a file of which no size is said":                {listing(map[string]any{"id": "file-A", "name": "a.txt", "mimeType": "text/plain", "capabilities": map[string]bool{"canDownload": true}}, foundFile("file-B", "b.txt")), []string{"file-B"}, nil},
		"a document of Google's, which has no size":      {listing(map[string]any{"id": "doc-A", "name": "Plan", "mimeType": "application/vnd.google-apps.spreadsheet", "capabilities": map[string]bool{"canDownload": true}}), []string{"doc-A"}, nil},
	} {
		b, _ := driveSearched(t, example.files, 200)
		found, e := searchDrive(t, b, "words")
		var ids []string
		for _, item := range found.Items {
			ids = append(ids, item.ID)
		}
		if e != example.err || strings.Join(ids, " ") != strings.Join(example.items, " ") {
			t.Errorf("%s: %v and %v, and not %v and %v", name, ids, e, example.items, example.err)
		}
		if name == "a search that did not look everywhere" && !found.More {
			t.Errorf("%s: it is not said that there may be more", name)
		}
	}
}

// What a search offers, adapter-drive reads: each name and size the search
// lets through is one the read takes.
func TestDriveSearchOffersWhatTheReadTakes(t *testing.T) {
	for _, name := range []string{"a", strings.Repeat("é", 125), "x\u202ey", "  spaced  name  ", "\u200f"} {
		if !readableName(name) {
			t.Errorf("the search and the read differ on the name %q", name)
		}
	}
	for name, read := range map[string]bool{"": false, "a\nb": false, "a\x00b": false, "a\rb": false, "a\x1fb": false, "a\x7fb": false, strings.Repeat("a", 251): false, strings.Repeat("a", 250): true} {
		if readableName(name) != read {
			t.Errorf("the name %.20q of %d bytes: %v", name, len(name), !read)
		}
	}
	for _, example := range []struct {
		media, size string
		read        bool
	}{{"text/plain", "1", true}, {"text/plain", "4194304", true}, {"text/plain", "4194305", false}, {"text/plain", "0", false}, {"text/plain", "-1", false}, {"text/plain", "", false}, {"text/plain", "1e3", false}, {"application/vnd.google-apps.document", "", true}} {
		if readableSize(example.media, example.size) != example.read {
			t.Errorf("a file of %s and the size %q: %v", example.media, example.size, !example.read)
		}
	}
}

func TestDriveSearchShowsANameAsText(t *testing.T) {
	long := strings.Repeat("é", 100) + strings.Repeat("a", 40)
	b, _ := driveSearched(t, listing(
		foundFile("a", "gnp\u202eexe.\u061cx\u200ey\u200fz\u202a\u202b\u202c\u202d\u2066\u2067\u2068\u2069end"),
		foundFile("b", "  one   two  "),
		foundFile("c", " \u2066\u200e "),
		foundFile(strings.Repeat("d", 200), "\u200f"),
	), 200)
	found, e := searchDrive(t, b, "words")
	if e != nil || len(found.Items) != 4 {
		t.Fatal(found, e)
	}
	if found.Items[0].Title != "gnp exe. x y z end" {
		t.Errorf("a name's marks of direction were shown: %q", found.Items[0].Title)
	}
	if found.Items[1].Title != "one two" {
		t.Errorf("a name's spaces were shown as they were: %q", found.Items[1].Title)
	}
	if found.Items[2].Title != "c" {
		t.Errorf("a name of nothing to show was shown as %q", found.Items[2].Title)
	}
	if got := []rune(found.Items[3].Title); len(got) != 128 || found.Items[3].Title != strings.Repeat("d", 128) {
		t.Errorf("an ID shown for a name was shown in %d characters", len(got))
	}
	b, _ = driveSearched(t, listing(foundFile("e", long)), 200)
	if found, e = searchDrive(t, b, "words"); e != nil || len(found.Items) != 1 {
		t.Fatal(found, e)
	}
	if got := []rune(found.Items[0].Title); len(got) != 128 || string(got) != strings.Repeat("é", 100)+strings.Repeat("a", 28) {
		t.Errorf("a long name was shown in %d characters: %q", len(got), found.Items[0].Title)
	}
}

func TestDriveSearchRefusals(t *testing.T) {
	b, asked := driveSearched(t, `{"files":[]}`, 200)
	for _, raw := range []string{`{"query":"a\nb"}`, `{"query":"a\rb"}`, `{"query":"a\u0000b"}`, `{"query":"` + strings.Repeat("a", 1025) + `"}`, `{"query":"a","pageToken":"x"}`, `{"Query":"a"}`, `{"query":"a","query":"b"}`, `[]`} {
		if _, e := b.Handle(context.Background(), "search", []byte(raw)); e != ErrRequest {
			t.Errorf("%.40s: %v", raw, e)
		}
	}
	if len(*asked) != 0 {
		t.Error("a refused search asked Drive")
	}
	if _, e := searchDrive(t, b, strings.Repeat("a", 1024)); e != nil || len(*asked) != 1 {
		t.Errorf("a search of 1024 bytes: %v", e)
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
	b, asked = driveSearched(t, `{"files":[]}`, 200)
	b.disabled = true
	if _, e := b.Handle(context.Background(), "search", []byte(`{"query":"words"}`)); e != ErrPolicy {
		t.Errorf("a search of a blocked connection: %v", e)
	}
	if len(*asked) != 0 {
		t.Error("a search of a blocked connection asked Drive")
	}
}

// A connection that ends while Drive is answering gives none of the answer:
// one that another took the place of, one that was removed, and one that the
// operator blocked.
func TestDriveSearchGivesNothingOfAConnectionThatEnded(t *testing.T) {
	for name, example := range map[string]struct {
		end  func(v *state)
		want error
	}{
		"the connection was made again":  {func(v *state) { v.Epoch = randomID() }, ErrCanceled},
		"the connection was removed":     {func(v *state) { v.Connection = nil }, ErrCanceled},
		"another connection is in place": {func(v *state) { v.Connection.ID = randomID() }, ErrCanceled},
		"the operator blocked it":        {func(v *state) { v.Disabled = true }, ErrPolicy},
	} {
		b, _ := driveSearched(t, listing(foundFile("file-A", "a.txt")), 200)
		inner := b.provider.client.Transport
		b.provider.client = &http.Client{Transport: pausedTransport(func(r *http.Request) (*http.Response, error) {
			res, e := inner.RoundTrip(r)
			if r.URL.Path == "/files" {
				b.store.locked(func(v *state) error { example.end(v); return b.store.write("state.json", v) })
			}
			return res, e
		})}
		if found, e := searchDrive(t, b, "words"); e != example.want || len(found.Items) != 0 {
			t.Errorf("%s: %+v, %v", name, found, e)
		}
	}
}

func TestDriveSelectionIsOfTheConnectionThatWasSearched(t *testing.T) {
	b, _ := driveSearched(t, listing(foundFile("file-A", "a.txt")), 200)
	found, e := searchDrive(t, b, "words")
	if e != nil {
		t.Fatal(e)
	}
	choose := func(ids []string, under string) ([]SourceSelection, error) {
		v, e := b.Handle(context.Background(), "select", mustJSON(map[string]any{"resourceIds": ids, "selectionContext": under}))
		if e != nil {
			return nil, e
		}
		return v.([]SourceSelection), nil
	}
	// file-B is one no search gave. A selection takes it, as the record says.
	picked, e := choose([]string{"file-A", "file-B", "file-C", "file-D"}, found.SelectionContext)
	if e != nil || len(picked) != 4 {
		t.Fatal(picked, e)
	}
	grants := map[string]bool{}
	for i, id := range []string{"file-A", "file-B", "file-C", "file-D"} {
		if picked[i].ResourceID != id || !opaque.MatchString(picked[i].Grant) || grants[picked[i].Grant] {
			t.Fatalf("the grant at %d is for %s", i, picked[i].ResourceID)
		}
		grants[picked[i].Grant] = true
		raw, e := b.store.read("grant-" + picked[i].Grant)
		var g grant
		if e != nil || json.Unmarshal(raw, &g) != nil || g.File != id {
			t.Errorf("the grant that is kept for %s is for %q", id, g.File)
		}
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

// The whole of what a host does to read a file: it connects, searches,
// selects what the search gave, and reads, each as a request in JSON and with
// what the request before it answered.
func TestDriveFileIsSearchedSelectedAndRead(t *testing.T) {
	b, reads, _ := testBroker(t)
	if r := finish(t, b, start(t, b, "connect"), nil); r.State != "complete" {
		t.Fatal(r)
	}
	files := b.provider.client.Transport
	b.provider.client = &http.Client{Transport: pausedTransport(func(r *http.Request) (*http.Response, error) {
		if r.URL.Path == "/files" {
			return fakeResponse(r, []byte(listing(map[string]any{"id": "file-A", "name": "policy.txt", "mimeType": "text/plain", "size": "23", "capabilities": map[string]bool{"canDownload": true}}))), nil
		}
		return files.RoundTrip(r)
	})}
	answer := func(method, params string) map[string]any {
		v, e := b.Handle(context.Background(), method, []byte(params))
		if e != nil {
			t.Fatal(method, e)
		}
		var out map[string]any
		raw, _ := json.Marshal(map[string]any{"result": v})
		if json.Unmarshal(raw, &out) != nil {
			t.Fatal(method, "answered what is no JSON")
		}
		return out
	}
	found := answer("search", `{"query":"policy"}`)["result"].(map[string]any)
	item := found["items"].([]any)[0].(map[string]any)
	picked := answer("select", string(mustJSON(map[string]any{"resourceIds": []any{item["id"]}, "selectionContext": found["selectionContext"]})))["result"].([]any)[0].(map[string]any)
	if len(picked) != 2 || picked["resourceId"] != "file-A" {
		t.Fatalf("a selection answered %v", picked)
	}
	out, e := b.provider.read(context.Background(), b.store, mustJSON(map[string]any{"fileId": picked["resourceId"], "grant": picked["grant"]}))
	if e != nil {
		t.Fatal(e)
	}
	var envelope struct {
		Result struct {
			Provenance struct {
				Source struct {
					FileID string `json:"fileId"`
				}
			}
		}
	}
	if json.Unmarshal(out, &envelope) != nil || envelope.Result.Provenance.Source.FileID != "file-A" || reads.Load() != 3 {
		t.Errorf("the read is of %q, in %d requests", envelope.Result.Provenance.Source.FileID, reads.Load())
	}
}

// The consent that is asked is for the whole Drive, and Google's own chooser
// of files is asked for in no part of it. An answer that names files as the
// chooser's did gives a connection and no grant.
func TestConsentAsksForTheWholeDriveAndForNoChooser(t *testing.T) {
	b, _, _ := testBroker(t)
	f := start(t, b, "connect")
	u, _ := url.Parse(f.URL)
	q := u.Query()
	if q.Get("scope") != "https://www.googleapis.com/auth/drive" || q.Get("include_granted_scopes") != "false" || q.Get("prompt") != "consent" || q.Get("access_type") != "offline" {
		t.Error("the consent asks", q.Encode())
	}
	for _, name := range []string{"trigger_onepick", "allow_multiple", "mimetypes", "picked_file_ids"} {
		if q.Has(name) {
			t.Error("the consent asks Google's chooser for", name)
		}
	}
	done := finish(t, b, f, url.Values{"picked_file_ids": {"file-A,file-B"}})
	if raw, _ := json.Marshal(done); done.State != "complete" || string(raw) != `{"id":"`+done.ID+`","state":"complete"}` {
		t.Errorf("a consent answered %s", raw)
	}
	names, e := os.ReadDir(b.store.root.Name())
	if e != nil {
		t.Fatal(e)
	}
	for _, name := range names {
		if strings.HasPrefix(name.Name(), "grant-") {
			t.Error("an answer that named files gave a grant")
		}
	}
	if _, e := b.Handle(context.Background(), "pick", []byte(`{}`)); e != ErrRequest {
		t.Errorf("pick: %v", e)
	}
}

// What the catalog says of Drive, whole.
func TestCatalogSaysDriveIsSearchedAndSelected(t *testing.T) {
	d, ok := LookupProvider("google-drive")
	if raw, _ := json.Marshal(d); !ok || string(raw) != `{"id":"google-drive","auth":"oauth","registration":"google-desktop","selection":"source-search","queryRequired":false,"operations":["status","configure","connect","poll","cancel","disconnect","search","select"]}` {
		t.Errorf("%s", raw)
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

// The read refuses, by what Drive says of a file, what the search does not
// offer: a selection takes any ID, so the read is what holds.
func TestReadRefusesAFileTheSearchWouldNotOffer(t *testing.T) {
	for name, said := range map[string]map[string]any{
		"a file with no name":                {"name": ""},
		"a name with a line end in it":       {"name": "line\none"},
		"a name with a delete in it":         {"name": "one\x7ftwo"},
		"a name of more than 250 bytes":      {"name": strings.Repeat("a", 251)},
		"a file that may not be downloaded":  {"capabilities": map[string]bool{"canDownload": false}},
		"a file of more than four mebibytes": {"size": "4194305"},
		"a file of no bytes":                 {"size": "0"},
		"a file of a kind that is not read":  {"mimeType": "application/zip"},
		"a file in the trash":                {"trashed": true},
	} {
		b, _, _ := testBroker(t)
		r := choose(t, b, "file-N")
		file := map[string]any{"id": "file-N", "name": "n.txt", "mimeType": "text/plain", "version": "7", "size": "3", "capabilities": map[string]bool{"canDownload": true}}
		for member, value := range said {
			file[member] = value
		}
		raw, _ := json.Marshal(file)
		content := 0
		b.provider.client = &http.Client{Transport: pausedTransport(func(r *http.Request) (*http.Response, error) {
			if r.URL.Query().Get("alt") == "media" {
				content++
			}
			return fakeResponse(r, raw), nil
		})}
		if out, e := b.provider.read(context.Background(), b.store, mustJSON(ReadRequest{r.Selections[0].Grant, "file-N"})); e == nil || len(out) != 0 || content != 0 {
			t.Errorf("%s: the read answered %v, and asked for the bytes %d times", name, e, content)
		}
	}
}
