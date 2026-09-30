//go:build linux || darwin

package connections

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

// driveAsItAnswers is a stand-in that refuses what Drive was seen to refuse:
// an order asked of a search by words. The status and the body are Drive's
// own, of 2026-09-29. It keeps what each request asked, and answers a
// listing with three items in an order that is neither of name nor of kind.
func driveAsItAnswers(t *testing.T, asked *[]url.Values) *httptest.Server {
	t.Helper()
	return httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" || r.URL.Path != "/files" {
			t.Error("a request that is no listing", r.Method, r.URL.Path)
			w.WriteHeader(500)
			return
		}
		q := r.URL.Query()
		*asked = append(*asked, q)
		if q.Has("orderBy") && strings.Contains(q.Get("q"), "fullText contains") {
			w.WriteHeader(403)
			io.WriteString(w, `{"error":{"code":403,"message":"Sorting is not supported for queries with fullText terms. Results are always in descending relevance order.","errors":[{"message":"Sorting is not supported for queries with fullText terms. Results are always in descending relevance order.","domain":"global","reason":"forbidden","location":"orderBy","locationType":"parameter"}]}}`)
			return
		}
		io.WriteString(w, `{"files":[`+
			`{"id":"file-M","name":"m.txt","mimeType":"text/plain","version":"1","size":"3","capabilities":{"canDownload":true,"canEdit":true,"canTrash":true}},`+
			`{"id":"folder-Z","name":"z","mimeType":"application/vnd.google-apps.folder","version":"1","capabilities":{}},`+
			`{"id":"file-A","name":"a.txt","mimeType":"text/plain","version":"1","size":"3","capabilities":{"canDownload":true,"canEdit":true,"canTrash":true}}]}`)
	}))
}

func driveSearchBroker(t *testing.T, server *httptest.Server) *Broker {
	t.Helper()
	s := testStore(t, "drive-search")
	s.locked(func(v *state) error {
		v.Epoch = "epoch"
		v.Connection = &credential{ID: "connection", Access: "private-token", Expires: time.Now().Add(time.Hour).Unix()}
		return s.write("state.json", v)
	})
	consented(t, s)
	b := New(s, false)
	b.provider.api = server.URL
	b.provider.client = server.Client()
	t.Cleanup(b.Close)
	return b
}

// What Drive is asked, for a listing and for a search, in a folder and in
// none; and that the items come as Drive gave them.
func TestStorageDriveAsksForAnOrderOnlyWithoutWords(t *testing.T) {
	for name, example := range map[string]struct {
		query    StorageQuery
		q, order string
	}{
		"a listing":                {StorageQuery{}, "trashed = false", "folder,name"},
		"a listing of a folder":    {StorageQuery{Folder: "folder-A"}, "trashed = false and 'folder-A' in parents", "folder,name"},
		"a search by words":        {StorageQuery{Query: "policy"}, "trashed = false and fullText contains 'policy'", ""},
		"a search within a folder": {StorageQuery{Folder: "folder-A", Query: "policy"}, "trashed = false and 'folder-A' in parents and fullText contains 'policy'", ""},
	} {
		var asked []url.Values
		server := driveAsItAnswers(t, &asked)
		b := driveSearchBroker(t, server)
		page, e := b.Handle(context.Background(), "files-list", mustJSON(example.query))
		if e != nil {
			t.Errorf("%s was refused: %v", name, e)
			server.Close()
			continue
		}
		if len(asked) != 1 || asked[0].Get("q") != example.q {
			t.Errorf("%s asked %v, and not once for %q", name, asked, example.q)
		} else if asked[0].Get("orderBy") != example.order || asked[0].Has("orderBy") != (example.order != "") {
			t.Errorf("%s asked for the order %q, and not %q", name, asked[0].Get("orderBy"), example.order)
		}
		items := page.(StoragePage).Items
		if len(items) != 3 || items[0].ID != "file-M" || items[1].ID != "folder-Z" || items[2].ID != "file-A" {
			t.Errorf("%s does not give the items as Drive gave them: %+v", name, items)
		}
		server.Close()
	}
}
