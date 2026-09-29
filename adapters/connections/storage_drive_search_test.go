//go:build linux || darwin

package connections

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// driveAsItAnswers is a stand-in that refuses what Drive was seen to refuse:
// an order asked of a search by words. The status and the body are Drive's
// own, of 2026-09-29. It keeps the order that each request asked for.
func driveAsItAnswers(t *testing.T, orders *[]string) *httptest.Server {
	t.Helper()
	return httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" || r.URL.Path != "/files" {
			t.Error("a request that is no listing", r.Method, r.URL.Path)
			w.WriteHeader(500)
			return
		}
		q := r.URL.Query()
		*orders = append(*orders, q.Get("orderBy"))
		if q.Has("orderBy") && q.Get("q") != "trashed = false" {
			w.WriteHeader(403)
			io.WriteString(w, `{"error":{"code":403,"message":"Sorting is not supported for queries with fullText terms. Results are always in descending relevance order.","errors":[{"message":"Sorting is not supported for queries with fullText terms. Results are always in descending relevance order.","domain":"global","reason":"forbidden","location":"orderBy","locationType":"parameter"}]}}`)
			return
		}
		io.WriteString(w, `{"files":[{"id":"file-A","name":"policy.txt","mimeType":"text/plain","version":"1","size":"3","capabilities":{"canDownload":true,"canEdit":true,"canTrash":true}}]}`)
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
	b := New(s, false)
	b.provider.api = server.URL
	b.provider.client = server.Client()
	t.Cleanup(b.Close)
	return b
}

func TestStorageDriveSearchByWordsAsksForNoOrder(t *testing.T) {
	var orders []string
	server := driveAsItAnswers(t, &orders)
	defer server.Close()
	b := driveSearchBroker(t, server)
	page, e := b.Handle(context.Background(), "files-list", mustJSON(StorageQuery{Query: "policy"}))
	if e != nil {
		t.Fatal("a search by words was refused:", e)
	}
	if found := page.(StoragePage); len(found.Items) != 1 || found.Items[0].ID != "file-A" {
		t.Fatal("the search did not give what Drive found", found.Items)
	}
	if len(orders) != 1 || orders[0] != "" {
		t.Fatal("the search asked for an order", orders)
	}
}

func TestStorageDriveListingWithoutWordsIsByName(t *testing.T) {
	var orders []string
	server := driveAsItAnswers(t, &orders)
	defer server.Close()
	b := driveSearchBroker(t, server)
	if _, e := b.Handle(context.Background(), "files-list", mustJSON(StorageQuery{})); e != nil {
		t.Fatal("a listing was refused:", e)
	}
	if len(orders) != 1 || orders[0] != "folder,name" {
		t.Fatal("the listing is not asked for by name, folders first", orders)
	}
}
