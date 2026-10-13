//go:build linux || darwin

package connections

import (
	"adapters/agreement"
	"adapters/internal/canon"
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

// Every test here answers from an in-process TLS server. The workspace's
// host name is of a workspace's form, and the test's transport dials the
// server whatever the name; nothing reaches a real workspace.
const (
	dbHost      = "example.cloud.databricks.com"
	dbWorkspace = "https://" + dbHost
	dbWarehouse = "0123456789abcdef"
	dbClient    = "00000000-0000-4000-8000-000000000000"
	// Markers: each is asserted absent wherever the connection writes.
	dbPAT       = "dapi-marker-personal-token-7f3a9c"
	dbSecret    = "dose-marker-client-secret-41b2e8"
	dbMinted    = "minted-marker-access-token-c90d17"
	dbStatement = "01f0a1b2-c3d4-1e5f-8a9b-0c1d2e3f4a5b"
)

func dbSucceeded(rows string) string {
	return `{"statement_id":"` + dbStatement + `","status":{"state":"SUCCEEDED"},"manifest":{"format":"JSON_ARRAY","schema":{"column_count":1,"columns":[{"name":"n","type_text":"STRING","type_name":"STRING","position":0}]},"total_chunk_count":1,"chunks":[{"chunk_index":0,"row_offset":0,"row_count":1}],"total_row_count":1,"truncated":false},"result":{"chunk_index":0,"row_offset":0,"row_count":1,"data_array":[` + rows + `]}}`
}

// dbFake is a workspace: its token endpoint and its API, each answering as
// the test sets it, counting what it was asked.
type dbFake struct {
	server *httptest.Server
	api    atomic.Int32
	mints  atomic.Int32
	mu     sync.Mutex
	answer func(w http.ResponseWriter, r *http.Request, body []byte)
	token  func(w http.ResponseWriter, r *http.Request, form url.Values)
	paths  []string
	bodies [][]byte
}

func newDBFake(t *testing.T) *dbFake {
	t.Helper()
	f := &dbFake{}
	f.answer = func(w http.ResponseWriter, r *http.Request, body []byte) { io.WriteString(w, dbSucceeded(`["1"]`)) }
	f.token = func(w http.ResponseWriter, r *http.Request, form url.Values) {
		io.WriteString(w, `{"access_token":"`+dbMinted+`","token_type":"Bearer","expires_in":3600,"scope":"all-apis"}`)
	}
	f.server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		f.mu.Lock()
		answer, token := f.answer, f.token
		f.mu.Unlock()
		if r.URL.Path == "/oidc/v1/token" {
			f.mints.Add(1)
			form, _ := url.ParseQuery(string(body))
			token(w, r, form)
			return
		}
		f.api.Add(1)
		f.mu.Lock()
		f.paths = append(f.paths, r.Method+" "+r.URL.RequestURI())
		f.bodies = append(f.bodies, body)
		f.mu.Unlock()
		answer(w, r, body)
	}))
	t.Cleanup(f.server.Close)
	return f
}
func (f *dbFake) set(answer func(w http.ResponseWriter, r *http.Request, body []byte)) {
	f.mu.Lock()
	f.answer = answer
	f.mu.Unlock()
}
func (f *dbFake) setToken(token func(w http.ResponseWriter, r *http.Request, form url.Values)) {
	f.mu.Lock()
	f.token = token
	f.mu.Unlock()
}
func (f *dbFake) last() (string, []byte) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.paths) == 0 {
		return "", nil
	}
	return f.paths[len(f.paths)-1], f.bodies[len(f.bodies)-1]
}

// provider is the connection's own provider, its redirect rule and
// timeouts included, with a transport that trusts the server and dials it.
func (f *dbFake) provider() provider {
	p := databricksProvider()
	transport := p.client.Transport.(*http.Transport).Clone()
	pool := x509.NewCertPool()
	pool.AddCert(f.server.Certificate())
	transport.TLSClientConfig = &tls.Config{RootCAs: pool, ServerName: "example.com"}
	transport.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, f.server.Listener.Addr().String())
	}
	p.client = &http.Client{Transport: transport, CheckRedirect: p.client.CheckRedirect, Timeout: p.client.Timeout}
	return p
}
func (f *dbFake) peer() string {
	sum := sha256.Sum256(f.server.Certificate().Raw)
	return "tls:sha256:" + hex.EncodeToString(sum[:])
}

func dbConfigure(b *Broker, fields map[string]string) error {
	raw, _ := json.Marshal(fields)
	_, err := b.Handle(context.Background(), "configure", raw)
	return err
}
func dbTokenFields() map[string]string {
	return map[string]string{"id": "lake", "name": "Lake", "workspace-url": dbWorkspace, "warehouse-id": dbWarehouse, "auth": "token", "token": dbPAT, "catalog": "main"}
}
func dbPrincipalFields() map[string]string {
	return map[string]string{"id": "lake", "name": "Lake", "workspace-url": dbWorkspace, "warehouse-id": dbWarehouse, "auth": "service-principal", "client-id": dbClient, "client-secret": dbSecret}
}

// dbFixture is a store holding one connection made of fields.
func dbFixture(t *testing.T, fields map[string]string) (*Store, *Broker, DatabricksConnection, string) {
	t.Helper()
	dir := t.TempDir()
	os.Chmod(dir, 0700)
	s, err := OpenDatabricksStore(dir, "test")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	b := NewDatabricks(s, false)
	t.Cleanup(b.Close)
	if err = dbConfigure(b, fields); err != nil {
		t.Fatal(err)
	}
	return s, b, dbConnection(t, s, fields["id"]), dir
}
func dbConnection(t *testing.T, s *Store, id string) DatabricksConnection {
	t.Helper()
	var c DatabricksConnection
	s.locked(func(v *state) error {
		for _, x := range v.Databricks.Connections {
			if x.ID == id {
				c = x
			}
		}
		return nil
	})
	if c.ID == "" {
		t.Fatal("no connection", id)
	}
	return c
}
func dbStatementRead(c DatabricksConnection, statement string) DatabricksRequest {
	return DatabricksRequest{Connection: c.ID, Revision: c.Revision, Read: "statement", Statement: statement}
}

// dbState is the custody file as it is on disk.
func dbState(t *testing.T, dir string) []byte {
	t.Helper()
	var found []byte
	filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err == nil && d.Name() == "state.json" && strings.Contains(path, string(filepath.Separator)+"databricks"+string(filepath.Separator)) {
			found, _ = os.ReadFile(path)
		}
		return nil
	})
	if found == nil {
		t.Fatal("no databricks state on disk")
	}
	return found
}

// An inline result is read in one request of the form the API states, and
// the envelope is held to the form the signer holds it to.
func TestDatabricksStatementIsOneInlineRequest(t *testing.T) {
	s, _, c, _ := dbFixture(t, dbTokenFields())
	f := newDBFake(t)
	answer := dbSucceeded(`["1"]`)
	f.set(func(w http.ResponseWriter, r *http.Request, body []byte) {
		if r.Header.Get("Authorization") != "Bearer "+dbPAT {
			t.Error("the token is not the bearer")
		}
		io.WriteString(w, answer)
	})
	one := "1"
	q := dbStatementRead(c, "SELECT :n AS n\n-- a comment")
	q.Parameters = []DatabricksParameter{{Name: "n", Value: &one, Type: "INT"}, {Name: "absent"}}
	raw, err := databricksAcquire(context.Background(), s, q, f.provider())
	if err != nil {
		t.Fatal(err)
	}
	path, body := f.last()
	if f.api.Load() != 1 || path != "POST /api/2.0/sql/statements" {
		t.Fatalf("%d requests, last %s", f.api.Load(), path)
	}
	var sent map[string]any
	if json.Unmarshal(body, &sent) != nil {
		t.Fatal("the request body is not JSON")
	}
	want := map[string]any{"warehouse_id": dbWarehouse, "statement": q.Statement, "wait_timeout": "30s", "on_wait_timeout": "CANCEL", "disposition": "INLINE", "format": "JSON_ARRAY", "catalog": "main",
		"parameters": []any{map[string]any{"name": "n", "value": "1", "type": "INT"}, map[string]any{"name": "absent"}}}
	if got, _ := json.Marshal(sent); string(got) != func() string { w, _ := json.Marshal(want); return string(w) }() {
		t.Fatalf("sent %s", got)
	}
	e, err := agreement.Parse(raw)
	if err != nil {
		t.Fatal("the envelope is not of the signer's form:", err)
	}
	a := e.Acquisition
	if a.Adapter.Name != "adapter-sources" || !canon.IsDigestString(a.Adapter.Digest) || a.Endpoint == nil || *a.Endpoint != dbWorkspace+"/api/2.0/sql/statements" ||
		a.Snapshot == nil || *a.Snapshot != dbStatement || a.PeerIdentity == nil || *a.PeerIdentity != f.peer() || a.Schema != nil || a.UpstreamToken != nil {
		t.Fatalf("acquisition %+v", a)
	}
	if observed, err := time.Parse("2006-01-02T15:04:05Z", a.ObservedAt); err != nil || time.Since(observed) > time.Minute {
		t.Fatal("observedAt", a.ObservedAt)
	}
	members, err := agreement.Statement(e)
	if err != nil {
		t.Fatal(err)
	}
	for name, want := range map[string]string{"connection": `"lake"`, "revision": `"` + c.Revision + `"`, "provider": `"databricks"`, "read": `"statement"`, "method": `"POST"`, "endpoint": `"` + dbWorkspace + `/api/2.0/sql/statements"`} {
		if string(members[name]) != want {
			t.Errorf("statement %s = %s", name, members[name])
		}
	}
	if !bytes.Equal(members["body"], func() []byte { c, _ := canon.Canonicalize(body, canon.RefuseNumbers); return c }()) {
		t.Errorf("the statement's body is not the body sent: %s", members["body"])
	}
	result, _ := canon.Canonicalize([]byte(answer), canon.CarryNumbersAsText)
	if !bytes.Equal(e.Result, result) {
		t.Fatalf("the result is not the answer as received:\n%s", e.Result)
	}
}

// A statement whose state is not SUCCEEDED is refused in the API's words,
// or for its wait; nothing is polled and nothing is asked again.
func TestDatabricksStatementStates(t *testing.T) {
	fields := dbTokenFields()
	fields["wait-seconds"] = "5"
	s, _, c, _ := dbFixture(t, fields)
	f := newDBFake(t)
	for _, k := range []struct {
		name, answer, want string
		sleep              time.Duration
	}{
		{"failed", `{"statement_id":"` + dbStatement + `","status":{"state":"FAILED","error":{"error_code":"BAD_REQUEST","message":"[TABLE_OR_VIEW_NOT_FOUND] The table or view ` + "`missing`" + ` cannot be found.\nVerify the spelling."}}}`,
			"statement-failed: [TABLE_OR_VIEW_NOT_FOUND] The table or view `missing` cannot be found.\nVerify the spelling.", 0},
		{"canceled with a message", `{"statement_id":"` + dbStatement + `","status":{"state":"CANCELED","error":{"error_code":"CANCELLED","message":"Cancelled by a user."}}}`, "statement-canceled: Cancelled by a user.", 0},
		{"pending", `{"statement_id":"` + dbStatement + `","status":{"state":"PENDING"}}`, "statement-timeout: the statement did not finish within 5 seconds; the workspace answered PENDING, and it is not polled", 0},
		{"chunked", `{"statement_id":"` + dbStatement + `","status":{"state":"SUCCEEDED"},"manifest":{"total_chunk_count":2,"truncated":false},"result":{"chunk_index":0,"data_array":[["1"]],"next_chunk_index":1,"next_chunk_internal_link":"/api/2.0/sql/statements/` + dbStatement + `/result/chunks/1"}}`,
			"result-incomplete: the workspace answered part of the result, in chunks or truncated; the rest is not fetched", 0},
		{"truncated", `{"statement_id":"` + dbStatement + `","status":{"state":"SUCCEEDED"},"manifest":{"total_chunk_count":1,"truncated":true},"result":{"data_array":[["1"]]}}`,
			"result-incomplete: the workspace answered part of the result, in chunks or truncated; the rest is not fetched", 0},
		{"no statement", `{"status":{"state":"SUCCEEDED"}}`, "provider-unavailable: the workspace's answer names no statement", 0},
		// The wait passes and the workspace answers CANCELED, as
		// on_wait_timeout CANCEL asks it to.
		{"wait timeout", `{"statement_id":"` + dbStatement + `","status":{"state":"CANCELED"}}`, "statement-timeout: the statement did not finish within 5 seconds and was cancelled", 5*time.Second + 100*time.Millisecond},
	} {
		before := f.api.Load()
		f.set(func(w http.ResponseWriter, r *http.Request, body []byte) {
			time.Sleep(k.sleep)
			io.WriteString(w, k.answer)
		})
		out, err := databricksAcquire(context.Background(), s, dbStatementRead(c, "SELECT * FROM missing"), f.provider())
		if out != nil || err == nil || err.Error() != k.want {
			t.Errorf("%s: %v", k.name, err)
		}
		if f.api.Load() != before+1 {
			t.Errorf("%s: %d requests", k.name, f.api.Load()-before)
		}
		_, body := f.last()
		var sent map[string]any
		if json.Unmarshal(body, &sent) != nil || sent["wait_timeout"] != "5s" || sent["on_wait_timeout"] != "CANCEL" || sent["disposition"] != "INLINE" {
			t.Errorf("%s: sent %s", k.name, body)
		}
	}
}

// A CANCELED state without a message before the wait has passed was not
// the wait's doing, and is not reported as it.
func TestDatabricksAnEarlyCancelIsNotTheWait(t *testing.T) {
	_, err := databricksStatement([]byte(`{"statement_id":"`+dbStatement+`","status":{"state":"CANCELED"}}`), 30, 2*time.Second, nil)
	if err == nil || err.Error() != "statement-canceled: the statement was cancelled in the workspace before 30 seconds had passed" {
		t.Fatal(err)
	}
	id, err := databricksStatement([]byte(dbSucceeded(`["1"]`)), 30, time.Second, nil)
	if err != nil || id != dbStatement {
		t.Fatal(id, err)
	}
}

// The configured bound holds an answer to it: one of the bound's size is
// read, one a byte over it is refused, with a length announced or not.
func TestDatabricksResultBound(t *testing.T) {
	fields := dbTokenFields()
	fields["max-result-bytes"] = "65536"
	s, _, c, _ := dbFixture(t, fields)
	f := newDBFake(t)
	sized := func(n int) string {
		short := dbSucceeded(`[""]`)
		return dbSucceeded(`["` + strings.Repeat("x", n-len(short)) + `"]`)
	}
	for _, k := range []struct {
		size     int
		announce bool
		ok       bool
	}{{65536, false, true}, {65536, true, true}, {65537, false, false}, {65537, true, false}} {
		body := sized(k.size)
		if len(body) != k.size {
			t.Fatal("fixture size", len(body))
		}
		f.set(func(w http.ResponseWriter, r *http.Request, _ []byte) {
			if k.announce {
				w.Header().Set("Content-Length", "65537")
				if k.size == 65536 {
					w.Header().Set("Content-Length", "65536")
				}
			}
			io.WriteString(w, body)
		})
		out, err := databricksAcquire(context.Background(), s, dbStatementRead(c, "SELECT 1"), f.provider())
		if k.ok != (err == nil) || !k.ok && (out != nil || err.Error() != "result-too-large: the workspace's answer is larger than the connection's bound of 65536 bytes") {
			t.Errorf("%d bytes, announced %v: %v", k.size, k.announce, err)
		}
	}
}

// Each answer other than 200 is refused naming its status and the API's
// error code, after one request: a 429 is reported with the wait it asks
// for and is not retried, and a redirect is not followed.
func TestDatabricksRefusalsNameTheStatusAndAreNotRetried(t *testing.T) {
	s, _, c, _ := dbFixture(t, dbTokenFields())
	f := newDBFake(t)
	for _, k := range []struct {
		name   string
		status int
		header map[string]string
		body   string
		want   string
	}{
		{"401", 401, nil, `{"error_code":"UNAUTHENTICATED","message":"Invalid access token."}`, "credentials-required: the workspace answered 401 (UNAUTHENTICATED)"},
		{"403", 403, nil, `{"error_code":"PERMISSION_DENIED","message":"User does not have USE CATALOG on Catalog 'main'."}`, "permission-denied: the workspace answered 403 (PERMISSION_DENIED)"},
		{"429 with Retry-After", 429, map[string]string{"Retry-After": "7"}, `{"error_code":"RESOURCE_EXHAUSTED","message":"Too many requests."}`, "rate-limited: the workspace answered 429 (RESOURCE_EXHAUSTED) and asks to wait 7 seconds before another request; it was not retried"},
		{"429 with RetryInfo", 429, nil, `{"error_code":"RESOURCE_EXHAUSTED","message":"Slow down.","details":[{"@type":"type.googleapis.com/google.rpc.RetryInfo","retry_delay":"3.5s"}]}`, "rate-limited: the workspace answered 429 (RESOURCE_EXHAUSTED) and asks to wait 3.5 seconds before another request; it was not retried"},
		{"429 from a front", 429, nil, `Too Many Requests`, "rate-limited: the workspace answered 429; it was not retried"},
		{"503", 503, nil, `{"error_code":"TEMPORARILY_UNAVAILABLE","message":"Try later."}`, "provider-unavailable: the workspace answered 503 (TEMPORARILY_UNAVAILABLE)"},
		{"500 without JSON", 500, nil, `<html>error</html>`, "provider-unavailable: the workspace answered 500"},
		{"400", 400, nil, `{"error_code":"INVALID_PARAMETER_VALUE","message":"bad"}`, "request-refused: the workspace answered 400 (INVALID_PARAMETER_VALUE)"},
		{"not JSON", 200, nil, `<html>sign in</html>`, "provider-unavailable: the workspace's answer is not JSON"},
		{"redirect", 302, map[string]string{"Location": "/api/2.0/sql/statements/elsewhere"}, ``, "provider-unavailable: the workspace answered 302, a redirect, which is not followed"},
	} {
		var answered atomic.Bool
		f.set(func(w http.ResponseWriter, r *http.Request, _ []byte) {
			// A request after the first, a retry or a redirect followed,
			// would be answered with a result.
			if answered.Swap(true) {
				io.WriteString(w, dbSucceeded(`["late"]`))
				return
			}
			for name, value := range k.header {
				w.Header().Set(name, value)
			}
			w.WriteHeader(k.status)
			io.WriteString(w, k.body)
		})
		for _, q := range []DatabricksRequest{dbStatementRead(c, "SELECT 1"), {Connection: c.ID, Revision: c.Revision, Read: "catalog", List: "catalogs"}} {
			answered.Store(false)
			before := f.api.Load()
			out, err := databricksAcquire(context.Background(), s, q, f.provider())
			if out != nil || err == nil || err.Error() != k.want {
				t.Errorf("%s, %s: %v", k.name, q.Read, err)
			}
			if f.api.Load() != before+1 {
				t.Errorf("%s, %s: %d requests", k.name, q.Read, f.api.Load()-before)
			}
		}
	}
}

// Each listing is one page per read: the caller's cursor is sent as the
// page token, and a next page token is the caller's to send, never followed.
func TestDatabricksCatalogListsOnePagePerRead(t *testing.T) {
	fields := dbTokenFields()
	fields["schema"] = "sales"
	s, _, c, _ := dbFixture(t, fields)
	f := newDBFake(t)
	for _, k := range []struct {
		list, catalog, schema, token string
		max                          int
		query                        string
		answer                       string
	}{
		{"catalogs", "", "", "", 0, "max_results=0", `{"catalogs":[{"name":"main"}],"next_page_token":"page-2"}`},
		{"catalogs", "", "", "page-2", 10, "max_results=10&page_token=page-2", `{"catalogs":[{"name":"system"}]}`},
		{"schemas", "", "", "", 0, "catalog_name=main&max_results=0", `{"schemas":[{"name":"sales","catalog_name":"main"}],"next_page_token":"s-2"}`},
		{"schemas", "other", "", "s-2", 0, "catalog_name=other&max_results=0&page_token=s-2", `{"schemas":[]}`},
		{"tables", "", "", "", 50, "catalog_name=main&max_results=50&schema_name=sales", `{"tables":[{"name":"orders","columns":[{"name":"id","position":0,"type_precision":0}]}],"next_page_token":"t-2"}`},
		{"tables", "", "", "t-2", 0, "catalog_name=main&max_results=0&page_token=t-2&schema_name=sales", `{"tables":[]}`},
		{"functions", "main", "finance", "", 0, "catalog_name=main&max_results=0&schema_name=finance", `{"functions":[{"name":"rate","full_name":"main.finance.rate"}],"next_page_token":"f-2"}`},
		{"functions", "main", "finance", "f-2", 1000, "catalog_name=main&max_results=1000&page_token=f-2&schema_name=finance", `{"functions":[]}`},
	} {
		before := f.api.Load()
		f.set(func(w http.ResponseWriter, r *http.Request, _ []byte) {
			if r.URL.Query().Get("page_token") != k.token {
				io.WriteString(w, `{"followed":true}`)
				return
			}
			io.WriteString(w, k.answer)
		})
		q := DatabricksRequest{Connection: c.ID, Revision: c.Revision, Read: "catalog", List: k.list, Catalog: k.catalog, Schema: k.schema, PageToken: k.token, MaxResults: k.max}
		raw, err := databricksAcquire(context.Background(), s, q, f.provider())
		if err != nil {
			t.Fatal(k.list, err)
		}
		path, _ := f.last()
		if f.api.Load() != before+1 || path != "GET /api/2.1/unity-catalog/"+k.list+"?"+k.query {
			t.Fatalf("%s: %d requests, last %s", k.list, f.api.Load()-before, path)
		}
		e, err := agreement.Parse(raw)
		if err != nil {
			t.Fatal(err)
		}
		result, _ := canon.Canonicalize([]byte(k.answer), canon.CarryNumbersAsText)
		if !bytes.Equal(e.Result, result) || *e.Acquisition.Snapshot != digest([]byte(k.answer)) || *e.Acquisition.Endpoint != dbWorkspace+"/api/2.1/unity-catalog/"+k.list || *e.Acquisition.PeerIdentity != f.peer() {
			t.Fatalf("%s: %s %+v", k.list, e.Result, e.Acquisition)
		}
		members, _ := agreement.Statement(e)
		if string(members["method"]) != `"GET"` || members["body"] != nil || members["query"] == nil {
			t.Fatalf("%s: statement %v", k.list, members)
		}
	}
	// Requests out of their form are refused before the network.
	before := f.api.Load()
	for name, q := range map[string]DatabricksRequest{
		"tables past 50":         {Read: "catalog", List: "tables", MaxResults: 51},
		"a negative page length": {Read: "catalog", List: "catalogs", MaxResults: -1},
		"an unknown listing":     {Read: "catalog", List: "volumes"},
		"a statement in a list":  {Read: "catalog", List: "catalogs", Statement: "SELECT 1"},
		"a list in a statement":  {Read: "statement", Statement: "SELECT 1", List: "tables"},
		"a page token of spaces": {Read: "catalog", List: "catalogs", PageToken: "a b"},
		"an empty statement":     {Read: "statement"},
		"a control character":    {Read: "statement", Statement: "SELECT 1\x00"},
		"a dotted catalog":       {Read: "catalog", List: "schemas", Catalog: "main.sales"},
		"a schema alone":         {Read: "catalog", List: "tables", Schema: "sales"},
		"a parameter twice":      {Read: "statement", Statement: "SELECT :a", Parameters: []DatabricksParameter{{Name: "a"}, {Name: "A"}}},
		"no read":                {},
	} {
		q.Connection, q.Revision = c.ID, c.Revision
		if _, err := databricksAcquire(context.Background(), s, q, f.provider()); err != ErrRequest {
			t.Errorf("%s: %v", name, err)
		}
	}
	if f.api.Load() != before {
		t.Fatal("a refused request reached the workspace")
	}
	// Without a default catalog, a schema listing needs one named.
	plain, _, pc, _ := dbFixture(t, map[string]string{"id": "plain", "name": "Plain", "workspace-url": dbWorkspace, "warehouse-id": dbWarehouse, "auth": "token", "token": dbPAT})
	if _, err := databricksAcquire(context.Background(), plain, DatabricksRequest{Connection: pc.ID, Revision: pc.Revision, Read: "catalog", List: "schemas"}, f.provider()); err != ErrRequest {
		t.Fatal(err)
	}
}

// The workspace URL is held to its form, case by case.
func TestDatabricksWorkspaceURLForm(t *testing.T) {
	for raw, want := range map[string]string{
		"https://example.cloud.databricks.com":                 "https://example.cloud.databricks.com",
		"https://example.cloud.databricks.com/":                "https://example.cloud.databricks.com",
		"https://adb-0000000000000000.0.azuredatabricks.net":   "https://adb-0000000000000000.0.azuredatabricks.net",
		"https://0000000000000000.0.gcp.databricks.com/":       "https://0000000000000000.0.gcp.databricks.com",
		"https://example.cloud.databricks.us":                  "https://example.cloud.databricks.us",
		"https://example.cloud.databricks.mil":                 "https://example.cloud.databricks.mil",
		"https://example.cloud.databricks.com/sql":             "",
		"https://example.cloud.databricks.com//":               "",
		"https://example.cloud.databricks.com/?o=1":            "",
		"https://example.cloud.databricks.com?o=1":             "",
		"https://example.cloud.databricks.com#top":             "",
		"https://user@example.cloud.databricks.com":            "",
		"https://user:password@example.cloud.databricks.com":   "",
		"http://example.cloud.databricks.com":                  "",
		"example.cloud.databricks.com":                         "",
		"https://example.cloud.databricks.com:443":             "",
		"https://example.cloud.databricks.com:8443":            "",
		"https://example.cloud.databricks.com.example.org":     "",
		"https://examplecloud.databricks.com":                  "",
		"https://example.databricks.com":                       "",
		"https://cloud.databricks.com":                         "",
		"https://example.cloud.databricks.com.":                "",
		"https://example.cloud.databricks.com./":               "",
		"https://192.0.2.1":                                    "",
		"https://[2001:db8::1]":                                "",
		"https://EXAMPLE.cloud.databricks.com":                 "",
		"https://accounts.cloud.databricks.com":                "",
		"https://accounts-dod.cloud.databricks.mil":            "",
		"https://xn--xample-9ua.cloud.databricks.com":          "",
		"https://-example.cloud.databricks.com":                "",
		"https://a.b.c.d.cloud.databricks.com":                 "",
		"https://example%2ecloud.databricks.com":               "",
		"https://example.cloud.databricks.com\\@example.org":   "",
		"https://example.cloud.databricks.com/%2e%2e":          "",
		"https://example.cloud.databricks.com/api/2.0/sql/":    "",
		"https://example.cloud.databricks.com\t":               "",
		"https://":                                             "",
		"":                                                     "",
		"https://example.cloud.databricks.com" + "/" + "x?y#z": "",
	} {
		got, ok := DatabricksWorkspace(raw)
		if ok != (want != "") || got != want {
			t.Errorf("%q: %q %v", raw, got, ok)
		}
		if want != "" {
			continue
		}
		// Configure refuses each, and keeps nothing of it.
		_, b, _, dir := dbFixture(t, dbTokenFields())
		fields := dbTokenFields()
		fields["id"], fields["workspace-url"] = "other", raw
		if err := dbConfigure(b, fields); err != ErrRequest || bytes.Contains(dbState(t, dir), []byte(`"other"`)) {
			t.Errorf("configure took %q: %v", raw, err)
		}
	}
}

// What configure takes, and what it refuses.
func TestDatabricksConfigureHoldsEachFieldToItsForm(t *testing.T) {
	_, b, _, _ := dbFixture(t, dbTokenFields())
	for name, change := range map[string]map[string]string{
		"a wait of 4":                {"wait-seconds": "4"},
		"a wait of 51":               {"wait-seconds": "51"},
		"a wait of 0":                {"wait-seconds": "0"},
		"a wait written 030":         {"wait-seconds": "030"},
		"a wait in words":            {"wait-seconds": "thirty"},
		"a bound under 64 KiB":       {"max-result-bytes": "65535"},
		"a bound over 15 MiB":        {"max-result-bytes": "15728641"},
		"a bound at the inline 25":   {"max-result-bytes": "26214400"},
		"no warehouse":               {"warehouse-id": ""},
		"a warehouse with a slash":   {"warehouse-id": "abc/def"},
		"another auth":               {"auth": "oauth"},
		"no token":                   {"token": ""},
		"a token with a space":       {"token": "dapi marker"},
		"a token and a client":       {"client-id": dbClient},
		"a scope with a token":       {"scope": "sql"},
		"a schema without a catalog": {"catalog": "", "schema": "sales"},
		"a catalog with a period":    {"catalog": "main.sales"},
		"an uppercase id":            {"id": "Lake"},
		"no name":                    {"name": ""},
	} {
		fields := dbTokenFields()
		fields["id"] = "second"
		for k, v := range change {
			fields[k] = v
		}
		if err := dbConfigure(b, fields); err != ErrRequest {
			t.Errorf("%s: %v", name, err)
		}
	}
	for name, change := range map[string]map[string]string{
		"a client id not a UUID": {"client-id": "lake-client"},
		"no client secret":       {"client-secret": ""},
		"a token too":            {"token": dbPAT},
		"a scope in capitals":    {"scope": "ALL-APIS"},
		"a scope twice":          {"scope": "sql sql"},
		"a scope with two gaps":  {"scope": "sql  unity-catalog"},
	} {
		fields := dbPrincipalFields()
		fields["id"] = "second"
		for k, v := range change {
			fields[k] = v
		}
		if err := dbConfigure(b, fields); err != ErrRequest {
			t.Errorf("%s: %v", name, err)
		}
	}
	accepted := dbPrincipalFields()
	accepted["id"], accepted["scope"], accepted["wait-seconds"], accepted["max-result-bytes"] = "third", "sql unity-catalog", "50", "15728640"
	if err := dbConfigure(b, accepted); err != nil {
		t.Fatal(err)
	}
	accepted["id"], accepted["wait-seconds"], accepted["max-result-bytes"] = "fourth", "5", "65536"
	if err := dbConfigure(b, accepted); err != nil {
		t.Fatal(err)
	}
}

// Status, configure, test and disconnect, under the store's custody rules.
func TestDatabricksControlsKeepCustody(t *testing.T) {
	s, b, c, dir := dbFixture(t, dbTokenFields())
	f := newDBFake(t)
	b.provider = f.provider()
	// The files are private.
	filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			t.Fatal(err)
		}
		info, _ := d.Info()
		if info.Mode().Perm()&0077 != 0 {
			t.Errorf("%s is %v", path, info.Mode().Perm())
		}
		return nil
	})
	out, err := b.Handle(context.Background(), "status", []byte(`{}`))
	raw, _ := json.Marshal(out)
	if err != nil || bytes.Contains(raw, []byte(dbPAT)) || bytes.Contains(raw, []byte(`"token":`)) || !bytes.Contains(raw, []byte(`"ready":true`)) || !bytes.Contains(raw, []byte(`"maxWaitSeconds":50`)) {
		t.Fatalf("status %s %v", raw, err)
	}
	// A configure with a stale revision is refused; a blank token keeps the
	// saved one only where it would go to the same workspace.
	stale := dbTokenFields()
	if err = dbConfigure(b, stale); err != ErrChanged {
		t.Fatal("a stale configure was taken", err)
	}
	update := dbTokenFields()
	update["revision"], update["token"], update["name"] = c.Revision, "", "Renamed"
	if err = dbConfigure(b, update); err != nil {
		t.Fatal(err)
	}
	c = dbConnection(t, s, "lake")
	if c.Token != dbPAT || c.Name != "Renamed" {
		t.Fatal("a blank token did not keep the saved one")
	}
	moved := dbTokenFields()
	moved["revision"], moved["token"], moved["workspace-url"] = c.Revision, "", "https://example.gcp.databricks.com"
	if err = dbConfigure(b, moved); err != ErrRequest {
		t.Fatal("a saved token went with the connection to another workspace", err)
	}
	// Six connections at most.
	for i := range 5 {
		more := dbTokenFields()
		more["id"] = "more-" + string(rune('a'+i))
		if err = dbConfigure(b, more); err != nil {
			t.Fatal(err)
		}
	}
	more := dbTokenFields()
	more["id"] = "seventh"
	if err = dbConfigure(b, more); err != ErrRequest {
		t.Fatal("a seventh connection", err)
	}
	// A test is one request, the first catalog, and returns nothing of it.
	f.set(func(w http.ResponseWriter, r *http.Request, _ []byte) {
		io.WriteString(w, `{"catalogs":[{"name":"main","comment":"private"}]}`)
	})
	answer, err := b.Handle(context.Background(), "test", []byte(`{"id":"lake","revision":"`+c.Revision+`"}`))
	raw, _ = json.Marshal(answer)
	path, _ := f.last()
	if err != nil || string(raw) != `{"ok":true}` || f.api.Load() != 1 || path != "GET /api/2.1/unity-catalog/catalogs?max_results=1" {
		t.Fatalf("test %s %v %d %s", raw, err, f.api.Load(), path)
	}
	// The lock: a configure waits while another holds it, and then runs.
	lockFile, err := s.root.OpenFile("state.lock", os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err = syscall.Flock(int(lockFile.Fd()), syscall.LOCK_EX); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		renamed := dbTokenFields()
		renamed["revision"], renamed["token"], renamed["name"] = c.Revision, "", "Locked"
		done <- dbConfigure(b, renamed)
	}()
	select {
	case err = <-done:
		t.Fatal("configure ran while another held the lock", err)
	case <-time.After(200 * time.Millisecond):
	}
	syscall.Flock(int(lockFile.Fd()), syscall.LOCK_UN)
	lockFile.Close()
	if err = <-done; err != nil {
		t.Fatal(err)
	}
	c = dbConnection(t, s, "lake")
	// Disconnect forgets the secret, and revokes nothing.
	answer, err = b.Handle(context.Background(), "disconnect", []byte(`{"id":"lake","revision":"`+c.Revision+`"}`))
	raw, _ = json.Marshal(answer)
	if err != nil || string(raw) != `{"disconnected":true,"revoked":false}` {
		t.Fatal(string(raw), err)
	}
	for i := range 5 {
		id := "more-" + string(rune('a'+i))
		m := dbConnection(t, s, id)
		if _, err = b.Handle(context.Background(), "disconnect", []byte(`{"id":"`+id+`","revision":"`+m.Revision+`"}`)); err != nil {
			t.Fatal(err)
		}
	}
	if bytes.Contains(dbState(t, dir), []byte(dbPAT)) {
		t.Fatal("disconnect kept the token")
	}
	if _, err = databricksAcquire(context.Background(), s, dbStatementRead(c, "SELECT 1"), f.provider()); err != ErrConnect {
		t.Fatal("a disconnected connection read", err)
	}
	// A state file another may read is refused.
	matches, _ := filepath.Glob(filepath.Join(dir, "databricks", "*", "state.json"))
	if len(matches) != 1 || os.Chmod(matches[0], 0644) != nil {
		t.Fatal("state file", matches)
	}
	if _, err = b.Handle(context.Background(), "status", []byte(`{}`)); err != ErrStorage {
		t.Fatal("a readable state file was used", err)
	}
}

// The broker's conventions: an unsupported method is refused, and an
// operator's block is kept and answered.
func TestDatabricksBrokerConventions(t *testing.T) {
	s, b, c, _ := dbFixture(t, dbTokenFields())
	for _, method := range []string{"search", "select", "connect", "poll", "statement", "catalog", "files-list"} {
		if _, err := b.Handle(context.Background(), method, []byte(`{}`)); err != ErrRequest {
			t.Errorf("%s: %v", method, err)
		}
	}
	blocked := NewDatabricks(s, true)
	defer blocked.Close()
	out, err := blocked.Handle(context.Background(), "status", []byte(`{}`))
	if err != nil || out.(Status).State != "blocked" || out.(Status).Provider != "databricks" {
		t.Fatal(out, err)
	}
	if _, err = blocked.Handle(context.Background(), "configure", []byte(`{}`)); err != ErrPolicy {
		t.Fatal(err)
	}
	f := newDBFake(t)
	if _, err = databricksAcquire(context.Background(), s, dbStatementRead(c, "SELECT 1"), f.provider()); err != ErrPolicy || f.api.Load() != 0 {
		t.Fatal("a blocked connection read", err)
	}
}

// A service principal's token is minted once, used while it is more than a
// minute from its expiry, minted again within that minute, and never held
// past its expiry; a minting failure names the status and the code.
func TestDatabricksTokenMinting(t *testing.T) {
	s, _, c, dir := dbFixture(t, dbPrincipalFields())
	f := newDBFake(t)
	f.setToken(func(w http.ResponseWriter, r *http.Request, form url.Values) {
		id, secret, ok := r.BasicAuth()
		if r.Method != "POST" || !ok || id != dbClient || secret != dbSecret || form.Get("grant_type") != "client_credentials" || form.Get("scope") != "all-apis" || len(form) != 2 {
			t.Errorf("token request %s %v %v", r.Method, form, ok)
		}
		io.WriteString(w, `{"access_token":"`+dbMinted+`","token_type":"Bearer","expires_in":3600}`)
	})
	f.set(func(w http.ResponseWriter, r *http.Request, _ []byte) {
		if r.Header.Get("Authorization") != "Bearer "+dbMinted {
			t.Error("the minted token is not the bearer")
		}
		io.WriteString(w, dbSucceeded(`["1"]`))
	})
	held := func() (databricksToken, bool) {
		var out databricksToken
		found := false
		s.locked(func(v *state) error {
			for _, tk := range v.Databricks.Tokens {
				out, found = tk, true
			}
			return nil
		})
		return out, found
	}
	read := func() error {
		_, err := databricksAcquire(context.Background(), s, dbStatementRead(c, "SELECT 1"), f.provider())
		return err
	}
	if err := read(); err != nil || f.mints.Load() != 1 {
		t.Fatal(err, f.mints.Load())
	}
	token, ok := held()
	if !ok || token.Access != dbMinted || token.Revision != c.Revision || time.Until(time.Unix(token.Expires, 0)) < 59*time.Minute {
		t.Fatalf("held %+v", token)
	}
	if err := read(); err != nil || f.mints.Load() != 1 {
		t.Fatal("a token in its lifetime was minted again", err, f.mints.Load())
	}
	expire := func(at time.Time) {
		s.locked(func(v *state) error {
			v.Databricks.Tokens[0].Expires = at.Unix()
			return s.write("state.json", v)
		})
	}
	expire(time.Now().Add(30 * time.Second))
	if err := read(); err != nil || f.mints.Load() != 2 {
		t.Fatal("a token within a minute of expiry was used", err, f.mints.Load())
	}
	expire(time.Now().Add(2 * time.Minute))
	if err := read(); err != nil || f.mints.Load() != 2 {
		t.Fatal("a token two minutes from expiry was not used", err, f.mints.Load())
	}
	// A failure: the status and the code, never the secret, and the expired
	// token is not kept.
	f.setToken(func(w http.ResponseWriter, r *http.Request, form url.Values) {
		w.WriteHeader(401)
		io.WriteString(w, `{"error":"invalid_client","error_description":"Client authentication failed for `+dbSecret+`"}`)
	})
	expire(time.Now().Add(-time.Second))
	api := f.api.Load()
	err := read()
	if err == nil || err.Error() != "token-failed: the workspace's token endpoint answered 401 (invalid_client)" || f.api.Load() != api {
		t.Fatal(err)
	}
	if _, ok = held(); ok || bytes.Contains(dbState(t, dir), []byte(dbMinted)) {
		t.Fatal("an expired token stayed in custody")
	}
	for name, k := range map[string]struct {
		status int
		body   string
		want   string
	}{
		"a redirect":       {302, ``, "token-failed: the workspace's token endpoint answered 302, a redirect, which is not followed"},
		"an outage":        {503, `{"error_code":"TEMPORARILY_UNAVAILABLE"}`, "token-failed: the workspace's token endpoint answered 503 (TEMPORARILY_UNAVAILABLE)"},
		"no code":          {400, `bad request`, "token-failed: the workspace's token endpoint answered 400"},
		"a code as secret": {400, `{"error":"` + dbSecret + `"}`, "token-failed: the workspace's token endpoint answered 400 ([redacted])"},
		"not a token":      {200, `{"access_token":"","token_type":"Bearer","expires_in":3600}`, "token-failed: the workspace's token endpoint answered 200 with a token not of the form asked for"},
		"another type":     {200, `{"access_token":"` + dbMinted + `","token_type":"mac","expires_in":3600}`, "token-failed: the workspace's token endpoint answered 200 with a token not of the form asked for"},
		"the secret back":  {200, `{"access_token":"` + dbSecret + `","token_type":"Bearer","expires_in":3600}`, "token-failed: the workspace's token endpoint answered 200 with a token not of the form asked for"},
		"no lifetime":      {200, `{"access_token":"` + dbMinted + `","token_type":"Bearer"}`, "token-failed: the workspace's token endpoint answered 200 with a token not of the form asked for"},
		"not JSON":         {200, `token`, "token-failed: the workspace's token endpoint answered 200 with a body that is not a token"},
	} {
		f.setToken(func(w http.ResponseWriter, r *http.Request, form url.Values) {
			if k.status == 302 {
				w.Header().Set("Location", "/oidc/v1/elsewhere")
			}
			w.WriteHeader(k.status)
			io.WriteString(w, k.body)
		})
		mints := f.mints.Load()
		if err := read(); err == nil || err.Error() != k.want || f.mints.Load() != mints+1 {
			t.Errorf("%s: %v (%d token requests)", name, err, f.mints.Load()-mints)
		}
	}
	// A narrower scope is asked for as configured.
	scoped := dbPrincipalFields()
	scoped["scope"] = "sql unity-catalog"
	s2, b2, c2, dir2 := dbFixture(t, scoped)
	f.setToken(func(w http.ResponseWriter, r *http.Request, form url.Values) {
		if form.Get("scope") != "sql unity-catalog" {
			t.Error("scope", form.Get("scope"))
		}
		io.WriteString(w, `{"access_token":"`+dbMinted+`","token_type":"Bearer","expires_in":3600}`)
	})
	if _, err := databricksAcquire(context.Background(), s2, dbStatementRead(c2, "SELECT 1"), f.provider()); err != nil {
		t.Fatal(err)
	}
	// Disconnect forgets the secret and the token minted for it.
	if !bytes.Contains(dbState(t, dir2), []byte(dbMinted)) {
		t.Fatal("no token was held")
	}
	if _, err := b2.Handle(context.Background(), "disconnect", []byte(`{"id":"lake","revision":"`+c2.Revision+`"}`)); err != nil {
		t.Fatal(err)
	}
	if held := dbState(t, dir2); bytes.Contains(held, []byte(dbMinted)) || bytes.Contains(held, []byte(dbSecret)) {
		t.Fatal("disconnect kept the secret or the token")
	}
	// A reconfigured connection drops the token minted under its earlier
	// revision.
	s.locked(func(v *state) error {
		v.Databricks.Tokens = []databricksToken{{c.ID, c.Revision, dbMinted, time.Now().Add(time.Hour).Unix()}}
		return s.write("state.json", v)
	})
	again := dbPrincipalFields()
	again["revision"], again["client-secret"] = c.Revision, ""
	if err := dbConfigure(NewDatabricks(s, false), again); err != nil {
		t.Fatal(err)
	}
	if _, ok = held(); ok {
		t.Fatal("a token outlived the revision it was minted under")
	}
}

// The personal access token, the client secret and the minted token are
// in no record, error, status, test answer or log line, on any path,
// whatever the workspace sends back.
func TestDatabricksCredentialsAreNeverEchoed(t *testing.T) {
	var logged bytes.Buffer
	log.SetOutput(&logged)
	defer log.SetOutput(os.Stderr)
	markers := []string{dbPAT, dbSecret, dbMinted}
	var seen [][]byte
	keep := func(v any) {
		raw, _ := json.Marshal(v)
		seen = append(seen, raw)
	}
	// reflect answers with everything it was sent: the headers, the form
	// and the body.
	reflect := func(r *http.Request, body []byte) string {
		auth := r.Header.Get("Authorization")
		user, secret, _ := r.BasicAuth()
		return strings.Join([]string{auth, user, secret, string(body), strings.TrimPrefix(auth, "Bearer ")}, " | ")
	}
	for _, fields := range []map[string]string{dbTokenFields(), dbPrincipalFields()} {
		s, b, c, dir := dbFixture(t, fields)
		f := newDBFake(t)
		b.provider = f.provider()
		for _, status := range []int{401, 403, 404, 429, 500, 503} {
			f.set(func(w http.ResponseWriter, r *http.Request, body []byte) {
				bearer := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
				w.Header().Set("Retry-After", bearer)
				w.WriteHeader(status)
				answer, _ := json.Marshal(map[string]any{"error_code": bearer, "message": reflect(r, body), "details": []any{map[string]string{"@type": "RetryInfo", "retry_delay": bearer + "s"}}})
				w.Write(answer)
			})
			_, err := databricksAcquire(context.Background(), s, dbStatementRead(c, "SELECT 1"), f.provider())
			keep(err.Error())
			answer, err := b.Handle(context.Background(), "test", []byte(`{"id":"lake","revision":"`+c.Revision+`"}`))
			keep(answer)
			keep(err.Error())
		}
		// A statement's own message repeating the credential.
		f.set(func(w http.ResponseWriter, r *http.Request, body []byte) {
			message, _ := json.Marshal("near " + reflect(r, body))
			io.WriteString(w, `{"statement_id":"`+dbStatement+`","status":{"state":"FAILED","error":{"error_code":"BAD_REQUEST","message":`+string(message)+`}}}`)
		})
		_, err := databricksAcquire(context.Background(), s, dbStatementRead(c, "SELECT 1"), f.provider())
		if err == nil || !strings.HasPrefix(err.Error(), "statement-failed: near Bearer [redacted] |") {
			t.Fatal(err)
		}
		keep(err.Error())
		// A result repeating it is not kept.
		f.set(func(w http.ResponseWriter, r *http.Request, body []byte) {
			value, _ := json.Marshal(reflect(r, body))
			io.WriteString(w, dbSucceeded(`[`+string(value)+`]`))
		})
		out, err := databricksAcquire(context.Background(), s, dbStatementRead(c, "SELECT 1"), f.provider())
		if out != nil || err == nil || err.Error() != "provider-unavailable: the workspace's answer repeats the credential, and is not kept" {
			t.Fatal(err)
		}
		keep(err.Error())
		// And an ordinary read, its record and its statement.
		f.set(func(w http.ResponseWriter, r *http.Request, body []byte) { io.WriteString(w, dbSucceeded(`["1"]`)) })
		out, err = databricksAcquire(context.Background(), s, dbStatementRead(c, "SELECT 1"), f.provider())
		if err != nil {
			t.Fatal(err)
		}
		seen = append(seen, out)
		status, err := b.Handle(context.Background(), "status", []byte(`{}`))
		keep(status)
		answer, err := b.Handle(context.Background(), "test", []byte(`{"id":"lake","revision":"`+c.Revision+`"}`))
		if err != nil {
			t.Fatal(err)
		}
		keep(answer)
		// A token endpoint reflecting the secret.
		if fields["auth"] == "service-principal" {
			s.locked(func(v *state) error { v.Databricks.Tokens = nil; return s.write("state.json", v) })
			f.setToken(func(w http.ResponseWriter, r *http.Request, form url.Values) {
				w.WriteHeader(401)
				code, _ := json.Marshal(reflect(r, nil))
				io.WriteString(w, `{"error":`+string(code)+`,"error_code":"`+dbSecret+`"}`)
			})
			_, err = databricksAcquire(context.Background(), s, dbStatementRead(c, "SELECT 1"), f.provider())
			keep(err.Error())
			_, err = b.Handle(context.Background(), "test", []byte(`{"id":"lake","revision":"`+c.Revision+`"}`))
			keep(err.Error())
		}
		// The receipt-bound record names no secret; custody holds the one
		// configured, and nothing after disconnect.
		_, err = b.Handle(context.Background(), "disconnect", []byte(`{"id":"lake","revision":"`+c.Revision+`"}`))
		if err != nil {
			t.Fatal(err)
		}
		seen = append(seen, dbState(t, dir))
	}
	seen = append(seen, logged.Bytes())
	for i, raw := range seen {
		for _, marker := range markers {
			if bytes.Contains(raw, []byte(marker)) {
				t.Errorf("output %d holds a credential: %s", i, raw)
			}
		}
	}
	if len(seen) < 30 {
		t.Fatal("too few outputs looked at", len(seen))
	}
}

// The descriptor and the plan name the provider as the other providers are
// named, and the version 2 catalog does not.
func TestDatabricksCatalogAndPlan(t *testing.T) {
	for _, p := range ConnectionCatalog().Providers {
		if p.ID == "databricks" {
			t.Fatal("databricks in the version 2 catalog")
		}
	}
	var d ProviderDescriptor
	for _, p := range ConnectionCatalogV3().Providers {
		if p.ID == "databricks" {
			d = p
		}
	}
	if d.Protocol != "databricks-v1" || d.Auth != "client-credentials" || d.Registration != "form" || d.Selection != "none" || d.Source != (SourceContract{"databricks", "http", "databricks-api-v1"}) || len(d.Setup) != 11 || len(d.Setup) > 12 {
		t.Fatalf("%+v", d)
	}
	if strings.Join(d.Operations, ",") != "status,configure,disconnect,test" {
		t.Fatal(d.Operations)
	}
	every, _ := json.Marshal(DatabricksConnection{"a", "b", "c", "d", "e", "f", "g", "h", "i", "j", "k", "l", "m", "n"})
	for _, field := range d.Setup {
		if (field.Type == "password") != (field.Key == "token" || field.Key == "client-secret") {
			t.Error("field type", field.Key, field.Type)
		}
		for _, locale := range []string{"en", "fr", "es", "de", "it", "pt-PT", "pt-BR", "ko", "ja", "zh-Hans", "zh-Hant", "yue-Hant"} {
			if field.Label[locale] == "" {
				t.Error("untranslated field", field.Key, locale)
			}
		}
		// Each field is a member configure reads by the field's key.
		if !strings.Contains(string(every), `"`+field.Key+`":"`) {
			t.Error("field not configured", field.Key)
		}
	}
	if d.Presentation.Name != "Databricks" {
		t.Fatal(d.Presentation)
	}
	if desc, ok := LookupProvider("databricks"); !ok || desc.supports("statement") || !desc.supports("test") {
		t.Fatal(desc)
	}
	found := false
	for _, source := range ConnectionLocalPlan().Sources {
		if source.ID == "databricks" {
			found = source.Executable == "adapter-sources" && strings.Join(source.Args, " ") == "--provider databricks --principal desk-local" && source.Shape == "http" && source.Timeout == 60 && source.Connections
		}
	}
	if !found {
		t.Fatal("the plan does not launch the source")
	}
	if DatabricksMaxWaitSeconds+databricksMarginSeconds >= 55 || DatabricksMaxResultBytes+1<<20 > MaxOutputBytes || DatabricksMaxResultBytes >= 25<<20 {
		t.Fatal("the bounds do not fit the envelope")
	}
}

// The live check reads one statement and one listing from a workspace the
// environment names. Without it, it is not run, and says so.
func TestDatabricksLiveCheck(t *testing.T) {
	workspace := os.Getenv("JPACK_DATABRICKS_LIVE_WORKSPACE")
	if workspace == "" {
		t.Skip("not run: JPACK_DATABRICKS_LIVE_WORKSPACE, JPACK_DATABRICKS_LIVE_WAREHOUSE and JPACK_DATABRICKS_LIVE_TOKEN (or _CLIENT_ID and _CLIENT_SECRET) name no workspace")
	}
	fields := map[string]string{"id": "live", "name": "Live", "workspace-url": workspace, "warehouse-id": os.Getenv("JPACK_DATABRICKS_LIVE_WAREHOUSE"), "auth": "token", "token": os.Getenv("JPACK_DATABRICKS_LIVE_TOKEN")}
	if id := os.Getenv("JPACK_DATABRICKS_LIVE_CLIENT_ID"); id != "" {
		fields["auth"], fields["token"], fields["client-id"], fields["client-secret"] = "service-principal", "", id, os.Getenv("JPACK_DATABRICKS_LIVE_CLIENT_SECRET")
	}
	s, _, c, _ := dbFixture(t, fields)
	for _, q := range []DatabricksRequest{dbStatementRead(c, "SELECT 1 AS one"), {Connection: c.ID, Revision: c.Revision, Read: "catalog", List: "catalogs", MaxResults: 1}} {
		raw, err := databricksAcquire(context.Background(), s, q, databricksProvider())
		if err != nil {
			t.Fatal(q.Read, err)
		}
		if _, err = agreement.Parse(raw); err != nil {
			t.Fatal(err)
		}
	}
}
