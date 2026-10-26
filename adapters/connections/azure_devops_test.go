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
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

// Every test here answers from an in-process TLS server. The organization's
// URL is of one of its two forms, and the test's transport dials the server
// whatever the host name; nothing reaches a real organization.
const (
	adoOrganization = "https://dev.azure.com/example"
	adoLegacy       = "https://example.visualstudio.com"
	adoProject      = "example-project"
	// Markers: each is asserted absent wherever the connection writes. They
	// are of an error type's form, so that an organization echoing one as
	// its typeKey would have it named but for the screens.
	adoPAT    = "adopatMarkerPersonalToken5e1c0a"
	adoBearer = "eyJmarkerEntraAccessToken77d4b2c9"
)

// adoBasic is the PAT's basic authentication value, as the request carries it.
var adoBasic = base64.StdEncoding.EncodeToString([]byte(":" + adoPAT))

// Recorded answers, of the forms the API reference pages show, with example
// names.
const (
	adoWIQL      = `{"queryType":"flat","queryResultType":"workItem","asOf":"2026-10-13T09:00:00.000Z","columns":[{"referenceName":"System.Id","name":"ID","url":"https://dev.azure.com/example/_apis/wit/fields/System.Id"}],"workItems":[{"id":12,"url":"https://dev.azure.com/example/_apis/wit/workItems/12"},{"id":7,"url":"https://dev.azure.com/example/_apis/wit/workItems/7"}]}`
	adoItems     = `{"count":2,"value":[{"id":12,"rev":3,"fields":{"System.Title":"Example item","System.State":"Active"},"url":"https://dev.azure.com/example/_apis/wit/workItems/12"},{"id":7,"rev":1,"fields":{"System.Title":"Another example","System.State":"New"},"url":"https://dev.azure.com/example/_apis/wit/workItems/7"}]}`
	adoItem      = `{"id":12,"rev":3,"fields":{"System.Title":"Example item","System.State":"Active","Microsoft.VSTS.Scheduling.Effort":2.5},"url":"https://dev.azure.com/example/_apis/wit/workItems/12"}`
	adoRepos     = `{"count":1,"value":[{"id":"5febef5a-833d-4e14-b9c0-14cb638f91e6","name":"example-repo","defaultBranch":"refs/heads/main","size":123456}]}`
	adoGitItems  = `{"count":1,"value":[{"objectId":"d1d5c2d49045d52bba6419652d6ecb2cd560dc29","gitObjectType":"tree","commitId":"23d0bc5b128a10056dc68afece360d8a0fabb014","path":"/docs","isFolder":true}]}`
	adoCommits   = `{"count":1,"value":[{"commitId":"be67f8871a4d2c75f13a51c1d3c30ac0d74d4ef4","comment":"Example change","author":{"name":"Example Author","email":"author@example.com","date":"2026-10-12T10:00:00Z"}}]}`
	adoPulls     = `{"count":1,"value":[{"pullRequestId":22,"status":"completed","title":"Example change","sourceRefName":"refs/heads/topic","targetRefName":"refs/heads/main"}]}`
	adoPipelines = `{"count":1,"value":[{"id":4,"revision":2,"name":"example-pipeline","folder":"\\"}]}`
	adoRuns      = `{"count":1,"value":[{"id":31,"name":"20261013.1","state":"completed","result":"succeeded"}]}`
	adoRun       = `{"id":31,"name":"20261013.1","state":"completed","result":"succeeded","pipeline":{"id":4,"name":"example-pipeline"}}`
)

// adoNormal is the recorded answer for the path a request names.
func adoNormal(r *http.Request) string {
	p := r.URL.Path
	switch {
	case strings.HasSuffix(p, "/_apis/wit/wiql"):
		return adoWIQL
	case strings.HasSuffix(p, "/_apis/wit/workitems"):
		return adoItems
	case strings.Contains(p, "/_apis/wit/workitems/"):
		return adoItem
	case strings.HasSuffix(p, "/_apis/git/repositories"):
		return adoRepos
	case strings.HasSuffix(p, "/items"):
		return adoGitItems
	case strings.HasSuffix(p, "/commits"):
		return adoCommits
	case strings.HasSuffix(p, "/pullrequests"):
		return adoPulls
	case strings.HasSuffix(p, "/_apis/pipelines"):
		return adoPipelines
	case strings.HasSuffix(p, "/runs"):
		return adoRuns
	case strings.Contains(p, "/runs/"):
		return adoRun
	}
	return `{"unexpected":true}`
}

// adoSeen is a request as the organization received it.
type adoSeen struct {
	line, host, auth string
	body             []byte
}

// adoFake is an organization's API, answering as the test sets it and
// recording what it was asked.
type adoFake struct {
	server   *httptest.Server
	calls    atomic.Int32
	mu       sync.Mutex
	answer   func(w http.ResponseWriter, r *http.Request, body []byte)
	requests []adoSeen
}

func newADOFake(t *testing.T) *adoFake {
	t.Helper()
	f := &adoFake{}
	f.answer = func(w http.ResponseWriter, r *http.Request, body []byte) { io.WriteString(w, adoNormal(r)) }
	f.server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		f.calls.Add(1)
		f.mu.Lock()
		f.requests = append(f.requests, adoSeen{r.Method + " " + r.URL.RequestURI(), r.Host, r.Header.Get("Authorization"), body})
		answer := f.answer
		f.mu.Unlock()
		answer(w, r, body)
	}))
	t.Cleanup(f.server.Close)
	return f
}
func (f *adoFake) set(answer func(w http.ResponseWriter, r *http.Request, body []byte)) {
	f.mu.Lock()
	f.answer = answer
	f.mu.Unlock()
}

// since is what the organization was asked from the nth request on.
func (f *adoFake) since(n int) []adoSeen {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]adoSeen{}, f.requests[n:]...)
}
func (f *adoFake) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.requests)
}

// provider is the connection's own provider, its redirect rule and timeouts
// included, with a transport that trusts the server and dials it.
func (f *adoFake) provider() provider {
	p := azureDevOpsProvider()
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
func (f *adoFake) peer() string {
	sum := sha256.Sum256(f.server.Certificate().Raw)
	return "tls:sha256:" + hex.EncodeToString(sum[:])
}

func adoConfigure(b *Broker, fields map[string]string) error {
	raw, _ := json.Marshal(fields)
	_, err := b.Handle(context.Background(), "configure", raw)
	return err
}
func adoTokenFields() map[string]string {
	return map[string]string{"id": "board", "name": "Board", "organization-url": adoOrganization, "project": adoProject, "auth": "token", "token": adoPAT}
}
func adoBearerFields() map[string]string {
	return map[string]string{"id": "board", "name": "Board", "organization-url": adoOrganization, "project": adoProject, "auth": "bearer", "access-token": adoBearer, "expires-at": time.Now().Add(time.Hour).UTC().Format(time.RFC3339)}
}

// adoFixture is a store holding one connection made of fields.
func adoFixture(t *testing.T, fields map[string]string) (*Store, *Broker, AzureDevOpsConnection, string) {
	t.Helper()
	dir := t.TempDir()
	os.Chmod(dir, 0700)
	s, err := OpenAzureDevOpsStore(dir, "test")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	b := NewAzureDevOps(s, false)
	t.Cleanup(b.Close)
	if err = adoConfigure(b, fields); err != nil {
		t.Fatal(err)
	}
	return s, b, adoConnection(t, s, fields["id"]), dir
}
func adoConnection(t *testing.T, s *Store, id string) AzureDevOpsConnection {
	t.Helper()
	var c AzureDevOpsConnection
	s.locked(func(v *state) error {
		for _, x := range v.AzureDevOps.Connections {
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

// adoState is the custody file as it is on disk.
func adoState(t *testing.T, dir string) []byte {
	t.Helper()
	matches, _ := filepath.Glob(filepath.Join(dir, "azure-devops", "*", "state.json"))
	if len(matches) != 1 {
		t.Fatal("no azure-devops state on disk", matches)
	}
	found, _ := os.ReadFile(matches[0])
	return found
}

// adoRead is one of the reads, the requests it makes, and the answer its
// snapshot digests, from the URL of the last of them, which the record
// names (query and all).
type adoRead struct {
	q        AzureDevOpsRequest
	lines    []string
	answer   string
	endpoint string
}

// adoReads is every read, as a request of c's would make it under the path
// prefix the organization URL gives.
func adoReads(c AzureDevOpsConnection, prefix string) []adoRead {
	base := prefix + "/" + adoProject + "/_apis/"
	q := func(read string) AzureDevOpsRequest {
		return AzureDevOpsRequest{Connection: c.ID, Revision: c.Revision, Read: read}
	}
	query := q("workitems.query")
	query.Query = "SELECT [System.Id] FROM WorkItems WHERE [System.State] = 'Active'"
	get := q("workitems.get")
	get.IDs, get.Fields = []int64{12, 7}, []string{"System.Title", "System.State"}
	one := q("workitems.get")
	one.ID = 12
	both := q("workitems.query-and-get")
	both.Query, both.Fields = query.Query, []string{"System.Title"}
	items := q("repos.items")
	items.Repository, items.Path = "example-repo", "/docs"
	commits := q("repos.commits")
	commits.Repository, commits.Top = "example-repo", 2
	pulls := q("pullrequests.list")
	pulls.Repository, pulls.Status = "example-repo", "completed"
	runs := q("pipelines.runs")
	runs.Pipeline = 4
	run := q("pipelines.run")
	run.Pipeline, run.Run = 4, 31
	org := c.Organization
	return []adoRead{
		{query, []string{"POST " + base + "wit/wiql?$top=200&api-version=7.1"}, adoWIQL, org + "/" + adoProject + "/_apis/wit/wiql"},
		{get, []string{"GET " + base + "wit/workitems?api-version=7.1&fields=System.Title,System.State&ids=12,7"}, adoItems, org + "/" + adoProject + "/_apis/wit/workitems"},
		{one, []string{"GET " + base + "wit/workitems/12?api-version=7.1"}, adoItem, org + "/" + adoProject + "/_apis/wit/workitems/12"},
		{both, []string{"POST " + base + "wit/wiql?$top=200&api-version=7.1", "GET " + base + "wit/workitems?api-version=7.1&fields=System.Title&ids=12,7"}, adoItems, org + "/" + adoProject + "/_apis/wit/workitems"},
		{q("repos.list"), []string{"GET " + base + "git/repositories?api-version=7.1"}, adoRepos, org + "/" + adoProject + "/_apis/git/repositories"},
		{items, []string{"GET " + base + "git/repositories/example-repo/items?$format=json&api-version=7.1&recursionLevel=oneLevel&scopePath=%2Fdocs"}, adoGitItems, org + "/" + adoProject + "/_apis/git/repositories/example-repo/items"},
		{commits, []string{"GET " + base + "git/repositories/example-repo/commits?api-version=7.1&searchCriteria.$skip=0&searchCriteria.$top=2"}, adoCommits, org + "/" + adoProject + "/_apis/git/repositories/example-repo/commits"},
		{pulls, []string{"GET " + base + "git/repositories/example-repo/pullrequests?$skip=0&$top=100&api-version=7.1&searchCriteria.status=completed"}, adoPulls, org + "/" + adoProject + "/_apis/git/repositories/example-repo/pullrequests"},
		{q("pipelines.list"), []string{"GET " + base + "pipelines?$top=100&api-version=7.1"}, adoPipelines, org + "/" + adoProject + "/_apis/pipelines"},
		{runs, []string{"GET " + base + "pipelines/4/runs?api-version=7.1"}, adoRuns, org + "/" + adoProject + "/_apis/pipelines/4/runs"},
		{run, []string{"GET " + base + "pipelines/4/runs/31?api-version=7.1"}, adoRun, org + "/" + adoProject + "/_apis/pipelines/4/runs/31"},
	}
}

func adoCanonical(t *testing.T, v any) []byte {
	t.Helper()
	raw, err := canon.EncodeJSON(v)
	if err != nil {
		t.Fatal(err)
	}
	out, err := canon.Canonicalize(raw, canon.CarryNumbersAsText)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// adoExpectedResult is the result a read keeps of its answers: the answer as
// received, the query's beside the items' for a query-and-get, and the page
// beside its continuation token for a pipelines listing.
func adoExpectedResult(t *testing.T, read string, answer string, token any) []byte {
	switch read {
	case "workitems.query-and-get":
		return adoCanonical(t, map[string]any{"query": json.RawMessage(adoWIQL), "items": json.RawMessage(answer)})
	case "pipelines.list":
		return adoCanonical(t, map[string]any{"pipelines": json.RawMessage(answer), "continuationToken": token})
	}
	return adoCanonical(t, json.RawMessage(answer))
}

// Each read is the request, or the two, the API reference documents, under
// the PAT as basic authentication with an empty user name, for both forms of
// the organization URL; the envelope is of the signer's form and its record
// names the endpoint, the request, the answer and the TLS peer.
func TestAzureDevOpsEachReadIsItsDocumentedRequest(t *testing.T) {
	for _, form := range []struct{ organization, host, prefix string }{{adoOrganization, "dev.azure.com", "/example"}, {adoLegacy, "example.visualstudio.com", ""}} {
		fields := adoTokenFields()
		fields["organization-url"] = form.organization + "/"
		s, _, c, _ := adoFixture(t, fields)
		if c.Organization != form.organization {
			t.Fatal("the organization URL was not kept in its form", c.Organization)
		}
		f := newADOFake(t)
		for _, k := range adoReads(c, form.prefix) {
			before := f.count()
			raw, err := azureDevOpsAcquire(context.Background(), s, k.q, f.provider())
			if err != nil {
				t.Fatal(k.q.Read, err)
			}
			if form.prefix != "" {
				writeEnvelope(t, "azure-devops."+k.q.Read, raw)
			}
			seen := f.since(before)
			if len(seen) != len(k.lines) {
				t.Fatalf("%s: %d requests", k.q.Read, len(seen))
			}
			for i, request := range seen {
				if request.line != k.lines[i] || request.host != form.host || request.auth != "Basic "+adoBasic {
					t.Errorf("%s: request %d is %q to %s under %q", k.q.Read, i, request.line, request.host, request.auth)
				}
			}
			e, err := agreement.Parse(raw)
			if err != nil {
				t.Fatal(k.q.Read, "the envelope is not of the signer's form:", err)
			}
			// The record names the URL the snapshot's answer came from, its
			// query included.
			_, last, _ := strings.Cut(k.lines[len(k.lines)-1], " ")
			if url := form.organization + strings.TrimPrefix(last, form.prefix); !strings.HasPrefix(url, k.endpoint+"?") {
				t.Fatalf("%s: the read's last request is not of its endpoint: %s", k.q.Read, url)
			} else {
				k.endpoint = url
			}
			a := e.Acquisition
			if a.Adapter.Name != "adapter-sources" || !canon.IsDigestString(a.Adapter.Digest) || a.Endpoint == nil || *a.Endpoint != k.endpoint || a.Snapshot == nil || *a.Snapshot != digest([]byte(k.answer)) ||
				a.PeerIdentity == nil || *a.PeerIdentity != f.peer() || a.Schema != nil || a.UpstreamToken != nil {
				t.Fatalf("%s: acquisition %+v", k.q.Read, a)
			}
			if observed, err := time.Parse("2006-01-02T15:04:05Z", a.ObservedAt); err != nil || time.Since(observed) > time.Minute {
				t.Fatal("observedAt", a.ObservedAt)
			}
			if !bytes.Equal(e.Result, adoExpectedResult(t, k.q.Read, k.answer, nil)) {
				t.Fatalf("%s: the result is not the answer as received:\n%s", k.q.Read, e.Result)
			}
			members, err := agreement.Statement(e)
			if err != nil {
				t.Fatal(err)
			}
			for name, want := range map[string]string{"connection": `"board"`, "revision": `"` + c.Revision + `"`, "provider": `"azure-devops"`, "project": `"` + adoProject + `"`, "read": `"` + k.q.Read + `"`} {
				if string(members[name]) != want {
					t.Errorf("%s: statement %s = %s", k.q.Read, name, members[name])
				}
			}
			// The statement is the first request as sent: its method, its
			// endpoint, its query and its body.
			method, target, _ := strings.Cut(k.lines[0], " ")
			path, rawQuery, _ := strings.Cut(target, "?")
			query := map[string]string{}
			for _, pair := range strings.Split(rawQuery, "&") {
				name, value, _ := strings.Cut(pair, "=")
				query[name] = value
			}
			var recorded map[string]string
			json.Unmarshal(members["query"], &recorded)
			for name, value := range query {
				if got := recorded[name]; got != value && strings.ReplaceAll(strings.ReplaceAll(got, "/", "%2F"), " ", "+") != value {
					t.Errorf("%s: statement query %s = %q, sent %q", k.q.Read, name, got, value)
				}
			}
			if len(recorded) != len(query) || string(members["method"]) != `"`+method+`"` || string(members["endpoint"]) != `"`+form.organization+strings.TrimPrefix(path, form.prefix)+`"` {
				t.Errorf("%s: statement %v", k.q.Read, members)
			}
			if method == "POST" {
				if body, _ := canon.Canonicalize(seen[0].body, canon.RefuseNumbers); !bytes.Equal(members["body"], body) {
					t.Errorf("%s: the statement's body is not the body sent: %s", k.q.Read, members["body"])
				}
			} else if members["body"] != nil {
				t.Errorf("%s: a GET has a body in its statement", k.q.Read)
			}
		}
	}
}

// An empty answer is a result like any other: a query that finds nothing
// makes no second request, and its record names the one answer read.
func TestAzureDevOpsEmptyAnswersAreResults(t *testing.T) {
	s, _, c, _ := adoFixture(t, adoTokenFields())
	f := newADOFake(t)
	emptyQuery := `{"queryType":"flat","queryResultType":"workItem","asOf":"2026-10-13T09:00:00.000Z","columns":[],"workItems":[]}`
	f.set(func(w http.ResponseWriter, r *http.Request, _ []byte) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/wiql"):
			io.WriteString(w, emptyQuery)
		case strings.Contains(r.URL.Path, "/runs/") || strings.Contains(r.URL.Path, "/workitems/"):
			io.WriteString(w, `{}`)
		default:
			io.WriteString(w, `{"count":0,"value":[]}`)
		}
	})
	for _, k := range adoReads(c, "/example") {
		before := f.count()
		raw, err := azureDevOpsAcquire(context.Background(), s, k.q, f.provider())
		if err != nil {
			t.Fatal(k.q.Read, err)
		}
		e, err := agreement.Parse(raw)
		if err != nil {
			t.Fatal(err)
		}
		if f.count()-before != 1 {
			t.Errorf("%s: %d requests", k.q.Read, f.count()-before)
		}
		if k.q.Read == "workitems.query-and-get" {
			want := adoCanonical(t, map[string]any{"query": json.RawMessage(emptyQuery), "items": nil})
			if !bytes.Equal(e.Result, want) || *e.Acquisition.Snapshot != digest([]byte(emptyQuery)) || *e.Acquisition.Endpoint != adoOrganization+"/"+adoProject+"/_apis/wit/wiql?$top=200&api-version=7.1" {
				t.Errorf("an empty query: %s %+v", e.Result, e.Acquisition)
			}
		}
	}
}

// Each answer other than 200 is refused naming its status and the error type
// the body gives, never its message, after one request: a 429 or a 503 with
// the wait its Retry-After asks for and is not retried; a redirect is not
// followed; a body that is not JSON is refused.
func TestAzureDevOpsRefusalsNameTheStatusAndAreNotRetried(t *testing.T) {
	s, _, c, _ := adoFixture(t, adoTokenFields())
	f := newADOFake(t)
	errorBody := func(typeKey, message string) string {
		return `{"$id":"1","innerException":null,"message":"` + message + `","typeName":"Microsoft.TeamFoundation.Framework.Server.` + typeKey + `, Microsoft.TeamFoundation.Framework.Server","typeKey":"` + typeKey + `","errorCode":0,"eventId":3000}`
	}
	for _, k := range []struct {
		name   string
		status int
		header map[string]string
		body   string
		want   string
	}{
		{"401", 401, nil, errorBody("UnauthorizedRequestException", "TF400813: The user is not authorized to access this resource."), "credentials-required: the organization answered 401 (UnauthorizedRequestException)"},
		{"403", 403, nil, errorBody("AccessCheckException", "TF401019: access denied."), "permission-denied: the organization answered 403 (AccessCheckException)"},
		{"404", 404, nil, errorBody("ProjectDoesNotExistWithNameException", "TF200016: The following project does not exist."), "request-refused: the organization answered 404 (ProjectDoesNotExistWithNameException)"},
		{"400", 400, nil, `{"message":"VS402337: The number of work items returned exceeds the size limit."}`, "request-refused: the organization answered 400"},
		{"429 with Retry-After", 429, map[string]string{"Retry-After": "30", "X-RateLimit-Resource": "ATCPU.WorkItemTracking"}, errorBody("RequestBlockedException", "TF400733: The request has been canceled: Request was blocked due to exceeding usage of resource."),
			"rate-limited: the organization answered 429 (RequestBlockedException) and asks to wait 30 seconds before another request (threshold: ATCPU.WorkItemTracking); it was not retried"},
		{"429 with a date", 429, map[string]string{"Retry-After": "Tue, 13 Oct 2026 10:00:00 GMT"}, ``, "rate-limited: the organization answered 429 and asks to wait until Tue, 13 Oct 2026 10:00:00 GMT before another request; it was not retried"},
		{"503 with Retry-After", 503, map[string]string{"Retry-After": "12"}, ``, "provider-unavailable: the organization answered 503 and asks to wait 12 seconds before another request; it was not retried"},
		{"503 without", 503, nil, `<html>unavailable</html>`, "provider-unavailable: the organization answered 503; it was not retried"},
		{"500", 500, nil, `<html>error</html>`, "provider-unavailable: the organization answered 500"},
		{"203 sign-in page", 203, nil, `<html>sign in</html>`, "provider-unavailable: the organization answered 203, which this connection does not read"},
		{"not JSON", 200, nil, `<html>sign in</html>`, "provider-unavailable: the organization's answer is not JSON"},
		{"redirect", 302, map[string]string{"Location": "https://dev.azure.com/example/_signin"}, ``, "provider-unavailable: the organization answered 302, a redirect, which is not followed"},
	} {
		var answered atomic.Bool
		f.set(func(w http.ResponseWriter, r *http.Request, _ []byte) {
			// A request after the first -- a retry, a redirect followed --
			// would be answered with a result.
			if answered.Swap(true) {
				io.WriteString(w, adoNormal(r))
				return
			}
			for name, value := range k.header {
				w.Header().Set(name, value)
			}
			w.WriteHeader(k.status)
			io.WriteString(w, k.body)
		})
		for _, read := range adoReads(c, "/example") {
			answered.Store(false)
			before := f.count()
			out, err := azureDevOpsAcquire(context.Background(), s, read.q, f.provider())
			if out != nil || err == nil || err.Error() != k.want {
				t.Errorf("%s, %s: %v", k.name, read.q.Read, err)
			}
			if f.count()-before != 1 {
				t.Errorf("%s, %s: %d requests", k.name, read.q.Read, f.count()-before)
			}
		}
	}
	// The second request of a query-and-get is refused the same way, after
	// the two.
	f.set(func(w http.ResponseWriter, r *http.Request, _ []byte) {
		if strings.HasSuffix(r.URL.Path, "/wiql") {
			io.WriteString(w, adoWIQL)
			return
		}
		w.WriteHeader(404)
		io.WriteString(w, errorBody("WorkItemDoesNotExistException", "TF401232: Work item 7 does not exist."))
	})
	before := f.count()
	_, err := azureDevOpsAcquire(context.Background(), s, adoReads(c, "/example")[3].q, f.provider())
	if err == nil || err.Error() != "request-refused: the organization answered 404 (WorkItemDoesNotExistException)" || f.count()-before != 2 {
		t.Fatal(err, f.count()-before)
	}
}

// The connection's bound holds every answer to it: one of the bound's size
// is read, one a byte over it is refused, with a length announced or not.
func TestAzureDevOpsResultBound(t *testing.T) {
	fields := adoTokenFields()
	fields["max-result-bytes"] = "65536"
	s, _, c, _ := adoFixture(t, fields)
	f := newADOFake(t)
	sized := func(n int) string {
		short := `{"count":0,"value":[],"pad":""}`
		return `{"count":0,"value":[],"pad":"` + strings.Repeat("x", n-len(short)) + `"}`
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
				w.Header().Set("Content-Length", strconv.Itoa(k.size))
			}
			io.WriteString(w, body)
		})
		for _, read := range adoReads(c, "/example") {
			out, err := azureDevOpsAcquire(context.Background(), s, read.q, f.provider())
			if k.ok != (err == nil) || !k.ok && (out != nil || err.Error() != "result-too-large: the organization's answer is larger than the connection's bound of 65536 bytes") {
				t.Errorf("%s, %d bytes, announced %v: %v", read.q.Read, k.size, k.announce, err)
			}
		}
	}
}

// A page is one request: the caller's cursor is sent as the continuation
// token, or the skip and top as the API names them, and the continuation
// token a pipelines page answers with is in the result for the caller to
// send, never followed.
func TestAzureDevOpsPagesAreTheCallersToFollow(t *testing.T) {
	s, _, c, _ := adoFixture(t, adoTokenFields())
	f := newADOFake(t)
	f.set(func(w http.ResponseWriter, r *http.Request, _ []byte) {
		query := r.URL.Query()
		switch {
		case strings.HasSuffix(r.URL.Path, "/pipelines") && query.Get("continuationToken") == "":
			w.Header().Set("X-MS-ContinuationToken", "next-page-1")
			io.WriteString(w, adoPipelines)
		case strings.HasSuffix(r.URL.Path, "/pipelines") && query.Get("continuationToken") == "next-page-1":
			io.WriteString(w, `{"count":1,"value":[{"id":5,"name":"second-pipeline"}]}`)
		default:
			io.WriteString(w, `{"followed":true}`)
		}
	})
	list := AzureDevOpsRequest{Connection: c.ID, Revision: c.Revision, Read: "pipelines.list", Top: 1}
	before := f.count()
	raw, err := azureDevOpsAcquire(context.Background(), s, list, f.provider())
	if err != nil {
		t.Fatal(err)
	}
	e, _ := agreement.Parse(raw)
	if seen := f.since(before); len(seen) != 1 || seen[0].line != "GET /example/"+adoProject+"/_apis/pipelines?$top=1&api-version=7.1" || !bytes.Equal(e.Result, adoExpectedResult(t, "pipelines.list", adoPipelines, "next-page-1")) {
		t.Fatalf("%v %s", seen, e.Result)
	}
	list.Cursor = "next-page-1"
	before = f.count()
	raw, err = azureDevOpsAcquire(context.Background(), s, list, f.provider())
	if err != nil {
		t.Fatal(err)
	}
	e, _ = agreement.Parse(raw)
	members, _ := agreement.Statement(e)
	if seen := f.since(before); len(seen) != 1 || seen[0].line != "GET /example/"+adoProject+"/_apis/pipelines?$top=1&api-version=7.1&continuationToken=next-page-1" ||
		!bytes.Equal(e.Result, adoExpectedResult(t, "pipelines.list", `{"count":1,"value":[{"id":5,"name":"second-pipeline"}]}`, nil)) || !strings.Contains(string(members["query"]), `"continuationToken":"next-page-1"`) {
		t.Fatalf("%v %s %s", seen, e.Result, members["query"])
	}
	// A token of no cursor's form, or given twice, is refused.
	for name, values := range map[string][]string{"a space": {"next page"}, "twice": {"a", "b"}} {
		f.set(func(w http.ResponseWriter, r *http.Request, _ []byte) {
			for _, v := range values {
				w.Header().Add("X-MS-ContinuationToken", v)
			}
			io.WriteString(w, adoPipelines)
		})
		list.Cursor = ""
		if _, err := azureDevOpsAcquire(context.Background(), s, list, f.provider()); err == nil || err.Error() != "provider-unavailable: the organization's continuation token is not of the form a cursor takes" {
			t.Errorf("%s: %v", name, err)
		}
	}
	// Commits and pull requests page by skip and top, as sent.
	f.set(func(w http.ResponseWriter, r *http.Request, _ []byte) { io.WriteString(w, adoNormal(r)) })
	for _, k := range []struct {
		q    AzureDevOpsRequest
		line string
	}{
		{AzureDevOpsRequest{Read: "repos.commits", Repository: "example-repo", Top: 50, Skip: 100, Path: "/docs/a b.md", Version: "main"},
			"GET /example/" + adoProject + "/_apis/git/repositories/example-repo/commits?api-version=7.1&searchCriteria.$skip=100&searchCriteria.$top=50&searchCriteria.itemPath=%2Fdocs%2Fa+b.md&searchCriteria.itemVersion.version=main&searchCriteria.itemVersion.versionType=branch"},
		{AzureDevOpsRequest{Read: "pullrequests.list", Repository: "5febef5a-833d-4e14-b9c0-14cb638f91e6", Top: 1000, Skip: 2000},
			"GET /example/" + adoProject + "/_apis/git/repositories/5febef5a-833d-4e14-b9c0-14cb638f91e6/pullrequests?$skip=2000&$top=1000&api-version=7.1"},
		{AzureDevOpsRequest{Read: "repos.items", Repository: "Example Repo", Recursion: "full", Version: "be67f8871a4d2c75f13a51c1d3c30ac0d74d4ef4", VersionType: "commit"},
			"GET /example/" + adoProject + "/_apis/git/repositories/Example%20Repo/items?$format=json&api-version=7.1&recursionLevel=full&scopePath=%2F&versionDescriptor.version=be67f8871a4d2c75f13a51c1d3c30ac0d74d4ef4&versionDescriptor.versionType=commit"},
		{AzureDevOpsRequest{Read: "workitems.query", Query: "SELECT [System.Id] FROM WorkItems", Top: 20000},
			"POST /example/" + adoProject + "/_apis/wit/wiql?$top=20000&api-version=7.1"},
	} {
		k.q.Connection, k.q.Revision = c.ID, c.Revision
		before := f.count()
		if _, err := azureDevOpsAcquire(context.Background(), s, k.q, f.provider()); err != nil {
			t.Fatal(k.q.Read, err)
		}
		if seen := f.since(before); len(seen) != 1 || seen[0].line != k.line {
			t.Errorf("%s: %v", k.q.Read, seen)
		}
	}
}

// A request for more work items than one request reads is refused before
// anything is sent; the bound's own number is sent.
func TestAzureDevOpsTheIDsBoundIsHeld(t *testing.T) {
	s, _, c, _ := adoFixture(t, adoTokenFields())
	f := newADOFake(t)
	f.set(func(w http.ResponseWriter, r *http.Request, _ []byte) { io.WriteString(w, `{"count":0,"value":[]}`) })
	ids := func(n int) []int64 {
		out := make([]int64, n)
		for i := range out {
			out[i] = int64(1000 + i)
		}
		return out
	}
	q := AzureDevOpsRequest{Connection: c.ID, Revision: c.Revision, Read: "workitems.get", IDs: ids(200)}
	before := f.count()
	if _, err := azureDevOpsAcquire(context.Background(), s, q, f.provider()); err != nil {
		t.Fatal(err)
	}
	if seen := f.since(before); len(seen) != 1 || !strings.HasSuffix(seen[0].line, "ids="+azureDevOpsJoin(ids(200))) {
		t.Fatal(seen)
	}
	q.IDs = ids(201)
	before = f.count()
	out, err := azureDevOpsAcquire(context.Background(), s, q, f.provider())
	if out != nil || err == nil || err.Error() != "ids-bound-exceeded: a read takes at most 200 work items, as one request reads them; nothing was sent" || f.count() != before {
		t.Fatal(err, f.count()-before)
	}
}

// A query-and-get reads the query, then the work items by the ids the query
// answered, in its order and no others, at most the bound's: the record
// commits the query, the fields and the bound, its snapshot is the items'
// answer, and the result holds both answers, the ids read among them.
func TestAzureDevOpsQueryAndGetReadsTheIDsTheQueryAnswered(t *testing.T) {
	s, _, c, _ := adoFixture(t, adoTokenFields())
	f := newADOFake(t)
	wiql := func(n int) string {
		refs := make([]string, n)
		for i := range refs {
			refs[i] = fmt.Sprintf(`{"id":%d,"url":"https://dev.azure.com/example/_apis/wit/workItems/%d"}`, 5000-i, 5000-i)
		}
		return `{"queryType":"flat","queryResultType":"workItem","workItems":[` + strings.Join(refs, ",") + `]}`
	}
	items := func(n int) string {
		values := make([]string, n)
		for i := range values {
			values[i] = fmt.Sprintf(`{"id":%d,"rev":1,"fields":{"System.Title":"Example %d"}}`, 5000-i, i)
		}
		return `{"count":` + strconv.Itoa(n) + `,"value":[` + strings.Join(values, ",") + `]}`
	}
	answering := func(first, second string) {
		f.set(func(w http.ResponseWriter, r *http.Request, _ []byte) {
			if strings.HasSuffix(r.URL.Path, "/wiql") {
				io.WriteString(w, first)
				return
			}
			io.WriteString(w, second)
		})
	}
	q := AzureDevOpsRequest{Connection: c.ID, Revision: c.Revision, Read: "workitems.query-and-get", Query: "SELECT [System.Id] FROM WorkItems ORDER BY [System.Id] DESC", Fields: []string{"System.Title", "System.State"}}
	// At the bound: the 200 ids the query answered, in its order.
	answering(wiql(200), items(200))
	before := f.count()
	raw, err := azureDevOpsAcquire(context.Background(), s, q, f.provider())
	if err != nil {
		t.Fatal(err)
	}
	asked := make([]int64, 200)
	for i := range asked {
		asked[i] = int64(5000 - i)
	}
	seen := f.since(before)
	if len(seen) != 2 || seen[0].line != "POST /example/"+adoProject+"/_apis/wit/wiql?$top=200&api-version=7.1" ||
		seen[1].line != "GET /example/"+adoProject+"/_apis/wit/workitems?api-version=7.1&fields=System.Title,System.State&ids="+azureDevOpsJoin(asked) {
		t.Fatalf("%d requests: %v", len(seen), seen)
	}
	e, err := agreement.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	if *e.Acquisition.Snapshot != digest([]byte(items(200))) || *e.Acquisition.Endpoint != adoOrganization+"/"+adoProject+"/_apis/wit/workitems?api-version=7.1&fields=System.Title,System.State&ids="+azureDevOpsJoin(asked) {
		t.Fatalf("%+v", e.Acquisition)
	}
	var result struct{ Query, Items json.RawMessage }
	json.Unmarshal(e.Result, &result)
	if !bytes.Equal(result.Query, adoCanonical(t, json.RawMessage(wiql(200)))) || !bytes.Equal(result.Items, adoCanonical(t, json.RawMessage(items(200)))) {
		t.Fatal("the result does not hold both answers")
	}
	members, _ := agreement.Statement(e)
	// The statement commits the query, its bound, the fields, and the
	// second request as it was sent: its ids in order, its fields and its
	// API version.
	var then struct {
		Method, Endpoint string
		Query            map[string]string
	}
	var fields []string
	json.Unmarshal(members["then"], &then)
	json.Unmarshal(members["fields"], &fields)
	if string(members["method"]) != `"POST"` || !strings.Contains(string(members["body"]), "ORDER BY [System.Id] DESC") || !strings.Contains(string(members["query"]), `"$top":"200"`) || strings.Join(fields, ",") != "System.Title,System.State" ||
		then.Method != "GET" || then.Endpoint != adoOrganization+"/"+adoProject+"/_apis/wit/workitems" || len(then.Query) != 3 || then.Query["ids"] != azureDevOpsJoin(asked) || then.Query["fields"] != "System.Title,System.State" || then.Query["api-version"] != "7.1" {
		t.Fatalf("statement %s %s %s %s %s", members["method"], members["body"], members["query"], members["fields"], members["then"])
	}
	// One past the bound: refused after the query, and nothing else asked.
	answering(wiql(201), items(201))
	before = f.count()
	out, err := azureDevOpsAcquire(context.Background(), s, q, f.provider())
	if out != nil || err == nil || err.Error() != "ids-bound-exceeded: the query answered 201 work items, more than the 200 this read takes in one request; the items were not read" || f.count()-before != 1 {
		t.Fatal(err, f.count()-before)
	}
	// A smaller bound is sent as the query's $top, and held to.
	q.Top = 5
	answering(wiql(5), items(5))
	before = f.count()
	if _, err = azureDevOpsAcquire(context.Background(), s, q, f.provider()); err != nil || f.since(before)[0].line != "POST /example/"+adoProject+"/_apis/wit/wiql?$top=5&api-version=7.1" {
		t.Fatal(err)
	}
	answering(wiql(6), items(6))
	before = f.count()
	if _, err = azureDevOpsAcquire(context.Background(), s, q, f.provider()); err == nil || !strings.HasPrefix(err.Error(), "ids-bound-exceeded: the query answered 6 work items, more than the 5") || f.count()-before != 1 {
		t.Fatal(err)
	}
	// The items' answer is held to the ids asked for.
	q.Top = 0
	for name, second := range map[string]string{
		"an item not asked for": `{"count":1,"value":[{"id":99,"fields":{}}]}`,
		"an item twice":         `{"count":2,"value":[{"id":5000,"fields":{}},{"id":5000,"fields":{}}]}`,
		"no list":               `{"count":0}`,
	} {
		answering(wiql(2), second)
		if _, err = azureDevOpsAcquire(context.Background(), s, q, f.provider()); err == nil || !strings.HasPrefix(err.Error(), "provider-unavailable: the organization's work items answer is not of the form") {
			t.Errorf("%s: %v", name, err)
		}
	}
	// A query of links is not a list of items, and nothing more is asked.
	for name, first := range map[string]string{
		"a tree":    `{"queryType":"tree","queryResultType":"workItemLink","workItemRelations":[{"rel":null,"source":null,"target":{"id":1}}]}`,
		"relations": `{"queryType":"oneHop","workItemRelations":[]}`,
	} {
		answering(first, items(1))
		before = f.count()
		if _, err = azureDevOpsAcquire(context.Background(), s, q, f.provider()); err == nil || !strings.HasPrefix(err.Error(), "query-not-flat:") || f.count()-before != 1 {
			t.Errorf("%s: %v", name, err)
		}
	}
	// ids in the request are not a query-and-get's: it reads the query's.
	q.IDs = []int64{1, 2}
	if _, err = azureDevOpsAcquire(context.Background(), s, q, f.provider()); err != ErrRequest {
		t.Fatal(err)
	}
}

// The organization URL is held to its two forms, case by case.
func TestAzureDevOpsOrganizationURLForm(t *testing.T) {
	for raw, want := range map[string]string{
		"https://dev.azure.com/example":                            "https://dev.azure.com/example",
		"https://dev.azure.com/example/":                           "https://dev.azure.com/example",
		"https://dev.azure.com/Example-Org2":                       "https://dev.azure.com/Example-Org2",
		"https://dev.azure.com/e":                                  "https://dev.azure.com/e",
		"https://example.visualstudio.com":                         "https://example.visualstudio.com",
		"https://example.visualstudio.com/":                        "https://example.visualstudio.com",
		"https://example-2.visualstudio.com":                       "https://example-2.visualstudio.com",
		"https://dev.azure.com/" + strings.Repeat("a", 49):         "https://dev.azure.com/" + strings.Repeat("a", 49),
		"https://dev.azure.com/" + strings.Repeat("a", 50):         "",
		"https://" + strings.Repeat("a", 50) + ".visualstudio.com": "",
		"http://dev.azure.com/example":                             "",
		"dev.azure.com/example":                                    "",
		"https://dev.azure.com":                                    "",
		"https://dev.azure.com/":                                   "",
		"https://dev.azure.com//":                                  "",
		"https://dev.azure.com/example//":                          "",
		"https://dev.azure.com/example/project":                    "",
		"https://dev.azure.com/example/_apis":                      "",
		"https://dev.azure.com/example?x=1":                        "",
		"https://dev.azure.com/example#top":                        "",
		"https://dev.azure.com/-example":                           "",
		"https://dev.azure.com/example-":                           "",
		"https://dev.azure.com/exa_mple":                           "",
		"https://dev.azure.com/exa.mple":                           "",
		"https://dev.azure.com/exam%70le":                          "",
		"https://dev.azure.com/ex ample":                           "",
		"https://dev.azure.com/examplé":                            "",
		"https://user@dev.azure.com/example":                       "",
		"https://user:secret@dev.azure.com/example":                "",
		"https://dev.azure.com:443/example":                        "",
		"https://DEV.AZURE.COM/example":                            "",
		"https://dev.azure.com./example":                           "",
		"https://dev.azure.com.example.org/example":                "",
		"https://vssps.dev.azure.com/example":                      "",
		"https://dev.azure.com\\@example.org/example":              "",
		"https://Example.visualstudio.com":                         "",
		"https://example.visualstudio.com/project":                 "",
		"https://example.visualstudio.com:443":                     "",
		"https://example.visualstudio.com.":                        "",
		"https://a.b.visualstudio.com":                             "",
		"https://visualstudio.com":                                 "",
		"https://.visualstudio.com":                                "",
		"https://xn--xmple-cua.visualstudio.com":                   "",
		"https://example.visualstudio.com.example.org":             "",
		"https://examplevisualstudio.com":                          "",
		"https://user@example.visualstudio.com":                    "",
		"https://192.0.2.1":                                        "",
		"https://[2001:db8::1]/example":                            "",
		"https://dev.azure.com/example\t":                          "",
		"":                                                         "",
	} {
		got, ok := AzureDevOpsOrganization(raw)
		if ok != (want != "") || got != want {
			t.Errorf("%q: %q %v", raw, got, ok)
		}
		if want != "" {
			continue
		}
		// Configure refuses each, and keeps nothing of it.
		_, b, _, dir := adoFixture(t, adoTokenFields())
		fields := adoTokenFields()
		fields["id"], fields["organization-url"] = "other", raw
		if err := adoConfigure(b, fields); err != ErrRequest || bytes.Contains(adoState(t, dir), []byte(`"other"`)) {
			t.Errorf("configure took %q: %v", raw, err)
		}
	}
}

// What configure takes, and what it refuses; and every request out of its
// read's form is refused before anything is sent.
func TestAzureDevOpsFormsAreHeldBeforeAnythingIsSent(t *testing.T) {
	s, b, c, _ := adoFixture(t, adoTokenFields())
	for name, change := range map[string]map[string]string{
		"no project":                {"project": ""},
		"a project with a slash":    {"project": "example/project"},
		"a project with a colon":    {"project": "example:project"},
		"a project of dots":         {"project": ".."},
		"a project ending in a dot": {"project": "example."},
		"a project starting with _": {"project": "_example"},
		"a project of 65":           {"project": strings.Repeat("p", 65)},
		"a project with a quote":    {"project": "example'project"},
		"a project with a newline":  {"project": "example\nproject"},
		"another auth":              {"auth": "oauth"},
		"no token":                  {"token": ""},
		"a token with a space":      {"token": "adopat marker"},
		"a token and an expiry":     {"expires-at": "2030-01-01T00:00:00Z"},
		"a token and an access":     {"access-token": adoBearer},
		"a bound under 64 KiB":      {"max-result-bytes": "65535"},
		"a bound over 15 MiB":       {"max-result-bytes": "15728641"},
		"an uppercase id":           {"id": "Board"},
		"no name":                   {"name": ""},
	} {
		fields := adoTokenFields()
		fields["id"] = "second"
		for k, v := range change {
			fields[k] = v
		}
		if err := adoConfigure(b, fields); err != ErrRequest {
			t.Errorf("%s: %v", name, err)
		}
	}
	for name, change := range map[string]map[string]string{
		"no expiry":            {"expires-at": ""},
		"an expiry in words":   {"expires-at": "tomorrow"},
		"a date alone":         {"expires-at": "2030-01-01"},
		"no access token":      {"access-token": ""},
		"a short access token": {"access-token": "eyJshort"},
		"a token too":          {"token": adoPAT},
	} {
		fields := adoBearerFields()
		fields["id"] = "second"
		for k, v := range change {
			fields[k] = v
		}
		if err := adoConfigure(b, fields); err != ErrRequest {
			t.Errorf("%s: %v", name, err)
		}
	}
	for name, project := range map[string]string{"a GUID": "6ce954b1-ce1f-45d1-b94d-e6bf2464ba2c", "a name with spaces": "Example Project (2026) & more", "unicode": "Projet d’exemple", "64": strings.Repeat("p", 64)} {
		fields := adoTokenFields()
		fields["id"], fields["project"] = "p-"+strings.ToLower(strings.Fields(name)[0]), project
		if err := adoConfigure(b, fields); err != nil {
			t.Errorf("%s: %v", name, err)
		}
		m := adoConnection(t, s, fields["id"])
		b.Handle(context.Background(), "disconnect", []byte(`{"id":"`+m.ID+`","revision":"`+m.Revision+`"}`))
	}
	f := newADOFake(t)
	ids := make([]int64, 0)
	for name, q := range map[string]AzureDevOpsRequest{
		"no read":                      {},
		"an unknown read":              {Read: "workitems.update"},
		"an empty query":               {Read: "workitems.query"},
		"a query of 32,001 characters": {Read: "workitems.query", Query: strings.Repeat("x", 32001)},
		"a control character":          {Read: "workitems.query", Query: "SELECT\x00"},
		"a top past 20,000":            {Read: "workitems.query", Query: "SELECT", Top: 20001},
		"a negative top":               {Read: "workitems.query", Query: "SELECT", Top: -1},
		"ids on a query":               {Read: "workitems.query", Query: "SELECT", IDs: []int64{1}},
		"a query-and-get past 200":     {Read: "workitems.query-and-get", Query: "SELECT", Top: 201},
		"no ids":                       {Read: "workitems.get"},
		"empty ids":                    {Read: "workitems.get", IDs: ids},
		"an id and ids":                {Read: "workitems.get", ID: 1, IDs: []int64{2}},
		"an id twice":                  {Read: "workitems.get", IDs: []int64{2, 2}},
		"an id of 0":                   {Read: "workitems.get", IDs: []int64{0}},
		"an id past int32":             {Read: "workitems.get", ID: 1 << 31},
		"a field out of form":          {Read: "workitems.get", ID: 1, Fields: []string{"Title"}},
		"a field with a comma":         {Read: "workitems.get", ID: 1, Fields: []string{"System.Title,System.State"}},
		"a field twice":                {Read: "workitems.get", ID: 1, Fields: []string{"System.Title", "system.title"}},
		"65 fields": {Read: "workitems.get", ID: 1, Fields: func() []string {
			out := []string{}
			for i := range 65 {
				out = append(out, fmt.Sprintf("Custom.F%d", i))
			}
			return out
		}()},
		"a repository on a list":     {Read: "repos.list", Repository: "example-repo"},
		"no repository":              {Read: "repos.items"},
		"a repository with a slash":  {Read: "repos.items", Repository: "a/b"},
		"a repository of dots":       {Read: "repos.items", Repository: ".."},
		"a relative path":            {Read: "repos.items", Repository: "r", Path: "docs"},
		"a path with ..":             {Read: "repos.items", Repository: "r", Path: "/docs/../secret"},
		"a path with //":             {Read: "repos.items", Repository: "r", Path: "/docs//a"},
		"a path ending in /":         {Read: "repos.items", Repository: "r", Path: "/docs/"},
		"a backslash path":           {Read: "repos.items", Repository: "r", Path: "/docs\\a"},
		"another recursion":          {Read: "repos.items", Repository: "r", Recursion: "oneLevelPlusNestedEmptyFolders"},
		"a version type alone":       {Read: "repos.items", Repository: "r", VersionType: "branch"},
		"a branch with ..":           {Read: "repos.items", Repository: "r", Version: "main..x"},
		"a branch with a space":      {Read: "repos.items", Repository: "r", Version: "my branch"},
		"a short commit":             {Read: "repos.items", Repository: "r", Version: "be67f88", VersionType: "commit"},
		"another version type":       {Read: "repos.items", Repository: "r", Version: "main", VersionType: "label"},
		"a commits page past 1000":   {Read: "repos.commits", Repository: "r", Top: 1001},
		"a negative skip":            {Read: "pullrequests.list", Repository: "r", Skip: -1},
		"another status":             {Read: "pullrequests.list", Repository: "r", Status: "draft"},
		"a cursor on a commits page": {Read: "repos.commits", Repository: "r", Cursor: "x"},
		"a cursor with a space":      {Read: "pipelines.list", Cursor: "a b"},
		"a skip on pipelines":        {Read: "pipelines.list", Skip: 1},
		"no pipeline":                {Read: "pipelines.runs"},
		"a run on runs":              {Read: "pipelines.runs", Pipeline: 1, Run: 2},
		"no run":                     {Read: "pipelines.run", Pipeline: 1},
		"a negative pipeline":        {Read: "pipelines.run", Pipeline: -1, Run: 2},
	} {
		q.Connection, q.Revision = c.ID, c.Revision
		if _, err := azureDevOpsAcquire(context.Background(), s, q, f.provider()); err != ErrRequest {
			t.Errorf("%s: %v", name, err)
		}
	}
	if f.count() != 0 {
		t.Fatal("a refused request reached the organization")
	}
}

// Status, configure, test and disconnect, under the store's custody rules.
func TestAzureDevOpsControlsKeepCustody(t *testing.T) {
	s, b, c, dir := adoFixture(t, adoTokenFields())
	f := newADOFake(t)
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
	if err != nil || bytes.Contains(raw, []byte(adoPAT)) || bytes.Contains(raw, []byte(adoBasic)) || bytes.Contains(raw, []byte(`"token":`)) || !bytes.Contains(raw, []byte(`"ready":true`)) || !bytes.Contains(raw, []byte(`"maxIds":200`)) || !bytes.Contains(raw, []byte(`"apiVersion":"7.1"`)) {
		t.Fatalf("status %s %v", raw, err)
	}
	// A configure with a stale revision is refused; a blank token keeps the
	// saved one only where it would go to the same organization.
	if err = adoConfigure(b, adoTokenFields()); err != ErrChanged {
		t.Fatal("a stale configure was taken", err)
	}
	update := adoTokenFields()
	update["revision"], update["token"], update["name"], update["project"] = c.Revision, "", "Renamed", "other-project"
	if err = adoConfigure(b, update); err != nil {
		t.Fatal(err)
	}
	c = adoConnection(t, s, "board")
	if c.Token != adoPAT || c.Name != "Renamed" || c.Project != "other-project" {
		t.Fatal("a blank token did not keep the saved one")
	}
	for _, organization := range []string{adoLegacy, "https://dev.azure.com/other"} {
		moved := adoTokenFields()
		moved["revision"], moved["token"], moved["organization-url"] = c.Revision, "", organization
		if err = adoConfigure(b, moved); err != ErrRequest {
			t.Fatal("a saved token went with the connection to another organization URL", organization, err)
		}
	}
	// A blank access token keeps the saved one and its expiry together, and
	// never another's expiry.
	bs, bb, bc, _ := adoFixture(t, adoBearerFields())
	kept := adoBearerFields()
	kept["revision"], kept["access-token"], kept["expires-at"] = bc.Revision, "", ""
	if err = adoConfigure(bb, kept); err != nil || adoConnection(t, bs, "board").AccessToken != adoBearer || adoConnection(t, bs, "board").ExpiresAt != bc.ExpiresAt {
		t.Fatal("a blank access token did not keep the saved one", err)
	}
	bc = adoConnection(t, bs, "board")
	later := adoBearerFields()
	later["revision"], later["access-token"], later["expires-at"] = bc.Revision, "", time.Now().Add(48*time.Hour).UTC().Format(time.RFC3339)
	if err = adoConfigure(bb, later); err != ErrRequest {
		t.Fatal("an expiry was given to a saved token", err)
	}
	// Six connections at most.
	for i := range 5 {
		more := adoTokenFields()
		more["id"] = "more-" + string(rune('a'+i))
		if err = adoConfigure(b, more); err != nil {
			t.Fatal(err)
		}
	}
	more := adoTokenFields()
	more["id"] = "seventh"
	if err = adoConfigure(b, more); err != ErrRequest {
		t.Fatal("a seventh connection", err)
	}
	// A test is one query for one work item, and returns nothing of it.
	f.set(func(w http.ResponseWriter, r *http.Request, _ []byte) {
		io.WriteString(w, `{"queryResultType":"workItem","workItems":[{"id":1,"url":"private"}]}`)
	})
	answer, err := b.Handle(context.Background(), "test", []byte(`{"id":"board","revision":"`+c.Revision+`"}`))
	raw, _ = json.Marshal(answer)
	seen := f.since(0)
	if err != nil || string(raw) != `{"ok":true}` || len(seen) != 1 || seen[0].line != "POST /example/other-project/_apis/wit/wiql?$top=1&api-version=7.1" ||
		string(seen[0].body) != `{"query":"`+azureDevOpsTestQuery+`"}` || seen[0].auth != "Basic "+adoBasic {
		t.Fatalf("test %s %v %v", raw, err, seen)
	}
	f.set(func(w http.ResponseWriter, r *http.Request, _ []byte) { w.WriteHeader(401) })
	answer, err = b.Handle(context.Background(), "test", []byte(`{"id":"board","revision":"`+c.Revision+`"}`))
	if raw, _ = json.Marshal(answer); err == nil || err.Error() != "credentials-required: the organization answered 401" || string(raw) != `{"ok":false}` {
		t.Fatal(string(raw), err)
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
		renamed := adoTokenFields()
		renamed["revision"], renamed["token"], renamed["name"] = c.Revision, "", "Locked"
		done <- adoConfigure(b, renamed)
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
	c = adoConnection(t, s, "board")
	// A read under an earlier revision is refused.
	if _, err = azureDevOpsAcquire(context.Background(), s, AzureDevOpsRequest{Connection: "board", Revision: strings.Repeat("0", 64), Read: "repos.list"}, f.provider()); err != ErrChanged {
		t.Fatal(err)
	}
	// Disconnect forgets the credential, and revokes nothing.
	answer, err = b.Handle(context.Background(), "disconnect", []byte(`{"id":"board","revision":"`+c.Revision+`"}`))
	raw, _ = json.Marshal(answer)
	if err != nil || string(raw) != `{"disconnected":true,"revoked":false}` {
		t.Fatal(string(raw), err)
	}
	for i := range 5 {
		id := "more-" + string(rune('a'+i))
		m := adoConnection(t, s, id)
		if _, err = b.Handle(context.Background(), "disconnect", []byte(`{"id":"`+id+`","revision":"`+m.Revision+`"}`)); err != nil {
			t.Fatal(err)
		}
	}
	if bytes.Contains(adoState(t, dir), []byte(adoPAT)) {
		t.Fatal("disconnect kept the token")
	}
	if _, err = azureDevOpsAcquire(context.Background(), s, AzureDevOpsRequest{Connection: "board", Revision: c.Revision, Read: "repos.list"}, f.provider()); err != ErrConnect {
		t.Fatal("a disconnected connection read", err)
	}
	// A state file another may read is refused.
	matches, _ := filepath.Glob(filepath.Join(dir, "azure-devops", "*", "state.json"))
	if len(matches) != 1 || os.Chmod(matches[0], 0644) != nil {
		t.Fatal("state file", matches)
	}
	if _, err = b.Handle(context.Background(), "status", []byte(`{}`)); err != ErrStorage {
		t.Fatal("a readable state file was used", err)
	}
}

// The broker's conventions: an unsupported method is refused, and an
// operator's block is kept and answered.
func TestAzureDevOpsBrokerConventions(t *testing.T) {
	s, b, c, _ := adoFixture(t, adoTokenFields())
	for _, method := range []string{"search", "select", "connect", "poll", "workitems.query", "files-list"} {
		if _, err := b.Handle(context.Background(), method, []byte(`{}`)); err != ErrRequest {
			t.Errorf("%s: %v", method, err)
		}
	}
	blocked := NewAzureDevOps(s, true)
	defer blocked.Close()
	out, err := blocked.Handle(context.Background(), "status", []byte(`{}`))
	if err != nil || out.(Status).State != "blocked" || out.(Status).Provider != "azure-devops" {
		t.Fatal(out, err)
	}
	if _, err = blocked.Handle(context.Background(), "configure", []byte(`{}`)); err != ErrPolicy {
		t.Fatal(err)
	}
	f := newADOFake(t)
	if _, err = azureDevOpsAcquire(context.Background(), s, AzureDevOpsRequest{Connection: c.ID, Revision: c.Revision, Read: "repos.list"}, f.provider()); err != ErrPolicy || f.count() != 0 {
		t.Fatal("a blocked connection read", err)
	}
}

// An access token is sent as the bearer while it is more than a minute from
// the expiry the operator gave; at or within that minute it is refused
// before any request, by a read and by a test, and status says it is not
// ready.
func TestAzureDevOpsAnExpiredAccessTokenIsNotSent(t *testing.T) {
	f := newADOFake(t)
	for _, k := range []struct {
		in time.Duration
		ok bool
	}{{-time.Hour, false}, {-time.Second, false}, {30 * time.Second, false}, {2 * time.Minute, true}, {time.Hour, true}} {
		fields := adoBearerFields()
		fields["expires-at"] = time.Now().Add(k.in).UTC().Format(time.RFC3339)
		s, b, c, _ := adoFixture(t, fields)
		b.provider = f.provider()
		before := f.count()
		_, err := azureDevOpsAcquire(context.Background(), s, AzureDevOpsRequest{Connection: c.ID, Revision: c.Revision, Read: "repos.list"}, f.provider())
		_, testErr := b.Handle(context.Background(), "test", []byte(`{"id":"board","revision":"`+c.Revision+`"}`))
		status, _ := b.Handle(context.Background(), "status", []byte(`{}`))
		raw, _ := json.Marshal(status)
		if k.ok {
			seen := f.since(before)
			if err != nil || testErr != nil || len(seen) != 2 || seen[0].auth != "Bearer "+adoBearer || !bytes.Contains(raw, []byte(`"ready":true`)) {
				t.Errorf("%v from now: %v %v %v", k.in, err, testErr, seen)
			}
			continue
		}
		if err != azureDevOpsExpired || testErr != azureDevOpsExpired || f.count() != before || !bytes.Contains(raw, []byte(`"ready":false`)) || bytes.Contains(raw, []byte(adoBearer)) {
			t.Errorf("%v from now: %v %v, %d requests, %s", k.in, err, testErr, f.count()-before, raw)
		}
	}
}

// The descriptor and the plan name the provider as the other providers are
// named, and the version 2 catalog does not.
func TestAzureDevOpsCatalogAndPlan(t *testing.T) {
	for _, p := range ConnectionCatalog().Providers {
		if p.ID == "azure-devops" {
			t.Fatal("azure-devops in the version 2 catalog")
		}
	}
	var d ProviderDescriptor
	for _, p := range ConnectionCatalogV3().Providers {
		if p.ID == "azure-devops" {
			d = p
		}
	}
	if d.Protocol != "azure-devops-v1" || d.Auth != "credentials" || d.Registration != "form" || d.Selection != "none" || d.Source != (SourceContract{"azure-devops", "http", "azure-devops-api-v1"}) || len(d.Setup) != 7 {
		t.Fatalf("%+v", d)
	}
	if strings.Join(d.Operations, ",") != "status,configure,disconnect,test" {
		t.Fatal(d.Operations)
	}
	every, _ := json.Marshal(AzureDevOpsConnection{"a", "b", "c", "d", "e", "f", "g", "h", "i", "j", nil})
	for _, field := range d.Setup {
		if (field.Type == "password") != (field.Key == "token" || field.Key == "access-token") {
			t.Error("field type", field.Key, field.Type)
		}
		for _, locale := range []string{"en", "fr", "es", "de", "it", "pt-PT", "pt-BR", "ko", "ja", "zh-Hans", "zh-Hant", "yue-Hant"} {
			if field.Label[locale] == "" || d.Presentation.Description[locale] == "" || d.Presentation.Instructions[locale] == "" {
				t.Error("untranslated", field.Key, locale)
			}
		}
		// Each field is a member configure reads by the field's key.
		if !strings.Contains(string(every), `"`+field.Key+`":"`) {
			t.Error("field not configured", field.Key)
		}
	}
	if d.Presentation.Name != "Azure DevOps" {
		t.Fatal(d.Presentation)
	}
	if desc, ok := LookupProvider("azure-devops"); !ok || desc.supports("workitems.query") || !desc.supports("test") {
		t.Fatal(desc)
	}
	found := false
	for _, source := range ConnectionLocalPlan().Sources {
		if source.ID == "azure-devops" {
			found = source.Executable == "adapter-sources" && strings.Join(source.Args, " ") == "--provider azure-devops --principal desk-local" && source.Shape == "http" && source.Timeout == 60 && source.Connections
		}
	}
	if !found {
		t.Fatal("the plan does not launch the source")
	}
	if 2*azureDevOpsSeconds >= 55 || AzureDevOpsMaxResultBytes+1<<20 > MaxOutputBytes {
		t.Fatal("the bounds do not fit the envelope")
	}
}

// The personal access token, its basic authentication value and the access
// token are in no record, error, status, test answer, custody file after
// disconnect or log line, on any path, whatever the organization sends back:
// the server here reflects the Authorization header in every error body,
// error type, wait, threshold and continuation token, and in answers.
func TestAzureDevOpsCredentialsAreNeverEchoed(t *testing.T) {
	var logged bytes.Buffer
	log.SetOutput(&logged)
	defer log.SetOutput(os.Stderr)
	markers := []string{adoPAT, adoBasic, adoBearer}
	var seen [][]byte
	keep := func(v any) {
		raw, _ := json.Marshal(v)
		seen = append(seen, raw)
	}
	credential := func(r *http.Request) string {
		auth := r.Header.Get("Authorization")
		if bearer, ok := strings.CutPrefix(auth, "Bearer "); ok {
			return bearer
		}
		if encoded, ok := strings.CutPrefix(auth, "Basic "); ok {
			decoded, _ := base64.StdEncoding.DecodeString(encoded)
			return strings.TrimPrefix(string(decoded), ":")
		}
		return ""
	}
	for _, fields := range []map[string]string{adoTokenFields(), adoBearerFields()} {
		s, b, c, dir := adoFixture(t, fields)
		f := newADOFake(t)
		b.provider = f.provider()
		reads := adoReads(c, "/example")
		for _, status := range []int{401, 403, 404, 429, 500, 503} {
			f.set(func(w http.ResponseWriter, r *http.Request, _ []byte) {
				auth := r.Header.Get("Authorization")
				w.Header().Set("Retry-After", credential(r))
				w.Header().Set("X-RateLimit-Resource", auth+" "+credential(r))
				w.WriteHeader(status)
				body, _ := json.Marshal(map[string]any{"message": auth + " | " + credential(r), "typeKey": credential(r), "typeName": auth})
				w.Write(body)
			})
			for _, read := range reads {
				_, err := azureDevOpsAcquire(context.Background(), s, read.q, f.provider())
				keep(err.Error())
			}
			answer, err := b.Handle(context.Background(), "test", []byte(`{"id":"board","revision":"`+c.Revision+`"}`))
			keep(answer)
			keep(err.Error())
		}
		// Answers repeating it, as written and escaped, and a continuation
		// token that is it: nothing of any of them is kept.
		for _, form := range []func(string) string{func(s string) string { return s }, adoEscaped} {
			f.set(func(w http.ResponseWriter, r *http.Request, _ []byte) {
				w.Header().Set("X-MS-ContinuationToken", credential(r))
				io.WriteString(w, `{"count":1,"value":[{"id":1,"name":"`+form(credential(r))+`","auth":"`+form(r.Header.Get("Authorization"))+`"}],"workItems":[{"id":1}]}`)
			})
			for _, read := range reads {
				out, err := azureDevOpsAcquire(context.Background(), s, read.q, f.provider())
				if out != nil || err == nil || err != azureDevOpsRepeats {
					t.Errorf("%s: %v", read.q.Read, err)
				}
				keep(err.Error())
			}
		}
		// And ordinary reads, their records and statements.
		f.set(func(w http.ResponseWriter, r *http.Request, _ []byte) {
			if strings.HasSuffix(r.URL.Path, "/pipelines") {
				w.Header().Set("X-MS-ContinuationToken", "next-page")
			}
			io.WriteString(w, adoNormal(r))
		})
		for _, read := range reads {
			out, err := azureDevOpsAcquire(context.Background(), s, read.q, f.provider())
			if err != nil {
				t.Fatal(read.q.Read, err)
			}
			seen = append(seen, out)
		}
		status, _ := b.Handle(context.Background(), "status", []byte(`{}`))
		keep(status)
		answer, err := b.Handle(context.Background(), "test", []byte(`{"id":"board","revision":"`+c.Revision+`"}`))
		if err != nil {
			t.Fatal(err)
		}
		keep(answer)
		// A name carrying the credential is refused, and nothing is kept.
		named := fields
		named["id"], named["name"] = "named", "Board "+credential(&http.Request{Header: http.Header{"Authorization": {c.authorization()}}})
		if err = adoConfigure(b, named); err != azureDevOpsInConfiguration {
			t.Fatal(err)
		}
		keep(err.Error())
		// Disconnect leaves nothing in custody.
		if _, err = b.Handle(context.Background(), "disconnect", []byte(`{"id":"board","revision":"`+c.Revision+`"}`)); err != nil {
			t.Fatal(err)
		}
		seen = append(seen, adoState(t, dir))
	}
	seen = append(seen, logged.Bytes())
	for i, raw := range seen {
		for _, marker := range markers {
			if bytes.Contains(raw, []byte(marker)) || bytes.Contains(raw, []byte(adoEscaped(marker))) {
				t.Errorf("output %d holds a credential: %s", i, raw)
			}
		}
	}
	if len(seen) < 100 {
		t.Fatal("too few outputs looked at", len(seen))
	}
}

// adoEscaped writes every character of s as a JSON \u escape.
func adoEscaped(s string) string {
	var b strings.Builder
	for _, r := range s {
		fmt.Fprintf(&b, `\u%04x`, r)
	}
	return b.String()
}

// The live check reads the project's repositories and one query from an
// organization the environment names. Without it, it is not run, and says
// so.
func TestAzureDevOpsLiveCheck(t *testing.T) {
	organization := os.Getenv("JPACK_AZURE_DEVOPS_LIVE_ORGANIZATION")
	if organization == "" {
		t.Skip("not run: JPACK_AZURE_DEVOPS_LIVE_ORGANIZATION, JPACK_AZURE_DEVOPS_LIVE_PROJECT and JPACK_AZURE_DEVOPS_LIVE_TOKEN name no organization")
	}
	s, _, c, _ := adoFixture(t, map[string]string{"id": "live", "name": "Live", "organization-url": organization, "project": os.Getenv("JPACK_AZURE_DEVOPS_LIVE_PROJECT"), "auth": "token", "token": os.Getenv("JPACK_AZURE_DEVOPS_LIVE_TOKEN")})
	for _, q := range []AzureDevOpsRequest{
		{Connection: c.ID, Revision: c.Revision, Read: "repos.list"},
		{Connection: c.ID, Revision: c.Revision, Read: "workitems.query-and-get", Query: azureDevOpsTestQuery, Top: 1, Fields: []string{"System.Title"}},
	} {
		raw, err := azureDevOpsAcquire(context.Background(), s, q, azureDevOpsProvider())
		if err != nil {
			t.Fatal(q.Read, err)
		}
		if _, err = agreement.Parse(raw); err != nil {
			t.Fatal(err)
		}
	}
}
