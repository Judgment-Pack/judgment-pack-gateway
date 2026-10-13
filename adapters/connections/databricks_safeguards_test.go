//go:build linux || darwin

package connections

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// The safeguards a cross-vendor review asked for (round 1, at 63494ba),
// held by tests that answer in process, without a listener.

// dbThrough is the connection's own provider, its redirect rule and
// timeouts included, with a transport that answers in process.
func dbThrough(answer func(r *http.Request) (*http.Response, error)) provider {
	p := databricksProvider()
	p.client = &http.Client{Transport: testTransportFunc(answer), CheckRedirect: p.client.CheckRedirect, Timeout: p.client.Timeout}
	return p
}

// dbAnswer is an answer with a verified peer certificate of the test's own.
func dbAnswer(r *http.Request, status int, body string) *http.Response {
	certificate := &x509.Certificate{Raw: []byte("a test peer certificate")}
	return &http.Response{StatusCode: status, Header: http.Header{"Content-Type": {"application/json"}}, Body: io.NopCloser(strings.NewReader(body)), ContentLength: int64(len(body)), Request: r,
		TLS: &tls.ConnectionState{PeerCertificates: []*x509.Certificate{certificate}, VerifiedChains: [][]*x509.Certificate{{certificate}}}}
}

// dbEscaped writes every character of s as a JSON \u escape.
func dbEscaped(s string) string {
	var b strings.Builder
	for _, r := range s {
		fmt.Fprintf(&b, `\u%04x`, r)
	}
	return b.String()
}

const dbMintedAnswer = `{"access_token":"` + dbMinted + `","token_type":"Bearer","expires_in":3600}`

// A credential the answer spells in escapes is found as decoded, in a
// value or a member name, for each of the three credentials, and nothing
// of the answer is kept.
func TestDatabricksAnEscapedCredentialInAnAnswerIsRefused(t *testing.T) {
	for _, k := range []struct{ name, secret string }{{"personal access token", dbPAT}, {"client secret", dbSecret}, {"minted token", dbMinted}} {
		for _, place := range []string{"value", "member name", "listing"} {
			fields := dbPrincipalFields()
			if k.secret == dbPAT {
				fields = dbTokenFields()
			}
			s, _, c, _ := dbFixture(t, fields)
			body := dbSucceeded(`["` + dbEscaped(k.secret) + `"]`)
			q := dbStatementRead(c, "SELECT 1")
			switch place {
			case "member name":
				body = strings.Replace(dbSucceeded(`["1"]`), `{"statement_id"`, `{"`+dbEscaped(k.secret)+`":true,"statement_id"`, 1)
			case "listing":
				body = `{"catalogs":[{"name":"main","comment":"` + dbEscaped(k.secret) + `"}]}`
				q = DatabricksRequest{Connection: c.ID, Revision: c.Revision, Read: "catalog", List: "catalogs"}
			}
			p := dbThrough(func(r *http.Request) (*http.Response, error) {
				if r.URL.Path == "/oidc/v1/token" {
					return dbAnswer(r, 200, dbMintedAnswer), nil
				}
				return dbAnswer(r, 200, body), nil
			})
			out, err := databricksAcquire(context.Background(), s, q, p)
			if out != nil || err == nil || err.Error() != "provider-unavailable: the workspace's answer repeats the credential, and is not kept" {
				t.Errorf("%s in a %s: %v", k.name, place, err)
			}
		}
	}
}

// A failure's message has every whole credential replaced before it is cut
// to its bound, so a credential across the cut leaves nothing of itself;
// one written in escapes is replaced as decoded.
func TestDatabricksAFailureMessageIsRedactedBeforeItIsCut(t *testing.T) {
	for name, message := range map[string]string{
		"across the cut":   strings.Repeat("x", databricksMessageBytes-len(dbPAT)+1) + dbPAT,
		"past the cut":     strings.Repeat("y", databricksMessageBytes+1000) + dbPAT,
		"at the cut's end": strings.Repeat("z", databricksMessageBytes-len(dbPAT)) + dbPAT + strings.Repeat("z", 100),
	} {
		raw, _ := json.Marshal(map[string]any{"statement_id": dbStatement, "status": map[string]any{"state": "FAILED", "error": map[string]string{"message": message}}})
		_, err := databricksStatement(raw, 30, 0, []string{dbPAT})
		if err == nil || strings.Contains(err.Error(), dbPAT[:8]) {
			t.Fatalf("%s: %.80q", name, err)
		}
		if name == "across the cut" && !strings.HasSuffix(err.Error(), "[redacted]") {
			t.Errorf("%s: the credential was not replaced whole", name)
		}
		if name == "past the cut" && (!strings.HasSuffix(err.Error(), "…") || len(err.Error()) != len("statement-failed: ")+databricksMessageBytes+len("…")) {
			t.Errorf("%s: not cut to the bound after redaction: %d bytes", name, len(err.Error()))
		}
	}
	escaped := `{"statement_id":"` + dbStatement + `","status":{"state":"FAILED","error":{"message":"near ` + dbEscaped(dbPAT) + `"}}}`
	if _, err := databricksStatement([]byte(escaped), 30, 0, []string{dbPAT}); err == nil || err.Error() != "statement-failed: near [redacted]" {
		t.Fatal(err)
	}
}

// The members a statement's answer is decided by are read by their exact
// names: an answer that also names one in another case, by the decoder's
// folding of ASCII, of the long s or of the Kelvin sign, or twice, is
// refused, and nothing of it is kept.
func TestDatabricksTheMembersDecidedByAreReadByExactName(t *testing.T) {
	s, _, c, _ := dbFixture(t, dbTokenFields())
	malformed := "provider-unavailable: the workspace's answer is not of the form this connection reads, or names a member it reads twice"
	id := `"statement_id":"` + dbStatement + `"`
	for name, k := range map[string]struct{ body, want string }{
		"a success beside a capital that says otherwise": {`{` + id + `,"status":{"state":"SUCCEEDED","State":"RUNNING"}}`, malformed},
		"a state beside its capital":                     {`{` + id + `,"status":{"state":"RUNNING","State":"SUCCEEDED"}}`, malformed},
		"a state in capitals alone":                      {`{` + id + `,"status":{"STATE":"SUCCEEDED"}}`, malformed},
		"a state beside its long s":                      {`{` + id + `,"status":{"state":"RUNNING","ſtate":"SUCCEEDED"}}`, malformed},
		"a state twice":                                  {`{` + id + `,"status":{"state":"RUNNING","state":"SUCCEEDED"}}`, malformed},
		"truncated beside its capital":                   {`{` + id + `,"status":{"state":"SUCCEEDED"},"manifest":{"truncated":true,"Truncated":false,"total_chunk_count":1}}`, malformed},
		"a chunk count beside its capitals":              {`{` + id + `,"status":{"state":"SUCCEEDED"},"manifest":{"total_chunk_count":2,"TOTAL_CHUNK_COUNT":1}}`, malformed},
		"a chunk index beside a Kelvin sign":             {`{` + id + `,"status":{"state":"SUCCEEDED"},"result":{"chunk_index":1,"chun` + "K" + `_index":0}}`, malformed},
		"a chunk link in capitals":                       {`{` + id + `,"status":{"state":"SUCCEEDED"},"result":{"Next_Chunk_Internal_Link":"/next"}}`, malformed},
		"a message beside its capital":                   {`{` + id + `,"status":{"state":"FAILED","error":{"message":"one","Message":"two"}}}`, malformed},
		"a status beside its capital":                    {`{` + id + `,"status":{"state":"RUNNING"},"Status":{"state":"SUCCEEDED"}}`, malformed},
		"a statement id beside its capitals":             {`{` + id + `,"Statement_ID":"other","status":{"state":"SUCCEEDED"}}`, malformed},
		"truncated as text":                              {`{` + id + `,"status":{"state":"SUCCEEDED"},"manifest":{"truncated":"false"}}`, malformed},
		"a later chunk":                                  {`{` + id + `,"status":{"state":"SUCCEEDED"},"result":{"chunk_index":1,"data_array":[["1"]]}}`, "result-incomplete: the workspace answered part of the result, in chunks or truncated; the rest is not fetched"},
	} {
		calls := 0
		p := dbThrough(func(r *http.Request) (*http.Response, error) { calls++; return dbAnswer(r, 200, k.body), nil })
		out, err := databricksAcquire(context.Background(), s, dbStatementRead(c, "SELECT 1"), p)
		if out != nil || err == nil || err.Error() != k.want || calls != 1 {
			t.Errorf("%s: %v (%d requests)", name, err, calls)
		}
	}
	// A member the connection does not decide by is the answer's own.
	p := dbThrough(func(r *http.Request) (*http.Response, error) {
		return dbAnswer(r, 200, strings.Replace(dbSucceeded(`["1"]`), `"status":{`, `"Statement_Type":"QUERY","status":{"sql_state":null,`, 1)), nil
	})
	if _, err := databricksAcquire(context.Background(), s, dbStatementRead(c, "SELECT 1"), p); err != nil {
		t.Fatal(err)
	}
}

// A request that carries the connection's credential, in any field it
// would send, is refused before it is sent, in words that name the rule.
func TestDatabricksARequestCarryingTheCredentialIsNotSent(t *testing.T) {
	var mints, api atomic.Int32
	p := dbThrough(func(r *http.Request) (*http.Response, error) {
		if r.URL.Path == "/oidc/v1/token" {
			mints.Add(1)
			return dbAnswer(r, 200, dbMintedAnswer), nil
		}
		api.Add(1)
		return dbAnswer(r, 200, dbSucceeded(`["1"]`)), nil
	})
	refused := func(name string, s *Store, q DatabricksRequest, secret string) {
		t.Helper()
		before, minted := api.Load(), mints.Load()
		out, err := databricksAcquire(context.Background(), s, q, p)
		if out != nil || err != databricksInRequest || strings.Contains(err.Error(), secret) || api.Load() != before {
			t.Errorf("%s: %v, %d requests", name, err, api.Load()-before)
		}
		if secret != dbMinted && mints.Load() != minted {
			t.Errorf("%s: a token was asked for", name)
		}
	}
	value := dbPAT
	s, _, c, _ := dbFixture(t, dbTokenFields())
	listing := func(token, catalog, schema string) DatabricksRequest {
		return DatabricksRequest{Connection: c.ID, Revision: c.Revision, Read: "catalog", List: "tables", Catalog: catalog, Schema: schema, PageToken: token}
	}
	refused("the statement", s, dbStatementRead(c, "SELECT '"+dbPAT+"'"), dbPAT)
	q := dbStatementRead(c, "SELECT :v")
	q.Parameters = []DatabricksParameter{{Name: "v", Value: &value}}
	refused("a parameter's value", s, q, dbPAT)
	q = dbStatementRead(c, "SELECT 1")
	q.Catalog = dbPAT
	refused("the statement's catalog", s, q, dbPAT)
	refused("a listing's catalog", s, listing("", dbPAT, "sales"), dbPAT)
	refused("a listing's schema", s, listing("", "main", dbPAT), dbPAT)
	refused("a listing's cursor", s, listing("page-"+dbPAT, "main", "sales"), dbPAT)
	// A token of a parameter name's form, as a name and as a type.
	plain := "dapiABCDEF0123456789abcdef"
	fields := dbTokenFields()
	fields["token"] = plain
	ps, _, pc, _ := dbFixture(t, fields)
	q = dbStatementRead(pc, "SELECT 1")
	q.Parameters = []DatabricksParameter{{Name: plain, Value: &value}}
	refused("a parameter's name", ps, q, plain)
	q = dbStatementRead(pc, "SELECT :v")
	q.Parameters = []DatabricksParameter{{Name: "v", Type: plain}}
	refused("a parameter's type", ps, q, plain)
	// A token that a query string encodes is found in the cursor as given.
	fields = dbTokenFields()
	fields["token"] = "dapi&marker=0123456789"
	es, _, ec, _ := dbFixture(t, fields)
	refused("an encoded cursor", es, DatabricksRequest{Connection: ec.ID, Revision: ec.Revision, Read: "catalog", List: "catalogs", PageToken: "after-dapi&marker=0123456789"}, "dapi&marker=0123456789")
	// A default the operator configured is sent too. Configure now refuses
	// one that spells the credential (round 1 of #255), so this one is
	// written into custody by another hand.
	if _, b, _, _ := dbFixture(t, dbTokenFields()); dbConfigure(b, map[string]string{"id": "other", "name": "Other", "workspace-url": dbWorkspace, "warehouse-id": dbWarehouse, "auth": "token", "token": dbPAT, "catalog": dbPAT}) != ErrRequest {
		t.Fatal("configure took a catalog that spells the credential")
	}
	ds, _, dc, _ := dbFixture(t, dbTokenFields())
	ds.locked(func(v *state) error {
		v.Databricks.Connections[0].Catalog = dbPAT
		return ds.write("state.json", v)
	})
	refused("a configured catalog", ds, dbStatementRead(dc, "SELECT 1"), dbPAT)
	// A service principal: its secret before a token is asked for, the
	// token it holds before another is, and one minted now before the
	// request is sent.
	ss, _, sc, _ := dbFixture(t, dbPrincipalFields())
	refused("the client secret", ss, dbStatementRead(sc, "SELECT '"+dbSecret+"'"), dbSecret)
	refused("a token minted for it", ss, dbStatementRead(sc, "SELECT '"+dbMinted+"'"), dbMinted)
	if mints.Load() != 1 {
		t.Fatal("no token was minted", mints.Load())
	}
	if _, err := databricksAcquire(context.Background(), ss, dbStatementRead(sc, "SELECT 1"), p); err != nil {
		t.Fatal(err)
	}
	minted := mints.Load()
	refused("the token it holds", ss, dbStatementRead(sc, "SELECT '"+dbMinted+"'"), dbMinted)
	if mints.Load() != minted {
		t.Fatal("a token was asked for while one was held")
	}
}

// A token that would not outlast the minute's slack when it arrives -- its
// lifetime counted from the request -- is neither used nor kept, and no
// other is asked for.
func TestDatabricksATokenThatWouldNotOutlastItsSlackIsNotUsed(t *testing.T) {
	for _, k := range []struct {
		lifetime int
		delay    time.Duration
		ok       bool
	}{{1, 0, false}, {60, 0, false}, {61, 1500 * time.Millisecond, false}, {120, 0, true}} {
		s, _, c, dir := dbFixture(t, dbPrincipalFields())
		var mints, api atomic.Int32
		p := dbThrough(func(r *http.Request) (*http.Response, error) {
			if r.URL.Path == "/oidc/v1/token" {
				mints.Add(1)
				time.Sleep(k.delay)
				return dbAnswer(r, 200, fmt.Sprintf(`{"access_token":"%s","token_type":"Bearer","expires_in":%d}`, dbMinted, k.lifetime)), nil
			}
			api.Add(1)
			return dbAnswer(r, 200, dbSucceeded(`["1"]`)), nil
		})
		_, err := databricksAcquire(context.Background(), s, dbStatementRead(c, "SELECT 1"), p)
		if k.ok {
			if err != nil || api.Load() != 1 {
				t.Errorf("%d seconds: %v", k.lifetime, err)
			}
			continue
		}
		if err == nil || err.Error() != "token-failed: the workspace's token endpoint answered 200 with a token that expires within a minute of its arrival; it was not used" || api.Load() != 0 || mints.Load() != 1 {
			t.Errorf("%d seconds after %v: %v, %d requests, %d token requests", k.lifetime, k.delay, err, api.Load(), mints.Load())
		}
		if bytes.Contains(dbState(t, dir), []byte(dbMinted)) {
			t.Errorf("%d seconds: the token was kept", k.lifetime)
		}
	}
}

// The token endpoint's 429 names the wait it asks for, as a read's does,
// after one request.
func TestDatabricksATokenEndpoints429NamesItsWait(t *testing.T) {
	for _, k := range []struct {
		header, body, want string
	}{
		{"17", `{"error":"rate_limit"}`, "token-failed: the workspace's token endpoint answered 429 (rate_limit) and asks to wait 17 seconds before another request; it was not retried"},
		{"", `{"error_code":"RESOURCE_EXHAUSTED","details":[{"@type":"type.googleapis.com/google.rpc.RetryInfo","retry_delay":"2.5s"}]}`, "token-failed: the workspace's token endpoint answered 429 (RESOURCE_EXHAUSTED) and asks to wait 2.5 seconds before another request; it was not retried"},
		{dbSecret, `Too Many Requests`, "token-failed: the workspace's token endpoint answered 429; it was not retried"},
	} {
		s, _, c, _ := dbFixture(t, dbPrincipalFields())
		calls := 0
		p := dbThrough(func(r *http.Request) (*http.Response, error) {
			calls++
			a := dbAnswer(r, 429, k.body)
			if k.header != "" {
				a.Header.Set("Retry-After", k.header)
			}
			return a, nil
		})
		_, err := databricksAcquire(context.Background(), s, dbStatementRead(c, "SELECT 1"), p)
		if err == nil || err.Error() != k.want || calls != 1 {
			t.Errorf("%q: %v, %d requests", k.header, err, calls)
		}
	}
}

// The bound is held as the answer is read, before it is parsed: an answer
// whose length is announced past it is not read at all, and one that is
// not announced is read a byte past it and no further.
func TestDatabricksTheBoundIsHeldBeforeTheAnswerIsParsed(t *testing.T) {
	for _, announced := range []bool{true, false} {
		fields := dbTokenFields()
		fields["max-result-bytes"] = "65536"
		s, _, c, _ := dbFixture(t, fields)
		body := &dbCountedBody{left: 1 << 20}
		calls := 0
		p := dbThrough(func(r *http.Request) (*http.Response, error) {
			calls++
			a := dbAnswer(r, 200, "")
			a.Body, a.ContentLength = body, -1
			if announced {
				a.ContentLength = 1 << 20
			}
			return a, nil
		})
		out, err := databricksAcquire(context.Background(), s, dbStatementRead(c, "SELECT 1"), p)
		if out != nil || err == nil || !strings.HasPrefix(err.Error(), "result-too-large") || calls != 1 || body.read > 65537 || announced && body.read != 0 {
			t.Errorf("announced %v: %v, %d bytes read", announced, err, body.read)
		}
	}
}

type dbCountedBody struct{ left, read int }

func (b *dbCountedBody) Read(p []byte) (int, error) {
	if b.left == 0 {
		return 0, io.EOF
	}
	n := min(len(p), b.left)
	for i := range n {
		p[i] = 'x'
	}
	b.left -= n
	b.read += n
	return n, nil
}
func (b *dbCountedBody) Close() error { return nil }

// A listing's cursor is in the statement the gateway commits to, and its
// answer in the snapshot; a change of workspace drops the token minted for
// the earlier one, and another is minted.
func TestDatabricksTheCursorIsCommittedAndAWorkspaceChangeDropsTheToken(t *testing.T) {
	fields := dbTokenFields()
	fields["schema"] = "sales"
	s, _, c, _ := dbFixture(t, fields)
	answer := `{"tables":[],"next_page_token":"next"}`
	p := dbThrough(func(r *http.Request) (*http.Response, error) { return dbAnswer(r, 200, answer), nil })
	acquisition := func(q DatabricksRequest) map[string]any {
		t.Helper()
		out, err := databricksAcquire(context.Background(), s, q, p)
		if err != nil {
			t.Fatal(err)
		}
		var v map[string]map[string]any
		json.Unmarshal(out, &v)
		return v["acquisition"]
	}
	q := DatabricksRequest{Connection: c.ID, Revision: c.Revision, Read: "catalog", List: "tables"}
	first := acquisition(q)
	q.PageToken = "next"
	second := acquisition(q)
	answer = `{"tables":[{"name":"changed"}]}`
	third := acquisition(q)
	if first["statement"] == second["statement"] || second["statement"] != third["statement"] || second["snapshot"] == third["snapshot"] {
		t.Fatal("the cursor or the answer is not in the record")
	}
	ss, b, sc, dir := dbFixture(t, dbPrincipalFields())
	var mints atomic.Int32
	mint := dbThrough(func(r *http.Request) (*http.Response, error) {
		if r.URL.Path == "/oidc/v1/token" {
			mints.Add(1)
			return dbAnswer(r, 200, dbMintedAnswer), nil
		}
		return dbAnswer(r, 200, dbSucceeded(`["1"]`)), nil
	})
	if _, err := databricksAcquire(context.Background(), ss, dbStatementRead(sc, "SELECT 1"), mint); err != nil {
		t.Fatal(err)
	}
	moved := dbPrincipalFields()
	moved["workspace-url"], moved["revision"] = "https://other.cloud.databricks.com", sc.Revision
	if err := dbConfigure(b, moved); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(dbState(t, dir), []byte(dbMinted)) {
		t.Fatal("the token outlived its workspace")
	}
	sc = dbConnection(t, ss, sc.ID)
	if _, err := databricksAcquire(context.Background(), ss, dbStatementRead(sc, "SELECT 1"), mint); err != nil || mints.Load() != 2 {
		t.Fatal("a token was used across workspaces", err, mints.Load())
	}
}

// The fixes of the Azure DevOps provider's cross-vendor round (round 1 of
// #255) that land in what this provider shares with it, held here.

// Escapes nested past the old four passes are decoded to the end: a
// credential under them is found in a result, in a statement before it is
// sent, and in a failed statement's message, which is then not repeated.
func TestDatabricksEscapesNestedPastAnyPassBoundAreHeld(t *testing.T) {
	for _, k := range []struct {
		name   string
		fields map[string]string
		secret string
	}{{"personal access token", dbTokenFields(), dbPAT}, {"client secret", dbPrincipalFields(), dbSecret}, {"minted token", dbPrincipalFields(), dbMinted}} {
		s, _, c, _ := dbFixture(t, k.fields)
		for form, nested := range map[string]string{"the round's nesting": adoReviewNested(k.secret), "thirty levels": adoNested(k.secret, 30)} {
			quoted, _ := json.Marshal(nested)
			var api atomic.Int32
			answer := dbSucceeded(`[` + string(quoted) + `]`)
			p := dbThrough(func(r *http.Request) (*http.Response, error) {
				if r.URL.Path == "/oidc/v1/token" {
					return dbAnswer(r, 200, dbMintedAnswer), nil
				}
				api.Add(1)
				return dbAnswer(r, 200, answer), nil
			})
			if out, err := databricksAcquire(context.Background(), s, dbStatementRead(c, "SELECT 1"), p); out != nil || err == nil || err.Error() != "provider-unavailable: the workspace's answer repeats the credential, and is not kept" {
				t.Errorf("%s under %s in a result: %v", k.name, form, err)
			}
			before := api.Load()
			if out, err := databricksAcquire(context.Background(), s, dbStatementRead(c, "SELECT '"+nested+"'"), p); out != nil || err != databricksInRequest || api.Load() != before {
				t.Errorf("%s under %s in a statement: %v", k.name, form, err)
			}
			message, _ := json.Marshal("near " + nested)
			answer = `{"statement_id":"` + dbStatement + `","status":{"state":"FAILED","error":{"error_code":"BAD_REQUEST","message":` + string(message) + `}}}`
			if _, err := databricksAcquire(context.Background(), s, dbStatementRead(c, "SELECT 1"), p); err == nil || err.Error() != "statement-failed: the workspace's message repeats the credential, and is not reported" {
				t.Errorf("%s under %s in a failure's message: %.120q", k.name, form, err)
			}
		}
	}
}

// Every credential custody holds for the provider is held out of every other
// connection's text, statements and results: connection A's personal access
// token, client secret or held token is refused in connection B's name, in
// B's statement and in B's answer, and status does not repeat it.
func TestDatabricksEveryCredentialCustodyHoldsIsHeldOut(t *testing.T) {
	for _, k := range []struct {
		name   string
		fields map[string]string
		secret string
	}{{"personal access token", dbTokenFields(), dbPAT}, {"client secret", dbPrincipalFields(), dbSecret}, {"held token", dbPrincipalFields(), dbMinted}} {
		s, b, a, dir := dbFixture(t, k.fields)
		if k.secret == dbMinted {
			s.locked(func(v *state) error {
				v.Databricks.Tokens = []databricksToken{{a.ID, a.Revision, dbMinted, time.Now().Add(time.Hour).Unix()}}
				return s.write("state.json", v)
			})
		}
		other := map[string]string{"id": "second", "name": "Second " + k.secret, "workspace-url": dbWorkspace, "warehouse-id": dbWarehouse, "auth": "token", "token": "dapi-other-synthetic-0000"}
		if err := dbConfigure(b, other); err != ErrRequest || bytes.Contains(dbState(t, dir), []byte(`"second"`)) {
			t.Errorf("%s as another connection's name: %v", k.name, err)
		}
		other["name"] = "Second"
		if err := dbConfigure(b, other); err != nil {
			t.Fatal(err)
		}
		c := dbConnection(t, s, "second")
		var api atomic.Int32
		p := dbThrough(func(r *http.Request) (*http.Response, error) {
			api.Add(1)
			return dbAnswer(r, 200, dbSucceeded(`["`+k.secret+`"]`)), nil
		})
		if out, err := databricksAcquire(context.Background(), s, dbStatementRead(c, "SELECT '"+k.secret+"'"), p); out != nil || err != databricksInRequest || api.Load() != 0 {
			t.Errorf("%s in another connection's statement: %v, %d requests", k.name, err, api.Load())
		}
		if out, err := databricksAcquire(context.Background(), s, dbStatementRead(c, "SELECT 1"), p); out != nil || err == nil || err.Error() != "provider-unavailable: the workspace's answer repeats the credential, and is not kept" {
			t.Errorf("%s in another connection's answer: %v", k.name, err)
		}
		status, err := b.Handle(context.Background(), "status", []byte(`{}`))
		raw, _ := json.Marshal(status)
		if err != nil || bytes.Contains(raw, []byte(k.secret)) {
			t.Errorf("%s in status: %s %v", k.name, raw, err)
		}
	}
}

// The bound is held to the bytes received: compression is neither asked for
// nor undone, an answer announced past the bound is refused unread, and one
// that names an encoding is refused.
func TestDatabricksTheBoundIsOnTheBytesReceived(t *testing.T) {
	var padded, small bytes.Buffer
	for range 3000 {
		z := gzip.NewWriter(&padded)
		z.Close()
	}
	for _, buffer := range []*bytes.Buffer{&padded, &small} {
		z := gzip.NewWriter(buffer)
		z.Write([]byte(dbSucceeded(`["1"]`)))
		z.Close()
	}
	for _, k := range []struct {
		entity *bytes.Buffer
		want   string
	}{
		{&padded, "result-too-large: the workspace's answer is larger than the connection's bound of 65536 bytes"},
		{&small, "provider-unavailable: the workspace's answer is encoded, and this connection reads only what it asked for, which is not"},
	} {
		p := databricksProvider()
		transport := p.client.Transport.(*http.Transport)
		var asked string
		transport.DialTLSContext = func(context.Context, string, string) (net.Conn, error) {
			client, server := net.Pipe()
			go func() {
				defer server.Close()
				req, err := http.ReadRequest(bufio.NewReader(server))
				if err != nil {
					return
				}
				asked = req.Header.Get("Accept-Encoding")
				req.Body.Close()
				fmt.Fprintf(server, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Encoding: gzip\r\nContent-Length: %d\r\nConnection: close\r\n\r\n", k.entity.Len())
				server.Write(k.entity.Bytes())
			}()
			return client, nil
		}
		response, body, err := p.databricksSend(context.Background(), "GET", dbWorkspace+"/api/2.1/unity-catalog/catalogs?max_results=0", nil, dbPAT, 65536, []string{dbPAT}, 30)
		transport.CloseIdleConnections()
		if response != nil || body != nil || err == nil || err.Error() != k.want || asked != "" {
			t.Errorf("%d-byte entity: %v, Accept-Encoding %q", k.entity.Len(), err, asked)
		}
	}
}

// A control answer whose fixed words would spell a credential is not
// written.
func TestDatabricksFixedWordsAreScreenedToo(t *testing.T) {
	fields := dbTokenFields()
	fields["token"] = "defaultWaitSeconds"
	_, b, _, _ := dbFixture(t, fields)
	if out, err := b.Handle(context.Background(), "status", []byte(`{}`)); out != nil || err != unwritten {
		raw, _ := json.Marshal(out)
		t.Fatalf("status %s %v", raw, err)
	}
}
