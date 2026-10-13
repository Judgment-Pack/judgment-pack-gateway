//go:build linux || darwin

package connections

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
)

// The safeguards the Databricks provider's review rounds asked of a
// provider, held here from the start, by tests that answer in process.

// adoThrough is the connection's own provider, its redirect rule and
// timeouts included, with a transport that answers in process.
func adoThrough(answer func(r *http.Request) (*http.Response, error)) provider {
	p := azureDevOpsProvider()
	p.client = &http.Client{Transport: testTransportFunc(answer), CheckRedirect: p.client.CheckRedirect, Timeout: p.client.Timeout}
	return p
}

// adoAnswer is an answer under a verified peer certificate of the test's
// own, named by certificate.
func adoAnswer(r *http.Request, status int, body, certificate string) *http.Response {
	leaf := &x509.Certificate{Raw: []byte(certificate)}
	return &http.Response{StatusCode: status, Header: http.Header{"Content-Type": {"application/json"}}, Body: io.NopCloser(strings.NewReader(body)), ContentLength: int64(len(body)), Request: r,
		TLS: &tls.ConnectionState{PeerCertificates: []*x509.Certificate{leaf}, VerifiedChains: [][]*x509.Certificate{{leaf}}}}
}

// adoSecrets is each secret a connection of fields holds, by name.
func adoSecrets(fields map[string]string) map[string]string {
	if fields["auth"] == "bearer" {
		return map[string]string{"access token": adoBearer}
	}
	return map[string]string{"personal access token": adoPAT, "basic value": adoBasic}
}

// A credential the answer spells in escapes is found as decoded -- in a
// value, a member name, or a string that is itself JSON -- in a single
// read's answer and in either answer of a query-and-get, and nothing of the
// answer is read or kept: the first answer's is refused before its ids are
// read, and nothing more is asked.
func TestAzureDevOpsAnEscapedCredentialInAnAnswerIsRefused(t *testing.T) {
	for _, fields := range []map[string]string{adoTokenFields(), adoBearerFields()} {
		s, _, c, _ := adoFixture(t, fields)
		for name, secret := range adoSecrets(fields) {
			for place, carrying := range map[string]string{
				"a value":       `{"count":1,"value":[{"id":12,"name":"` + adoEscaped(secret) + `"}],"workItems":[{"id":12}]}`,
				"a member name": `{"count":1,"value":[{"id":12,"` + adoEscaped(secret) + `":true}],"workItems":[{"id":12}]}`,
				"a JSON string": `{"count":1,"value":[{"id":12,"note":"{\"inner\":\"` + strings.ReplaceAll(adoEscaped(secret), `\`, `\\`) + `\"}"}],"workItems":[{"id":12}]}`,
			} {
				for _, k := range []struct {
					read     string
					which    string
					requests int
				}{{"repos.list", "", 1}, {"workitems.query-and-get", "first", 1}, {"workitems.query-and-get", "second", 2}} {
					calls := 0
					p := adoThrough(func(r *http.Request) (*http.Response, error) {
						calls++
						if k.which == "second" && strings.HasSuffix(r.URL.Path, "/wiql") {
							return adoAnswer(r, 200, `{"queryResultType":"workItem","workItems":[{"id":12}]}`, "peer"), nil
						}
						return adoAnswer(r, 200, carrying, "peer"), nil
					})
					q := AzureDevOpsRequest{Connection: c.ID, Revision: c.Revision, Read: k.read}
					if k.read != "repos.list" {
						q.Query = "SELECT [System.Id] FROM WorkItems"
					}
					out, err := azureDevOpsAcquire(context.Background(), s, q, p)
					if out != nil || err != azureDevOpsRepeats || calls != k.requests {
						t.Errorf("%s in %s, %s %s: %v, %d requests", name, place, k.read, k.which, err, calls)
					}
				}
			}
		}
	}
}

// A request that carries the connection's credential, in anything it would
// send, as written or in escapes, is refused before it is sent, in words that
// name the rule and not the value.
func TestAzureDevOpsARequestCarryingTheCredentialIsNotSent(t *testing.T) {
	for _, fields := range []map[string]string{adoTokenFields(), adoBearerFields()} {
		s, _, c, _ := adoFixture(t, fields)
		calls := 0
		p := adoThrough(func(r *http.Request) (*http.Response, error) {
			calls++
			return adoAnswer(r, 200, `{"count":0,"value":[]}`, "peer"), nil
		})
		for name, secret := range adoSecrets(fields) {
			for place, q := range map[string]AzureDevOpsRequest{
				"the query":           {Read: "workitems.query", Query: "SELECT [System.Id] FROM WorkItems WHERE [System.Title] = '" + secret + "'"},
				"the query, escaped":  {Read: "workitems.query", Query: "SELECT [System.Id] FROM WorkItems WHERE [System.Title] = '" + adoEscaped(secret) + "'"},
				"a query-and-get":     {Read: "workitems.query-and-get", Query: "SELECT '" + secret + "'"},
				"a field":             {Read: "workitems.get", ID: 1, Fields: []string{"Custom." + secret}},
				"the repository":      {Read: "repos.commits", Repository: secret},
				"a path":              {Read: "repos.items", Repository: "example-repo", Path: "/docs/" + secret},
				"a commits path":      {Read: "repos.commits", Repository: "example-repo", Path: "/" + secret},
				"a branch":            {Read: "repos.items", Repository: "example-repo", Version: "topic/" + secret},
				"the cursor":          {Read: "pipelines.list", Cursor: "after-" + secret},
				"the cursor, escaped": {Read: "pipelines.list", Cursor: "after-" + strings.ReplaceAll(adoEscaped(secret), " ", "")},
			} {
				// A field or a branch can only take a credential of its own
				// form; one that is not is refused by its form, before this.
				if _, err := q.check(); err != nil {
					if !strings.Contains(name, "basic") {
						t.Errorf("%s in %s: refused by its form: %v", name, place, err)
					}
					continue
				}
				q.Connection, q.Revision = c.ID, c.Revision
				before := calls
				out, err := azureDevOpsAcquire(context.Background(), s, q, p)
				if out != nil || err != azureDevOpsInRequest || strings.Contains(err.Error(), secret) || calls != before {
					t.Errorf("%s in %s: %v, %d requests", name, place, err, calls-before)
				}
			}
		}
	}
}

// The members a read is decided by are read by their exact names: a query's
// answer or the items' answer that also names one of them in another case --
// by ASCII, by the long s or the Kelvin sign -- or twice, is refused, and
// nothing is asked after a query's answer that is; a member the connection
// does not decide by is the answer's own.
func TestAzureDevOpsTheMembersDecidedByAreReadByExactName(t *testing.T) {
	s, _, c, _ := adoFixture(t, adoTokenFields())
	query := "provider-unavailable: the organization's query answer is not of the form this connection reads, or names a member it reads in another case or twice"
	items := "provider-unavailable: the organization's work items answer is not of the form this connection reads, names a member it reads in another case or twice, or names an item that was not asked for"
	flat := `{"queryResultType":"workItem","workItems":[{"id":12}]}`
	good := `{"count":1,"value":[{"id":12,"fields":{}}]}`
	for name, k := range map[string]struct {
		first, second, want string
		requests            int
	}{
		"items beside their capital":          {`{"workItems":[{"id":12}],"WorkItems":[{"id":99}]}`, good, query, 1},
		"items in capitals alone":             {`{"WORKITEMS":[{"id":99}]}`, good, query, 1},
		"items beside a long s":               {`{"workItems":[{"id":12}],"workItemſ":[{"id":99}]}`, good, query, 1},
		"a result type beside its capital":    {`{"queryResultType":"workItem","QueryResultType":"workItemLink","workItems":[{"id":12}]}`, good, query, 1},
		"relations beside a capital":          {`{"workItems":[{"id":12}],"WorkItemRelations":[]}`, good, query, 1},
		"an id beside its capital":            {`{"workItems":[{"id":12,"ID":99}]}`, good, query, 1},
		"items beside a Kelvin sign":          {`{"workItems":[{"id":12}],"wor` + "\u212a" + `Items":[{"id":99}]}`, good, query, 1},
		"an id twice":                         {`{"workItems":[{"id":12,"id":99}]}`, good, query, 1},
		"items twice":                         {`{"workItems":[{"id":12}],"workItems":[{"id":99}]}`, good, query, 1},
		"an id as text":                       {`{"workItems":[{"id":"12"}]}`, good, query, 1},
		"an id with a fraction":               {`{"workItems":[{"id":12.5}]}`, good, query, 1},
		"an id past int32":                    {`{"workItems":[{"id":2147483648}]}`, good, query, 1},
		"an id of 0":                          {`{"workItems":[{"id":0}]}`, good, query, 1},
		"an id twice in the list":             {`{"workItems":[{"id":12},{"id":12}]}`, good, query, 1},
		"items not a list":                    {`{"workItems":{"id":12}}`, good, query, 1},
		"not an object":                       {`[{"id":12}]`, good, query, 1},
		"the items' value beside its capital": {flat, `{"value":[{"id":12}],"Value":[{"id":99}]}`, items, 2},
		"an item's id beside its capitals":    {flat, `{"value":[{"id":12,"ID":99}]}`, items, 2},
		"an item's id in capitals alone":      {flat, `{"value":[{"ID":12}]}`, items, 2},
		"the items' value twice":              {flat, `{"value":[{"id":12}],"value":[{"id":99}]}`, items, 2},
	} {
		calls := 0
		p := adoThrough(func(r *http.Request) (*http.Response, error) {
			calls++
			if strings.HasSuffix(r.URL.Path, "/wiql") {
				return adoAnswer(r, 200, k.first, "peer"), nil
			}
			return adoAnswer(r, 200, k.second, "peer"), nil
		})
		out, err := azureDevOpsAcquire(context.Background(), s, AzureDevOpsRequest{Connection: c.ID, Revision: c.Revision, Read: "workitems.query-and-get", Query: "SELECT [System.Id] FROM WorkItems"}, p)
		if out != nil || err == nil || err.Error() != k.want || calls != k.requests {
			t.Errorf("%s: %v (%d requests)", name, err, calls)
		}
	}
	// Members the connection does not decide by are the answer's own.
	p := adoThrough(func(r *http.Request) (*http.Response, error) {
		if strings.HasSuffix(r.URL.Path, "/wiql") {
			return adoAnswer(r, 200, `{"QueryType":"flat","workItems":[{"id":12,"URL":"x"}],"Columns":[]}`, "peer"), nil
		}
		return adoAnswer(r, 200, `{"Count":1,"value":[{"id":12,"Fields":{},"REV":1}]}`, "peer"), nil
	})
	if _, err := azureDevOpsAcquire(context.Background(), s, AzureDevOpsRequest{Connection: c.ID, Revision: c.Revision, Read: "workitems.query-and-get", Query: "SELECT [System.Id] FROM WorkItems"}, p); err != nil {
		t.Fatal(err)
	}
	// An error type named beside its capital is not named.
	refusing := adoThrough(func(r *http.Request) (*http.Response, error) {
		return adoAnswer(r, 401, `{"typeKey":"UnauthorizedRequestException","TypeKey":"OtherException"}`, "peer"), nil
	})
	if _, err := azureDevOpsAcquire(context.Background(), s, AzureDevOpsRequest{Connection: c.ID, Revision: c.Revision, Read: "repos.list"}, refusing); err == nil || err.Error() != "credentials-required: the organization answered 401" {
		t.Fatal(err)
	}
}

// A threshold the organization names has every whole credential replaced
// before it is cut to its bound, so a credential across the cut leaves
// nothing of itself.
func TestAzureDevOpsARefusalIsRedactedBeforeItIsCut(t *testing.T) {
	for _, fields := range []map[string]string{adoTokenFields(), adoBearerFields()} {
		s, _, c, _ := adoFixture(t, fields)
		for name, secret := range adoSecrets(fields) {
			for place, resource := range map[string]string{
				"across the cut":   strings.Repeat("x", azureDevOpsResourceBytes-len(secret)+1) + secret,
				"at the cut's end": strings.Repeat("z", azureDevOpsResourceBytes-len(secret)) + secret + strings.Repeat("z", 100),
				"past the cut":     strings.Repeat("y", azureDevOpsResourceBytes+100) + secret,
			} {
				p := adoThrough(func(r *http.Request) (*http.Response, error) {
					a := adoAnswer(r, 429, ``, "peer")
					a.Header.Set("Retry-After", "5")
					a.Header.Set("X-RateLimit-Resource", resource)
					return a, nil
				})
				_, err := azureDevOpsAcquire(context.Background(), s, AzureDevOpsRequest{Connection: c.ID, Revision: c.Revision, Read: "repos.list"}, p)
				if err == nil || !strings.HasPrefix(err.Error(), "rate-limited: the organization answered 429 and asks to wait 5 seconds before another request (threshold: ") || strings.Contains(err.Error(), secret[:8]) {
					t.Errorf("%s %s: %.120q", name, place, err)
					continue
				}
				if place == "across the cut" && !strings.Contains(err.Error(), "[redacted])") {
					t.Errorf("%s %s: the credential was not replaced whole: %q", name, place, err)
				}
				if place == "past the cut" && !strings.Contains(err.Error(), strings.Repeat("y", azureDevOpsResourceBytes)+"…)") {
					t.Errorf("%s %s: not cut to the bound after redaction", name, place)
				}
			}
		}
	}
}

// Configure refuses a connection whose own text -- its name or its project --
// carries its credential, as written or in escapes, and keeps nothing of it.
func TestAzureDevOpsConfigureRefusesACredentialInItsOwnText(t *testing.T) {
	for _, fields := range []map[string]string{adoTokenFields(), adoBearerFields()} {
		_, b, _, dir := adoFixture(t, fields)
		for name, secret := range adoSecrets(fields) {
			for place, change := range map[string]map[string]string{
				"the name":           {"name": "Board " + secret},
				"the name, escaped":  {"name": "Board " + adoEscaped(secret)},
				"the project":        {"project": "p-" + secret},
				"the project, cased": {"project": secret},
			} {
				changed := map[string]string{}
				for k, v := range fields {
					changed[k] = v
				}
				changed["id"] = "other"
				for k, v := range change {
					changed[k] = v
				}
				// A basic value is not of a project's form: its slash or its
				// plus refuses it there before its credential does.
				err := adoConfigure(b, changed)
				if err != azureDevOpsInConfiguration && !(err == ErrRequest && strings.Contains(place, "project") && strings.ContainsAny(secret, "/+=")) {
					t.Errorf("%s in %s: %v", name, place, err)
				}
				if bytes.Contains(adoState(t, dir), []byte(`"other"`)) {
					t.Errorf("%s in %s: kept", name, place)
				}
			}
		}
	}
}

// Every text the connection writes out is held once more against the
// credential: an error that would name it (an organization giving it as its
// error type) has it replaced, for a read and a test; a status row whose own
// text would spell it is reported with that text replaced and not ready; and
// a sentence that would still spell it in escapes is not reported.
func TestAzureDevOpsEveryOutgoingTextIsScreened(t *testing.T) {
	for _, fields := range []map[string]string{adoTokenFields(), adoBearerFields()} {
		s, b, c, _ := adoFixture(t, fields)
		for name, secret := range adoSecrets(fields) {
			if strings.ContainsAny(secret, "+/=") {
				continue // not of an error type's form, and never named
			}
			p := adoThrough(func(r *http.Request) (*http.Response, error) {
				return adoAnswer(r, 401, `{"typeKey":"`+secret+`"}`, "peer"), nil
			})
			b.provider = p
			_, err := azureDevOpsAcquire(context.Background(), s, AzureDevOpsRequest{Connection: c.ID, Revision: c.Revision, Read: "repos.list"}, p)
			_, testErr := b.Handle(context.Background(), "test", []byte(`{"id":"board","revision":"`+c.Revision+`"}`))
			for _, e := range []error{err, testErr} {
				if e == nil || e.Error() != "credentials-required: the organization answered 401 ([redacted])" {
					t.Errorf("%s: %v", name, e)
				}
			}
		}
		// A row written into custody by another hand, its name spelling the
		// credential.
		s.locked(func(v *state) error {
			secret := adoPAT
			if fields["auth"] == "bearer" {
				secret = adoBearer
			}
			v.AzureDevOps.Connections[0].Name = "Board " + secret
			return s.write("state.json", v)
		})
		status, err := b.Handle(context.Background(), "status", []byte(`{}`))
		raw, _ := json.Marshal(status)
		if err != nil || !bytes.Contains(raw, []byte(`"name":"[redacted]"`)) || !bytes.Contains(raw, []byte(`"ready":false`)) || bytes.Contains(raw, []byte(adoPAT)) || bytes.Contains(raw, []byte(adoBearer)) {
			t.Errorf("status %s %v", raw, err)
		}
		secrets := adoConnection(t, s, "board").secrets()
		if got := azureDevOpsOutward(Error("request-refused: near "+adoEscaped(secrets[len(secrets)-1])), secrets); got.Error() != "provider-unavailable: the organization's refusal would repeat the credential, and is not reported" {
			t.Errorf("an escaped sentence: %v", got)
		}
	}
}

// The bound is held as the answer is read, before it is parsed: an answer
// whose length is announced past it is not read at all, and one that is not
// announced is read a byte past it and no further.
func TestAzureDevOpsTheBoundIsHeldBeforeTheAnswerIsParsed(t *testing.T) {
	for _, announced := range []bool{true, false} {
		fields := adoTokenFields()
		fields["max-result-bytes"] = "65536"
		s, _, c, _ := adoFixture(t, fields)
		body := &dbCountedBody{left: 1 << 20}
		calls := 0
		p := adoThrough(func(r *http.Request) (*http.Response, error) {
			calls++
			a := adoAnswer(r, 200, "", "peer")
			a.Body, a.ContentLength = body, -1
			if announced {
				a.ContentLength = 1 << 20
			}
			return a, nil
		})
		out, err := azureDevOpsAcquire(context.Background(), s, AzureDevOpsRequest{Connection: c.ID, Revision: c.Revision, Read: "repos.list"}, p)
		if out != nil || err == nil || !strings.HasPrefix(err.Error(), "result-too-large") || calls != 1 || body.read > 65537 || announced && body.read != 0 {
			t.Errorf("announced %v: %v, %d bytes read", announced, err, body.read)
		}
	}
}

// The two answers of a query-and-get come from one organization under one
// TLS identity, which the record names; answers under two are not kept.
func TestAzureDevOpsTheTwoAnswersComeUnderOneTLSIdentity(t *testing.T) {
	s, _, c, _ := adoFixture(t, adoTokenFields())
	for _, k := range []struct {
		second string
		ok     bool
	}{{"the organization's certificate", true}, {"another certificate", false}} {
		p := adoThrough(func(r *http.Request) (*http.Response, error) {
			if strings.HasSuffix(r.URL.Path, "/wiql") {
				return adoAnswer(r, 200, adoWIQL, "the organization's certificate"), nil
			}
			return adoAnswer(r, 200, adoItems, k.second), nil
		})
		out, err := azureDevOpsAcquire(context.Background(), s, AzureDevOpsRequest{Connection: c.ID, Revision: c.Revision, Read: "workitems.query-and-get", Query: "SELECT [System.Id] FROM WorkItems"}, p)
		if !k.ok {
			if out != nil || err == nil || err.Error() != "provider-unavailable: the organization's two answers came under different TLS identities, and neither is kept" {
				t.Errorf("%s: %v", k.second, err)
			}
			continue
		}
		var v struct{ Acquisition struct{ PeerIdentity string } }
		json.Unmarshal(out, &v)
		sum := sha256.Sum256([]byte(k.second))
		if err != nil || v.Acquisition.PeerIdentity != "tls:sha256:"+hex.EncodeToString(sum[:]) {
			t.Errorf("%s: %v %s", k.second, err, v.Acquisition.PeerIdentity)
		}
	}
}
