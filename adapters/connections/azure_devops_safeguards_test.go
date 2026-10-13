//go:build linux || darwin

package connections

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"
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

// The cross-vendor round's probes (round 1, at 5f451bd), adopted as
// regressions: each asserted a defect, and now asserts its fix.

// adoNested hides each character of s under levels of escapes, as a reader
// decoding the text level by level would find it: \ spelling the
// backslash of the next level, each level costing five bytes.
func adoNested(s string, levels int) string {
	var b strings.Builder
	for _, r := range s {
		b.WriteString(`\`)
		b.WriteString(strings.Repeat("u005c", levels))
		fmt.Fprintf(&b, "u%04x", r)
	}
	return b.String()
}

// adoReviewNested is the round's own nesting: the escaped secret with every
// backslash written as \, eight times over.
func adoReviewNested(secret string) string {
	text := adoEscaped(secret)
	for range 8 {
		text = strings.ReplaceAll(text, `\`, `\`)
	}
	return text
}

// A test is held to a read's screens: a request that would carry a
// credential is not sent, and an answer that repeats one, in escapes, is
// refused; the test answers not ok.
func TestAzureDevOpsATestIsScreenedAsAReadIs(t *testing.T) {
	fields := adoTokenFields()
	fields["token"] = "System.Id"
	s, b, c, _ := adoFixture(t, fields)
	calls := 0
	b.provider = adoThrough(func(r *http.Request) (*http.Response, error) {
		calls++
		return adoAnswer(r, 200, `{"workItems":[]}`, "peer"), nil
	})
	answer, err := b.Handle(context.Background(), "test", []byte(`{"id":"board","revision":"`+c.Revision+`"}`))
	if err != azureDevOpsInRequest || calls != 0 || answer.(map[string]bool)["ok"] {
		t.Fatalf("a test carrying the credential: %v %v, %d requests", answer, err, calls)
	}
	if out, err := azureDevOpsAcquire(context.Background(), s, AzureDevOpsRequest{Connection: c.ID, Revision: c.Revision, Read: "workitems.query", Query: azureDevOpsTestQuery, Top: 1}, b.provider); out != nil || err != azureDevOpsInRequest {
		t.Fatal("the read the test makes was not refused", err)
	}
	for _, fields := range []map[string]string{adoTokenFields(), adoBearerFields()} {
		_, b, c, _ := adoFixture(t, fields)
		for name, secret := range adoSecrets(fields) {
			for form, echo := range map[string]string{"escaped": adoEscaped(secret), "nested": adoReviewNested(secret)} {
				b.provider = adoThrough(func(r *http.Request) (*http.Response, error) {
					return adoAnswer(r, 200, `{"workItems":[],"echo":"`+echo+`"}`, "peer"), nil
				})
				answer, err := b.Handle(context.Background(), "test", []byte(`{"id":"board","revision":"`+c.Revision+`"}`))
				if err != azureDevOpsRepeats || answer.(map[string]bool)["ok"] {
					t.Errorf("%s %s in a test's answer: %v %v", form, name, answer, err)
				}
			}
		}
	}
}

// Every credential custody holds for the provider is held out of every other
// connection's text, requests and results: connection A's token, its basic
// value or its access token is refused as connection B's name, in B's query,
// and in B's answer.
func TestAzureDevOpsEveryCredentialCustodyHoldsIsHeldOut(t *testing.T) {
	for _, fields := range []map[string]string{adoTokenFields(), adoBearerFields()} {
		for name, secret := range adoSecrets(fields) {
			s, b, _, dir := adoFixture(t, fields)
			other := adoTokenFields()
			other["id"], other["name"], other["token"] = "second", "Board "+secret, "OtherSyntheticPAT987654321"
			if err := adoConfigure(b, other); err != azureDevOpsInConfiguration || bytes.Contains(adoState(t, dir), []byte(`"second"`)) {
				t.Errorf("%s as another connection's name: %v", name, err)
			}
			other["name"] = "Second"
			if err := adoConfigure(b, other); err != nil {
				t.Fatal(err)
			}
			c := adoConnection(t, s, "second")
			calls := 0
			p := adoThrough(func(r *http.Request) (*http.Response, error) {
				calls++
				return adoAnswer(r, 200, `{"count":1,"value":[{"echo":"`+secret+`"}]}`, "peer"), nil
			})
			if out, err := azureDevOpsAcquire(context.Background(), s, AzureDevOpsRequest{Connection: c.ID, Revision: c.Revision, Read: "workitems.query", Query: "SELECT '" + secret + "'"}, p); out != nil || err != azureDevOpsInRequest || calls != 0 {
				t.Errorf("%s in another connection's query: %v, %d requests", name, err, calls)
			}
			if out, err := azureDevOpsAcquire(context.Background(), s, AzureDevOpsRequest{Connection: c.ID, Revision: c.Revision, Read: "repos.list"}, p); out != nil || err != azureDevOpsRepeats {
				t.Errorf("%s in another connection's answer: %v", name, err)
			}
			status, err := b.Handle(context.Background(), "status", []byte(`{}`))
			raw, _ := json.Marshal(status)
			if err != nil || bytes.Contains(raw, []byte(secret)) {
				t.Errorf("%s in status: %s %v", name, raw, err)
			}
		}
	}
}

// Escapes nested past the old four passes are decoded to the end: a
// credential under them is found in an answer, in a query and in an error's
// threshold, and the threshold is not named.
func TestAzureDevOpsEscapesNestedPastAnyPassBoundAreHeld(t *testing.T) {
	for _, fields := range []map[string]string{adoTokenFields(), adoBearerFields()} {
		s, _, c, _ := adoFixture(t, fields)
		for name, secret := range adoSecrets(fields) {
			for form, nested := range map[string]string{"the round's nesting": adoReviewNested(secret), "five levels": adoNested(secret, 5), "thirty levels": adoNested(secret, 30)} {
				answer, _ := json.Marshal(map[string]string{"echo": nested})
				calls := 0
				p := adoThrough(func(r *http.Request) (*http.Response, error) {
					calls++
					return adoAnswer(r, 200, string(answer), "peer"), nil
				})
				if out, err := azureDevOpsAcquire(context.Background(), s, AzureDevOpsRequest{Connection: c.ID, Revision: c.Revision, Read: "repos.list"}, p); out != nil || err != azureDevOpsRepeats {
					t.Errorf("%s under %s in an answer: %v", name, form, err)
				}
				before := calls
				if out, err := azureDevOpsAcquire(context.Background(), s, AzureDevOpsRequest{Connection: c.ID, Revision: c.Revision, Read: "workitems.query", Query: "SELECT '" + nested + "'"}, p); out != nil || err != azureDevOpsInRequest || calls != before {
					t.Errorf("%s under %s in a query: %v", name, form, err)
				}
				refusing := adoThrough(func(r *http.Request) (*http.Response, error) {
					a := adoAnswer(r, 429, ``, "peer")
					a.Header.Set("X-RateLimit-Resource", nested)
					return a, nil
				})
				if _, err := azureDevOpsAcquire(context.Background(), s, AzureDevOpsRequest{Connection: c.ID, Revision: c.Revision, Read: "repos.list"}, refusing); err == nil || err.Error() != "rate-limited: the organization answered 429; it was not retried" {
					t.Errorf("%s under %s in a threshold: %.120q", name, form, err)
				}
			}
		}
	}
}

// An access token is held to its expiry immediately before every request: a
// query-and-get whose second request would go within the minute is refused,
// and nothing of it is kept.
func TestAzureDevOpsTheBearerIsCheckedBeforeEverySend(t *testing.T) {
	fields := adoBearerFields()
	fields["expires-at"] = time.Now().Add(62 * time.Second).UTC().Format(time.RFC3339)
	s, _, c, _ := adoFixture(t, fields)
	calls := 0
	p := adoThrough(func(r *http.Request) (*http.Response, error) {
		calls++
		time.Sleep(2500 * time.Millisecond)
		return adoAnswer(r, 200, `{"workItems":[{"id":12}]}`, "peer"), nil
	})
	out, err := azureDevOpsAcquire(context.Background(), s, AzureDevOpsRequest{Connection: c.ID, Revision: c.Revision, Read: "workitems.query-and-get", Query: "SELECT [System.Id] FROM WorkItems"}, p)
	if out != nil || err != azureDevOpsExpired || calls != 1 {
		t.Fatalf("%v, %d requests", err, calls)
	}
}

// The statement commits the second request as it was sent, so two reads of
// one query that read different items commit differently; and the record
// names the URL the snapshot's answer came from, query and all.
func TestAzureDevOpsTheStatementCommitsTheSecondRequest(t *testing.T) {
	s, _, c, _ := adoFixture(t, adoTokenFields())
	statements := []string{}
	for _, id := range []int{12, 99} {
		urls := []string{}
		p := adoThrough(func(r *http.Request) (*http.Response, error) {
			urls = append(urls, r.URL.String())
			body := fmt.Sprintf(`{"workItems":[{"id":%d}]}`, id)
			if len(urls) == 2 {
				body = fmt.Sprintf(`{"value":[{"id":%d}]}`, id)
			}
			return adoAnswer(r, 200, body, "peer"), nil
		})
		out, err := azureDevOpsAcquire(context.Background(), s, AzureDevOpsRequest{Connection: c.ID, Revision: c.Revision, Read: "workitems.query-and-get", Query: "SELECT [System.Id] FROM WorkItems", Fields: []string{"System.Title"}}, p)
		if err != nil {
			t.Fatal(err)
		}
		var v struct {
			Acquisition struct{ Endpoint, Statement string }
		}
		json.Unmarshal(out, &v)
		statements = append(statements, v.Acquisition.Statement)
		if len(urls) != 2 || v.Acquisition.Endpoint != urls[1] || !strings.Contains(v.Acquisition.Statement, fmt.Sprintf(`"then":{"endpoint":"%s/%s/_apis/wit/workitems","method":"GET","query":{"api-version":"7.1","fields":"System.Title","ids":"%d"}}`, adoOrganization, adoProject, id)) {
			t.Fatalf("%d: the record names %s, the second request was %v: %s", id, v.Acquisition.Endpoint, urls, v.Acquisition.Statement)
		}
	}
	if statements[0] == statements[1] {
		t.Fatal("two reads of different items committed alike")
	}
}

// A project is held to the 64 characters the naming restrictions give a
// project, at the bound and one past; an escape in its name stays its own
// text in the path.
func TestAzureDevOpsAProjectIsHeldToItsOwnBound(t *testing.T) {
	_, b, _, _ := adoFixture(t, adoTokenFields())
	for project, ok := range map[string]bool{strings.Repeat("a", 64): true, strings.Repeat("é", 64): true, strings.Repeat("a", 65): false, strings.Repeat("é", 65): false} {
		fields := adoTokenFields()
		fields["id"], fields["project"] = "other", project
		if err := adoConfigure(b, fields); (err == nil) != ok {
			t.Errorf("%d characters: %v", len([]rune(project)), err)
		}
		if ok {
			s := b.store
			c := adoConnection(t, s, "other")
			b.Handle(context.Background(), "disconnect", []byte(`{"id":"other","revision":"`+c.Revision+`"}`))
		}
	}
	for project, path := range map[string]string{"encoded%2Fsegment": "/encoded%252Fsegment/", "%2e%2e": "/%252e%252e/"} {
		fields := adoTokenFields()
		fields["project"] = project
		_, _, c, _ := adoFixture(t, fields)
		k, _ := (AzureDevOpsRequest{Read: "repos.list"}).call(c)
		if !strings.HasPrefix(k.target(), adoOrganization+path+"_apis/") {
			t.Errorf("%q: %s", project, k.target())
		}
	}
}

// Fixed words are screened as the rest is: a status whose own words would
// spell a credential is not written, a threshold spelling one in escapes is
// not named, and where even the sentence that says so would spell one,
// nothing is written.
func TestAzureDevOpsFixedWordsAreScreenedToo(t *testing.T) {
	fields := adoTokenFields()
	fields["token"] = "azure-devops"
	_, b, _, _ := adoFixture(t, fields)
	if out, err := b.Handle(context.Background(), "status", []byte(`{}`)); out != nil || err != unwritten {
		raw, _ := json.Marshal(out)
		t.Fatalf("status %s %v", raw, err)
	}
	fields = adoTokenFields()
	fields["token"] = "provider-unavailable"
	s, _, c, _ := adoFixture(t, fields)
	p := adoThrough(func(r *http.Request) (*http.Response, error) {
		a := adoAnswer(r, 429, `{}`, "peer")
		a.Header.Set("X-RateLimit-Resource", adoEscaped(c.Token))
		return a, nil
	})
	if _, err := azureDevOpsAcquire(context.Background(), s, AzureDevOpsRequest{Connection: c.ID, Revision: c.Revision, Read: "repos.list"}, p); err == nil || strings.Contains(err.Error(), c.Token) {
		t.Fatal(err)
	}
	// The ladder: as it is, redacted, the fallback, and nothing.
	secrets := []string{"provider-unavailable"}
	for _, k := range []struct{ in, want string }{
		{"request-refused: the organization answered 404", "request-refused: the organization answered 404"},
		{"provider-unavailable: near", "[redacted]: near"},
		{"rate-limited: near " + adoEscaped("provider-unavailable"), ""},
	} {
		if got := azureDevOpsOutward(Error(k.in), secrets); got.Error() != k.want {
			t.Errorf("%q: %q", k.in, got)
		}
	}
	if got := azureDevOpsOutward(Error("rate-limited: near "+adoEscaped(adoPAT)), []string{adoPAT}); got != azureDevOpsUnreported {
		t.Errorf("the fallback: %q", got)
	}
}

// The bound is held to the bytes received: compression is neither asked for
// nor undone, an answer whose announced length is past the bound is refused
// unread, and one that names an encoding is refused.
func TestAzureDevOpsTheBoundIsOnTheBytesReceived(t *testing.T) {
	fields := adoTokenFields()
	fields["max-result-bytes"] = "65536"
	_, _, c, _ := adoFixture(t, fields)
	var padded, small bytes.Buffer
	for range 3000 {
		z := gzip.NewWriter(&padded)
		z.Close()
	}
	for _, buffer := range []*bytes.Buffer{&padded, &small} {
		z := gzip.NewWriter(buffer)
		z.Write([]byte(`{"value":[]}`))
		z.Close()
	}
	for _, k := range []struct {
		entity *bytes.Buffer
		want   string
	}{
		{&padded, "result-too-large: the organization's answer is larger than the connection's bound of 65536 bytes"},
		{&small, "provider-unavailable: the organization's answer is encoded, and this connection reads only what it asked for, which is not"},
	} {
		p := azureDevOpsProvider()
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
		response, body, err := p.azureDevOpsSend(context.Background(), c, "GET", c.Organization+"/"+adoProject+"/_apis/git/repositories?api-version=7.1", nil, c.resultBound(), c.secrets())
		transport.CloseIdleConnections()
		if response != nil || body != nil || err == nil || err.Error() != k.want || asked != "" {
			t.Errorf("%d-byte entity: %v, Accept-Encoding %q", k.entity.Len(), err, asked)
		}
	}
	if padded.Len() <= 65536 || small.Len() > 65536 {
		t.Fatal("fixture sizes", padded.Len(), small.Len())
	}
}

// What reads keep and refuse otherwise holds: each read's requests are its
// documented ones under the configured host and authorization, a 200 that
// asks for a wait is kept, and every other status is refused after one
// request without the API's message.
func TestAzureDevOpsReadsKeepWhatTheyShouldAndRefuseTheRest(t *testing.T) {
	s, _, c, _ := adoFixture(t, adoTokenFields())
	for _, read := range adoReads(c, "/example") {
		calls := []string{}
		p := adoThrough(func(r *http.Request) (*http.Response, error) {
			calls = append(calls, r.Method+" "+r.URL.RequestURI())
			if r.URL.Host != "dev.azure.com" || r.URL.Scheme != "https" || r.Header.Get("Authorization") != "Basic "+adoBasic {
				t.Error("wrong destination or authorization", r.URL, r.Header.Get("Authorization"))
			}
			a := adoAnswer(r, 200, adoNormal(r), "peer")
			a.Header.Set("Retry-After", "10")
			return a, nil
		})
		out, err := azureDevOpsAcquire(context.Background(), s, read.q, p)
		if err != nil || out == nil || fmt.Sprint(calls) != fmt.Sprint(read.lines) {
			t.Fatalf("%s: %v %v, want %v", read.q.Read, err, calls, read.lines)
		}
	}
	for _, status := range []int{302, 307, 429, 503, 401, 403, 404} {
		calls := 0
		p := adoThrough(func(r *http.Request) (*http.Response, error) {
			calls++
			a := adoAnswer(r, status, `{"typeKey":"SyntheticFailure","message":"not safe to repeat"}`, "peer")
			a.Header.Set("Location", "https://another.example/elsewhere")
			a.Header.Set("Retry-After", "7")
			return a, nil
		})
		out, err := azureDevOpsAcquire(context.Background(), s, AzureDevOpsRequest{Connection: c.ID, Revision: c.Revision, Read: "repos.list"}, p)
		if err == nil || out != nil || calls != 1 || strings.Contains(err.Error(), "not safe to repeat") {
			t.Fatalf("status %d: %v, %d requests", status, err, calls)
		}
	}
}
