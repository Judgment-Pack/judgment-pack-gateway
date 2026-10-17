//go:build linux || darwin

package connections

// The arguments of a search held to their table (ADR-0019): each at its
// bounds and one past them, each argument a provider does not take refused
// by name, the request schema --describe-research gives agreeing with what
// acquisition does, and each schema version naming one schema.
//
// The provider here is a stand-in on loopback that counts what reaches it:
// its client connects to the test's own TLS server whatever address a
// request names, so that a request that was sent is counted and nothing
// reaches a network.

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"regexp"
	"slices"
	"strings"
	"sync"
	"testing"
	"unicode/utf8"

	"adapters/internal/canon"
)

// standIn is a provider on loopback: it answers Google's token request, a
// grounded answer and Tavily's search, and keeps each request but the token
// request's body.
type standIn struct {
	mu       sync.Mutex
	requests []goldenRequest
}

func (s *standIn) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.requests)
}

func (s *standIn) last() goldenRequest {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.requests[len(s.requests)-1]
}

func newStandIn(t *testing.T) (*standIn, provider) {
	t.Helper()
	in := &standIn{}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		in.mu.Lock()
		in.requests = append(in.requests, goldenRequest{r.Method, "https://" + r.Host + r.URL.RequestURI(), string(body)})
		in.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Host == "oauth2.googleapis.com":
			w.Write([]byte(`{"access_token":"isolated-token","token_type":"Bearer","expires_in":3600}`))
		case strings.HasSuffix(r.URL.Path, ":generateContent"):
			w.Write([]byte(goldenGrounded))
		default:
			w.Write([]byte(goldenTavilyAnswer(12)))
		}
	}))
	t.Cleanup(server.Close)
	transport := server.Client().Transport.(*http.Transport).Clone()
	transport.Proxy = nil
	transport.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, server.Listener.Addr().String())
	}
	// The test server's certificate names example.com; every request is
	// verified against it, whatever host the request names.
	transport.TLSClientConfig = transport.TLSClientConfig.Clone()
	transport.TLSClientConfig.ServerName = "example.com"
	if transport.TLSClientConfig.MinVersion == 0 {
		transport.TLSClientConfig.MinVersion = tls.VersionTLS12
	}
	p := google()
	p.search = true
	p.client = &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	return in, p
}

// bench is a store with a Tavily connection, demo, and a Google
// connection, grounded, each allowed many requests a day, and a stand-in
// for both providers.
type bench struct {
	s  *Store
	in *standIn
	p  provider
}

func argumentStore(t *testing.T) (*bench, map[string]SearchConnection) {
	t.Helper()
	s, _ := goldenStore(t, "global")
	in, p := newStandIn(t)
	connections := map[string]SearchConnection{}
	if err := s.locked(func(v *state) error {
		for i := range v.Search.Connections {
			v.Search.Connections[i].DailyLimit = 10000
			connections[v.Search.Connections[i].Provider] = v.Search.Connections[i]
		}
		return s.write("state.json", v)
	}); err != nil {
		t.Fatal(err)
	}
	return &bench{s, in, p}, connections
}

// request is a request of connection c with the four arguments every
// request carries, and the changes given: a member set to a value, or, for
// a nil value, taken out.
func request(c SearchConnection, change map[string]any) []byte {
	members := map[string]any{"connection": c.ID, "revision": c.Revision, "query": "public policy guidance", "maxResults": 5}
	for name, value := range change {
		if value == nil {
			delete(members, name)
		} else {
			members[name] = value
		}
	}
	raw, _ := canon.EncodeJSON(members)
	return raw
}

// rawJSON is a member value written as given.
type rawJSON string

func (r rawJSON) MarshalJSON() ([]byte, error) { return []byte(r), nil }

func domains(n int) []string {
	out := make([]string, n)
	for i := range out {
		out[i] = fmt.Sprintf("d%d.example.org", i)
	}
	return out
}

// longDomain is a domain name of n bytes, its labels of at most 63.
func longDomain(n int) string {
	var labels []string
	for n > 0 {
		size := min(63, n)
		if n-size == 1 {
			size-- // a final label of one byte after a dot of one: keep two
		}
		labels = append(labels, strings.Repeat(string(rune('a'+len(labels))), size))
		n -= size + 1
	}
	return strings.Join(labels, ".")
}

type outcome struct {
	out     []byte
	err     error
	sent    int
	charged int
}

func acquire(t *testing.T, b *bench, c SearchConnection, raw []byte) outcome {
	t.Helper()
	sent, spent := b.in.count(), searchSpent(t, b.s, c.ID)
	out, err := readSearch(context.Background(), b.s, raw, b.p)
	return outcome{out, err, b.in.count() - sent, searchSpent(t, b.s, c.ID) - spent}
}

func refusedUnsent(t *testing.T, label string, o outcome, want string) {
	t.Helper()
	if o.err == nil || o.err.Error() != want || len(o.out) != 0 || o.sent != 0 || o.charged != 0 {
		t.Errorf("%s: %v, %d bytes written, %d requests sent, %d charged; want %q and nothing sent", label, o.err, len(o.out), o.sent, o.charged, want)
	}
}

func TestEachArgumentIsHeldToItsBounds(t *testing.T) {
	b, connections := argumentStore(t)
	type value struct {
		label string
		v     any
	}
	bounds := map[string]struct{ in, out []value }{
		"query": {
			in:  []value{{"one byte", "q"}, {"2000 bytes", strings.Repeat("q", 2000)}, {"2000 bytes of two-byte characters", strings.Repeat("é", 1000)}},
			out: []value{{"none", ""}, {"2001 bytes", strings.Repeat("q", 2001)}, {"2002 bytes of two-byte characters", strings.Repeat("é", 1001)}, {"a line feed", "a\nb"}, {"a control character past ASCII", "a\u0085b"}, {"a number", 7}, {"null", rawJSON("null")}},
		},
		"maxResults": {
			in:  []value{{"one", 1}, {"ten", 10}},
			out: []value{{"none", 0}, {"eleven", 11}, {"fewer than none", -1}, {"a string", "5"}, {"a fraction", rawJSON("2.5")}, {"an exponent", rawJSON("1e1")}, {"past 32 bits", rawJSON("4294967297")}},
		},
		"includeDomains": {
			in:  []value{{"one", domains(1)}, {"twenty", domains(20)}, {"a name of 253 bytes", []string{longDomain(253)}}, {"a label of 63", []string{strings.Repeat("a", 63) + ".org"}}, {"a punycode label", []string{"xn--bcher-kva.example"}}},
			out: []value{{"none", []string{}}, {"twenty-one", domains(21)}, {"a name of 254 bytes", []string{longDomain(254)}}, {"a label of 64", []string{strings.Repeat("a", 64) + ".org"}}, {"twice", []string{"example.org", "example.org"}}, {"a capital", []string{"Example.org"}}, {"one label", []string{"example"}}, {"a scheme", []string{"https://example.org"}}, {"a path", []string{"example.org/policy"}}, {"a port", []string{"example.org:443"}}, {"a wildcard", []string{"*.example.org"}}, {"a final dot", []string{"example.org."}}, {"a hyphen first", []string{"-a.example.org"}}, {"a line feed after", []string{"example.org\n"}}, {"a string, not a list", "example.org"}, {"a number in the list", rawJSON(`["example.org",7]`)}, {"null", rawJSON("null")}},
		},
		"timeRange": {
			in:  []value{{"day", "day"}, {"week", "week"}, {"month", "month"}, {"year", "year"}},
			out: []value{{"a decade", "decade"}, {"an abbreviation", "d"}, {"a capital", "Day"}, {"none", ""}, {"a number", 7}},
		},
	}
	bounds["excludeDomains"] = bounds["includeDomains"]
	for _, a := range searchArguments {
		bound, ok := bounds[a.name]
		if a.form.kind == formConnection || a.form.kind == formRevision {
			continue // TestTheRequestSchemaIsWhatAcquisitionEnforces holds these
		}
		if !ok {
			t.Fatalf("no bounds are held for %s", a.name)
		}
		for _, provider := range a.providers {
			c := connections[provider]
			for _, v := range bound.in {
				label := provider + ", " + a.name + ", " + v.label
				o := acquire(t, b, c, request(c, map[string]any{a.name: v.v}))
				if o.err != nil || len(o.out) == 0 || o.charged != 1 {
					t.Errorf("%s: refused: %v (%d charged)", label, o.err, o.charged)
					continue
				}
				carried(t, label, a, v.v, c, o.out, b.in)
			}
			for _, v := range bound.out {
				label := provider + ", " + a.name + ", " + v.label
				o := acquire(t, b, c, request(c, map[string]any{a.name: v.v}))
				refusedUnsent(t, label, o, `search-argument-invalid: "`+a.name+`" must be `+a.form.says()+`; nothing was sent`)
			}
		}
	}
}

// carried holds an admitted argument to what was sent and to the statement:
// Tavily is sent it exactly, under its member there, and the statement
// names it as given.
func carried(t *testing.T, label string, a searchArgument, v any, c SearchConnection, out []byte, in *standIn) {
	t.Helper()
	want, _ := json.Marshal(v)
	var envelope struct{ Acquisition struct{ Statement string } }
	var statement map[string]json.RawMessage
	if json.Unmarshal(out, &envelope) != nil || json.Unmarshal([]byte(envelope.Acquisition.Statement), &statement) != nil {
		t.Fatalf("%s: no statement in %s", label, out)
	}
	if !bytes.Equal(statement[a.name], want) {
		t.Errorf("%s: the statement says %s, the request %s", label, statement[a.name], want)
	}
	sent := in.last()
	var body map[string]json.RawMessage
	if json.Unmarshal([]byte(sent.Body), &body) != nil {
		t.Fatalf("%s: what was sent is not an object: %s", label, sent.Body)
	}
	switch c.Provider {
	case "tavily":
		if !bytes.Equal(body[a.tavily], want) {
			t.Errorf("%s: Tavily was sent %s=%s, the request %s", label, a.tavily, body[a.tavily], want)
		}
		if len(body) != len(tavilyFixed)+2+boolInt(a.name != "query" && a.name != "maxResults") {
			t.Errorf("%s: Tavily was sent members besides the arguments: %s", label, sent.Body)
		}
	case "google-grounding":
		// The query, inside the adapter's own instruction; no other
		// argument is sent to Google.
		var asked struct {
			Contents []struct{ Parts []struct{ Text string } }
		}
		json.Unmarshal([]byte(sent.Body), &asked)
		if len(body) != 3 || body["contents"] == nil || body["tools"] == nil || body["generationConfig"] == nil || len(asked.Contents) != 1 || len(asked.Contents[0].Parts) != 1 {
			t.Fatalf("%s: Google was sent %s", label, sent.Body)
		}
		if q, ok := v.(string); ok && a.name == "query" && !strings.HasSuffix(asked.Contents[0].Parts[0].Text, " Query: "+q) {
			t.Errorf("%s: Google was not sent the query", label)
		}
	}
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

// Each argument the table does not give a provider is refused by name, for
// each provider: an argument of the other provider's after the connection is
// read, any other name before, and nothing is sent or charged.
func TestEachArgumentAProviderDoesNotTakeIsRefusedByName(t *testing.T) {
	b, connections := argumentStore(t)
	valid := map[string]any{"includeDomains": []string{"example.org"}, "excludeDomains": []string{"example.org"}, "timeRange": "week"}
	// Names a provider documents that the table does not hold, the names
	// Tavily's own request uses, members that are the adapter's or the
	// operator's, a name in another case, and a name that is not plain.
	others := []string{"searchDepth", "search_depth", "topic", "days", "startDate", "start_date", "endDate", "country", "chunksPerSource", "includeAnswer", "include_answer", "includeRawContent", "includeImages", "autoParameters", "include_domains", "exclude_domains", "time_range", "max_results", "excludeDomain", "freshness", "endpoint", "url", "headers", "credential", "provider", "model", "generationConfig", "tools", "Query", "TIMERANGE"}
	for _, provider := range searchBothProviders {
		c := connections[provider]
		for _, a := range searchArguments {
			if a.takes(provider) {
				continue
			}
			o := acquire(t, b, c, request(c, map[string]any{a.name: valid[a.name]}))
			refusedUnsent(t, provider+", "+a.name, o, `search-argument-unsupported: "`+a.name+`" is not an argument a `+provider+` connection takes; nothing was sent`)
		}
		for _, name := range others {
			o := acquire(t, b, c, request(c, map[string]any{name: "x"}))
			refusedUnsent(t, provider+", "+name, o, `search-argument-unsupported: "`+name+`" is not an argument of web-search; nothing was sent`)
		}
		for _, name := range []string{"include-domains", "maxRe" + "ſ" + "ults", "a b", strings.Repeat("a", 65), "tvly-" + strings.Repeat("k", 32)} {
			o := acquire(t, b, c, request(c, map[string]any{name: "x"}))
			refusedUnsent(t, provider+", "+name, o, `search-argument-unsupported: a member whose name is not a plain name is not an argument of web-search; nothing was sent`)
		}
	}
	// Google takes none of the three: a request with all of them is refused
	// for the first in the table's order.
	c := connections["google-grounding"]
	o := acquire(t, b, c, request(c, valid))
	refusedUnsent(t, "google, all three", o, `search-argument-unsupported: "includeDomains" is not an argument a google-grounding connection takes; nothing was sent`)
	// The refusal by provider comes after the connection is read: a stale
	// revision is that, and an unsupported argument with a stale one is
	// refused as stale.
	stale := request(c, map[string]any{"revision": strings.Repeat("0", 64), "timeRange": "week"})
	if o := acquire(t, b, c, stale); o.err != ErrChanged || o.sent != 0 || o.charged != 0 {
		t.Errorf("a stale revision with an unsupported argument: %v", o.err)
	}
}

func TestARequiredArgumentAbsentIsRefusedByName(t *testing.T) {
	b, connections := argumentStore(t)
	for _, provider := range searchBothProviders {
		c := connections[provider]
		for _, a := range searchArguments {
			if !a.required {
				continue
			}
			o := acquire(t, b, c, request(c, map[string]any{a.name: nil}))
			refusedUnsent(t, provider+", no "+a.name, o, `search-argument-invalid: "`+a.name+`" is required; nothing was sent`)
		}
	}
	// Faults are refused in one order: a name the table does not hold
	// first, then the table's order.
	c := connections["tavily"]
	o := acquire(t, b, c, request(c, map[string]any{"zeta": 1, "maxResults": 99, "query": nil}))
	refusedUnsent(t, "three faults", o, `search-argument-unsupported: "zeta" is not an argument of web-search; nothing was sent`)
	o = acquire(t, b, c, request(c, map[string]any{"maxResults": 99, "query": nil}))
	refusedUnsent(t, "two faults", o, `search-argument-invalid: "query" is required; nothing was sent`)
	for _, raw := range []string{`null`, `[]`, `"query"`, `{"query":"a","query":"b"}`, `{"connection":"demo"} {}`} {
		o := acquire(t, b, c, []byte(raw))
		if o.err != ErrRequest || o.sent != 0 || o.charged != 0 {
			t.Errorf("%s: %v", raw, o.err)
		}
	}
}

// The table is consistent with what the adapter sends and states.
func TestTheArgumentTableIsWhole(t *testing.T) {
	known, names, wires := map[string]bool{}, map[string]bool{}, map[string]bool{}
	for _, p := range searchProviders() {
		known[p["id"].(string)] = true
		if _, ok := searchSchemaVersions[p["id"].(string)]; !ok {
			t.Errorf("provider %s has no schema versions", p["id"])
		}
	}
	statementOwn := []string{"provider", "method", "endpoint"}
	for _, a := range searchArguments {
		if names[a.name] || a.tavily != "" && wires[a.tavily] {
			t.Errorf("%s is in the table twice", a.name)
		}
		names[a.name], wires[a.tavily] = true, true
		if !plainName.MatchString(a.name) {
			t.Errorf("%s is not a plain name, and a refusal would not repeat it", a.name)
		}
		for _, p := range a.providers {
			if !known[p] {
				t.Errorf("%s names a provider there is not: %s", a.name, p)
			}
		}
		if a.required && len(a.providers) != len(known) {
			t.Errorf("%s is required and not taken by every provider", a.name)
		}
		if _, fixed := tavilyFixed[a.tavily]; fixed {
			t.Errorf("%s would be sent as a member the adapter fixes: %s", a.name, a.tavily)
		}
		if slices.Contains(statementOwn, a.name) {
			t.Errorf("%s would replace a member of the statement that is the adapter's", a.name)
		}
		if a.takes("tavily") && a.tavily == "" && a.form.kind != formConnection && a.form.kind != formRevision {
			t.Errorf("%s is taken by Tavily and sent as nothing", a.name)
		}
	}
}

// --- The request schema and acquisition agree ---

// schemaValid is a reading of the keywords the request schemas use, and
// fails the test on any other, so that a keyword added to the schemas is
// not one this agreement passes over.
func schemaValid(t *testing.T, schema map[string]any, v any) bool {
	t.Helper()
	ok := true
	for keyword, k := range schema {
		switch keyword {
		case "$schema", "description":
		case "type":
			switch k {
			case "object":
				_, is := v.(map[string]any)
				ok = ok && is
			case "string":
				_, is := v.(string)
				ok = ok && is
			case "integer":
				n, is := v.(json.Number)
				_, err := n.Int64()
				ok = ok && is && err == nil
			case "array":
				_, is := v.([]any)
				ok = ok && is
			default:
				t.Fatalf("a type this reading does not know: %v", k)
			}
		case "const":
			ok = ok && fmt.Sprint(v) == fmt.Sprint(k)
		case "enum":
			found := false
			for _, e := range k.([]any) {
				found = found || fmt.Sprint(v) == fmt.Sprint(e)
			}
			ok = ok && found
		case "minimum", "maximum":
			n, is := v.(json.Number)
			if is {
				value, err1 := n.Float64()
				bound, err2 := k.(json.Number).Float64()
				if err1 != nil || err2 != nil || keyword == "minimum" && value < bound || keyword == "maximum" && value > bound {
					ok = false
				}
			}
		case "minLength", "maxLength":
			if s, is := v.(string); is {
				bound, _ := k.(json.Number).Int64()
				n := int64(utf8.RuneCountInString(s))
				ok = ok && !(keyword == "minLength" && n < bound || keyword == "maxLength" && n > bound)
			}
		case "pattern":
			if s, is := v.(string); is {
				ok = ok && regexp.MustCompile(k.(string)).MatchString(s)
			}
		case "minItems", "maxItems":
			if list, is := v.([]any); is {
				bound, _ := k.(json.Number).Int64()
				n := int64(len(list))
				ok = ok && !(keyword == "minItems" && n < bound || keyword == "maxItems" && n > bound)
			}
		case "uniqueItems":
			if list, is := v.([]any); is && k == true {
				seen := map[string]bool{}
				for _, item := range list {
					key, _ := json.Marshal(item)
					ok = ok && !seen[string(key)]
					seen[string(key)] = true
				}
			}
		case "items":
			if list, is := v.([]any); is {
				for _, item := range list {
					ok = ok && schemaValid(t, k.(map[string]any), item)
				}
			}
		case "properties":
			if object, is := v.(map[string]any); is {
				for name, member := range object {
					if sub, declared := k.(map[string]any)[name]; declared {
						ok = ok && schemaValid(t, sub.(map[string]any), member)
					}
				}
			}
		case "additionalProperties":
			if object, is := v.(map[string]any); is && k == false {
				for name := range object {
					_, declared := schema["properties"].(map[string]any)[name]
					ok = ok && declared
				}
			}
		case "required":
			if object, is := v.(map[string]any); is {
				for _, name := range k.([]any) {
					_, present := object[name.(string)]
					ok = ok && present
				}
			}
		default:
			t.Fatalf("a keyword this reading does not know: %s", keyword)
		}
	}
	return ok
}

func readJSON(t *testing.T, raw []byte) any {
	t.Helper()
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	var v any
	if err := d.Decode(&v); err != nil {
		t.Fatal(err)
	}
	return v
}

// samples are values for a member, derived from its schema alone: each
// bound and one past it, each choice and one that is none, a constant and
// another, and for a list each of a list of candidate names.
func samples(property map[string]any) []any {
	var out []any
	integer := func(k string) (int64, bool) {
		n, ok := property[k].(json.Number)
		if !ok {
			return 0, false
		}
		v, _ := n.Int64()
		return v, true
	}
	switch property["type"] {
	case "integer":
		for _, k := range []string{"minimum", "maximum"} {
			if v, ok := integer(k); ok {
				out = append(out, json.Number(fmt.Sprint(v-1)), json.Number(fmt.Sprint(v)), json.Number(fmt.Sprint(v+1)))
			}
		}
		out = append(out, "5", json.Number("2.5"))
	case "string":
		if c, ok := property["const"]; ok {
			out = append(out, c, fmt.Sprint(c)+"x", strings.Repeat("0", 64))
		}
		if e, ok := property["enum"].([]any); ok {
			for _, v := range e {
				out = append(out, v, strings.ToUpper(v.(string)), v.(string)+"s")
			}
			out = append(out, "", "none")
		}
		for _, k := range []string{"minLength", "maxLength"} {
			if v, ok := integer(k); ok {
				for _, n := range []int64{v - 1, v, v + 1} {
					if n >= 0 {
						out = append(out, strings.Repeat("q", int(n)))
					}
				}
			}
		}
		out = append(out, json.Number("7"))
	case "array":
		items, _ := property["items"].(map[string]any)
		candidates := []string{"example.org", "a.b", "xn--bcher-kva.example", "Example.org", "example", "-a.org", "a-.org", "a..org", "example.org.", "*.example.org", "https://example.org", "example.org/path", "exa mple.org", "example.org:443", "example.org\n", longDomain(253), longDomain(254), strings.Repeat("a", 63) + ".org", strings.Repeat("a", 64) + ".org", ""}
		for _, c := range candidates {
			out = append(out, []any{c})
		}
		if items != nil {
			valid := func(n int64) []any {
				list := make([]any, n)
				for i := range list {
					list[i] = fmt.Sprintf("d%d.example.org", i)
				}
				return list
			}
			for _, k := range []string{"minItems", "maxItems"} {
				if v, ok := integer(k); ok {
					for _, n := range []int64{v - 1, v, v + 1} {
						if n >= 0 {
							out = append(out, valid(n))
						}
					}
				}
			}
			out = append(out, []any{"example.org", "example.org"}, []any{"example.org", json.Number("7")})
		}
		out = append(out, "example.org")
	}
	return out
}

// The request schema --describe-research gives a connection is what
// searchRequestSchema makes of the table, and it agrees with acquisition:
// each value derived from the schema is admitted by acquisition exactly
// when the schema admits it, with each argument of the table, each member
// of the schema and each required member taken out.
func TestTheRequestSchemaIsWhatAcquisitionEnforces(t *testing.T) {
	b, connections := argumentStore(t)
	for _, provider := range searchBothProviders {
		c := connections[provider]
		description, err := DescribeSearchBinding(b.s, []byte(`{"connection":"`+c.ID+`","revision":"`+c.Revision+`"}`))
		if err != nil {
			t.Fatal(err)
		}
		var d ResearchBindingDescriptor
		if json.Unmarshal(description, &d) != nil {
			t.Fatal("no description")
		}
		generated, _ := canon.EncodeJSON(searchRequestSchema(c))
		if !bytes.Equal(d.RequestSchema, generated) {
			t.Fatalf("%s: the description's request schema is not the table's:\n%s\n%s", provider, d.RequestSchema, generated)
		}
		schema := readJSON(t, d.RequestSchema).(map[string]any)
		properties := schema["properties"].(map[string]any)
		base := map[string]any{"connection": c.ID, "revision": c.Revision, "query": "public policy guidance", "maxResults": json.Number("5")}
		admitted, refused := 0, 0
		check := func(label string, members map[string]any) {
			t.Helper()
			raw, _ := json.Marshal(members)
			want := schemaValid(t, schema, readJSON(t, raw))
			o := acquire(t, b, c, raw)
			got := o.err == nil && len(o.out) > 0
			if got {
				admitted++
			} else {
				refused++
			}
			if got != want {
				t.Errorf("%s, %s: the schema admits it %v, acquisition %v (%v)", provider, label, want, got, o.err)
			}
			if !got && (o.sent != 0 || o.charged != 0) {
				t.Errorf("%s, %s: refused after %d requests and %d charged", provider, label, o.sent, o.charged)
			}
		}
		check("the four", base)
		names := []string{}
		for name := range properties {
			names = append(names, name)
		}
		for _, a := range searchArguments {
			names = append(names, a.name) // the table's arguments the schema leaves out too
		}
		slices.Sort(names)
		names = slices.Compact(names)
		for _, name := range names {
			property, declared := properties[name].(map[string]any)
			if !declared {
				// An argument of the table the schema does not give this
				// provider, with a value the other provider takes.
				a, _ := searchArgumentNamed(name)
				other := connections["tavily"]
				if provider == "tavily" {
					t.Fatalf("Tavily's schema leaves out %s", name)
				}
				otherSchema := readJSON(t, mustEncode(searchRequestSchema(other))).(map[string]any)
				for _, v := range samples(otherSchema["properties"].(map[string]any)[a.name].(map[string]any)) {
					members := copyOf(base)
					members[name] = v
					check(name+" = "+short(v), members)
				}
				continue
			}
			for _, v := range samples(property) {
				members := copyOf(base)
				members[name] = v
				check(name+" = "+short(v), members)
			}
			members := copyOf(base)
			delete(members, name)
			check("no "+name, members)
		}
		for _, name := range []string{"extra", "Query", "searchDepth"} {
			members := copyOf(base)
			members[name] = "x"
			check(name, members)
		}
		// Both answers were given, so that neither side agreed by refusing,
		// or admitting, everything.
		if admitted < 10 || refused < 10 {
			t.Errorf("%s: %d values admitted and %d refused", provider, admitted, refused)
		}
		t.Logf("%s: %d values admitted and %d refused, each as the schema says", provider, admitted, refused)
	}
}

func copyOf(m map[string]any) map[string]any {
	out := map[string]any{}
	for k, v := range m {
		out[k] = v
	}
	return out
}

func mustEncode(v any) []byte {
	raw, err := canon.EncodeJSON(v)
	if err != nil {
		panic(err)
	}
	return raw
}

func short(v any) string {
	raw, _ := json.Marshal(v)
	if len(raw) > 40 {
		return string(raw[:40]) + "..."
	}
	return string(raw)
}

// The result schema describes the results acquisition answers with.
func TestTheResultSchemaDescribesWhatAcquisitionAnswers(t *testing.T) {
	b, connections := argumentStore(t)
	for _, provider := range searchBothProviders {
		c := connections[provider]
		o := acquire(t, b, c, request(c, map[string]any{"maxResults": 10}))
		if o.err != nil {
			t.Fatal(o.err)
		}
		var envelope struct{ Result json.RawMessage }
		json.Unmarshal(o.out, &envelope)
		schema := readJSON(t, mustEncode(searchResultSchema(c))).(map[string]any)
		if !schemaValid(t, schema, readJSON(t, envelope.Result)) {
			t.Errorf("%s: the result is not one its schema describes: %s", provider, envelope.Result)
		}
		other := connections[map[string]string{"tavily": "google-grounding", "google-grounding": "tavily"}[provider]]
		otherSchema := readJSON(t, mustEncode(searchResultSchema(other))).(map[string]any)
		if schemaValid(t, otherSchema, readJSON(t, envelope.Result)) {
			t.Errorf("%s: the result is one the other provider's schema describes", provider)
		}
	}
}

// Each schema version names one schema: the digest of what it was when it
// was given. A change of a schema with no new version fails here; a new
// version is a new row, and the old row goes with the schema it named.
func TestSearchSchemaVersionsNameOneSchemaEach(t *testing.T) {
	pinned := map[string]string{
		"tavily-request-1":           "sha256:0e8771d04110d6e7ca704c29f31ceb579a18e95bb7d21a038523fe98bf210320",
		"tavily-result-1":            "sha256:fc117aadcc0e6a346cb7cbd3e6d9aca23aa0c8cca9e99409bb467191a822e758",
		"google-grounding-request-1": "sha256:5e34c0dd5df4fda297924192c6648212895bdad0a4df7b898c57347a86bcebfd",
		"google-grounding-result-1":  "sha256:ac95ece6df9ee61a8732b77a160c308f9581554522d45bab2f92f195a78f4f1f",
	}
	c := SearchConnection{ID: "pinned", Revision: strings.Repeat("a", 64), Project: "demo-project", Location: "global", Model: "gemini-2.5-flash"}
	for provider, versions := range searchSchemaVersions {
		c.Provider = provider
		for version, schema := range map[string]any{versions.request: searchRequestSchema(c), versions.result: searchResultSchema(c)} {
			sum := sha256.Sum256(mustEncode(schema))
			got := "sha256:" + hex.EncodeToString(sum[:])
			want, known := pinned[version]
			if !known || got != want {
				t.Errorf("schema %s is %s, pinned %q: a changed schema takes a new version", version, got, want)
			}
		}
	}
	if len(pinned) != 2*len(searchSchemaVersions) {
		t.Errorf("%d versions pinned for %d providers", len(pinned), len(searchSchemaVersions))
	}
}
