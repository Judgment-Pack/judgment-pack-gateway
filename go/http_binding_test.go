package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// recordsBinding is a catalog entry whose one operation is live by the http
// shape (ADR-0024), with every member it may carry.
const recordsBinding = `{
  "bindingVersion": "1",
  "platform": "records",
  "operations": {
    "live": {"shape": "http", "endpoint": "https://records.example/api", "paths": ["/search", "/health"], "methods": ["GET", "POST"],
      "headers": ["Accept=application/json"], "bearer": "API_TOKEN", "checkPath": "/health", "licence": "Apache-2.0"}
  }
}`

// httpLive is a binding of one http live operation with the members given,
// and the shape and licence every operation carries.
func httpLive(members string) string {
	return `{"bindingVersion":"1","platform":"p","operations":{"live":{"shape":"http","licence":"MIT"` + members + `}}}`
}

// pathsOfWord is the paths member of 128 distinct paths, none past its
// bound, whose "--paths=" word on adapter-http's command line is exactly
// word bytes long.
func pathsOfWord(word int) string {
	n := maxHTTPPaths
	left := word - len("--paths=") - (n - 1)
	quoted := make([]string, n)
	for i := range quoted {
		size := min(maxHTTPItem, left-5*(n-1-i))
		quoted[i] = `"/` + fmt.Sprintf("%03d", i) + strings.Repeat("a", size-4) + `"`
		left -= size
	}
	return `"paths":[` + strings.Join(quoted, ",") + `]`
}

// An http live operation is held to its shape before the engine starts:
// exactly its members, an endpoint of the endpoint form, paths the adapter
// takes as written and the engine's command line carries as one each,
// methods GET and POST, fixed headers no credential's and none the adapter
// writes, exactly one credentials member sent, a check path among the
// paths by GET, and no other operation beside it. A refusal names the
// member by its place and repeats no value.
func TestHTTPOperationRefusals(t *testing.T) {
	const ok = `,"endpoint":"https://records.example","paths":["/a"],"bearer":"T"`
	write := `"write":{"shape":"mcp","server":{"image":"x@` + testImageDigest + `"},"tools":["w"],"licence":"MIT"}`
	history := `"history":{"shape":"airbyte","image":"x@` + testImageDigest + `","licence":"MIT"}`
	live := `"live":{"shape":"http","licence":"MIT"` + ok + `}`
	cases := []struct{ name, text, want string }{
		{"no endpoint", httpLive(`,"paths":["/a"],"bearer":"T"`), `missing member "endpoint"`},
		{"no paths", httpLive(`,"endpoint":"https://records.example","bearer":"T"`), `missing member "paths"`},
		{"an unknown member", httpLive(ok + `,"caFile":"/ca.pem"`), `unknown member "caFile"`},
		{"a timeout of its own", httpLive(ok + `,"timeout":"5s"`), `unknown member "timeout"`},
		{"a member twice", httpLive(ok + `,"paths":["/b"]`), `duplicate member name "paths"`},
		{"an endpoint null", httpLive(`,"endpoint":null,"paths":["/a"],"bearer":"T"`), "endpoint must be https"},
		{"an empty endpoint", httpLive(`,"endpoint":"","paths":["/a"],"bearer":"T"`), "endpoint must be https"},
		{"plaintext off loopback", httpLive(`,"endpoint":"http://records.example","paths":["/a"],"bearer":"T"`), "endpoint must be https"},
		{"plaintext to a name for loopback", httpLive(`,"endpoint":"http://localhost:8080","paths":["/a"],"bearer":"T"`), "endpoint must be https"},
		{"an endpoint with a query", httpLive(`,"endpoint":"https://records.example/?k=v","paths":["/a"],"bearer":"T"`), "endpoint must be https"},
		{"an endpoint with a user", httpLive(`,"endpoint":"https://u@records.example","paths":["/a"],"bearer":"T"`), "endpoint must be https"},
		{"an endpoint template", httpLive(`,"endpoint":"https://{tenant}.records.example","paths":["/a"],"bearer":"T"`), "names no placeholder"},
		{"a relative endpoint", httpLive(`,"endpoint":"records.example/api","paths":["/a"],"bearer":"T"`), "endpoint must be https"},
		{"a percent sign in the endpoint", httpLive(`,"endpoint":"https://records.example/a%2Fb","paths":["/a"],"bearer":"T"`), "endpoint's path carries a percent sign"},
		{"a dot segment in the endpoint", httpLive(`,"endpoint":"https://records.example/api/../admin","paths":["/a"],"bearer":"T"`), "endpoint's path carries a dot segment"},
		{"an endpoint ending in a dot segment", httpLive(`,"endpoint":"https://records.example/api/.","paths":["/a"],"bearer":"T"`), "endpoint's path carries a dot segment"},
		{"an empty segment in the endpoint", httpLive(`,"endpoint":"https://records.example/a//b","paths":["/a"],"bearer":"T"`), "endpoint's path carries an empty segment"},
		{"an endpoint ending in two slashes", httpLive(`,"endpoint":"https://records.example/api//","paths":["/a"],"bearer":"T"`), "endpoint's path carries an empty segment"},
		{"paths not an array", httpLive(`,"endpoint":"https://records.example","paths":"/a","bearer":"T"`), "paths must be an array of 1 to 128 strings"},
		{"no path", httpLive(`,"endpoint":"https://records.example","paths":[],"bearer":"T"`), "paths must be an array of 1 to 128 strings"},
		{"a path null", httpLive(`,"endpoint":"https://records.example","paths":["/a",null],"bearer":"T"`), "paths[1] must be a non-empty string"},
		{"an empty path", httpLive(`,"endpoint":"https://records.example","paths":[""],"bearer":"T"`), "paths[0] must be a non-empty string"},
		{"a relative path", httpLive(`,"endpoint":"https://records.example","paths":["a"],"bearer":"T"`), `paths[0] must begin with "/"`},
		{"a comma, which would be two paths", httpLive(`,"endpoint":"https://records.example","paths":["/a,/admin"],"bearer":"T"`), "paths[0] carries a comma"},
		{"a percent sign", httpLive(`,"endpoint":"https://records.example","paths":["/a%2Fb"],"bearer":"T"`), "paths[0] carries a comma, a percent sign"},
		{"a brace", httpLive(`,"endpoint":"https://records.example","paths":["/{id}"],"bearer":"T"`), "paths[0] carries a comma, a percent sign or a brace"},
		{"a query", httpLive(`,"endpoint":"https://records.example","paths":["/a?x=1"],"bearer":"T"`), "paths[0] carries a query"},
		{"a backslash", httpLive(`,"endpoint":"https://records.example","paths":["/a\\b"],"bearer":"T"`), "paths[0] carries a query, a fragment or a backslash"},
		{"a space", httpLive(`,"endpoint":"https://records.example","paths":["/a b"],"bearer":"T"`), "paths[0] must be printable ASCII"},
		{"beyond ASCII", httpLive(`,"endpoint":"https://records.example","paths":["/café"],"bearer":"T"`), "paths[0] must be printable ASCII"},
		{"a dot segment", httpLive(`,"endpoint":"https://records.example","paths":["/a/../admin"],"bearer":"T"`), "paths[0] carries a dot segment"},
		{"an empty segment", httpLive(`,"endpoint":"https://records.example","paths":["/a//b"],"bearer":"T"`), "paths[0] carries an empty segment"},
		{"a path twice", httpLive(`,"endpoint":"https://records.example","paths":["/a","/b","/a"],"bearer":"T"`), "paths[2] repeats an earlier path"},
		{"a path past its bound", httpLive(`,"endpoint":"https://records.example","paths":["/` + strings.Repeat("a", maxHTTPItem) + `"],"bearer":"T"`), "paths[0] must be a non-empty string of at most 1024 bytes"},
		{"paths past one argument", httpLive(`,"endpoint":"https://records.example",` + pathsOfWord(maxHTTPPathsWord+1) + `,"bearer":"T"`), "paths must join, with commas, into one argument of adapter-http's command line under 128 KiB"},
		{"no method", httpLive(ok + `,"methods":[]`), "methods must be an array of 1 to 2 strings"},
		{"a method of another kind", httpLive(ok + `,"methods":["PUT"]`), "methods[0] is neither GET nor POST"},
		{"a method in lower case", httpLive(ok + `,"methods":["get"]`), "methods[0] is neither GET nor POST"},
		{"a method twice", httpLive(ok + `,"methods":["GET","GET"]`), "methods[1] repeats an earlier method"},
		{"no credential member", httpLive(`,"endpoint":"https://records.example","paths":["/a"]`), "exactly one of bearer and credentialHeader"},
		{"two credential members", httpLive(ok + `,"credentialHeader":"X-Key=T"`), "exactly one of bearer and credentialHeader"},
		{"a bearer null", httpLive(`,"endpoint":"https://records.example","paths":["/a"],"bearer":null`), "bearer names the credentials member"},
		{"an empty bearer", httpLive(`,"endpoint":"https://records.example","paths":["/a"],"bearer":""`), "bearer names the credentials member"},
		{"a credential header without a member", httpLive(`,"endpoint":"https://records.example","paths":["/a"],"credentialHeader":"X-Key="`), "credentialHeader is NAME=MEMBER"},
		{"a credential header not a pair", httpLive(`,"endpoint":"https://records.example","paths":["/a"],"credentialHeader":"X-Key"`), "credentialHeader is NAME=MEMBER"},
		{"a credential header without a name", httpLive(`,"endpoint":"https://records.example","paths":["/a"],"credentialHeader":"=T"`), "credentialHeader is NAME=MEMBER"},
		{"a credential sent to a proxy", httpLive(`,"endpoint":"https://records.example","paths":["/a"],"credentialHeader":"Proxy-Authorization=T"`), "credentialHeader names Proxy-Authorization"},
		{"a credential under a header the adapter writes", httpLive(`,"endpoint":"https://records.example","paths":["/a"],"credentialHeader":"Host=T"`), "credentialHeader names Host"},
		{"no header", httpLive(ok + `,"headers":[]`), "headers must be an array of 1 to 32 strings"},
		{"a header not a pair", httpLive(ok + `,"headers":["Accept"]`), "headers[0] must be NAME=VALUE"},
		{"a header with no value", httpLive(ok + `,"headers":["Accept="]`), "headers[0] must be NAME=VALUE"},
		{"a header value padded", httpLive(ok + `,"headers":["Accept= json"]`), "headers[0] must be NAME=VALUE"},
		{"a header value with a control character", httpLive(ok + `,"headers":["Accept=a\tb"]`), "headers[0] must be NAME=VALUE"},
		{"a credential as a header", httpLive(ok + `,"headers":["Accept=json","Authorization=Bearer secret-in-binding"]`), "headers[1] names Authorization, a credential's header"},
		{"a cookie as a header", httpLive(ok + `,"headers":["Cookie=session=secret-in-binding"]`), "headers[0] names Cookie, a credential's header"},
		{"a header the adapter writes", httpLive(ok + `,"headers":["Content-Type=text/plain"]`), "headers[0] names Content-Type, which adapter-http writes itself"},
		{"a header twice", httpLive(ok + `,"headers":["Accept=a","accept=b"]`), "headers[1] names a header already named"},
		{"a header the credential is sent under", httpLive(`,"endpoint":"https://records.example","paths":["/a"],"credentialHeader":"X-Key=T","headers":["X-Key=fixed"]`), "headers[0] names a header already named"},
		{"a check path not among the paths", httpLive(ok + `,"methods":["GET"],"checkPath":"/health"`), "checkPath, when present, is one of the operation's paths"},
		{"a check path null", httpLive(ok + `,"methods":["GET"],"checkPath":null`), "checkPath, when present, is one of the operation's paths"},
		{"a check path by a method not named", httpLive(ok + `,"checkPath":"/a"`), "checkPath is requested by GET, which methods does not name"},
		{"history beside it", `{"bindingVersion":"1","platform":"p","operations":{` + history + `,` + live + `}}`, "operation live of the http shape is its binding's only operation"},
		{"a write beside it", `{"bindingVersion":"1","platform":"p","operations":{` + live + `,` + write + `}}`, "operation live of the http shape is its binding's only operation"},
		{"a write by the http shape", `{"bindingVersion":"1","platform":"p","operations":{"write":{"shape":"http","licence":"MIT"` + ok + `}}}`, `operation write is served by the mcp shape, not "http"`},
		{"history by the http shape", `{"bindingVersion":"1","platform":"p","operations":{"history":{"shape":"http","licence":"MIT"` + ok + `}}}`, `operation history is served by the airbyte shape, not "http"`},
		{"an owner-declared binding", `{"bindingVersion":"2","platform":"p","operations":{"live":{"shape":"http","licence":"MIT"` + ok + `,"toolTaxonomies":{}}}}`, "the http shape is a bindingVersion 1 operation"},
		{"a bindingVersion 3 binding", `{"bindingVersion":"3","platform":"p","operations":{"live":{"shape":"http","licence":"MIT"` + ok + `,"toolTaxonomies":{}}}}`, "the http shape is a bindingVersion 1 operation"},
		{"no licence", `{"bindingVersion":"1","platform":"p","operations":{"live":{"shape":"http"` + ok + `}}}`, "licence must be stated"},
	}
	for _, c := range cases {
		_, err := parseBinding([]byte(c.text))
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: want %q, got %v", c.name, c.want, err)
			continue
		}
		if strings.Contains(err.Error(), "secret-in-binding") || strings.Contains(err.Error(), "fixed") && c.name == "a header the credential is sent under" {
			t.Errorf("%s: the refusal repeats a value: %v", c.name, err)
		}
	}
}

// A binding of an http live operation parses to what adapter-http is
// started with; methods are POST alone when the binding names none, as
// the adapter's own default.
func TestHTTPOperationParses(t *testing.T) {
	b, err := parseBinding([]byte(recordsBinding))
	if err != nil {
		t.Fatal(err)
	}
	want := &httpOperation{endpoint: "https://records.example/api", paths: []string{"/search", "/health"}, methods: []string{"GET", "POST"},
		headers: []string{"Accept=application/json"}, bearer: "API_TOKEN", checkPath: "/health"}
	if b.live == nil || b.live.shape != "http" || !reflect.DeepEqual(b.live.http, want) || b.live.tools != nil || b.history != nil || b.write != nil {
		t.Fatalf("the operation: %+v", b.live)
	}
	b, err = parseBinding([]byte(httpLive(`,"endpoint":"http://127.0.0.1:8080","paths":["/"],"credentialHeader":"X-Api-Key=KEY"`)))
	if err != nil {
		t.Fatal(err)
	}
	if h := b.live.http; !reflect.DeepEqual(h.methods, []string{"POST"}) || h.credentialHeader != "X-Api-Key=KEY" || h.bearer != "" || h.headers != nil || h.checkPath != "" {
		t.Fatalf("the defaults: %+v", h)
	}
	// The owner-declared readings of the configuration see no MCP
	// operation in it: nothing for the current admission to hold to an
	// owner taxonomy, and nothing to capture descriptors of.
	if ops := enabledMCPOperations(platformConfig{}, b); len(ops) != 0 {
		t.Fatalf("an http live operation is no MCP operation: %v", ops)
	}
	if describedOperation(b, false) != nil {
		t.Fatal("an http live operation has no tool to describe")
	}
	if err := currentBindingOwners(engineConfig{platforms: []platformConfig{{name: "p"}}}, map[string]binding{"p": b}); err != nil {
		t.Fatalf("the current admission holds no http operation to an owner taxonomy: %v", err)
	}
	// The bounds hold from inside: paths whose word is the longest one
	// argument carries, and an endpoint ending in the one "/" the adapter
	// drops.
	b, err = parseBinding([]byte(httpLive(`,"endpoint":"https://records.example/api/",` + pathsOfWord(maxHTTPPathsWord) + `,"bearer":"T"`)))
	if err != nil {
		t.Fatal(err)
	}
	if word := httpSourceArgv("adapter-http", *b.live.http, "c")[2]; maxHTTPPathsWord != 128<<10-1 || len(word) != maxHTTPPathsWord || !strings.HasPrefix(word, "--paths=/000") {
		t.Fatalf("the paths word at its bound: %d bytes", len(word))
	}
}

// The engine derives `<platform>/live` of an http binding as adapter-http,
// started as the platform's user with the platform's live credentials
// file: the binding's endpoint, paths, methods, member and headers on its
// command line, each flag and its value one word; shape http; no tools,
// no grant, no descriptors, no approval; and the check path for a check.
// From engine version 13 it runs under the source sandbox as every adapter
// does.
func TestEngineDerivesAnHTTPSource(t *testing.T) {
	catalog := catalogWith(t, map[string]string{"records": recordsBinding})
	ref := "records@" + digestOf(recordsBinding)
	bin := abs(t, t.TempDir(), "bin")
	text := engineJSON(t, catalog, `,"adapters":"`+bin+`"`, platformJSONFor(t, "records", ref, "engine-docs", `,"environment":{"HTTPS_PROXY":"http://proxy.internal:3128"}`, "live"))
	cfg, sources, err := load(t, text)
	if err != nil {
		t.Fatal(err)
	}
	p := cfg.platforms[0]
	binDir := strings.ReplaceAll(bin, `\\`, `\`)
	want := map[string]sourceSpec{
		"records/live": {
			argv: []string{filepath.Join(binDir, "adapter-http"), "--endpoint=https://records.example/api", "--paths=/search,/health", "--methods=GET,POST",
				"--credentials=" + p.credentials["live"], "--bearer=API_TOKEN", "--header=Accept=application/json"},
			env: []string{"HOME=/home/engine-docs", "HTTPS_PROXY=http://proxy.internal:3128"}, user: "engine-docs", shape: "http", binding: ref,
			check: []string{"--check-path=/health"},
		},
	}
	if !reflect.DeepEqual(sources, want) {
		t.Fatalf("derived sources:\n got %+v\nwant %+v", sources, want)
	}
	// A credential under its own header, and no check path: the check is
	// the connection alone.
	keyed := httpLive(`,"endpoint":"https://records.example","paths":["/a"],"credentialHeader":"X-Api-Key=KEY"`)
	keyed = strings.Replace(keyed, `"platform":"p"`, `"platform":"records"`, 1)
	_, sources, err = load(t, engineJSON(t, catalogWith(t, map[string]string{"records": keyed}), ``, platformJSONFor(t, "records", "records@"+digestOf(keyed), "engine-docs", ``, "live")))
	if err != nil {
		t.Fatal(err)
	}
	if live := sources["records/live"]; live.argv[0] != "adapter-http" || live.argv[5] != "--credential-header=X-Api-Key=KEY" || len(live.argv) != 6 || live.check != nil {
		t.Fatalf("a credential header, on PATH, no check path: %+v", live)
	}
	// Under the source sandbox, as an adapter.
	sandboxed := strings.Replace(text, `"engineVersion":"1"`, `"engineVersion":"13"`, 1)
	_, sources, err = load(t, sandboxed)
	if err != nil {
		t.Fatal(err)
	}
	if sb := sources["records/live"].sandbox; sb == nil || sb.helper != filepath.Join(binDir, "adapter-sandbox") || sb.source != "records/live" || !reflect.DeepEqual(sb.classes, []string{"adapter"}) {
		t.Fatalf("the source sandbox wraps the http source as an adapter: %+v", sb)
	}
}

// A platform whose binding serves live by the http shape is refused what
// it would leave unused, and so read as in force: a grant, an endpoint,
// write: true and so a decision policy, parameters, descriptor pins and
// statements, and a credentials file for an operation the binding does
// not offer. Each refusal names the platform.
func TestEngineRefusesWhatAnHTTPPlatformWouldNotUse(t *testing.T) {
	catalog := catalogWith(t, map[string]string{"records": recordsBinding})
	ref := "records@" + digestOf(recordsBinding)
	stateDir := abs(t, t.TempDir(), "custody")
	pin := `"sha256:` + strings.Repeat("0", 64) + `"`
	at := func(version, extra string, ops ...string) string {
		if len(ops) == 0 {
			ops = []string{"live"}
		}
		s := engineJSON(t, catalog, ``, platformJSONFor(t, "records", ref, "engine-docs", extra, ops...))
		return strings.Replace(s, `"engineVersion":"1"`, `"engineVersion":"`+version+`"`, 1)
	}
	for _, c := range []struct{ name, text, want string }{
		{"a grant", at("16", `,"grant":{"provider":"notion","connection":"records","stateDir":"`+stateDir+`","principal":"operator","user":"engine-desk"}`), "platform records: names a grant, and binding records@"},
		{"an endpoint", at("1", `,"endpoint":"records.internal"`), "platform records: names an endpoint, and binding records@"},
		{"write: true", at("1", `,"write":true`), "platform records: sets write: true, and binding records@"},
		{"a decision policy", at("4", `,"write":true,"decisionPolicy":{"search":{"outcomes":["approve"]}}`), "platform records: sets write: true, and binding records@"},
		{"a decision policy without write: true", at("4", `,"decisionPolicy":{"search":{"outcomes":["approve"]}}`), "platform records: decisionPolicy holds write tools to a decision, and the platform does not set write: true"},
		{"parameters", at("8", `,"parameters":{"tenant":"acme"}`), "platform records: parameters.tenant is named by no placeholder of binding records@"},
		{"a descriptors pin", at("3", `,"descriptors":`+pin), "platform records: descriptors pins a snapshot of a live MCP operation"},
		{"operation descriptors", at("11", `,"operationDescriptors":{"live":`+pin+`}`), "operationDescriptors requires an owner-declared bindingVersion2"},
		{"descriptor statements", at("12", `,"descriptorStatements":{"live":`+pin+`}`), "platform records: descriptorStatements must cover exactly the captured operations"},
		{"no live credentials", at("1", ``, "history"), "platform records: the binding offers live but credentials name no live file"},
		{"history credentials too", at("1", ``, "history", "live"), "platform records: credentials name a history file but the binding offers no history"},
	} {
		if _, _, err := load(t, c.text); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: want %q, got %v", c.name, c.want, err)
		}
	}
	// What remains loads: the platform's own user, its live credentials,
	// an environment.
	if _, _, err := load(t, at("18", `,"environment":{"HTTPS_PROXY":"http://proxy.internal:3128"}`)); err != nil {
		t.Fatalf("a platform of an http binding at the current version: %v", err)
	}
}

// The adapter's check report, read for an http source: the endpoint the
// source was given, a probe exactly when a check path was given, of that
// path and answered 2xx. A refusal repeats neither endpoint.
func TestDescribeAnHTTPCheck(t *testing.T) {
	report := func(check string) []byte {
		return []byte(`{"check":{"status":"succeeded","adapter":{"name":"adapter-http","version":"0.30.0","digest":"` + testImageDigest + `"},` + check + `}}`)
	}
	spec := func(endpoint, checkPath string) sourceSpec {
		s := sourceSpec{shape: "http", argv: []string{"adapter-http", "--endpoint=" + endpoint, "--paths=/a,/health"}}
		if checkPath != "" {
			s.check = []string{"--check-path=" + checkPath}
		}
		return s
	}
	const tls = `"peerIdentity":"tls:sha256:` + "ab" + `"`
	got, err := describeSourceCheck(spec("https://records.example/api", "/health"), report(`"endpoint":"https://records.example/api",`+tls+`,"probe":{"path":"/health","status":204}`))
	if err != nil || got != "adapter-http:0.30.0 ("+testImageDigest+"): endpoint https://records.example/api, peer tls:sha256:ab; GET /health answered 204" {
		t.Fatalf("a check path answered: %q %v", got, err)
	}
	got, err = describeSourceCheck(spec("http://127.0.0.1:8080", ""), report(`"endpoint":"http://127.0.0.1:8080"`))
	if err != nil || got != "adapter-http:0.30.0 ("+testImageDigest+"): endpoint http://127.0.0.1:8080; reached" {
		t.Fatalf("the connection alone: %q %v", got, err)
	}
	for _, c := range []struct {
		name  string
		spec  sourceSpec
		check string
		want  string
	}{
		{"another endpoint", spec("https://records.example/api", ""), `"endpoint":"https://elsewhere.example/api"`, "the endpoint the adapter reports is not the one the source was given"},
		{"no endpoint", spec("https://records.example/api", ""), `"peerIdentity":"x"`, "the endpoint the adapter reports is not the one the source was given"},
		{"a probe not asked for", spec("https://records.example/api", ""), `"endpoint":"https://records.example/api","probe":{"path":"/health","status":200}`, "a check path the source was not given"},
		{"no probe where one was asked", spec("https://records.example/api", "/health"), `"endpoint":"https://records.example/api"`, "does not report the check path the source was given"},
		{"a probe of another path", spec("https://records.example/api", "/health"), `"endpoint":"https://records.example/api","probe":{"path":"/a","status":200}`, "does not report the check path the source was given"},
		{"a probe that failed", spec("https://records.example/api", "/health"), `"endpoint":"https://records.example/api","probe":{"path":"/health","status":401}`, "the check path answered 401"},
		{"a failed check", spec("https://records.example/api", ""), `"endpoint":"https://records.example/api"`, ""},
	} {
		text := report(c.check)
		if c.name == "a failed check" {
			text = []byte(strings.Replace(string(text), `"succeeded"`, `"failed"`, 1))
			c.want = `the adapter reported "failed", not a success`
		}
		_, err := describeSourceCheck(c.spec, text)
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: want %q, got %v", c.name, c.want, err)
			continue
		}
		if strings.Contains(err.Error(), "records.example") || strings.Contains(err.Error(), "elsewhere") {
			t.Errorf("%s: the refusal repeats an endpoint: %v", c.name, err)
		}
	}
	// Every other shape is read as before.
	if got, err := describeSourceCheck(sourceSpec{shape: "airbyte", argv: []string{"adapter-airbyte"}}, []byte(airbyteReport)); err != nil || !strings.HasSuffix(got, "answered succeeded: Connected") {
		t.Fatalf("an airbyte check: %q %v", got, err)
	}
}

// connect writes the entry of an http platform after the adapter's check
// answered: the source checked is adapter-http as the platform's user with
// the check path, nothing is captured, and the entry written is the one
// serve derives the same source from. An endpoint for the platform is
// refused before anything is checked.
func TestConnectAnHTTPPlatform(t *testing.T) {
	binding := strings.Replace(recordsBinding, `"platform": "records"`, `"platform": "postgres"`, 1)
	f := newConnectFixture(t, binding, ``)
	f.reports["http"] = `{"check":{"status":"succeeded","adapter":{"name":"adapter-http","version":"0.30.0","digest":"` + testImageDigest + `"},"endpoint":"https://records.example/api","peerIdentity":"tls:sha256:ab","probe":{"path":"/health","status":200}}}`
	req := f.request()
	req.credentials = map[string]string{"live": f.credentials}
	refused := req
	if _, err := connect(context.Background(), refused, f.host, f.check); err == nil || !strings.Contains(err.Error(), "platform warehouse: names an endpoint, and binding postgres@") || len(f.asked) != 0 {
		t.Fatalf("an endpoint for an http platform: %v, asked %d", err, len(f.asked))
	}
	req.endpoint = ""
	out, err := connect(context.Background(), req, f.host, f.check)
	if err != nil {
		t.Fatal(err)
	}
	if len(f.asked) != 1 || f.asked[0].shape != "http" || f.asked[0].user != "engine-warehouse" || !reflect.DeepEqual(f.asked[0].check, []string{"--check-path=/health"}) {
		t.Fatalf("one check, of adapter-http as the platform's user, with the check path and no capture: %+v", f.asked)
	}
	if len(out.answers) != 1 || out.answers[0] != "warehouse/live: adapter-http:0.30.0 ("+testImageDigest+"): endpoint https://records.example/api, peer tls:sha256:ab; GET /health answered 200" {
		t.Fatalf("the answer: %q", out.answers)
	}
	text := f.fileText(t)
	if strings.Contains(text, "descriptors") || strings.Contains(text, `"endpoint"`) || !strings.Contains(text, "\"engineVersion\": \"1\",") {
		t.Fatalf("no descriptors, no endpoint, the version as found: %s", text)
	}
	cfg, bindings, err := loadEngineConfig(f.config, stubAccounts(stubUsers))
	if err != nil {
		t.Fatal(err)
	}
	if live := deriveSources(cfg, bindings)["warehouse/live"]; live.shape != "http" || !reflect.DeepEqual(live.argv[1:], f.asked[0].argv[1:]) {
		t.Fatalf("serve derives the source connect checked: %+v", live)
	}
	// --replace with a report from another endpoint writes nothing.
	before := f.fileText(t)
	f.reports["http"] = strings.Replace(f.reports["http"], "records.example", "elsewhere.example", 1)
	req.replace = true
	if _, err := connect(context.Background(), req, f.host, f.check); err == nil || !strings.Contains(err.Error(), "warehouse/live: the endpoint the adapter reports is not the one the source was given") {
		t.Fatalf("another endpoint answered: %v", err)
	}
	if f.fileText(t) != before {
		t.Fatal("a refused connect wrote the file")
	}
}

// The MCP frontend lists no tool of an http platform, which has none, and
// starts: only the seal tool is listed, and nothing of the platform is
// held to an owner taxonomy or a descriptor snapshot.
func TestTheMCPFrontendListsNoToolOfAnHTTPPlatform(t *testing.T) {
	b, err := parseBinding([]byte(recordsBinding))
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "engine.json")
	if err := os.WriteFile(path, []byte("{}"), 0o640); err != nil {
		t.Fatal(err)
	}
	cfg := engineConfig{
		authority: "gateway:test", listen: "127.0.0.1:8787", configPath: path,
		platforms: []platformConfig{{name: "records", binding: "records@" + digestOf(recordsBinding)}},
		mcp:       &mcpConfig{listen: "127.0.0.1:0", resource: "https://engine.test/mcp", sessions: 4, idleSeconds: 60, concurrency: 2, callsPerMinute: 100},
	}
	server, err := newMCPServer(cfg, map[string]binding{"records": b}, nil, path)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(server.order, []string{mcpSealTool}) || len(server.tools) != 1 {
		t.Fatalf("the seal tool alone: %v", server.order)
	}
}

// posture reports the http source among the configuration's sources, as
// the platform's own user.
func TestPostureCountsAnHTTPSource(t *testing.T) {
	catalog := catalogWith(t, map[string]string{"records": recordsBinding})
	text := engineJSON(t, catalog, ``, platformJSONFor(t, "records", "records@"+digestOf(recordsBinding), "engine-docs", ``, "live"))
	path := filepath.Join(t.TempDir(), "engine.json")
	if err := os.WriteFile(path, []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
	in, err := postureOfConfig(path, stubAccounts(stubUsers))
	if err != nil {
		t.Fatal(err)
	}
	if live, ok := in.sources["records/live"]; !ok || len(in.sources) != 1 || live.user != "engine-docs" || live.shape != "http" {
		t.Fatalf("the http source, as the platform's user: %+v", in.sources)
	}
}
