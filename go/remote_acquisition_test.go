package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// endpointCase is one endpoint of the table the endpoint form's four
// implementations answer to (testdata/remote-endpoints/cases.json): the
// signer's, which gateway verify and the engine use; verify-ts's; and the
// adapter's, adapters/mcphttp.EndpointProblem.
type endpointCase struct {
	Rule     string `json:"rule"`
	Endpoint string `json:"endpoint"`
	PadTo    int    `json:"padTo"`
}

// text is the endpoint the case names, extended with "a" to its padTo.
func (c endpointCase) text() string {
	if c.PadTo > len(c.Endpoint) {
		return c.Endpoint + strings.Repeat("a", c.PadTo-len(c.Endpoint))
	}
	return c.Endpoint
}

// endpointCases reads the table, held to its own rule: every case names a
// rule the table lists, and every rule has a case on each side.
func endpointCases(t *testing.T) (accepted, refused []endpointCase) {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "testdata", "remote-endpoints", "cases.json"))
	if err != nil {
		t.Fatal(err)
	}
	var table struct {
		About    []string       `json:"about"`
		Rules    []string       `json:"rules"`
		Accepted []endpointCase `json:"accepted"`
		Refused  []endpointCase `json:"refused"`
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&table); err != nil {
		t.Fatal(err)
	}
	for _, rule := range table.Rules {
		var sides [2]int
		for side, cases := range [][]endpointCase{table.Accepted, table.Refused} {
			for _, c := range cases {
				if c.Rule == rule {
					sides[side]++
				}
			}
		}
		if sides[0] == 0 || sides[1] == 0 {
			t.Fatalf("rule %s has %d accepted and %d refused cases; every rule has one on each side", rule, sides[0], sides[1])
		}
	}
	for _, c := range append(append([]endpointCase{}, table.Accepted...), table.Refused...) {
		if !contains(table.Rules, c.Rule) {
			t.Fatalf("%q names the rule %q, which the table does not list", c.Endpoint, c.Rule)
		}
	}
	return table.Accepted, table.Refused
}

// The endpoint form a remote MCP server is named by, in a receipt and in a
// binding: the table's cases, which the adapter's own rule answers to as
// well, so the adapter's endpoint never leaves it.
func TestRemoteEndpointForm(t *testing.T) {
	accepted, refused := endpointCases(t)
	for _, c := range accepted {
		if !isRemoteEndpoint(c.text()) {
			t.Errorf("%s: %q refused", c.Rule, c.text())
		}
	}
	for _, c := range refused {
		if isRemoteEndpoint(c.text()) {
			t.Errorf("%s: %q accepted", c.Rule, c.text())
		}
	}
}

// remoteEnvelope is an envelope as adapter-mcp writes it for a remote
// server: the eight members, transport and server, the URL as the endpoint
// and the TLS identity the answer came under.
func remoteEnvelope() (map[string]any, map[string]any) {
	acquisition := map[string]any{
		"adapter":       map[string]any{"name": "adapter-mcp", "version": "0", "digest": envelopeDigest("adapter-mcp")},
		"endpoint":      "https://mcp.example/api/mcp",
		"statement":     `{"arguments":{"id":7},"tool":"lookup"}`,
		"snapshot":      nil,
		"peerIdentity":  "tls:" + envelopeDigest("peer"),
		"schema":        nil,
		"upstreamToken": nil,
		"observedAt":    "2026-10-13T10:00:00Z",
		"transport":     "http",
		"server":        map[string]any{"name": "remote", "version": "1.4"},
	}
	return map[string]any{"acquisition": acquisition, "result": map[string]any{"content": []any{}}}, acquisition
}

// A remote acquisition is recorded as reported, transport and server with
// the rest, and the store verifies; an envelope whose remote members are
// out of their form, or reported by another shape than mcp, is refused as
// not an envelope, with nothing minted.
func TestRemoteMembersAreRecordedAndHeldToTheirForm(t *testing.T) {
	service, server := shapedService(t, "mcp")
	env, reported := remoteEnvelope()
	t.Setenv(envSourceEnvelope, envelopeText(t, env))
	code, first := post(t, server, "/acquire", `{"session":"remote-1","source":"history","arguments":{}}`)
	if code != http.StatusOK {
		t.Fatalf("acquire failed: %d %v", code, first)
	}
	acquisition := first["receipt"].(map[string]any)["acquisition"].(map[string]any)
	for _, name := range []string{"adapter", "endpoint", "peerIdentity", "transport", "server", "observedAt"} {
		if !reflect.DeepEqual(acquisition[name], reported[name]) {
			t.Fatalf("%s recorded as %v, reported %v", name, acquisition[name], reported[name])
		}
	}
	if len(acquisition) != 11 || acquisition["shape"] != "mcp" {
		t.Fatalf("the nine members of an acquisition and the two a remote server adds: %v", acquisition)
	}
	// Over plaintext loopback no identity is established.
	env, reported = remoteEnvelope()
	reported["endpoint"], reported["peerIdentity"] = "http://127.0.0.1:8080/mcp", nil
	t.Setenv(envSourceEnvelope, envelopeText(t, env))
	if code, body := post(t, server, "/acquire", `{"session":"remote-1","source":"history","arguments":{}}`); code != http.StatusOK {
		t.Fatalf("a loopback acquisition: %d %v", code, body)
	}
	// Every endpoint of the table's accepted cases is signed, and the store
	// verifies below; every refused one is refused as not an envelope, with
	// nothing minted.
	accepted, refused := endpointCases(t)
	withEndpoint := func(endpoint string) map[string]any {
		env, acq := remoteEnvelope()
		acq["endpoint"] = endpoint
		if strings.HasPrefix(endpoint, "http://") {
			acq["peerIdentity"] = nil
		}
		return env
	}
	for _, c := range accepted {
		t.Setenv(envSourceEnvelope, envelopeText(t, withEndpoint(c.text())))
		if code, body := post(t, server, "/acquire", `{"session":"remote-1","source":"history","arguments":{}}`); code != http.StatusOK {
			t.Fatalf("%s: %q, of the form, refused: %d %v", c.Rule, c.text(), code, body)
		}
	}
	for _, c := range refused {
		t.Setenv(envSourceEnvelope, envelopeText(t, withEndpoint(c.text())))
		code, body := post(t, server, "/acquire", `{"session":"remote-2","source":"history","arguments":{}}`)
		if code == http.StatusOK || !strings.Contains(fmt.Sprint(body["error"]), "not an envelope") {
			t.Fatalf("%s: %q must be refused as not an envelope: %d %v", c.Rule, c.text(), code, body)
		}
	}
	for _, tc := range []struct {
		name   string
		mutate func(acq map[string]any)
	}{
		{"transport without server", func(acq map[string]any) { delete(acq, "server") }},
		{"server without transport", func(acq map[string]any) { delete(acq, "transport") }},
		{"a transport outside its enumeration", func(acq map[string]any) { acq["transport"] = "sse" }},
		{"a transport that is not a string", func(acq map[string]any) { acq["transport"] = true }},
		{"a server that is not an object", func(acq map[string]any) { acq["server"] = "remote 1.4" }},
		{"a server without a version", func(acq map[string]any) { delete(acq["server"].(map[string]any), "version") }},
		{"a server whose name is a number", func(acq map[string]any) { acq["server"].(map[string]any)["name"] = 7 }},
		{"a server with a member the signer did not ask for", func(acq map[string]any) { acq["server"].(map[string]any)["vendor"] = "x" }},
		{"an endpoint off its form", func(acq map[string]any) { acq["endpoint"] = "warehouse.internal:5432" }},
		{"an http endpoint off loopback", func(acq map[string]any) { acq["endpoint"] = "http://mcp.example/mcp"; acq["peerIdentity"] = nil }},
		{"an endpoint with a user", func(acq map[string]any) { acq["endpoint"] = "https://user@mcp.example/mcp" }},
		{"a null endpoint", func(acq map[string]any) { acq["endpoint"] = nil }},
		{"no identity over TLS", func(acq map[string]any) { acq["peerIdentity"] = nil }},
		{"an identity in upper case", func(acq map[string]any) { acq["peerIdentity"] = strings.ToUpper(acq["peerIdentity"].(string)) }},
		{"an identity of another kind", func(acq map[string]any) { acq["peerIdentity"] = "spiffe://example/mcp" }},
		{"an identity in the clear", func(acq map[string]any) { acq["endpoint"] = "http://127.0.0.1:8080/mcp" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			env, acq := remoteEnvelope()
			tc.mutate(acq)
			t.Setenv(envSourceEnvelope, envelopeText(t, env))
			code, body := post(t, server, "/acquire", `{"session":"remote-2","source":"history","arguments":{}}`)
			if code == http.StatusOK || !strings.Contains(fmt.Sprint(body["error"]), "not an envelope") {
				t.Fatalf("must be refused as not an envelope: %d %v", code, body)
			}
		})
	}
	if code, body := post(t, server, "/seal", `{"session":"remote-1"}`); code != http.StatusOK {
		t.Fatalf("seal failed: %d %v", code, body)
	}
	report, err := verifyWithRegistry(service.storeRoot, service.regPath, "gateway:test", service.publicKey)
	if err != nil || !report.OK {
		t.Fatalf("a store of remote acquisitions verifies, and no refusal minted: %v %+v", err, report)
	}
	// Another shape reports no remote server: an http adapter's envelope
	// carrying the two is refused.
	_, httpServer := shapedService(t, "http")
	env, _ = remoteEnvelope()
	t.Setenv(envSourceEnvelope, envelopeText(t, env))
	if code, body := post(t, httpServer, "/acquire", `{"session":"remote-3","source":"history","arguments":{}}`); code == http.StatusOK ||
		!strings.Contains(fmt.Sprint(body["error"]), "members of shape mcp alone") {
		t.Fatalf("an http-shaped source reporting a remote MCP server: %d %v", code, body)
	}
}

// A binding's mcp operation names a remote server by its URL, the member
// of the operation's credentials file sent as the bearer, and optionally
// fixed headers; the engine derives adapter-mcp's remote form for it, and
// the write's endpoint is the URL.
const remoteBinding = `{
  "bindingVersion": "1",
  "platform": "remote",
  "operations": {
    "live": {"shape": "mcp", "server": {"url": "https://mcp.example/api/mcp", "bearer": "TOKEN", "headers": ["X-MCP-Readonly=true"]}, "tools": ["lookup"], "probe": {"tool": "lookup"}, "licence": "MIT"},
    "write": {"shape": "mcp", "server": {"url": "https://mcp.example/api/mcp", "bearer": "WRITE_TOKEN"}, "tools": ["update"], "licence": "MIT"}
  }
}`

func TestEngineDerivesARemoteServer(t *testing.T) {
	catalog := catalogWith(t, map[string]string{"remote": remoteBinding})
	bin := abs(t, t.TempDir(), "bin")
	text := engineJSON(t, catalog, `,"adapters":"`+bin+`","runtime":"podman"`,
		platformJSONFor(t, "remote", "remote@"+digestOf(remoteBinding), "engine-desk", `,"endpoint":"desk.internal","write":true`, "live", "write"))
	cfg, sources, err := load(t, text)
	if err != nil {
		t.Fatal(err)
	}
	creds := cfg.platforms[0].credentials
	adapter := filepath.Join(cfg.adapters, "adapter-mcp")
	live, write := sources["remote/live"], sources["remote/write"]
	if want := []string{adapter, "--url=https://mcp.example/api/mcp", "--credentials=" + creds["live"], "--bearer=TOKEN", "--header=X-MCP-Readonly=true", "--tools=lookup"}; !reflect.DeepEqual(live.argv, want) ||
		!reflect.DeepEqual(live.check, []string{"--probe=lookup"}) || live.shape != "mcp" {
		t.Fatalf("live:\n got %q %q\nwant %q", live.argv, live.check, want)
	}
	if want := []string{adapter, "--url=https://mcp.example/api/mcp", "--credentials=" + creds["write"], "--bearer=WRITE_TOKEN", "--tools=update", "--error-results"}; !reflect.DeepEqual(write.argv, want) {
		t.Fatalf("write:\n got %q\nwant %q", write.argv, want)
	}
	if write.endpoint != "https://mcp.example/api/mcp" {
		t.Fatalf("the write's endpoint is the URL it went to, not the platform's: %q", write.endpoint)
	}
}

func TestRemoteBindingRefusals(t *testing.T) {
	op := func(server string) string {
		return `{"bindingVersion":"1","platform":"p","operations":{"live":{"shape":"mcp","server":` + server + `,"tools":["q"],"licence":"MIT"}}}`
	}
	for server, want := range map[string]string{
		`{"url":"https://mcp.example/mcp","bearer":"T","image":"x@` + testImageDigest + `"}`:  `unknown member "image"`,
		`{"url":"https://mcp.example/mcp","bearer":"T","args":["--x"]}`:                       `unknown member "args"`,
		`{"url":"https://mcp.example/mcp"}`:                                                   `missing member "bearer"`,
		`{"url":"https://mcp.example/mcp","bearer":""}`:                                       "server.bearer names the credentials member",
		`{"url":"http://mcp.example/mcp","bearer":"T"}`:                                       "server.url must be https",
		`{"url":"https://user@mcp.example/mcp","bearer":"T"}`:                                 "server.url must be https",
		`{"url":"https://mcp.example/mcp?key=k","bearer":"T"}`:                                "server.url must be https",
		`{"url":"https://mcp.example/%zz","bearer":"T"}`:                                      "every '%' followed by two hexadecimal digits",
		`{"url":7,"bearer":"T"}`:                                                              "server.url must be https",
		`{"url":"https://mcp.example/mcp","bearer":"T","headers":[]}`:                         "server.headers, when present, is a non-empty array",
		`{"url":"https://mcp.example/mcp","bearer":"T","headers":["X-Read-Only"]}`:            "server.headers must be NAME=VALUE",
		`{"url":"https://mcp.example/mcp","bearer":"T","headers":["Authorization=Bearer x"]}`: "server.headers names Authorization",
		`{"url":"https://mcp.example/mcp","bearer":"T","headers":["mcp-session-id=s"]}`:       "server.headers names mcp-session-id",
	} {
		if _, err := parseBinding([]byte(op(server))); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: want %q, got %v", server, want, err)
		}
	}
	// The table's endpoints, as a binding's url: each accepted case starts
	// and each refused one is refused before the engine starts, as written
	// and as a template's text. A case with a brace is a template's
	// placeholder in a binding, and is held as one elsewhere.
	accepted, refused := endpointCases(t)
	quoted := func(endpoint string) string {
		text, _ := json.Marshal(endpoint)
		return string(text)
	}
	for _, c := range accepted {
		if strings.ContainsAny(c.Endpoint, "{}") {
			continue
		}
		if _, err := parseBinding([]byte(op(`{"url":` + quoted(c.text()) + `,"bearer":"T"}`))); err != nil {
			t.Errorf("%s: %q, of the form, refused: %v", c.Rule, c.text(), err)
		}
		if err := urlTemplateProblem(c.text()); err != nil {
			t.Errorf("%s: %q, of the form, refused as a template: %v", c.Rule, c.text(), err)
		}
	}
	for _, c := range refused {
		if _, err := parseBinding([]byte(op(`{"url":` + quoted(c.text()) + `,"bearer":"T"}`))); err == nil || !strings.Contains(err.Error(), "server.url must be https") {
			t.Errorf("%s: %q: want a refusal of server.url, got %v", c.Rule, c.text(), err)
		}
		if err := urlTemplateProblem(c.text()); err == nil {
			t.Errorf("%s: %q accepted as a template", c.Rule, c.text())
		}
		// A template whose placeholders resolve, with the URL as the table
		// gives it: the resolved URL is held to the form again. An empty URL
		// names no remote server, and is refused as written above.
		if c.text() == "" {
			continue
		}
		b := binding{platform: "p", live: &operation{shape: "mcp", url: c.text(), tools: []string{"{tool}"}}}
		if _, err := resolveParameters(b, map[string]string{"tool": "q"}, "p@x"); err == nil || !strings.Contains(err.Error(), "of the endpoint form") {
			t.Errorf("%s: %q: want the resolved URL refused, got %v", c.Rule, c.text(), err)
		} else if len(c.text()) > len("https://h/") && strings.Contains(err.Error(), c.text()) {
			t.Errorf("%s: the refusal repeats the URL: %v", c.Rule, err)
		}
	}
}

// A binding's URL may carry, by mistake, what is never to be shown -- a
// credential pasted into its path -- so no refusal of it repeats it: not as
// written, not as a template, not a placeholder's text, not as the
// platform's parameters resolve it, and not as a descriptors pin or a
// connect check compares it. Each refusal names the binding, the operation
// and the rule, or the endpoints compared by their roles; the marker is in
// the URL's path, and in no error.
func TestARefusalOfABindingsURLRepeatsNothingOfIt(t *testing.T) {
	const marker = "MARKER-NOT-TO-BE-SHOWN"
	server := func(url string) string {
		return `{"bindingVersion":"1","platform":"p","operations":{"live":{"shape":"mcp","server":{"url":"` + url + `","bearer":"T"},"tools":["q"],"licence":"MIT"}}}`
	}
	for _, tc := range []struct{ name, url, want string }{
		{"out of the form as written", "https://mcp.example/" + marker + "/?q", "server.url must be https"},
		{"a template out of the form", "https://mcp.example/" + marker + "/{x}?q", "must be of the endpoint form with its placeholders filled"},
		{"a template naming the host", "https://" + marker + "{x}/mcp", "must write its host as it is"},
		{"a template of a scheme not written", "{x}://mcp.example/" + marker, "must begin with its scheme written as it is"},
		{"a placeholder not a parameter's name", "https://mcp.example/{" + marker + "}", "names a placeholder which is not a parameter's name"},
		{"a } closing no placeholder", "https://mcp.example/" + marker + "}", "holds a } that closes no placeholder"},
		{"a { no } closes", "https://mcp.example/" + marker + "{x", "holds a { that no } closes"},
	} {
		_, err := parseBinding([]byte(server(tc.url)))
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: want a refusal saying %q, got %v", tc.name, tc.want, err)
		} else if strings.Contains(err.Error(), marker) {
			t.Errorf("%s: the refusal repeats the URL: %v", tc.name, err)
		}
	}
	// Resolved: past the form's length by its parameters, and out of the
	// form once filled.
	template := "https://mcp.example/" + marker + "/" + strings.Repeat("{tenant}/", 10)
	b, err := parseBinding([]byte(server(template)))
	if err != nil {
		t.Fatal(err)
	}
	tenant := strings.Repeat("a", maxParameterValue)
	if err := parameterProblem("tenant", tenant); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		b    binding
		want string
	}{
		{"resolved past the form's length", b, "more than the 2048 of the endpoint form"},
		{"resolved out of the form", binding{platform: "p", live: &operation{shape: "mcp", url: "https://mcp.example/" + marker + "/{tenant}?q", tools: []string{"q"}}}, "is not of the endpoint form"},
	} {
		_, err := resolveParameters(tc.b, map[string]string{"tenant": tenant}, "p@sha256:0")
		if err == nil || !strings.Contains(err.Error(), tc.want) || !strings.Contains(err.Error(), "binding p@sha256:0: the live operation's URL") {
			t.Errorf("%s: want a refusal naming the binding, the operation and %q, got %v", tc.name, tc.want, err)
		} else if strings.Contains(err.Error(), marker) || strings.Contains(err.Error(), tenant) {
			t.Errorf("%s: the refusal repeats the URL: %v", tc.name, err)
		}
	}
	// And at start, as the engine refuses the platform.
	catalog := catalogWith(t, map[string]string{"p": server(template)})
	text := engineJSON(t, catalog, ``, platformJSONFor(t, "p", "p@"+digestOf(server(template)), "engine-desk", `,"parameters":{"tenant":"`+tenant+`"}`, "live"))
	text = strings.Replace(text, `"engineVersion":"1"`, `"engineVersion":"8"`, 1)
	if _, _, err := load(t, text); err == nil || !strings.Contains(err.Error(), "more than the 2048 of the endpoint form") {
		t.Fatalf("the engine starts on a resolved URL past the form: %v", err)
	} else if strings.Contains(err.Error(), marker) {
		t.Fatalf("the start-up refusal repeats the URL: %v", err)
	}
	// A descriptors pin compared with the endpoint the parameters resolve
	// to, and a connect check's reported endpoint compared with the URL the
	// source was given: each refusal names the endpoints by their roles.
	pinned, reached := "https://mcp.example/"+marker+"/pinned", "https://mcp.example/"+marker+"/reached"
	for _, tc := range []struct {
		name     string
		snapshot snapshot
		url      string
		want     string
	}{
		{"a pin of another endpoint", snapshot{endpoint: pinned}, reached, "now reaches another endpoint than the one its pinned descriptors were captured at"},
		{"a pin of a remote server for a server the adapter runs", snapshot{endpoint: pinned}, "", "the pinned descriptors were captured at a remote server"},
		{"a pin naming no endpoint for a remote server", snapshot{}, reached, "names no endpoint, and the platform's operation reaches a remote server"},
	} {
		err := snapshotEndpointProblem(tc.snapshot, &operation{shape: "mcp", url: tc.url})
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: want a refusal saying %q, got %v", tc.name, tc.want, err)
		} else if strings.Contains(err.Error(), marker) {
			t.Errorf("%s: the refusal repeats an endpoint: %v", tc.name, err)
		}
	}
	report := func(endpoint string) []byte {
		return []byte(`{"check":{"adapter":{"name":"adapter-mcp","version":"0","digest":"sha256:0"},"status":"succeeded","protocolVersion":"2025-06-18","endpoint":"` + endpoint + `","tools":["q"]}}`)
	}
	for _, tc := range []struct{ name, reported, given, want string }{
		{"a check of another endpoint", reached, pinned, "the endpoint the adapter reports is not the one the source was given"},
		{"a check reporting an endpoint for a server the adapter runs", reached, "", "the adapter reports an endpoint for a server it runs"},
	} {
		_, err := describeCheck("mcp", report(tc.reported), tc.given)
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: want a refusal saying %q, got %v", tc.name, tc.want, err)
		} else if strings.Contains(err.Error(), marker) {
			t.Errorf("%s: the refusal repeats an endpoint: %v", tc.name, err)
		}
	}
}
