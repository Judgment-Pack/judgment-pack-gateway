package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// The write-back platforms (issue #248): a catalog binding whose write
// operation names a remote MCP server by a URL template, filled from the
// platform's parameters (engineVersion 8; ADR-0015, amended 2026-10-13),
// and whose tools are held to decision policies (ADR-0011, ADR-0012; the
// Azure DevOps dispatcher by a fixed action and a closed argument set,
// ADR-0016, engineVersion 9, and the shape of its updates, ADR-0018,
// engineVersion 10). No
// test here reaches a real service: every remote server is the in-process
// stand-in below, and the live checks at the end run only when their
// environment names an organization or a workspace, and are skipped
// otherwise.

// writeStandIn is a remote MCP server over Streamable HTTP in the test's
// own process: it issues a session and holds every later request to it,
// lists the tools it is given, and answers a call by echoing what it was
// sent -- or, when refuse is set, once, as a target refusing the write, an
// error result; or, while failure is set, as a failure of the protocol
// after the call: an HTTP error status, a JSON-RPC error, or a result that
// repeats the bearer -- and refuses every write it is sent under the
// read-only header, as the Azure DevOps server's read-only mode would. It records
// every request: the verb, the path, the JSON-RPC method, the read-only
// header and the bearer.
type writeStandIn struct {
	*httptest.Server
	tools   string
	mu      sync.Mutex
	seen    []standInRequest
	refuse  bool
	failure string // "http", "rpc" or "echo"; "" answers the call
}

type standInRequest struct {
	verb, path, method, readonly, bearer string
	params                               json.RawMessage
}

func newWriteStandIn(t *testing.T, tools string) *writeStandIn {
	t.Helper()
	s := &writeStandIn{tools: tools}
	s.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var m struct {
			ID     json.RawMessage `json:"id"`
			Method string          `json:"method"`
			Params json.RawMessage `json:"params"`
		}
		json.Unmarshal(body, &m)
		s.mu.Lock()
		s.seen = append(s.seen, standInRequest{verb: r.Method, path: r.URL.Path, method: m.Method, readonly: r.Header.Get("X-MCP-Readonly"), bearer: r.Header.Get("Authorization"), params: m.Params})
		refuse := s.refuse && m.Method == "tools/call"
		if refuse {
			s.refuse = false
		}
		failure := s.failure
		s.mu.Unlock()
		if m.Method != "initialize" && r.Header.Get("Mcp-Session-Id") != "write-session" {
			http.Error(w, "unknown session", http.StatusNotFound)
			return
		}
		if r.Method == http.MethodDelete {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		if len(m.ID) == 0 {
			w.WriteHeader(http.StatusAccepted)
			return
		}
		if m.Method == "tools/call" && failure != "" {
			w.Header().Set("Content-Type", "application/json")
			switch failure {
			case "http":
				http.Error(w, "write-secret-token", http.StatusServiceUnavailable)
			case "rpc":
				io.WriteString(w, `{"jsonrpc":"2.0","id":`+string(m.ID)+`,"error":{"code":-32000,"message":"failed"}}`)
			case "echo":
				io.WriteString(w, `{"jsonrpc":"2.0","id":`+string(m.ID)+`,"result":{"content":[{"type":"text","text":"write-secret-token"}]}}`)
			}
			return
		}
		var result string
		switch m.Method {
		case "initialize":
			w.Header().Set("Mcp-Session-Id", "write-session")
			result = `{"protocolVersion":"2025-06-18","capabilities":{"tools":{}},"serverInfo":{"name":"write-standin","version":"1.0"}}`
		case "tools/list":
			result = `{"tools":` + s.tools + `}`
		case "tools/call":
			switch {
			case strings.EqualFold(r.Header.Get("X-MCP-Readonly"), "true"):
				result = `{"content":[{"type":"text","text":"read-only: this server makes no write"}],"isError":true}`
			case refuse:
				result = `{"content":[{"type":"text","text":"the target refused the write: the revision has changed"}],"isError":true}`
			default:
				result = `{"content":[{"type":"text","text":"written"}],"structuredContent":{"params":` + string(m.Params) + `}}`
			}
		}
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"jsonrpc":"2.0","id":`+string(m.ID)+`,"result":`+result+`}`)
	}))
	t.Cleanup(s.Close)
	return s
}

func (s *writeStandIn) requests() []standInRequest {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]standInRequest(nil), s.seen...)
}

func (s *writeStandIn) forget() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.seen = nil
}

// historicalCatalogFile preserves exact V1 bytes for historical engine/policy fixtures.
func historicalCatalogFile(t *testing.T, name string) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "testdata", "catalog-v1", name+".json"))
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

// atStandIn is a shipped binding with its URL's scheme and host -- from --
// put at the stand-in's: the binding's tools, bearer, headers and the rest
// of its template are the shipped file's.
func atStandIn(t *testing.T, name, from, to string) string {
	t.Helper()
	text := historicalCatalogFile(t, name)
	if !strings.Contains(text, `"url": "`+from) {
		t.Fatalf("catalog/%s.json holds no URL beginning %s", name, from)
	}
	return strings.Replace(text, `"url": "`+from, `"url": "`+to, 1)
}

// The tools each stand-in lists: the shipped bindings' tools, each with a
// description and an input schema the descriptors capture can keep.
const (
	boardsTools = `[` +
		`{"name":"wit_work_item_write","description":"Write operations for work items. Use the action parameter to specify the operation.","inputSchema":{"type":"object","properties":{"action":{"type":"string"},"id":{"type":"integer"},"project":{"type":"string"}},"required":["action"]}},` +
		`{"name":"wit_work_item_comment_write","description":"Write operations for work item comments.","inputSchema":{"type":"object","properties":{"action":{"type":"string"},"workItemId":{"type":"integer"},"text":{"type":"string"}},"required":["action"]}},` +
		`{"name":"wit_work_item_link_write","description":"Write operations for work item links.","inputSchema":{"type":"object","properties":{"action":{"type":"string"}},"required":["action"]}},` +
		`{"name":"wit_work_item","description":"Retrieve work item data.","inputSchema":{"type":"object","properties":{"action":{"type":"string"},"id":{"type":"integer"}},"required":["action"]}}]`
	ledgerTools = `[{"name":"main__decisions__record_approval","description":"Records an approval of a case at a revision.","inputSchema":{"type":"object","properties":{"case_id":{"type":"string"},"revision":{"type":"integer"}},"required":["case_id","revision"]}}]`
)

// writePlatformCase is one write-back platform as these tests configure it.
type writePlatformCase struct {
	variant    string // what sets the case apart from another of its catalog; "" for the first
	version    string // the configuration's engineVersion
	platform   string // the configured platform's name
	catalog    string // the shipped catalog file's name
	from       string // the shipped URL's scheme and host, put at the stand-in's
	path       string // the resolved URL's path at the stand-in
	parameters string // the platform's parameters, a JSON object; the stand-in's address stands for a workspace
	tool       string // the write tool, resolved
	tools      string // what the stand-in lists
	facts      string // the record's facts
	arguments  string // the write's arguments, held to the facts
	hold       string // the policy's members that hold the arguments: bind, and fix, shape and closed
	mismatched []mismatchedWrite
	// admitted are writes other than arguments that the policy admits, each
	// sent once: what it holds, recorded where it is less than one request.
	admitted []string
}

// mismatchedWrite is a write the policy refuses at policy-bind, by the
// sentence want.
type mismatchedWrite struct {
	arguments, want string
}

// boardsArguments is the write the Azure DevOps cases hold: work item 42 at
// revision 3, the revision tested first, then the state set to the one the
// outcome maps to.
const boardsArguments = `{"action":"update","id":42,"updates":[{"op":"test","path":"/rev","value":3},{"op":"replace","path":"/fields/System.State","value":"Approved"}]}`

// boardsHold is the Azure DevOps policy of ADR-0016: action fixed to update,
// the revision test first and the state the outcome maps to fixed, the work
// item's id and the tested revision bound to the record's, and closed, so
// that nothing else may be asked.
const boardsHold = `"fix":[{"argument":"/action","value":"update"},{"argument":"/updates/0/op","value":"test"},{"argument":"/updates/0/path","value":"/rev"},` +
	`{"argument":"/updates/1","value":{"op":"replace","path":"/fields/System.State","value":"Approved"}}],` +
	`"bind":[{"argument":"/id","fact":"/workItem/id"},{"argument":"/updates/0/value","fact":"/workItem/rev"}],"closed":true`

// boardsShape is what ADR-0018 adds to it, and the worked policy of
// engine-config.md, "The write-back platforms", holds: updates is an array,
// of at most two elements, so with the second fixed, of exactly two.
const boardsShape = `,"shape":[{"pointer":"/updates","type":"array","maxLength":2}]`

// boardsObjectUpdates is the write the review of #265 found: an object whose
// members are named "0" and "1" in place of the updates array, which RFC 6901
// reads as that array's elements, a numeric token on an object naming a
// member.
const boardsObjectUpdates = `{"action":"update","id":42,"updates":{"0":{"op":"test","path":"/rev","value":3},"1":{"op":"replace","path":"/fields/System.State","value":"Approved"}}}`

// boardsRefused are the writes both Azure DevOps policies refuse, each by the
// same sentence.
var boardsRefused = []mismatchedWrite{
	// another work item
	{`{"action":"update","id":43,"updates":[{"op":"test","path":"/rev","value":3},{"op":"replace","path":"/fields/System.State","value":"Approved"}]}`, `the argument at "/id" does not equal the fact at "/workItem/id"`},
	// another revision than the one decided
	{`{"action":"update","id":42,"updates":[{"op":"test","path":"/rev","value":4},{"op":"replace","path":"/fields/System.State","value":"Approved"}]}`, `the argument at "/updates/0/value" does not equal the fact at "/workItem/rev"`},
	// the revision test left out
	{`{"action":"update","id":42,"updates":[{"op":"replace","path":"/fields/System.State","value":"Approved"}]}`, `the argument at "/updates/0/value" does not equal the fact at "/workItem/rev"`},
	// another action of the same tool, the same work item
	{`{"action":"update_batch","id":42,"updates":[{"op":"test","path":"/rev","value":3},{"op":"replace","path":"/fields/System.State","value":"Approved"}]}`, `argument "/action" is not the fixed value`},
	// another action, writing the items its batchUpdates name
	{`{"action":"update_batch","id":42,"updates":[{"op":"test","path":"/rev","value":3},{"op":"replace","path":"/fields/System.State","value":"Approved"}],"batchUpdates":[{"id":7,"path":"/fields/System.State","value":"Closed"}]}`, `argument "/action" is not the fixed value`},
	// no action at all: the engine fills none in
	{`{"id":42,"updates":[{"op":"test","path":"/rev","value":3},{"op":"replace","path":"/fields/System.State","value":"Approved"}]}`, `argument "/action" is not the fixed value`},
	// another state than the outcome maps to
	{`{"action":"update","id":42,"updates":[{"op":"test","path":"/rev","value":3},{"op":"replace","path":"/fields/System.State","value":"Closed"}]}`, `argument "/updates/1" is not the fixed value`},
	// a member the policy does not name
	{`{"action":"update","id":42,"updates":[{"op":"test","path":"/rev","value":3},{"op":"replace","path":"/fields/System.State","value":"Approved"}],"batchUpdates":[{"id":7,"path":"/fields/System.State","value":"Closed"}]}`, `argument "/batchUpdates" is reached by no binding`},
	{`{"action":"update","id":42,"project":"another-project","updates":[{"op":"test","path":"/rev","value":3},{"op":"replace","path":"/fields/System.State","value":"Approved"}]}`, `argument "/project" is reached by no binding`},
	// a member the policy does not name, inside an operation
	{`{"action":"update","id":42,"updates":[{"op":"test","path":"/rev","value":3,"from":"/fields/System.Title"},{"op":"replace","path":"/fields/System.State","value":"Approved"}]}`, `argument "/updates/0/from" is reached by no binding`},
}

// boardsThreeOperations is one operation more than the policies name.
const boardsThreeOperations = `{"action":"update","id":42,"updates":[{"op":"test","path":"/rev","value":3},{"op":"replace","path":"/fields/System.State","value":"Approved"},{"op":"add","path":"/fields/System.AssignedTo","value":"someone"}]}`

var writePlatformCases = []writePlatformCase{
	{
		version: "10", platform: "boards", catalog: "azure-devops", from: "https://mcp.dev.azure.com", path: "/example-org",
		parameters: `{"organization":"example-org"}`, tool: "wit_work_item_write", tools: boardsTools,
		// The decision is about work item 42 at revision 3, and its facts
		// state that item alone. The policy holds the dispatcher to the one
		// write the outcome means (ADR-0016, ADR-0018; engine-config.md, "The
		// write-back platforms"): ADR-0016's policy, and updates held to an
		// array of exactly two, so that the request has one shape.
		facts:     `{"workItem":{"id":42,"rev":3}}`,
		arguments: boardsArguments,
		hold:      boardsHold + boardsShape,
		mismatched: append(append([]mismatchedWrite(nil), boardsRefused...),
			// one operation more: the array past its bound, held before the
			// closed set is walked
			mismatchedWrite{boardsThreeOperations, `argument "/updates" holds more elements than the policy's shape allows`},
			// the object in place of the array, which the policy without a
			// shape admits (below): refused, and nothing is sent
			mismatchedWrite{boardsObjectUpdates, `argument "/updates" is not of the shape the policy holds it to`},
		),
	},
	{
		variant: " without a shape", version: "9", platform: "boards", catalog: "azure-devops", from: "https://mcp.dev.azure.com", path: "/example-org",
		parameters: `{"organization":"example-org"}`, tool: "wit_work_item_write", tools: boardsTools,
		// ADR-0016's policy alone, in a version-9 file, as it was written
		// before ADR-0018: it means what it meant.
		facts:     `{"workItem":{"id":42,"rev":3}}`,
		arguments: boardsArguments,
		hold:      boardsHold,
		mismatched: append(append([]mismatchedWrite(nil), boardsRefused...),
			// one operation more than the policy names
			mismatchedWrite{boardsThreeOperations, `argument "/updates/2" is reached by no binding`},
		),
		// The policy holds the values it names and that nothing else is
		// there, not the container type of an ancestor (ADR-0016, section 5):
		// an object whose members are named "0" and "1" in place of the
		// updates array is read as that array's elements, as RFC 6901 reads
		// a numeric token on an object, and is admitted and sent once. What
		// the server makes of it is the server's. The policy with a shape,
		// above, refuses it.
		admitted: []string{boardsObjectUpdates},
	},
	{
		version: "9", platform: "ledger", catalog: "databricks", from: "https://{workspace}", path: "/api/2.0/mcp/functions/main/decisions/record_approval",
		parameters: `{"catalog":"main","function":"record_approval","schema":"decisions"}`, tool: "main__decisions__record_approval", tools: ledgerTools,
		// The function's named parameters, each bound to a fact.
		facts:     `{"case":{"id":"CASE-7","revision":3}}`,
		arguments: `{"case_id":"CASE-7","revision":3}`,
		hold:      `"bind":[{"argument":"/case_id","fact":"/case/id"},{"argument":"/revision","fact":"/case/revision"}]`,
		mismatched: []mismatchedWrite{
			{`{"case_id":"CASE-8","revision":3}`, `the argument at "/case_id" does not equal the fact at "/case/id"`},
			{`{"case_id":"CASE-7","revision":4}`, `the argument at "/revision" does not equal the fact at "/case/revision"`},
			{`{"case_id":"CASE-7","revision":"3"}`, `the argument at "/revision" does not equal the fact at "/case/revision"`},
			{`{"case_id":"CASE-7"}`, `the request's arguments hold nothing at "/revision"`},
		},
	},
}

// writeConfig writes an engine configuration of one write-back platform
// whose binding is text, under the catalog name given, and returns its
// path; the adapters are bin's, and the write credentials file holds the
// token. The file is of version 9; writeConfigAt writes one of the version
// given.
func writeConfig(t *testing.T, dir, bin, catalogName, text, platform, parameters, policy string) string {
	t.Helper()
	return writeConfigAt(t, "9", dir, bin, catalogName, text, platform, parameters, policy)
}

func writeConfigAt(t *testing.T, version, dir, bin, catalogName, text, platform, parameters, policy string) string {
	t.Helper()
	credentials := filepath.Join(dir, platform+"-write.json")
	if err := os.WriteFile(credentials, []byte(`{"token":"write-secret-token"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	catalog := catalogWith(t, map[string]string{catalogName: text})
	escape := func(p string) string { return strings.ReplaceAll(p, `\`, `\\`) }
	extra := ""
	if parameters != "" {
		extra += `,"parameters":` + parameters
	}
	if policy != "" {
		extra += `,"decisionPolicy":` + policy
	}
	config := `{"engineVersion":"` + version + `","authority":"gateway:test","seed":"` + escape(filepath.Join(dir, "gateway.seed")) + `","store":"` + escape(filepath.Join(dir, "store")) + `",` +
		`"registry":"` + escape(filepath.Join(dir, "registry.jsonl")) + `","decisionRecords":"` + escape(filepath.Join(dir, "decisions")) + `",` +
		`"listen":"127.0.0.1:0","catalog":"` + escape(catalog) + `","adapters":"` + escape(bin) + `",` +
		`"platforms":{"` + platform + `":{"binding":"` + catalogName + `@` + digestOf(text) + `","credentials":{"write":{"file":"` + escape(credentials) + `"}},` +
		`"user":"engine-` + platform + `","write":true` + extra + `}}}`
	path := filepath.Join(dir, "engine.json")
	if err := os.WriteFile(path, []byte(config), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// The executor through each write-back platform, over the stand-in: every
// refusal of the ladder that a write to these platforms meets -- no
// verifying judgment cited, each policy check, each argument bind holds --
// sends nothing; a write the policy holds is sent once, to the URL the
// platform's parameters resolved, and the action receipt names that URL and
// the tool asked for; a target's refusal is receipted as its bytes; and the
// store, the registry and the records verify together.
func TestTheWriteBackPlatformsWriteUnderTheirPolicies(t *testing.T) {
	bin, _ := buildMCPStandIns(t, t.TempDir())
	cases := append([]writePlatformCase(nil), writePlatformCases...)
	for _, wp := range writePlatformCases {
		wp.variant += " V2"
		wp.version = "11"
		cases = append(cases, wp)
	}
	for _, wp := range cases {
		t.Run(wp.catalog+wp.variant, func(t *testing.T) {
			stand := newWriteStandIn(t, wp.tools)
			key := keyFromSeed(t, vectorSeed1)
			policy := `{"outcomes":["approve"],"packs":["` + packA + `"],"reviewed":true,"requireSignedRecord":["` + key.public + `"],` + wp.hold + `}`
			text := atStandIn(t, wp.catalog, wp.from, stand.URL)
			current := strings.HasSuffix(wp.variant, " V2")
			if current {
				raw, err := os.ReadFile(filepath.Join("..", "catalog", wp.catalog+".json"))
				if err != nil {
					t.Fatal(err)
				}
				text = strings.Replace(string(raw), `"url": "`+wp.from, `"url": "`+stand.URL, 1)
			}
			config := writeConfigAt(t, wp.version, t.TempDir(), bin, wp.catalog, text, wp.platform, wp.parameters, `{"`+wp.tool+`":`+policy+`}`)
			if current {
				approveV2WriteFixture(t, config)
				stand.forget()
			}
			cfg, bindings, err := loadEngineConfig(config, stubAccounts(map[string]int{"engine-" + wp.platform: 1001}))
			if err != nil {
				t.Fatal(err)
			}
			spec := deriveSources(cfg, bindings)[wp.platform+"/write"]
			spec.user = ""
			resolved := stand.URL + wp.path
			if spec.endpoint != resolved || !contains(spec.argv, "--url="+resolved) || strings.Contains(strings.Join(spec.argv, " "), "{") {
				t.Fatalf("the executor is given the resolved URL and no template: %q %q", spec.endpoint, spec.argv)
			}
			service, server := testService(t)
			service.sources[wp.platform+"/write"] = spec
			service.decisionRecords = t.TempDir()
			issuer := newIssuer(t)
			id := identityFor(t, issuer)
			service.identity = &id
			token := issuer.mint(t, "ec-1", nil, goodClaims(time.Now()))
			code, first := authed(t, server, "/acquire", `{"session":"wb","source":"screening","arguments":{"q":"example"}}`, token)
			if code != http.StatusOK {
				t.Fatalf("acquire: %d %v", code, first)
			}
			signature := first["receipt"].(map[string]any)["signature"].(string)
			trail := strings.Repeat("4e", 16)
			// record is the runtime's line of a chained trail at a sequence,
			// with edits made to it, as a pair of text to find and its
			// replacement.
			record := func(sequence int, edits ...string) string {
				line := `{"recordVersion":"1","trail":"` + trail + `","sequence":` + strconv.Itoa(sequence) + `,"previous":"sha256:` + strings.Repeat("7c", 32) + `",` +
					`"run":"4f1c2b3a5d6e7f80","at":"2026-10-13T10:00:00Z","kind":"evaluation","surface":"evaluate","tool":{"name":"jpack","version":"0.32.0"},"evaluatorSpecVersion":"1.0",` +
					`"pack":{"id":"write-back","version":"1.0.0","specVersion":"1.0","digest":"` + packA + `"},` +
					`"inputs":{"facts":` + wp.facts + `,"evidence":null,"evidenceSupplied":false},"reviewed":true,` +
					`"cites":[{"sessionId":"wb","callIndex":0,"signature":"` + signature + `"}],` +
					`"disposition":{"handoff":{"state":"none"},"kind":"outcome","outcomeId":"approve","reasons":[]}}`
				for i := 0; i+1 < len(edits); i += 2 {
					if !strings.Contains(line, edits[i]) {
						t.Fatalf("the record holds no %q", edits[i])
					}
					line = strings.Replace(line, edits[i], edits[i+1], 1)
				}
				return line
			}
			good := record(1)
			unsigned := record(2)
			other := record(3, `"outcomeId":"approve"`, `"outcomeId":"reject"`)
			unnamed := record(4, `"digest":"`+packA+`"`, `"digest":"`+packB+`"`)
			unreviewed := record(5, `"reviewed":true`, `"reviewed":false`)
			digest := func(line string) string { return "sha256:" + hexOf([]byte(line)) }
			var sidecar strings.Builder
			for i, line := range []string{good, "", other, unnamed, unreviewed} {
				if line != "" {
					sidecar.WriteString(signedLine(key, trail, int64(i+1), digest(line)) + "\n")
				}
			}
			if err := os.WriteFile(filepath.Join(service.decisionRecords, "evaluations.jsonl"), []byte(strings.Join([]string{good, unsigned, other, unnamed, unreviewed}, "\n")+"\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(service.decisionRecords, sidecarName), []byte(sidecar.String()), 0o600); err != nil {
				t.Fatal(err)
			}
			request := func(arguments, recordDigest, packDigest, cited string) string {
				return `{"session":"wb","platform":"` + wp.platform + `","tool":"` + wp.tool + `","arguments":` + arguments + `,` +
					`"decision":{"recordDigest":"` + recordDigest + `","packDigest":"` + packDigest + `"},` +
					`"cites":[{"sessionId":"wb","callIndex":0,"signature":"` + cited + `"}]}`
			}
			type refusal struct {
				name, body, step string
			}
			// what a refusal says, by its name, where the test looks at it
			wants := map[string]string{}
			refusals := []refusal{
				{"a tool the binding does not name", strings.Replace(request(wp.arguments, digest(good), packA, signature), `"tool":"`+wp.tool+`"`, `"tool":"unlisted"`, 1), "tool"},
				{"no judgment cited", strings.Replace(request(wp.arguments, digest(good), packA, signature), `"cites":[{"sessionId":"wb","callIndex":0,"signature":"`+signature+`"}]`, `"cites":[]`, 1), "cites"},
				{"a citation the store does not hold", request(wp.arguments, digest(good), packA, strings.Repeat("e", 128)), "cites"},
				{"a record the directory does not hold", request(wp.arguments, "sha256:"+strings.Repeat("0", 64), packA, signature), "decision"},
				{"a record no trusted key signed", request(wp.arguments, digest(unsigned), packA, signature), "policy-signed"},
				{"an outcome the policy does not allow", request(wp.arguments, digest(other), packA, signature), "policy-outcome"},
				{"a pack the policy does not name", request(wp.arguments, digest(unnamed), packB, signature), "policy-packs"},
				{"a decision not judged under reviewed law", request(wp.arguments, digest(unreviewed), packA, signature), "policy-reviewed"},
			}
			for i, m := range wp.mismatched {
				name := "arguments the policy does not admit " + strconv.Itoa(i)
				refusals = append(refusals, refusal{name, request(m.arguments, digest(good), packA, signature), "policy-bind"})
				wants[name] = m.want
			}
			for _, r := range refusals {
				if code, body := authed(t, server, "/act", r.body, token); code != http.StatusBadRequest || body["refusedAt"] != r.step || !strings.Contains(fmt.Sprint(body["error"]), wants[r.name]) {
					t.Fatalf("%s: %d %v", r.name, code, body)
				}
				if seen := stand.requests(); len(seen) != 0 {
					t.Fatalf("%s: a write the ladder refused reached the server: %+v", r.name, seen)
				}
			}
			// The write the policy holds: sent once, to the resolved URL, with
			// the write credential and without the read-only header.
			code, acted := authed(t, server, "/act", request(wp.arguments, digest(good), packA, signature), token)
			if code != http.StatusOK {
				t.Fatalf("act: %d %v", code, acted)
			}
			inner := acted["receipt"].(map[string]any)["action"].(map[string]any)
			tool := inner["tool"].(map[string]any)
			if tool["endpoint"] != resolved || tool["name"] != wp.tool || tool["shape"] != "mcp" || inner["policy"] == nil || inner["decision"].(map[string]any)["recordBytes"] != "exact" {
				t.Fatalf("the action receipt names the resolved URL and the tool asked for: %v", inner)
			}
			// and the transport that reached it, so a verifier holds that URL
			// to the endpoint form (#268): the store verifies below with it.
			if tool["transport"] != "http" || len(tool) != 4 {
				t.Fatalf("a remote write's tool names its transport, and nothing more: %v", tool)
			}
			var trace []string
			calls := 0
			for _, r := range stand.requests() {
				trace = append(trace, r.verb+" "+r.path+" "+r.method)
				if r.readonly != "" || r.bearer != "Bearer write-secret-token" {
					t.Fatalf("a write is sent with the write credential and no read-only header: %+v", r)
				}
				if r.method == "tools/call" {
					calls++
					var params struct {
						Name      string          `json:"name"`
						Arguments json.RawMessage `json:"arguments"`
					}
					if err := json.Unmarshal(r.params, &params); err != nil || params.Name != wp.tool || canonOf(t, string(params.Arguments)) != canonOf(t, wp.arguments) {
						t.Fatalf("the target got the write as sent: %s", r.params)
					}
				}
			}
			p := wp.path
			if strings.Join(trace, "|") != "POST "+p+" initialize|POST "+p+" notifications/initialized|POST "+p+" tools/list|POST "+p+" tools/call|DELETE "+p+" " || calls != 1 {
				t.Fatalf("the write is one session at the resolved URL and one call: %q", trace)
			}
			// Each other write the policy admits is sent once too, exactly as
			// asked.
			for _, arguments := range wp.admitted {
				stand.forget()
				if code, acted := authed(t, server, "/act", request(arguments, digest(good), packA, signature), token); code != http.StatusOK {
					t.Fatalf("%s: a write the policy admits: %d %v", arguments, code, acted)
				}
				calls := 0
				for _, r := range stand.requests() {
					if r.method != "tools/call" {
						continue
					}
					calls++
					var params struct {
						Arguments json.RawMessage `json:"arguments"`
					}
					if err := json.Unmarshal(r.params, &params); err != nil || canonOf(t, string(params.Arguments)) != canonOf(t, arguments) {
						t.Fatalf("%s: the target got the write as asked: %s", arguments, r.params)
					}
				}
				if calls != 1 {
					t.Fatalf("%s: a write the policy admits was sent %d times", arguments, calls)
				}
			}
			// A target's refusal is a response to receipt: its bytes are the
			// result, and the receipt is minted.
			stand.forget()
			stand.refuse = true
			code, refused := authed(t, server, "/act", request(wp.arguments, digest(good), packA, signature), token)
			if code != http.StatusOK {
				t.Fatalf("a target's refusal is receipted: %d %v", code, refused)
			}
			if result := refused["result"].(map[string]any); result["isError"] != true || !strings.Contains(string(mustJSON(t, result)), "the revision has changed") {
				t.Fatalf("the receipt's result is the target's refusal bytes: %v", result)
			}
			// A failure of the protocol after the call was sent -- an HTTP
			// error status, a JSON-RPC error, a result that repeats the bearer
			// -- is no answer to receipt: the call went once, nothing is minted,
			// the session's count stands, and the bearer is in no answer.
			index := func() int64 {
				service.mu.Lock()
				defer service.mu.Unlock()
				return service.sessions["wb"].index
			}
			for _, failure := range []string{"http", "rpc", "echo"} {
				stand.forget()
				stand.mu.Lock()
				stand.failure = failure
				stand.mu.Unlock()
				before := index()
				code, body := authed(t, server, "/act", request(wp.arguments, digest(good), packA, signature), token)
				if code == http.StatusOK || body["receipt"] != nil || index() != before || strings.Contains(string(mustJSON(t, body)), "write-secret-token") {
					t.Fatalf("a %s failure is not receipted and leaks nothing: %d %v", failure, code, body)
				}
				calls := 0
				for _, r := range stand.requests() {
					if r.method == "tools/call" {
						calls++
					}
				}
				if calls != 1 {
					t.Fatalf("a %s failure: the write was sent %d times", failure, calls)
				}
			}
			stand.mu.Lock()
			stand.failure = ""
			stand.mu.Unlock()
			if code, body := authed(t, server, "/seal", `{"session":"wb"}`, token); code != http.StatusOK {
				t.Fatalf("seal: %d %v", code, body)
			}
			report, err := verifyWithRegistryAndRecords(service.storeRoot, service.regPath, "gateway:test", service.decisionRecords, service.publicKey)
			if err != nil || !report.OK {
				t.Fatalf("the store, the registry and the records verify together: %v %+v", err, report)
			}
		})
	}
}

func canonOf(t *testing.T, text string) string {
	t.Helper()
	v, err := parseJSON([]byte(text))
	if err != nil {
		t.Fatalf("%s: %v", text, err)
	}
	return string(canon(v))
}

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	out, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// An acquisition through a remote binding whose URL is a template records
// the URL the platform's parameters resolved as its endpoint, never the
// template.
func TestARemoteAcquisitionRecordsTheResolvedURL(t *testing.T) {
	bin, _ := buildMCPStandIns(t, t.TempDir())
	stand := newWriteStandIn(t, boardsTools)
	text := `{"bindingVersion":"1","platform":"boards","operations":{"live":{"shape":"mcp","server":{"url":"` + stand.URL + `/{organization}","bearer":"token"},"tools":["wit_work_item"],"licence":"MIT"}}}`
	dir := t.TempDir()
	credentials := filepath.Join(dir, "live.json")
	if err := os.WriteFile(credentials, []byte(`{"token":"live-secret-token"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	config := strings.Replace(writeConfigText(t, dir, bin, "boards", text, `"live":{"file":"`+strings.ReplaceAll(credentials, `\`, `\\`)+`"}`, `,"parameters":{"organization":"example-org"}`), `"write":true`, `"write":false`, 1)
	path := filepath.Join(dir, "engine.json")
	if err := os.WriteFile(path, []byte(config), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, bindings, err := loadEngineConfig(path, stubAccounts(map[string]int{"engine-boards": 1001}))
	if err != nil {
		t.Fatal(err)
	}
	spec := deriveSources(cfg, bindings)["boards/live"]
	spec.user = ""
	service, server := testService(t)
	service.sources["boards/live"] = spec
	code, first := post(t, server, "/acquire", `{"session":"live-1","source":"boards/live","arguments":{"tool":"wit_work_item","arguments":{"action":"get","id":42}}}`)
	if code != http.StatusOK {
		t.Fatalf("acquire: %d %v", code, first)
	}
	acquisition := first["receipt"].(map[string]any)["acquisition"].(map[string]any)
	if acquisition["endpoint"] != stand.URL+"/example-org" || acquisition["transport"] != "http" {
		t.Fatalf("the acquisition names the resolved URL: %v", acquisition)
	}
	for _, r := range stand.requests() {
		if r.path != "/example-org" {
			t.Fatalf("every request went to the resolved URL: %+v", r)
		}
	}
}

// writeConfigText is an engine configuration of one platform of the
// binding given, with the credentials member given as written and extra
// appended to the platform.
func writeConfigText(t *testing.T, dir, bin, catalogName, text, credentials, extra string) string {
	t.Helper()
	catalog := catalogWith(t, map[string]string{catalogName: text})
	escape := func(p string) string { return strings.ReplaceAll(p, `\`, `\\`) }
	return `{"engineVersion":"8","authority":"gateway:test","seed":"` + escape(filepath.Join(dir, "gateway.seed")) + `","store":"` + escape(filepath.Join(dir, "store")) + `",` +
		`"registry":"` + escape(filepath.Join(dir, "registry.jsonl")) + `","decisionRecords":"` + escape(filepath.Join(dir, "decisions")) + `",` +
		`"listen":"127.0.0.1:0","catalog":"` + escape(catalog) + `","adapters":"` + escape(bin) + `",` +
		`"platforms":{"boards":{"binding":"` + catalogName + `@` + digestOf(text) + `","credentials":{` + credentials + `},"user":"engine-boards","write":true` + extra + `}}}`
}

// A platform's parameters fill its binding's templates, and every way a
// template or a parameter could send a credential somewhere the binding
// did not say is refused at start, by a sentence naming the rule.
func TestParametersFillARemoteBindingsTemplates(t *testing.T) {
	template := func(url, tools string) string {
		return `{"bindingVersion":"1","platform":"boards","operations":{"write":{"shape":"mcp","server":{"url":"` + url + `","bearer":"token"},"tools":` + tools + `,"licence":"MIT"}}}`
	}
	organization := template("https://mcp.dev.azure.com/{organization}", `["wit_work_item_write"]`)
	workspace := template("https://{workspace}/api/2.0/mcp/functions/{catalog}/{schema}/{function}", `["{catalog}__{schema}__{function}"]`)
	long := template("https://mcp.example/"+strings.Repeat("p", 2026)+"/{organization}", `["write"]`)
	configured := func(version, binding, extra string) string {
		catalog := catalogWith(t, map[string]string{"boards": binding})
		return strings.Replace(engineJSON(t, catalog, ``, platformJSONFor(t, "boards", "boards@"+digestOf(binding), "engine-desk", `,"write":true`+extra, "write")), `"engineVersion":"1"`, `"engineVersion":"`+version+`"`, 1)
	}
	databricks := `,"parameters":{"workspace":"dbc-example.cloud.databricks.com","catalog":"main","schema":"decisions","function":"record_approval"}`
	for _, tc := range []struct {
		name, version, binding, extra, want string
	}{
		{"a placeholder without a parameter", "8", organization, ``, "names the placeholder {organization}, and the platform's parameters give no organization"},
		{"a parameter without a placeholder", "8", organization, `,"parameters":{"organization":"example-org","project":"example"}`, "parameters.project is named by no placeholder"},
		{"a parameter on a binding with no template", "8", template("https://mcp.example/mcp", `["write"]`), `,"parameters":{"organization":"example-org"}`, "parameters.organization is named by no placeholder"},
		{"a value with a slash", "8", organization, `,"parameters":{"organization":"example/org"}`, "parameters.organization is not a parameter's value"},
		{"a value of dots alone", "8", organization, `,"parameters":{"organization":".."}`, "parameters.organization is not a parameter's value"},
		{"a value past its bound", "8", organization, `,"parameters":{"organization":"` + strings.Repeat("a", 254) + `"}`, "parameters.organization is not a parameter's value"},
		{"a value that is not a string", "8", organization, `,"parameters":{"organization":7}`, "parameters.organization must be a string"},
		{"a name out of form", "8", organization, `,"parameters":{"Organization":"example-org"}`, "which is not a parameter's name"},
		{"no parameter at all", "8", organization, `,"parameters":{}`, "parameters, when present, is an object of at least one string value"},
		{"a resolved URL out of the endpoint form", "8", long, `,"parameters":{"organization":"example-org"}`, "more than the 2048 of the endpoint form"},
		{"a workspace off the workspace domains", "8", workspace, strings.Replace(databricks, "dbc-example.cloud.databricks.com", "dbc-example.example.com", 1), "parameters.workspace is not a Databricks workspace's host"},
		{"a workspace that is the account console", "8", workspace, strings.Replace(databricks, "dbc-example.cloud.databricks.com", "accounts.cloud.databricks.com", 1), "parameters.workspace is not a Databricks workspace's host"},
		{"a workspace under a workspace domain's look-alike", "8", workspace, strings.Replace(databricks, "dbc-example.cloud.databricks.com", "dbc-example.cloud.databricks.com.example.net", 1), "parameters.workspace is not a Databricks workspace's host"},
		{"a workspace of four labels", "8", workspace, strings.Replace(databricks, "dbc-example.cloud.databricks.com", "a.b.c.d.azuredatabricks.net", 1), "parameters.workspace is not a Databricks workspace's host"},
		{"a template that names the scheme", "8", template("{scheme}://mcp.example/mcp", `["write"]`), `,"parameters":{"scheme":"https"}`, "must begin with its scheme written as it is"},
		{"a template that extends the host", "8", template("https://mcp.example{organization}/mcp", `["write"]`), `,"parameters":{"organization":"example-org"}`, "must write its host as it is, or as {workspace} alone over https"},
		{"a template that names a label of the host", "8", template("https://{organization}.mcp.example/mcp", `["write"]`), `,"parameters":{"organization":"example-org"}`, "must write its host as it is, or as {workspace} alone over https"},
		{"a template whose host is another placeholder", "8", template("https://{organization}/mcp", `["write"]`), `,"parameters":{"organization":"example-org"}`, "must write its host as it is, or as {workspace} alone over https"},
		{"a template that names the port", "8", template("https://{workspace}:8443/mcp", `["write"]`), `,"parameters":{"workspace":"dbc-example.cloud.databricks.com"}`, "must write its host as it is, or as {workspace} alone over https"},
		{"a template of the workspace in the clear", "8", template("http://{workspace}/mcp", `["write"]`), `,"parameters":{"workspace":"dbc-example.cloud.databricks.com"}`, "must write its host as it is, or as {workspace} alone over https"},
		{"a template with a query", "8", template("https://mcp.example/{organization}?tenant=1", `["write"]`), `,"parameters":{"organization":"example-org"}`, "must be of the endpoint form with its placeholders filled"},
		{"a placeholder of an upper-case name", "8", template("https://mcp.example/{Organization}", `["write"]`), `,"parameters":{"organization":"example-org"}`, "names a placeholder which is not a parameter's name"},
		{"an empty placeholder", "8", template("https://mcp.example/{}", `["write"]`), `,"parameters":{"organization":"example-org"}`, "names a placeholder which is not a parameter's name"},
		{"a placeholder never closed", "8", template("https://mcp.example/{organization", `["write"]`), `,"parameters":{"organization":"example-org"}`, "holds a { that no } closes"},
		{"a brace that closes nothing", "8", template("https://mcp.example/organization}", `["write"]`), `,"parameters":{"organization":"example-org"}`, "holds a } that closes no placeholder"},
		{"a tool of a disallowed placeholder", "8", template("https://mcp.example/{organization}", `["{Organization}_write"]`), `,"parameters":{"organization":"example-org"}`, "a tool names a placeholder which is not a parameter's name"},
		{"two tools that resolve to one", "8", template("https://mcp.example/{a}/{b}", `["{a}","{b}"]`), `,"parameters":{"a":"same","b":"same"}`, `two of the write operation's tools resolve to "same"`},
		{"parameters in a version-7 file", "7", organization, `,"parameters":{"organization":"example-org"}`, "parameters is a version-8 member; engineVersion 7 has no parameters"},
		{"a policy named by the tool's template", "8", workspace, databricks + `,"decisionPolicy":{"{catalog}__{schema}__{function}":{"outcomes":["approve"]}}`, `decisionPolicy names tool "{catalog}__{schema}__{function}", which the binding's write operation does not name`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, _, err := load(t, configured(tc.version, tc.binding, tc.extra))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("want %q, got %v", tc.want, err)
			}
		})
	}
	// Version 8 without parameters loads as a version 7 file did.
	if _, _, err := load(t, strings.Replace(engineJSON(t, catalogWith(t, map[string]string{"postgres": postgresBinding}), ``, platformJSON(t, "warehouse", "postgres@"+digestOf(postgresBinding), "engine-warehouse", ``)), `"engineVersion":"1"`, `"engineVersion":"8"`, 1)); err != nil {
		t.Fatalf("a version-8 file without parameters: %v", err)
	}
	// With them, the sources are the resolved binding's: the URL, the tools,
	// the endpoint an action receipt names; a policy names the resolved tool.
	cfg, sources, err := load(t, configured("8", workspace, databricks+`,"decisionPolicy":{"main__decisions__record_approval":{"outcomes":["approve"]}}`))
	if err != nil {
		t.Fatal(err)
	}
	write := sources["boards/write"]
	url := "https://dbc-example.cloud.databricks.com/api/2.0/mcp/functions/main/decisions/record_approval"
	if !contains(write.argv, "--url="+url) || !contains(write.argv, "--tools=main__decisions__record_approval") || write.endpoint != url ||
		strings.Join(write.tools, ",") != "main__decisions__record_approval" || write.policies["main__decisions__record_approval"] == nil || cfg.platforms[0].parameters["workspace"] != "dbc-example.cloud.databricks.com" {
		t.Fatalf("the resolved binding: %+v", write)
	}
}

// The workspace host forms the engine holds a {workspace} parameter to are
// the Databricks connection's own: the two modules share no code, so the
// lists are held to each other here.
func TestTheWorkspaceDomainsAreTheConnections(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "adapters", "connections", "databricks.go"))
	if err != nil {
		t.Fatal(err)
	}
	m := regexp.MustCompile(`var databricksDomains = \[\]string\{([^}]*)\}`).FindSubmatch(data)
	if m == nil {
		t.Fatal("the connection's databricksDomains is not where this test reads it")
	}
	var theirs []string
	for _, q := range regexp.MustCompile(`"([^"]+)"`).FindAllSubmatch(m[1], -1) {
		theirs = append(theirs, string(q[1]))
	}
	if strings.Join(theirs, ",") != strings.Join(workspaceDomains, ",") {
		t.Fatalf("the engine's workspace domains %q are not the connection's %q", workspaceDomains, theirs)
	}
}

// connect writes a platform's parameters, raising the file to version 8,
// resolves the binding with them before anything runs, captures the write
// tools' descriptors of a binding with no live operation through the remote
// form's check at the resolved URL -- the real adapter, against the
// stand-in -- and keeps the parameters on --replace when none are given.
func TestConnectCapturesTheWriteBackPlatformsDescriptorsAndKeepsTheParameters(t *testing.T) {
	bin, _ := buildMCPStandIns(t, t.TempDir())
	adapter := filepath.Join(bin, "adapter-mcp")
	for _, wp := range writePlatformCases {
		// connect is of the platform, whatever policy holds its tools: one
		// run per catalog.
		if wp.variant != "" {
			continue
		}
		t.Run(wp.catalog, func(t *testing.T) {
			stand := newWriteStandIn(t, wp.tools)
			f := newConnectFixture(t, restrictedBinding, ``)
			raw, err := os.ReadFile(filepath.Join("..", "catalog", wp.catalog+".json"))
			if err != nil {
				t.Fatal(err)
			}
			text := strings.Replace(string(raw), `"url": "`+wp.from, `"url": "`+stand.URL, 1)
			if err := os.WriteFile(filepath.Join(f.catalog, wp.catalog+".json"), []byte(text), 0o600); err != nil {
				t.Fatal(err)
			}
			credentials := filepath.Join(t.TempDir(), "write.json")
			if err := os.WriteFile(credentials, []byte(`{"token":"write-secret-token"}`), 0o600); err != nil {
				t.Fatal(err)
			}
			// The real adapter, run as this test's user, given a credentials
			// file this test wrote in place of the stub filesystem's.
			var asked []sourceSpec
			check := func(ctx context.Context, spec sourceSpec) ([]byte, error) {
				asked = append(asked, spec)
				spec.user = ""
				argv := []string{adapter}
				for _, arg := range spec.argv[1:] {
					if strings.HasPrefix(arg, "--credentials=") {
						arg = "--credentials=" + credentials
					}
					argv = append(argv, arg)
				}
				spec.argv = argv
				return runCheck(ctx, spec)
			}
			var parameters map[string]string
			if err := json.Unmarshal([]byte(wp.parameters), &parameters); err != nil {
				t.Fatal(err)
			}
			req := connectRequest{config: f.config, platform: wp.platform, binding: wp.catalog, credentials: map[string]string{"write": f.credentials}, user: "engine-warehouse", write: true}
			for name, value := range parameters {
				req.parameters = append(req.parameters, name+"="+value)
			}
			out, err := connect(context.Background(), req, f.host, check)
			if err != nil {
				t.Fatal(err)
			}
			if len(asked) != 1 || !contains(asked[0].argv, "--url="+stand.URL+wp.path) || !contains(asked[0].check, "--descriptors-platform="+wp.platform) {
				t.Fatalf("one check, of the write operation at the resolved URL, asked to capture: %+v", asked)
			}
			// What connect prints names the endpoint the check reached, as
			// resolved, and never the bearer.
			answers := strings.Join(out.answers, "\n")
			if !strings.Contains(answers, wp.platform+"/write: adapter-mcp") || !strings.Contains(answers, "endpoint "+stand.URL+wp.path+", server write-standin 1.0") || strings.Contains(answers, "write-secret-token") {
				t.Fatalf("connect names the resolved endpoint and no bearer: %q", out.answers)
			}
			cfg, bindings, err := loadEngineConfig(f.config, stubAccounts(stubUsers))
			if err != nil {
				t.Fatal(err)
			}
			entry := cfg.platforms[0]
			if cfg.version != "12" || entry.operationDescriptors["write"] == "" || len(entry.parameters) != len(parameters) {
				t.Fatalf("version %s, pin %q, parameters %v; answers %q", cfg.version, entry.operationDescriptors["write"], entry.parameters, out.answers)
			}
			kept, err := os.ReadFile(filepath.Join(f.config+".descriptors", strings.TrimPrefix(entry.operationDescriptors["write"], "sha256:")+".json"))
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(string(kept), "write-secret-token") {
				t.Fatal("the snapshot holds the bearer")
			}
			snap, err := parseSnapshot(kept)
			if err != nil || len(snap.names) == 0 || snap.tools[wp.tool].inputSchemaText == nil || snap.platform != wp.platform || snap.endpoint != stand.URL+wp.path {
				t.Fatalf("the snapshot holds the write tools as the server described them: %v %s", err, kept)
			}
			// The frontend reads and verifies it at start, and lists no
			// write tool, since it calls /acquire alone; the preview renders
			// the write tools' captured descriptors.
			if _, err := readServedPlatforms(f.config, cfg, bindings); err != nil {
				t.Fatalf("the frontend reads the pinned snapshot: %v", err)
			}
			preview, err := previewDescriptors(f.config, cfg, bindings, wp.platform)
			if err != nil || !strings.Contains(preview, "tool "+wp.tool) || !strings.Contains(preview, "write tools remain /act only") {
				t.Fatalf("the preview renders the write tools: %v\n%s", err, preview)
			}
			// --replace with no parameter keeps the entry's own.
			req.parameters = nil
			req.replace = true
			if _, err := connect(context.Background(), req, f.host, check); err != nil {
				t.Fatal(err)
			}
			again, _, err := loadEngineConfig(f.config, stubAccounts(stubUsers))
			if err != nil || len(again.platforms[0].parameters) != len(parameters) || again.version != "12" {
				t.Fatalf("connect keeps the parameters: %v %+v", err, again.platforms)
			}
			// A parameter the binding does not name is refused before
			// anything runs.
			asked = nil
			before := f.fileText(t)
			req.parameters = append(req.parameters, "project=example")
			for name, value := range parameters {
				req.parameters = append(req.parameters, name+"="+value)
			}
			if _, err := connect(context.Background(), req, f.host, check); err == nil || !strings.Contains(err.Error(), "parameters.project is named by no placeholder") {
				t.Fatalf("a parameter nothing uses: %v", err)
			}
			if len(asked) != 0 || f.fileText(t) != before {
				t.Fatal("nothing is asked and nothing is written for a parameter nothing uses")
			}
		})
	}
}

// The live checks: each runs the remote form's check against the real
// service -- the handshake and the tool listing, with the descriptors
// captured and no tool called -- and only when its environment names the
// service; without it, it is skipped and reported as not run.
func TestTheWriteBackPlatformsLiveCheck(t *testing.T) {
	for _, live := range []struct {
		catalog, env string
		parameters   func() map[string]string
	}{
		{"azure-devops", "JPACK_AZURE_DEVOPS_LIVE_WRITE_CREDENTIALS", func() map[string]string {
			return map[string]string{"organization": os.Getenv("JPACK_AZURE_DEVOPS_LIVE_WRITE_ORGANIZATION")}
		}},
		{"databricks", "JPACK_DATABRICKS_LIVE_WRITE_CREDENTIALS", func() map[string]string {
			return map[string]string{"workspace": os.Getenv("JPACK_DATABRICKS_LIVE_WRITE_WORKSPACE"), "catalog": os.Getenv("JPACK_DATABRICKS_LIVE_WRITE_CATALOG"),
				"schema": os.Getenv("JPACK_DATABRICKS_LIVE_WRITE_SCHEMA"), "function": os.Getenv("JPACK_DATABRICKS_LIVE_WRITE_FUNCTION")}
		}},
	} {
		t.Run(live.catalog, func(t *testing.T) {
			credentials := os.Getenv(live.env)
			if credentials == "" {
				t.Skipf("not run: %s names no credentials file of {\"token\": …}; this live check contacts the real service, and only when asked", live.env)
			}
			bin, _ := buildMCPStandIns(t, t.TempDir())
			text := historicalCatalogFile(t, live.catalog)
			b, err := parseBinding([]byte(text))
			if err != nil {
				t.Fatal(err)
			}
			ref := live.catalog + "@" + digestOf(text)
			if b, err = resolveParameters(b, live.parameters(), ref); err != nil {
				t.Fatal(err)
			}
			argv := mcpServerArgv(filepath.Join(bin, "adapter-mcp"), *b.write, credentials, "", "", "--error-results")
			spec := sourceSpec{argv: argv, shape: "mcp", check: []string{"--descriptors-platform=live", "--descriptors-binding=" + ref}}
			report, err := runCheck(context.Background(), spec)
			if err != nil {
				t.Fatalf("the live check: %v", err)
			}
			if _, err := readCapture(report, "live", ref, b.write); err != nil {
				t.Fatalf("the live capture: %v", err)
			}
			t.Logf("live check of %s answered: %s", b.write.url, describeOrRaw(report, b.write.url))
		})
	}
}

func describeOrRaw(report []byte, url string) string {
	if line, err := describeCheck("mcp", report, url); err == nil {
		return line
	}
	return string(report)
}

// A descriptor pin is of the server at the endpoint it was captured at
// (cross-vendor round 1 on #257): a binding's digest pins its template and
// not its tenant, so for each write-back platform a snapshot captured for
// one organization or workspace is served while the platform's parameters
// resolve to it, and refused at the frontend's start, with a sentence
// naming the rule, once they resolve elsewhere; a remote server's snapshot
// that names no endpoint is refused too.
func TestADescriptorPinIsOfTheResolvedEndpoint(t *testing.T) {
	for _, tc := range []struct {
		catalog, tool, parameter, changed string
		parameters                        map[string]string
	}{
		{"azure-devops", "wit_work_item_write", "organization", "other-org", map[string]string{"organization": "example-org"}},
		{"databricks", "main__decisions__record_approval", "workspace", "dbc-other.cloud.databricks.com",
			map[string]string{"workspace": "dbc-example.cloud.databricks.com", "catalog": "main", "schema": "decisions", "function": "record_approval"}},
	} {
		t.Run(tc.catalog, func(t *testing.T) {
			text := historicalCatalogFile(t, tc.catalog)
			ref := tc.catalog + "@" + digestOf(text)
			template, err := parseBinding([]byte(text))
			if err != nil {
				t.Fatal(err)
			}
			resolved, err := resolveParameters(template, tc.parameters, ref)
			if err != nil {
				t.Fatal(err)
			}
			snapshotAt := func(endpoint string) []byte {
				member := ""
				if endpoint != "" {
					member = `"endpoint":"` + endpoint + `",`
				}
				v, err := parseJSON([]byte(`{"binding":"` + ref + `",` + member + `"capturedAt":"2026-10-13T01:02:03Z","platform":"tickets","policy":1,"tools":{"` + tc.tool + `":{"description":"The tenant's own tool"}}}`))
				if err != nil {
					t.Fatal(err)
				}
				return canon(v)
			}
			f := newServedFixture(t, snapshotAt(resolved.write.url))
			p := &f.cfg.platforms[0]
			p.binding, p.write, p.parameters = ref, true, tc.parameters
			f.bindings["tickets"] = resolved
			if _, err := readServedPlatforms(f.config, f.cfg, f.bindings); err != nil {
				t.Fatalf("the pin of the endpoint the parameters resolve to: %v", err)
			}
			moved := map[string]string{}
			for name, value := range tc.parameters {
				moved[name] = value
			}
			moved[tc.parameter] = tc.changed
			if f.bindings["tickets"], err = resolveParameters(template, moved, ref); err != nil {
				t.Fatal(err)
			}
			if _, err := readServedPlatforms(f.config, f.cfg, f.bindings); err == nil || !strings.Contains(err.Error(), "now reaches") || !strings.Contains(err.Error(), "captured anew with connect --replace") {
				t.Fatalf("a pin of another tenant's server: %v", err)
			}
			p.descriptors = f.write(t, snapshotAt(""))
			f.bindings["tickets"] = resolved
			if _, err := readServedPlatforms(f.config, f.cfg, f.bindings); err == nil || !strings.Contains(err.Error(), "names no endpoint") {
				t.Fatalf("a remote server's pin that names no endpoint: %v", err)
			}
		})
	}
}

// A parameter's value stays in the segment its template puts it in
// (cross-vendor round 1 on #257): nothing that is empty, dots alone, or
// carries a separator of a path, a host, a port, a scheme, a query, a
// fragment, an escape or the tools list is a value, and a value of the
// form resolves into the organization's segment and nowhere else.
func TestAParameterValueStaysInItsSegment(t *testing.T) {
	b, err := parseBinding([]byte(historicalCatalogFile(t, "azure-devops")))
	if err != nil {
		t.Fatal(err)
	}
	for _, v := range []string{"", ".", "..", "...", "a/b", `a\b`, "%2e%2e", "x?y", "x#y", "x:y", "x@y", "https://other", "x,y", "x y"} {
		if err := parameterProblem("organization", v); err == nil {
			t.Errorf("%q is taken as a value", v)
		}
	}
	for _, v := range []string{"example-org", "example..org", "a_b", "a.b", "-a"} {
		if err := parameterProblem("organization", v); err != nil {
			t.Fatal(err)
		}
		r, err := resolveParameters(b, map[string]string{"organization": v}, "azure-devops@sha256:"+strings.Repeat("0", 64))
		if err != nil || r.write.url != "https://mcp.dev.azure.com/"+v {
			t.Fatalf("%q resolves to %v: %v", v, r.write, err)
		}
	}
}

// connect holds the endpoint an adapter's check reports to the URL the
// source was given (cross-vendor round 1 on #257), refusing a check that
// names another by the roles of the two endpoints and repeating neither
// (the review round on #266: a URL may carry, by mistake, what is never to
// be shown), and names it in the line it prints for a check that holds; a
// server the adapter runs reports none.
func TestConnectHoldsTheReportedEndpointToTheResolvedOne(t *testing.T) {
	report := func(endpoint string) []byte {
		member := ""
		if endpoint != "" {
			member = `"transport":"http","endpoint":"` + endpoint + `",`
		}
		return []byte(`{"check":{"status":"succeeded","adapter":{"name":"adapter-mcp","version":"0","digest":"sha256:ab"},` + member + `"server":{"name":"srv","version":"1"},"protocolVersion":"2025-06-18","tools":["wit_work_item_write"]}}`)
	}
	url := "https://mcp.dev.azure.com/example-org"
	if line, err := describeCheck("mcp", report(url), url); err != nil || line != "adapter-mcp:0 (sha256:ab): endpoint "+url+", server srv 1, protocol 2025-06-18, tools wit_work_item_write" {
		t.Fatalf("the resolved endpoint named: %q %v", line, err)
	}
	for _, tc := range []struct{ reported, given, want string }{
		{"https://mcp.dev.azure.com/other-org", url, "the endpoint the adapter reports is not the one the source was given"},
		{"", url, "the endpoint the adapter reports is not the one the source was given"},
		{url, "", "the adapter reports an endpoint for a server it runs, which has none"},
	} {
		_, err := describeCheck("mcp", report(tc.reported), tc.given)
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Fatalf("reported %q, given %q: %v", tc.reported, tc.given, err)
		}
		if strings.Contains(err.Error(), "mcp.dev.azure.com") {
			t.Fatalf("reported %q, given %q: the refusal repeats an endpoint: %v", tc.reported, tc.given, err)
		}
	}
	if got := remoteURL([]string{"adapter-mcp", "--url=" + url, "--tools=a", "--", "--url=https://elsewhere.example/"}); got != url {
		t.Fatalf("the source's own --url, not the server's arguments: %q", got)
	}
}
