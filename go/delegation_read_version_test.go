package main

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

// admissionReadsSHA256 is the SHA-256 of testdata/delegation/admission-reads.json,
// as the spec repository's conformance/delegation/README.md records it for
// its conformance/delegation/admission-reads.json, of which this file is a
// byte-for-byte copy: the read cases of spec RFC 0030's amendment of
// 2026-11-22, tables 4 and 5, hand-written and shared with the agent library.
const admissionReadsSHA256 = "57c8011e7b21ce0fbf4441a85061f01ae5686f5928720325e79fad18f3fdb095"

const admissionReadsPath = "../testdata/delegation/admission-reads.json"

// gatewayReadCases is how many cases name the gateway as a sender.
const gatewayReadCases = 19

type admissionReadCase struct {
	Name        string            `json:"name"`
	Table       int               `json:"table"`
	Applies     map[string]string `json:"applies"`
	Senders     []string          `json:"senders"`
	ReadVersion string            `json:"readVersion"`
	Inputs      struct {
		Chain    string `json:"chain"`
		At       string `json:"at"`
		Audience struct {
			Kind string `json:"kind"`
			Name string `json:"name"`
		} `json:"audience"`
		Call     json.RawMessage `json:"call"`
		Standing json.RawMessage `json:"standing"`
		Version  *string         `json:"version"`
	} `json:"inputs"`
	Body   json.RawMessage `json:"body"`
	Answer json.RawMessage `json:"answer"`
	Expect struct {
		Sender string `json:"sender"`
		Reads  int    `json:"reads"`
	} `json:"expect"`
}

// readAdmissionReadCases reads the copy, its bytes held to the pin before
// they are parsed.
func readAdmissionReadCases(t *testing.T) []admissionReadCase {
	t.Helper()
	raw, err := os.ReadFile(admissionReadsPath)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(raw)
	if got := hex.EncodeToString(sum[:]); got != admissionReadsSHA256 {
		t.Fatalf("testdata/delegation/admission-reads.json is %s, not the spec's %s", got, admissionReadsSHA256)
	}
	var doc struct {
		Cases []admissionReadCase `json:"cases"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	return doc.Cases
}

// conformanceChain is the chain of the named case of statements.json (the
// spec's ed25519-statements.json), verified under its keys.
func conformanceChain(t *testing.T, name string) *delegationChain {
	t.Helper()
	raw, err := os.ReadFile("../testdata/delegation/statements.json")
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Keys    map[string][]json.RawMessage `json:"keys"`
		Vectors []struct {
			Name  string          `json:"name"`
			Chain json.RawMessage `json:"chain"`
		} `json:"vectors"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	for _, v := range doc.Vectors {
		if v.Name != name {
			continue
		}
		parsed, err := parseJSON(v.Chain)
		if err != nil {
			t.Fatal(err)
		}
		chain, refusal := verifyDelegationChain(parsed, pinDelegationKeys(t, doc.Keys))
		if refusal != nil {
			t.Fatalf("chain %q: %v", name, refusal)
		}
		return chain
	}
	t.Fatalf("no case %q in statements.json", name)
	return nil
}

// readDouble is an issuing host's admission endpoint that answers every
// read with answer and keeps each body as sent.
type readDouble struct {
	server *httptest.Server
	mu     sync.Mutex
	bodies [][]byte
	answer string
}

func newReadDouble(t *testing.T, answer string) *readDouble {
	t.Helper()
	d := &readDouble{answer: answer}
	d.server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		d.mu.Lock()
		d.bodies = append(d.bodies, raw)
		answer := d.answer
		d.mu.Unlock()
		_, _ = io.WriteString(w, answer)
	}))
	t.Cleanup(d.server.Close)
	return d
}

func (d *readDouble) sent() [][]byte {
	d.mu.Lock()
	defer d.mu.Unlock()
	return append([][]byte(nil), d.bodies...)
}

// service is a delegation service holding the one host "desk", read at
// readVersion, under audience.
func (d *readDouble) service(readVersion, audience string) (*delegationService, *delegationHost) {
	host := &delegationHost{delegationHostSpec: delegationHostSpec{host: "desk", requester: hostRequester, admission: d.server.URL, readVersion: readVersion}, bearer: "admission-credential-1"}
	svc := newDelegationService(map[string]*delegationHost{"desk": host}, nil, false)
	pool := x509.NewCertPool()
	pool.AddCert(d.server.Certificate())
	svc.client = admissionClient(pool)
	svc.audience = audience
	return svc, host
}

// runReadCase makes the case's read as the gateway makes it, at the
// configured readVersion given, and answers what the gateway reports.
func runReadCase(t *testing.T, c admissionReadCase, readVersion string) (string, [][]byte) {
	t.Helper()
	var answer string
	if err := json.Unmarshal(c.Answer, &answer); err != nil {
		t.Fatalf("%s: answer: %v", c.Name, err)
	}
	double := newReadDouble(t, answer)
	svc, host := double.service(readVersion, c.Inputs.Audience.Name)
	if c.Inputs.Standing != nil {
		v, err := parseJSON(c.Inputs.Standing)
		if err != nil {
			t.Fatal(err)
		}
		sub, ok := parsePrincipalRef(v)
		if !ok {
			t.Fatalf("%s: standing is not a principal reference", c.Name)
		}
		verdict := svc.standingRead(host, sub)
		if verdict == "" {
			verdict = refusalStandingUnknown
		}
		return verdict, double.sent()
	}
	at, err := time.Parse(time.RFC3339Nano, c.Inputs.At)
	if err != nil {
		t.Fatal(err)
	}
	var call *delegatedCall
	if string(c.Inputs.Call) != "null" {
		var in struct {
			Source, Tool, Effect string
			Count                bool
		}
		if err := json.Unmarshal(c.Inputs.Call, &in); err != nil {
			t.Fatal(err)
		}
		call = &delegatedCall{source: in.Source, tool: in.Tool, effect: in.Effect, count: in.Count}
		if c.Inputs.Version != nil {
			call.version = *c.Inputs.Version
		}
	}
	verdict := "admit"
	if r := svc.admissionReadAt(host, c.Inputs.Audience.Name, conformanceChain(t, c.Inputs.Chain), call, at); r != nil {
		verdict = r.name
	}
	return verdict, double.sent()
}

// Every case of the shared set whose sender part names the gateway, against
// an issuing-host double answering the case's answer: the body sent byte for
// byte, or for a body no sender emits a body other than it; the refusal the
// gateway reports; and the reads made, one, never resent.
func TestAdmissionReadsConformanceCases(t *testing.T) {
	ran := 0
	for _, c := range readAdmissionReadCases(t) {
		if _, sender := c.Applies["sender"]; !sender || !slices.Contains(c.Senders, "gateway") {
			continue
		}
		ran++
		t.Run(c.Name, func(t *testing.T) {
			var body string
			if err := json.Unmarshal(c.Body, &body); err != nil {
				t.Fatal(err)
			}
			verdict, sent := runReadCase(t, c, c.ReadVersion)
			if len(sent) != c.Expect.Reads {
				t.Fatalf("%d reads made, the case says %d", len(sent), c.Expect.Reads)
			}
			if strings.HasPrefix(c.Applies["sender"], "never emits") {
				if string(sent[0]) == body {
					t.Fatalf("the gateway sent a body no sender emits")
				}
			} else if string(sent[0]) != body {
				t.Fatalf("body:\n%s\nthe case's:\n%s", sent[0], body)
			}
			if verdict != c.Expect.Sender {
				t.Fatalf("reported %q, the case says %q", verdict, c.Expect.Sender)
			}
		})
	}
	if ran != gatewayReadCases {
		t.Fatalf("%d cases name the gateway as a sender, want %d", ran, gatewayReadCases)
	}
}

// With no readVersion (below the new engine version) and with "1", the
// gateway sends read-v1-call's bytes, the same at both; and over /acquire a
// host at "" and at "1" is sent identical reads.
func TestAdmissionReadV1UnchangedByteForByte(t *testing.T) {
	var v1 admissionReadCase
	for _, c := range readAdmissionReadCases(t) {
		if c.Name == "read-v1-call" {
			v1 = c
		}
	}
	var body string
	if err := json.Unmarshal(v1.Body, &body); err != nil {
		t.Fatal(err)
	}
	for _, rv := range []string{"", "1"} {
		verdict, sent := runReadCase(t, v1, rv)
		if verdict != "admit" || len(sent) != 1 || string(sent[0]) != body {
			t.Fatalf("readVersion %q: %s %d\n%s", rv, verdict, len(sent), sent)
		}
	}
	h := newDelegationHarness(t, false)
	cred := h.credential(t, statement(t, nil))
	var calls [][]byte
	for i, rv := range []string{"", "1"} {
		h.d.hosts["desk"].readVersion = rv
		status, out := h.present(t, "/acquire", h.acquireBody("s-v1-"+rv+"x", "query"), cred)
		if status != http.StatusOK {
			t.Fatalf("acquire at %q: %d %v", rv, status, out)
		}
		reads := h.host.rawReads()
		if len(reads) != 2+i {
			t.Fatalf("reads: %d", len(reads))
		}
		calls = append(calls, reads[len(reads)-1])
	}
	if string(calls[0]) != string(calls[1]) || !strings.Contains(string(calls[0]), `"readVersion":"1"`) || strings.Contains(string(calls[0]), "skills") {
		t.Fatalf("a host at \"\" and at \"1\" sent:\n%s\n%s", calls[0], calls[1])
	}
}

const testToolDigest = "sha256:5b0c2a7e9d3f4a1b8c6e0d2f4a6b8c0e2d4f6a8b0c2e4d6f8a0b2c4e6d8f0a2b"

// At "2" an /acquire names the live operation's approved digest and skills
// null, whatever the request carries; each new answer refuses under its
// name with exactly one read, none of them resent at "1"; and at "1" each is
// admission-unknown.
func TestAdmissionReadV2Acquire(t *testing.T) {
	h := newDelegationHarness(t, false)
	live := h.g.sources["tickets/live"]
	live.versions = map[string]string{"query": testToolDigest}
	h.g.sources["tickets/live"] = live
	h.d.hosts["desk"].readVersion = "2"
	root := statement(t, nil)
	cred := h.credential(t, root)
	binding := string(h.host.rawReads()[0])
	if !strings.Contains(binding, `"call":null`) || !strings.Contains(binding, `"readVersion":"2"`) {
		t.Fatalf("binding read at 2: %s", binding)
	}
	status, out := h.present(t, "/acquire", h.acquireBody("s-v2-plain", "query"), cred)
	if status != http.StatusOK {
		t.Fatalf("acquire: %d %v", status, out)
	}
	plain := h.host.rawReads()[1]
	want := `{"at":"2026-10-30T01:00:00.000Z","audience":{"kind":"gateway","name":"` + h.g.authority + `"},"call":{"count":true,"effect":"read-external","skills":null,"source":"tickets/live","tool":"query","version":"` + testToolDigest + `"},"chain":["` + statementDigest(t, root) + `"],"host":"desk","readVersion":"2"}`
	if string(plain) != want {
		t.Fatalf("call read at 2:\n%s\nwant\n%s", plain, want)
	}
	// A request naming a version and skills changes no byte of the read.
	named := `{"session":"s-v2-named","source":"tickets/live","arguments":{"tool":"query","arguments":{"key":"k","version":"sha256:` + strings.Repeat("0", 64) + `","skills":[{"id":"x","digest":"sha256:` + strings.Repeat("1", 64) + `"}]}}}`
	if status, out := h.present(t, "/acquire", named, cred); status != http.StatusOK {
		t.Fatalf("acquire naming a version: %d %v", status, out)
	}
	if got := h.host.rawReads()[2]; string(got) != want {
		t.Fatalf("a request's version or skills reached the read:\n%s", got)
	}
	answers := []struct{ answer, at2, at1 string }{
		{`{"admission":"refuse","refusal":"tool-version-refused"}`, "tool-version-refused", refusalAdmissionUnknown},
		{`{"admission":"refuse","refusal":"skill-refused"}`, "skill-refused", refusalAdmissionUnknown},
		{`{"refusal":"read-version-unsupported"}`, refusalReadVersionUnsupported, refusalAdmissionUnknown},
		{`{"refusal":"read-malformed"}`, refusalReadMalformed, refusalAdmissionUnknown},
		{`{"refusal":"read-malformed","admission":"refuse"}`, refusalAdmissionUnknown, refusalAdmissionUnknown},
		{`{"admission":"refuse","refusal":"skill-refused","reason":"x"}`, refusalAdmissionUnknown, refusalAdmissionUnknown},
	}
	for _, rv := range []string{"2", "1"} {
		h.d.hosts["desk"].readVersion = rv
		for i, a := range answers {
			h.host.setAnswer(func(map[string]any) (int, string) { return http.StatusOK, a.answer })
			before := len(h.host.rawReads())
			status, out := h.present(t, "/acquire", h.acquireBody("s-v2-"+rv+"-"+string(rune('a'+i)), "query"), cred)
			want := a.at2
			if rv == "1" {
				want = a.at1
			}
			reads := h.host.rawReads()
			if status != http.StatusForbidden || refusalOf(out) != want {
				t.Fatalf("at %s, answered %s: %d %v", rv, a.answer, status, out)
			}
			if len(reads) != before+1 || !strings.Contains(string(reads[before]), `"readVersion":"`+rv+`"`) {
				t.Fatalf("at %s, answered %s: %d reads, not one at %s", rv, a.answer, len(reads)-before, rv)
			}
		}
	}
}

// The read's own refusals are reported where steps 8 to 10 are, before the
// gateway's own out-of-scope; a step-12 refusal after it.
func TestAdmissionReadV2Order(t *testing.T) {
	h := newDelegationHarness(t, false)
	h.d.hosts["desk"].readVersion = "2"
	cred := h.credential(t, statement(t, nil))
	h.d.mu.Lock()
	bound := h.d.credentials[tokenDigestOf(cred)]
	h.d.mu.Unlock()
	leaf := bound.chain.leaf()
	who := &delegatedSender{kind: "actor", credential: bound, scope: reservationScope{sub: leaf.sub, rootActor: leaf.agent, host: "desk"}}
	outside := delegatedCall{source: "tickets/live", tool: "elsewhere", effect: "read-external", count: true}
	for answer, want := range map[string]string{
		`{"refusal":"read-malformed"}`:                            refusalReadMalformed,
		`{"refusal":"read-version-unsupported"}`:                  refusalReadVersionUnsupported,
		`{"admission":"refuse","refusal":"tool-version-refused"}`: refusalOutOfScope,
		`{"admission":"refuse","refusal":"skill-refused"}`:        refusalOutOfScope,
	} {
		h.host.setAnswer(func(map[string]any) (int, string) { return http.StatusOK, answer })
		if _, r := h.d.admitDelegated(who, outside); r == nil || r.name != want {
			t.Fatalf("answered %s outside the scope: %v, want %s", answer, r, want)
		}
	}
	h.host.setAnswer(func(map[string]any) (int, string) {
		return http.StatusOK, `{"admission":"refuse","refusal":"tool-version-refused"}`
	})
	inside := delegatedCall{source: "tickets/live", tool: "query", effect: "read-external", count: true, version: testToolDigest}
	if _, r := h.d.admitDelegated(who, inside); r == nil || r.name != "tool-version-refused" {
		t.Fatalf("a step-12 refusal within the scope: %v", r)
	}
}

// The binding read at "2": a step-12 refusal answering it is
// admission-unknown, a body refusal refuses the binding under its name.
func TestAdmissionReadV2Binding(t *testing.T) {
	h := newDelegationHarness(t, false)
	h.d.hosts["desk"].readVersion = "2"
	for answer, want := range map[string]string{
		`{"admission":"refuse","refusal":"tool-version-refused"}`: refusalAdmissionUnknown,
		`{"admission":"refuse","refusal":"skill-refused"}`:        refusalAdmissionUnknown,
		`{"refusal":"read-malformed"}`:                            refusalReadMalformed,
		`{"refusal":"read-version-unsupported"}`:                  refusalReadVersionUnsupported,
	} {
		h.host.setAnswer(func(map[string]any) (int, string) { return http.StatusOK, answer })
		before := h.host.readCount()
		status, out := h.bind(t, []map[string]any{statement(t, nil)}, nil)
		if status != http.StatusForbidden || refusalOf(out) != want || h.host.readCount() != before+1 {
			t.Fatalf("binding answered %s: %d %v", answer, status, out)
		}
	}
}

// The standing read at "2" carries readVersion "2"; a body refusal answering
// it is standing-unknown.
func TestAdmissionReadV2Standing(t *testing.T) {
	sub := principalRef{kind: "person", issuer: testIssuerURL, subject: testSubjectSub}
	for answer, want := range map[string]string{`{"standing":"current"}`: "current", `{"refusal":"read-malformed"}`: "", `{"refusal":"read-version-unsupported"}`: ""} {
		double := newReadDouble(t, answer)
		svc, host := double.service("2", "gateway:test")
		if got := svc.standingRead(host, sub); got != want {
			t.Fatalf("standing answered %s: %q", answer, got)
		}
		if sent := double.sent(); len(sent) != 1 || !strings.Contains(string(sent[0]), `"readVersion":"2"`) {
			t.Fatalf("standing read: %s", sent)
		}
	}
}

// admission.readVersion is the new engine version's member: refused by name
// below it; "1", "2" or absent from it, and nothing else.
func TestEngineVersionGatesAdmissionReadVersion(t *testing.T) {
	host := func(readVersion string) value {
		member := ""
		if readVersion != "" {
			member = `,"readVersion":` + readVersion
		}
		v, err := parseJSON([]byte(`{"host":"desk","requester":"service:desk","keys":["00028d283e279178a6ce561e45f1b89f2a6ac45690fbb5ac48313ad61ab04584"],"admission":{"url":"https://issuer-a.example/admission","credential":"/etc/engine/issuer-a-token"` + member + `}}`))
		if err != nil {
			t.Fatal(err)
		}
		return v
	}
	if _, err := parseDelegationHost(host(`"2"`), requestLimitsVersion); err == nil || !strings.Contains(err.Error(), "admission.readVersion is a version-"+admissionReadV2Version+" member") {
		t.Fatalf("readVersion below the version: %v", err)
	}
	if h, err := parseDelegationHost(host(""), requestLimitsVersion); err != nil || h.readVersion != "" || h.sentVersion() != "1" {
		t.Fatalf("no readVersion below the version: %v %q", err, h.readVersion)
	}
	for given, want := range map[string]string{"": "1", `"1"`: "1", `"2"`: "2"} {
		if h, err := parseDelegationHost(host(given), admissionReadV2Version); err != nil || h.readVersion != want {
			t.Fatalf("readVersion %s: %v %q", given, err, h.readVersion)
		}
	}
	for _, bad := range []string{`3`, `"3"`, `""`, `true`, `null`, `["2"]`} {
		if _, err := parseDelegationHost(host(bad), admissionReadV2Version); err == nil || !strings.Contains(err.Error(), "host desk: admission.readVersion is "+bad+`; it is "1" or "2"`) {
			t.Fatalf("readVersion %s: %v", bad, err)
		}
	}
	if !engineVersions[admissionReadV2Version] || engineVersion != admissionReadV2Version {
		t.Fatalf("the engine reads %q, newest %q", admissionReadV2Version, engineVersion)
	}
}

// toolVersions: labels by allowed tool, of the label form.
func TestAdmissionReadToolVersionsForm(t *testing.T) {
	parse := func(text string) (map[string]string, error) {
		v, err := parseJSON([]byte(text))
		if err != nil {
			t.Fatal(err)
		}
		return parseToolVersions(v.(*vObject), []string{"query", "search"})
	}
	if got, err := parse(`{"toolVersions":{"query":"2.4.1+build.7"}}`); err != nil || got["query"] != "2.4.1+build.7" || len(got) != 1 {
		t.Fatalf("a label: %v %v", got, err)
	}
	if got, err := parse(`{}`); err != nil || got != nil {
		t.Fatalf("none: %v %v", got, err)
	}
	for _, bad := range []string{`{"toolVersions":{"other":"1"}}`, `{"toolVersions":{"query":""}}`, `{"toolVersions":{"query":".1"}}`, `{"toolVersions":{"query":"a b"}}`, `{"toolVersions":{"query":"` + strings.Repeat("a", 65) + `"}}`, `{"toolVersions":{"query":1}}`, `{"toolVersions":["query"]}`} {
		if _, err := parse(bad); err == nil {
			t.Fatalf("accepted %s", bad)
		}
	}
}

// Posture names each issuing host's readVersion from the new engine version,
// and nothing new below it.
func TestPostureNamesEachHostsReadVersion(t *testing.T) {
	if lines := delegationLines(&delegationPosture{}, nil); len(lines) != 3 {
		t.Fatalf("below the version: %v", lines)
	}
	for versions, state := range map[string]string{"1,1": postureNotEnforced, "2,1": posturePartial, "2,2": postureEnforced} {
		v := strings.Split(versions, ",")
		lines := delegationLines(&delegationPosture{readVersions: map[string]string{"desk": v[0], "issuer-b": v[1]}}, nil)
		last := lines[len(lines)-1]
		if len(lines) != 4 || last.name != protectionDelegationReadVersion || last.state != state || !strings.Contains(last.reason, `desk at "`+v[0]+`", issuer-b at "`+v[1]+`"`) {
			t.Fatalf("%s: %v", versions, last)
		}
	}
}

// tools/list _meta names descriptorDigest and versionLabel at the new engine
// version alone; below it the entry is byte for byte as before.
func TestMCPListingMetaVersionMembers(t *testing.T) {
	p := &servedPlatform{tools: map[string]servedTool{"query": {descriptorDigest: testToolDigest}}}
	tool := mcpTool{name: "tickets.query", platform: "tickets", tool: "query", binding: "tickets@1", taxonomy: ToolTaxonomy{Operation: "read", Effect: "read-external"}}
	before, err := listingEntry(tool, p, -1)
	if err != nil {
		t.Fatal(err)
	}
	labelled := tool
	labelled.versionLabel = "2.4.1"
	if below, _ := listingEntry(labelled, p, -1); string(below) != string(before) || strings.Contains(string(before), "descriptorDigest") {
		t.Fatalf("below the version:\n%s\n%s", below, before)
	}
	labelled.versionMeta = true
	at, _ := listingEntry(labelled, p, -1)
	var entry struct {
		Meta map[string]any `json:"_meta"`
	}
	if err := json.Unmarshal(at, &entry); err != nil || entry.Meta["descriptorDigest"] != testToolDigest || entry.Meta["versionLabel"] != "2.4.1" {
		t.Fatalf("at the version: %s", at)
	}
	plain, _ := listingEntry(labelled, nil, -1)
	if strings.Contains(string(plain), "descriptorDigest") || !strings.Contains(string(plain), `"versionLabel":"2.4.1"`) {
		t.Fatalf("described as if nothing were captured: %s", plain)
	}
}

// The start holds each source's digests from its pinned snapshot only when
// some host is read at "2": a snapshot of a version holding no
// descriptorDigest gives every tool null, and one whose bytes are not the
// pin refuses the start.
func TestAdmissionReadV2HoldsTheDigestsAtStart(t *testing.T) {
	f := newServedFixture(t, canonicalSnapshot(t, servedTools))
	f.cfg.configPath = f.config
	sources := map[string]sourceSpec{"tickets/live": {shape: "mcp"}}
	f.cfg.delegation = &delegationSpec{hosts: []delegationHostSpec{{host: "desk", readVersion: "1"}}}
	if err := os.WriteFile(f.path(), []byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := holdToolVersions(f.cfg, f.bindings, sources); err != nil || sources["tickets/live"].versions != nil {
		t.Fatalf("no host at 2 reads nothing: %v %v", err, sources["tickets/live"].versions)
	}
	f.cfg.delegation.hosts[0].readVersion = "2"
	if err := holdToolVersions(f.cfg, f.bindings, sources); err == nil {
		t.Fatal("a pinned snapshot whose bytes are not the pin started")
	}
	if err := os.WriteFile(f.path(), canonicalSnapshot(t, servedTools), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := holdToolVersions(f.cfg, f.bindings, sources); err != nil {
		t.Fatal(err)
	}
	if v := sources["tickets/live"].versions; v == nil || len(v) != 0 {
		t.Fatalf("a snapshot holding no descriptorDigest: %v", v)
	}
}
