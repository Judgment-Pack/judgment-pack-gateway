package agreement

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
	"time"

	"adapters/airbyte"
	"adapters/mcp"
)

// The golden record of the postgres platform: the World sample database's
// city with id 1 (docs/design/both-paths-agreement.md). The live query asks
// the database to render the row as JSON and hand it over as text; the
// history request names the stream and reads the page that holds the row.
const (
	worldImage    = "ghusta/postgres-world-db:2.15.1@sha256:879d0919fdccb39a2508a21fe784d046f7a6f2b51ef4de5ba845eabdb93eb8c3"
	goldenQuery   = "SELECT to_jsonb(c)::text AS record FROM city c WHERE id = 1"
	untypedQuery  = "SELECT id, name, country_code, district, population, local_name FROM city WHERE id = 1"
	textPastQuery = "SELECT to_jsonb(x)::text AS record FROM (SELECT 9007199254740993::bigint AS n) x"
	jsonPastQuery = "SELECT to_jsonb(x) AS record FROM (SELECT 9007199254740993::bigint AS n) x"
	goldenKey     = "id"
	goldenKeyJSON = "1"
	goldenFacts   = `{"country_code":"AFG","district":"Kabol","id":1,"local_name":null,"name":"Kabul","population":1780000}`
	// past the canon domain, an integer is carried as text spelled as the
	// database spelled it; through a JSON column parsed by the driver it is
	// rounded to the nearest double first
	pastFacts    = `{"n":"9007199254740993"}`
	roundedFacts = `{"record":{"n":"9007199254740992"}}`
)

func fixture(t *testing.T, name string) Envelope {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", "postgres", name))
	if err != nil {
		t.Fatal(err)
	}
	e, err := Parse(data)
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	return e
}

// binding reads the shipped binding: the images each operation pins, so a
// fixture captured under another artifact cannot pass as the platform's.
func binding(t *testing.T) (historyImage, liveImage string) {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "..", "catalog", "postgres.json"))
	if err != nil {
		t.Fatal(err)
	}
	var b struct {
		Operations struct {
			History struct {
				Image string `json:"image"`
			} `json:"history"`
			Live struct {
				Server struct {
					Image string `json:"image"`
				} `json:"server"`
			} `json:"live"`
		} `json:"operations"`
	}
	if err := json.Unmarshal(data, &b); err != nil {
		t.Fatal(err)
	}
	if b.Operations.History.Image == "" || b.Operations.Live.Server.Image == "" {
		t.Fatal("the binding names no images")
	}
	return b.Operations.History.Image, b.Operations.Live.Server.Image
}

func digestOf(image string) string { return image[strings.LastIndex(image, "@")+1:] }

// statementMembers reads a statement as the object the adapter recorded.
func statementMembers(t *testing.T, e Envelope) map[string]json.RawMessage {
	t.Helper()
	if e.Acquisition.Statement == nil {
		t.Fatal("no statement recorded")
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal([]byte(*e.Acquisition.Statement), &m); err != nil {
		t.Fatalf("statement is not an object: %v", err)
	}
	return m
}

// requireHistoryStatement holds a history envelope to the read it claims: the
// stream, the namespace, the sync mode and the cursor, and no state resumed.
func requireHistoryStatement(t *testing.T, e Envelope, syncMode string) {
	t.Helper()
	m := statementMembers(t, e)
	want := map[string]string{"stream": `"city"`, "namespace": `"public"`, "syncMode": `"` + syncMode + `"`, "cursorField": "null", "state": "null"}
	if len(m) != len(want) {
		t.Fatalf("history statement has %d members, want %d: %s", len(m), len(want), *e.Acquisition.Statement)
	}
	for k, v := range want {
		if string(m[k]) != v {
			t.Fatalf("history statement %s = %s, want %s", k, m[k], v)
		}
	}
	if !e.Page || e.Acquisition.Schema == nil || !strings.HasPrefix(*e.Acquisition.Schema, "sha256:") {
		t.Fatal("history envelope is not a page with a schema digest")
	}
}

// requireLiveStatement holds a live envelope to the one tool call it claims.
func requireLiveStatement(t *testing.T, e Envelope, sql string) {
	t.Helper()
	m := statementMembers(t, e)
	args, _ := json.Marshal(map[string]string{"sql": sql})
	if len(m) != 2 || string(m["tool"]) != `"execute_sql"` || string(m["arguments"]) != string(args) {
		t.Fatalf("live statement is not execute_sql of %q: %s", sql, *e.Acquisition.Statement)
	}
	if e.Page {
		t.Fatal("a live envelope is not a page")
	}
}

func requireDigest(t *testing.T, e Envelope, image string) {
	t.Helper()
	if e.Acquisition.Adapter.Digest != digestOf(image) {
		t.Fatalf("captured under %s, not the binding's %s", e.Acquisition.Adapter.Digest, image)
	}
}

func TestTheGoldenRecordDerivesToTheSameFactsThroughBothShapes(t *testing.T) {
	historyImage, liveImage := binding(t)
	history, live := fixture(t, "history.json"), fixture(t, "live.json")
	requireDigest(t, history, historyImage)
	requireDigest(t, live, liveImage)
	requireHistoryStatement(t, history, "full_refresh")
	requireLiveStatement(t, live, goldenQuery)
	h, err := HistoryFacts(history, goldenKey, json.RawMessage(goldenKeyJSON))
	if err != nil {
		t.Fatal(err)
	}
	l, err := LiveFacts(live)
	if err != nil {
		t.Fatal(err)
	}
	if string(h) != string(l) {
		t.Fatalf("the two shapes disagree:\nhistory: %s\nlive:    %s", h, l)
	}
	if string(h) != goldenFacts {
		t.Fatalf("the facts are not the golden record's:\n%s", h)
	}
}

// keysOf returns an object's member names, sorted.
func keysOf(t *testing.T, facts []byte) ([]string, map[string]json.RawMessage) {
	t.Helper()
	var m map[string]json.RawMessage
	if err := json.Unmarshal(facts, &m); err != nil {
		t.Fatal(err)
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys, m
}

// The rule asks the database to render the row because a driver's typing is
// not the database's: through the same server, a plain SELECT hands the two
// bigint columns back as strings, and the row then has exactly the
// connector's members and differs on exactly those two. Kept so the rule's
// reason is pinned to evidence.
func TestADriverTypedRowIsNotTheConnectorsRecord(t *testing.T) {
	_, liveImage := binding(t)
	history, untyped := fixture(t, "history.json"), fixture(t, "live-driver-typed.json")
	requireDigest(t, untyped, liveImage)
	requireLiveStatement(t, untyped, untypedQuery)
	h, err := HistoryFacts(history, goldenKey, json.RawMessage(goldenKeyJSON))
	if err != nil {
		t.Fatal(err)
	}
	u, err := LiveRowFacts(untyped)
	if err != nil {
		t.Fatal(err)
	}
	requireDriverTypedDivergence(t, h, u)
}

// requireDriverTypedDivergence holds a driver-typed row against the
// connector's record: the same member names, both ways, and a difference on
// id and population alone, each a string on the driver's side.
func requireDriverTypedDivergence(t *testing.T, connector, driver []byte) {
	t.Helper()
	if string(connector) == string(driver) {
		t.Fatal("a driver-typed row agreed with the connector's record; the rule no longer needs to_jsonb, revise the design note")
	}
	hk, hm := keysOf(t, connector)
	uk, um := keysOf(t, driver)
	if strings.Join(hk, ",") != strings.Join(uk, ",") {
		t.Fatalf("the two rows have different members: connector %v, driver %v", hk, uk)
	}
	var differ []string
	for _, k := range hk {
		if string(hm[k]) != string(um[k]) {
			differ = append(differ, k)
		}
	}
	if strings.Join(differ, ",") != "id,population" {
		t.Fatalf("the members that differ are %v, not the two bigint columns", differ)
	}
	if string(um["id"]) != `"1"` || string(um["population"]) != `"1780000"` {
		t.Fatalf("the driver rendered the bigints as %s and %s, not as strings", um["id"], um["population"])
	}
}

// The rule hands the rendered row over as text because a JSON column is
// parsed by the driver as JavaScript numbers: an integer past 2^53 comes
// back rounded, where the text keeps the database's spelling and the canon
// carries it, past the domain, as that spelling. Kept so the rule's second
// reason is pinned to evidence.
func TestAnIntegerPastTheCanonDomainSurvivesOnlyAsText(t *testing.T) {
	_, liveImage := binding(t)
	text, rounded := fixture(t, "live-text-past-2p53.json"), fixture(t, "live-jsonb-past-2p53.json")
	requireDigest(t, text, liveImage)
	requireDigest(t, rounded, liveImage)
	requireLiveStatement(t, text, textPastQuery)
	requireLiveStatement(t, rounded, jsonPastQuery)
	facts, err := LiveFacts(text)
	if err != nil {
		t.Fatal(err)
	}
	if string(facts) != pastFacts {
		t.Fatalf("the text-carried integer derived to %s, not %s", facts, pastFacts)
	}
	if _, err := LiveFacts(rounded); err == nil || !strings.Contains(err.Error(), "not text") {
		t.Fatalf("a JSON column derived facts under the rule: %v", err)
	}
	row, err := LiveRowFacts(rounded)
	if err != nil {
		t.Fatal(err)
	}
	if string(row) != roundedFacts {
		t.Fatalf("the driver-parsed JSON column came back as %s, not rounded as %s; the rule's reason has changed, revise the design note", row, roundedFacts)
	}
}

// withText rebuilds a live envelope's result around the given answer text.
func withText(e Envelope, text string, isError bool) Envelope {
	result := map[string]any{"content": []map[string]string{{"type": "text", "text": text}}}
	if isError {
		result["isError"] = true
	}
	e.Result, _ = json.Marshal(result)
	return e
}

// textOf returns a live envelope's answer text.
func textOf(t *testing.T, e Envelope) string {
	t.Helper()
	var r struct {
		Content []struct {
			Text string `json:"text"`
		} `json:"content"`
	}
	if err := json.Unmarshal(e.Result, &r); err != nil || len(r.Content) != 1 {
		t.Fatal("not one content item")
	}
	return r.Content[0].Text
}

func TestDerivationRefusals(t *testing.T) {
	history := fixture(t, "history.json")
	if _, err := HistoryFacts(history, goldenKey, json.RawMessage("999999")); err == nil || !strings.Contains(err.Error(), "no record has") {
		t.Fatalf("a key no record carries: %v", err)
	}
	if _, err := HistoryFacts(history, "country_code", json.RawMessage(`"AFG"`)); err == nil || !strings.Contains(err.Error(), "more than one record") {
		t.Fatalf("a key many records carry: %v", err)
	}
	unpaged := history
	unpaged.Page = false
	if _, err := HistoryFacts(unpaged, goldenKey, json.RawMessage(goldenKeyJSON)); err == nil || !strings.Contains(err.Error(), "not a page") {
		t.Fatalf("a history result that is not a page: %v", err)
	}

	live := fixture(t, "live.json")
	if _, err := LiveFacts(fixture(t, "live-driver-typed.json")); err == nil || !strings.Contains(err.Error(), "`record`") {
		t.Fatalf("a live answer without the rendered record: %v", err)
	}
	good := textOf(t, live)
	if _, err := LiveFacts(withText(live, good, false)); err != nil {
		t.Fatalf("the rebuilt good answer: %v", err)
	}
	cases := []struct {
		name string
		e    Envelope
		want string
	}{
		{"a well-formed answer marked as an error", withText(live, good, true), "reports an error"},
		{"success false with Success true", withText(live, strings.Replace(good, `"success": true`, `"success": false, "Success": true`, 1), false), "not DBHub's answer"},
		{"a duplicate wrapper member", withText(live, strings.Replace(good, `"success": true`, `"success": true, "success": true`, 1), false), "not well-formed"},
		{"success not true", withText(live, strings.Replace(good, `"success": true`, `"success": false`, 1), false), "not a success"},
		{"an extra row member", withText(live, strings.Replace(good, `"record":`, `"extra": 1, "record":`, 1), false), "exactly one member"},
		{"a count that is not one", withText(live, strings.Replace(good, `"count": 1`, `"count": 2`, 1), false), "count of one"},
		{"an unknown statement member", withText(live, strings.Replace(good, `"count": 1`, `"count": 1, "warnings": []`, 1), false), "statement"},
		{"a second statement", withText(live, strings.Replace(good, `"statements": [`, `"statements": [{"sql": "SELECT 1", "rows": [], "count": 0}, `, 1), false), "not one statement"},
		{"a record that holds an array", withText(live, strings.Replace(good, `"record": "{`, `"record": "[{`, 1), false), "JSON object"},
		{"a record that holds a scalar", withText(live, regexp.MustCompile(`"record": "\{[^\n]*\}"`).ReplaceAllString(good, `"record": "1"`), false), "JSON object"},
	}
	for _, c := range cases {
		if _, err := LiveFacts(c.e); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v", c.name, err)
		}
		if _, err := LiveRowFacts(c.e); err == nil && !strings.HasPrefix(c.name, "a record") && c.name != "an extra row member" {
			t.Errorf("%s: the row derivation did not refuse it", c.name)
		}
	}

	envelope, _ := os.ReadFile(filepath.Join("testdata", "postgres", "live.json"))
	for name, mutate := range map[string]func(string) string{
		"no adapter digest":               func(s string) string { return strings.Replace(s, `"digest":"sha256:`, `"digest":"`, 1) },
		"a member the spec does not name": func(s string) string { return strings.Replace(s, `"endpoint":`, `"shape":"mcp","endpoint":`, 1) },
		"a missing member":                func(s string) string { return regexp.MustCompile(`"peerIdentity":null,`).ReplaceAllString(s, "") },
		"page not true":                   func(s string) string { return strings.Replace(s, `"result":`, `"page":false,"result":`, 1) },
		"observedAt with a zone offset": func(s string) string {
			return regexp.MustCompile(`"observedAt":"([^"]*)Z"`).ReplaceAllString(s, `"observedAt":"${1}+00:00"`)
		},
		"a duplicate member": func(s string) string { return strings.Replace(s, `"endpoint":`, `"endpoint":"x","endpoint":`, 1) },
	} {
		mutated := mutate(string(envelope))
		if mutated == string(envelope) {
			t.Fatalf("%s: the mutation did not apply", name)
		}
		if _, err := Parse([]byte(mutated)); err == nil {
			t.Errorf("%s: parsed", name)
		}
	}
}

// TestBothPathsAgreeOnAFreshFetch fetches the golden record both ways
// against a World database started in the container runtime AGREEMENT_RUNTIME
// names (docker or podman), through the adapter implementations as the
// binaries call them, under a role Postgres holds to reading, and holds the
// fresh facts to each other and to the fixtures'; it also fetches the two
// counterexamples afresh, so a driver that stops rounding or stops typing is
// noticed, and reads the stream once more in the connector's xmin mode,
// whose cursor the connector defines, to hold that read to incremental.
// Without the variable it is skipped: the fixtures above are the offline
// record, and this is the test that keeps them honest wherever a runtime
// is at hand (the CI job "both paths agree").
func TestBothPathsAgreeOnAFreshFetch(t *testing.T) {
	runtime := os.Getenv("AGREEMENT_RUNTIME")
	if runtime == "" {
		t.Skip("set AGREEMENT_RUNTIME=docker (or podman) to fetch the golden record both ways")
	}
	historyImage, liveImage := binding(t)
	name := fmt.Sprintf("jp-agreement-%d-%d", os.Getpid(), time.Now().UnixNano())
	run := func(timeout time.Duration, args ...string) ([]byte, error) {
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()
		return exec.CommandContext(ctx, runtime, args...).CombinedOutput()
	}
	// registered before the database is started, so a container the runtime
	// created and could not start is removed too, with its anonymous volume
	t.Cleanup(func() {
		if out, err := run(time.Minute, "rm", "-fv", name); err != nil && !strings.Contains(string(out), "No such container") {
			t.Errorf("removing the World database container: %v\n%s", err, out)
		}
	})
	if out, err := run(5*time.Minute, "run", "-d", "--name", name, "-e", "POSTGRES_PASSWORD=world123", worldImage); err != nil {
		t.Fatalf("starting the World database: %v\n%s", err, out)
	}
	// The image's first start loads the data through a temporary server
	// that answers on the socket alone and then restarts; ready is when a
	// query over TCP sees every city.
	deadline := time.Now().Add(3 * time.Minute)
	for {
		out, err := run(20*time.Second, "exec", name, "psql", "-h", "127.0.0.1", "-U", "world", "-d", "world-db", "-Atc", "SELECT count(*) FROM city")
		if err == nil && strings.TrimSpace(string(out)) == "4079" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("the World database did not become ready: %v\n%s", err, out)
		}
		time.Sleep(time.Second)
	}
	// the reading role the binding's README requires of a live connection
	// string: SELECT alone is what holds it to reading; the transaction
	// default is a guard a session can lift, and the test shows both
	grants := "CREATE ROLE reader LOGIN PASSWORD 'reader123'; GRANT CONNECT ON DATABASE \"world-db\" TO reader; GRANT USAGE ON SCHEMA public TO reader; GRANT SELECT ON ALL TABLES IN SCHEMA public TO reader; ALTER ROLE reader SET default_transaction_read_only = on;"
	if out, err := run(20*time.Second, "exec", name, "psql", "-h", "127.0.0.1", "-U", "world", "-d", "world-db", "-Atc", grants); err != nil {
		t.Fatalf("creating the reading role: %v\n%s", err, out)
	}
	ipOut, err := run(20*time.Second, "inspect", "-f", "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}", name)
	if err != nil {
		t.Fatalf("inspecting the database container: %v\n%s", err, ipOut)
	}
	ip := strings.TrimSpace(string(ipOut))
	if !regexp.MustCompile(`^\d+\.\d+\.\d+\.\d+$`).MatchString(ip) {
		t.Fatalf("no address for the database container: %q", ip)
	}
	dir := t.TempDir()
	liveCreds := filepath.Join(dir, "live.json")
	if err := os.WriteFile(liveCreds, []byte(fmt.Sprintf(`{"DSN": "postgresql://reader:reader123@%s:5432/world-db"}`, ip)), 0o600); err != nil {
		t.Fatal(err)
	}
	historyCreds := func(method string) string {
		path := filepath.Join(dir, "history-"+strings.ToLower(method)+".json")
		if err := os.WriteFile(path, []byte(fmt.Sprintf(`{"host": "%s", "port": 5432, "database": "world-db", "username": "reader", "password": "reader123", "schemas": ["public"], "ssl_mode": {"mode": "disable"}, "replication_method": {"method": "%s"}}`, ip, method)), 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	liveCfg := mcp.Config{Runtime: runtime, Image: liveImage, Args: []string{"--transport", "stdio"}, Credentials: liveCreds, Endpoint: ip, Tools: []string{"execute_sql", "search_objects"}, MaxOutput: 1 << 20}
	query := func(sql string) Envelope {
		t.Helper()
		req, err := mcp.ParseRequest(strings.NewReader(fmt.Sprintf(`{"tool":"execute_sql","arguments":{"sql":%q}}`, sql)))
		if err != nil {
			t.Fatal(err)
		}
		out, err := mcp.Acquire(ctx, liveCfg, req)
		if err != nil {
			t.Fatalf("live fetch of %q: %v", sql, err)
		}
		e, err := Parse(out)
		if err != nil {
			t.Fatal(err)
		}
		requireDigest(t, e, liveImage)
		requireLiveStatement(t, e, sql)
		return e
	}
	refused := func(sql, reason string) {
		t.Helper()
		req, _ := mcp.ParseRequest(strings.NewReader(fmt.Sprintf(`{"tool":"execute_sql","arguments":{"sql":%q}}`, sql)))
		if _, err := mcp.Acquire(ctx, liveCfg, req); err == nil || !strings.Contains(err.Error(), reason) {
			t.Fatalf("%q was not refused with %q: %v", sql, reason, err)
		}
	}
	live := query(goldenQuery)
	l, err := LiveFacts(live)
	if err != nil {
		t.Fatal(err)
	}
	// the reading role holds: a write is Postgres's refusal, reported as an
	// error result and so a failed acquisition -- by the transaction default
	// when the session leaves it, and by the role's privileges when the
	// session lifts it, which a session may
	refused("UPDATE city SET population = population WHERE id = 1", "cannot execute UPDATE in a read-only transaction")
	refused("BEGIN READ WRITE; UPDATE city SET population = population WHERE id = 1; COMMIT", "permission denied for table city")

	historyCfg := airbyte.Config{Runtime: runtime, Image: historyImage, Credentials: historyCreds("Standard"), Endpoint: ip, MaxRecords: 5000, MaxOutput: 8 << 20}
	read := func(cfg airbyte.Config, syncMode string) Envelope {
		t.Helper()
		req, err := airbyte.ParseRequest(strings.NewReader(`{"stream":"city","namespace":"public","limit":5000}`), 5000)
		if err != nil {
			t.Fatal(err)
		}
		out, err := airbyte.Acquire(ctx, cfg, req)
		if err != nil {
			t.Fatalf("history fetch (%s): %v", syncMode, err)
		}
		e, err := Parse(out)
		if err != nil {
			t.Fatal(err)
		}
		requireDigest(t, e, historyImage)
		requireHistoryStatement(t, e, syncMode)
		return e
	}
	history := read(historyCfg, "full_refresh")
	h, err := HistoryFacts(history, goldenKey, json.RawMessage(goldenKeyJSON))
	if err != nil {
		t.Fatal(err)
	}
	if string(h) != string(l) || string(h) != goldenFacts {
		t.Fatalf("a fresh fetch disagrees:\nhistory: %s\nlive:    %s\ngolden:  %s", h, l, goldenFacts)
	}
	fixtureHistory := fixture(t, "history.json")
	if fh, _ := HistoryFacts(fixtureHistory, goldenKey, json.RawMessage(goldenKeyJSON)); string(fh) != string(h) {
		t.Fatalf("the fixtures no longer say what a fresh fetch says:\nfixture: %s\nfresh:   %s", fh, h)
	}
	if *history.Acquisition.Schema != *fixtureHistory.Acquisition.Schema {
		t.Fatalf("the stream's schema digest is %s afresh and %s in the fixture", *history.Acquisition.Schema, *fixtureHistory.Acquisition.Schema)
	}

	// the counterexamples, afresh: the driver still types a plain SELECT's
	// bigints as strings, and still rounds a JSON column past 2^53, where
	// the text keeps the spelling
	untyped, err := LiveRowFacts(query(untypedQuery))
	if err != nil {
		t.Fatal(err)
	}
	requireDriverTypedDivergence(t, h, untyped)
	if facts, err := LiveFacts(query(textPastQuery)); err != nil || string(facts) != pastFacts {
		t.Fatalf("the text-carried integer past 2^53: %s %v", facts, err)
	}
	if row, err := LiveRowFacts(query(jsonPastQuery)); err != nil || string(row) != roundedFacts {
		t.Fatalf("the JSON column past 2^53 came back as %s (%v), not rounded as %s; the rule's reason has changed, revise the design note", row, err, roundedFacts)
	}

	// the connector's xmin mode defines the cursor itself and names no
	// field: the read is incremental, and the record is the same
	xminCfg := historyCfg
	xminCfg.Credentials = historyCreds("Xmin")
	xmin := read(xminCfg, "incremental")
	if x, err := HistoryFacts(xmin, goldenKey, json.RawMessage(goldenKeyJSON)); err != nil || string(x) != goldenFacts {
		t.Fatalf("the xmin-mode read: %s %v", x, err)
	}
	if *xmin.Acquisition.Schema != *history.Acquisition.Schema {
		t.Fatalf("the xmin-mode read discovered another schema: %s", *xmin.Acquisition.Schema)
	}
}
