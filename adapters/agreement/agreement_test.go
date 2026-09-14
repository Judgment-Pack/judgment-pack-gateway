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
	goldenKey     = "id"
	goldenKeyJSON = "1"
	goldenFacts   = `{"country_code":"AFG","district":"Kabol","id":1,"local_name":null,"name":"Kabul","population":1780000}`
	// The second golden record: a one-row table holding an integer past the
	// canon domain, 2^53 + 1. Both shapes carry it as text spelled as the
	// database spelled it; through a JSON column parsed by the driver it is
	// rounded to the nearest double first.
	pastTable     = "CREATE TABLE past (n bigint); INSERT INTO past VALUES (9007199254740993); GRANT SELECT ON past TO reader;"
	textPastQuery = "SELECT to_jsonb(p)::text AS record FROM past p"
	jsonPastQuery = "SELECT to_jsonb(p) AS record FROM past p"
	pastKey       = "n"
	pastKeyJSON   = "9007199254740993"
	pastFacts     = `{"n":"9007199254740993"}`
	roundedFacts  = `{"record":{"n":"9007199254740992"}}`
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
	m, err := Statement(e)
	if err != nil {
		t.Fatal(err)
	}
	return m
}

// requireHistoryStatement holds a history envelope to the read it claims: the
// stream, the namespace, the sync mode and the cursor, and no state resumed.
func requireHistoryStatement(t *testing.T, e Envelope, stream, syncMode string) {
	t.Helper()
	m := statementMembers(t, e)
	want := map[string]string{"stream": `"` + stream + `"`, "namespace": `"public"`, "syncMode": `"` + syncMode + `"`, "cursorField": "null", "state": "null"}
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
	requireHistoryStatement(t, history, "city", "full_refresh")
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

// The second golden record, past the canon domain: the connector carries
// 2^53 + 1 as text spelled as the database spelled it, and so does the
// rendered row handed over as text, and the two agree. The rule hands the
// row over as text because a JSON column is parsed by the driver as
// JavaScript numbers and the same integer comes back rounded. Kept so the
// rule's second reason is pinned to evidence.
func TestAnIntegerPastTheCanonDomainAgreesOnlyAsText(t *testing.T) {
	historyImage, liveImage := binding(t)
	history, text, rounded := fixture(t, "history-past-2p53.json"), fixture(t, "live-text-past-2p53.json"), fixture(t, "live-jsonb-past-2p53.json")
	requireDigest(t, history, historyImage)
	requireDigest(t, text, liveImage)
	requireDigest(t, rounded, liveImage)
	requireHistoryStatement(t, history, "past", "full_refresh")
	requireLiveStatement(t, text, textPastQuery)
	requireLiveStatement(t, rounded, jsonPastQuery)
	h, err := HistoryFacts(history, pastKey, json.RawMessage(pastKeyJSON))
	if err != nil {
		t.Fatal(err)
	}
	facts, err := LiveFacts(text)
	if err != nil {
		t.Fatal(err)
	}
	if string(h) != string(facts) || string(facts) != pastFacts {
		t.Fatalf("the integer past 2^53 derived to\nhistory: %s\nlive:    %s\nwant:    %s", h, facts, pastFacts)
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

// quote encodes a string as a JSON string.
func quote(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
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
	// what the pinned server may add is read as its type
	withMessages := strings.Replace(good, `"source_id": "default"`, `"source_id": "default", "messages": ["NOTICE: fine"]`, 1)
	if _, err := LiveFacts(withText(live, withMessages, false)); err != nil {
		t.Fatalf("an answer with messages: %v", err)
	}
	// a string is its value, whatever its spelling: an escape a recorder
	// preserved in the statement, or the server used in its echo, is the
	// same SQL
	escapedStatement := strings.Replace(*live.Acquisition.Statement, `"sql":"SELECT`, `"sql":"\u0053ELECT`, 1)
	escaped := live
	escaped.Acquisition.Statement = &escapedStatement
	if escapedStatement == *live.Acquisition.Statement {
		t.Fatal("the statement escape did not apply")
	}
	if _, err := LiveFacts(escaped); err != nil {
		t.Fatalf("a statement with the SQL under an escape: %v", err)
	}
	if _, err := LiveFacts(withText(live, strings.Replace(good, `"sql": "SELECT`, `"sql": "\u0053ELECT`, 1), false)); err != nil {
		t.Fatalf("an echo with the SQL under an escape: %v", err)
	}
	if _, err := LiveFacts(withText(live, strings.Replace(good, `"success": true`, `"succ\u0065ss": true`, 1), false)); err != nil {
		t.Fatalf("a member name under an escape: %v", err)
	}
	escapedTool := strings.Replace(*live.Acquisition.Statement, `"tool":"execute_sql"`, `"tool":"execute_sq\u006c"`, 1)
	escaped.Acquisition.Statement = &escapedTool
	if escapedTool == *live.Acquisition.Statement {
		t.Fatal("the tool escape did not apply")
	}
	if _, err := LiveFacts(escaped); err != nil {
		t.Fatalf("a statement with the tool name under an escape: %v", err)
	}
	cases := []struct {
		name string
		e    Envelope
		want string
	}{
		{"a well-formed answer marked as an error", withText(live, good, true), "reports an error"},
		{"messages that are not strings", withText(live, strings.Replace(good, `"source_id": "default"`, `"source_id": "default", "messages": [1]`, 1), false), "messages"},
		{"a source_id that is not a string", withText(live, strings.Replace(good, `"source_id": "default"`, `"source_id": 1`, 1), false), "source_id"},
		{"an answer to other SQL than the statement records", withText(live, strings.Replace(good, `"sql": "SELECT`, `"sql": "SELECT /* other */`, 1), false), "other SQL"},
		{"a count that is not a number", withText(live, strings.Replace(good, `"count": 1`, `"count": "1"`, 1), false), "count of one"},
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
	// the tool result around the text, as the signer reads it: an envelope
	// built by hand is held to the same as one parsed
	for name, result := range map[string]string{
		"a duplicate isError, the last one false": `{"content":[{"type":"text","text":` + quote(good) + `}],"isError":true,"isError":false}`,
		"an isError that is not a boolean":        `{"content":[{"type":"text","text":` + quote(good) + `}],"isError":"false"}`,
		"a scalar structuredContent":              `{"content":[{"type":"text","text":` + quote(good) + `}],"structuredContent":1}`,
		"a number past the canon domain":          `{"content":[{"type":"text","text":` + quote(good) + `}],"_meta":{"n":9007199254740993}}`,
		"a duplicate member under an escape":      `{"content":[{"type":"text","text":` + quote(good) + `}],"isError":true,"isErr\u006fr":false}`,
	} {
		e := live
		e.Result = json.RawMessage(result)
		if _, err := LiveFacts(e); err == nil {
			t.Errorf("%s: derived facts", name)
		}
		if _, err := LiveRowFacts(e); err == nil {
			t.Errorf("%s: the row derivation did not refuse it", name)
		}
	}
	// the statement is a JSON text inside a string, which the envelope's
	// own check does not look into
	for name, statement := range map[string]string{
		"a duplicate member":                 `{"arguments":{"sql":"SELECT 1"},"tool":"execute_sql","tool":"execute_sql"}`,
		"a duplicate member under an escape": `{"arguments":{"sql":"SELECT 1"},"tool":"execute_sql","to\u006fl":"execute_sql"}`,
		"not an object":                      `["execute_sql"]`,
	} {
		e := live
		e.Acquisition.Statement = &statement
		if _, err := Statement(e); err == nil {
			t.Errorf("statement with %s: read", name)
		}
		if _, err := LiveFacts(e); err == nil {
			t.Errorf("statement with %s: derived facts", name)
		}
	}
	// a history result built by hand is held to the same, as a whole: a
	// duplicate or a number past the domain in another record of the page
	// than the one asked for refuses the page
	for name, result := range map[string]string{
		"a duplicate member in another record":       `[{"id":2,"id":2},{"id":1}]`,
		"a number past the domain in another record": `[{"id":2,"n":9007199254740993},{"id":1}]`,
	} {
		duplicated := history
		duplicated.Result = json.RawMessage(result)
		if _, err := HistoryFacts(duplicated, goldenKey, json.RawMessage(goldenKeyJSON)); err == nil {
			t.Errorf("a history result with %s derived facts", name)
		}
	}

	envelope, _ := os.ReadFile(filepath.Join("testdata", "postgres", "live.json"))
	if _, err := Parse([]byte(strings.Replace(string(envelope), `"version":"1.2.3"`, `"version":""`, 1))); err != nil {
		t.Errorf("an empty adapter version, which §6 permits: %v", err)
	}
	for name, mutate := range map[string]func(string) string{
		"no adapter digest":               func(s string) string { return strings.Replace(s, `"digest":"sha256:`, `"digest":"`, 1) },
		"a member the spec does not name": func(s string) string { return strings.Replace(s, `"endpoint":`, `"shape":"mcp","endpoint":`, 1) },
		"a missing member":                func(s string) string { return regexp.MustCompile(`"peerIdentity":null,`).ReplaceAllString(s, "") },
		"page not true":                   func(s string) string { return strings.Replace(s, `"result":`, `"page":false,"result":`, 1) },
		"page true and a result that is not an array": func(s string) string {
			return strings.Replace(s, `"result":`, `"page":true,"result":`, 1)
		},
		"observedAt with a zone offset": func(s string) string {
			return regexp.MustCompile(`"observedAt":"([^"]*)Z"`).ReplaceAllString(s, `"observedAt":"${1}+00:00"`)
		},
		"observedAt that is no instant": func(s string) string {
			return regexp.MustCompile(`"observedAt":"[^"]*"`).ReplaceAllString(s, `"observedAt":"2026-99-99T99:99:99Z"`)
		},
		"observedAt with a fraction of a second": func(s string) string {
			return regexp.MustCompile(`"observedAt":"([^"]*)Z"`).ReplaceAllString(s, `"observedAt":"${1}.1Z"`)
		},
		"observedAt with a comma fraction": func(s string) string {
			return regexp.MustCompile(`"observedAt":"([^"]*)Z"`).ReplaceAllString(s, `"observedAt":"${1},1Z"`)
		},
		"observedAt with a one-digit hour": func(s string) string {
			return regexp.MustCompile(`"observedAt":"[^"]*"`).ReplaceAllString(s, `"observedAt":"2026-09-14T8:34:16Z"`)
		},
		"a schema that is not a digest": func(s string) string { return strings.Replace(s, `"schema":null`, `"schema":"x"`, 1) },
		"an adapter name that is null":  func(s string) string { return strings.Replace(s, `"name":"bytebase/dbhub"`, `"name":null`, 1) },
		"a duplicate member":            func(s string) string { return strings.Replace(s, `"endpoint":`, `"endpoint":"x","endpoint":`, 1) },
		"a number past the canon domain, in the result": func(s string) string {
			return strings.Replace(s, `"result":{"content":`, `"result":{"_meta":{"n":9007199254740993},"content":`, 1)
		},
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

// TestBothPathsAgreeOnAFreshFetch fetches the golden records both ways
// against a World database started in the container runtime AGREEMENT_RUNTIME
// names (docker or podman), through the adapter implementations as the
// binaries call them, under a role Postgres holds to reading, and holds the
// fresh facts to each other and to the fixtures'; it also fetches the two
// counterexamples afresh, so a driver that stops rounding or stops typing is
// noticed, and reads the stream once more in the connector's xmin mode,
// whose cursor the connector defines, to hold that read to incremental.
// Without the variable it is skipped: the fixtures above are the offline
// record, and this is the test that keeps them honest wherever a runtime
// is at hand (the CI job "both paths agree"). Every deadline derives from
// the test's own, with time left to remove what was started.
func TestBothPathsAgreeOnAFreshFetch(t *testing.T) {
	runtime := os.Getenv("AGREEMENT_RUNTIME")
	if runtime == "" {
		t.Skip("set AGREEMENT_RUNTIME=docker (or podman) to fetch the golden record both ways")
	}
	historyImage, liveImage := binding(t)
	deadline := time.Now().Add(20 * time.Minute)
	if d, ok := t.Deadline(); ok {
		deadline = d.Add(-90 * time.Second)
	}
	bounded := func(limit time.Duration) (context.Context, context.CancelFunc) {
		until := time.Now().Add(limit)
		if until.After(deadline) {
			until = deadline
		}
		return context.WithDeadline(context.Background(), until)
	}
	name := fmt.Sprintf("jp-agreement-%d-%d", os.Getpid(), time.Now().UnixNano())
	run := func(limit time.Duration, args ...string) ([]byte, error) {
		ctx, cancel := bounded(limit)
		defer cancel()
		return exec.CommandContext(ctx, runtime, args...).CombinedOutput()
	}
	// registered before the database is started, so a container the runtime
	// created and could not start is removed too, with its anonymous volume;
	// removal runs on its own clock, past the test's deadline if need be
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		if out, err := exec.CommandContext(ctx, runtime, "rm", "-fv", name).CombinedOutput(); err != nil && !strings.Contains(string(out), "No such container") {
			t.Errorf("removing the World database container: %v\n%s", err, out)
		}
	})
	if out, err := run(5*time.Minute, "run", "-d", "--name", name, "-e", "POSTGRES_PASSWORD=world123", worldImage); err != nil {
		t.Fatalf("starting the World database: %v\n%s", err, out)
	}
	// The image's first start loads the data through a temporary server
	// that answers on the socket alone and then restarts; ready is when a
	// query over TCP sees every city.
	psql := func(sql string) ([]byte, error) {
		return run(20*time.Second, "exec", name, "psql", "-h", "127.0.0.1", "-U", "world", "-d", "world-db", "-Atc", sql)
	}
	ready := time.Now().Add(3 * time.Minute)
	for {
		out, err := psql("SELECT count(*) FROM city")
		if err == nil && strings.TrimSpace(string(out)) == "4079" {
			break
		}
		if time.Now().After(ready) || time.Now().After(deadline) {
			t.Fatalf("the World database did not become ready: %v\n%s", err, out)
		}
		time.Sleep(time.Second)
	}
	// the reading role the binding's README requires of a live connection
	// string -- SELECT alone is what holds it to reading; the transaction
	// default is a guard a session can lift, and the test shows both -- and
	// the second golden record's table
	grants := "CREATE ROLE reader LOGIN PASSWORD 'reader123'; GRANT CONNECT ON DATABASE \"world-db\" TO reader; GRANT USAGE ON SCHEMA public TO reader; GRANT SELECT ON ALL TABLES IN SCHEMA public TO reader; ALTER ROLE reader SET default_transaction_read_only = on; " + pastTable
	if out, err := psql(grants); err != nil {
		t.Fatalf("creating the reading role and the past table: %v\n%s", err, out)
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
	ctx, cancel := bounded(15 * time.Minute)
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
	// a refusal is the tool's own error result and nothing else: an
	// acquisition that also failed to stop its server reports the stop
	// first, and is not a refusal
	refused := func(sql, reason string) {
		t.Helper()
		req, _ := mcp.ParseRequest(strings.NewReader(fmt.Sprintf(`{"tool":"execute_sql","arguments":{"sql":%q}}`, sql)))
		_, err := mcp.Acquire(ctx, liveCfg, req)
		if err == nil || !strings.HasPrefix(err.Error(), "the tool reported an error: ") || !strings.Contains(err.Error(), reason) {
			t.Fatalf("%q was not refused by the tool with %q: %v", sql, reason, err)
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
	read := func(cfg airbyte.Config, stream, syncMode string) Envelope {
		t.Helper()
		req, err := airbyte.ParseRequest(strings.NewReader(fmt.Sprintf(`{"stream":%q,"namespace":"public","limit":5000}`, stream)), 5000)
		if err != nil {
			t.Fatal(err)
		}
		out, err := airbyte.Acquire(ctx, cfg, req)
		if err != nil {
			t.Fatalf("history fetch of %s (%s): %v", stream, syncMode, err)
		}
		e, err := Parse(out)
		if err != nil {
			t.Fatal(err)
		}
		requireDigest(t, e, historyImage)
		requireHistoryStatement(t, e, stream, syncMode)
		return e
	}
	history := read(historyCfg, "city", "full_refresh")
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

	// the second golden record, past 2^53, both ways as text; and the
	// counterexamples afresh: the driver still types a plain SELECT's
	// bigints as strings, and still rounds a JSON column past 2^53
	past := read(historyCfg, "past", "full_refresh")
	ph, err := HistoryFacts(past, pastKey, json.RawMessage(pastKeyJSON))
	if err != nil {
		t.Fatal(err)
	}
	if pl, err := LiveFacts(query(textPastQuery)); err != nil || string(pl) != string(ph) || string(pl) != pastFacts {
		t.Fatalf("the integer past 2^53 afresh:\nhistory: %s\nlive:    %s (%v)\nwant:    %s", ph, pl, err, pastFacts)
	}
	if fp, _ := HistoryFacts(fixture(t, "history-past-2p53.json"), pastKey, json.RawMessage(pastKeyJSON)); string(fp) != string(ph) {
		t.Fatalf("the past-2^53 fixture no longer says what a fresh fetch says:\nfixture: %s\nfresh:   %s", fp, ph)
	}
	untyped, err := LiveRowFacts(query(untypedQuery))
	if err != nil {
		t.Fatal(err)
	}
	requireDriverTypedDivergence(t, h, untyped)
	if row, err := LiveRowFacts(query(jsonPastQuery)); err != nil || string(row) != roundedFacts {
		t.Fatalf("the JSON column past 2^53 came back as %s (%v), not rounded as %s; the rule's reason has changed, revise the design note", row, err, roundedFacts)
	}

	// the connector's xmin mode defines the cursor itself and names no
	// field: the read is incremental, and the record is the same
	xminCfg := historyCfg
	xminCfg.Credentials = historyCreds("Xmin")
	xmin := read(xminCfg, "city", "incremental")
	if x, err := HistoryFacts(xmin, goldenKey, json.RawMessage(goldenKeyJSON)); err != nil || string(x) != goldenFacts {
		t.Fatalf("the xmin-mode read: %s %v", x, err)
	}
	if *xmin.Acquisition.Schema != *history.Acquisition.Schema {
		t.Fatalf("the xmin-mode read discovered another schema: %s", *xmin.Acquisition.Schema)
	}
}
