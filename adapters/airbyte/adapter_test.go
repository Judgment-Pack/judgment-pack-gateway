package airbyte

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"adapters/internal/fakeruntime"
)

func TestMain(m *testing.M) {
	if os.Getenv(fakeruntime.EnvActivate) == "1" {
		os.Exit(fakeruntime.Run(os.Args[1:]))
	}
	os.Exit(m.Run())
}

const testDigest = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

const discoverFixture = `{"type":"LOG","log":{"level":"INFO","message":"starting"}}
not a message line
{"type":"CATALOG","catalog":{"streams":[{"name":"decisions","json_schema":{"type":"object","properties":{"id":{"type":"integer"},"amount":{"type":"number","multipleOf":0.01},"status":{"type":"string"}}},"supported_sync_modes":["full_refresh","incremental"],"default_cursor_field":["updated_at"],"source_defined_primary_key":[["id"]]},{"name":"audit","json_schema":{"type":"object"},"supported_sync_modes":["full_refresh"]}]}}
`

// canonicalSchema is the decisions schema as the adapter digests it: sorted,
// compact, the fractional multipleOf carried as text.
const canonicalSchema = `{"properties":{"amount":{"multipleOf":"0.01","type":"number"},"id":{"type":"integer"},"status":{"type":"string"}},"type":"object"}`

const state1 = `{"type":"STREAM","stream":{"stream_descriptor":{"name":"decisions"},"stream_state":{"updated_at":"2026-09-12T10:00:02Z"}}}`
const state2 = `{"type":"STREAM","stream":{"stream_descriptor":{"name":"decisions"},"stream_state":{"updated_at":"2026-09-12T10:00:04Z"}}}`

const readFixture = `{"type":"LOG","log":{"level":"INFO","message":"reading"}}
{"type":"RECORD","record":{"stream":"decisions","emitted_at":1757671200000,"data":{"id":101,"status":"approved","amount":12.50,"note":"café <b>","big":9007199254740993}}}
{"type":"RECORD","record":{"stream":"audit","emitted_at":1,"data":{"id":1}}}
{"type":"RECORD","record":{"stream":"decisions","emitted_at":1757671200001,"data":{"id":102,"status":"denied","amount":7}}}
{"type":"RECORD","record":{"stream":"decisions","emitted_at":1757671200002,"data":{"id":103,"status":"approved","nested":{"z":1,"a":[true,null]}}}}
{"type":"STATE","state":{"type":"STREAM","stream":{"stream_descriptor":{"name":"other"},"stream_state":{"x":1}}}}
{"type":"STATE","state":` + state1 + `}
{"type":"RECORD","record":{"stream":"decisions","emitted_at":1757671200003,"data":{"id":104,"status":"denied"}}}
{"type":"RECORD","record":{"stream":"decisions","emitted_at":1757671200004,"data":{"id":105,"status":"approved"}}}
{"type":"STATE","state":` + state2 + `}
`

const credentialsFixture = `{"host":"warehouse.internal","port":5432,"password":"hunter2"}`

var stampForm = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$`)

// fake installs the test binary as the container runtime with the given
// connector output, and returns a configuration pointing at it.
func fake(t *testing.T, discover, read string) Config {
	t.Helper()
	dir := t.TempDir()
	write := func(name, content string) string {
		t.Helper()
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	t.Setenv(fakeruntime.EnvActivate, "1")
	t.Setenv(fakeruntime.EnvTrace, filepath.Join(dir, "trace.jsonl"))
	t.Setenv(fakeruntime.EnvKills, filepath.Join(dir, "kills"))
	t.Setenv(fakeruntime.EnvDiscover, write("discover.out", discover))
	t.Setenv(fakeruntime.EnvRead, write("read.out", read))
	t.Setenv(fakeruntime.EnvStderr, "")
	t.Setenv(fakeruntime.EnvExit, "")
	t.Setenv(fakeruntime.EnvHang, "")
	return Config{
		Runtime:     os.Args[0],
		Image:       "airbyte/source-postgres:3.6.1@" + testDigest,
		Credentials: write("credentials.json", credentialsFixture),
		MaxRecords:  10000,
		MaxOutput:   1 << 20,
	}
}

func invocations(t *testing.T) []fakeruntime.Invocation {
	t.Helper()
	data, err := os.ReadFile(os.Getenv(fakeruntime.EnvTrace))
	if err != nil {
		t.Fatal(err)
	}
	var out []fakeruntime.Invocation
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		var inv fakeruntime.Invocation
		if err := json.Unmarshal([]byte(line), &inv); err != nil {
			t.Fatal(err)
		}
		out = append(out, inv)
	}
	return out
}

func kills(t *testing.T) []string {
	t.Helper()
	data, err := os.ReadFile(os.Getenv(fakeruntime.EnvKills))
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		t.Fatal(err)
	}
	return strings.Split(strings.TrimSpace(string(data)), "\n")
}

type decodedEnvelope struct {
	Acquisition map[string]any    `json:"acquisition"`
	Result      []json.RawMessage `json:"result"`
	Page        bool              `json:"page"`
}

func decode(t *testing.T, out []byte) decodedEnvelope {
	t.Helper()
	var top map[string]json.RawMessage
	if err := json.Unmarshal(out, &top); err != nil {
		t.Fatalf("envelope is not JSON: %v\n%s", err, out)
	}
	if len(top) != 3 {
		t.Fatalf("envelope carries exactly acquisition, result and page: %s", out)
	}
	var env decodedEnvelope
	if err := json.Unmarshal(out, &env); err != nil {
		t.Fatal(err)
	}
	return env
}

// One page: the records of the requested stream up to the limit and the
// checkpoint that covers them, carried into the canon domain; the
// acquisition as §1.2a's envelope states it.
func TestAcquireReadsOnePageAndRecordsTheAcquisition(t *testing.T) {
	cfg := fake(t, discoverFixture, readFixture)
	cfg.Endpoint = "warehouse.internal:5432"
	out, err := Acquire(context.Background(), cfg, Request{Stream: "decisions", Limit: 3})
	if err != nil {
		t.Fatal(err)
	}
	env := decode(t, out)
	if !env.Page {
		t.Fatal("a read is a page")
	}
	want := []string{
		`{"amount":"12.50","big":"9007199254740993","id":101,"note":"café <b>","status":"approved"}`,
		`{"amount":7,"id":102,"status":"denied"}`,
		`{"id":103,"nested":{"a":[true,null],"z":1},"status":"approved"}`,
	}
	if len(env.Result) != len(want) {
		t.Fatalf("page has %d records, want %d: %s", len(env.Result), len(want), out)
	}
	for i := range want {
		if string(env.Result[i]) != want[i] {
			t.Fatalf("record %d is %s, want %s", i, env.Result[i], want[i])
		}
	}
	acq := env.Acquisition
	for _, name := range []string{"adapter", "endpoint", "statement", "snapshot", "peerIdentity", "schema", "upstreamToken", "observedAt"} {
		if _, present := acq[name]; !present {
			t.Fatalf("acquisition lacks %q: %v", name, acq)
		}
	}
	if len(acq) != 8 {
		t.Fatalf("acquisition carries exactly the eight members an adapter reports: %v", acq)
	}
	adapter := acq["adapter"].(map[string]any)
	if adapter["name"] != "airbyte/source-postgres" || adapter["version"] != "3.6.1" || adapter["digest"] != testDigest {
		t.Fatalf("adapter is the pinned image: %v", adapter)
	}
	if acq["endpoint"] != "warehouse.internal:5432" || acq["peerIdentity"] != nil || acq["upstreamToken"] != nil {
		t.Fatalf("endpoint as named; peer identity and upstream token null: %v", acq)
	}
	if acq["snapshot"] != state1 {
		t.Fatalf("snapshot is the covering checkpoint as emitted: %v", acq["snapshot"])
	}
	sum := sha256.Sum256([]byte(canonicalSchema))
	if acq["schema"] != "sha256:"+hex.EncodeToString(sum[:]) {
		t.Fatalf("schema is the digest of the canonical discovered schema: %v", acq["schema"])
	}
	statement, _ := acq["statement"].(string)
	var stmt map[string]any
	if err := json.Unmarshal([]byte(statement), &stmt); err != nil || stmt["stream"] != "decisions" || stmt["syncMode"] != "incremental" || stmt["state"] != nil {
		t.Fatalf("statement names the read: %s", statement)
	}
	if !stampForm.MatchString(acq["observedAt"].(string)) {
		t.Fatalf("observedAt is a stamp: %v", acq["observedAt"])
	}
	// What the connector was asked, and with what.
	inv := invocations(t)
	if len(inv) != 2 || inv[0].Verb != "discover" || inv[1].Verb != "read" {
		t.Fatalf("discover then read: %+v", inv)
	}
	for _, i := range inv {
		if i.Image != cfg.Image || i.Argv[0] != "run" || i.Argv[1] != "--rm" || i.Files["config.json"] != credentialsFixture {
			t.Fatalf("the pinned image, removed after, with the credentials as its config: %+v", i)
		}
	}
	var catalog struct {
		Streams []struct {
			Stream      struct{ Name string }
			SyncMode    string   `json:"sync_mode"`
			CursorField []string `json:"cursor_field"`
		}
	}
	if err := json.Unmarshal([]byte(inv[1].Files["catalog.json"]), &catalog); err != nil || len(catalog.Streams) != 1 ||
		catalog.Streams[0].Stream.Name != "decisions" || catalog.Streams[0].SyncMode != "incremental" || len(catalog.Streams[0].CursorField) != 1 {
		t.Fatalf("the configured catalog is the one stream, incremental on its cursor: %s", inv[1].Files["catalog.json"])
	}
	if _, present := inv[1].Files["state.json"]; present || strings.Contains(strings.Join(inv[1].Argv, " "), "--state") {
		t.Fatal("a first page carries no state")
	}
	// The page was complete before the stream ended, so the container was
	// told to stop by the name it was run under.
	name := inv[1].Argv[3]
	if got := kills(t); len(got) != 1 || got[0] != name {
		t.Fatalf("the read container must be killed by name once the page is complete: %v (name %s)", got, name)
	}
}

// The previous snapshot resumes the read: it is written back in the form
// the connector reads and named in the statement.
func TestAcquireResumesFromTheSnapshot(t *testing.T) {
	second := `{"type":"RECORD","record":{"stream":"decisions","emitted_at":3,"data":{"id":104,"status":"denied"}}}
{"type":"RECORD","record":{"stream":"decisions","emitted_at":4,"data":{"id":105,"status":"approved"}}}
{"type":"STATE","state":` + state2 + `}
`
	cfg := fake(t, discoverFixture, second)
	state := state1
	out, err := Acquire(context.Background(), cfg, Request{Stream: "decisions", Limit: 100, State: &state})
	if err != nil {
		t.Fatal(err)
	}
	env := decode(t, out)
	if len(env.Result) != 2 || env.Acquisition["snapshot"] != state2 {
		t.Fatalf("the second page: %s", out)
	}
	inv := invocations(t)
	if inv[1].Files["state.json"] != "["+state1+"]" || !strings.Contains(strings.Join(inv[1].Argv, " "), "--state /secrets/state.json") {
		t.Fatalf("the snapshot must be handed back as a state file: %+v", inv[1])
	}
	if !strings.Contains(env.Acquisition["statement"].(string), `"state":{"type":"STREAM"`) {
		t.Fatalf("the statement names the state resumed from: %v", env.Acquisition["statement"])
	}
	if len(kills(t)) != 0 {
		t.Fatal("a stream that ended on its own is not killed")
	}
}

// The limit is a floor, not a cut: records after it are kept until the
// checkpoint that covers them, so a resume never repeats them.
func TestAcquireWaitsForTheCoveringCheckpoint(t *testing.T) {
	cfg := fake(t, discoverFixture, readFixture)
	out, err := Acquire(context.Background(), cfg, Request{Stream: "decisions", Limit: 2})
	if err != nil {
		t.Fatal(err)
	}
	env := decode(t, out)
	if len(env.Result) != 3 || env.Acquisition["snapshot"] != state1 {
		t.Fatalf("limit 2 reads to the first covering checkpoint: %d records, snapshot %v", len(env.Result), env.Acquisition["snapshot"])
	}
}

// A stream that ends without a checkpoint is one page with no snapshot; a
// stream that offers none within the cap is given up on.
func TestAcquireWithoutCheckpoints(t *testing.T) {
	two := `{"type":"RECORD","record":{"stream":"decisions","emitted_at":1,"data":{"id":1}}}
{"type":"RECORD","record":{"stream":"decisions","emitted_at":2,"data":{"id":2}}}
`
	cfg := fake(t, discoverFixture, two)
	out, err := Acquire(context.Background(), cfg, Request{Stream: "decisions", Limit: 5})
	if err != nil {
		t.Fatal(err)
	}
	env := decode(t, out)
	if len(env.Result) != 2 || env.Acquisition["snapshot"] != nil {
		t.Fatalf("a stream that ends without a checkpoint: %s", out)
	}
	cfg.MaxRecords = 1
	_, err = Acquire(context.Background(), cfg, Request{Stream: "decisions", Limit: 1})
	if err == nil || !strings.Contains(err.Error(), "no checkpoint within 1 records") {
		t.Fatalf("past the cap without a checkpoint the read is given up on: %v", err)
	}
}

// Failures the connector or the operator can cause, each named.
func TestAcquireRefusals(t *testing.T) {
	t.Run("unknown stream", func(t *testing.T) {
		cfg := fake(t, discoverFixture, readFixture)
		_, err := Acquire(context.Background(), cfg, Request{Stream: "invoices", Limit: 1})
		if err == nil || !strings.Contains(err.Error(), `stream "invoices" is not one the connector offers: [decisions audit]`) {
			t.Fatalf("an unknown stream names the offered ones: %v", err)
		}
	})
	t.Run("unpinned image", func(t *testing.T) {
		cfg := fake(t, discoverFixture, readFixture)
		cfg.Image = "airbyte/source-postgres:3.6.1"
		if _, err := Acquire(context.Background(), cfg, Request{Stream: "decisions", Limit: 1}); err == nil || !strings.Contains(err.Error(), "must be pinned") {
			t.Fatalf("an unpinned image is refused: %v", err)
		}
	})
	t.Run("connector fails discover", func(t *testing.T) {
		cfg := fake(t, "", readFixture)
		t.Setenv(fakeruntime.EnvExit, "1")
		t.Setenv(fakeruntime.EnvStderr, "boom: no such host\nmore\n")
		_, err := Acquire(context.Background(), cfg, Request{Stream: "decisions", Limit: 1})
		if err == nil || !strings.Contains(err.Error(), "boom: no such host") || strings.Contains(err.Error(), "more") {
			t.Fatalf("the connector's first line of stderr, not more: %v", err)
		}
	})
	t.Run("connector trace error", func(t *testing.T) {
		cfg := fake(t, discoverFixture, `{"type":"TRACE","trace":{"type":"ERROR","error":{"message":"permission denied for table decisions"}}}`+"\n")
		_, err := Acquire(context.Background(), cfg, Request{Stream: "decisions", Limit: 1})
		if err == nil || !strings.Contains(err.Error(), "permission denied for table decisions") {
			t.Fatalf("a trace error is reported: %v", err)
		}
	})
	t.Run("duplicate member in a record", func(t *testing.T) {
		cfg := fake(t, discoverFixture, `{"type":"RECORD","record":{"stream":"decisions","emitted_at":1,"data":{"id":1,"id":2}}}`+"\n")
		if _, err := Acquire(context.Background(), cfg, Request{Stream: "decisions", Limit: 1}); err == nil || !strings.Contains(err.Error(), "duplicate member") {
			t.Fatalf("a record outside the canon domain is refused: %v", err)
		}
	})
	t.Run("output bound", func(t *testing.T) {
		cfg := fake(t, discoverFixture, readFixture)
		cfg.MaxOutput = 64
		// Refused while reading, at the record that crossed the bound --
		// not after the whole page was held in memory.
		if _, err := Acquire(context.Background(), cfg, Request{Stream: "decisions", Limit: 3}); err == nil || !strings.Contains(err.Error(), "the page exceeds the output bound of 64 bytes after 1 records") {
			t.Fatalf("a page past the bound is refused at the record that crossed it: %v", err)
		}
	})
	t.Run("credentials not JSON", func(t *testing.T) {
		cfg := fake(t, discoverFixture, readFixture)
		if err := os.WriteFile(cfg.Credentials, []byte("password=hunter2"), 0o600); err != nil {
			t.Fatal(err)
		}
		_, err := Acquire(context.Background(), cfg, Request{Stream: "decisions", Limit: 1})
		if err == nil || !strings.Contains(err.Error(), "not JSON") || strings.Contains(err.Error(), "hunter2") {
			t.Fatalf("refused without echoing the file: %v", err)
		}
	})
	t.Run("state not a state", func(t *testing.T) {
		cfg := fake(t, discoverFixture, readFixture)
		state := `{"cursor":1}`
		if _, err := Acquire(context.Background(), cfg, Request{Stream: "decisions", Limit: 1, State: &state}); err == nil || !strings.Contains(err.Error(), "neither a stream") {
			t.Fatalf("a snapshot that is not a state message is refused: %v", err)
		}
	})
}

// A connector that hangs is stopped when the acquisition's time is up: the
// runtime client is cancelled and the container is told to stop by name.
func TestAcquireStopsAHangingConnector(t *testing.T) {
	cfg := fake(t, discoverFixture, readFixture[:len(readFixture)-len("{\"type\":\"STATE\",\"state\":"+state2+"}\n")])
	t.Setenv(fakeruntime.EnvHang, "1")
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err := Acquire(ctx, cfg, Request{Stream: "decisions", Limit: 100})
	// Reported as the deadline it was, with what had been read, not as a
	// connector failure.
	if err == nil || !strings.Contains(err.Error(), "connector read stopped after 5 records: context deadline exceeded") {
		t.Fatalf("a hanging connector must fail the acquisition as a deadline: %v", err)
	}
	if time.Since(start) > 10*time.Second {
		t.Fatal("the acquisition did not end when its time was up")
	}
	inv := invocations(t)
	if got := kills(t); len(got) != 1 || got[0] != inv[1].Argv[3] {
		t.Fatalf("the hanging read container must be killed by name: %v", got)
	}
}

func TestParseRequest(t *testing.T) {
	good, err := ParseRequest(strings.NewReader(`{"stream":"decisions"}`), 10000)
	if err != nil || good.Stream != "decisions" || good.Limit != defaultLimit || good.State != nil {
		t.Fatalf("defaults: %+v %v", good, err)
	}
	for in, want := range map[string]string{
		`{"stream":"decisions","limit":3,"state":"{\"type\":\"LEGACY\",\"data\":{}}","extra":1}`: "unknown field",
		`{"limit":3}`:                          `"stream" is required`,
		`{"stream":"decisions","limit":0}`:     "",
		`{"stream":"decisions","limit":-1}`:    `"limit" must be between 1 and 10000`,
		`{"stream":"decisions","limit":10001}`: `"limit" must be between 1 and 10000`,
		`{"stream":"decisions","limit":1.5}`:   "cannot unmarshal",
		`{"stream":"decisions","state":""}`:    `"state" is the previous snapshot text`,
		`{"stream":"decisions"} {}`:            "trailing content",
		`[]`:                                   "cannot unmarshal",
	} {
		_, err := ParseRequest(strings.NewReader(in), 10000)
		if want == "" {
			if err != nil {
				t.Errorf("%s: %v", in, err)
			}
			continue
		}
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: got %v, want %q", in, err, want)
		}
	}
}

func TestParseImage(t *testing.T) {
	for ref, want := range map[string]imageRef{
		"airbyte/source-postgres:3.6.1@" + testDigest: {"airbyte/source-postgres", "3.6.1", testDigest},
		"airbyte/source-postgres@" + testDigest:       {"airbyte/source-postgres", "", testDigest},
		"registry.example:5000/x/y:v1@" + testDigest:  {"registry.example:5000/x/y", "v1", testDigest},
		"registry.example:5000/x/y@" + testDigest:     {"registry.example:5000/x/y", "", testDigest},
	} {
		got, err := parseImage(ref)
		if err != nil || got != want {
			t.Errorf("%s: %+v %v, want %+v", ref, got, err, want)
		}
	}
	for _, ref := range []string{"airbyte/source-postgres:3.6.1", "airbyte/source-postgres@sha256:abc", "@" + testDigest, "x@md5:" + testDigest[7:]} {
		if _, err := parseImage(ref); err == nil {
			t.Errorf("%s must be refused", ref)
		}
	}
}
