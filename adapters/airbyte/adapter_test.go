package airbyte

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"adapters/internal/fakeruntime"
)

func given(s string) OptionalString { return OptionalString{Given: true, Value: &s} }

func givenNull() OptionalString { return OptionalString{Given: true} }

func TestMain(m *testing.M) {
	if os.Getenv(fakeruntime.EnvActivate) == "1" {
		os.Exit(fakeruntime.Run(os.Args[1:]))
	}
	os.Exit(m.Run())
}

const testDigest = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

const discoverFixture = `{"type":"LOG","log":{"level":"INFO","message":"starting"}}
not a message line
{"level":"INFO","message":"a JSON line that is not a message"}
{"type":"CATALOG","catalog":{"streams":[{"name":"decisions","json_schema":{"type":"object","properties":{"id":{"type":"integer"},"amount":{"type":"number","multipleOf":0.01},"status":{"type":"string"}}},"supported_sync_modes":["full_refresh","incremental"],"default_cursor_field":["updated_at"],"source_defined_primary_key":[["id"]]},{"name":"audit","json_schema":{"type":"object"},"supported_sync_modes":["full_refresh"]}]}}
`

// canonicalSchema is the decisions schema as the adapter digests it: sorted,
// compact, the fractional multipleOf carried as text.
const canonicalSchema = `{"properties":{"amount":{"multipleOf":"0.01","type":"number"},"id":{"type":"integer"},"status":{"type":"string"}},"type":"object"}`

const state1 = `{"type":"STREAM","stream":{"stream_descriptor":{"name":"decisions"},"stream_state":{"updated_at":"2026-09-12T10:00:02Z"}}}`
const state2 = `{"type":"STREAM","stream":{"stream_descriptor":{"name":"decisions"},"stream_state":{"updated_at":"2026-09-12T10:00:04Z"}}}`

func rec(id int, at string, rest string) string {
	return `{"type":"RECORD","record":{"stream":"decisions","emitted_at":` + strconv.Itoa(id) + `,"data":{"id":` + strconv.Itoa(id) + `,"updated_at":"2026-09-12T10:00:0` + at + `Z"` + rest + `}}}` + "\n"
}

var readFixture = `{"type":"LOG","log":{"level":"INFO","message":"reading"}}` + "\n" +
	rec(101, "0", `,"status":"approved","amount":12.50,"note":"café <b>","big":9007199254740993`) +
	`{"type":"RECORD","record":{"stream":"audit","emitted_at":1,"data":{"id":1}}}` + "\n" +
	rec(102, "1", `,"status":"denied","amount":7`) +
	rec(103, "2", `,"status":"approved","nested":{"z":1,"a":[true,null]}`) +
	`{"type":"STATE","state":{"type":"STREAM","stream":{"stream_descriptor":{"name":"other"},"stream_state":{"x":1}}}}` + "\n" +
	`{"type":"STATE","state":` + state1 + `}` + "\n" +
	rec(104, "3", `,"status":"denied"`) +
	rec(105, "4", `,"status":"approved"`) +
	`{"type":"STATE","state":` + state2 + `}` + "\n"

const credentialsFixture = `{"host":"warehouse.internal","port":5432,"password":"hunter2","ssl":{"mode":"require"}}`

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
	for _, name := range []string{fakeruntime.EnvStderr, fakeruntime.EnvExit, fakeruntime.EnvHang, fakeruntime.EnvHold,
		fakeruntime.EnvHoldStderr, fakeruntime.EnvKillExit, fakeruntime.EnvKillDelay, fakeruntime.EnvInspectExit, fakeruntime.EnvStuckOnRead,
		fakeruntime.EnvInspectStderr, fakeruntime.EnvHoldInspect} {
		t.Setenv(name, "")
	}
	t.Setenv(fakeruntime.EnvActivate, "1")
	t.Setenv(fakeruntime.EnvTrace, filepath.Join(dir, "trace.jsonl"))
	t.Setenv(fakeruntime.EnvKills, filepath.Join(dir, "kills"))
	t.Setenv(fakeruntime.EnvHolderPid, filepath.Join(dir, "holder"))
	t.Setenv(fakeruntime.EnvDiscover, write("discover.out", discover))
	t.Setenv(fakeruntime.EnvRead, write("read.out", read))
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

// containerNames are the names the runs were given, in order.
func containerNames(inv []fakeruntime.Invocation) []string {
	var names []string
	for _, i := range inv {
		names = append(names, i.Argv[3])
	}
	return names
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

func acquire(t *testing.T, cfg Config, req Request) decodedEnvelope {
	t.Helper()
	out, err := Acquire(context.Background(), cfg, req)
	if err != nil {
		t.Fatal(err)
	}
	return decode(t, out)
}

func mustFail(t *testing.T, cfg Config, req Request, want string) {
	t.Helper()
	_, err := Acquire(context.Background(), cfg, req)
	if err == nil || !strings.Contains(err.Error(), want) {
		t.Fatalf("want an error containing %q, got %v", want, err)
	}
}

// One page: the records of the requested stream up to the limit and the
// checkpoint that covers them, carried into the canon domain; the
// acquisition as §1.2a's envelope states it; both containers told to stop.
func TestAcquireReadsOnePageAndRecordsTheAcquisition(t *testing.T) {
	cfg := fake(t, discoverFixture, readFixture)
	cfg.Endpoint = "warehouse.internal:5432"
	env := acquire(t, cfg, Request{Stream: "decisions", Limit: 3})
	if !env.Page {
		t.Fatal("a read is a page")
	}
	want := []string{
		`{"amount":"12.50","big":"9007199254740993","id":101,"note":"café <b>","status":"approved","updated_at":"2026-09-12T10:00:00Z"}`,
		`{"amount":7,"id":102,"status":"denied","updated_at":"2026-09-12T10:00:01Z"}`,
		`{"id":103,"nested":{"a":[true,null],"z":1},"status":"approved","updated_at":"2026-09-12T10:00:02Z"}`,
	}
	if len(env.Result) != len(want) {
		t.Fatalf("page has %d records, want %d", len(env.Result), len(want))
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
	if err := json.Unmarshal([]byte(statement), &stmt); err != nil || stmt["stream"] != "decisions" || stmt["namespace"] != nil || stmt["syncMode"] != "incremental" || stmt["state"] != nil {
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
		if runtime.GOOS != "windows" && (i.Modes["dir"] != "0755" || i.Modes["config.json"] != "0644") {
			t.Fatalf("the mount is readable by the connector's own user: %v", i.Modes)
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
	// Every container is told to stop by name, whether it ended on its own
	// (discover) or was stopped once the page was complete (read).
	if got, names := kills(t), containerNames(inv); len(got) != 2 || got[0] != names[0] || got[1] != names[1] {
		t.Fatalf("both containers must be told to stop by name: %v vs %v", got, names)
	}
}

// Two pages driven by the state: the first page's snapshot, handed back as
// the request's state, is written for the connector in the form it reads
// and yields exactly what follows it.
func TestAcquireResumesFromTheSnapshot(t *testing.T) {
	cfg := fake(t, discoverFixture, readFixture)
	first := acquire(t, cfg, Request{Stream: "decisions", Limit: 3})
	state := first.Acquisition["snapshot"].(string)
	second := acquire(t, cfg, Request{Stream: "decisions", Limit: 100, State: &state})
	if len(second.Result) != 2 || !strings.Contains(string(second.Result[0]), `"id":104`) || !strings.Contains(string(second.Result[1]), `"id":105`) {
		t.Fatalf("the second page is what follows the first's checkpoint: %s", second.Result)
	}
	if second.Acquisition["snapshot"] != state2 {
		t.Fatalf("the second page's snapshot: %v", second.Acquisition["snapshot"])
	}
	inv := invocations(t)
	if inv[3].Files["state.json"] != "["+state1+"]" || !strings.Contains(strings.Join(inv[3].Argv, " "), "--state /secrets/state.json") {
		t.Fatalf("the snapshot must be handed back as a state file: %+v", inv[3])
	}
	if !strings.Contains(second.Acquisition["statement"].(string), `"state":{"type":"STREAM"`) {
		t.Fatalf("the statement names the state resumed from: %v", second.Acquisition["statement"])
	}
	// A legacy state is handed back as its data.
	legacy := `{"type":"LEGACY","data":{"updated_at":"2026-09-12T10:00:03Z"}}`
	third := acquire(t, cfg, Request{Stream: "decisions", Limit: 100, State: &legacy})
	if len(third.Result) != 1 || invocations(t)[5].Files["state.json"] != `{"updated_at":"2026-09-12T10:00:03Z"}` {
		t.Fatalf("a legacy state is handed back as its data: %s %+v", third.Result, invocations(t)[5].Files)
	}
}

// The limit is a floor, not a cut: records after it are kept until the
// checkpoint that covers them, so a resume never repeats them.
func TestAcquireWaitsForTheCoveringCheckpoint(t *testing.T) {
	cfg := fake(t, discoverFixture, readFixture)
	env := acquire(t, cfg, Request{Stream: "decisions", Limit: 2})
	if len(env.Result) != 3 || env.Acquisition["snapshot"] != state1 {
		t.Fatalf("limit 2 reads to the first covering checkpoint: %d records, snapshot %v", len(env.Result), env.Acquisition["snapshot"])
	}
}

// A stream that ends without any checkpoint is one page with no snapshot; a
// stream that offers none within the cap is given up on; a stream that ends
// with records after its last checkpoint is refused, since a page
// bookmarked there would repeat them on resume.
func TestAcquireAtTheEndOfTheStream(t *testing.T) {
	two := rec(1, "0", "") + rec(2, "1", "")
	cfg := fake(t, discoverFixture, two)
	env := acquire(t, cfg, Request{Stream: "decisions", Limit: 5})
	if len(env.Result) != 2 || env.Acquisition["snapshot"] != nil {
		t.Fatalf("a stream that ends without a checkpoint: %d records, snapshot %v", len(env.Result), env.Acquisition["snapshot"])
	}
	cfg.MaxRecords = 1
	mustFail(t, cfg, Request{Stream: "decisions", Limit: 1}, "no checkpoint within 1 records")

	tail := rec(1, "0", "") + `{"type":"STATE","state":` + state1 + `}` + "\n" + rec(2, "3", "")
	cfg = fake(t, discoverFixture, tail)
	mustFail(t, cfg, Request{Stream: "decisions", Limit: 5}, `ended stream "decisions" with 1 records after its last checkpoint`)
}

// A stream is identified by name and namespace: a name the catalog holds in
// two namespaces is ambiguous without one, and with one only that
// namespace's records and checkpoints count.
func TestAcquireByNamespace(t *testing.T) {
	catalog := `{"type":"CATALOG","catalog":{"streams":[` +
		`{"name":"decisions","namespace":"public","json_schema":{"type":"object"},"supported_sync_modes":["incremental"],"default_cursor_field":["updated_at"]},` +
		`{"name":"decisions","namespace":"archive","json_schema":{"type":"object"},"supported_sync_modes":["full_refresh"]}]}}` + "\n"
	read := `{"type":"RECORD","record":{"stream":"decisions","namespace":"archive","emitted_at":1,"data":{"id":1}}}` + "\n" +
		`{"type":"RECORD","record":{"stream":"decisions","namespace":"public","emitted_at":2,"data":{"id":2}}}` + "\n" +
		`{"type":"STATE","state":{"type":"STREAM","stream":{"stream_descriptor":{"name":"decisions","namespace":"archive"},"stream_state":{"x":1}}}}` + "\n" +
		`{"type":"STATE","state":{"type":"STREAM","stream":{"stream_descriptor":{"name":"decisions","namespace":"public"},"stream_state":{"updated_at":"2026-09-12T10:00:00Z"}}}}` + "\n"
	cfg := fake(t, catalog, read)
	mustFail(t, cfg, Request{Stream: "decisions", Limit: 5}, `exists in more than one namespace [public archive]`)
	env := acquire(t, cfg, Request{Stream: "decisions", Namespace: given("public"), Limit: 1})
	if len(env.Result) != 1 || string(env.Result[0]) != `{"id":2}` {
		t.Fatalf("only the namespace's records: %s", env.Result)
	}
	if !strings.Contains(env.Acquisition["snapshot"].(string), `"namespace":"public"`) {
		t.Fatalf("only the namespace's checkpoint: %v", env.Acquisition["snapshot"])
	}
	if !strings.Contains(env.Acquisition["statement"].(string), `"namespace":"public"`) {
		t.Fatalf("the statement names the namespace: %v", env.Acquisition["statement"])
	}
	mustFail(t, cfg, Request{Stream: "decisions", Namespace: given("staging"), Limit: 1}, `stream "staging/decisions" is not one the connector offers: [public/decisions archive/decisions]`)
}

// Failures the connector or the operator can cause, each named, and none
// disclosing the configuration.
func TestAcquireRefusals(t *testing.T) {
	t.Run("unknown stream", func(t *testing.T) {
		mustFail(t, fake(t, discoverFixture, readFixture), Request{Stream: "invoices", Limit: 1}, `stream "invoices" is not one the connector offers: [decisions audit]`)
	})
	t.Run("unpinned image", func(t *testing.T) {
		cfg := fake(t, discoverFixture, readFixture)
		cfg.Image = "airbyte/source-postgres:3.6.1"
		mustFail(t, cfg, Request{Stream: "decisions", Limit: 1}, "must be pinned")
	})
	t.Run("connector fails discover without a catalog", func(t *testing.T) {
		cfg := fake(t, "", readFixture)
		t.Setenv(fakeruntime.EnvExit, "1")
		t.Setenv(fakeruntime.EnvStderr, "boom: no such host\nmore\n")
		_, err := Acquire(context.Background(), cfg, Request{Stream: "decisions", Limit: 1})
		if err == nil || !strings.Contains(err.Error(), "boom: no such host") || strings.Contains(err.Error(), "more") {
			t.Fatalf("the connector's first line of stderr, not more: %v", err)
		}
	})
	t.Run("connector fails discover after a catalog", func(t *testing.T) {
		cfg := fake(t, discoverFixture, readFixture)
		t.Setenv(fakeruntime.EnvExit, "1")
		mustFail(t, cfg, Request{Stream: "decisions", Limit: 1}, "connector discover failed")
	})
	t.Run("connector trace error", func(t *testing.T) {
		cfg := fake(t, discoverFixture, `{"type":"TRACE","trace":{"type":"ERROR","error":{"message":"permission denied for table decisions"}}}`+"\n")
		mustFail(t, cfg, Request{Stream: "decisions", Limit: 1}, "permission denied for table decisions")
	})
	t.Run("diagnostics are redacted", func(t *testing.T) {
		cfg := fake(t, discoverFixture, `{"type":"TRACE","trace":{"type":"ERROR","error":{"message":"password hunter2 rejected by warehouse.internal"}}}`+"\n")
		_, err := Acquire(context.Background(), cfg, Request{Stream: "decisions", Limit: 1})
		if err == nil || strings.Contains(err.Error(), "hunter2") || strings.Contains(err.Error(), "warehouse.internal") || !strings.Contains(err.Error(), "password [redacted] rejected by [redacted]") {
			t.Fatalf("configured values are redacted from a trace: %v", err)
		}
		cfg = fake(t, "", readFixture)
		t.Setenv(fakeruntime.EnvExit, "1")
		t.Setenv(fakeruntime.EnvStderr, "FATAL: password authentication failed with hunter2\n")
		_, err = Acquire(context.Background(), cfg, Request{Stream: "decisions", Limit: 1})
		if err == nil || strings.Contains(err.Error(), "hunter2") || !strings.Contains(err.Error(), "[redacted]") {
			t.Fatalf("configured values are redacted from stderr: %v", err)
		}
	})
	t.Run("duplicate member in a record", func(t *testing.T) {
		cfg := fake(t, discoverFixture, `{"type":"RECORD","record":{"stream":"decisions","emitted_at":1,"data":{"id":1,"id":2}}}`+"\n")
		mustFail(t, cfg, Request{Stream: "decisions", Limit: 1}, "duplicate member")
	})
	t.Run("record data not an object", func(t *testing.T) {
		cfg := fake(t, discoverFixture, `{"type":"RECORD","record":{"stream":"decisions","emitted_at":1,"data":null}}`+"\n")
		mustFail(t, cfg, Request{Stream: "decisions", Limit: 1}, "data is not an object")
	})
	t.Run("malformed record message", func(t *testing.T) {
		cfg := fake(t, discoverFixture, `{"type":"RECORD","record":{"stream":5,"data":{"id":1}}}`+"\n")
		mustFail(t, cfg, Request{Stream: "decisions", Limit: 1}, "malformed RECORD message")
	})
	t.Run("state without a state", func(t *testing.T) {
		cfg := fake(t, discoverFixture, rec(1, "0", "")+`{"type":"STATE","state":null}`+"\n")
		mustFail(t, cfg, Request{Stream: "decisions", Limit: 1}, "malformed STATE message")
		cfg = fake(t, discoverFixture, rec(1, "0", "")+`{"type":"STATE","state":{"type":"STREAM"}}`+"\n")
		mustFail(t, cfg, Request{Stream: "decisions", Limit: 1}, "without a stream descriptor")
	})
	t.Run("output bound", func(t *testing.T) {
		cfg := fake(t, discoverFixture, readFixture)
		cfg.MaxOutput = 64
		// Refused while reading, at the record that crossed the bound --
		// not after the whole page was held in memory.
		mustFail(t, cfg, Request{Stream: "decisions", Limit: 3}, "the page exceeds the output bound of 64 bytes after 1 records")
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
		mustFail(t, cfg, Request{Stream: "decisions", Limit: 1, State: &state}, "neither a stream")
	})
	t.Run("container that will not stop", func(t *testing.T) {
		cfg := fake(t, discoverFixture, readFixture)
		t.Setenv(fakeruntime.EnvKillExit, "1")
		t.Setenv(fakeruntime.EnvInspectExit, "0")
		mustFail(t, cfg, Request{Stream: "decisions", Limit: 3}, "could not be stopped and is still known")
		// A kill the runtime refuses because the container is already gone
		// is not a failure.
		t.Setenv(fakeruntime.EnvInspectExit, "1")
		acquire(t, cfg, Request{Stream: "decisions", Limit: 3})
	})
}

// A connector that hangs is stopped when the acquisition's time is up: the
// runtime client is cancelled and the container is told to stop by name;
// the deadline is reported as one, with what had been read.
func TestAcquireStopsAHangingConnector(t *testing.T) {
	cfg := fake(t, discoverFixture, strings.TrimSuffix(readFixture, `{"type":"STATE","state":`+state2+`}`+"\n"))
	t.Setenv(fakeruntime.EnvHang, "1")
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err := Acquire(ctx, cfg, Request{Stream: "decisions", Limit: 100})
	if err == nil || !strings.Contains(err.Error(), "connector read stopped after 5 records: context deadline exceeded") {
		t.Fatalf("a hanging connector must fail the acquisition as a deadline: %v", err)
	}
	if time.Since(start) > 10*time.Second {
		t.Fatal("the acquisition did not end when its time was up")
	}
	inv := invocations(t)
	if got := kills(t); len(got) != 2 || got[1] != inv[1].Argv[3] {
		t.Fatalf("the hanging read container must be killed by name: %v", got)
	}
}

// A runtime client that exits leaving a descendant holding stdout does not
// hold the adapter past its deadline: the reader is closed with the context.
func TestAcquireIsNotHeldByADescendantOnStdout(t *testing.T) {
	cfg := fake(t, discoverFixture, rec(1, "0", ""))
	t.Setenv(fakeruntime.EnvHold, "1")
	t.Cleanup(func() {
		data, err := os.ReadFile(os.Getenv(fakeruntime.EnvHolderPid))
		if err != nil {
			return
		}
		for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
			if pid, err := strconv.Atoi(line); err == nil {
				if p, err := os.FindProcess(pid); err == nil {
					p.Kill()
					p.Wait()
				}
			}
		}
	})
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err := Acquire(ctx, cfg, Request{Stream: "decisions", Limit: 100})
	if err == nil || !strings.Contains(err.Error(), "context deadline exceeded") {
		t.Fatalf("the deadline must end the acquisition: %v", err)
	}
	if time.Since(start) > 10*time.Second {
		t.Fatal("a descendant on stdout held the acquisition past its deadline")
	}
}

// Stopping a container is bounded: a kill the runtime does not answer is
// given up on within the window, and the acquisition still ends.
func TestStoppingIsBounded(t *testing.T) {
	cfg := fake(t, discoverFixture, readFixture)
	t.Setenv(fakeruntime.EnvKillDelay, "30")
	start := time.Now()
	acquire(t, cfg, Request{Stream: "decisions", Limit: 3})
	// Two containers, each a kill window and an inspect window at most: the
	// bound is written out so a widened window is caught, not absorbed.
	if elapsed := time.Since(start); elapsed > 12*time.Second {
		t.Fatalf("stopping two containers took %v", elapsed)
	}
}

// A connector that floods stderr does not fail an acquisition that
// succeeded, and its first line is still what a failure reports.
func TestStderrIsBoundedWithoutBreakingThePipe(t *testing.T) {
	cfg := fake(t, discoverFixture, readFixture)
	t.Setenv(fakeruntime.EnvStderr, "first line\n"+strings.Repeat("x", 20000)+"\n")
	acquire(t, cfg, Request{Stream: "decisions", Limit: 3})
	t.Setenv(fakeruntime.EnvExit, "1")
	cfg = fake(t, "", readFixture)
	t.Setenv(fakeruntime.EnvExit, "1")
	t.Setenv(fakeruntime.EnvStderr, "first line\n"+strings.Repeat("x", 20000)+"\n")
	mustFail(t, cfg, Request{Stream: "decisions", Limit: 1}, "connector discover failed: first line")
}

func TestParseRequest(t *testing.T) {
	good, err := ParseRequest(strings.NewReader(`{"stream":"decisions"}`), 10000)
	if err != nil || good.Stream != "decisions" || good.Limit != defaultLimit || good.State != nil || good.Namespace.Given {
		t.Fatalf("defaults: %+v %v", good, err)
	}
	if r, err := ParseRequest(strings.NewReader(`{"stream":"decisions","namespace":"public","limit":2}`), 10000); err != nil || !r.Namespace.Given || *r.Namespace.Value != "public" || r.Limit != 2 {
		t.Fatalf("namespace: %+v %v", r, err)
	}
	// A null namespace is given, and names the streams without one.
	if r, err := ParseRequest(strings.NewReader(`{"stream":"decisions","namespace":null}`), 10000); err != nil || !r.Namespace.Given || r.Namespace.Value != nil {
		t.Fatalf("null namespace: %+v %v", r, err)
	}
	if _, err := ParseRequest(strings.NewReader(`{"stream":"decisions","namespace":5}`), 10000); err == nil || !strings.Contains(err.Error(), "must be a string or null") {
		t.Fatalf("a numeric namespace is refused: %v", err)
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

// Absence is established positively: an inspect the runtime cannot answer
// leaves the question open, and an open question fails the acquisition.
func TestStopRequiresAPositiveAnswerFromInspect(t *testing.T) {
	cfg := fake(t, discoverFixture, readFixture)
	t.Setenv(fakeruntime.EnvKillExit, "1")
	t.Setenv(fakeruntime.EnvInspectExit, "2")
	mustFail(t, cfg, Request{Stream: "decisions", Limit: 3}, "could not say whether it is gone (Cannot connect to the Docker daemon)")
}

// Every scalar of the credentials is redacted, longest first: a short
// password, a numeric one, and one that contains another value.
func TestRedactionCoversEveryScalar(t *testing.T) {
	cfg := fake(t, "", readFixture)
	if err := os.WriteFile(cfg.Credentials, []byte(`{"host":"host","password":"host-private-password","pin":123456,"short":"abc","port":5432}`), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv(fakeruntime.EnvExit, "1")
	t.Setenv(fakeruntime.EnvStderr, "FATAL: host-private-password rejected for host, pin 123456, key abc, port 5432\n")
	_, err := Acquire(context.Background(), cfg, Request{Stream: "decisions", Limit: 1})
	if err == nil {
		t.Fatal("expected a failure")
	}
	want := "FATAL: [redacted] rejected for [redacted], pin [redacted], key [redacted], port [redacted]"
	if !strings.Contains(err.Error(), want) {
		t.Fatalf("redaction: %v, want %q", err, want)
	}
}

// A TRACE that names its type but is not a TRACE is an error, not a log
// line: what it failed to say may have been an error.
func TestMalformedTraceIsAnError(t *testing.T) {
	cfg := fake(t, discoverFixture, rec(1, "0", "")+`{"type":"TRACE","trace":{"type":"ERROR","error":{"message":123}}}`+"\n"+`{"type":"STATE","state":`+state1+`}`+"\n")
	mustFail(t, cfg, Request{Stream: "decisions", Limit: 1}, "malformed TRACE message")
	cfg = fake(t, `{"type":"TRACE","trace":{"type":"ERROR","error":{"message":123}}}`+"\n"+discoverFixture, readFixture)
	mustFail(t, cfg, Request{Stream: "decisions", Limit: 1}, "malformed TRACE message")
}

// An empty record is an object, with or without whitespace; an empty state
// is no bookmark.
func TestEmptyObjects(t *testing.T) {
	cfg := fake(t, discoverFixture,
		`{"type":"RECORD","record":{"stream":"decisions","emitted_at":1,"data":{}}}`+"\n"+
			`{"type":"RECORD","record":{"stream":"decisions","emitted_at":2,"data":{ }}}`+"\n")
	env := acquire(t, cfg, Request{Stream: "decisions", Limit: 5})
	if len(env.Result) != 2 || string(env.Result[0]) != "{}" || string(env.Result[1]) != "{}" {
		t.Fatalf("empty records: %s", env.Result)
	}
	cfg = fake(t, discoverFixture, rec(1, "0", "")+`{"type":"STATE","state":{ }}`+"\n")
	mustFail(t, cfg, Request{Stream: "decisions", Limit: 1}, "malformed STATE message")
}

// A descendant holding stderr after the client exited stretches the wait
// to the wait delay and no further: the acquisition still ends within its
// deadline and the stopping budget.
func TestAcquireIsNotHeldByADescendantOnStderr(t *testing.T) {
	cfg := fake(t, discoverFixture, rec(1, "0", ""))
	t.Setenv(fakeruntime.EnvHoldStderr, "1")
	t.Cleanup(func() { killHolders(t) })
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err := Acquire(ctx, cfg, Request{Stream: "decisions", Limit: 100})
	if err == nil || !strings.Contains(err.Error(), "context deadline exceeded") {
		t.Fatalf("the deadline must end the acquisition: %v", err)
	}
	// The kill is answered at once here, so what remains after the deadline
	// is the wait delay alone: two seconds, written out so a longer one is
	// caught rather than absorbed.
	if elapsed := time.Since(start); elapsed > 500*time.Millisecond+4*time.Second {
		t.Fatalf("a descendant on stderr held the acquisition for %v", elapsed)
	}
}

func killHolders(t *testing.T) {
	t.Helper()
	data, err := os.ReadFile(os.Getenv(fakeruntime.EnvHolderPid))
	if err != nil {
		return
	}
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		if pid, err := strconv.Atoi(line); err == nil {
			if p, err := os.FindProcess(pid); err == nil {
				p.Kill()
				p.Wait()
			}
		}
	}
}

// When the connector fails and its container will not stop, the container
// comes first in the error, since the gateway keeps only the start of it.
func TestContainerWarningComesFirst(t *testing.T) {
	cfg := fake(t, discoverFixture, `{"type":"TRACE","trace":{"type":"ERROR","error":{"message":"permission denied"}}}`+"\n")
	t.Setenv(fakeruntime.EnvStuckOnRead, "1")
	_, err := Acquire(context.Background(), cfg, Request{Stream: "decisions", Limit: 1})
	if err == nil || !strings.HasPrefix(err.Error(), "container jp-airbyte-") || !strings.Contains(err.Error(), "could not be stopped and is still known") ||
		!strings.Contains(err.Error(), "the acquisition had also failed: connector reported an error: permission denied") {
		t.Fatalf("the container warning must lead: %v", err)
	}
}

// A null namespace and an empty one are distinct streams, as the protocol
// says: only the matching one's records and checkpoints count -- a
// checkpoint of the other namespace neither completes the page nor
// bookmarks it -- the statement keeps the distinction, and an explicit
// null selects the stream without a namespace.
func TestEmptyNamespaceIsNotNull(t *testing.T) {
	catalog := `{"type":"CATALOG","catalog":{"streams":[` +
		`{"name":"decisions","json_schema":{"type":"object"},"supported_sync_modes":["full_refresh"]},` +
		`{"name":"decisions","namespace":"","json_schema":{"type":"object"},"supported_sync_modes":["full_refresh"]}]}}` + "\n"
	nullState := `{"type":"STREAM","stream":{"stream_descriptor":{"name":"decisions"},"stream_state":{"k":"null-ns"}}}`
	emptyState := `{"type":"STREAM","stream":{"stream_descriptor":{"name":"decisions","namespace":""},"stream_state":{"k":"empty-ns"}}}`
	read := `{"type":"RECORD","record":{"stream":"decisions","emitted_at":1,"data":{"id":1}}}` + "\n" +
		`{"type":"RECORD","record":{"stream":"decisions","namespace":"","emitted_at":2,"data":{"id":2}}}` + "\n" +
		`{"type":"STATE","state":` + nullState + `}` + "\n" +
		`{"type":"RECORD","record":{"stream":"decisions","namespace":"","emitted_at":3,"data":{"id":3}}}` + "\n" +
		`{"type":"RECORD","record":{"stream":"decisions","namespace":null,"emitted_at":4,"data":{"id":4}}}` + "\n" +
		`{"type":"STATE","state":` + emptyState + `}` + "\n" +
		`{"type":"RECORD","record":{"stream":"decisions","namespace":"","emitted_at":5,"data":{"id":5}}}` + "\n" +
		`{"type":"STATE","state":` + nullState + `}` + "\n"
	cfg := fake(t, catalog, read)
	mustFail(t, cfg, Request{Stream: "decisions", Limit: 5}, `exists in more than one namespace [null ]`)
	// Limit 1 on the empty namespace: id 2 reaches the limit; the null
	// namespace's checkpoint must not complete the page, so id 3 is read
	// and the empty namespace's checkpoint completes it.
	env := acquire(t, cfg, Request{Stream: "decisions", Namespace: given(""), Limit: 1})
	if len(env.Result) != 2 || string(env.Result[0]) != `{"id":2}` || string(env.Result[1]) != `{"id":3}` {
		t.Fatalf("the empty namespace's records to its own checkpoint: %s", env.Result)
	}
	if env.Acquisition["snapshot"] != emptyState {
		t.Fatalf("bookmarked by the empty namespace's checkpoint: %v", env.Acquisition["snapshot"])
	}
	if !strings.Contains(env.Acquisition["statement"].(string), `"namespace":""`) {
		t.Fatalf("the statement keeps the empty namespace: %v", env.Acquisition["statement"])
	}
	// An explicit null selects the stream without a namespace: ids 1 and 4,
	// bookmarked by the null namespace's second checkpoint.
	env = acquire(t, cfg, Request{Stream: "decisions", Namespace: givenNull(), Limit: 2})
	if len(env.Result) != 2 || string(env.Result[0]) != `{"id":1}` || string(env.Result[1]) != `{"id":4}` || env.Acquisition["snapshot"] != nullState {
		t.Fatalf("the null namespace's records and checkpoint: %s %v", env.Result, env.Acquisition["snapshot"])
	}
	if !strings.Contains(env.Acquisition["statement"].(string), `"namespace":null`) {
		t.Fatalf("the statement keeps the null namespace: %v", env.Acquisition["statement"])
	}
	mustFail(t, cfg, Request{Stream: "decisions", Namespace: given("x"), Limit: 1}, `stream "x/decisions" is not one the connector offers: [decisions /decisions]`)
}

// An inspect's answer counts as absence only when it says "no such" of the
// container itself, in docker's or podman's words; a transport failure
// that says "no such host" names no container and leaves the question
// open.
func TestInspectAbsenceNamesTheContainer(t *testing.T) {
	for _, wording := range []string{"Error: No such object: {name}", "Error: inspecting object: no such container {name}"} {
		cfg := fake(t, discoverFixture, readFixture)
		t.Setenv(fakeruntime.EnvKillExit, "1")
		t.Setenv(fakeruntime.EnvInspectExit, "125")
		t.Setenv(fakeruntime.EnvInspectStderr, wording)
		acquire(t, cfg, Request{Stream: "decisions", Limit: 3})
	}
	cfg := fake(t, discoverFixture, readFixture)
	t.Setenv(fakeruntime.EnvKillExit, "1")
	t.Setenv(fakeruntime.EnvInspectExit, "1")
	t.Setenv(fakeruntime.EnvInspectStderr, "error during connect: dial tcp: lookup dockerd: no such host")
	mustFail(t, cfg, Request{Stream: "decisions", Limit: 3}, "could not say whether it is gone (error during connect: dial tcp: lookup dockerd: no such host)")
}

// An inspect whose output is held by a descendant is drained within its
// own bound, so stopping stays inside the budget.
func TestInspectDrainIsBounded(t *testing.T) {
	cfg := fake(t, discoverFixture, readFixture)
	t.Setenv(fakeruntime.EnvKillExit, "1")
	t.Setenv(fakeruntime.EnvInspectExit, "2")
	t.Setenv(fakeruntime.EnvHoldInspect, "1")
	t.Cleanup(func() { killHolders(t) })
	start := time.Now()
	mustFail(t, cfg, Request{Stream: "decisions", Limit: 3}, "could not say whether it is gone")
	// The discover container's stop: a kill answered at once, an inspect
	// that exits at once but leaves its pipes held for the drain window.
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Fatalf("a descendant on inspect's output held stopping for %v", elapsed)
	}
}

// A message of a known type without the payload its type requires is
// refused in whatever phase it appears.
func TestPayloadIsRequiredPerType(t *testing.T) {
	cfg := fake(t, discoverFixture, rec(1, "0", "")+`{"type":"TRACE","trace":{}}`+"\n"+`{"type":"STATE","state":`+state1+`}`+"\n")
	mustFail(t, cfg, Request{Stream: "decisions", Limit: 1}, "malformed TRACE message")
	cfg = fake(t, `{"type":"STATE","state":5}`+"\n"+discoverFixture, readFixture)
	mustFail(t, cfg, Request{Stream: "decisions", Limit: 1}, "malformed STATE message")
	cfg = fake(t, discoverFixture, `{"type":"CATALOG","catalog":null}`+"\n"+readFixture)
	mustFail(t, cfg, Request{Stream: "decisions", Limit: 3}, "malformed CATALOG message")
	cfg = fake(t, discoverFixture, `{"type":"RECORD","record":{"stream":"decisions"}}`+"\n")
	mustFail(t, cfg, Request{Stream: "decisions", Limit: 1}, "malformed RECORD message")
}

// Redaction is one pass over the original text: a value that appears many
// times in the configuration is replaced once per occurrence in the
// diagnostic, a replacement is never re-matched, and the output cannot
// grow past its bound.
func TestRedactionIsOnePass(t *testing.T) {
	var config strings.Builder
	config.WriteString(`{"a":"e"`)
	for i := 0; i < 20; i++ {
		fmt.Fprintf(&config, `,"k%d":"e"`, i)
	}
	config.WriteString(`,"long":"red"}`)
	secrets := secretsOf([]byte(config.String()))
	if len(secrets) != 2 || secrets[0] != "red" || secrets[1] != "e" {
		t.Fatalf("deduplicated, longest first: %v", secrets)
	}
	if got := redact("e", secrets); got != "[redacted]" {
		t.Fatalf("one occurrence, one marker: %q", got)
	}
	if got := redact("see red", secrets); got != "s[redacted][redacted] [redacted]" {
		t.Fatalf("each occurrence once, longest first: %q", got)
	}
	if got := redact(strings.Repeat("e", 10000), secrets); len(got) > maxDiagnostic+len("…")+len("[redacted]") {
		t.Fatalf("bounded as it is built: %d bytes", len(got))
	}
}
