package mcp

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"adapters/internal/fakemcp"
)

func TestMain(m *testing.M) {
	if os.Getenv(fakemcp.EnvActivate) == "1" {
		os.Exit(fakemcp.Run(os.Args[1:]))
	}
	os.Exit(m.Run())
}

const testDigest = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

const credentialsFixture = `{"DATABASE_URL":"postgresql://app:hunter2@warehouse.internal:5432/decisions","PGSSLMODE":"require"}`

// queryOutputSchema is the default tool's declared output schema as the
// fake describes it, in the canonical form the adapter digests.
const queryOutputSchema = `{"properties":{"rows":{"type":"array"}},"type":"object"}`

var stampForm = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$`)

// fake installs the test binary as the MCP server (Command) and returns a
// configuration pointing at it; image switches it to the runtime form.
func fake(t *testing.T) Config {
	t.Helper()
	dir := t.TempDir()
	for _, name := range []string{fakemcp.EnvTools, fakemcp.EnvResult, fakemcp.EnvHang, fakemcp.EnvExitBeforeCall, fakemcp.EnvStderr,
		fakemcp.EnvServerRequest, fakemcp.EnvNotify, fakemcp.EnvJunk, fakemcp.EnvPagedTools, fakemcp.EnvInitError, fakemcp.EnvStuck,
		fakemcp.EnvPing, fakemcp.EnvWrongID, fakemcp.EnvHoldStdin, fakemcp.EnvConflict, fakemcp.EnvExitAtStart, fakemcp.EnvProtocol, fakemcp.EnvNoTools,
		fakemcp.EnvLinger, fakemcp.EnvNullError, fakemcp.EnvServerInfo, fakemcp.EnvListRaw, fakemcp.EnvListLine, fakemcp.EnvListPages, fakemcp.EnvStderrFile, fakemcp.EnvRequire} {
		t.Setenv(name, "")
	}
	t.Setenv(fakemcp.EnvActivate, "1")
	t.Setenv(fakemcp.EnvTrace, filepath.Join(dir, "trace.jsonl"))
	t.Setenv(fakemcp.EnvKills, filepath.Join(dir, "kills"))
	t.Setenv(fakemcp.EnvHolderPid, filepath.Join(dir, "holder"))
	t.Setenv(fakemcp.EnvEnvKeys, "DATABASE_URL,PGSSLMODE,ADAPTER_MARK")
	credentials := filepath.Join(dir, "credentials.json")
	if err := os.WriteFile(credentials, []byte(credentialsFixture), 0o600); err != nil {
		t.Fatal(err)
	}
	return Config{Command: []string{os.Args[0]}, Credentials: credentials, MaxOutput: 1 << 20}
}

func image(cfg Config) Config {
	cfg.Command = nil
	cfg.Runtime = os.Args[0]
	cfg.Image = "ghcr.io/example/mcp-postgres:2.1@" + testDigest
	return cfg
}

// trace returns the JSON lines the fake recorded: messages it received,
// its environment, and runtime runs.
func trace(t *testing.T) []map[string]any {
	t.Helper()
	data, err := os.ReadFile(os.Getenv(fakemcp.EnvTrace))
	if err != nil {
		t.Fatal(err)
	}
	var out []map[string]any
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		var m map[string]any
		if err := json.Unmarshal([]byte(line), &m); err != nil {
			t.Fatalf("trace line %q: %v", line, err)
		}
		out = append(out, m)
	}
	return out
}

func methods(tr []map[string]any) []string {
	var out []string
	for _, m := range tr {
		if method, ok := m["method"].(string); ok {
			out = append(out, method)
		}
	}
	return out
}

func decode(t *testing.T, out []byte) (map[string]any, json.RawMessage) {
	t.Helper()
	var top map[string]json.RawMessage
	if err := json.Unmarshal(out, &top); err != nil {
		t.Fatalf("envelope is not JSON: %v\n%s", err, out)
	}
	if len(top) != 2 {
		t.Fatalf("a tool call's envelope carries acquisition and result, never page: %s", out)
	}
	var acq map[string]any
	if err := json.Unmarshal(top["acquisition"], &acq); err != nil {
		t.Fatal(err)
	}
	return acq, top["result"]
}

// acquire runs one acquisition under a bound that a server answering at
// once never approaches, so a client that stops talking -- to a server
// waiting on an answer of its own, or lingering after the call -- fails
// here instead of hanging.
func acquire(t *testing.T, cfg Config, req Request) (map[string]any, json.RawMessage) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	start := time.Now()
	out, err := Acquire(ctx, cfg, req)
	if err != nil {
		t.Fatal(err)
	}
	if elapsed := time.Since(start); elapsed > 1500*time.Millisecond {
		t.Fatalf("an acquisition against a server that answers at once took %v: the server was not ended by end-of-input", elapsed)
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

func query(sql string) Request {
	return Request{Tool: "query", Arguments: json.RawMessage(`{"sql":"` + sql + `"}`)}
}

// One tool call through a local server: the handshake in order, the tool's
// whole result carried into the canon domain, the acquisition as §1.2a's
// envelope states it, and the credentials in the server's environment.
func TestAcquireCallsOneToolAndRecordsTheAcquisition(t *testing.T) {
	cfg := fake(t)
	cfg.Endpoint = "warehouse.internal:5432"
	t.Setenv("ADAPTER_MARK", "declared-for-the-adapter")
	before := time.Now().UTC().Truncate(time.Second).Format(stampLayout)
	acq, result := acquire(t, cfg, query("select 1"))
	after := time.Now().UTC().Truncate(time.Second).Format(stampLayout)
	if string(result) != `{"content":[{"text":"1 row","type":"text"}],"structuredContent":{"rows":[{"amount":"12.5","id":101}]}}` {
		t.Fatalf("the result is the tool's whole answer, canonical: %s", result)
	}
	for _, name := range []string{"adapter", "endpoint", "statement", "snapshot", "peerIdentity", "schema", "upstreamToken", "observedAt"} {
		if _, present := acq[name]; !present {
			t.Fatalf("acquisition lacks %q: %v", name, acq)
		}
	}
	if len(acq) != 8 {
		t.Fatalf("exactly the eight members an adapter reports: %v", acq)
	}
	adapter := acq["adapter"].(map[string]any)
	self, _ := os.ReadFile(os.Args[0])
	sum := sha256.Sum256(self)
	if adapter["name"] != os.Args[0] || adapter["version"] != "1.0" || adapter["digest"] != "sha256:"+hex.EncodeToString(sum[:]) {
		t.Fatalf("a command server is named as configured, versioned as it says, digested as its executable: %v", adapter)
	}
	if acq["endpoint"] != "warehouse.internal:5432" || acq["snapshot"] != nil || acq["peerIdentity"] != nil || acq["upstreamToken"] != nil {
		t.Fatalf("endpoint as named; snapshot, peer identity and upstream token null: %v", acq)
	}
	if acq["statement"] != `{"arguments":{"sql":"select 1"},"tool":"query"}` {
		t.Fatalf("the statement is the call: %v", acq["statement"])
	}
	schemaSum := sha256.Sum256([]byte(queryOutputSchema))
	if acq["schema"] != "sha256:"+hex.EncodeToString(schemaSum[:]) {
		t.Fatalf("the schema is the digest of the tool's canonical output schema: %v", acq["schema"])
	}
	observedAt, _ := acq["observedAt"].(string)
	if !stampForm.MatchString(observedAt) || observedAt < before || after < observedAt {
		t.Fatalf("observedAt is a stamp of when the answer was read: %v (between %s and %s)", acq["observedAt"], before, after)
	}
	tr := trace(t)
	if got := methods(tr); strings.Join(got, " ") != "initialize notifications/initialized tools/list tools/call" {
		t.Fatalf("the handshake, the listing, the call, in order: %v", got)
	}
	env, _ := tr[0]["env"].(map[string]any)
	if env["DATABASE_URL"] != "postgresql://app:hunter2@warehouse.internal:5432/decisions" || env["PGSSLMODE"] != "require" || env["ADAPTER_MARK"] != "declared-for-the-adapter" {
		t.Fatalf("the credentials and the adapter's own environment reach a command server: %v", env)
	}
	for _, m := range tr {
		if m["method"] == "tools/call" {
			params := m["params"].(map[string]any)
			if params["name"] != "query" || params["arguments"].(map[string]any)["sql"] != "select 1" {
				t.Fatalf("the call carries the tool and the arguments: %v", params)
			}
		}
	}
}

// Through the runtime form: the image is run with stdin attached, its
// credentials in an env file inside the private mount, and the container is
// told to stop by name when the call is done; the adapter is the image.
func TestAcquireThroughTheRuntime(t *testing.T) {
	cfg := image(fake(t))
	acq, _ := acquire(t, cfg, query("select 1"))
	adapter := acq["adapter"].(map[string]any)
	if adapter["name"] != "ghcr.io/example/mcp-postgres" || adapter["version"] != "2.1" || adapter["digest"] != testDigest {
		t.Fatalf("the adapter is the pinned image: %v", adapter)
	}
	tr := trace(t)
	run, _ := tr[0]["run"].(map[string]any)
	argv := run["argv"].([]any)
	joined := make([]string, len(argv))
	for i, a := range argv {
		joined[i] = a.(string)
	}
	line := strings.Join(joined, " ")
	if joined[0] != "run" || joined[1] != "--rm" || !strings.Contains(line, " --env-file ") || !strings.Contains(line, " -i -- "+cfg.Image) ||
		strings.Index(line, " --env-file ") > strings.Index(line, cfg.Image) {
		t.Fatalf("run --rm --name NAME -v MOUNT:/secrets:ro --env-file MOUNT/env -i IMAGE, the env file before the image: %s", line)
	}
	if run["envFile"] != "DATABASE_URL=postgresql://app:hunter2@warehouse.internal:5432/decisions\nPGSSLMODE=require\n" {
		t.Fatalf("the env file carries the credentials, sorted: %q", run["envFile"])
	}
	kills, _ := os.ReadFile(os.Getenv(fakemcp.EnvKills))
	if strings.TrimSpace(string(kills)) != joined[3] {
		t.Fatalf("the container is told to stop by name: %q vs %s", kills, joined[3])
	}
	t.Setenv(fakemcp.EnvStuck, "1")
	mustFail(t, cfg, query("select 1"), "could not be stopped and is still known")
}

func TestAcquireRefusals(t *testing.T) {
	t.Run("unknown tool", func(t *testing.T) {
		mustFail(t, fake(t), Request{Tool: "drop_table", Arguments: json.RawMessage(`{}`)}, `tool "drop_table" is not one the server offers: [query]`)
	})
	t.Run("tool outside the allowlist", func(t *testing.T) {
		cfg := fake(t)
		cfg.Tools = []string{"read_file"}
		mustFail(t, cfg, query("select 1"), `tool "query" is not one this source may call: [read_file]`)
		if _, err := os.Stat(os.Getenv(fakemcp.EnvTrace)); err == nil {
			t.Fatal("a refused tool starts no server")
		}
	})
	t.Run("tool error", func(t *testing.T) {
		cfg := fake(t)
		path := filepath.Join(t.TempDir(), "result.json")
		os.WriteFile(path, []byte(`{"isError":true,"content":[{"type":"text","text":"permission denied for hunter2 at warehouse.internal"}]}`), 0o600)
		t.Setenv(fakemcp.EnvResult, path)
		_, err := Acquire(context.Background(), cfg, query("select 1"))
		if err == nil || !strings.Contains(err.Error(), "the tool reported an error: permission denied for [redacted] at warehouse.internal") {
			t.Fatalf("a tool error fails the acquisition, redacted: %v", err)
		}
	})
	t.Run("server exits before answering", func(t *testing.T) {
		cfg := fake(t)
		t.Setenv(fakemcp.EnvExitBeforeCall, "1")
		t.Setenv(fakemcp.EnvStderr, "FATAL: password authentication failed for hunter2\nmore\n")
		_, err := Acquire(context.Background(), cfg, query("select 1"))
		if err == nil || !strings.Contains(err.Error(), "the server ended before answering tools/call: FATAL: password authentication failed for [redacted]") || strings.Contains(err.Error(), "more") {
			t.Fatalf("the server's first line of stderr, redacted: %v", err)
		}
	})
	t.Run("initialize error", func(t *testing.T) {
		cfg := fake(t)
		t.Setenv(fakemcp.EnvInitError, "1")
		mustFail(t, cfg, query("select 1"), "initialize: unsupported protocol version (code -32602)")
	})
	t.Run("junk on stdout", func(t *testing.T) {
		cfg := fake(t)
		t.Setenv(fakemcp.EnvJunk, "1")
		mustFail(t, cfg, query("select 1"), "not a JSON-RPC message")
	})
	t.Run("output bound", func(t *testing.T) {
		cfg := fake(t)
		cfg.MaxOutput = 64
		// Refused at the tool's result, before an envelope is built around it.
		mustFail(t, cfg, query("select 1"), "the tool's result exceeds the output bound of 64 bytes")
		// A result within the bound whose envelope is not: refused too.
		cfg.MaxOutput = 200
		mustFail(t, cfg, query("select 1"), "the envelope exceeds the output bound of 200 bytes")
	})
	t.Run("unsupported protocol version", func(t *testing.T) {
		cfg := fake(t)
		t.Setenv(fakemcp.EnvProtocol, "1999-01-01")
		mustFail(t, cfg, query("select 1"), `speaks protocol version '1999-01-01', which this client does not`)
	})
	t.Run("no tools capability", func(t *testing.T) {
		cfg := fake(t)
		t.Setenv(fakemcp.EnvNoTools, "1")
		mustFail(t, cfg, query("select 1"), "the server offers no tools capability")
	})
	t.Run("server exits at start with stderr only", func(t *testing.T) {
		cfg := fake(t)
		t.Setenv(fakemcp.EnvExitAtStart, "1")
		t.Setenv(fakemcp.EnvStderr, "cannot bind: address in use\n")
		_, err := Acquire(context.Background(), cfg, query("select 1"))
		if err == nil {
			t.Fatal("a server that exits at start cannot answer the acquisition")
		}
		// The child can exit before the initialize write or before its reply
		// is read. Both failures must retain the child's diagnostic.
		message := err.Error()
		ended := strings.HasPrefix(message, "the server ended before answering initialize:")
		inputClosed := strings.HasPrefix(message, "the server's input closed:")
		if (!ended && !inputClosed) || !strings.HasSuffix(message, ": cannot bind: address in use") {
			t.Fatalf("a startup failure with the server's stderr: %v", err)
		}
	})
	t.Run("result and error both", func(t *testing.T) {
		cfg := fake(t)
		t.Setenv(fakemcp.EnvConflict, "1")
		mustFail(t, cfg, query("select 1"), "answered with both a result and an error")
		// An error member that is null is still an error member.
		cfg = fake(t)
		t.Setenv(fakemcp.EnvNullError, "1")
		mustFail(t, cfg, query("select 1"), "answered with both a result and an error")
	})
	t.Run("duplicate output schema in a descriptor", func(t *testing.T) {
		cfg := fake(t)
		path := filepath.Join(t.TempDir(), "tools.json")
		os.WriteFile(path, []byte(`[{"name":"query","inputSchema":{"type":"object"},"outputSchema":{"type":"object"},"outputSchema":null}]`), 0o600)
		t.Setenv(fakemcp.EnvTools, path)
		mustFail(t, cfg, query("select 1"), `JSON-RPC message that is malformed: duplicate member name 'outputSchema'`)
	})
	t.Run("tool results held to their shape", func(t *testing.T) {
		for text, want := range map[string]string{
			`{}`:                                     "has no content array",
			`{"content":null}`:                       "has no content array",
			`{"content":[{"text":"x"}]}`:             "a content item without a type",
			`{"content":[],"structuredContent":[1]}`: "structuredContent is not an object",
			`{"content":[],"isError":"yes"}`:         "isError is not a boolean",
			`{"content":[],"isError":null}`:          "isError is not a boolean",
			`{"content":[{"Type":"text"}]}`:          "a content item without a type",
			`{"content":[{"type":1.5}]}`:             "a content item without a type",
			`{"content":[{"type":"text","text":"boom"}],"isError":true,"ISERROR":false}`: "the tool reported an error: boom",
			`{"content":[{"type":"text","text":"boom"}],"isError":true,"iserror":false}`: "the tool reported an error: boom",
			`{"content":[{"type":"text","text":"ok"}]}`:                                  "",
		} {
			cfg := fake(t)
			path := filepath.Join(t.TempDir(), "result.json")
			os.WriteFile(path, []byte(text), 0o600)
			t.Setenv(fakemcp.EnvResult, path)
			if want == "" {
				if _, result := acquire(t, cfg, query("select 1")); string(result) != `{"content":[{"text":"ok","type":"text"}]}` {
					t.Fatalf("a content-only result is a result: %s", result)
				}
				continue
			}
			mustFail(t, cfg, query("select 1"), want)
		}
	})
	t.Run("server-derived diagnostics are redacted", func(t *testing.T) {
		cfg := fake(t)
		os.WriteFile(cfg.Credentials, []byte(`{"TOKEN":"hunter2"}`), 0o600)
		path := filepath.Join(t.TempDir(), "tools.json")
		os.WriteFile(path, []byte(`[{"name":"hunter2","inputSchema":{"type":"object"}}]`), 0o600)
		t.Setenv(fakemcp.EnvTools, path)
		_, err := Acquire(context.Background(), cfg, query("select 1"))
		if err == nil || strings.Contains(err.Error(), "hunter2") || !strings.Contains(err.Error(), "not one the server offers: [[redacted]]") {
			t.Fatalf("offered names are redacted: %v", err)
		}
		cfg = fake(t)
		os.WriteFile(cfg.Credentials, []byte(`{"TOKEN":"hunter2"}`), 0o600)
		result := filepath.Join(t.TempDir(), "result.json")
		os.WriteFile(result, []byte(`{"content":[],"hunter2":0,"hunter2":1}`), 0o600)
		t.Setenv(fakemcp.EnvResult, result)
		_, err = Acquire(context.Background(), cfg, query("select 1"))
		if err == nil || strings.Contains(err.Error(), "hunter2") || !strings.Contains(err.Error(), `duplicate member name '[redacted]'`) {
			t.Fatalf("a canonicalization diagnostic is redacted: %v", err)
		}
	})
	t.Run("credentials not an object of strings", func(t *testing.T) {
		cfg := fake(t)
		os.WriteFile(cfg.Credentials, []byte(`{"PORT":5432}`), 0o600)
		mustFail(t, cfg, query("select 1"), "a credentials member is not a string")
		os.WriteFile(cfg.Credentials, []byte(`{"KEY":"a\nb"}`), 0o600)
		mustFail(t, cfg, query("select 1"), "a credentials member has a value an environment cannot carry")
		os.WriteFile(cfg.Credentials, []byte(`{"A=B":"x"}`), 0o600)
		mustFail(t, cfg, query("select 1"), "a credentials member is not an environment variable name")
	})
	t.Run("neither or both servers", func(t *testing.T) {
		cfg := fake(t)
		cfg.Command = nil
		mustFail(t, cfg, query("select 1"), "exactly one of --image and a server command after --")
		cfg = image(fake(t))
		cfg.Command = []string{"x"}
		mustFail(t, cfg, query("select 1"), "exactly one of --image and a server command after --")
		cfg = image(fake(t))
		cfg.Runtime = ""
		mustFail(t, cfg, query("select 1"), "a container runtime is required")
	})
	t.Run("command missing", func(t *testing.T) {
		cfg := fake(t)
		cfg.Command = []string{filepath.Join(t.TempDir(), "missing")}
		mustFail(t, cfg, query("select 1"), "server command could not be resolved")
	})
	t.Run("unpinned image", func(t *testing.T) {
		cfg := image(fake(t))
		cfg.Image = "ghcr.io/example/mcp-postgres:2.1"
		mustFail(t, cfg, query("select 1"), "must be pinned")
	})
}

// A server's own request is answered with "method not found" and a ping
// with an empty result, and the call still completes; a notification and a
// response to an id this client never used are passed over; a paged tool
// list is walked to the tool, and a tool without an output schema records
// null.
func TestAcquireTalksTheProtocol(t *testing.T) {
	cfg := fake(t)
	t.Setenv(fakemcp.EnvServerRequest, "1")
	t.Setenv(fakemcp.EnvPing, "1")
	t.Setenv(fakemcp.EnvNotify, "1")
	t.Setenv(fakemcp.EnvWrongID, "1")
	_, result := acquire(t, cfg, query("select 1"))
	if strings.Contains(string(result), "WRONG") {
		t.Fatalf("a response to another id is not this call's: %s", result)
	}
	var refused, pinged bool
	for _, m := range trace(t) {
		if m["id"] == "srv-1" && m["error"] != nil {
			if code := m["error"].(map[string]any)["code"]; code != float64(-32601) {
				t.Fatalf("the server's request is refused with method-not-found: %v", m)
			}
			refused = true
		}
		if m["id"] == "ping-1" {
			if res, ok := m["result"].(map[string]any); !ok || len(res) != 0 || m["error"] != nil {
				t.Fatalf("a ping is answered with an empty result: %v", m)
			}
			pinged = true
		}
	}
	if !refused || !pinged {
		t.Fatalf("the server's request (%v) and its ping (%v) must both be answered", refused, pinged)
	}
	cfg = fake(t)
	path := filepath.Join(t.TempDir(), "tools.json")
	os.WriteFile(path, []byte(`[{"name":"other","inputSchema":{"type":"object"}},{"name":"query","inputSchema":{"type":"object"}}]`), 0o600)
	t.Setenv(fakemcp.EnvTools, path)
	t.Setenv(fakemcp.EnvPagedTools, "1")
	acq, _ := acquire(t, cfg, query("select 1"))
	if acq["schema"] != nil {
		t.Fatalf("a tool that declares no output schema records null: %v", acq["schema"])
	}
	if got := methods(trace(t)); strings.Count(strings.Join(got, " "), "tools/list") != 2 {
		t.Fatalf("two pages listed: %v", got)
	}
}

// A server that never answers is stopped when the acquisition's time is up,
// at once: the deadline is the budget, and the context kills the server (or
// the runtime client, whose container is then told to stop by name).
func TestAcquireStopsAHangingServer(t *testing.T) {
	for _, form := range []string{"command", "image"} {
		cfg := fake(t)
		if form == "image" {
			cfg = image(cfg)
		}
		t.Setenv(fakemcp.EnvHang, "1")
		ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
		start := time.Now()
		_, err := Acquire(ctx, cfg, query("select 1"))
		cancel()
		if err == nil || !strings.Contains(err.Error(), "did not answer in time: context deadline exceeded") {
			t.Fatalf("%s: a deadline is reported as one: %v", form, err)
		}
		if elapsed := time.Since(start); elapsed > 500*time.Millisecond+4*time.Second {
			t.Fatalf("%s: the server held the acquisition past its deadline: %v", form, elapsed)
		}
		if form == "image" {
			if kills, _ := os.ReadFile(os.Getenv(fakemcp.EnvKills)); len(strings.TrimSpace(string(kills))) == 0 {
				t.Fatal("the container is told to stop by name")
			}
		}
	}
}

// A server that answered but ignores end-of-input is given the wait delay
// to end on it and then killed -- in both forms -- so a stop costs the wait
// delay and no more, and a server that ends on end-of-input costs nothing
// (the acquire helper's bound).
func TestStopGivesEndOfInputAChance(t *testing.T) {
	for _, form := range []string{"command", "image"} {
		cfg := fake(t)
		if form == "image" {
			cfg = image(cfg)
		}
		t.Setenv(fakemcp.EnvLinger, "1")
		start := time.Now()
		out, err := Acquire(context.Background(), cfg, query("select 1"))
		if err != nil {
			t.Fatalf("%s: %v", form, err)
		}
		decode(t, out)
		elapsed := time.Since(start)
		if elapsed < 2*time.Second || elapsed > 6*time.Second {
			t.Fatalf("%s: a lingering server costs the wait delay and is then killed; took %v", form, elapsed)
		}
	}
}

// A write blocked on stdin -- a descendant holds the pipe and nobody reads
// -- ends with the deadline: stdin is closed with the context.
func TestAcquireIsNotHeldByABlockedWrite(t *testing.T) {
	cfg := fake(t)
	t.Setenv(fakemcp.EnvHoldStdin, "1")
	t.Cleanup(func() {
		data, err := os.ReadFile(os.Getenv(fakemcp.EnvHolderPid))
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
	big := Request{Tool: "query", Arguments: json.RawMessage(`{"sql":"` + strings.Repeat("x", 300000) + `"}`)}
	_, err := Acquire(ctx, cfg, big)
	if err == nil || !strings.Contains(err.Error(), "context deadline exceeded") {
		t.Fatalf("the deadline must end the acquisition: %v", err)
	}
	if time.Since(start) > 500*time.Millisecond+4*time.Second {
		t.Fatalf("a blocked write held the acquisition for %v", time.Since(start))
	}
}

// The adapter cannot tell a read tool from a write tool: an offered tool of
// any name is callable unless the operator restricts the source. That is
// the boundary the README states as the operator's.
func TestWriteCapableToolIsTheOperatorsToRestrict(t *testing.T) {
	cfg := fake(t)
	path := filepath.Join(t.TempDir(), "tools.json")
	os.WriteFile(path, []byte(`[{"name":"query","inputSchema":{"type":"object"}},{"name":"delete_rows","inputSchema":{"type":"object"}}]`), 0o600)
	t.Setenv(fakemcp.EnvTools, path)
	acquire(t, cfg, Request{Tool: "delete_rows", Arguments: json.RawMessage(`{"table":"decisions"}`)})
	cfg.Tools = []string{"query"}
	mustFail(t, cfg, Request{Tool: "delete_rows", Arguments: json.RawMessage(`{}`)}, `tool "delete_rows" is not one this source may call: [query]`)
}

// Nothing of the credentials reaches the envelope: neither the result nor
// the statement nor the acquisition repeats them.
func TestCredentialsStayOutOfTheEnvelope(t *testing.T) {
	cfg := fake(t)
	out, err := Acquire(context.Background(), cfg, query("select 1"))
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"hunter2", "DATABASE_URL", "require"} {
		if strings.Contains(string(out), secret) {
			t.Fatalf("the envelope carries %q", secret)
		}
	}
}

func TestParseRequest(t *testing.T) {
	r, err := ParseRequest(strings.NewReader(`{"tool":"query"}`))
	if err != nil || r.Tool != "query" || string(r.Arguments) != "{}" {
		t.Fatalf("defaults: %+v %v", r, err)
	}
	if _, err := ParseRequest(strings.NewReader(`{"tool":"query","arguments":{"x":"` + strings.Repeat("y", 2<<20) + `"}}`)); err == nil {
		t.Fatal("a request past one mebibyte is refused")
	}
	for in, want := range map[string]string{
		`{"tool":"query","arguments":{"sql":"x"},"extra":1}`: "unknown field",
		`{"arguments":{}}`:                  `"tool" is required`,
		`{"tool":"query","arguments":[]}`:   `"arguments" must be an object`,
		`{"tool":"query","arguments":"x"}`:  `"arguments" must be an object`,
		`{"tool":"query","arguments":null}`: "",
		`{"tool":"query"} {}`:               "trailing content",
		`[]`:                                "cannot unmarshal",
	} {
		_, err := ParseRequest(strings.NewReader(in))
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

func decodeCheck(t *testing.T, out []byte) (adapter, server map[string]string, protocol string, tools []string) {
	t.Helper()
	var top map[string]json.RawMessage
	if err := json.Unmarshal(out, &top); err != nil || len(top) != 1 {
		t.Fatalf("a check report is one member, check: %s", out)
	}
	var report struct {
		Adapter         map[string]string `json:"adapter"`
		Server          map[string]string `json:"server"`
		ProtocolVersion string            `json:"protocolVersion"`
		Tools           []string          `json:"tools"`
	}
	if err := json.Unmarshal(top["check"], &report); err != nil {
		t.Fatalf("check: %v\n%s", err, out)
	}
	return report.Adapter, report.Server, report.ProtocolVersion, report.Tools
}

// runArgv is the runtime command line the stand-in recorded for its run.
func runArgv(t *testing.T) []string {
	t.Helper()
	var argv []string
	for _, m := range trace(t) {
		run, ok := m["run"].(map[string]any)
		if !ok {
			continue
		}
		argv = nil
		for _, a := range run["argv"].([]any) {
			argv = append(argv, a.(string))
		}
	}
	if argv == nil {
		t.Fatal("the stand-in recorded no run")
	}
	return argv
}

func TestCheckReportsTheServerAndItsTools(t *testing.T) {
	cfg := image(fake(t))
	cfg.Args = []string{"--access-mode=restricted"}
	cfg.Tools = []string{"query"}
	// The server answers only with its credential in the env file it was
	// run with: a check that did not hand it over does not succeed.
	t.Setenv(fakemcp.EnvRequire, "PGSSLMODE=require")
	out, err := Check(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	adapter, server, protocol, tools := decodeCheck(t, out)
	if adapter["name"] != "ghcr.io/example/mcp-postgres" || adapter["version"] != "2.1" || adapter["digest"] != testDigest {
		t.Fatalf("the report names the pinned image: %s", out)
	}
	if server["name"] != "fake-mcp" || server["version"] != "1.0" || protocol != "2025-06-18" || len(tools) != 1 || tools[0] != "query" {
		t.Fatalf("the report carries the server's identity, protocol and tools: %s", out)
	}
	if got := methods(trace(t)); strings.Join(got, " ") != "initialize notifications/initialized tools/list" {
		t.Fatalf("a check completes the handshake and lists, and calls nothing: %v", got)
	}
	argv := runArgv(t)
	if n := len(argv); n < 2 || argv[n-2] != cfg.Image || argv[n-1] != "--access-mode=restricted" {
		t.Fatalf("the server's own arguments follow the image on the runtime's command line: %v", argv)
	}
	if data, _ := os.ReadFile(os.Getenv(fakemcp.EnvKills)); len(strings.TrimSpace(string(data))) == 0 {
		t.Fatal("the container is told to stop by name after a check as after an acquisition")
	}
}

func TestCheckListsEveryPage(t *testing.T) {
	cfg := fake(t)
	// As a command, the credential must be in the server's environment.
	t.Setenv(fakemcp.EnvRequire, "PGSSLMODE=require")
	tools := filepath.Join(t.TempDir(), "tools.json")
	if err := os.WriteFile(tools, []byte(`[{"name":"query","inputSchema":{"type":"object"}},{"name":"other","inputSchema":{"type":"object"}}]`), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv(fakemcp.EnvTools, tools)
	t.Setenv(fakemcp.EnvPagedTools, "1")
	cfg.Tools = []string{"other"}
	out, err := Check(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	_, _, _, listed := decodeCheck(t, out)
	if strings.Join(listed, ",") != "query,other" {
		t.Fatalf("every page's tools are listed in the server's order: %v", listed)
	}
}

func TestCheckRefusesAnAllowedToolTheServerDoesNotOffer(t *testing.T) {
	cfg := fake(t)
	cfg.Tools = []string{"query", "drop_table"}
	out, err := Check(context.Background(), cfg)
	if err == nil || out != nil || !strings.Contains(err.Error(), `tool "drop_table" is allowed by the configuration but not offered by the server: [query]`) {
		t.Fatalf("a binding naming a tool the server lacks is found out at connect time: %v %s", err, out)
	}
}

func TestCheckFailsAsAcquireDoes(t *testing.T) {
	for _, tc := range []struct {
		name string
		env  map[string]string
		args []string
		want string
	}{
		{"initialize refused", map[string]string{fakemcp.EnvInitError: "1"}, nil, "initialize"},
		{"no tools capability", map[string]string{fakemcp.EnvNoTools: "1"}, nil, "offers no tools capability"},
		{"server exits with its reason redacted", map[string]string{fakemcp.EnvExitAtStart: "1", fakemcp.EnvStderr: "cannot connect as app with hunter2\n"}, nil, "cannot connect as [redacted] with [redacted]"},
		{"args with a command", nil, []string{"--flag"}, "a server command carries its own arguments"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := fake(t)
			for k, v := range tc.env {
				t.Setenv(k, v)
			}
			cfg.Args = tc.args
			out, err := Check(context.Background(), cfg)
			if err == nil || out != nil || !strings.Contains(err.Error(), tc.want) || strings.Contains(err.Error(), "hunter2") {
				t.Fatalf("want %q, redacted: %v %s", tc.want, err, out)
			}
		})
	}
}

func TestImageArgumentsFollowTheImageOnAcquire(t *testing.T) {
	cfg := image(fake(t))
	cfg.Args = []string{"--access-mode=restricted", "--transport=stdio"}
	if _, err := Acquire(context.Background(), cfg, Request{Tool: "query", Arguments: json.RawMessage(`{"sql":"select 1"}`)}); err != nil {
		t.Fatal(err)
	}
	argv := runArgv(t)
	if n := len(argv); n < 3 || argv[n-3] != cfg.Image || argv[n-2] != "--access-mode=restricted" || argv[n-1] != "--transport=stdio" {
		t.Fatalf("the server's own arguments follow the image, in order: %v", argv)
	}
	cfg = fake(t)
	cfg.Args = []string{"--flag"}
	if _, err := Acquire(context.Background(), cfg, Request{Tool: "query", Arguments: json.RawMessage(`{}`)}); err == nil || !strings.Contains(err.Error(), "a server command carries its own arguments") {
		t.Fatalf("args beside a command are refused: %v", err)
	}
}

func TestCheckRedactsWhatTheServerSaysOfItself(t *testing.T) {
	cfg := fake(t)
	// The server echoes the credential in its name, its version and a
	// tool's name; none of it reaches the report as written.
	t.Setenv(fakemcp.EnvServerInfo, `{"name":"server for app","version":"1.0+hunter2"}`)
	tools := filepath.Join(t.TempDir(), "tools.json")
	if err := os.WriteFile(tools, []byte(`[{"name":"query_hunter2","inputSchema":{"type":"object"}}]`), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv(fakemcp.EnvTools, tools)
	out, err := Check(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	adapter, server, _, listed := decodeCheck(t, out)
	if strings.Contains(string(out), "hunter2") || strings.Contains(string(out), "app") {
		t.Fatalf("the report carries no credential: %s", out)
	}
	if server["name"] != "server for [redacted]" || server["version"] != "1.0+[redacted]" || adapter["version"] != "1.0+[redacted]" || strings.Join(listed, ",") != "query_[redacted]" {
		t.Fatalf("every field the server said is redacted: %s", out)
	}
	// The same version goes into an acquisition's envelope for a command,
	// redacted there too.
	envelope, err := Acquire(context.Background(), cfg, Request{Tool: "query_hunter2", Arguments: json.RawMessage(`{}`)})
	if err == nil || !strings.Contains(err.Error(), "not one the server offers") {
		// The tool's own name carries the secret and the request names it
		// verbatim, which the server matches; the envelope must not carry it.
		if err != nil {
			t.Fatal(err)
		}
		// The statement names the tool as the caller asked for it; the
		// adapter's version is the server's word and is redacted.
		acq, _ := decode(t, envelope)
		if acq["adapter"].(map[string]any)["version"] != "1.0+[redacted]" {
			t.Fatalf("the envelope's adapter version is redacted: %s", envelope)
		}
	}
}

func TestInitializeRequiresTheServersIdentity(t *testing.T) {
	for _, tc := range []struct{ info, want string }{
		{"absent", "the server's answer carries no serverInfo object"},
		{`null`, "the server's answer carries no serverInfo object"},
		{`"pg"`, "the server's answer carries no serverInfo object"},
		{`{"version":"1"}`, "serverInfo names no server"},
		{`{"name":"","version":"1"}`, "serverInfo names no server"},
		{`{"name":"pg"}`, "serverInfo carries no version string"},
		{`{"name":"pg","version":null}`, "serverInfo carries no version string"},
		{`{"name":"pg","version":3}`, "serverInfo carries no version string"},
	} {
		t.Run(tc.info, func(t *testing.T) {
			cfg := fake(t)
			t.Setenv(fakemcp.EnvServerInfo, tc.info)
			if _, err := Check(context.Background(), cfg); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("check: want %q, got %v", tc.want, err)
			}
			if _, err := Acquire(context.Background(), cfg, Request{Tool: "query", Arguments: json.RawMessage(`{}`)}); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("acquire: want %q, got %v", tc.want, err)
			}
		})
	}
	cfg := fake(t)
	t.Setenv(fakemcp.EnvServerInfo, `{"name":"pg","version":""}`)
	if _, err := Check(context.Background(), cfg); err != nil {
		t.Fatalf("an empty version string is a version string: %v", err)
	}
}

func TestToolListMustBeAPage(t *testing.T) {
	for _, tc := range []struct{ raw, want string }{
		{`{}`, "carries no tools array"},
		{`{"tools":null}`, "carries no tools array"},
		{`{"tools":{}}`, "carries no tools array"},
		{`{"TOOLS":[]}`, "carries no tools array"},
		{`{"tools":[],"nextCursor":""}`, "nextCursor, when present, is a non-empty string"},
		{`{"tools":[],"nextCursor":5}`, "nextCursor, when present, is a non-empty string"},
		{`[]`, "is not a tool list"},
	} {
		t.Run(tc.raw, func(t *testing.T) {
			cfg := fake(t)
			raw := filepath.Join(t.TempDir(), "list.json")
			if err := os.WriteFile(raw, []byte(tc.raw), 0o600); err != nil {
				t.Fatal(err)
			}
			t.Setenv(fakemcp.EnvListRaw, raw)
			// No allowed tools, so an empty page would otherwise succeed.
			if out, err := Check(context.Background(), cfg); err == nil || out != nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("want %q, got %v %s", tc.want, err, out)
			}
			if _, err := Acquire(context.Background(), cfg, Request{Tool: "query", Arguments: json.RawMessage(`{}`)}); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("acquire: want %q, got %v", tc.want, err)
			}
		})
	}
	cfg := fake(t)
	raw := filepath.Join(t.TempDir(), "list.json")
	if err := os.WriteFile(raw, []byte(`{"tools":[]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv(fakemcp.EnvListRaw, raw)
	out, err := Check(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, _, listed := decodeCheck(t, out); len(listed) != 0 || !strings.Contains(string(out), `"tools":[]`) {
		t.Fatalf("a server offering no tool is reported as offering none: %s", out)
	}
}

func TestAnImageShapedLikeAnOptionIsRefused(t *testing.T) {
	cfg := image(fake(t))
	for _, ref := range []string{"--label=probe=value@" + testDigest, "-x@" + testDigest, "ghcr.io/-example/mcp@" + testDigest, "a/b:-tag@" + testDigest, "a b@" + testDigest} {
		cfg.Image = ref
		if _, err := Check(context.Background(), cfg); err == nil || !strings.Contains(err.Error(), "is not a reference") {
			t.Fatalf("%s: %v", ref, err)
		}
	}
	// The runtime's option parsing is ended before the image, so a server
	// argument shaped like an option is the server's.
	cfg = image(fake(t))
	cfg.Args = []string{"--name", "stray"}
	if _, err := Check(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	argv := runArgv(t)
	if n := len(argv); n < 4 || argv[n-4] != "--" || argv[n-3] != cfg.Image || argv[n-2] != "--name" || argv[n-1] != "stray" {
		t.Fatalf("-- ends the runtime's options before the image and the server's arguments: %v", argv)
	}
}

func TestAServerEchoingACredentialWithQuotesIsRedacted(t *testing.T) {
	cfg := fake(t)
	// A credential with a quote and a backslash: quoted with %q it would
	// be escaped past the redactor.
	credentials := filepath.Join(t.TempDir(), "credentials.json")
	if err := os.WriteFile(credentials, []byte(`{"TOKEN":"ab\"cd\\e"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg.Credentials = credentials
	t.Setenv(fakemcp.EnvProtocol, `ab"cd\e`)
	_, err := Check(context.Background(), cfg)
	if err == nil || !strings.Contains(err.Error(), "protocol version '[redacted]'") || strings.Contains(err.Error(), "cd") {
		t.Fatalf("the server's word is redacted as it said it: %v", err)
	}
}

func TestAResponseIsReadByExactMemberNames(t *testing.T) {
	for _, tc := range []struct{ line, want string }{
		{`{"jsonrpc":"2.0","id":{id},"result":null,"RESULT":{"tools":[]}}`, "is not a tool list"},
		{`{"jsonrpc":"2.0","id":{id},"result":{"tools":[]},"result":{"tools":[{"name":"query"}]}}`, `malformed: duplicate member name 'result'`},
		{`{"jsonrpc":"2.0","ID":{id},"result":{"tools":[]}}`, "neither a request, a notification nor a response"},
		{`{"JSONRPC":"2.0","id":{id},"result":{"tools":[]}}`, "is not a JSON-RPC message"},
		{`{"jsonrpc":"2.0","id":{id},"error":null,"ERROR":{"code":1,"message":"x"}}`, "an error that is not an object"},
	} {
		t.Run(tc.line, func(t *testing.T) {
			cfg := fake(t)
			line := filepath.Join(t.TempDir(), "line.json")
			if err := os.WriteFile(line, []byte(tc.line), 0o600); err != nil {
				t.Fatal(err)
			}
			t.Setenv(fakemcp.EnvListLine, line)
			if _, err := Check(context.Background(), cfg); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("want %q, got %v", tc.want, err)
			}
		})
	}
}

func TestAToolIsNamedByItsExactMember(t *testing.T) {
	cfg := fake(t)
	tools := filepath.Join(t.TempDir(), "tools.json")
	if err := os.WriteFile(tools, []byte(`[{"name":"other","NAME":"query","inputSchema":{"type":"object"}}]`), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv(fakemcp.EnvTools, tools)
	cfg.Tools = []string{"query"}
	if _, err := Check(context.Background(), cfg); err == nil || !strings.Contains(err.Error(), `tool "query" is allowed by the configuration but not offered by the server: [other]`) {
		t.Fatalf("NAME does not stand in for name: %v", err)
	}
	if err := os.WriteFile(tools, []byte(`[{"name":"a","name":"query","inputSchema":{"type":"object"}}]`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Check(context.Background(), cfg); err == nil || !strings.Contains(err.Error(), `malformed: duplicate member name 'name'`) {
		t.Fatalf("a duplicate name is refused: %v", err)
	}
}

func TestADuplicateMemberEchoingACredentialIsRedacted(t *testing.T) {
	cfg := fake(t)
	credentials := filepath.Join(t.TempDir(), "credentials.json")
	if err := os.WriteFile(credentials, []byte(`{"TOKEN":"ab\"cd\\e"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg.Credentials = credentials
	line := filepath.Join(t.TempDir(), "line.json")
	if err := os.WriteFile(line, []byte(`{"jsonrpc":"2.0","id":{id},"result":{"tools":[]},"ab\"cd\\e":1,"ab\"cd\\e":2}`), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv(fakemcp.EnvListLine, line)
	_, err := Check(context.Background(), cfg)
	if err == nil || !strings.Contains(err.Error(), "duplicate member name '[redacted]'") || strings.Contains(err.Error(), "cd") {
		t.Fatalf("a duplicate name is written as it is and redacted: %v", err)
	}
}

func TestStderrIsRedactedBeforeItIsCut(t *testing.T) {
	// A credential longer than a line's worth, echoed whole on stderr,
	// is matched whole: the buffer is redacted before the first line is
	// taken, and it holds more than a few kilobytes.
	cfg := fake(t)
	secret := strings.Repeat("k", 5000)
	credentials := filepath.Join(t.TempDir(), "credentials.json")
	if err := os.WriteFile(credentials, []byte(`{"TOKEN":"`+secret+`"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg.Credentials = credentials
	t.Setenv(fakemcp.EnvExitAtStart, "1")
	t.Setenv(fakemcp.EnvStderr, "refused: "+secret+"\n")
	_, err := Check(context.Background(), cfg)
	if err == nil || !strings.Contains(err.Error(), "refused: [redacted]") || strings.Contains(err.Error(), strings.Repeat("k", 64)) {
		t.Fatalf("redacted whole: %.120v", err)
	}
}

func TestATruncatedDiagnosticDoesNotEndWithTheStartOfACredential(t *testing.T) {
	// The server writes more than the buffer holds, and a credential
	// begins just before the cut: what remains of it is cut off too.
	cfg := fake(t)
	secret := strings.Repeat("k", 70000) // longer than the buffer holds
	credentials := filepath.Join(t.TempDir(), "credentials.json")
	if err := os.WriteFile(credentials, []byte(`{"TOKEN":"`+secret+`"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg.Credentials = credentials
	text := filepath.Join(t.TempDir(), "stderr.txt")
	if err := os.WriteFile(text, []byte("refused: "+secret+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv(fakemcp.EnvStderrFile, text)
	t.Setenv(fakemcp.EnvExitAtStart, "1")
	_, err := Check(context.Background(), cfg)
	if err == nil || !strings.Contains(err.Error(), "initialize: refused: ") || strings.Contains(err.Error(), "kkkkkkkk") {
		t.Fatalf("the start of the credential is cut off: %.120v", err)
	}
}

func TestCredentialsAreHeldToWhatAnEnvironmentCarries(t *testing.T) {
	for _, tc := range []struct{ text, want string }{
		{`{"TOKEN":"hunter2\r"}`, "has a value an environment cannot carry"},
		{`{"TOKEN":"a\nb"}`, "has a value an environment cannot carry"},
		{`{"#TOKEN":"x"}`, "is not an environment variable name"},
		{`{" TOKEN":"x"}`, "is not an environment variable name"},
		{`{"TO KEN":"x"}`, "is not an environment variable name"},
		{`{"1TOKEN":"x"}`, "is not an environment variable name"},
		{`{"TO=KEN":"x"}`, "is not an environment variable name"},
		{`{"TOKEN":null}`, "is not a string"},
		{`{"TOKEN":1}`, "is not a string"},
		{`{"TOKEN":["x"]}`, "is not a string"},
		{`null`, "is not a JSON object of strings"},
		{`[]`, "is not a JSON object of strings"},
		{`"x"`, "is not a JSON object of strings"},
		{`{"a":"1","\u0061":"2"}`, "credentials file has a member name twice"},
		{`{"TOKEN":"hunter2","hunter2":"x","hunter2":"y"}`, "credentials file has a member name twice"},
		{`{"a":"\xff"}`, "credentials file is not JSON"},
	} {
		t.Run(tc.text, func(t *testing.T) {
			cfg := fake(t)
			credentials := filepath.Join(t.TempDir(), "credentials.json")
			if err := os.WriteFile(credentials, []byte(tc.text), 0o600); err != nil {
				t.Fatal(err)
			}
			cfg.Credentials = credentials
			if _, err := Check(context.Background(), cfg); err == nil || !strings.Contains(err.Error(), tc.want) || strings.Contains(err.Error(), "hunter2") {
				t.Fatalf("want %q, naming nothing of the file: %v", tc.want, err)
			}
		})
	}
	cfg := fake(t)
	big := filepath.Join(t.TempDir(), "credentials.json")
	if err := os.WriteFile(big, []byte(`{"TOKEN":"`+strings.Repeat("k", 1<<20)+`"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg.Credentials = big
	if _, err := Check(context.Background(), cfg); err == nil || !strings.Contains(err.Error(), "credentials file exceeds 1 MiB") {
		t.Fatalf("bounded: %v", err)
	}
}

func TestAWholeCredentialWhoseEndRepeatsItsStartIsRedactedWhole(t *testing.T) {
	cfg := fake(t)
	secret := "TOPSECRET" + strings.Repeat("x", 64<<10-9-18) + "TOPSECRET"
	credentials := filepath.Join(t.TempDir(), "credentials.json")
	if err := os.WriteFile(credentials, []byte(`{"TOKEN":"`+secret+`"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg.Credentials = credentials
	text := filepath.Join(t.TempDir(), "stderr.txt")
	// Exactly the buffer's worth, and the newline overflows it.
	if err := os.WriteFile(text, []byte("refused: "+secret+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv(fakemcp.EnvStderrFile, text)
	t.Setenv(fakemcp.EnvExitAtStart, "1")
	_, err := Check(context.Background(), cfg)
	if err == nil || !strings.HasSuffix(err.Error(), "refused: [redacted]") {
		t.Fatalf("whole before prefix: %.120v", err)
	}
}

func TestAValueUnderARepeatedNestedNameIsASecret(t *testing.T) {
	cfg := fake(t)
	credentials := filepath.Join(t.TempDir(), "credentials.json")
	if err := os.WriteFile(credentials, []byte(`{"BLOB":"{\"token\":\"first-secret\",\"token\":\"second-secret\"}"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg.Credentials = credentials
	t.Setenv(fakemcp.EnvStderr, "rejected first-secret and second-secret\n")
	t.Setenv(fakemcp.EnvExitAtStart, "1")
	_, err := Check(context.Background(), cfg)
	if err == nil || !strings.Contains(err.Error(), "rejected [redacted] and [redacted]") {
		t.Fatalf("both values are secrets: %v", err)
	}
}

func TestACredentialAnotherOneBeginsInsideIsRedactedWhole(t *testing.T) {
	cfg := fake(t)
	credentials := filepath.Join(t.TempDir(), "credentials.json")
	if err := os.WriteFile(credentials, []byte(`{"USER":"alice","PASSWORD":"ice-super-secret"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg.Credentials = credentials
	t.Setenv(fakemcp.EnvStderr, "rejected alice-super-secret\n")
	t.Setenv(fakemcp.EnvExitAtStart, "1")
	_, err := Check(context.Background(), cfg)
	if err == nil || !strings.HasSuffix(err.Error(), "rejected [redacted]") {
		t.Fatalf("covered together: %v", err)
	}
}

func TestCheckProbesThePlatform(t *testing.T) {
	cfg := fake(t)
	cfg.Tools = []string{"query"}
	cfg.Probe = "query"
	out, err := Check(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(out), `"probe":{"tool":"query","answered":true}`) {
		t.Fatalf("the report says the probe answered: %s", out)
	}
	if got := methods(trace(t)); strings.Join(got, " ") != "initialize notifications/initialized tools/list tools/call" {
		t.Fatalf("the probe is one call: %v", got)
	}
	// A probe the server answers with an error is a platform not reached.
	result := filepath.Join(t.TempDir(), "result.json")
	if err := os.WriteFile(result, []byte(`{"content":[{"type":"text","text":"connection refused for app"}],"isError":true}`), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv(fakemcp.EnvResult, result)
	_, err = Check(context.Background(), cfg)
	if err == nil || !strings.Contains(err.Error(), `probe "query": the tool reported an error: connection refused for [redacted]`) {
		t.Fatalf("an error answer fails the check, redacted: %v", err)
	}
	// A server that catches its own failure answers ordinary text, isError
	// false; the binding names what such an answer begins with.
	if err := os.WriteFile(result, []byte(`{"content":[{"type":"text","text":"Error: connection to warehouse.internal refused for app"}]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Check(context.Background(), cfg); err != nil {
		t.Fatalf("without a failure text named, ordinary text is an answer: %v", err)
	}
	cfg.ProbeFailure = "Error:"
	_, err = Check(context.Background(), cfg)
	if err == nil || !strings.Contains(err.Error(), `probe "query": the platform was not reached: Error: connection to warehouse.internal refused for [redacted]`) {
		t.Fatalf("the named failure text fails the check, redacted: %v", err)
	}
	cfg.ProbeFailure = ""
	t.Setenv(fakemcp.EnvResult, "")
	cfg.Probe = "drop_table"
	if _, err := Check(context.Background(), cfg); err == nil || !strings.Contains(err.Error(), `probe "drop_table" is not one this source may call`) {
		t.Fatalf("a probe outside the allowed tools: %v", err)
	}
	cfg.Tools = nil
	if _, err := Check(context.Background(), cfg); err == nil || !strings.Contains(err.Error(), `probe "drop_table" is not one the server offers`) {
		t.Fatalf("a probe the server lacks: %v", err)
	}
	// Without a probe, nothing is called.
	cfg.Probe = ""
	if _, err := Check(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	// Across the runs above, only the four with an offered probe called
	// anything.
	if got := strings.Join(methods(trace(t)), " "); strings.Count(got, "tools/call") != 4 {
		t.Fatalf("a call only for an offered probe: %v", got)
	}
}

func TestAProbeAnswerIsReadByExactMembers(t *testing.T) {
	cfg := fake(t)
	cfg.Tools = []string{"query"}
	cfg.Probe = "query"
	cfg.ProbeFailure = "Error:"
	result := filepath.Join(t.TempDir(), "result.json")
	t.Setenv(fakemcp.EnvResult, result)
	// A "Text" beside "text" would make struct decoding fail and the
	// item be passed over; read exactly, the item says Error:.
	if err := os.WriteFile(result, []byte(`{"content":[{"type":"text","text":"Error: refused","Text":0}]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Check(context.Background(), cfg); err == nil || !strings.Contains(err.Error(), `probe "query": the platform was not reached: Error: refused`) {
		t.Fatalf("the failure text is seen through an extra member: %v", err)
	}
	// A text item whose text is not a string -- a number, null, a number
	// the canonical form would carry as a string -- fails the check and the
	// acquisition rather than being passed over or filled in.
	for _, text := range []string{"0", "null", "0.5", "[]"} {
		if err := os.WriteFile(result, []byte(`{"content":[{"type":"text","text":`+text+`}]}`), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := Check(context.Background(), cfg); err == nil || !strings.Contains(err.Error(), `probe "query": tools/call: a text item's text is not a string`) {
			t.Fatalf("text %s: a text item that is not a string fails the check: %v", text, err)
		}
		if _, err := Acquire(context.Background(), cfg, Request{Tool: "query", Arguments: json.RawMessage(`{}`)}); err == nil || !strings.Contains(err.Error(), "a text item's text is not a string") {
			t.Fatalf("text %s: and the acquisition: %v", text, err)
		}
	}
	// The prefix is matched as written: a leading space on either side
	// counts.
	cfg.ProbeFailure = " Error:"
	if err := os.WriteFile(result, []byte(`{"content":[{"type":"text","text":" Error: refused"}]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Check(context.Background(), cfg); err == nil || !strings.Contains(err.Error(), "the platform was not reached:  Error: refused") {
		t.Fatalf("matched as written: %v", err)
	}
	if err := os.WriteFile(result, []byte(`{"content":[{"type":"text","text":"Error: refused"}]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Check(context.Background(), cfg); err != nil {
		t.Fatalf("an answer without the space does not begin with the prefix: %v", err)
	}
}

// An executor asks for a target's error to be enveloped: with ErrorResults
// the result that reports an error is the result of the call, content and
// flag intact; without it, the failure it always was.
func TestErrorResultsAreEnvelopedOnlyWhenAsked(t *testing.T) {
	raw := json.RawMessage(`{"content":[{"type":"text","text":"permission denied"}],"isError":true}`)
	if _, err := parseToolResult(raw, false); err == nil || !strings.Contains(err.Error(), "the tool reported an error: permission denied") {
		t.Fatalf("a source's error result fails the acquisition: %v", err)
	}
	result, err := parseToolResult(raw, true)
	if err != nil {
		t.Fatalf("an executor's error result is the result: %v", err)
	}
	if !strings.Contains(string(result), `"isError":true`) || !strings.Contains(string(result), "permission denied") {
		t.Fatalf("the error result is carried whole: %s", result)
	}
	if _, err := parseToolResult(json.RawMessage(`{"content":[],"isError":"true"}`), true); err == nil || !strings.Contains(err.Error(), "isError is not a boolean") {
		t.Fatalf("a flag that is not a boolean is refused whatever was asked: %v", err)
	}
}
