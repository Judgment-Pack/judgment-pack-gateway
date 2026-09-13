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
		fakemcp.EnvLinger, fakemcp.EnvNullError} {
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
	if joined[0] != "run" || joined[1] != "--rm" || !strings.Contains(line, " --env-file ") || !strings.Contains(line, " -i "+cfg.Image) ||
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
		mustFail(t, cfg, query("select 1"), `speaks protocol version "1999-01-01", which this client does not`)
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
		mustFail(t, cfg, query("select 1"), "the server ended before answering initialize: cannot bind: address in use")
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
		mustFail(t, cfg, query("select 1"), `tool "query": descriptor: duplicate member name "outputSchema"`)
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
		if err == nil || strings.Contains(err.Error(), "hunter2") || !strings.Contains(err.Error(), `duplicate member name "[redacted]"`) {
			t.Fatalf("a canonicalization diagnostic is redacted: %v", err)
		}
	})
	t.Run("credentials not an object of strings", func(t *testing.T) {
		cfg := fake(t)
		os.WriteFile(cfg.Credentials, []byte(`{"PORT":5432}`), 0o600)
		mustFail(t, cfg, query("select 1"), "not a JSON object of strings")
		os.WriteFile(cfg.Credentials, []byte(`{"KEY":"a\nb"}`), 0o600)
		mustFail(t, cfg, query("select 1"), `credentials member "KEY" cannot be carried`)
		os.WriteFile(cfg.Credentials, []byte(`{"A=B":"x"}`), 0o600)
		mustFail(t, cfg, query("select 1"), `credentials member "A=B" cannot be carried`)
	})
	t.Run("neither or both servers", func(t *testing.T) {
		cfg := fake(t)
		cfg.Command = nil
		mustFail(t, cfg, query("select 1"), "exactly one of --image and --command")
		cfg = image(fake(t))
		cfg.Command = []string{"x"}
		mustFail(t, cfg, query("select 1"), "exactly one of --image and --command")
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
