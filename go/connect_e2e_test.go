package main

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// From a request to a written entry: connect runs the real adapter-airbyte
// and adapter-mcp binaries against a stand-in runtime built here -- which
// answers the connector's check and speaks as the MCP server the image
// would be -- and writes the platform only after both reported. The
// platform's user is stripped before the adapters are started, since this
// test does not run as a user that can switch, and the filesystem the
// isolation refusals read is stood in, as in the refusal tests; what this
// proves is the pipeline from the command line to the file, end to end.
func TestConnectRunsBothAdaptersEndToEnd(t *testing.T) {
	goTool, err := exec.LookPath("go")
	if err != nil {
		t.Skip("no go toolchain on PATH")
	}
	dir := t.TempDir()
	exe := ""
	if runtime.GOOS == "windows" {
		exe = ".exe"
	}
	bin := filepath.Join(dir, "bin")
	if err := os.MkdirAll(bin, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"adapter-mcp", "adapter-airbyte"} {
		build := exec.Command(goTool, "build", "-buildvcs=false", "-o", filepath.Join(bin, name+exe), "./cmd/"+name)
		build.Dir = filepath.Join("..", "adapters")
		build.Env = append(os.Environ(), "GOWORK=off")
		if out, err := build.CombinedOutput(); err != nil {
			t.Fatalf("building %s: %v\n%s", name, err, out)
		}
	}
	fakeDir := filepath.Join(dir, "fake")
	if err := os.MkdirAll(fakeDir, 0o700); err != nil {
		t.Fatal(err)
	}
	// The stand-in runtime: for the connector image, `check` answers with
	// the status CHECK_STATUS names (SUCCEEDED when unset) after reading
	// the mounted configuration; for the server image, it speaks JSON-RPC
	// with the tools the server offers; every run's command line is
	// appended to the trace named by FAKE_TRACE.
	fakeSource := `package main

import (
	"bufio"
	"encoding/json"
	"os"
	"strings"
)

func main() {
	if len(os.Args) < 2 {
		os.Exit(2)
	}
	switch os.Args[1] {
	case "kill":
		os.Exit(0)
	case "inspect":
		os.Stderr.WriteString("Error: No such object: " + os.Args[2] + "\n")
		os.Exit(1)
	}
	if trace := os.Getenv("FAKE_TRACE"); trace != "" {
		f, _ := os.OpenFile(trace, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
		f.WriteString(strings.Join(os.Args[1:], " ") + "\n")
		f.Close()
	}
	mount := ""
	for i, a := range os.Args {
		if a == "-v" && i+1 < len(os.Args) {
			mount = strings.TrimSuffix(os.Args[i+1], ":/secrets:ro")
		}
	}
	line := strings.Join(os.Args, " ")
	if strings.Contains(line, "source-postgres") {
		// The connector's configuration: the fields its spec names, with
		// the port a number, as the real connector reads it.
		config, _ := os.ReadFile(mount + "/config.json")
		var spec struct {
			Host     string ` + "`json:\"host\"`" + `
			Port     int    ` + "`json:\"port\"`" + `
			Database string ` + "`json:\"database\"`" + `
			Username string ` + "`json:\"username\"`" + `
			Password string ` + "`json:\"password\"`" + `
		}
		if json.Unmarshal(config, &spec) != nil || spec.Host != "warehouse.internal" || spec.Port != 5432 || spec.Database != "decisions" || spec.Username != "app" || spec.Password != "hunter2" {
			os.Stderr.WriteString("the connector's configuration is not the connector's\n")
			os.Exit(1)
		}
		status := os.Getenv("CHECK_STATUS")
		if status == "" {
			status = "SUCCEEDED"
		}
		os.Stdout.WriteString("{\"type\":\"CONNECTION_STATUS\",\"connectionStatus\":{\"status\":\"" + status + "\",\"message\":\"checked with hunter2\"}}\n")
		return
	}
	env, _ := os.ReadFile(mount + "/env")
	if !strings.Contains(string(env), "DATABASE_URI=postgresql://app:hunter2@") {
		os.Stderr.WriteString("no connection string in the env file\n")
		os.Exit(1)
	}
	in := bufio.NewScanner(os.Stdin)
	for in.Scan() {
		var m struct {
			ID     json.RawMessage ` + "`json:\"id\"`" + `
			Method string          ` + "`json:\"method\"`" + `
		}
		if json.Unmarshal(in.Bytes(), &m) != nil || len(m.ID) == 0 {
			continue
		}
		var result any
		switch m.Method {
		case "initialize":
			result = map[string]any{"protocolVersion": "2025-06-18", "capabilities": map[string]any{"tools": map[string]any{}}, "serverInfo": map[string]any{"name": "standin", "version": "0.1"}}
		case "tools/list":
			result = map[string]any{"tools": []any{map[string]any{"name": "query", "inputSchema": map[string]any{"type": "object"}}, map[string]any{"name": "explain", "inputSchema": map[string]any{"type": "object"}}}}
		case "tools/call":
			// The probe: a server that could not reach its database says
			// so here, whatever the handshake said.
			if os.Getenv("PROBE_FAILS") == "1" {
				// As the pinned Postgres server does: the failure caught
				// and answered as ordinary text, isError false.
				result = map[string]any{"content": []any{map[string]any{"type": "text", "text": "Error: connection refused"}}}
			} else {
				result = map[string]any{"content": []any{map[string]any{"type": "text", "text": "public"}}}
			}
		default:
			continue
		}
		b, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": m.ID, "result": result})
		os.Stdout.Write(append(b, '\n'))
	}
}
`
	if err := os.WriteFile(filepath.Join(fakeDir, "main.go"), []byte(fakeSource), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(fakeDir, "go.mod"), []byte("module fake\n\ngo 1.26\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	fake := filepath.Join(dir, "fake-runtime"+exe)
	build := exec.Command(goTool, "build", "-buildvcs=false", "-o", fake, ".")
	build.Dir = fakeDir
	build.Env = append(os.Environ(), "GOWORK=off")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("building the stand-in runtime: %v\n%s", err, out)
	}
	// Two credentials files, one per operation, each in the form its
	// adapter reads: the connector's configuration, and the server's
	// environment.
	connector := filepath.Join(dir, "warehouse-connector.json")
	if err := os.WriteFile(connector, []byte(`{"host":"warehouse.internal","port":5432,"database":"decisions","username":"app","password":"hunter2","ssl_mode":{"mode":"require"}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	credentials := filepath.Join(dir, "warehouse-env.json")
	if err := os.WriteFile(credentials, []byte(`{"DATABASE_URI":"postgresql://app:hunter2@warehouse.internal:5432/decisions"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	catalog := catalogWith(t, map[string]string{"postgres": restrictedBinding})
	// The seed sits in the signer's own directory, the credentials in one
	// nobody but root could replace them in.
	signerDir := filepath.Join(dir, "signer")
	if err := os.MkdirAll(signerDir, 0o700); err != nil {
		t.Fatal(err)
	}
	seed := filepath.Join(signerDir, "gateway.seed")
	if err := os.WriteFile(seed, testSeed, 0o600); err != nil {
		t.Fatal(err)
	}
	config := filepath.Join(dir, "engine.json")
	text := `{"engineVersion":"1","authority":"gateway:test","seed":"` + escapePath(seed) + `","store":"` + abs(t, dir, "store") + `",` +
		`"registry":"` + abs(t, dir, "registry.jsonl") + `","decisionRecords":"` + abs(t, dir, "decisions") + `",` +
		`"listen":"127.0.0.1:0","catalog":"` + escapePath(catalog) + `","runtime":"` + escapePath(fake) + `","adapters":"` + escapePath(bin) + `",` +
		`"platforms":{}}`
	if err := os.WriteFile(config, []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
	trace := filepath.Join(dir, "runtime.trace")
	fs := goodFilesystem(seed, credentials, os.Geteuid(), 4242)
	fs[connector] = fileOwnership{uid: 4242, mode: 0o600}
	three := uint64(1<<capSetuid | 1<<capSetgid | 1<<capKill)
	host := engineHost{
		euid:         os.Geteuid(),
		sockets:      func(string) []string { return nil },
		capabilities: func() capabilitySets { return capabilitySets{known: true, effective: three, permitted: three} },
		fileOwner:    fs.owner,
		readLink:     readLinkStub,
		account:      stubAccounts(map[string]int{"engine-warehouse": 4242}),
	}
	asSelf := func(ctx context.Context, spec sourceSpec) ([]byte, error) {
		spec.user = ""
		return runCheck(ctx, spec)
	}
	req := connectRequest{config: config, platform: "warehouse", binding: "postgres", credentials: map[string]string{"history": connector, "live": credentials}, user: "engine-warehouse",
		endpoint: "warehouse.internal:5432", environment: []string{"FAKE_TRACE=" + trace}}
	out, err := connect(context.Background(), req, host, asSelf)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	if len(out.answers) != 2 || !strings.HasPrefix(out.answers[0], "warehouse/history: airbyte/source-postgres:3.8.5 ("+testImageDigest+") answered succeeded: checked with ") || strings.Contains(out.answers[0], "hunter2") ||
		out.answers[1] != "warehouse/live: crystaldba/postgres-mcp:0.3.0 ("+testImageDigest+"): server standin 0.1, protocol 2025-06-18, tools query, explain; query answered" {
		t.Fatalf("both adapters reported, the connector's message redacted: %q", out.answers)
	}
	traced, _ := os.ReadFile(trace)
	lines := strings.Split(strings.TrimSpace(string(traced)), "\n")
	if len(lines) != 2 || !strings.Contains(lines[0], "airbyte/source-postgres:3.8.5@"+testImageDigest+" check --config /secrets/config.json") ||
		!strings.HasSuffix(lines[1], "crystaldba/postgres-mcp:0.3.0@"+testImageDigest+" --access-mode=restricted") {
		t.Fatalf("the runtime ran the connector's check and the server with its arguments after the image:\n%s", traced)
	}
	cfg, bindings, err := loadEngineConfig(config, stubAccounts(map[string]int{"engine-warehouse": 4242}))
	if err != nil || len(cfg.platforms) != 1 || cfg.platforms[0].binding != "postgres@"+digestOf(restrictedBinding) {
		t.Fatalf("the written file is what serve reads: %v %+v", err, cfg.platforms)
	}
	if sources := deriveSources(cfg, bindings); len(sources) != 2 || !strings.HasSuffix(strings.Join(sources["warehouse/live"].argv, " "), " -- --access-mode=restricted") ||
		!strings.Contains(strings.Join(sources["warehouse/history"].argv, " "), "--credentials="+connector+" ") || !strings.Contains(strings.Join(sources["warehouse/live"].argv, " "), "--credentials="+credentials+" ") {
		t.Fatalf("serve derives both sources from the written entry: %v", sources)
	}
	// A platform that does not answer is not configured: replacing the
	// entry with one the connector answers FAILED to ends the connect
	// before the server is asked, and the file is left as it was.
	before, _ := os.ReadFile(config)
	os.Remove(trace)
	req.replace = true
	req.environment = append(req.environment, "CHECK_STATUS=FAILED")
	_, err = connect(context.Background(), req, host, asSelf)
	// The reason comes from the adapter's own failed report on stdout,
	// redacted by the adapter.
	if err == nil || !strings.Contains(err.Error(), "warehouse/history: the connector could not connect (FAILED): checked with ") || strings.Contains(err.Error(), "hunter2") {
		t.Fatalf("the connector's own answer ends the connect: %v", err)
	}
	traced, _ = os.ReadFile(trace)
	after, _ := os.ReadFile(config)
	if strings.Count(string(traced), "\n") != 1 || string(after) != string(before) {
		t.Fatalf("the server is not asked after the connector failed, and nothing is written:\n%s", traced)
	}
	// A server that answers the handshake but cannot reach its platform
	// is found out by the probe, and nothing is written.
	req.environment = []string{"FAKE_TRACE=" + trace, "PROBE_FAILS=1"}
	_, err = connect(context.Background(), req, host, asSelf)
	if err == nil || !strings.Contains(err.Error(), `warehouse/live: probe "query": the platform was not reached: Error: connection refused`) {
		t.Fatalf("the probe's error ends the connect: %v", err)
	}
	if after, _ := os.ReadFile(config); string(after) != string(before) {
		t.Fatal("nothing is written when the probe fails")
	}
}
