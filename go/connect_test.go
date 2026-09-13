package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"
)

// A binding whose live server takes its own arguments.
const restrictedBinding = `{
  "bindingVersion": "1",
  "platform": "postgres",
  "operations": {
    "history": {"shape": "airbyte", "image": "airbyte/source-postgres:3.8.5@` + testImageDigest + `", "licence": "ELv2"},
    "live": {"shape": "mcp", "server": {"image": "crystaldba/postgres-mcp:0.3.0@` + testImageDigest + `", "args": ["--access-mode=restricted"]}, "tools": ["query"], "probe": {"tool": "query", "failure": "Error:"}, "licence": "MIT"}
  }
}`

const airbyteReport = `{"check":{"status":"succeeded","adapter":{"name":"airbyte/source-postgres","version":"3.8.5","digest":"` + testImageDigest + `"},"message":"Connected"}}`
const mcpReport = `{"check":{"status":"succeeded","adapter":{"name":"crystaldba/postgres-mcp","version":"0.3.0","digest":"` + testImageDigest + `"},"server":{"name":"postgres-mcp","version":"0.3.0"},"protocolVersion":"2025-03-26","tools":["query","explain"]}}`

// connectFixture is a configuration before its first connect, a catalog,
// a stub host under which the platform's user holds private credentials,
// and a check that answers as the adapters would and records what it was
// asked.
type connectFixture struct {
	dir, config, catalog, seed, credentials string
	host                                    engineHost
	fs                                      ownership
	asked                                   []sourceSpec
	reports                                 map[string]string // by shape
	fail                                    map[string]string // by shape: an error instead
	groupless                               string            // a user whose groups cannot be read
}

func newConnectFixture(t *testing.T, bindingText string, platforms string) *connectFixture {
	t.Helper()
	f := &connectFixture{dir: t.TempDir(), reports: map[string]string{"airbyte": airbyteReport, "mcp": mcpReport}, fail: map[string]string{}}
	f.catalog = catalogWith(t, map[string]string{"postgres": bindingText})
	// Synthetic paths, rooted on the platform's volume so they are absolute
	// on Windows too; the stub filesystem is what holds them.
	root := filepath.VolumeName(f.dir) + string(filepath.Separator)
	// The seed is real, judged as serve judges it; the credentials are
	// synthetic, held by the stub filesystem.
	signer := filepath.Join(t.TempDir(), "signer")
	if err := os.MkdirAll(signer, 0o700); err != nil {
		t.Fatal(err)
	}
	f.seed = filepath.Join(signer, "gateway.seed")
	if err := os.WriteFile(f.seed, testSeed, 0o600); err != nil {
		t.Fatal(err)
	}
	f.credentials = filepath.Join(root, "run", "secrets", "warehouse")
	f.config = filepath.Join(f.dir, "engine.json")
	text := `{"engineVersion":"1","authority":"gateway:acme","seed":"` + escapePath(f.seed) + `","store":"` + abs(t, f.dir, "store") + `",` +
		`"registry":"` + abs(t, f.dir, "registry.jsonl") + `","decisionRecords":"` + abs(t, f.dir, "decisions") + `","listen":"127.0.0.1:0",` +
		`"catalog":"` + abs(t, f.catalog) + `","platforms":{` + platforms + `}}`
	if err := os.WriteFile(f.config, []byte(text), 0o640); err != nil {
		t.Fatal(err)
	}
	f.fs = goodFilesystem(f.seed, f.credentials, 1000, 1001)
	three := uint64(1<<capSetuid | 1<<capSetgid | 1<<capKill)
	f.host = engineHost{
		euid:         1000,
		sockets:      func(string) []string { return []string{filepath.Join(f.dir, "absent.sock")} },
		capabilities: func() capabilitySets { return capabilitySets{known: true, effective: three, permitted: three} },
		fileOwner:    func(path string) (fileOwnership, error) { return f.fs.owner(path) },
		readLink:     readLinkStub,
		account:      stubAccounts(stubUsers),
		switching:    stubSwitching(stubUsers, &f.groupless),
		executable: func() (exeFacts, error) {
			return exeFacts{path: "/usr/local/bin/gateway", mode: 0o700, capabilities: true}, nil
		},
	}
	return f
}

// stubSwitching judges sources as requireUserSwitching does, against
// stub accounts: a user the accounts do not hold, or the one named as
// groupless, is a credential that cannot be taken. Sources are judged in
// name order, so the refusal is the same every time.
func stubSwitching(users map[string]int, groupless *string) func(map[string]sourceSpec) error {
	return func(sources map[string]sourceSpec) error {
		var names []string
		for name := range sources {
			names = append(names, name)
		}
		sort.Strings(names)
		for _, name := range names {
			user := sources[name].user
			if user == "" {
				continue
			}
			if _, ok := users[user]; !ok {
				return fmt.Errorf("--source-user %s: user %s: unknown", name, user)
			}
			if groupless != nil && user == *groupless {
				return fmt.Errorf("--source-user %s: user %s: groups: lookup failed", name, user)
			}
		}
		return nil
	}
}

func escapePath(p string) string { return strings.ReplaceAll(p, `\`, `\\`) }

func (f *connectFixture) check(_ context.Context, spec sourceSpec) ([]byte, error) {
	f.asked = append(f.asked, spec)
	if msg, ok := f.fail[spec.shape]; ok {
		return nil, errors.New(msg)
	}
	return []byte(f.reports[spec.shape]), nil
}

func (f *connectFixture) request() connectRequest {
	return connectRequest{config: f.config, platform: "warehouse", binding: "postgres", credentials: map[string]string{"history": f.credentials, "live": f.credentials}, user: "engine-warehouse",
		endpoint: "warehouse.internal:5432", environment: []string{"DOCKER_HOST=unix:///run/user/1001/docker.sock"}, write: true}
}

func (f *connectFixture) fileText(t *testing.T) string {
	t.Helper()
	data, err := os.ReadFile(f.config)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func TestConnectWritesTheEntryAfterThePlatformAnswered(t *testing.T) {
	f := newConnectFixture(t, restrictedBinding, ``)
	before := f.fileText(t)
	out, err := connect(context.Background(), f.request(), f.host, f.check)
	if err != nil {
		t.Fatal(err)
	}
	// Both of the platform's operations were asked, history first, as the
	// platform's user, in the environment serve would give them.
	if len(f.asked) != 2 || f.asked[0].shape != "airbyte" || f.asked[1].shape != "mcp" || f.asked[0].user != "engine-warehouse" || f.asked[1].user != "engine-warehouse" {
		t.Fatalf("both operations checked as the platform's user: %+v", f.asked)
	}
	if env := strings.Join(f.asked[1].env, " "); !strings.Contains(env, "HOME=") || !strings.Contains(env, "DOCKER_HOST=unix:///run/user/1001/docker.sock") {
		t.Fatalf("the check runs in the derived environment: %v", f.asked[1].env)
	}
	if argv := strings.Join(f.asked[1].argv, " "); !strings.HasSuffix(argv, " --endpoint=warehouse.internal:5432 -- --access-mode=restricted") || !strings.Contains(argv, "--credentials="+f.credentials+" ") {
		t.Fatalf("the derived command line carries the binding's server arguments after --: %s", argv)
	}
	if strings.Join(f.asked[1].check, " ") != "--probe=query --probe-failure=Error:" || len(f.asked[0].check) != 0 {
		t.Fatalf("the check carries the binding's probe: %q %q", f.asked[0].check, f.asked[1].check)
	}
	if len(out.answers) != 2 || out.answers[0] != "warehouse/history: airbyte/source-postgres:3.8.5 ("+testImageDigest+") answered succeeded: Connected" ||
		out.answers[1] != "warehouse/live: crystaldba/postgres-mcp:0.3.0 ("+testImageDigest+"): server postgres-mcp 0.3.0, protocol 2025-03-26, tools query, explain" {
		t.Fatalf("what the platform answered, one line per operation: %q", out.answers)
	}
	if out.written != f.config || len(out.statements) != 0 {
		t.Fatalf("written %q, statements %v", out.written, out.statements)
	}
	after := f.fileText(t)
	if after == before || !strings.HasPrefix(after, "{\n  \"authority\": \"gateway:acme\",\n") || !strings.HasSuffix(after, "}\n") {
		t.Fatalf("the file is rewritten in the engine's form: %s", after)
	}
	// What was written is what serve reads: the entry as requested, the
	// binding pinned to the catalog file's digest, and the sources derived
	// from it carry the server's arguments.
	cfg, bindings, err := loadEngineConfig(f.config, stubAccounts(stubUsers))
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.platforms) != 1 {
		t.Fatalf("one platform: %+v", cfg.platforms)
	}
	p := cfg.platforms[0]
	if p.name != "warehouse" || p.binding != "postgres@"+digestOf(restrictedBinding) || p.credentials["history"] != f.credentials || p.credentials["live"] != f.credentials || p.user != "engine-warehouse" ||
		p.endpoint != "warehouse.internal:5432" || strings.Join(p.environment, ",") != "DOCKER_HOST=unix:///run/user/1001/docker.sock" || !p.write {
		t.Fatalf("the entry as requested: %+v", p)
	}
	live := deriveSources(cfg, bindings)["warehouse/live"]
	if argv := strings.Join(live.argv, " "); !strings.HasSuffix(argv, " -- --access-mode=restricted") {
		t.Fatalf("serve derives the server's arguments from the written entry: %s", argv)
	}
	// Beside the file: its lock where a lock is taken (Unix), and nothing
	// else -- no temporary file.
	var names []string
	entries, _ := os.ReadDir(f.dir)
	for _, e := range entries {
		names = append(names, e.Name())
	}
	want := "engine.json,engine.json.lock"
	if runtime.GOOS == "windows" {
		want = "engine.json"
	}
	if strings.Join(names, ",") != want {
		t.Fatalf("beside the file: %v, want %s", names, want)
	}
	if info, _ := os.Stat(f.config); runtime.GOOS != "windows" && info.Mode().Perm() != 0o640 {
		t.Fatalf("the file keeps its mode: %v", info.Mode())
	}
	// The other members survive as written, in canonical order.
	if !strings.Contains(after, "\n  \"catalog\": ") || !strings.Contains(after, "\n  \"engineVersion\": \"1\",\n") || !strings.Contains(after, "\n  \"platforms\": {\n    \"warehouse\": {\n      \"binding\": \"postgres@") || !strings.Contains(after, "\n      \"credentials\": {\n        \"history\": {\n          \"file\": ") {
		t.Fatalf("members in canonical order: %s", after)
	}
}

func TestConnectRefusesToOverwriteUnlessTold(t *testing.T) {
	f := newConnectFixture(t, restrictedBinding, ``)
	if _, err := connect(context.Background(), f.request(), f.host, f.check); err != nil {
		t.Fatal(err)
	}
	before := f.fileText(t)
	f.asked = nil
	_, err := connect(context.Background(), f.request(), f.host, f.check)
	if err == nil || !strings.Contains(err.Error(), "platform warehouse is already configured") || !strings.Contains(err.Error(), "--replace") {
		t.Fatalf("an existing entry is not overwritten: %v", err)
	}
	if len(f.asked) != 0 || f.fileText(t) != before {
		t.Fatal("nothing is asked and nothing is written for a refused connect")
	}
	// Replacing: the new entry is judged in the old one's place, so its
	// user does not collide with the entry it replaces.
	req := f.request()
	req.replace = true
	req.endpoint = "warehouse-replica.internal:5432"
	req.write = false
	if _, err := connect(context.Background(), req, f.host, f.check); err != nil {
		t.Fatalf("--replace: %v", err)
	}
	cfg, _, err := loadEngineConfig(f.config, stubAccounts(stubUsers))
	if err != nil || len(cfg.platforms) != 1 || cfg.platforms[0].endpoint != "warehouse-replica.internal:5432" || cfg.platforms[0].write {
		t.Fatalf("the entry is replaced: %v %+v", err, cfg.platforms)
	}
}

func TestConnectRefusesBeforeAnyCheck(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(f *connectFixture, req *connectRequest)
		want   string
	}{
		{"a binding not in the catalog", func(f *connectFixture, req *connectRequest) { req.binding = "jira" }, "binding jira is not in the catalog"},
		{"a binding name that is a path", func(f *connectFixture, req *connectRequest) { req.binding = "../postgres" }, `binding "../postgres" is not a catalog name`},
		{"a platform name with a separator", func(f *connectFixture, req *connectRequest) { req.platform = "ware/house" }, "platform name"},
		{"a relative credentials path", func(f *connectFixture, req *connectRequest) {
			req.credentials = map[string]string{"history": "secrets/warehouse", "live": f.credentials}
		}, "credentials-file history must be an absolute path"},
		{"credentials for an operation the binding lacks", func(f *connectFixture, req *connectRequest) {
			req.credentials["write"] = f.credentials
		}, "credentials name a write file but the binding offers no write"},
		{"credentials missing an operation the binding offers", func(f *connectFixture, req *connectRequest) {
			delete(req.credentials, "live")
		}, "the binding offers live but credentials name no live file"},
		{"a credentials path that is not UTF-8", func(f *connectFixture, req *connectRequest) {
			req.credentials["live"] = f.credentials + "\xff"
		}, "not valid UTF-8"},
		{"an endpoint that is not UTF-8", func(f *connectFixture, req *connectRequest) { req.endpoint = "h\xff" }, "not valid UTF-8"},
		{"an environment that sets HOME", func(f *connectFixture, req *connectRequest) { req.environment = []string{"HOME=/tmp"} }, "environment may not set HOME"},
		{"an environment without a value", func(f *connectFixture, req *connectRequest) { req.environment = []string{"DEBUG"} }, "is not KEY=VALUE"},
		{"an unknown user", func(f *connectFixture, req *connectRequest) { req.user = "nobody-here" }, "platform warehouse: file does not exist"},
		{"credentials owned by another user", func(f *connectFixture, req *connectRequest) {
			f.fs[f.credentials] = fileOwnership{uid: 1002, mode: 0o600}
		}, "must be owned by engine-warehouse"},
		{"credentials readable by others", func(f *connectFixture, req *connectRequest) {
			f.fs[f.credentials] = fileOwnership{uid: 1001, mode: 0o644}
		}, "readable"},
		{"the signer's own user", func(f *connectFixture, req *connectRequest) {
			req.user = "engine-desk"
			f.host.euid = 1003
			f.fs = goodFilesystem(f.seed, f.credentials, 1003, 1003)
		}, "user engine-desk is the signer's own"},
		{"root as the platform's user", func(f *connectFixture, req *connectRequest) { req.user = "root" }, "user root is root"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newConnectFixture(t, restrictedBinding, ``)
			before := f.fileText(t)
			req := f.request()
			tc.change(f, &req)
			_, err := connect(context.Background(), req, f.host, f.check)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("want %q, got %v", tc.want, err)
			}
			if len(f.asked) != 0 || f.fileText(t) != before {
				t.Fatalf("nothing is asked and nothing is written: asked %d, changed %v", len(f.asked), f.fileText(t) != before)
			}
		})
	}
}

func TestConnectWritesNothingWhenAnOperationCannotAnswer(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(f *connectFixture)
		want   string
		asked  int
	}{
		{"the history check fails", func(f *connectFixture) { f.fail["airbyte"] = "the connector could not connect (FAILED): no route" }, "warehouse/history: the connector could not connect (FAILED): no route", 1},
		{"the live check fails", func(f *connectFixture) {
			f.fail["mcp"] = "tool \"query\" is allowed by the configuration but not offered"
		}, "warehouse/live: tool \"query\" is allowed", 2},
		{"a report that is not a check", func(f *connectFixture) { f.reports["airbyte"] = `{"acquisition":{}}` }, "warehouse/history: the adapter's report is not a check report", 1},
		{"a report without an adapter", func(f *connectFixture) { f.reports["mcp"] = `{"check":{"server":{"name":"x"}}}` }, "warehouse/live: the adapter's report is not a check report", 2},
		{"a history report that is not a success", func(f *connectFixture) {
			f.reports["airbyte"] = `{"check":{"adapter":{"name":"a","version":"1","digest":"` + testImageDigest + `"},"status":"failed","message":"x"}}`
		}, `warehouse/history: the adapter reported "failed", not a success`, 1},
		{"a live report without a protocol", func(f *connectFixture) {
			f.reports["mcp"] = `{"check":{"status":"succeeded","adapter":{"name":"a","version":"1","digest":"` + testImageDigest + `"},"tools":[]}}`
		}, "warehouse/live: the adapter's report names no protocol version", 2},
		{"a live report without a status", func(f *connectFixture) {
			f.reports["mcp"] = `{"check":{"adapter":{"name":"a","version":"1","digest":"` + testImageDigest + `"},"protocolVersion":"2025-06-18","tools":[]}}`
		}, `warehouse/live: the adapter reported "", not a success`, 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newConnectFixture(t, restrictedBinding, ``)
			before := f.fileText(t)
			tc.change(f)
			out, err := connect(context.Background(), f.request(), f.host, f.check)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("want %q, got %v", tc.want, err)
			}
			if len(f.asked) != tc.asked || f.fileText(t) != before || out.written != "" {
				t.Fatalf("the first operation that cannot answer ends the connect and nothing is written: asked %d, written %q, changed %v", len(f.asked), out.written, f.fileText(t) != before)
			}
		})
	}
}

func TestConnectFindsAStalePinAmongThePlatformsAlreadyConfigured(t *testing.T) {
	docs := filepath.Join(filepath.VolumeName(t.TempDir())+string(filepath.Separator), "run", "secrets", "docs")
	f := newConnectFixture(t, restrictedBinding, `"docs":{"binding":"postgres@`+digestOf(postgresBinding)+`","credentials":{"history":{"file":"`+escapePath(docs)+`"},"live":{"file":"`+escapePath(docs)+`"}},"user":"engine-docs"}`)
	_, err := connect(context.Background(), f.request(), f.host, f.check)
	if err == nil || !strings.Contains(err.Error(), "platform docs") || !strings.Contains(err.Error(), "does not digest to the pinned") {
		t.Fatalf("a pin the catalog no longer digests to is found at connect, not at the next start: %v", err)
	}
}

// The users serve switches to are judged for every platform, not the
// one being written: an existing account whose groups can no longer be
// read is a start that refuses, so the connect refuses first, before any
// adapter is run.
func TestConnectHoldsEveryPlatformToTheSwitchingServeRequires(t *testing.T) {
	docs := filepath.Join(filepath.VolumeName(t.TempDir())+string(filepath.Separator), "run", "secrets", "docs")
	f := newConnectFixture(t, restrictedBinding, `"docs":{"binding":"postgres@`+digestOf(restrictedBinding)+`","credentials":{"history":{"file":"`+escapePath(docs)+`"},"live":{"file":"`+escapePath(docs)+`"}},"user":"engine-docs"}`)
	f.fs[docs] = fileOwnership{uid: 1002, mode: 0o600}
	f.groupless = "engine-docs"
	before := f.fileText(t)
	_, err := connect(context.Background(), f.request(), f.host, f.check)
	if err == nil || err.Error() != "--source-user docs/history: user engine-docs: groups: lookup failed" || len(f.asked) != 0 || f.fileText(t) != before {
		t.Fatalf("an existing platform's user this process cannot switch to: %v (asked %d)", err, len(f.asked))
	}
	f.groupless = ""
	if _, err := connect(context.Background(), f.request(), f.host, f.check); err != nil || len(f.asked) != 2 {
		t.Fatalf("with every user's credential to be had: %v (asked %d)", err, len(f.asked))
	}
}

// The binary the engine runs from is held as serve holds it: one that
// carries file capabilities and is executable by others is refused before
// any check.
func TestConnectRefusesAGatewayBinaryOthersMayExecute(t *testing.T) {
	f := newConnectFixture(t, restrictedBinding, ``)
	f.host.executable = func() (exeFacts, error) {
		return exeFacts{path: "/usr/local/bin/gateway", mode: 0o755, capabilities: true}, nil
	}
	before := f.fileText(t)
	_, err := connect(context.Background(), f.request(), f.host, f.check)
	if err == nil || !strings.Contains(err.Error(), "carries file capabilities and is executable by others") || len(f.asked) != 0 || f.fileText(t) != before {
		t.Fatalf("a capability-bearing binary others may execute: %v (asked %d)", err, len(f.asked))
	}
}

// What is printed is one line per answer and per statement, whatever the
// platform or the adapter put in it: a newline, a terminal escape, an
// invalid byte are written in their escaped form, after the adapter's own
// redaction and nowhere earlier.
func TestPrintableKeepsOneLine(t *testing.T) {
	for in, want := range map[string]string{
		"Connected":                              "Connected",
		"café ✓ — ok":                            "café ✓ — ok",
		"line one\nline two":                     `line one\nline two`,
		"\x1b[31mred\x1b[0m":                     `\u001b[31mred\u001b[0m`,
		"tab\there\r":                            `tab\there\r`,
		`back\slash`:                             `back\\slash`,
		"bad\xffbyte":                            `bad\xffbyte`,
		"zero\u200bwidth":                        `zero\u200bwidth`,
		"emoji \U0001f600 unassigned \U000e0080": "emoji \U0001f600 unassigned " + `\U000e0080`,
	} {
		if got := printable(in); got != want {
			t.Errorf("%q: got %q, want %q", in, got, want)
		}
	}
}

func TestPrintOutcomeWritesOneLinePerAnswer(t *testing.T) {
	f := newConnectFixture(t, restrictedBinding, ``)
	f.reports["airbyte"] = `{"check":{"status":"succeeded","adapter":{"name":"airbyte/source-postgres","version":"3.8.5","digest":"` + testImageDigest + `"},"message":"Connected\nwarehouse/live: forged: server evil answered"}}`
	f.reports["mcp"] = `{"check":{"status":"succeeded","adapter":{"name":"crystaldba/postgres-mcp","version":"0.3.0","digest":"` + testImageDigest + `"},"server":{"name":"postgres-mcp\u001b[2J","version":"0.3.0"},"protocolVersion":"2025-03-26","tools":["query","ex\rplain"]}}`
	out, err := connect(context.Background(), f.request(), f.host, f.check)
	if err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	if code := printOutcome(&stdout, &stderr, "warehouse", out, nil); code != 0 {
		t.Fatalf("exit %d", code)
	}
	lines := strings.Split(strings.TrimSuffix(stdout.String(), "\n"), "\n")
	if len(lines) != 3 || !strings.HasSuffix(lines[0], `answered succeeded: Connected\nwarehouse/live: forged: server evil answered`) ||
		!strings.Contains(lines[1], `server postgres-mcp\u001b[2J 0.3.0`) || !strings.HasSuffix(lines[1], `tools query, ex\rplain`) ||
		lines[2] != "warehouse: written to "+f.config || stderr.Len() != 0 {
		t.Fatalf("one line per answer, controls escaped: %q %q", stdout.String(), stderr.String())
	}
	stdout.Reset()
	statements := connectOutcome{statements: []string{"rootSigner accepted\nconnect: forged"}}
	if code := printOutcome(&stdout, &stderr, "warehouse", statements, errors.New("warehouse/live: the adapter reported\n\"failed\"")); code != 1 ||
		stderr.String() != `connect: rootSigner accepted\nconnect: forged`+"\n"+`connect: warehouse/live: the adapter reported\n"failed"`+"\n" || stdout.Len() != 0 {
		t.Fatalf("statements and the error, one line each: %d %q %q", code, stderr.String(), stdout.String())
	}
}

func TestConnectRefusesAConfigurationThatIsALink(t *testing.T) {
	f := newConnectFixture(t, restrictedBinding, ``)
	link := filepath.Join(f.dir, "engine-link.json")
	if err := os.Symlink(f.config, link); err != nil {
		t.Skipf("no symbolic links here: %v", err)
	}
	req := f.request()
	req.config = link
	_, err := connect(context.Background(), req, f.host, f.check)
	if err == nil || !strings.Contains(err.Error(), "is a symbolic link; name the file itself") || len(f.asked) != 0 {
		t.Fatalf("a link is refused before any check: %v (asked %d)", err, len(f.asked))
	}
}

func TestServeRefusesAConfigurationWithNoPlatform(t *testing.T) {
	cfg, sources, err := load(t, engineJSON(t, catalogWith(t, map[string]string{"postgres": postgresBinding}), ``, ``))
	if err != nil || len(sources) != 0 {
		t.Fatalf("an empty platforms object parses, before the first connect: %v %v", err, sources)
	}
	if _, err := engineRefusals(ptr(cfg), engineHost{}); err == nil || !strings.Contains(err.Error(), "names no platform") {
		t.Fatalf("serving it is refused: %v", err)
	}
}

func TestParseConnectArgs(t *testing.T) {
	want := connectRequest{config: "e.json", platform: "warehouse", binding: "postgres", user: "engine-warehouse", endpoint: "h:1", environment: []string{"A=1", "B=2"}, write: true, replace: true}
	for _, args := range [][]string{
		{"warehouse", "--config", "e.json", "--binding", "postgres", "--credentials-file", "history=/run/secrets/w", "--credentials-file", "live=/run/secrets/e", "--user", "engine-warehouse", "--endpoint", "h:1", "--environment", "A=1", "--environment", "B=2", "--write", "--replace"},
		{"--config", "e.json", "--binding", "postgres", "--credentials-file", "history=/run/secrets/w", "--credentials-file", "live=/run/secrets/e", "--user", "engine-warehouse", "--endpoint", "h:1", "--environment", "A=1", "--environment", "B=2", "--write", "--replace", "warehouse"},
		// The documented form: the platform among the flags.
		{"--config", "e.json", "warehouse", "--binding", "postgres", "--credentials-file", "history=/run/secrets/w", "--credentials-file", "live=/run/secrets/e", "--user", "engine-warehouse", "--endpoint", "h:1", "--environment", "A=1", "--environment", "B=2", "--write", "--replace"},
	} {
		got, msg, ok := parseConnectArgs(args)
		if !ok || got.config != want.config || got.platform != want.platform || got.binding != want.binding || got.credentials["history"] != "/run/secrets/w" || got.credentials["live"] != "/run/secrets/e" || len(got.credentials) != 2 || got.user != want.user ||
			got.endpoint != want.endpoint || strings.Join(got.environment, ",") != "A=1,B=2" || !got.write || !got.replace {
			t.Fatalf("%v: %+v %q", args, got, msg)
		}
	}
	for _, args := range [][]string{
		{},
		{"warehouse"},
		{"warehouse", "--config", "e.json", "--binding", "postgres", "--credentials-file", "live=/x"},
		{"--config", "e.json", "--binding", "postgres", "--credentials-file", "live=/x", "--user", "u"},
		{"warehouse", "extra", "--config", "e.json", "--binding", "postgres", "--credentials-file", "live=/x", "--user", "u"},
		{"--config", "e.json", "warehouse", "--binding", "postgres", "extra", "--credentials-file", "live=/x", "--user", "u"},
		{"warehouse", "--config", "e.json", "--binding", "postgres", "--credentials-file", "live=/x", "--user", "u", "--unknown"},
		{"warehouse", "--config", "e.json", "--binding", "postgres", "--credentials-file", "/x", "--user", "u"},
		{"warehouse", "--config", "e.json", "--binding", "postgres", "--credentials-file", "live=/x", "--credentials-file", "live=/y", "--user", "u"},
	} {
		if _, msg, ok := parseConnectArgs(args); ok || !strings.HasPrefix(msg, "usage: gateway connect") {
			t.Fatalf("%v: accepted, or no usage: %q", args, msg)
		}
	}
}

func TestFormatValueIsCanonicalOrderIndented(t *testing.T) {
	v, err := parseJSON([]byte(`{"z":[1,{"b":null,"a":"xé"},[]],"a":{},"m":true}`))
	if err != nil {
		t.Fatal(err)
	}
	var sb strings.Builder
	formatValue(&sb, v, "")
	want := "{\n  \"a\": {},\n  \"m\": true,\n  \"z\": [\n    1,\n    {\n      \"a\": \"xé\",\n      \"b\": null\n    },\n    []\n  ]\n}"
	if sb.String() != want {
		t.Fatalf("formatted:\n%s\nwant:\n%s", sb.String(), want)
	}
	// What is written parses back to the same canonical bytes.
	again, err := parseJSON([]byte(sb.String()))
	if err != nil || string(canon(again)) != string(canon(v)) {
		t.Fatalf("round trip: %v %s", err, canon(again))
	}
}

func TestDescribeCheckShapes(t *testing.T) {
	if got, err := describeCheck("mcp", []byte(`{"check":{"status":"succeeded","adapter":{"name":"npx","version":"","digest":"sha256:ab"},"server":{"name":"","version":""},"protocolVersion":"2024-11-05","tools":[]}}`)); err != nil || got != "npx (sha256:ab): server an unnamed server, protocol 2024-11-05, tools " {
		t.Fatalf("a command without a version, a server without a name: %q %v", got, err)
	}
	if _, err := describeCheck("http", []byte(airbyteReport)); err == nil || !strings.Contains(err.Error(), `no check for shape "http"`) {
		t.Fatalf("an unknown shape: %v", err)
	}
	if _, err := describeCheck("airbyte", []byte(`{"check":{"adapter":{"name":"a","digest":"d"},"status":"succeeded"},"extra":1}`)); err == nil {
		t.Fatal("a report with more than the check is not a check report")
	}
	// A failed report says why; anything else is not one.
	if reason, ok := failedCheck([]byte(`{"check":{"status":"failed","message":"no route to host"}}`)); !ok || reason != "no route to host" {
		t.Fatalf("failed report: %q %v", reason, ok)
	}
	for _, text := range []string{`{"check":{"status":"succeeded","message":"x"}}`, `{"check":{"status":"failed"}}`, `{"check":{"status":"failed","message":"x"},"more":1}`, `not json`} {
		if _, ok := failedCheck([]byte(text)); ok {
			t.Fatalf("%s is not a failed report", text)
		}
	}
}

func TestConnectRefusesAConfigurationThatWouldExceedTheBound(t *testing.T) {
	// Another platform's environment fills the file to just under what
	// serve reads; the entry would take it past, and nothing is asked.
	docs := filepath.Join(filepath.VolumeName(t.TempDir())+string(filepath.Separator), "run", "secrets", "docs")
	entry := func(filler string) string {
		return `"docs":{"binding":"postgres@` + digestOf(restrictedBinding) + `","credentials":{"history":{"file":"` + escapePath(docs) + `"},"live":{"file":"` + escapePath(docs) + `"}},"user":"engine-docs","environment":{"FILLER":"` + filler + `"}}`
	}
	// Measured: the file lands 64 bytes under the bound, so it reads, and
	// the entry -- a few hundred bytes -- takes it past.
	probe := newConnectFixture(t, restrictedBinding, entry(""))
	filler := strings.Repeat("x", maxEngineConfigBytes-64-len(probe.fileText(t)))
	f := newConnectFixture(t, restrictedBinding, entry(filler))
	if size := len(f.fileText(t)); size > maxEngineConfigBytes || size < maxEngineConfigBytes-128 {
		t.Fatalf("the fixture is %d bytes", size)
	}
	f.fs[docs] = fileOwnership{uid: 1002, mode: 0o600}
	before := f.fileText(t)
	_, err := connect(context.Background(), f.request(), f.host, f.check)
	if err == nil || !strings.Contains(err.Error(), "would exceed") || len(f.asked) != 0 || f.fileText(t) != before {
		t.Fatalf("refused before any check, nothing written: %v (asked %d)", err, len(f.asked))
	}
}

func TestConnectRefusesToWriteOverAFileThatChangedMeanwhile(t *testing.T) {
	f := newConnectFixture(t, restrictedBinding, ``)
	before := f.fileText(t)
	changed := false
	check := func(ctx context.Context, spec sourceSpec) ([]byte, error) {
		if !changed {
			// Someone edits the file while the checks run.
			if err := os.WriteFile(f.config, []byte(strings.Replace(before, `"gateway:acme"`, `"gateway:other"`, 1)), 0o640); err != nil {
				t.Fatal(err)
			}
			changed = true
		}
		return f.check(ctx, spec)
	}
	_, err := connect(context.Background(), f.request(), f.host, check)
	if err == nil || !strings.Contains(err.Error(), "the file changed while the checks ran") {
		t.Fatalf("not written over: %v", err)
	}
	if !strings.Contains(f.fileText(t), `"gateway:other"`) || strings.Contains(f.fileText(t), "warehouse") {
		t.Fatal("the edit stands and the entry was not written")
	}
}

func TestReplaceRepairsAStalePinOfTheEntryReplaced(t *testing.T) {
	// The entry being replaced pins a digest the catalog no longer has;
	// --replace is how that is repaired, so the old entry is not resolved.
	f := newConnectFixture(t, restrictedBinding, `"warehouse":{"binding":"postgres@`+digestOf(postgresBinding)+`","credentials":{"history":{"file":"`+escapePath(f0(t))+`"},"live":{"file":"`+escapePath(f0(t))+`"}},"user":"engine-warehouse"}`)
	req := f.request()
	if _, err := connect(context.Background(), req, f.host, f.check); err == nil || !strings.Contains(err.Error(), "already configured") {
		t.Fatalf("without --replace the entry stands: %v", err)
	}
	req.replace = true
	if _, err := connect(context.Background(), req, f.host, f.check); err != nil {
		t.Fatalf("--replace repairs the pin: %v", err)
	}
	cfg, _, err := loadEngineConfig(f.config, stubAccounts(stubUsers))
	if err != nil || len(cfg.platforms) != 1 || cfg.platforms[0].binding != "postgres@"+digestOf(restrictedBinding) {
		t.Fatalf("the new pin is written: %v %+v", err, cfg.platforms)
	}
}

// f0 is a rooted synthetic path for an entry that is never resolved.
func f0(t *testing.T) string {
	t.Helper()
	return filepath.Join(filepath.VolumeName(t.TempDir())+string(filepath.Separator), "run", "secrets", "old")
}

func TestConnectJudgesTheSeedAsServeDoes(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("file modes are not judged on Windows")
	}
	f := newConnectFixture(t, restrictedBinding, ``)
	if err := os.Chmod(f.seed, 0o644); err != nil {
		t.Fatal(err)
	}
	before := f.fileText(t)
	_, err := connect(context.Background(), f.request(), f.host, f.check)
	if err == nil || !strings.Contains(err.Error(), "seed:") || !strings.Contains(err.Error(), "chmod 0600") || len(f.asked) != 0 || f.fileText(t) != before {
		t.Fatalf("a seed serve would refuse ends the connect before any check: %v (asked %d)", err, len(f.asked))
	}
	if err := os.Chmod(f.seed, 0o600); err != nil {
		t.Fatal(err)
	}
	for _, content := range []string{"", "too short", strings.Repeat("a", 31)} {
		if err := os.WriteFile(f.seed, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := connect(context.Background(), f.request(), f.host, f.check); err == nil || !strings.Contains(err.Error(), "seed: seed file does not hold a 32-byte seed") {
			t.Fatalf("a seed that is not one (%d bytes) is refused before any check: %v", len(content), err)
		}
	}
	os.Remove(f.seed)
	if _, err := connect(context.Background(), f.request(), f.host, f.check); err == nil || !strings.Contains(err.Error(), "seed:") {
		t.Fatalf("an absent seed too: %v", err)
	}
	if len(f.asked) != 0 {
		t.Fatal("nothing was asked for any of them")
	}
}

func TestDescribeCheckReportsTheProbe(t *testing.T) {
	report := `{"check":{"status":"succeeded","adapter":{"name":"crystaldba/postgres-mcp","version":"0.3.0","digest":"` + testImageDigest + `"},"server":{"name":"postgres-mcp","version":"0.3.0"},"protocolVersion":"2025-03-26","tools":["list_schemas"],"probe":{"tool":"list_schemas","answered":true}}}`
	got, err := describeCheck("mcp", []byte(report))
	if err != nil || !strings.HasSuffix(got, "tools list_schemas; list_schemas answered") {
		t.Fatalf("%q %v", got, err)
	}
	if _, err := describeCheck("mcp", []byte(strings.Replace(report, `"answered":true`, `"answered":false`, 1))); err == nil || !strings.Contains(err.Error(), `the probe "list_schemas" did not answer`) {
		t.Fatalf("a probe that did not answer: %v", err)
	}
}

func TestConnectJudgesThePathsServeMakes(t *testing.T) {
	// Written out rather than tabled: each case changes a different path.
	f := newConnectFixture(t, restrictedBinding, ``)
	store := storeOf(t, f)
	if err := os.WriteFile(store, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	before := f.fileText(t)
	_, err := connect(context.Background(), f.request(), f.host, f.check)
	if err == nil || !strings.Contains(err.Error(), "store "+store+" is not a directory") || len(f.asked) != 0 || f.fileText(t) != before {
		t.Fatalf("a store serve could not make is refused before any check: %v (asked %d)", err, len(f.asked))
	}
	os.Remove(store)
	// The store's own directories, which serve makes on start.
	for _, child := range []string{"artifacts", "receipts"} {
		if err := os.MkdirAll(store, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(store, child), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := connect(context.Background(), f.request(), f.host, f.check); err == nil || !strings.Contains(err.Error(), "store "+store+": "+child+" is not a directory") {
			t.Fatalf("a file in the place of %s: %v", child, err)
		}
		os.RemoveAll(store)
	}
	registry := strings.TrimSuffix(store, "store") + "registry.jsonl"
	if err := os.Mkdir(registry, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := connect(context.Background(), f.request(), f.host, f.check); err == nil || !strings.Contains(err.Error(), "registry "+registry+" is not a regular file") {
		t.Fatalf("a registry that is a directory: %v", err)
	}
	os.Remove(registry)
	decisions := strings.TrimSuffix(store, "store") + "decisions"
	if err := os.WriteFile(decisions, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := connect(context.Background(), f.request(), f.host, f.check); err == nil || !strings.Contains(err.Error(), "decisionRecords "+decisions+" is not a directory") {
		t.Fatalf("a decision-record path that is a file: %v", err)
	}
	os.Remove(decisions)
	if _, err := connect(context.Background(), f.request(), f.host, f.check); err != nil {
		t.Fatalf("absent, with a directory to make them in: %v", err)
	}
	if err := preflightPaths(filepath.Join(t.TempDir(), "missing", "store"), registry, decisions); err == nil || !strings.Contains(err.Error(), "cannot be made: its directory is not there") {
		t.Fatalf("a store with no directory to make it in: %v", err)
	}
	// A link that leads nowhere is not absence: making a directory over
	// it fails.
	if err := os.MkdirAll(store, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("gone", filepath.Join(store, "artifacts")); err == nil {
		// The entry the connect above wrote, taken back.
		if err := os.WriteFile(f.config, []byte(before), 0o640); err != nil {
			t.Fatal(err)
		}
		asked := len(f.asked)
		if _, err := connect(context.Background(), f.request(), f.host, f.check); err == nil || !strings.Contains(err.Error(), "artifacts is a link that leads nowhere") || len(f.asked) != asked || f.fileText(t) != before {
			t.Fatalf("a dangling link in the place of artifacts: %v (asked %d)", err, len(f.asked)-asked)
		}
		os.Remove(filepath.Join(store, "artifacts"))
		// A loop is a lookup that fails for another reason than absence.
		os.Symlink("loop-b", filepath.Join(store, "loop-a"))
		os.Symlink("loop-a", filepath.Join(store, "loop-b"))
		if err := preflightPaths(filepath.Join(store, "loop-a"), registry, decisions); err == nil || !strings.Contains(err.Error(), "store "+filepath.Join(store, "loop-a")+" is a link that leads nowhere") {
			t.Fatalf("a link loop: %v", err)
		}
	}
	os.RemoveAll(store)
}

// storeOf is the store path the fixture's configuration names.
func storeOf(t *testing.T, f *connectFixture) string {
	t.Helper()
	cfg, err := parseEngineConfig([]byte(f.fileText(t)))
	if err != nil {
		t.Fatal(err)
	}
	return cfg.store
}
