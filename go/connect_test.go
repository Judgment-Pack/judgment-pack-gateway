package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// A binding whose live server takes its own arguments.
const restrictedBinding = `{
  "bindingVersion": "1",
  "platform": "postgres",
  "operations": {
    "history": {"shape": "airbyte", "image": "airbyte/source-postgres:3.8.5@` + testImageDigest + `", "licence": "ELv2"},
    "live": {"shape": "mcp", "server": {"image": "crystaldba/postgres-mcp:0.3.0@` + testImageDigest + `", "args": ["--access-mode=restricted"]}, "tools": ["query"], "licence": "MIT"}
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
}

func newConnectFixture(t *testing.T, bindingText string, platforms string) *connectFixture {
	t.Helper()
	f := &connectFixture{dir: t.TempDir(), reports: map[string]string{"airbyte": airbyteReport, "mcp": mcpReport}, fail: map[string]string{}}
	f.catalog = catalogWith(t, map[string]string{"postgres": bindingText})
	// Synthetic paths, rooted on the platform's volume so they are absolute
	// on Windows too; the stub filesystem is what holds them.
	root := filepath.VolumeName(f.dir) + string(filepath.Separator)
	f.seed = filepath.Join(root, "var", "lib", "engine", "gateway.seed")
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
	}
	return f
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
	return connectRequest{config: f.config, platform: "warehouse", binding: "postgres", credentials: f.credentials, user: "engine-warehouse",
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
	if argv := strings.Join(f.asked[1].argv, " "); !strings.HasSuffix(argv, " --endpoint warehouse.internal:5432 -- --access-mode=restricted") || !strings.Contains(argv, "--credentials "+f.credentials+" ") {
		t.Fatalf("the derived command line carries the binding's server arguments after --: %s", argv)
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
	if p.name != "warehouse" || p.binding != "postgres@"+digestOf(restrictedBinding) || p.credentials != f.credentials || p.user != "engine-warehouse" ||
		p.endpoint != "warehouse.internal:5432" || strings.Join(p.environment, ",") != "DOCKER_HOST=unix:///run/user/1001/docker.sock" || !p.write {
		t.Fatalf("the entry as requested: %+v", p)
	}
	live := deriveSources(cfg, bindings)["warehouse/live"]
	if argv := strings.Join(live.argv, " "); !strings.HasSuffix(argv, " -- --access-mode=restricted") {
		t.Fatalf("serve derives the server's arguments from the written entry: %s", argv)
	}
	if entries, _ := os.ReadDir(f.dir); len(entries) != 1 {
		t.Fatalf("nothing is left beside the file: %v", entries)
	}
	if info, _ := os.Stat(f.config); runtime.GOOS != "windows" && info.Mode().Perm() != 0o640 {
		t.Fatalf("the file keeps its mode: %v", info.Mode())
	}
	// The other members survive as written, in canonical order.
	if !strings.Contains(after, "\n  \"catalog\": ") || !strings.Contains(after, "\n  \"engineVersion\": \"1\",\n") || !strings.Contains(after, "\n  \"platforms\": {\n    \"warehouse\": {\n      \"binding\": \"postgres@") {
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
		{"a relative credentials path", func(f *connectFixture, req *connectRequest) { req.credentials = "secrets/warehouse" }, "credentials-file must be an absolute path"},
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
	f := newConnectFixture(t, restrictedBinding, `"docs":{"binding":"postgres@`+digestOf(postgresBinding)+`","credentials":{"file":"`+escapePath(docs)+`"},"user":"engine-docs"}`)
	_, err := connect(context.Background(), f.request(), f.host, f.check)
	if err == nil || !strings.Contains(err.Error(), "platform docs") || !strings.Contains(err.Error(), "does not digest to the pinned") {
		t.Fatalf("a pin the catalog no longer digests to is found at connect, not at the next start: %v", err)
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
	want := connectRequest{config: "e.json", platform: "warehouse", binding: "postgres", credentials: "/run/secrets/w", user: "engine-warehouse", endpoint: "h:1", environment: []string{"A=1", "B=2"}, write: true, replace: true}
	for _, args := range [][]string{
		{"warehouse", "--config", "e.json", "--binding", "postgres", "--credentials-file", "/run/secrets/w", "--user", "engine-warehouse", "--endpoint", "h:1", "--environment", "A=1", "--environment", "B=2", "--write", "--replace"},
		{"--config", "e.json", "--binding", "postgres", "--credentials-file", "/run/secrets/w", "--user", "engine-warehouse", "--endpoint", "h:1", "--environment", "A=1", "--environment", "B=2", "--write", "--replace", "warehouse"},
	} {
		got, msg, ok := parseConnectArgs(args)
		if !ok || got.config != want.config || got.platform != want.platform || got.binding != want.binding || got.credentials != want.credentials || got.user != want.user ||
			got.endpoint != want.endpoint || strings.Join(got.environment, ",") != "A=1,B=2" || !got.write || !got.replace {
			t.Fatalf("%v: %+v %q", args, got, msg)
		}
	}
	for _, args := range [][]string{
		{},
		{"warehouse"},
		{"warehouse", "--config", "e.json", "--binding", "postgres", "--credentials-file", "/x"},
		{"--config", "e.json", "--binding", "postgres", "--credentials-file", "/x", "--user", "u"},
		{"warehouse", "extra", "--config", "e.json", "--binding", "postgres", "--credentials-file", "/x", "--user", "u"},
		{"warehouse", "--config", "e.json", "--binding", "postgres", "--credentials-file", "/x", "--user", "u", "--unknown"},
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
