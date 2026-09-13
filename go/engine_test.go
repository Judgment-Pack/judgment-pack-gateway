package main

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

const testImageDigest = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

// postgresBinding is a catalog entry with both operations.
const postgresBinding = `{
  "bindingVersion": "1",
  "platform": "postgres",
  "operations": {
    "history": {"shape": "airbyte", "image": "airbyte/source-postgres:3.6.1@` + testImageDigest + `", "licence": "ELv2"},
    "live": {"shape": "mcp", "server": {"image": "ghcr.io/example/mcp-postgres:2.1@` + testImageDigest + `"}, "tools": ["query", "explain"], "licence": "MIT"},
    "write": {"shape": "mcp", "server": {"image": "ghcr.io/example/mcp-postgres:2.1@` + testImageDigest + `"}, "tools": ["execute"], "licence": "MIT"}
  }
}`

func digestOf(data string) string {
	sum := sha256.Sum256([]byte(data))
	return "sha256:" + hex.EncodeToString(sum[:])
}

// catalogWith writes bindings into a catalog directory and returns it.
func catalogWith(t *testing.T, bindings map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for name, text := range bindings {
		if err := os.WriteFile(filepath.Join(dir, name+".json"), []byte(text), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func engineJSON(catalog string, extra string, platforms string) string {
	return `{"engineVersion":"1","authority":"gateway:acme","seed":"/var/lib/engine/gateway.seed","store":"/var/lib/engine/store",` +
		`"registry":"/var/lib/engine/registry.jsonl","decisionRecords":"/var/lib/engine/decisions","listen":"127.0.0.1:8787",` +
		`"catalog":"` + strings.ReplaceAll(catalog, `\`, `\\`) + `"` + extra + `,"platforms":{` + platforms + `}}`
}

func warehousePlatform(binding string, extra string) string {
	return `"warehouse":{"binding":"` + binding + `","credentials":{"file":"/run/secrets/warehouse"},"user":"engine-warehouse"` + extra + `}`
}

// A configuration names platforms, and the engine derives from each one
// source per operation its binding offers: the adapter command line, the
// shape, the platform's user, and an environment of HOME alone.
func TestEngineDerivesSourcesFromPlatforms(t *testing.T) {
	catalog := catalogWith(t, map[string]string{"postgres": postgresBinding})
	ref := "postgres@" + digestOf(postgresBinding)
	path := filepath.Join(t.TempDir(), "engine.json")
	text := engineJSON(catalog, `,"runtime":"podman","adapters":"/opt/engine/bin"`, warehousePlatform(ref, `,"endpoint":"warehouse.internal:5432","write":true`))
	if err := os.WriteFile(path, []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, sources, err := loadEngineConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.authority != "gateway:acme" || cfg.listen != "127.0.0.1:8787" || cfg.runtime != "podman" || cfg.rootSigner || cfg.hostRuntime {
		t.Fatalf("configuration: %+v", cfg)
	}
	if len(cfg.platforms) != 1 || cfg.platforms[0].user != "engine-warehouse" || !cfg.platforms[0].write {
		t.Fatalf("platforms: %+v", cfg.platforms)
	}
	want := map[string]sourceSpec{
		"warehouse/history": {
			argv: []string{filepath.Join("/opt/engine/bin", "adapter-airbyte"), "--image", "airbyte/source-postgres:3.6.1@" + testImageDigest,
				"--credentials", "/run/secrets/warehouse", "--runtime", "podman", "--endpoint", "warehouse.internal:5432"},
			env: []string{"HOME"}, user: "engine-warehouse", shape: "airbyte",
		},
		"warehouse/live": {
			argv: []string{filepath.Join("/opt/engine/bin", "adapter-mcp"), "--image", "ghcr.io/example/mcp-postgres:2.1@" + testImageDigest,
				"--credentials", "/run/secrets/warehouse", "--runtime", "podman", "--tools", "query,explain", "--endpoint", "warehouse.internal:5432"},
			env: []string{"HOME"}, user: "engine-warehouse", shape: "mcp",
		},
	}
	if !reflect.DeepEqual(sources, want) {
		t.Fatalf("derived sources:\n got %+v\nwant %+v", sources, want)
	}
	// Without an adapters directory the binaries are found on PATH; a
	// binding with one operation derives one source; the write operation
	// derives nothing.
	one := `{"bindingVersion":"1","platform":"docs","operations":{"history":{"shape":"airbyte","image":"airbyte/source-s3:4.0.0@` + testImageDigest + `","licence":"MIT"}}}`
	catalog = catalogWith(t, map[string]string{"docs": one})
	text = engineJSON(catalog, ``, `"policy-documents":{"binding":"docs@`+digestOf(one)+`","credentials":{"file":"/run/secrets/docs"},"user":"engine-docs"}`)
	os.WriteFile(path, []byte(text), 0o600)
	_, sources, err = loadEngineConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(sources) != 1 || sources["policy-documents/history"].argv[0] != "adapter-airbyte" || sources["policy-documents/history"].argv[6] != "docker" {
		t.Fatalf("one source, adapter on PATH, docker by default: %+v", sources)
	}
}

// Every departure from the configuration's shape is refused by name.
func TestEngineConfigRefusals(t *testing.T) {
	catalog := catalogWith(t, map[string]string{"postgres": postgresBinding})
	ref := "postgres@" + digestOf(postgresBinding)
	good := warehousePlatform(ref, ``)
	cases := []struct {
		name string
		text string
		want string
	}{
		{"not an object", `[]`, "not an object"},
		{"unknown member", engineJSON(catalog, `,"port":8787`, good), `unknown member "port"`},
		{"duplicate member", `{"engineVersion":"1","engineVersion":"1"}`, "duplicate"},
		{"missing member", strings.Replace(engineJSON(catalog, ``, good), `"registry":"/var/lib/engine/registry.jsonl",`, ``, 1), `missing member "registry"`},
		{"wrong version", strings.Replace(engineJSON(catalog, ``, good), `"engineVersion":"1"`, `"engineVersion":"2"`, 1), `engineVersion "2" is not "1"`},
		{"identity present", engineJSON(catalog, `,"identity":{"issuer":"https://login.example.com/"}`, good), "identity is not supported by this release"},
		{"listen not loopback", strings.Replace(engineJSON(catalog, ``, good), `"listen":"127.0.0.1:8787"`, `"listen":"0.0.0.0:8787"`, 1), "not a loopback address"},
		{"listen without port", strings.Replace(engineJSON(catalog, ``, good), `"listen":"127.0.0.1:8787"`, `"listen":"127.0.0.1"`, 1), "not host:port"},
		{"rootSigner not accepted", engineJSON(catalog, `,"rootSigner":true`, good), `rootSigner, when present, is the string "accepted"`},
		{"hostRuntime wrong word", engineJSON(catalog, `,"hostRuntime":"yes"`, good), `hostRuntime, when present, is the string "accepted"`},
		{"runtime not a string", engineJSON(catalog, `,"runtime":1`, good), "runtime must be a non-empty string"},
		{"no platforms", engineJSON(catalog, ``, ``), "names no platform"},
		{"platform name with slash", engineJSON(catalog, ``, `"a/b":{"binding":"`+ref+`","credentials":{"file":"/f"},"user":"u"}`), `platform name "a/b"`},
		{"platform unknown member", engineJSON(catalog, ``, warehousePlatform(ref, `,"command":"x"`)), `unknown member "command"`},
		{"platform without user", engineJSON(catalog, ``, `"warehouse":{"binding":"`+ref+`","credentials":{"file":"/f"}}`), `missing member "user"`},
		{"platform empty user", engineJSON(catalog, ``, `"warehouse":{"binding":"`+ref+`","credentials":{"file":"/f"},"user":""}`), "an adapter running as the signer could read the seed"},
		{"credentials as a value", engineJSON(catalog, ``, `"warehouse":{"binding":"`+ref+`","credentials":{"env":"DATABASE_URL"},"user":"u"}`), `unknown member "env"`},
		{"binding unpinned", engineJSON(catalog, ``, `"warehouse":{"binding":"postgres","credentials":{"file":"/f"},"user":"u"}`), "binding must be name@sha256"},
		{"binding digest mismatch", engineJSON(catalog, ``, `"warehouse":{"binding":"postgres@`+testImageDigest+`","credentials":{"file":"/f"},"user":"u"}`), "does not digest to the pinned"},
		{"binding absent from the catalog", engineJSON(catalog, ``, `"warehouse":{"binding":"jira@`+testImageDigest+`","credentials":{"file":"/f"},"user":"u"}`), "binding jira@"},
		{"write not a boolean", engineJSON(catalog, ``, warehousePlatform(ref, `,"write":"yes"`)), "write, when present, is a boolean"},
		{"endpoint empty", engineJSON(catalog, ``, warehousePlatform(ref, `,"endpoint":""`)), "endpoint, when present, is a non-empty string"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "engine.json")
			os.WriteFile(path, []byte(tc.text), 0o600)
			_, _, err := loadEngineConfig(path)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("want %q, got %v", tc.want, err)
			}
		})
	}
}

// A catalog entry is held to its shape: pinned images, stated licences,
// the shape each operation is served by, no unknown operation or member.
func TestBindingRefusals(t *testing.T) {
	cases := map[string]string{
		`{"bindingVersion":"2","platform":"p","operations":{}}`: `bindingVersion "2"`,
		`{"bindingVersion":"1","platform":"p","operations":{}}`: "no history or live operation",
		`{"bindingVersion":"1","platform":"p","operations":{"history":{"shape":"airbyte","image":"airbyte/source-postgres:3.6.1","licence":"ELv2"}}}`:                 "image must be pinned",
		`{"bindingVersion":"1","platform":"p","operations":{"history":{"shape":"airbyte","image":"x@` + testImageDigest + `"}}}`:                                      "licence must be stated",
		`{"bindingVersion":"1","platform":"p","operations":{"history":{"shape":"mcp","server":{"image":"x@` + testImageDigest + `"},"tools":["q"],"licence":"MIT"}}}`: "operation history is served by the airbyte shape",
		`{"bindingVersion":"1","platform":"p","operations":{"live":{"shape":"airbyte","image":"x@` + testImageDigest + `","licence":"MIT"}}}`:                         "operation live is served by the mcp shape",
		`{"bindingVersion":"1","platform":"p","operations":{"live":{"shape":"mcp","server":{"image":"x@` + testImageDigest + `"},"tools":[],"licence":"MIT"}}}`:       "tools must be a non-empty array",
		`{"bindingVersion":"1","platform":"p","operations":{"live":{"shape":"mcp","server":{"image":"x@` + testImageDigest + `"},"tools":["a,b"],"licence":"MIT"}}}`:  "without commas",
		`{"bindingVersion":"1","platform":"p","operations":{"live":{"shape":"http","licence":"MIT"}}}`:                                                                "http shape is not shipped",
		`{"bindingVersion":"1","platform":"p","operations":{"sync":{"shape":"airbyte","image":"x@` + testImageDigest + `","licence":"MIT"}}}`:                         `unknown operation "sync"`,
		`{"bindingVersion":"1","platform":"p","operations":{"history":{"shape":"airbyte","image":"x@` + testImageDigest + `","licence":"MIT","pull":true}}}`:          `unknown member "pull"`,
		`{"bindingVersion":"1","platform":"p","operations":{"history":{"shape":"airbyte","image":"x@` + testImageDigest + `","licence":"MIT"}},"extra":1}`:            `unknown member "extra"`,
	}
	for text, want := range cases {
		if _, err := parseBinding([]byte(text)); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: want %q, got %v", text, want, err)
		}
	}
	// The file must name the platform the reference names.
	catalog := catalogWith(t, map[string]string{"jira": postgresBinding})
	if _, err := loadBinding(catalog, "jira@"+digestOf(postgresBinding)); err == nil || !strings.Contains(err.Error(), `the file names platform "postgres"`) {
		t.Fatalf("platform mismatch: %v", err)
	}
}

// The refusals the isolation claim depends on, with the filesystem and the
// user database stood in for: a root signer must be accepted by name; an
// adapter user must not be the signer's; credentials must be owned by the
// adapter's user and readable by nobody else; a host runtime socket must
// be accepted by name.
func TestEngineRefusalsForIsolation(t *testing.T) {
	cfg := engineConfig{runtime: "docker", platforms: []platformConfig{{name: "warehouse", credentials: "/run/secrets/warehouse", user: "engine-warehouse"}}}
	users := func(name string) (int, error) { return 1001, nil }
	owned := func(uid int, mode os.FileMode) func(string) (int, os.FileMode, error) {
		return func(string) (int, os.FileMode, error) { return uid, mode, nil }
	}
	noSockets := []string{filepath.Join(t.TempDir(), "absent.sock")}
	socket := filepath.Join(t.TempDir(), "docker.sock")
	os.WriteFile(socket, nil, 0o600)

	statements, err := engineRefusals(cfg, 1000, noSockets, owned(1001, 0o600), users)
	if err != nil || len(statements) != 0 {
		t.Fatalf("a non-root signer beside a platform user with private credentials starts silently: %v %v", err, statements)
	}
	if _, err := engineRefusals(cfg, 0, noSockets, owned(1001, 0o600), users); err == nil || !strings.Contains(err.Error(), "the signer runs as root") {
		t.Fatalf("a root signer is refused unless accepted: %v", err)
	}
	accepted := cfg
	accepted.rootSigner = true
	if statements, err := engineRefusals(accepted, 0, noSockets, owned(1001, 0o600), users); err != nil || len(statements) != 1 || !strings.Contains(statements[0], "rootSigner accepted") {
		t.Fatalf("an accepted root signer starts with a statement: %v %v", err, statements)
	}
	if _, err := engineRefusals(cfg, 1001, noSockets, owned(1001, 0o600), users); err == nil || !strings.Contains(err.Error(), "is the signer's own") {
		t.Fatalf("a platform user that is the signer is refused: %v", err)
	}
	if _, err := engineRefusals(cfg, 1000, noSockets, owned(1000, 0o600), users); err == nil || !strings.Contains(err.Error(), "must be owned by engine-warehouse") {
		t.Fatalf("credentials owned by another user are refused: %v", err)
	}
	if _, err := engineRefusals(cfg, 1000, noSockets, owned(1001, 0o640), users); err == nil || !strings.Contains(err.Error(), "readable beyond its owner (mode 0640)") {
		t.Fatalf("credentials readable beyond their owner are refused: %v", err)
	}
	if _, err := engineRefusals(cfg, 1000, noSockets, owned(1001, 0o600), func(string) (int, error) { return 0, os.ErrNotExist }); err == nil || !strings.Contains(err.Error(), "platform warehouse:") {
		t.Fatalf("an unknown user is refused: %v", err)
	}
	if _, err := engineRefusals(cfg, 1000, []string{socket}, owned(1001, 0o600), users); err == nil || !strings.Contains(err.Error(), "host container runtime socket is present") {
		t.Fatalf("a host runtime socket is refused unless accepted: %v", err)
	}
	accepted = cfg
	accepted.hostRuntime = true
	if statements, err := engineRefusals(accepted, 1000, []string{socket}, owned(1001, 0o600), users); err != nil || len(statements) != 1 || !strings.Contains(statements[0], "hostRuntime accepted") {
		t.Fatalf("an accepted host runtime starts with a statement: %v %v", err, statements)
	}
}

// `serve --config` refuses before anything is written: a configuration
// that does not parse, and one whose platform user this process cannot
// switch to.
func TestServeConfigRefusesBeforeWriting(t *testing.T) {
	dir := t.TempDir()
	store := filepath.Join(dir, "store")
	catalog := catalogWith(t, map[string]string{"postgres": postgresBinding})
	seed := filepath.Join(dir, "gateway.seed")
	if code := cmdKeygen([]string{seed}); code != 0 {
		t.Fatal("keygen")
	}
	path := filepath.Join(dir, "engine.json")
	text := engineJSON(catalog, ``, warehousePlatform("postgres@"+digestOf(postgresBinding), ``))
	text = strings.Replace(text, `"seed":"/var/lib/engine/gateway.seed"`, `"seed":"`+strings.ReplaceAll(seed, `\`, `\\`)+`"`, 1)
	text = strings.Replace(text, `"store":"/var/lib/engine/store"`, `"store":"`+strings.ReplaceAll(store, `\`, `\\`)+`"`, 1)
	os.WriteFile(path, []byte(text), 0o600)
	stderr := captureStderr(t)
	if code := cmdServe([]string{"--config", path}); code != 1 {
		t.Fatalf("exit %d, want 1", code)
	}
	out := stderr()
	if !strings.Contains(out, "start:") {
		t.Fatalf("the refusal is reported: %q", out)
	}
	if _, err := os.Stat(store); err == nil {
		t.Fatal("the store was created before the configuration was refused")
	}
	stderr = captureStderr(t)
	if code := cmdServe([]string{"--config", path, "--port", "1"}); code != 2 {
		t.Fatalf("anything beside the file is a usage error: %d", code)
	}
	stderr()
	os.WriteFile(path, []byte(`{"engineVersion":"1"}`), 0o600)
	stderr = captureStderr(t)
	if code := cmdServe([]string{"--config", path}); code != 1 || !strings.Contains(stderr(), `missing member`) {
		t.Fatal("a configuration that does not parse is refused")
	}
}
