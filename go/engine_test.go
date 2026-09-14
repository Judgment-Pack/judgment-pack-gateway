package main

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"os/user"
	"path/filepath"
	"reflect"
	"runtime"
	"slices"
	"strings"
	"testing"
)

const testImageDigest = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

// postgresBinding is a catalog entry with both operations and a write path.
const postgresBinding = `{
  "bindingVersion": "1",
  "platform": "postgres",
  "operations": {
    "history": {"shape": "airbyte", "image": "airbyte/source-postgres:3.6.1@` + testImageDigest + `", "licence": "ELv2"},
    "live": {"shape": "mcp", "server": {"image": "ghcr.io/example/mcp-postgres:2.1@` + testImageDigest + `"}, "tools": ["query", "explain"], "licence": "MIT"},
    "write": {"shape": "mcp", "server": {"image": "ghcr.io/example/mcp-postgres:2.1@` + testImageDigest + `"}, "tools": ["execute", "drop"], "licence": "MIT"}
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

// abs is an absolute path for a configuration on any platform, escaped for
// JSON.
func abs(t *testing.T, elem ...string) string {
	t.Helper()
	p := filepath.Join(elem...)
	if !filepath.IsAbs(p) {
		p = filepath.Join(t.TempDir(), p)
	}
	return strings.ReplaceAll(p, `\`, `\\`)
}

func engineJSON(t *testing.T, catalog string, extra string, platforms string) string {
	t.Helper()
	base := t.TempDir()
	return `{"engineVersion":"1","authority":"gateway:acme","seed":"` + abs(t, base, "gateway.seed") + `","store":"` + abs(t, base, "store") + `",` +
		`"registry":"` + abs(t, base, "registry.jsonl") + `","decisionRecords":"` + abs(t, base, "decisions") + `","listen":"127.0.0.1:8787",` +
		`"catalog":"` + abs(t, catalog) + `"` + extra + `,"platforms":{` + platforms + `}}`
}

func platformJSON(t *testing.T, name, binding, user string, extra string) string {
	t.Helper()
	return platformJSONFor(t, name, binding, user, extra, "history", "live")
}

// platformJSONFor is a platform entry with a credentials file for each
// operation named.
func platformJSONFor(t *testing.T, name, binding, user string, extra string, ops ...string) string {
	t.Helper()
	dir := t.TempDir()
	credentials := ""
	for i, op := range ops {
		if i > 0 {
			credentials += ","
		}
		credentials += `"` + op + `":{"file":"` + abs(t, dir, name+"-"+op+".json") + `"}`
	}
	return `"` + name + `":{"binding":"` + binding + `","credentials":{` + credentials + `},"user":"` + user + `"` + extra + `}`
}

// stubAccounts resolves the named users to fixed uids and homes.
func stubAccounts(users map[string]int) func(string) (int, string, error) {
	return func(name string) (int, string, error) {
		uid, ok := users[name]
		if !ok {
			return 0, "", os.ErrNotExist
		}
		return uid, "/home/" + name, nil
	}
}

var stubUsers = map[string]int{"engine-warehouse": 1001, "engine-docs": 1002, "engine-desk": 1003, "root": 0}

func load(t *testing.T, text string) (engineConfig, map[string]sourceSpec, error) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "engine.json")
	if err := os.WriteFile(path, []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, bindings, err := loadEngineConfig(path, stubAccounts(stubUsers))
	if err != nil {
		return cfg, nil, err
	}
	return cfg, deriveSources(cfg, bindings), nil
}

// A configuration names platforms, and the engine derives from each one
// source per operation its binding offers: the adapter command line, the
// shape, the platform's user, and an environment of that user's HOME and
// what the platform declared for its runtime.
func TestEngineDerivesSourcesFromPlatforms(t *testing.T) {
	catalog := catalogWith(t, map[string]string{"postgres": postgresBinding})
	ref := "postgres@" + digestOf(postgresBinding)
	bin := abs(t, t.TempDir(), "bin")
	text := engineJSON(t, catalog, `,"runtime":"podman","adapters":"`+bin+`"`,
		platformJSONFor(t, "warehouse", ref, "engine-warehouse", `,"endpoint":"warehouse.internal:5432","write":true,"environment":{"DOCKER_HOST":"unix:///run/user/1001/docker.sock"}`, "history", "live", "write"))
	cfg, sources, err := load(t, text)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.authority != "gateway:acme" || cfg.listen != "127.0.0.1:8787" || cfg.runtime != "podman" || cfg.rootSigner || cfg.hostRuntime {
		t.Fatalf("configuration: %+v", cfg)
	}
	p := cfg.platforms[0]
	if len(cfg.platforms) != 1 || p.user != "engine-warehouse" || p.uid != 1001 || p.home != "/home/engine-warehouse" || !p.write {
		t.Fatalf("platforms: %+v", cfg.platforms)
	}
	binDir := strings.ReplaceAll(bin, `\\`, `\`)
	env := []string{"HOME=/home/engine-warehouse", "DOCKER_HOST=unix:///run/user/1001/docker.sock"}
	want := map[string]sourceSpec{
		"warehouse/history": {
			argv: []string{filepath.Join(binDir, "adapter-airbyte"), "--image=airbyte/source-postgres:3.6.1@" + testImageDigest,
				"--credentials=" + p.credentials["history"], "--runtime=podman", "--endpoint=warehouse.internal:5432"},
			env: env, user: "engine-warehouse", shape: "airbyte",
		},
		"warehouse/live": {
			argv: []string{filepath.Join(binDir, "adapter-mcp"), "--image=ghcr.io/example/mcp-postgres:2.1@" + testImageDigest,
				"--credentials=" + p.credentials["live"], "--runtime=podman", "--tools=query,explain", "--endpoint=warehouse.internal:5432"},
			env: env, user: "engine-warehouse", shape: "mcp",
		},
		// The write operation, since the platform allows writes: the
		// executor is adapter-mcp on the binding's write server, with the
		// write tools and the write credentials (executor.md).
		"warehouse/write": {
			argv: []string{filepath.Join(binDir, "adapter-mcp"), "--image=ghcr.io/example/mcp-postgres:2.1@" + testImageDigest,
				"--credentials=" + p.credentials["write"], "--runtime=podman", "--tools=execute,drop", "--error-results", "--endpoint=warehouse.internal:5432"},
			env: env, user: "engine-warehouse", shape: "mcp", tools: []string{"execute", "drop"}, endpoint: "warehouse.internal:5432",
		},
	}
	if !reflect.DeepEqual(sources, want) {
		t.Fatalf("derived sources:\n got %+v\nwant %+v", sources, want)
	}
	// A platform that does not allow writes derives no write source and
	// names no write credential, whatever its binding states; one that
	// allows them against a binding stating none derives none either --
	// the executor is what refuses a request to write there.
	_, sources, err = load(t, engineJSON(t, catalog, ``, platformJSON(t, "warehouse", ref, "engine-warehouse", ``)))
	if err != nil {
		t.Fatal(err)
	}
	if _, derived := sources["warehouse/write"]; derived || len(sources) != 2 {
		t.Fatalf("no write: true, no write source: %+v", sources)
	}
	if _, _, err := load(t, engineJSON(t, catalog, ``, platformJSONFor(t, "warehouse", ref, "engine-warehouse", ``, "history", "live", "write"))); err == nil || !strings.Contains(err.Error(), "credentials name a write file but the binding offers no write") {
		t.Fatalf("a write credential for a platform that allows no writes: %v", err)
	}
	// A write operation naming a probe is refused: a check of a write source
	// calls no tool, so a probe there would be a write no check may make.
	probed := `{"bindingVersion":"1","platform":"postgres","operations":{"write":{"shape":"mcp","server":{"image":"ghcr.io/example/mcp-postgres:2.1@` + testImageDigest + `"},"tools":["execute"],"probe":{"tool":"execute"},"licence":"MIT"}}}`
	if _, _, err := load(t, engineJSON(t, catalogWith(t, map[string]string{"postgres": probed}), ``, platformJSONFor(t, "warehouse", "postgres@"+digestOf(probed), "engine-warehouse", `,"write":true`, "write"))); err == nil || !strings.Contains(err.Error(), "operation write accepts no probe") {
		t.Fatalf("a probe on a write operation: %v", err)
	}
	noWrite := `{"bindingVersion":"1","platform":"postgres","operations":{"live":{"shape":"mcp","server":{"image":"ghcr.io/example/mcp-postgres:2.1@` + testImageDigest + `"},"tools":["query"],"licence":"MIT"}}}`
	_, sources, err = load(t, engineJSON(t, catalogWith(t, map[string]string{"postgres": noWrite}), ``, platformJSONFor(t, "warehouse", "postgres@"+digestOf(noWrite), "engine-warehouse", `,"write":true`, "live")))
	if err != nil {
		t.Fatal(err)
	}
	if _, derived := sources["warehouse/write"]; derived || len(sources) != 1 {
		t.Fatalf("write: true against a binding with no write operation derives none: %+v", sources)
	}
	// Without an adapters directory the binaries are found on PATH; a
	// binding with one operation derives one source; the runtime is
	// docker by default.
	one := `{"bindingVersion":"1","platform":"docs","operations":{"history":{"shape":"airbyte","image":"airbyte/source-s3:4.0.0@` + testImageDigest + `","licence":"MIT"}}}`
	catalog = catalogWith(t, map[string]string{"docs": one})
	_, sources, err = load(t, engineJSON(t, catalog, ``, platformJSONFor(t, "policy-documents", "docs@"+digestOf(one), "engine-docs", ``, "history")))
	if err != nil {
		t.Fatal(err)
	}
	if len(sources) != 1 || sources["policy-documents/history"].argv[0] != "adapter-airbyte" || sources["policy-documents/history"].argv[3] != "--runtime=docker" ||
		!reflect.DeepEqual(sources["policy-documents/history"].env, []string{"HOME=/home/engine-docs"}) {
		t.Fatalf("one source, adapter on PATH, docker by default, HOME alone: %+v", sources)
	}
}

// Every departure from the configuration's shape is refused by name.
func TestEngineConfigRefusals(t *testing.T) {
	catalog := catalogWith(t, map[string]string{"postgres": postgresBinding})
	ref := "postgres@" + digestOf(postgresBinding)
	good := platformJSON(t, "warehouse", ref, "engine-warehouse", ``)
	base := engineJSON(t, catalog, ``, good)
	replace := func(old, new string) string { return strings.Replace(base, old, new, 1) }
	cases := []struct {
		name string
		text string
		want string
	}{
		{"not an object", `[]`, "not an object"},
		{"unknown member", engineJSON(t, catalog, `,"port":8787`, good), `unknown member "port"`},
		{"duplicate member", `{"engineVersion":"1","engineVersion":"1"}`, "duplicate"},
		{"missing member", replace(`"registry":"`, `"registryx":"`), `unknown member "registryx"`},
		{"wrong version", replace(`"engineVersion":"1"`, `"engineVersion":"2"`), `engineVersion "2" is not "1"`},
		{"identity without an audience", engineJSON(t, catalog, `,"identity":{"issuer":"https://login.example","keys":"`+abs(t, t.TempDir(), "keys.json")+`"}`, good), `missing member "audience"`},
		{"identity with an unknown member", engineJSON(t, catalog, `,"identity":{"issuer":"https://login.example","audience":"gateway:acme","keys":"`+abs(t, t.TempDir(), "keys.json")+`","jwksUrl":"https://x"}`, good), `unknown member "jwksUrl"`},
		{"identity with an empty issuer", engineJSON(t, catalog, `,"identity":{"issuer":"","audience":"gateway:acme","keys":"`+abs(t, t.TempDir(), "keys.json")+`"}`, good), "identity.issuer must be the token issuer"},
		{"identity keys relative", engineJSON(t, catalog, `,"identity":{"issuer":"https://login.example","audience":"gateway:acme","keys":"keys.json"}`, good), "identity.keys must be an absolute path"},
		{"listen not loopback", replace(`"listen":"127.0.0.1:8787"`, `"listen":"0.0.0.0:8787"`), "not a literal loopback address"},
		{"listen localhost by name", replace(`"listen":"127.0.0.1:8787"`, `"listen":"localhost:8787"`), "not a literal loopback address"},
		{"listen without port", replace(`"listen":"127.0.0.1:8787"`, `"listen":"127.0.0.1"`), "not host:port"},
		{"listen port out of range", replace(`"listen":"127.0.0.1:8787"`, `"listen":"127.0.0.1:65536"`), "has no valid port"},
		{"relative seed", replace(`"seed":"`, `"seed":"relative/`), "seed must be an absolute path"},
		{"relative catalog", replace(`"catalog":"`, `"catalog":"./`), "catalog must be an absolute path"},
		{"unclean store", replace(`"store":"`, `"store":"`+abs(t, t.TempDir())+`/../`), "store must be a clean path"},
		{"relative adapters", engineJSON(t, catalog, `,"adapters":"."`, good), "adapters must be an absolute path"},
		{"rootSigner not accepted", engineJSON(t, catalog, `,"rootSigner":true`, good), `rootSigner, when present, is the string "accepted"`},
		{"hostRuntime wrong word", engineJSON(t, catalog, `,"hostRuntime":"yes"`, good), `hostRuntime, when present, is the string "accepted"`},
		{"runtime not a string", engineJSON(t, catalog, `,"runtime":1`, good), "runtime must be a non-empty string"},
		{"platform name with slash", engineJSON(t, catalog, ``, `"a/b":{"binding":"`+ref+`","credentials":{"history":{"file":"/f"},"live":{"file":"/f"}},"user":"u"}`), `platform name "a/b"`},
		{"platform unknown member", engineJSON(t, catalog, ``, platformJSON(t, "warehouse", ref, "engine-warehouse", `,"command":"x"`)), `unknown member "command"`},
		{"platform without user", engineJSON(t, catalog, ``, `"warehouse":{"binding":"`+ref+`","credentials":{"history":{"file":"/f"},"live":{"file":"/f"}}}`), `missing member "user"`},
		{"platform empty user", engineJSON(t, catalog, ``, `"warehouse":{"binding":"`+ref+`","credentials":{"history":{"file":"`+abs(t, t.TempDir(), "f")+`"},"live":{"file":"`+abs(t, t.TempDir(), "g")+`"}},"user":""}`), "an adapter running as the signer could read the seed"},
		{"platform unknown user", engineJSON(t, catalog, ``, platformJSON(t, "warehouse", ref, "nobody-here", ``)), "platform warehouse: file does not exist"},
		{"credentials as a value", engineJSON(t, catalog, ``, `"warehouse":{"binding":"`+ref+`","credentials":{"env":"DATABASE_URL"},"user":"u"}`), `unknown member "env"`},
		{"credentials one file for all", engineJSON(t, catalog, ``, `"warehouse":{"binding":"`+ref+`","credentials":{"file":"/f"},"user":"u"}`), `unknown member "file"`},
		{"credentials naming no operation", engineJSON(t, catalog, ``, `"warehouse":{"binding":"`+ref+`","credentials":{},"user":"u"}`), "credentials names no operation"},
		{"credentials relative", engineJSON(t, catalog, ``, `"warehouse":{"binding":"`+ref+`","credentials":{"history":{"file":"secrets/w"},"live":{"file":"/f"}},"user":"engine-warehouse"}`), "credentials.history.file must be an absolute path"},
		{"credentials for an operation the binding lacks", engineJSON(t, catalog, ``, `"warehouse":{"binding":"`+ref+`","credentials":{"history":{"file":"`+abs(t, t.TempDir(), "f")+`"}},"user":"engine-warehouse"}`), "the binding offers live but credentials name no live file"},
		{"binding unpinned", engineJSON(t, catalog, ``, `"warehouse":{"binding":"postgres","credentials":{"history":{"file":"/f"},"live":{"file":"/f"}},"user":"u"}`), "binding must be name@sha256"},
		{"binding traversal", engineJSON(t, catalog, ``, `"warehouse":{"binding":"../postgres@`+digestOf(postgresBinding)+`","credentials":{"history":{"file":"/f"},"live":{"file":"/f"}},"user":"u"}`), "binding must be name@sha256"},
		{"binding digest mismatch", engineJSON(t, catalog, ``, platformJSON(t, "warehouse", "postgres@"+testImageDigest, "engine-warehouse", ``)), "does not digest to the pinned"},
		{"binding absent from the catalog", engineJSON(t, catalog, ``, platformJSON(t, "warehouse", "jira@"+testImageDigest, "engine-warehouse", ``)), "binding jira@"},
		{"write not a boolean", engineJSON(t, catalog, ``, platformJSON(t, "warehouse", ref, "engine-warehouse", `,"write":"yes"`)), "write, when present, is a boolean"},
		{"endpoint empty", engineJSON(t, catalog, ``, platformJSON(t, "warehouse", ref, "engine-warehouse", `,"endpoint":""`)), "endpoint, when present, is a non-empty string"},
		{"environment sets HOME", engineJSON(t, catalog, ``, platformJSON(t, "warehouse", ref, "engine-warehouse", `,"environment":{"HOME":"/x"}`)), "environment may not set HOME"},
		{"environment sets PATH", engineJSON(t, catalog, ``, platformJSON(t, "warehouse", ref, "engine-warehouse", `,"environment":{"PATH":"/x"}`)), "environment may not set PATH"},
		{"environment value not a string", engineJSON(t, catalog, ``, platformJSON(t, "warehouse", ref, "engine-warehouse", `,"environment":{"X":1}`)), "environment.X must be a string value"},
		{"environment key with equals", engineJSON(t, catalog, ``, platformJSON(t, "warehouse", ref, "engine-warehouse", `,"environment":{"A=B":"x"}`)), "environment.A=B must be a string value"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, _, err := load(t, tc.text)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("want %q, got %v", tc.want, err)
			}
		})
	}
}

// A catalog entry is held to its shape: pinned images, stated licences,
// the shape each operation is served by, no unknown operation or member,
// no restriction the acquisition does not yet apply.
func TestBindingRefusals(t *testing.T) {
	cases := map[string]string{
		`{"bindingVersion":"2","platform":"p","operations":{}}`: `bindingVersion "2"`,
		`{"bindingVersion":"1","platform":"p","operations":{}}`: "no history or live operation",
		`{"bindingVersion":"1","platform":"p","operations":{"history":{"shape":"airbyte","image":"airbyte/source-postgres:3.6.1","licence":"ELv2"}}}`:                                                           "image must be pinned",
		`{"bindingVersion":"1","platform":"p","operations":{"history":{"shape":"airbyte","image":"--label=probe@` + testImageDigest + `","licence":"ELv2"}}}`:                                                   "image must be pinned",
		`{"bindingVersion":"1","platform":"p","operations":{"live":{"shape":"mcp","server":{"image":"-x/mcp@` + testImageDigest + `"},"tools":["q"],"licence":"MIT"}}}`:                                         "server.image must be pinned",
		`{"bindingVersion":"1","platform":"p","operations":{"live":{"shape":"mcp","server":{"image":"x/mcp@` + testImageDigest + `","args":"--flag"},"tools":["q"],"licence":"MIT"}}}`:                          "server.args, when present, is a non-empty array",
		`{"bindingVersion":"1","platform":"p","operations":{"live":{"shape":"mcp","server":{"image":"x/mcp@` + testImageDigest + `","args":[]},"tools":["q"],"licence":"MIT"}}}`:                                "server.args, when present, is a non-empty array",
		`{"bindingVersion":"1","platform":"p","operations":{"live":{"shape":"mcp","server":{"image":"x/mcp@` + testImageDigest + `","args":[""]},"tools":["q"],"licence":"MIT"}}}`:                              "server.args must be non-empty strings without newlines",
		`{"bindingVersion":"1","platform":"p","operations":{"live":{"shape":"mcp","server":{"image":"x/mcp@` + testImageDigest + `","args":["a\nb"]},"tools":["q"],"licence":"MIT"}}}`:                          "server.args must be non-empty strings without newlines",
		`{"bindingVersion":"1","platform":"p","operations":{"live":{"shape":"mcp","server":{"image":"x/mcp@` + testImageDigest + `","args":[1]},"tools":["q"],"licence":"MIT"}}}`:                               "server.args must be non-empty strings without newlines",
		`{"bindingVersion":"1","platform":"p","operations":{"live":{"shape":"mcp","server":{"image":"x/mcp@` + testImageDigest + `"},"tools":["q"],"probe":{"tool":"other"},"licence":"MIT"}}}`:                 `probe "other" is not one of its tools`,
		`{"bindingVersion":"1","platform":"p","operations":{"live":{"shape":"mcp","server":{"image":"x/mcp@` + testImageDigest + `"},"tools":["q"],"probe":{"tool":"q","failure":""},"licence":"MIT"}}}`:        "probe.failure, when present, is the text a failed answer begins with",
		`{"bindingVersion":"1","platform":"p","operations":{"live":{"shape":"mcp","server":{"image":"x/mcp@` + testImageDigest + `"},"tools":["q"],"probe":{"tool":"q","text":"x"},"licence":"MIT"}}}`:          `unknown member "text"`,
		`{"bindingVersion":"1","platform":"p","operations":{"live":{"shape":"mcp","server":{"image":"x/mcp@` + testImageDigest + `"},"tools":["q"],"probe":{"tool":"q","failure":" Error:"},"licence":"MIT"}}}`: "probe.failure may not begin or end with whitespace",
		`{"bindingVersion":"1","platform":"p","operations":{"live":{"shape":"mcp","server":{"image":"x/mcp@` + testImageDigest + `"},"tools":["q"],"probe":"q","licence":"MIT"}}}`:                              "probe, when present, is an object naming a tool",
		`{"bindingVersion":"1","platform":"p","operations":{"history":{"shape":"airbyte","image":"x@` + testImageDigest + `"}}}`:                                                                                "licence must be stated",
		`{"bindingVersion":"1","platform":"p","operations":{"history":{"shape":"airbyte","image":"x@` + testImageDigest + `","licence":"MIT","streams":["a"]}}}`:                                                `unknown member "streams"`,
		`{"bindingVersion":"1","platform":"p","operations":{"history":{"shape":"mcp","server":{"image":"x@` + testImageDigest + `"},"tools":["q"],"licence":"MIT"}}}`:                                           "operation history is served by the airbyte shape",
		`{"bindingVersion":"1","platform":"p","operations":{"live":{"shape":"airbyte","image":"x@` + testImageDigest + `","licence":"MIT"}}}`:                                                                   "operation live is served by the mcp shape",
		`{"bindingVersion":"1","platform":"p","operations":{"live":{"shape":"mcp","server":{"image":"x@` + testImageDigest + `"},"tools":[],"licence":"MIT"}}}`:                                                 "tools must be a non-empty array",
		`{"bindingVersion":"1","platform":"p","operations":{"live":{"shape":"mcp","server":{"image":"x@` + testImageDigest + `"},"tools":["a,b"],"licence":"MIT"}}}`:                                            "without commas",
		`{"bindingVersion":"1","platform":"p","operations":{"live":{"shape":"mcp","server":{"image":"x@` + testImageDigest + `","pull":"always"},"tools":["q"],"licence":"MIT"}}}`:                              `unknown member "pull"`,
		`{"bindingVersion":"1","platform":"p","operations":{"live":{"shape":"mcp","server":{},"tools":["q"],"licence":"MIT"}}}`:                                                                                 `missing member "image"`,
		`{"bindingVersion":"1","platform":"p","operations":{"live":{"shape":"http","licence":"MIT"}}}`:                                                                                                          "http shape is not shipped",
		`{"bindingVersion":"1","platform":"p","operations":{"sync":{"shape":"airbyte","image":"x@` + testImageDigest + `","licence":"MIT"}}}`:                                                                   `unknown operation "sync"`,
		`{"bindingVersion":"1","platform":"p","operations":{"history":{"shape":"airbyte","image":"x@` + testImageDigest + `","licence":"MIT"}},"extra":1}`:                                                      `unknown member "extra"`,
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

// ownership stands the filesystem in: a map of paths to owners, and the
// links among them to their targets (a link's entry has link set; where it
// points is in targets).
type ownership map[string]fileOwnership

var linkTargets = map[string]string{}

func (o ownership) owner(path string) (fileOwnership, error) {
	if fo, ok := o[path]; ok {
		return fo, nil
	}
	return fileOwnership{}, os.ErrNotExist
}

// readLinkStub is where a stub link points.
func readLinkStub(path string) (string, error) {
	if target, ok := linkTargets[path]; ok {
		return target, nil
	}
	return "", os.ErrNotExist
}

// A filesystem in which everything the configuration names is as it should
// be: root-owned traversable directories, credentials owned by the
// platform's user and private, the seed under the signer's own directory.
func goodFilesystem(seed, credentials string, signer, adapter int) ownership {
	fs := ownership{}
	for _, path := range []string{seed, credentials} {
		for dir := filepath.Dir(path); ; dir = filepath.Dir(dir) {
			fs[dir] = fileOwnership{uid: 0, mode: 0o755, dir: true}
			if filepath.Dir(dir) == dir {
				break
			}
		}
	}
	fs[filepath.Dir(seed)] = fileOwnership{uid: signer, mode: 0o700, dir: true}
	fs[seed] = fileOwnership{uid: signer, mode: 0o600}
	fs[credentials] = fileOwnership{uid: adapter, mode: 0o600}
	return fs
}

// The refusals the isolation claim depends on, with the filesystem, the
// user database and the kernel stood in for.
func ptr(c engineConfig) *engineConfig {
	copied := c
	copied.platforms = append([]platformConfig(nil), c.platforms...)
	for i := range copied.platforms {
		credentials := map[string]string{}
		for op, path := range copied.platforms[i].credentials {
			credentials[op] = path
		}
		copied.platforms[i].credentials = credentials
	}
	return &copied
}

func TestComponentsSplitOnEverySeparatorThePlatformAccepts(t *testing.T) {
	// A link target may be written with "/" where the platform also
	// accepts another separator; each element must still be walked.
	root := filepath.VolumeName(abs(t, t.TempDir())) + string(filepath.Separator)
	got := components(filepath.Join(root, "hop") + "/../secrets")
	if want := []string{"hop", "..", "secrets"}; !slices.Equal(got, want) {
		t.Fatalf("components = %q, want %q", got, want)
	}
	if got := components(root); len(got) != 0 {
		t.Fatalf("the root has no components, got %q", got)
	}
}

func TestEngineRefusalsForIsolation(t *testing.T) {
	seed := filepath.Join(string(filepath.Separator), "var", "lib", "engine", "gateway.seed")
	credentials := filepath.Join(string(filepath.Separator), "run", "secrets", "warehouse")
	both := func(path string) map[string]string { return map[string]string{"history": path, "live": path} }
	cfg := engineConfig{runtime: "docker", seed: seed, platforms: []platformConfig{{name: "warehouse", credentials: both(credentials), user: "engine-warehouse", uid: 1001}}}
	noSockets := []string{filepath.Join(t.TempDir(), "absent.sock")}
	socket := filepath.Join(t.TempDir(), "docker.sock")
	os.WriteFile(socket, nil, 0o600)
	// Links resolve as the stub filesystem says; a path with none resolves
	// to itself.
	host := func(euid int, fs ownership, sockets []string, caps func() capabilitySets) engineHost {
		return engineHost{euid: euid, sockets: func(string) []string { return sockets }, capabilities: caps, fileOwner: fs.owner, readLink: readLinkStub}
	}
	three := uint64(1<<capSetuid | 1<<capSetgid | 1<<capKill)
	noCaps := func() capabilitySets { return capabilitySets{known: true, effective: three, permitted: three} }
	good := goodFilesystem(seed, credentials, 1000, 1001)

	if statements, err := engineRefusals(ptr(cfg), host(1000, good, noSockets, noCaps)); err != nil || len(statements) != 0 {
		t.Fatalf("a non-root signer beside a platform user with private credentials starts silently: %v %v", err, statements)
	}
	expect := func(name string, h engineHost, c engineConfig, want string) {
		t.Helper()
		if _, err := engineRefusals(ptr(c), h); err == nil || !strings.Contains(err.Error(), want) {
			t.Fatalf("%s: want %q, got %v", name, want, err)
		}
	}
	asRoot := goodFilesystem(seed, credentials, 0, 1001)
	expect("root signer", host(0, asRoot, noSockets, noCaps), cfg, "the signer runs as root")
	accepted := cfg
	accepted.rootSigner = true
	if statements, err := engineRefusals(ptr(accepted), host(0, asRoot, noSockets, noCaps)); err != nil || len(statements) != 1 || !strings.Contains(statements[0], "rootSigner accepted") {
		t.Fatalf("an accepted root signer starts with a statement: %v %v", err, statements)
	}
	// The binary itself: with file capabilities, executable by its owner
	// alone; without them, its mode is nobody's concern here.
	exe := func(mode os.FileMode, capabilities bool) engineHost {
		h := host(1000, good, noSockets, noCaps)
		h.executable = func() (exeFacts, error) {
			return exeFacts{path: "/usr/local/bin/gateway", mode: mode, capabilities: capabilities}, nil
		}
		return h
	}
	expect("a capability-bearing binary others may execute", exe(0o755, true), cfg, "carries file capabilities and is executable by others (mode 0755)")
	expect("a capability-bearing binary the group may execute", exe(0o710, true), cfg, "executable by others (mode 0710)")
	for _, h := range []engineHost{exe(0o700, true), exe(0o755, false)} {
		if _, err := engineRefusals(ptr(cfg), h); err != nil {
			t.Fatalf("a binary others cannot execute, or one without capabilities: %v", err)
		}
	}
	asRootExe := exe(0o755, true)
	asRootExe.euid, asRootExe.fileOwner = 0, asRoot.owner
	expect("root's capability-bearing binary others may execute", asRootExe, accepted, "carries file capabilities and is executable by others")
	failing := host(1000, good, noSockets, noCaps)
	failing.executable = func() (exeFacts, error) { return exeFacts{}, errors.New("stat: gone") }
	expect("a binary that cannot be looked at", failing, cfg, "the gateway binary: stat: gone")
	expect("effective DAC capability", host(1000, good, noSockets, func() capabilitySets {
		return capabilitySets{known: true, effective: three | 1<<capDacOverride, permitted: three}
	}), cfg, "CAP_DAC_OVERRIDE or CAP_DAC_READ_SEARCH")
	expect("permitted-only DAC capability", host(1000, good, noSockets, func() capabilitySets {
		return capabilitySets{known: true, effective: three, permitted: three | 1<<capDacReadSearch}
	}), cfg, "CAP_DAC_OVERRIDE or CAP_DAC_READ_SEARCH")
	expect("ambient capabilities", host(1000, good, noSockets, func() capabilitySets {
		return capabilitySets{known: true, effective: three, permitted: three, ambient: 1 << capSetuid}
	}), cfg, "holds ambient capabilities")
	expect("inheritable capabilities", host(1000, good, noSockets, func() capabilitySets {
		return capabilitySets{known: true, effective: three, permitted: three, inheritable: 1 << capSetuid}
	}), cfg, "holds inheritable capabilities")
	if _, err := engineRefusals(ptr(cfg), host(1000, good, noSockets, func() capabilitySets { return capabilitySets{} })); err != nil {
		t.Fatalf("where the kernel reports no capabilities, none are judged: %v", err)
	}

	rootUser := cfg
	rootUser.platforms = []platformConfig{{name: "warehouse", credentials: both(credentials), user: "root", uid: 0}}
	expect("platform user root", host(1000, goodFilesystem(seed, credentials, 1000, 0), noSockets, noCaps), rootUser, "user root is root")
	expect("platform user is the signer", host(1001, goodFilesystem(seed, credentials, 1001, 1001), noSockets, noCaps), cfg, "is the signer's own")
	shared := cfg
	shared.platforms = []platformConfig{
		{name: "docs", credentials: both(credentials), user: "engine-warehouse", uid: 1001},
		{name: "warehouse", credentials: both(credentials), user: "also-warehouse", uid: 1001},
	}
	expect("two platforms one user", host(1000, good, noSockets, noCaps), shared, "is also platform docs's")

	wrongOwner := goodFilesystem(seed, credentials, 1000, 1000)
	expect("credentials owned by the signer", host(1000, wrongOwner, noSockets, noCaps), cfg, "must be owned by engine-warehouse")
	open := goodFilesystem(seed, credentials, 1000, 1001)
	open[credentials] = fileOwnership{uid: 1001, mode: 0o640}
	expect("credentials readable beyond their owner", host(1000, open, noSockets, noCaps), cfg, "readable beyond its owner (mode 0640)")
	writableDir := goodFilesystem(seed, credentials, 1000, 1001)
	writableDir[filepath.Dir(credentials)] = fileOwnership{uid: 0, mode: 0o777, dir: true}
	expect("credentials directory writable by others", host(1000, writableDir, noSockets, noCaps), cfg, "writable beyond its owner (mode 0777) without the sticky bit")
	stickyDir := goodFilesystem(seed, credentials, 1000, 1001)
	stickyDir[filepath.Dir(credentials)] = fileOwnership{uid: 0, mode: 0o777, dir: true, sticky: true}
	if _, err := engineRefusals(ptr(cfg), host(1000, stickyDir, noSockets, noCaps)); err != nil {
		t.Fatalf("a sticky directory keeps others from replacing what is under it: %v", err)
	}
	foreignDir := goodFilesystem(seed, credentials, 1000, 1001)
	foreignDir[filepath.Dir(credentials)] = fileOwnership{uid: 1002, mode: 0o755, dir: true}
	expect("credentials directory owned by another user", host(1000, foreignDir, noSockets, noCaps), cfg, "owned by uid 1002, neither root nor uid 1001")
	closedDir := goodFilesystem(seed, credentials, 1000, 1001)
	closedDir[filepath.Dir(credentials)] = fileOwnership{uid: 0, mode: 0o700, dir: true}
	expect("credentials directory the adapter cannot traverse", host(1000, closedDir, noSockets, noCaps), cfg, "cannot be traversed by uid 1001")
	// Traversal is judged by the class that applies: a directory the user
	// owns without its owner's execute bit is closed to the user however
	// open it is to others; one the user owns with it is open to the user
	// however closed to others.
	ownedClosed := goodFilesystem(seed, credentials, 1000, 1001)
	ownedClosed[filepath.Dir(credentials)] = fileOwnership{uid: 1001, mode: 0o655, dir: true}
	expect("credentials directory owned by the user without its execute bit", host(1000, ownedClosed, noSockets, noCaps), cfg, "cannot be traversed by uid 1001")
	ownedPrivate := goodFilesystem(seed, credentials, 1000, 1001)
	ownedPrivate[filepath.Dir(credentials)] = fileOwnership{uid: 1001, mode: 0o700, dir: true}
	if _, err := engineRefusals(ptr(cfg), host(1000, ownedPrivate, noSockets, noCaps)); err != nil {
		t.Fatalf("a private directory of the user's own is traversable by the user: %v", err)
	}
	seedDir := goodFilesystem(seed, credentials, 1000, 1001)
	seedDir[filepath.Dir(seed)] = fileOwnership{uid: 1000, mode: 0o770, dir: true}
	expect("seed directory writable by its group", host(1000, seedDir, noSockets, noCaps), cfg, "seed: ")

	// A symbolic link among the configured components: root's is a
	// system's own and is allowed, its target's directories held; anyone
	// else's could be retargeted and is refused; and a link a platform user
	// placed in their own directory pointing into trusted directories is
	// refused for the link, not for its target.
	root := string(filepath.Separator)
	plainSeed := filepath.Join(root, "srv", "engine", "gateway.seed")
	linked := filepath.Join(root, "var", "secrets", "warehouse")
	target := filepath.Join(root, "private", "var", "secrets", "warehouse")
	// /var is root's link to /private/var; the walk goes through the
	// target's components, so the configured chain never looks under /var
	// itself.
	viaLink := goodFilesystem(plainSeed, target, 1000, 1001)
	viaLink[filepath.Join(root, "var")] = fileOwnership{uid: 0, mode: 0o755, link: true}
	linkTargets[filepath.Join(root, "var")] = filepath.Join(root, "private", "var")
	linkedCfg := cfg
	linkedCfg.seed = plainSeed
	linkedCfg.platforms = []platformConfig{{name: "warehouse", credentials: both(linked), user: "engine-warehouse", uid: 1001}}
	resolved := ptr(linkedCfg)
	if _, err := engineRefusals(resolved, host(1000, viaLink, noSockets, noCaps)); err != nil {
		t.Fatalf("a root-owned link among the components is a system's own: %v", err)
	}
	if resolved.platforms[0].credentials["history"] != target {
		t.Fatalf("the path used from here on is the resolved one: %s", resolved.platforms[0].credentials)
	}
	// The target's components are held: a root-owned link into a directory
	// another user owns is refused for that directory.
	badTarget := goodFilesystem(plainSeed, target, 1000, 1001)
	badTarget[filepath.Join(root, "var")] = fileOwnership{uid: 0, mode: 0o755, link: true}
	badTarget[filepath.Join(root, "private", "var")] = fileOwnership{uid: 1002, mode: 0o755, dir: true}
	expect("a root-owned link into another user's directory", host(1000, badTarget, noSockets, noCaps), linkedCfg, filepath.Join(root, "private", "var")+" is owned by uid 1002")
	// A root-owned link whose target passes through another user's link:
	// every hop is held, and the second link's owner refuses it.
	hops := goodFilesystem(plainSeed, target, 1000, 1001)
	hops[filepath.Join(root, "entry")] = fileOwnership{uid: 0, mode: 0o755, link: true}
	linkTargets[filepath.Join(root, "entry")] = filepath.Join(root, "home", "other", "hop")
	hops[filepath.Join(root, "home")] = fileOwnership{uid: 0, mode: 0o755, dir: true}
	hops[filepath.Join(root, "home", "other")] = fileOwnership{uid: 0, mode: 0o755, dir: true}
	hops[filepath.Join(root, "home", "other", "hop")] = fileOwnership{uid: 1002, mode: 0o777, link: true}
	linkTargets[filepath.Join(root, "home", "other", "hop")] = filepath.Join(root, "private", "var", "secrets")
	hopCfg := cfg
	hopCfg.seed = plainSeed
	hopCfg.platforms = []platformConfig{{name: "warehouse", credentials: both(filepath.Join(root, "entry", "warehouse")), user: "engine-warehouse", uid: 1001}}
	expect("a root-owned link through another user's link", host(1000, hops, noSockets, noCaps), hopCfg, filepath.Join(root, "home", "other", "hop")+" is a symbolic link owned by uid 1002, not root")
	hops[filepath.Join(root, "home", "other", "hop")] = fileOwnership{uid: 0, mode: 0o755, link: true}
	hops[filepath.Join(root, "home", "other")] = fileOwnership{uid: 1002, mode: 0o755, dir: true}
	expect("a root-owned link through another user's directory", host(1000, hops, noSockets, noCaps), hopCfg, filepath.Join(root, "home", "other")+" is owned by uid 1002")
	hops[filepath.Join(root, "home", "other")] = fileOwnership{uid: 0, mode: 0o755, dir: true}
	resolvedHops := ptr(hopCfg)
	if _, err := engineRefusals(resolvedHops, host(1000, hops, noSockets, noCaps)); err != nil || resolvedHops.platforms[0].credentials["history"] != target {
		t.Fatalf("two root-owned hops resolve to the target: %v %s", err, resolvedHops.platforms[0].credentials)
	}
	// A link the platform's own user placed, in the user's own directory,
	// is refused as a link: only root's links are a system's own.
	owned := goodFilesystem(plainSeed, target, 1000, 1001)
	owned[filepath.Join(root, "srv")] = fileOwnership{uid: 0, mode: 0o755, dir: true}
	owned[filepath.Join(root, "srv", "mine")] = fileOwnership{uid: 1001, mode: 0o700, dir: true}
	owned[filepath.Join(root, "srv", "mine", "link")] = fileOwnership{uid: 1001, mode: 0o777, link: true}
	linkTargets[filepath.Join(root, "srv", "mine", "link")] = filepath.Join(root, "private", "var", "secrets")
	ownedCfg := cfg
	ownedCfg.seed = plainSeed
	ownedCfg.platforms = []platformConfig{{name: "warehouse", credentials: both(filepath.Join(root, "srv", "mine", "link", "warehouse")), user: "engine-warehouse", uid: 1001}}
	expect("a link owned by the platform's own user", host(1000, owned, noSockets, noCaps), ownedCfg, filepath.Join(root, "srv", "mine", "link")+" is a symbolic link owned by uid 1001, not root")
	// A target is walked as written, never cleaned first: "hop/../secrets"
	// follows hop (a link elsewhere) before ".." applies, so the walk
	// arrives where the kernel would and holds what it passes through.
	written := goodFilesystem(plainSeed, filepath.Join(root, "opt", "release", "secrets", "warehouse"), 1000, 1001)
	written[filepath.Join(root, "srv")] = fileOwnership{uid: 0, mode: 0o755, dir: true}
	written[filepath.Join(root, "srv", "entry")] = fileOwnership{uid: 0, mode: 0o755, link: true}
	linkTargets[filepath.Join(root, "srv", "entry")] = "hop" + string(filepath.Separator) + ".." + string(filepath.Separator) + "secrets"
	written[filepath.Join(root, "srv", "hop")] = fileOwnership{uid: 0, mode: 0o755, link: true}
	linkTargets[filepath.Join(root, "srv", "hop")] = filepath.Join(root, "opt", "release", "subdir")
	written[filepath.Join(root, "opt", "release", "subdir")] = fileOwnership{uid: 0, mode: 0o755, dir: true}
	written[filepath.Join(root, "srv", "secrets")] = fileOwnership{uid: 1002, mode: 0o755, dir: true} // where cleaning first would wrongly arrive
	writtenCfg := cfg
	writtenCfg.seed = plainSeed
	writtenCfg.platforms = []platformConfig{{name: "warehouse", credentials: both(filepath.Join(root, "srv", "entry", "warehouse")), user: "engine-warehouse", uid: 1001}}
	arrived := ptr(writtenCfg)
	if _, err := engineRefusals(arrived, host(1000, written, noSockets, noCaps)); err != nil {
		t.Fatalf("a target with .. after a link is walked as the kernel walks it: %v", err)
	}
	if arrived.platforms[0].credentials["history"] != filepath.Join(root, "opt", "release", "secrets", "warehouse") {
		t.Fatalf("the walk must arrive where the kernel would: %s", arrived.platforms[0].credentials)
	}
	written[filepath.Join(root, "srv", "hop")] = fileOwnership{uid: 1002, mode: 0o755, link: true}
	expect("a hop that cleaning would erase is held", host(1000, written, noSockets, noCaps), writtenCfg, filepath.Join(root, "srv", "hop")+" is a symbolic link owned by uid 1002")
	empty := goodFilesystem(plainSeed, target, 1000, 1001)
	empty[filepath.Join(root, "var")] = fileOwnership{uid: 0, mode: 0o755, link: true}
	linkTargets[filepath.Join(root, "var")] = ""
	expect("a link with an empty target", host(1000, empty, noSockets, noCaps), cfg, filepath.Join(root, "var")+" is a symbolic link with an empty target")
	linkTargets[filepath.Join(root, "var")] = filepath.Join(root, "private", "var")
	loop := goodFilesystem(plainSeed, target, 1000, 1001)
	loop[filepath.Join(root, "loop")] = fileOwnership{uid: 0, mode: 0o755, link: true}
	linkTargets[filepath.Join(root, "loop")] = filepath.Join(root, "loop")
	loopCfg := cfg
	loopCfg.seed = plainSeed
	loopCfg.platforms = []platformConfig{{name: "warehouse", credentials: both(filepath.Join(root, "loop", "warehouse")), user: "engine-warehouse", uid: 1001}}
	expect("a link loop", host(1000, loop, noSockets, noCaps), loopCfg, "more than 32 symbolic links")
	viaLink[filepath.Join(root, "var")] = fileOwnership{uid: 1002, mode: 0o755, link: true}
	expect("a link owned by another user", host(1000, viaLink, noSockets, noCaps), linkedCfg, "symbolic link owned by uid 1002, not root")
	ownLink := filepath.Join(root, "home", "other", "link", "warehouse")
	own := goodFilesystem(plainSeed, target, 1000, 1001)
	own[filepath.Join(root, "home")] = fileOwnership{uid: 0, mode: 0o755, dir: true}
	own[filepath.Join(root, "home", "other")] = fileOwnership{uid: 1002, mode: 0o755, dir: true}
	own[filepath.Join(root, "home", "other", "link")] = fileOwnership{uid: 1002, mode: 0o777, link: true}
	linkTargets[filepath.Join(root, "home", "other", "link")] = filepath.Join(root, "private", "var", "secrets")
	ownCfg := cfg
	ownCfg.seed = plainSeed
	ownCfg.platforms = []platformConfig{{name: "warehouse", credentials: both(ownLink), user: "engine-warehouse", uid: 1001}}
	expect("a link in another user's directory into trusted directories", host(1000, own, noSockets, noCaps), ownCfg, "owned by uid 1002, neither root nor uid 1001")
	// The credentials file itself may not be a link.
	fileLink := goodFilesystem(seed, credentials, 1000, 1001)
	fileLink[credentials] = fileOwnership{uid: 1001, mode: 0o600, link: true}
	expect("credentials that is a link", host(1000, fileLink, noSockets, noCaps), cfg, "is a symbolic link")
	missing := goodFilesystem(seed, credentials, 1000, 1001)
	delete(missing, credentials)
	expect("credentials absent", host(1000, missing, noSockets, noCaps), cfg, "credentials.history: file does not exist")

	expect("host runtime socket", host(1000, good, []string{socket}, noCaps), cfg, "host container runtime socket is present")
	accepted = cfg
	accepted.hostRuntime = true
	if statements, err := engineRefusals(ptr(accepted), host(1000, good, []string{socket}, noCaps)); err != nil || len(statements) != 1 || !strings.Contains(statements[0], "hostRuntime accepted") {
		t.Fatalf("an accepted host runtime starts with a statement: %v %v", err, statements)
	}
}

// The host runtime's sockets are looked up by the command's base name, so a
// runtime given by path is held to the same check.
func TestHostRuntimeSocketsByBaseName(t *testing.T) {
	for runtime, want := range map[string]string{
		"docker": "/var/run/docker.sock", "/usr/bin/docker": "/var/run/docker.sock", "docker.exe": "/var/run/docker.sock",
		"podman": "/run/podman/podman.sock", "/usr/local/bin/podman": "/run/podman/podman.sock",
	} {
		if got := hostRuntimeSockets(runtime); len(got) != 1 || got[0] != want {
			t.Errorf("%s: %v", runtime, got)
		}
	}
	if got := hostRuntimeSockets("/opt/standin"); got != nil {
		t.Errorf("an unknown runtime names no socket: %v", got)
	}
}

// `serve --config` reaches the isolation refusals before the seed is
// loaded, before any switching is attempted, and before anything is
// written: with the real filesystem and user database, a platform whose
// user is this process's own is refused as such on Unix, and the
// configuration form is refused outright where users cannot be switched.
func TestServeConfigRefusesBeforeWriting(t *testing.T) {
	dir := t.TempDir()
	store := filepath.Join(dir, "store")
	catalog := catalogWith(t, map[string]string{"postgres": postgresBinding})
	self, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	credentials := filepath.Join(dir, "warehouse.json")
	os.WriteFile(credentials, []byte(`{}`), 0o600)
	text := `{"engineVersion":"1","authority":"gateway:test","seed":"` + abs(t, dir, "gateway.seed") + `","store":"` + abs(t, store) + `",` +
		`"registry":"` + abs(t, dir, "registry.jsonl") + `","decisionRecords":"` + abs(t, dir, "decisions") + `","listen":"127.0.0.1:0",` +
		`"catalog":"` + abs(t, catalog) + `","platforms":{"warehouse":{"binding":"postgres@` + digestOf(postgresBinding) + `","credentials":{"history":{"file":"` + abs(t, credentials) + `"},"live":{"file":"` + abs(t, credentials) + `"}},"user":"` + self.Username + `"}}}`
	path := filepath.Join(dir, "engine.json")
	os.WriteFile(path, []byte(text), 0o600)
	stderr := captureStderr(t)
	code := cmdServe([]string{"--config", path})
	out := stderr()
	if code != 1 {
		t.Fatalf("exit %d, want 1: %s", code, out)
	}
	if runtime.GOOS == "windows" {
		if !strings.Contains(out, "does not switch to") {
			t.Fatalf("the configuration form is refused where users cannot be switched: %q", out)
		}
	} else if os.Geteuid() == 0 {
		if !strings.Contains(out, "the signer runs as root") {
			t.Fatalf("a root signer is refused first: %q", out)
		}
	} else if !strings.Contains(out, "is the signer's own") {
		t.Fatalf("the isolation refusal is reached through the command line: %q", out)
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

// A configuration or binding is read through one descriptor, judged as the
// file that was opened, and refused past its bound or when it is no
// regular file.
func TestReadBounded(t *testing.T) {
	dir := t.TempDir()
	small := filepath.Join(dir, "small.json")
	os.WriteFile(small, []byte(`{}`), 0o600)
	if data, err := readBounded(small, 16); err != nil || string(data) != "{}" {
		t.Fatalf("a small file is read: %q %v", data, err)
	}
	big := filepath.Join(dir, "big.json")
	os.WriteFile(big, make([]byte, 17), 0o600)
	if _, err := readBounded(big, 16); err == nil || !strings.Contains(err.Error(), "larger than 16 bytes") {
		t.Fatalf("a file past the bound is refused: %v", err)
	}
	if _, err := readBounded(dir, 16); err == nil || !strings.Contains(err.Error(), "not a regular file") {
		t.Fatalf("a directory is refused: %v", err)
	}
	// Consumption stops one byte past the bound, whatever the file holds.
	file, err := os.Open(big)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	if _, err := readBoundedFrom(file, big, 4); err == nil || !strings.Contains(err.Error(), "larger than 4 bytes") {
		t.Fatalf("past the bound is refused: %v", err)
	}
	if offset, _ := file.Seek(0, 1); offset != 5 {
		t.Fatalf("read %d bytes of a 17-byte file, want the bound plus one", offset)
	}
}

// A failure prefix of "--" reaches the adapter as one word, flag=value,
// not as the delimiter the adapter splits its line at.
func TestAProbeFailureOfTwoDashesReachesTheAdapter(t *testing.T) {
	binding := `{"bindingVersion":"1","platform":"postgres","operations":{"live":{"shape":"mcp","server":{"image":"x/mcp@` + testImageDigest + `"},"tools":["q"],"probe":{"tool":"q","failure":"--"},"licence":"MIT"}}}`
	catalog := catalogWith(t, map[string]string{"postgres": binding})
	_, sources, err := load(t, engineJSON(t, catalog, ``, platformJSONFor(t, "warehouse", "postgres@"+digestOf(binding), "engine-warehouse", ``, "live")))
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(sources["warehouse/live"].check, " "); got != "--probe=q --probe-failure=--" {
		t.Fatalf("check arguments: %q", got)
	}
	// A tool named "--" likewise: one word with its flag, never the
	// delimiter.
	binding = `{"bindingVersion":"1","platform":"postgres","operations":{"live":{"shape":"mcp","server":{"image":"x/mcp@` + testImageDigest + `"},"tools":["--","q"],"probe":{"tool":"--"},"licence":"MIT"}}}`
	catalog = catalogWith(t, map[string]string{"postgres": binding})
	_, sources, err = load(t, engineJSON(t, catalog, ``, platformJSONFor(t, "warehouse", "postgres@"+digestOf(binding), "engine-warehouse", ``, "live")))
	if err != nil {
		t.Fatal(err)
	}
	argv := strings.Join(sources["warehouse/live"].argv, " ")
	if !strings.Contains(argv, " --tools=--,q ") && !strings.HasSuffix(argv, " --tools=--,q") || strings.Join(sources["warehouse/live"].check, " ") != "--probe=--" {
		t.Fatalf("a tool named --: %s %q", argv, sources["warehouse/live"].check)
	}
}

// A platform name is a word an operator reads: graphic characters only.
func TestPlatformNamesAreGraphic(t *testing.T) {
	for _, name := range []string{"warehouse", "ware house", "wäre-house.1", "docs_2"} {
		if err := validPlatformName(name); err != nil {
			t.Errorf("%q: %v", name, err)
		}
	}
	for _, name := range []string{"ware\nhouse", "ware\rhouse", "ware\x1b[2Jhouse", "ware\thouse", "ware\u200bhouse", "", " warehouse", "ware/house", "ware=house", "ware\x00house"} {
		if err := validPlatformName(name); err == nil {
			t.Errorf("%q: allowed", name)
		}
	}
	if err := validPlatformName("ware\nhouse"); err == nil || !strings.Contains(err.Error(), "non-graphic character") {
		t.Fatalf("a control character is named as the reason: %v", err)
	}
}
