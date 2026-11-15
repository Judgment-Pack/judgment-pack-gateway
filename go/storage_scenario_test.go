//go:build unix

package main

// The storage kinds through the binary (scripts/checks/storage-scenario.sh,
// run by the CI job postgresql): the binary GATEWAY_SCENARIO_GATEWAY names
// migrates the PostgreSQL kind, and exports, checks and verifies what a
// start on it wrote, and the export is held to the binary's export of the
// same calls on the filesystem kind; and, with GATEWAY_SCENARIO_MAIN_GATEWAY naming main's
// binary, a store a configuration without storage wrote is exported by
// each, byte for byte alike. The serving itself runs in this process
// (scenarioWork).

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// scenarioBinary is the binary a variable names, or a skip: the test
// builds nothing and starts no program by name.
func scenarioBinary(t *testing.T, variable string) string {
	t.Helper()
	path := os.Getenv(variable)
	if path == "" {
		t.Skipf("%s names no binary; scripts/checks/storage-scenario.sh names one", variable)
	}
	if !filepath.IsAbs(path) {
		t.Fatalf("%s is a path, absolute", variable)
	}
	return path
}

// binaryRun runs the binary to its end and returns its exit code and
// streams.
func binaryRun(t *testing.T, binary string, stdin []byte, args ...string) (int, string, string) {
	t.Helper()
	cmd := exec.Command(binary, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdin, cmd.Stdout, cmd.Stderr = bytes.NewReader(stdin), &stdout, &stderr
	err := cmd.Run()
	if err != nil && cmd.ProcessState == nil {
		t.Fatalf("%s: %v", strings.Join(args, " "), err)
	}
	return cmd.ProcessState.ExitCode(), stdout.String(), stderr.String()
}

func scenarioGet(t *testing.T, url string) []byte {
	t.Helper()
	resp, err := http.Get(url)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var body bytes.Buffer
	body.ReadFrom(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("%s: %d %s", url, resp.StatusCode, body.String())
	}
	return body.Bytes()
}

// scenarioState is a state directory with a seed the binary made.
func scenarioState(t *testing.T, binary string) (dir, publicKey string) {
	t.Helper()
	dir = tempDirAt(t, 0o700)
	code, stdout, stderr := binaryRun(t, binary, nil, "keygen", filepath.Join(dir, "gateway.seed"))
	if code != 0 {
		t.Fatalf("keygen: %d %s", code, stderr)
	}
	for _, line := range strings.Split(stdout, "\n") {
		if key, ok := strings.CutPrefix(line, "publicKey "); ok {
			publicKey = strings.TrimSpace(key)
		}
	}
	if len(publicKey) != 64 {
		t.Fatalf("keygen named no public key: %q", stdout)
	}
	if err := os.Mkdir(filepath.Join(dir, "decisions"), 0o700); err != nil {
		t.Fatal(err)
	}
	return dir, publicKey
}

// exportAndVerify exports the configuration's store, checks the export
// against its manifest and verifies it under the public key, each by the
// binary.
func exportAndVerify(t *testing.T, binary, config, out, authority, publicKey string) []string {
	t.Helper()
	var said []string
	code, stdout, stderr := binaryRun(t, binary, nil, "export", "--config", config, "--out", out)
	said = append(said, stdout, stderr)
	if code != 0 {
		t.Fatalf("export: %d %s %s", code, stdout, stderr)
	}
	code, stdout, stderr = binaryRun(t, binary, nil, "export", "--check", out)
	said = append(said, stdout, stderr)
	if code != 0 || !strings.Contains(stdout, `"ok":true`) {
		t.Fatalf("export --check: %d %s %s", code, stdout, stderr)
	}
	args := []string{"verify", filepath.Join(out, "store"), filepath.Join(out, "registry"), authority}
	if _, err := os.Stat(filepath.Join(out, "decision-records")); err == nil {
		args = append(args, "--decision-records", filepath.Join(out, "decision-records"))
	}
	code, stdout, stderr = binaryRun(t, binary, []byte(publicKey+"\n"), args...)
	said = append(said, stdout, stderr)
	var verdict struct {
		OK bool `json:"ok"`
	}
	if code != 0 || json.Unmarshal([]byte(stdout), &verdict) != nil || !verdict.OK {
		t.Fatalf("verify: %d %s %s", code, stdout, stderr)
	}
	return said
}

// scenarioWork is one acquisition and its seal, over HTTP, against a
// service in this process: serve --config refuses a configuration without
// a platform, and a platform's source runs as its own user, which only a
// start as root can switch to.
func scenarioWork(t *testing.T, service *gatewayService) []string {
	t.Helper()
	server := httptest.NewServer(service.handler())
	defer server.Close()
	var said []string
	for _, call := range []struct{ path, body string }{
		{"/acquire", `{"session":"scenario-1","source":"screening","arguments":{"q":"intake"}}`},
		{"/seal", `{"session":"scenario-1"}`},
	} {
		resp, err := http.Post(server.URL+call.path, "application/json", strings.NewReader(call.body))
		if err != nil {
			t.Fatal(err)
		}
		var body bytes.Buffer
		body.ReadFrom(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("%s: %d %s", call.path, resp.StatusCode, body.String())
		}
		said = append(said, body.String())
	}
	return said
}

var scenarioSources = map[string]sourceSpec{"screening": {argv: []string{os.Args[0]}, env: helperEnv}}

// scenarioOnFilesystem is scenarioWork on a configuration without storage
// under the seed scenarioState made in dir: its store, registry and
// decision records in dir, or in a directory of their own, sub, when the
// state directory serves another configuration too.
func scenarioOnFilesystem(t *testing.T, dir, sub string) (string, engineConfig) {
	t.Helper()
	at := dir
	if sub != "" {
		at = filepath.Join(dir, sub)
		if err := os.Mkdir(at, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Mkdir(filepath.Join(at, "decisions"), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	config := filepath.Join(at, "engine.json")
	text := `{"engineVersion":"23","authority":"gateway:scenario","seed":"` + filepath.Join(dir, "gateway.seed") + `","store":"` + filepath.Join(at, "store") + `",` +
		`"registry":"` + filepath.Join(at, "registry.jsonl") + `","decisionRecords":"` + filepath.Join(at, "decisions") + `",` +
		`"listen":"127.0.0.1:8787","catalog":"` + filepath.Join(dir, "catalog") + `","platforms":{}}`
	if err := os.WriteFile(config, []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := parseEngineConfig([]byte(text))
	if err != nil {
		t.Fatal(err)
	}
	seed, err := loadSeed(cfg.seed)
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv(envSourceHelper, "1")
	service, err := buildService(cfg.store, seed, cfg.authority, cfg.registry, engineServeOptions(cfg, scenarioSources, nil))
	if err != nil {
		t.Fatal(err)
	}
	scenarioWork(t, service)
	return config, cfg
}

// scenarioMoment is each member whose value two runs of the same calls
// write differently on any kind: the times, to the second (servedAt,
// acquisition.observedAt, sealedAt); the arguments commitment, salted
// afresh each call (SPEC.md); and the signatures over them, the previous
// receipt's (prevSignature) among them.
var scenarioMoment = regexp.MustCompile(`"(servedAt|observedAt|sealedAt|argumentsCommitment|signature|prevSignature)":"[^"]*"`)

// scenarioManifestDigest is a file's digest in an export's manifest.
var scenarioManifestDigest = regexp.MustCompile(`"digest":"[^"]*","path":"([^"]*)"`)

// requireKindsExportAlike holds the PostgreSQL kind's export to the
// filesystem kind's, of the same calls under the same seed and authority:
// the same files, each artifact byte for byte, and every other file byte
// for byte but for the values of the members scenarioMoment names, and in
// the manifest the digests of the files those members are in. Those values
// are each export's own; export --check and verify hold them, in each.
func requireKindsExportAlike(t *testing.T, postgres, filesystem map[string][]byte) {
	t.Helper()
	if len(filesystem["registry"]) == 0 || len(filesystem["store/receipts/scenario-1/0.json"]) == 0 {
		t.Fatalf("the filesystem kind's export holds no registry or no receipt: %d files", len(filesystem))
	}
	mask := func(path string, data []byte) []byte {
		if strings.HasPrefix(path, "store/artifacts/") {
			return data
		}
		data = scenarioMoment.ReplaceAll(data, []byte(`"$1":"(this run's)"`))
		return scenarioManifestDigest.ReplaceAllFunc(data, func(m []byte) []byte {
			file := scenarioManifestDigest.FindSubmatch(m)[1]
			if bytes.HasPrefix(file, []byte("store/artifacts/")) {
				return m
			}
			return []byte(`"digest":"(this run's)","path":"` + string(file) + `"`)
		})
	}
	masked := func(tree map[string][]byte) map[string][]byte {
		out := map[string][]byte{}
		for path, data := range tree {
			out[path] = mask(path, data)
		}
		return out
	}
	requireSameTree(t, "the PostgreSQL kind's export and the filesystem kind's", masked(postgres), masked(filesystem))
}

// The PostgreSQL kind, its commands through the binary: the migration as
// the migration login, and refused as the run-time login; the start on the
// kind (the start lease taken, the registry made) and one acquisition and
// its seal; an export from the kind that the binary's export --check and
// verify hold; the same calls on the filesystem kind, exported by the
// binary, and the two exports alike (requireKindsExportAlike); and no
// output of the run, and no file it made, holding either login's password.
func TestStorageScenarioThroughTheBinary(t *testing.T) {
	binary := scenarioBinary(t, "GATEWAY_SCENARIO_GATEWAY")
	db := newPgTestDB(t)
	dir, publicKey := scenarioState(t, binary)
	var said []string
	migration := writeConnection(t, db.migrator)
	runtime := filepath.Join(dir, "connection")
	if err := os.WriteFile(runtime, []byte(pgTestURL(db.runtime)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	code, stdout, stderr := binaryRun(t, binary, nil, "store", "migrate", "--connection-file", runtime, "--owner", db.roles.owner, "--runtime", db.roles.runtime)
	said = append(said, stdout, stderr)
	if code != 1 || !strings.Contains(stderr, "neither the owner role nor the run-time role") {
		t.Fatalf("store migrate as the run-time login: %d %s %s", code, stdout, stderr)
	}
	code, stdout, stderr = binaryRun(t, binary, nil, "store", "migrate", "--connection-file", migration, "--owner", db.roles.owner, "--runtime", db.roles.runtime)
	said = append(said, stdout, stderr)
	if code != 0 || !strings.HasPrefix(stdout, `{"applied":[1,2,3,4,5],`) {
		t.Fatalf("store migrate: %d %s %s", code, stdout, stderr)
	}
	config := filepath.Join(dir, "engine.json")
	text := `{"engineVersion":"24","authority":"gateway:scenario","seed":"` + filepath.Join(dir, "gateway.seed") + `",` +
		`"storage":{"kind":"postgresql","connection":{"file":"` + runtime + `"}},"decisionRecords":"` + filepath.Join(dir, "decisions") + `",` +
		`"listen":"127.0.0.1:8787","catalog":"` + filepath.Join(dir, "catalog") + `","platforms":{}}`
	if err := os.WriteFile(config, []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := parseEngineConfig([]byte(text))
	if err != nil {
		t.Fatal(err)
	}
	seed, err := loadSeed(cfg.seed)
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv(envSourceHelper, "1")
	var lines bytes.Buffer
	started, err := startEngineOnKind(cfg, seed, scenarioSources, nil, &lines)
	if err != nil {
		t.Fatalf("start: %v", err)
	}
	said = append(said, scenarioWork(t, started.service)...)
	started.stop(&lines)
	said = append(said, lines.String())
	said = append(said, exportAndVerify(t, binary, config, filepath.Join(dir, "export"), "gateway:scenario", publicKey)...)
	// the same calls on the filesystem kind, under the same seed and
	// authority, exported by the same binary: the two exports alike
	fsConfig, _ := scenarioOnFilesystem(t, dir, "filesystem")
	said = append(said, exportAndVerify(t, binary, fsConfig, filepath.Join(dir, "export-filesystem"), "gateway:scenario", publicKey)...)
	requireKindsExportAlike(t, readTreeBytes(t, filepath.Join(dir, "export")), readTreeBytes(t, filepath.Join(dir, "export-filesystem")))
	for _, secret := range []string{db.runtime.password, db.migrator.password} {
		for _, text := range said {
			if strings.Contains(text, secret) {
				t.Fatalf("a password is in what the run said:\n%s", text)
			}
		}
		filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
			if err != nil || d.IsDir() || path == runtime {
				return err
			}
			if data, _ := os.ReadFile(path); bytes.Contains(data, []byte(secret)) {
				t.Errorf("a password is in %s", path)
			}
			return nil
		})
	}
}

// A configuration without storage: a store this binary's start wrote, with
// one acquisition and its seal, is exported by this binary and by main's
// alike, byte for byte; each export holds the store's own bytes, and each
// checks and verifies.
func TestStorageScenarioWithoutStorageExportsAsMainDoes(t *testing.T) {
	binary := scenarioBinary(t, "GATEWAY_SCENARIO_GATEWAY")
	mainBinary := scenarioBinary(t, "GATEWAY_SCENARIO_MAIN_GATEWAY")
	dir, publicKey := scenarioState(t, binary)
	config, cfg := scenarioOnFilesystem(t, dir, "")
	exportAndVerify(t, binary, config, filepath.Join(dir, "export-ours"), "gateway:scenario", publicKey)
	exportAndVerify(t, mainBinary, config, filepath.Join(dir, "export-main"), "gateway:scenario", publicKey)
	ours, mains := readTreeBytes(t, filepath.Join(dir, "export-ours")), readTreeBytes(t, filepath.Join(dir, "export-main"))
	if len(ours) == 0 {
		t.Fatal("nothing was exported")
	}
	requireSameTree(t, "this binary's export and main's", ours, mains)
	store := readTreeBytes(t, cfg.store)
	exported := map[string][]byte{}
	for path, data := range ours {
		if rest, ok := strings.CutPrefix(path, "store/"); ok {
			exported[rest] = data
		}
	}
	requireSameTree(t, "the exported store and the store", exported, store)
	registry, err := os.ReadFile(cfg.registry)
	if err != nil || !bytes.Equal(ours["registry"], registry) {
		t.Fatalf("the exported registry is not the registry: %v", err)
	}
}
