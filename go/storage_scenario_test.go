//go:build unix

package main

// The storage kinds through the binary (scripts/checks/storage-scenario.sh,
// run by the CI job postgresql): the binary GATEWAY_SCENARIO_GATEWAY names
// migrates the PostgreSQL kind, and exports, checks and verifies what a
// start on it wrote; and, with GATEWAY_SCENARIO_MAIN_GATEWAY naming main's
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

// The PostgreSQL kind, its commands through the binary: the migration as
// the migration login, and refused as the run-time login; the start on the
// kind (the start lease taken, the registry made) and one acquisition and
// its seal; an export from the kind that the binary's export --check and
// verify hold; and no output of the run, and no file it made, holding
// either login's password.
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
	if code != 0 || !strings.HasPrefix(stdout, `{"applied":[1,2],`) {
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
	config := filepath.Join(dir, "engine.json")
	text := `{"engineVersion":"23","authority":"gateway:scenario","seed":"` + filepath.Join(dir, "gateway.seed") + `","store":"` + filepath.Join(dir, "store") + `",` +
		`"registry":"` + filepath.Join(dir, "registry.jsonl") + `","decisionRecords":"` + filepath.Join(dir, "decisions") + `",` +
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
