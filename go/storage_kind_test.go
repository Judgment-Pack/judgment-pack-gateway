package main

// The storage member (storage_kind.go): how a version-24 configuration
// names the PostgreSQL kind, what it refuses, what is refused by name while
// the kind keeps the store, and that the connection string is in nothing the
// engine writes or says.

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// storageConfig is a version-24 configuration whose storage member is
// storage ("" for none, with the store and registry paths in its place),
// with extra members after the catalog and the platforms given.
func storageConfig(t *testing.T, storage, extra, platforms string) string {
	t.Helper()
	base := t.TempDir()
	where := `"store":"` + abs(t, base, "store") + `","registry":"` + abs(t, base, "registry.jsonl") + `"`
	if storage != "" {
		where = `"storage":` + storage
	}
	return `{"engineVersion":"24","authority":"gateway:acme","seed":"` + abs(t, base, "gateway.seed") + `",` + where + `,` +
		`"decisionRecords":"` + abs(t, base, "decisions") + `","listen":"127.0.0.1:8787","catalog":"` + abs(t, base, "catalog") + `"` +
		extra + `,"platforms":{` + platforms + `}}`
}

func storageByFile(t *testing.T) string {
	t.Helper()
	return `{"kind":"postgresql","connection":{"file":"` + abs(t, t.TempDir(), "connection") + `"}}`
}

// A version-24 configuration names the kind and a reference to its
// connection string, and then neither the store's path nor the registry's.
func TestTheStorageMemberNamesTheKindAndItsConnectionByReference(t *testing.T) {
	file := abs(t, t.TempDir(), "connection")
	cfg, err := parseEngineConfig([]byte(storageConfig(t, `{"kind":"postgresql","connection":{"file":"`+file+`"}}`, ``, ``)))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.storage == nil || cfg.storage.file != filepath.FromSlash(strings.ReplaceAll(file, `\\`, `\`)) || cfg.storage.environment != "" {
		t.Fatalf("storage by file: %+v", cfg.storage)
	}
	if cfg.storage.connections != pgDefaultConnections || cfg.storage.operation != pgDefaultOperation {
		t.Fatalf("the defaults: %+v", cfg.storage)
	}
	if cfg.store != "" || cfg.registry != "" {
		t.Fatalf("with storage there is no store or registry path: %q %q", cfg.store, cfg.registry)
	}
	cfg, err = parseEngineConfig([]byte(storageConfig(t, `{"kind":"postgresql","connection":{"environment":"GATEWAY_STORE_URL"},"connections":8,"operationSeconds":5}`, ``, ``)))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.storage.environment != "GATEWAY_STORE_URL" || cfg.storage.file != "" || cfg.storage.connections != 8 || cfg.storage.operation != 5*time.Second {
		t.Fatalf("storage by environment: %+v", cfg.storage)
	}
	// without the member, version 24 is the filesystem kind at its paths
	cfg, err = parseEngineConfig([]byte(storageConfig(t, ``, ``, ``)))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.storage != nil || cfg.store == "" || cfg.registry == "" {
		t.Fatalf("no storage: %+v %q %q", cfg.storage, cfg.store, cfg.registry)
	}
}

// Every form the member does not take is refused, by name.
func TestTheStorageMemberRefusesWhatItDoesNotTake(t *testing.T) {
	file := abs(t, t.TempDir(), "connection")
	byFile := `"connection":{"file":"` + file + `"}`
	for _, tc := range []struct{ name, config, want string }{
		{"an earlier version", strings.Replace(storageConfig(t, `{"kind":"postgresql",`+byFile+`}`, ``, ``), `"engineVersion":"24"`, `"engineVersion":"23"`, 1),
			"engine configuration: storage is a version-24 member; engineVersion 23 has no storage"},
		{"store beside it", strings.Replace(storageConfig(t, `{"kind":"postgresql",`+byFile+`}`, ``, ``), `"storage":`, `"store":"`+abs(t, t.TempDir(), "store")+`","storage":`, 1),
			"engine configuration: store is the filesystem kind's; with storage naming the postgresql kind, store and registry are not given"},
		{"registry beside it", strings.Replace(storageConfig(t, `{"kind":"postgresql",`+byFile+`}`, ``, ``), `"storage":`, `"registry":"`+abs(t, t.TempDir(), "r.jsonl")+`","storage":`, 1),
			"engine configuration: registry is the filesystem kind's; with storage naming the postgresql kind, store and registry are not given"},
		{"neither storage nor store", strings.Replace(storageConfig(t, `{"kind":"postgresql",`+byFile+`}`, ``, ``), `"storage":{"kind":"postgresql",`+byFile+`},`, ``, 1),
			`engine configuration: missing member "store"`},
		{"another kind", storageConfig(t, `{"kind":"filesystem",`+byFile+`}`, ``, ``),
			`engine configuration: storage.kind is "postgresql"; without storage the filesystem kind keeps the store at store and registry`},
		{"an unknown member", storageConfig(t, `{"kind":"postgresql",`+byFile+`,"dsn":"x"}`, ``, ``),
			`engine configuration: storage: unknown member "dsn"`},
		{"no connection", storageConfig(t, `{"kind":"postgresql"}`, ``, ``),
			`engine configuration: storage: missing member "connection"`},
		{"both references", storageConfig(t, `{"kind":"postgresql","connection":{"file":"`+file+`","environment":"X"}}`, ``, ``),
			"engine configuration: storage.connection names the connection string by one reference: file, an absolute path, or environment, a variable's name"},
		{"neither reference", storageConfig(t, `{"kind":"postgresql","connection":{}}`, ``, ``),
			"engine configuration: storage.connection names the connection string by one reference: file, an absolute path, or environment, a variable's name"},
		{"the string itself", storageConfig(t, `{"kind":"postgresql","connection":{"url":"postgresql://u:p@h/d"}}`, ``, ``),
			`engine configuration: storage.connection: unknown member "url"`},
		{"a relative file", storageConfig(t, `{"kind":"postgresql","connection":{"file":"connection"}}`, ``, ``),
			"engine configuration: storage.connection.file"},
		{"a variable's name out of form", storageConfig(t, `{"kind":"postgresql","connection":{"environment":"store url"}}`, ``, ``),
			"engine configuration: storage.connection.environment is a variable's name: capital letters, digits and _, not starting with a digit, at most 128"},
		{"no connections", storageConfig(t, `{"kind":"postgresql",`+byFile+`,"connections":0}`, ``, ``),
			"engine configuration: storage.connections 0 is outside 1 to 64"},
		{"too many connections", storageConfig(t, `{"kind":"postgresql",`+byFile+`,"connections":65}`, ``, ``),
			"engine configuration: storage.connections 65 is outside 1 to 64"},
		{"no operation time", storageConfig(t, `{"kind":"postgresql",`+byFile+`,"operationSeconds":0}`, ``, ``),
			"engine configuration: storage.operationSeconds 0 is outside 1 to 600"},
		{"too long an operation time", storageConfig(t, `{"kind":"postgresql",`+byFile+`,"operationSeconds":601}`, ``, ``),
			"engine configuration: storage.operationSeconds 601 is outside 1 to 600"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := parseEngineConfig([]byte(tc.config))
			if err == nil || !strings.HasPrefix(err.Error(), tc.want) {
				t.Fatalf("got %v, want %q", err, tc.want)
			}
		})
	}
}

// What reads the filesystem store directly is refused by name at the
// configuration's load while the PostgreSQL kind keeps the store; each is
// taken without storage, so the refusal is the kind's.
func TestWhatReadsTheStoreOnDiskIsRefusedByNameWithThePostgreSQLKind(t *testing.T) {
	statement := "sha256:" + strings.Repeat("a", 64)
	for _, tc := range []struct{ name, extra, platform, want string }{
		{"a witness", `,"witness":{}`, ``, "witness, which keeps its files beside the registry on disk,"},
		{"sealOpenAtStart", `,"sealOpenAtStart":true`, ``, "sealOpenAtStart, which reads the sessions on disk,"},
		{"a platform's writes", ``, `,"write":true`, "platform crm's write: true, whose actions keep their journal and evidence on disk,"},
		{"a platform's descriptor statements", ``, `,"descriptorStatements":{"live":"` + statement + `"}`, "platform crm's descriptorStatements, whose snapshot is read from the store on disk,"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			platforms := ``
			if tc.platform != "" {
				platforms = platformJSON(t, "crm", "postgres@sha256:"+strings.Repeat("b", 64), "gw-crm", tc.platform)
			}
			_, err := parseEngineConfig([]byte(storageConfig(t, storageByFile(t), tc.extra, platforms)))
			if !errors.Is(err, errStorageKindUnsupported) || !strings.Contains(err.Error(), "storage-kind-unsupported: "+tc.want+" is not available with the PostgreSQL storage kind yet") {
				t.Fatalf("got %v", err)
			}
			if tc.name == "a witness" {
				return // a witness needs more than {} to be read at all
			}
			if _, err := parseEngineConfig([]byte(storageConfig(t, ``, tc.extra, platforms))); err != nil {
				t.Fatalf("without storage the same configuration is read: %v", err)
			}
		})
	}
}

// A platform's scope is admitted with the PostgreSQL kind, and its sources
// carry it; what reads the store on disk stays refused by name beside it (a
// platform with a scope allows no write with either kind).
func TestAPlatformsScopeIsAdmittedWithThePostgreSQLKind(t *testing.T) {
	binding := "postgres@sha256:" + strings.Repeat("b", 64)
	platforms := platformJSON(t, "crm", binding, "gw-crm", `,"scope":"scope-a"`) + `,` + platformJSON(t, "erp", binding, "gw-erp", ``)
	cfg, err := parseEngineConfig([]byte(storageConfig(t, storageByFile(t), ``, platforms)))
	if err != nil {
		t.Fatal(err)
	}
	scopes := map[string]string{}
	for _, p := range cfg.platforms {
		scopes[p.name] = p.scope
	}
	if scopes["crm"] != "scope-a" || scopes["erp"] != "" {
		t.Fatalf("the platforms' scopes: %v", scopes)
	}
	statement := "sha256:" + strings.Repeat("a", 64)
	for _, tc := range []struct{ name, extra, platform, want string }{
		{"sealOpenAtStart", `,"sealOpenAtStart":true`, `,"scope":"scope-a"`, "sealOpenAtStart, which reads the sessions on disk,"},
		{"a scoped platform's descriptor statements", ``, `,"scope":"scope-a","descriptorStatements":{"live":"` + statement + `"}`, "platform crm's descriptorStatements, whose snapshot is read from the store on disk,"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := parseEngineConfig([]byte(storageConfig(t, storageByFile(t), tc.extra, platformJSON(t, "crm", binding, "gw-crm", tc.platform))))
			if !errors.Is(err, errStorageKindUnsupported) || !strings.Contains(err.Error(), "storage-kind-unsupported: "+tc.want+" is not available with the PostgreSQL storage kind yet") {
				t.Fatalf("got %v", err)
			}
		})
	}
}

// emptyWorkingDirectory makes the test's working directory an empty one,
// and returns a check that it is empty still: a command that took the
// PostgreSQL kind's "" for a store would read and write here.
func emptyWorkingDirectory(t *testing.T) func() {
	t.Helper()
	dir := t.TempDir()
	t.Chdir(dir)
	return func() {
		t.Helper()
		entries, err := os.ReadDir(dir)
		if err != nil || len(entries) != 0 {
			t.Fatalf("the working directory holds %v (%v): something took the store's \"\" for a directory", entries, err)
		}
	}
}

// The commands that read the store on disk refuse a configuration whose
// store the PostgreSQL kind keeps, by name, and none reads or makes a
// directory in its place.
func TestCommandsThatReadTheStoreOnDiskRefuseThePostgreSQLKindByName(t *testing.T) {
	stillEmpty := emptyWorkingDirectory(t)
	config := filepath.Join(t.TempDir(), "engine.json")
	if err := os.WriteFile(config, []byte(storageConfig(t, storageByFile(t), ``, ``)), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		run  func(stdout, stderr *bytes.Buffer) int
		want string
	}{
		{"seal-open", func(stdout, stderr *bytes.Buffer) int {
			return cmdSealOpenAt([]string{"--config", config, "--all"}, stdout, stderr, nowStamp)
		}, "gateway seal-open, which reads the sessions on disk,"},
		{"remove-artifact", func(stdout, stderr *bytes.Buffer) int {
			return cmdRemoveArtifactAt([]string{"--config", config, "--receipt", "s/0", "--by", "operator"}, stdout, stderr, nowStamp)
		}, "gateway remove-artifact, which keeps its removal records in the store on disk,"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			if code := tc.run(&stdout, &stderr); code == 0 || !strings.Contains(stderr.String(), "storage-kind-unsupported: "+tc.want) {
				t.Fatalf("%d %q %q", code, stdout.String(), stderr.String())
			}
			stillEmpty()
		})
	}
	// A descriptor capture, which connect and the operation descriptors
	// retain in the store on disk, is refused where it is retained.
	cfg, err := parseEngineConfig([]byte(storageConfig(t, storageByFile(t), ``, ``)))
	if err != nil {
		t.Fatal(err)
	}
	seedPath := filepath.Join(t.TempDir(), "gateway.seed")
	if err := os.WriteFile(seedPath, []byte(hex.EncodeToString(testSeed)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg.seed = seedPath
	if _, err := retainConnectedCapture(cfg, []byte(`{}`), "live"); !errors.Is(err, errStorageKindUnsupported) || !strings.Contains(err.Error(), "a descriptor capture") {
		t.Fatalf("a capture: %v", err)
	}
	stillEmpty()
}

// gateway connect with a configuration whose store the PostgreSQL kind
// keeps refuses a descriptor capture, which the store on disk keeps, before
// any adapter is asked and with nothing written.
func TestConnectRefusesADescriptorCaptureWithThePostgreSQLKindBeforeAskingAnything(t *testing.T) {
	stillEmpty := emptyWorkingDirectory(t)
	f := newConnectFixture(t, restrictedBinding, ``)
	text := f.fileText(t)
	parsed, err := parseJSON([]byte(text))
	if err != nil {
		t.Fatal(err)
	}
	top := parsed.(*vObject)
	kept := newObject()
	for _, name := range top.names {
		member, _ := top.get(name)
		switch name {
		case "store", "registry":
			continue
		case "engineVersion":
			member = vString("24")
		}
		kept.set(name, member)
	}
	storage, err := parseJSON([]byte(`{"kind":"postgresql","connection":{"environment":"GATEWAY_STORE_URL"}}`))
	if err != nil {
		t.Fatal(err)
	}
	kept.set("storage", storage)
	if err := os.WriteFile(f.config, canon(kept), 0o640); err != nil {
		t.Fatal(err)
	}
	before := f.fileText(t)
	_, err = connect(context.Background(), f.request(), f.host, f.check)
	if !errors.Is(err, errStorageKindUnsupported) || !strings.Contains(err.Error(), "a descriptor capture") {
		t.Fatalf("got %v", err)
	}
	if len(f.asked) != 0 {
		t.Fatalf("an adapter was asked: %+v", f.asked)
	}
	if f.fileText(t) != before {
		t.Fatal("the configuration was written")
	}
	stillEmpty()
}

// The service over another kind answers what reads the store on disk with
// the named refusal, and reads no directory in its place.
func TestTheServiceOnAnotherKindRefusesWhatReadsTheDiskByName(t *testing.T) {
	stillEmpty := emptyWorkingDirectory(t)
	t.Setenv(envSourceHelper, "1")
	service, err := newGatewayServiceOn(newMemoryKind(nil), testSeed, "gateway:test",
		map[string]sourceSpec{"screening": {argv: []string{os.Args[0]}, env: helperEnv}})
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(service.handler())
	t.Cleanup(server.Close)
	issuer := newIssuer(t)
	id := identityFor(t, issuer)
	service.identity = &id
	token := issuer.mint(t, "ec-1", nil, goodClaims(time.Now()))
	if code, body := authed(t, server, "/acquire", `{"session":"kind-1","source":"screening","arguments":{"q":"acme"}}`, token); code != http.StatusOK {
		t.Fatalf("acquire: %d %v", code, body)
	}
	if code, body := authed(t, server, "/seal", `{"session":"kind-1"}`, token); code != http.StatusOK {
		t.Fatalf("seal: %d %v", code, body)
	}
	// sealed in the kind's registry, which the service reads back
	if code, body := authed(t, server, "/seal", `{"session":"kind-1"}`, token); code == http.StatusOK || !strings.Contains(fmt.Sprint(body), "sealed") {
		t.Fatalf("a second seal: %d %v", code, body)
	}
	for _, tc := range []struct{ path, body, want string }{
		{"/verify", `{}`, "/verify, which verifies the store on disk"},
		{"/act", `{"session":"kind-1"}`, "/act, whose session, journal and evidence are on disk,"},
	} {
		code, body := authed(t, server, tc.path, tc.body, token)
		if code != http.StatusNotImplemented || !strings.Contains(fmt.Sprint(body["error"]), "storage-kind-unsupported: "+tc.want) {
			t.Fatalf("%s: %d %v", tc.path, code, body)
		}
	}
	if code, body := authed(t, server, "/acquire", `{"session":"kind-2","source":"screening","arguments":{"q":"acme"}}`, token); code != http.StatusOK {
		t.Fatalf("acquire: %d %v", code, body)
	}
	stillEmpty()
}

// layoutHidingKind is a kind that wraps another and forwards the contract
// alone: neither a scope keeper nor a kind known to keep one layout.
type layoutHidingKind struct{ storeKind }

// A source fixed to a scope identifier, served over a kind that neither
// keeps each scope's rows apart nor is known to keep one layout, is refused
// its acquisition, and nothing is written: its rows are never taken for
// rows of no scope (#447). Over the kind that keeps one layout the same
// acquisition is taken, and a source of no scope over the wrapper is too.
func TestAScopedSourceOverAKindOfNoKnownLayoutIsRefused(t *testing.T) {
	t.Setenv(envSourceHelper, "1")
	sources := map[string]sourceSpec{
		"plain":       {argv: []string{os.Args[0]}, env: helperEnv},
		"screening-a": {argv: []string{os.Args[0]}, env: helperEnv, scope: "scope-a"},
	}
	issuer := newIssuer(t)
	id := identityFor(t, issuer)
	token := issuer.mint(t, "ec-1", nil, goodClaims(time.Now()))
	for _, tc := range []struct {
		name  string
		wrap  bool
		taken bool
	}{{"over the kind in memory", false, true}, {"over a kind that hides its layout", true, false}} {
		t.Run(tc.name, func(t *testing.T) {
			memory := newMemoryKind(nil)
			var kind storeKind = memory
			if tc.wrap {
				kind = layoutHidingKind{memory}
			}
			service, err := newGatewayServiceOn(kind, testSeed, "gateway:test", sources)
			if err != nil {
				t.Fatal(err)
			}
			service.identity = &id
			server := httptest.NewServer(service.handler())
			t.Cleanup(server.Close)
			code, body := authed(t, server, "/acquire", `{"session":"scoped-1","source":"screening-a","scope":"scope-a","arguments":{"q":"acme"}}`, token)
			if taken := code == http.StatusOK; taken != tc.taken {
				t.Fatalf("a scoped source's acquisition: %d %v", code, body)
			}
			if !tc.taken && !strings.Contains(fmt.Sprint(body["error"]), "the store's kind keeps no view of a scope identifier") {
				t.Fatalf("a scoped source's acquisition was refused otherwise: %d %v", code, body)
			}
			series, _ := memory.receipts().listSeries()
			blobs, _ := memory.artifacts().listBlobs()
			if !tc.taken && (len(series) != 0 || len(blobs) != 0) {
				t.Fatalf("a refused acquisition wrote series %v and blobs %v", series, blobs)
			}
			if code, body := authed(t, server, "/acquire", `{"session":"plain-1","source":"plain","arguments":{"q":"acme"}}`, token); code != http.StatusOK {
				t.Fatalf("a source of no scope: %d %v", code, body)
			}
		})
	}
}

// The connection string's file is held as the seed's is; a variable is
// removed from the environment once read; and no refusal of the string
// carries any of it.
func TestTheConnectionStringIsReadByItsReferenceAndNamedInNoRefusal(t *testing.T) {
	const marker = "synthetic-marker-password"
	dir := tempDirAt(t, 0o700)
	file := filepath.Join(dir, "connection")
	good := "postgresql://gateway_run:" + marker + "@127.0.0.1:5432/gateway?sslmode=disable\n"
	if err := os.WriteFile(file, []byte(good), 0o600); err != nil {
		t.Fatal(err)
	}
	d, err := storageConnection(&storageSpec{file: file})
	if err != nil || d.password != marker || d.user != "gateway_run" || d.tls {
		t.Fatalf("by file: %v %v", err, d.user)
	}
	// Mode bits are not the seed's protection on Windows (spawn_other.go
	// says so at start): the refusal of a file others may read is Unix only.
	if runtime.GOOS != "windows" {
		if err := os.Chmod(file, 0o640); err != nil {
			t.Fatal(err)
		}
		if _, err := storageConnection(&storageSpec{file: file}); err == nil || !strings.Contains(err.Error(), "is held as the seed's file is") || strings.Contains(err.Error(), marker) {
			t.Fatalf("a file others may read: %v", err)
		}
	}
	if err := os.WriteFile(file, []byte("postgresql://gateway_run:"+marker+"@db.example:5432/gateway?sslmode=disable"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(file, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := storageConnection(&storageSpec{file: file}); err == nil || strings.Contains(err.Error(), marker) || strings.Contains(err.Error(), "db.example") {
		t.Fatalf("a string out of form: %v", err)
	}
	t.Setenv("GATEWAY_TEST_STORE_URL", good)
	d, err = storageConnection(&storageSpec{environment: "GATEWAY_TEST_STORE_URL"})
	if err != nil || d.password != marker {
		t.Fatalf("by environment: %v", err)
	}
	if _, set := os.LookupEnv("GATEWAY_TEST_STORE_URL"); set {
		t.Fatal("the variable is left in the environment once read")
	}
	if _, err := storageConnection(&storageSpec{environment: "GATEWAY_TEST_STORE_URL"}); err == nil || err.Error() != "storage.connection.environment names GATEWAY_TEST_STORE_URL, which is not set" {
		t.Fatalf("a variable not set: %v", err)
	}
	// a server that is not there: the refusal names the reference, not the string
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	listener.Close()
	t.Setenv("GATEWAY_TEST_STORE_URL", fmt.Sprintf("postgresql://gateway_run:%s@127.0.0.1:%d/gateway?sslmode=disable&connect_timeout=1", marker, port))
	if _, err := openStorageKind(&storageSpec{environment: "GATEWAY_TEST_STORE_URL", connections: 1, operation: time.Second}); err == nil || strings.Contains(err.Error(), marker) || strings.Contains(err.Error(), "gateway_run") {
		t.Fatalf("a server not there: %v", err)
	}
	if line := storageStartLine(&storageSpec{file: file}); !strings.Contains(line, file) || strings.Contains(line, marker) {
		t.Fatalf("the start line: %s", line)
	}
}

// The MCP server is denied the connection string as it is denied the
// store: the connection file must be closed to it, and the variable must
// not be in its environment.
func TestTheMCPServerIsDeniedTheConnectionString(t *testing.T) {
	file := filepath.Join(t.TempDir(), "connection")
	opened := map[string]bool{}
	host := mcpReachHost{euid: frontendUID, gid: frontendUID, groups: func() ([]int, error) { return nil, nil }, caps: func() (bool, string) { return true, "" },
		open: func(path string) error {
			opened[path] = true
			if path == file {
				return nil
			}
			return fs.ErrPermission
		},
		lookupEnv: func(string) (string, bool) { return "", false }}
	cfg := engineConfig{seed: "/seed", storage: &storageSpec{kind: storagePostgreSQL, file: file}}
	if err := mcpReachCheck(cfg, host); err == nil || !strings.Contains(err.Error(), "can open the storage connection file") {
		t.Fatalf("an open connection file: %v", err)
	}
	if opened[""] {
		t.Fatal("the store's \"\" was opened")
	}
	cfg.storage = &storageSpec{kind: storagePostgreSQL, environment: "GATEWAY_STORE_URL"}
	if err := mcpReachCheck(cfg, host); err != nil {
		t.Fatalf("a variable not set: %v", err)
	}
	host.lookupEnv = func(name string) (string, bool) { return "x", name == "GATEWAY_STORE_URL" }
	if err := mcpReachCheck(cfg, host); err == nil || !strings.Contains(err.Error(), "environment holds GATEWAY_STORE_URL") {
		t.Fatalf("a variable set: %v", err)
	}
	host.lookupEnv = nil
	if err := mcpReachCheck(cfg, host); err == nil {
		t.Fatal("a host that cannot read its environment is taken")
	}
}

// Without storage, the start judges the store and the registry at their
// paths as it always did: the store's path being a file is a start refused.
func TestAConfigurationWithoutStorageIsJudgedAtItsPathsAsBefore(t *testing.T) {
	dir := t.TempDir()
	store := filepath.Join(dir, "store")
	if err := os.WriteFile(store, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	records := filepath.Join(dir, "decisions")
	if err := preflightPathsOf(store, filepath.Join(dir, "registry.jsonl"), records, true); err == nil || err.Error() != "store "+store+" is not a directory" {
		t.Fatalf("with the store at its path: %v", err)
	}
	if err := preflightPaths(store, filepath.Join(dir, "registry.jsonl"), records); err == nil || err.Error() != "store "+store+" is not a directory" {
		t.Fatalf("preflightPaths: %v", err)
	}
	if err := preflightPathsOf("", "", records, false); err != nil {
		t.Fatalf("with another kind keeping the store: %v", err)
	}
	var cfg engineConfig
	cfg.store, cfg.registry, cfg.decisionRecords = store, filepath.Join(dir, "registry.jsonl"), records
	if err := refuseUnderPostgreSQL(cfg, "x"); err != nil {
		t.Fatalf("no storage refuses nothing: %v", err)
	}
	if err := rotationPendingAtStart(cfg, []string{filepath.Join(dir, "gateway.seed")}); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "gateway.seed")+nextSeedSuffix, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	err := rotationPendingAtStart(cfg, []string{filepath.Join(dir, "gateway.seed")})
	if want := rotationPendingBesideAny([]string{filepath.Join(dir, "gateway.seed")}, cfg.registry); err == nil || want == nil || err.Error() != want.Error() {
		t.Fatalf("a rotation under way without storage: %v", err)
	}
	cfg.storage = &storageSpec{kind: storagePostgreSQL, environment: "X"}
	if err := rotationPendingAtStart(cfg, []string{filepath.Join(dir, "gateway.seed")}); !errors.Is(err, errRotationPending) || !errors.Is(err, errStorageKindUnsupported) {
		t.Fatalf("a rotation under way with the PostgreSQL kind: %v", err)
	}
}

// pgTestURL is a login's connection string.
func pgTestURL(d pgDSN) string {
	u := url.URL{Scheme: "postgresql", User: url.UserPassword(d.user, d.password), Host: net.JoinHostPort(d.host, d.port), Path: "/" + d.database}
	if !d.tls {
		u.RawQuery = "sslmode=disable"
	} else {
		u.RawQuery = "sslmode=verify-full"
		if d.rootCertFile != "" {
			u.RawQuery += "&sslrootcert=" + url.QueryEscape(d.rootCertFile)
		}
	}
	return u.String()
}

// One acquisition and a seal served over the PostgreSQL kind a
// configuration names, then exported and verified: the run-time login's
// password, the marker, is in no response, no line said, and no file the
// run made but the connection file itself.
func TestThePostgresKindServesAndExportsWithTheConnectionStringInNoOutput(t *testing.T) {
	db := newPgTestDB(t)
	db.migrate(t)
	marker := db.runtime.password
	dir := tempDirAt(t, 0o700)
	connection := filepath.Join(dir, "connection")
	if err := os.WriteFile(connection, []byte(pgTestURL(db.runtime)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	seedPath := filepath.Join(dir, "gateway.seed")
	if err := os.WriteFile(seedPath, []byte(hex.EncodeToString(testSeed)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	records := filepath.Join(dir, "decisions")
	if err := os.Mkdir(records, 0o700); err != nil {
		t.Fatal(err)
	}
	config := filepath.Join(dir, "engine.json")
	text := `{"engineVersion":"24","authority":"gateway:test","seed":"` + abs(t, seedPath) + `","storage":{"kind":"postgresql","connection":{"file":"` + abs(t, connection) + `"},"connections":2},` +
		`"decisionRecords":"` + abs(t, records) + `","listen":"127.0.0.1:8787","catalog":"` + abs(t, dir, "catalog") + `","platforms":{}}`
	if err := os.WriteFile(config, []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := parseEngineConfig([]byte(text))
	if err != nil {
		t.Fatal(err)
	}
	var said bytes.Buffer
	t.Setenv(envSourceHelper, "1")
	// serve --config's start on the kind: opened, the start lease taken, the
	// service built and the registry walked
	started, err := startEngineOnKind(cfg, testSeed, map[string]sourceSpec{"screening": {argv: []string{os.Args[0]}, env: helperEnv}}, nil, &said)
	if err != nil {
		t.Fatalf("start: %v", err)
	}
	t.Cleanup(func() { started.stop(&said) })
	service := started.service
	server := httptest.NewServer(service.handler())
	t.Cleanup(server.Close)
	for _, call := range []struct{ path, body string }{
		{"/acquire", `{"session":"pg-1","source":"screening","arguments":{"q":"acme"}}`},
		{"/seal", `{"session":"pg-1"}`},
		{"/registry", ``},
		{"/verify", `{}`},
	} {
		resp, err := http.Post(server.URL+call.path, "application/json", strings.NewReader(call.body))
		if err != nil {
			t.Fatal(err)
		}
		var body bytes.Buffer
		_, _ = body.ReadFrom(resp.Body)
		resp.Body.Close()
		fmt.Fprintf(&said, "%s %d %s\n", call.path, resp.StatusCode, body.String())
		if want := map[string]int{"/verify": http.StatusNotImplemented}[call.path]; want == 0 && resp.StatusCode != http.StatusOK || want != 0 && resp.StatusCode != want {
			t.Fatalf("%s: %d %s", call.path, resp.StatusCode, body.String())
		}
	}
	// the export is made beside the working directory: the kind keeps no
	// directory an export could be inside of, and "" is never taken for one
	t.Chdir(dir)
	out := filepath.Join(dir, "export")
	summary, err := exportEngine(config, out, nil)
	if err != nil {
		t.Fatalf("export: %v", err)
	}
	said.Write(canon(summary))
	requireExportChecks(t, out)
	if verdict := restoredVerdict(t, out, cfg.authority, service.publicKey); !bytes.Contains(verdict, []byte(`"ok":true`)) {
		t.Fatalf("the export does not verify: %s", verdict)
	}
	// a login refused: the refusal names none of the string
	if err := os.WriteFile(connection, []byte(strings.Replace(pgTestURL(db.runtime), marker, marker+"-wrong", 1)), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := openStorageKind(cfg.storage); err == nil {
		t.Fatal("a wrong password opened the kind")
	} else {
		fmt.Fprintln(&said, err)
	}
	if bytes.Contains(said.Bytes(), []byte(marker)) || bytes.Contains(said.Bytes(), []byte(db.runtime.user+":")) {
		t.Fatalf("the connection string is in what was said:\n%s", said.String())
	}
	err = filepath.WalkDir(dir, func(path string, entry fs.DirEntry, err error) error {
		if err != nil || entry.IsDir() || path == connection {
			return err
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if bytes.Contains(data, []byte(marker)) {
			t.Errorf("the connection string's password is in %s", path)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	var registryLine string
	for _, line := range strings.Split(said.String(), "\n") {
		if strings.HasPrefix(line, "/registry 200 ") {
			registryLine = line
		}
	}
	if !strings.Contains(registryLine, `"sessionId":"pg-1"`) {
		t.Fatalf("the seal is not in the registry the kind keeps:\n%s", said.String())
	}
}

// A session an earlier process left in the kind's store is not continued,
// nor sealed from a count, as one left on disk is not (leftInStore); and a
// registry missing beside a store that holds sessions is a start refused.
func TestASessionAnEarlierProcessLeftInTheKindIsNotContinued(t *testing.T) {
	stillEmpty := emptyWorkingDirectory(t)
	t.Setenv(envSourceHelper, "1")
	kind := newMemoryKind(nil)
	stampSession(t, newStoreOn("", kind.artifacts(), kind.receipts(), testSeed, "gateway:test"), "left-1", 1)
	sources := map[string]sourceSpec{"screening": {argv: []string{os.Args[0]}, env: helperEnv}}
	if _, err := newGatewayServiceOn(kind, testSeed, "gateway:test", sources); err == nil || !strings.Contains(err.Error(), "the store holds sessions and the registry is not there: "+pgRegistryName) {
		t.Fatalf("no registry beside sessions: %v", err)
	}
	if err := kind.registry().createLog(); err != nil {
		t.Fatal(err)
	}
	service, err := newGatewayServiceOn(kind, testSeed, "gateway:test", sources)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(service.handler())
	t.Cleanup(server.Close)
	want := fmt.Sprintf(refusalLeftOpen, "left-1")
	if code, body := post(t, server, "/acquire", `{"session":"left-1","source":"screening","arguments":{"q":"acme"}}`); code == http.StatusOK || fmt.Sprint(body["error"]) != want {
		t.Fatalf("acquire into a session left open: %d %v", code, body)
	}
	if code, body := post(t, server, "/seal", `{"session":"left-1"}`); code == http.StatusOK || fmt.Sprint(body["error"]) != want {
		t.Fatalf("seal of a session left open: %d %v", code, body)
	}
	stillEmpty()
}
