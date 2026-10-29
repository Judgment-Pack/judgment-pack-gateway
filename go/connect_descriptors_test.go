package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// capturedQuery is a capture of the one tool the restricted binding's live
// operation allows.
const capturedOwnedQuery = `{"query":{"description":"Run a query","inputSchemaText":"{\"type\":\"object\"}","taxonomy":{"operation":"read","effect":"read-external"}}}`

const capturedQuery = `{"query":{"description":"Run a query","inputSchemaText":"{\"type\":\"object\"}"}}`

// pinnedSnapshot is what the configuration pins for the platform, and the
// snapshot file it names.
func pinnedSnapshot(t *testing.T, f *connectFixture) (engineConfig, string, []byte) {
	t.Helper()
	cfg, _, err := loadEngineConfig(f.config, stubAccounts(stubUsers))
	if err != nil {
		t.Fatal(err)
	}
	pin := cfg.platforms[0].operationDescriptors["live"]
	if pin == "" {
		pin = cfg.platforms[0].descriptors
	}
	if pin == "" {
		return cfg, "", nil
	}
	data, err := os.ReadFile(filepath.Join(f.config+".descriptors", strings.TrimPrefix(pin, "sha256:")+".json"))
	if err != nil {
		t.Fatal(err)
	}
	return cfg, pin, data
}

func hasLine(lines []string, want string) bool {
	for _, line := range lines {
		if line == want {
			return true
		}
	}
	return false
}

func TestConnectPinsTheSnapshotItCaptured(t *testing.T) {
	f := newConnectFixture(t, restrictedBinding, ``)
	f.captured = capturedQuery
	out, err := connect(context.Background(), f.request(), f.host, f.check)
	if err != nil {
		t.Fatal(err)
	}
	cfg, pin, data := pinnedSnapshot(t, f)
	if cfg.version != "12" || pin == "" || digestOf(string(data)) != pin {
		t.Fatalf("version %s, pin %q: the file names the snapshot kept, by its digest", cfg.version, pin)
	}
	s, err := parseSnapshot(data)
	if err != nil || s.platform != "warehouse" || s.binding != cfg.platforms[0].binding || strings.Join(s.names, ",") != "query" || s.server == nil {
		t.Fatalf("the snapshot kept is the capture, for this platform and binding: %v %+v", err, s)
	}
	if !hasLine(out.answers, "warehouse/live: descriptors: query captured (description 11 bytes, input schema 17 bytes)") ||
		!hasLine(out.answers, "warehouse/live: descriptors: server postgres-mcp 0.3.0") || len(out.after) != 0 {
		t.Fatalf("the operator is told what was captured: %q %q", out.answers, out.after)
	}
	entries, _ := os.ReadDir(f.dir)
	for _, e := range entries {
		if strings.Contains(e.Name(), ".connect-") {
			t.Fatalf("a private directory is left behind: %s", e.Name())
		}
	}
}

func TestConnectRequiresCompleteMetadataEvenWhenDisplayCandidatesAreAbsent(t *testing.T) {
	f := newConnectFixture(t, restrictedBinding, "")
	if _, err := connect(context.Background(), f.request(), f.host, f.check); err != nil {
		t.Fatal(err)
	}
	cfg, pin, raw := pinnedSnapshot(t, f)
	if cfg.version != "12" || pin == "" || !bytes.Contains(raw, []byte(`"taxonomy"`)) {
		t.Fatal("owner metadata dropped with absent candidates")
	}
	f = newConnectFixture(t, restrictedBinding, "")
	req := f.request()
	req.noDescriptors = true
	before := f.fileText(t)
	if _, err := connect(context.Background(), req, f.host, f.check); err == nil || len(f.asked) != 0 || f.fileText(t) != before {
		t.Fatal("current registration bypassed owner capture")
	}
}

func TestConnectRefusesACaptureItCannotHoldTo(t *testing.T) {
	for _, tc := range []struct {
		name  string
		setup func(f *connectFixture)
		want  string
	}{
		{"a member twice in the report", func(f *connectFixture) { f.captured, f.capturedExtra = capturedQuery, `"descriptors":{},` }, "not strict JSON"},
		{"a tool the live operation does not allow", func(f *connectFixture) {
			f.captured = `{"explain":{"description":"x","taxonomy":{"operation":"read","effect":"read-external"}}}`
		}, "complete V2 snapshot evidence"},
		{"another platform's snapshot", func(f *connectFixture) {
			f.snapshotAs = `{"binding":"postgres@` + digestOf(restrictedBinding) + `","capturedAt":"2026-09-15T00:00:00Z","platform":"other","policy":1,"tools":` + capturedQuery + `}`
		}, "complete V2 snapshot evidence"},
		{"a schema that is not a string", func(f *connectFixture) { f.captured = `{"query":{"inputSchemaText":{"type":"object"}}}` }, "not a string"},
		{"another policy", func(f *connectFixture) {
			f.snapshotAs = `{"binding":"postgres@` + digestOf(restrictedBinding) + `","capturedAt":"2026-09-15T00:00:00Z","platform":"warehouse","policy":2,"tools":` + capturedQuery + `}`
		}, "display policy"},
		{"no snapshot, and no reason", func(f *connectFixture) { f.noSnapshot = true }, "says of none why"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newConnectFixture(t, restrictedBinding, ``)
			before := f.fileText(t)
			tc.setup(f)
			if _, err := connect(context.Background(), f.request(), f.host, f.check); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("want %q: %v", tc.want, err)
			}
			if f.fileText(t) != before {
				t.Fatal("the configuration is left as it was")
			}
			entries, err := os.ReadDir(f.config + ".descriptors")
			if err != nil || len(entries) != 1 {
				t.Fatalf("only unused immutable declaration remains: %v %v", entries, err)
			}
		})
	}
	f := newConnectFixture(t, restrictedBinding, "")
	f.noSnapshot, f.capturedExtra = true, `"descriptorsDropped":"report too large",`
	before := f.fileText(t)
	if _, err := connect(context.Background(), f.request(), f.host, f.check); err == nil || f.fileText(t) != before {
		t.Fatal("dropped classification was accepted")
	}
}

func TestConnectReusesATakenNameOnlyWhenItVerifies(t *testing.T) {
	f := newConnectFixture(t, restrictedBinding, ``)
	f.captured = capturedQuery
	if _, err := connect(context.Background(), f.request(), f.host, f.check); err != nil {
		t.Fatal(err)
	}
	_, pin, data := pinnedSnapshot(t, f)
	// The same capture again: the name is taken by the same bytes, and
	// reused.
	req := f.request()
	req.replace = true
	out, err := connect(context.Background(), req, f.host, f.check)
	if err != nil {
		t.Fatal(err)
	}
	if !hasLine(out.answers, "warehouse/live: descriptors: against the previous snapshot, nothing changed") || !hasLine(out.after, "restart: nothing either process reads changed") {
		t.Fatalf("%q %q", out.answers, out.after)
	}
	// The name taken by other bytes: refused before any configuration
	// names it.
	path := filepath.Join(f.config+".descriptors", strings.TrimPrefix(pin, "sha256:")+".json")
	if err := os.WriteFile(path, bytes.Replace(data, []byte("Run a query"), []byte("Run a QUERY"), 1), 0o644); err != nil {
		t.Fatal(err)
	}
	before := f.fileText(t)
	if _, err := connect(context.Background(), req, f.host, f.check); err == nil || !strings.Contains(err.Error(), "does not digest to its name") {
		t.Fatalf("a name taken by other bytes: %v", err)
	}
	if f.fileText(t) != before {
		t.Fatal("the configuration is left as it was")
	}
	noStaging(t, f.config+".descriptors")
}

// noStaging fails when a staging name is left in the snapshots' directory.
func noStaging(t *testing.T, dir string) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".staged") {
			t.Fatalf("a staging name is left behind: %s", e.Name())
		}
	}
}

func TestConnectFailingBeforeTheCommitPointLeavesTheOldConfiguration(t *testing.T) {
	f := newConnectFixture(t, restrictedBinding, ``)
	f.captured = capturedQuery
	before := f.fileText(t)
	edited := strings.Replace(before, `"gateway:acme"`, `"gateway:other"`, 1)
	check := func(ctx context.Context, spec sourceSpec) ([]byte, error) {
		// Someone edits the file while the checks run, so the rename
		// does not happen -- after the snapshot is kept.
		if err := os.WriteFile(f.config, []byte(edited), 0o640); err != nil {
			t.Fatal(err)
		}
		return f.check(ctx, spec)
	}
	if _, err := connect(context.Background(), f.request(), f.host, check); err == nil || !strings.Contains(err.Error(), "the file changed while the checks ran") {
		t.Fatalf("%v", err)
	}
	if f.fileText(t) != edited {
		t.Fatal("the configuration found is the one there before the commit point")
	}
	// The snapshot kept is there, unpinned, immutable and harmless.
	entries, err := os.ReadDir(f.config + ".descriptors")
	if err != nil || len(entries) != 2 {
		t.Fatalf("the snapshot and declaration kept before the failure stay: %v %v", err, entries)
	}
}

func TestConnectFailingAfterTheCommitPointSaysSo(t *testing.T) {
	f := newConnectFixture(t, restrictedBinding, ``)
	f.captured = capturedQuery
	var synced []string
	directorySynced = func(name string) error {
		synced = append(synced, name)
		// The configuration's directory, synced after the rename.
		if name == "." && len(synced) == 5 {
			return os.ErrPermission
		}
		return nil
	}
	defer func() { directorySynced = nil }()
	out, err := connect(context.Background(), f.request(), f.host, f.check)
	if err == nil || !strings.Contains(err.Error(), "replaced, but its directory could not be synced, so the replacement may not survive a crash") {
		t.Fatalf("%v", err)
	}
	if out.written != f.config || !strings.Contains(f.fileText(t), `"operationDescriptors":`) {
		t.Fatalf("the configuration was replaced, and connect says where: %q", out.written)
	}
	var stdout, stderr bytes.Buffer
	if code := printOutcome(&stdout, &stderr, "warehouse", out, err); code == 0 || !strings.Contains(stderr.String(), "may not survive a crash") {
		t.Fatalf("exit %d: %s", code, stderr.String())
	}
}

func TestConnectSyncsInTheDesignsOrder(t *testing.T) {
	f := newConnectFixture(t, restrictedBinding, ``)
	f.captured = capturedQuery
	var synced []string
	directorySynced = func(name string) error { synced = append(synced, name); return nil }
	defer func() { directorySynced = nil }()
	if _, err := connect(context.Background(), f.request(), f.host, f.check); err != nil {
		t.Fatal(err)
	}
	// The configuration's directory for the snapshots' directory made,
	// the snapshots' directory for the snapshot linked, then the
	// configuration's directory for the rename.
	if got := strings.Join(synced, " "); got != ". engine.json.descriptors . engine.json.descriptors ." {
		t.Fatalf("syncs %q", got)
	}
	synced = nil
	req := f.request()
	req.replace = true
	f.captured = `{"query":{"description":"Run a read-only query"}}`
	if _, err := connect(context.Background(), req, f.host, f.check); err != nil {
		t.Fatal(err)
	}
	// Found, the directory's parent is synced all the same: a connect
	// that made it may have stopped before its own sync.
	if got := strings.Join(synced, " "); got != ". engine.json.descriptors . engine.json.descriptors ." {
		t.Fatalf("with the directory there, syncs %q", got)
	}
}

// twoToolBinding is the restricted binding with a live operation that
// allows two tools.
var twoToolBinding = strings.Replace(strings.Replace(restrictedBinding, `"tools": ["query"]`, `"tools": ["query", "explain"]`, 1), `"toolTaxonomies":{"query":{"operation":"read","effect":"read-external"}}`, `"toolTaxonomies":{"query":{"operation":"read","effect":"read-external"},"explain":{"operation":"read","effect":"read-external"}}`, 1)

func TestConnectComparesWithThePreviousSnapshot(t *testing.T) {
	f := newConnectFixture(t, twoToolBinding, ``)
	f.captured = `{"query":{"description":"Run a query"}}`
	if _, err := connect(context.Background(), f.request(), f.host, f.check); err != nil {
		t.Fatal(err)
	}
	req := f.request()
	req.replace = true
	step := func(captured, want, restart string) {
		t.Helper()
		f.captured = captured
		out, err := connect(context.Background(), req, f.host, f.check)
		if err != nil {
			t.Fatal(err)
		}
		if !hasLine(out.answers, "warehouse/live: descriptors: "+want) || !hasLine(out.after, restart) {
			t.Fatalf("want %q and %q: %q %q", want, restart, out.answers, out.after)
		}
	}
	const frontend = "restart: what the signer reads changed (operation descriptor approvals); restart both processes"
	step(`{"explain":{"description":"Explain"},"query":{"description":"Run a query"}}`, "against the previous snapshot: explain changed", frontend)
	step(`{"explain":{"description":"Explain it"},"query":{"description":"Run a query"}}`, "against the previous snapshot: explain changed", frontend)
	step(`{"query":{"description":"Run a query"}}`, "against the previous snapshot: explain changed", frontend)
	// The previous snapshot altered where it lies: it does not verify
	// against its pin, and nothing is compared.
	_, pin, data := pinnedSnapshot(t, f)
	previousPath := filepath.Join(f.config+".descriptors", strings.TrimPrefix(pin, "sha256:")+".json")
	if err := os.WriteFile(previousPath, bytes.Replace(data, []byte("Run a query"), []byte("Run a QUERY"), 1), 0o644); err != nil {
		t.Fatal(err)
	}
	f.captured = `{"query":{"description":"Run a query?"}}`
	out0, err := connect(context.Background(), req, f.host, f.check)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(strings.Join(out0.answers, "\n"), "the previous snapshot does not verify against its pin, so nothing is compared") ||
		strings.Contains(strings.Join(out0.answers, "\n"), "against the previous snapshot:") {
		t.Fatalf("%q", out0.answers)
	}
	// The previous snapshot gone: nothing is compared.
	_, pin, _ = pinnedSnapshot(t, f)
	if err := os.Remove(filepath.Join(f.config+".descriptors", strings.TrimPrefix(pin, "sha256:")+".json")); err != nil {
		t.Fatal(err)
	}
	f.captured = `{"query":{"description":"Run a query!"}}`
	out, err := connect(context.Background(), req, f.host, f.check)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, line := range out.answers {
		found = found || strings.HasPrefix(line, "warehouse/live: descriptors: the previous snapshot does not verify against its pin, so nothing is compared")
	}
	if !found {
		t.Fatalf("%q", out.answers)
	}
	// The binding narrowed in the catalog: the previous binding cannot be
	// read, and the previous snapshot stands for what it allowed.
	f.captured = `{"explain":{"description":"Explain"},"query":{"description":"Run a query!"}}`
	if _, err := connect(context.Background(), req, f.host, f.check); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(f.catalog, "postgres.json"), []byte(restrictedBinding), 0o644); err != nil {
		t.Fatal(err)
	}
	f.captured = `{"query":{"description":"Run a query!"}}`
	out, err = connect(context.Background(), req, f.host, f.check)
	if err != nil {
		t.Fatal(err)
	}
	if !hasLine(out.answers, "warehouse/live: descriptors: against the previous snapshot (the previous binding cannot be read, so which tools it allowed is not known): explain removed") ||
		!hasLine(out.after, "restart: what the signer reads changed (the binding, operation descriptor approvals); restart both processes") {
		t.Fatalf("%q %q", out.answers, out.after)
	}
}

func TestRestartLinesNameWhatTheSignerReads(t *testing.T) {
	base := platformConfig{binding: "b@x", credentials: map[string]string{"live": "/a"}, user: "u", endpoint: "e", environment: []string{"K=V"}, descriptors: "sha256:1"}
	for _, tc := range []struct {
		change func(p *platformConfig)
		want   string
	}{
		{func(p *platformConfig) { p.binding = "b@y" }, "(the binding)"},
		{func(p *platformConfig) { p.credentials = map[string]string{"live": "/b"} }, "(a credentials path)"},
		{func(p *platformConfig) { p.user = "v" }, "(the user)"},
		{func(p *platformConfig) { p.endpoint = "f" }, "(the endpoint)"},
		{func(p *platformConfig) { p.environment = []string{"K=W"} }, "(the environment)"},
		{func(p *platformConfig) { p.write = true }, "(the write flag)"},
		{func(p *platformConfig) { p.descriptors = "sha256:2" }, "only the descriptors' pin changed"},
		{func(p *platformConfig) {}, "nothing either process reads changed"},
	} {
		next := base
		next.credentials = map[string]string{"live": "/a"}
		next.environment = []string{"K=V"}
		tc.change(&next)
		if got := restartLines(base, next); len(got) != 1 || !strings.Contains(got[0], tc.want) {
			t.Errorf("want %q: %q", tc.want, got)
		}
	}
}

func TestADescriptorsPinIsAVersion3MemberOfALiveBinding(t *testing.T) {
	f := newConnectFixture(t, historicalRestrictedBinding, "")
	data, err := os.ReadFile(f.config)
	if err != nil {
		t.Fatal(err)
	}
	textBytes, err := renderPlatformEntry(data, f.request(), "postgres@"+digestOf(historicalRestrictedBinding), "sha256:"+strings.Repeat("0", 64), nil)
	if err != nil {
		t.Fatal(err)
	}
	text := string(textBytes)
	for _, tc := range []struct{ name, text, want string }{
		{"version 2", strings.Replace(text, `"engineVersion": "3"`, `"engineVersion": "2"`, 1), "descriptors is a version-3 member"},
		{"not a digest", strings.Replace(text, `"descriptors": "sha256:`, `"descriptors": "sha512:`, 1), "descriptors must be sha256:"},
	} {
		if _, err := parseEngineConfig([]byte(tc.text)); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: want %q: %v", tc.name, tc.want, err)
		}
	}
	// A binding without a live operation has nothing to pin.
	historyOnly := `{"bindingVersion":"1","platform":"postgres","operations":{"history":{"shape":"airbyte","image":"airbyte/source-postgres:3.8.5@` + testImageDigest + `","licence":"ELv2"}}}`
	if err := os.WriteFile(filepath.Join(f.catalog, "postgres.json"), []byte(historyOnly), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg, err := parseEngineConfig([]byte(strings.Replace(text, digestOf(historicalRestrictedBinding), digestOf(historyOnly), 1)))
	if err != nil {
		t.Fatal(err)
	}
	delete(cfg.platforms[0].credentials, "live")
	if _, err := resolveEngineConfig(&cfg, stubAccounts(stubUsers)); err == nil || !strings.Contains(err.Error(), "offers the platform neither") {
		t.Fatalf("%v", err)
	}
}

// What a capture says reaches the terminal through the door every answer
// does: a server's name holding a line feed, which display policy 1
// admits, cannot forge a line.
func TestWhatACaptureSaysIsPrintedEscaped(t *testing.T) {
	f := newConnectFixture(t, restrictedBinding, ``)
	f.snapshotAs = `{"snapshotVersion":"2","operation":"live","binding":"postgres@` + digestOf(restrictedBinding) + `","capturedAt":"2026-09-15T00:00:00Z","platform":"warehouse","policy":1,"server":{"name":"pg\nwarehouse: written to /elsewhere","version":"1"},"tools":` + capturedOwnedQuery + `}`
	out, err := connect(context.Background(), f.request(), f.host, f.check)
	if err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	printOutcome(&stdout, &stderr, "warehouse", out, nil)
	for _, line := range strings.Split(stdout.String(), "\n") {
		if strings.HasPrefix(line, "warehouse: written to /elsewhere") {
			t.Fatalf("a captured name forged a line: %q", stdout.String())
		}
	}
	if !strings.Contains(stdout.String(), `descriptors: server pg\nwarehouse: written to /elsewhere 1`) {
		t.Fatalf("%q", stdout.String())
	}
}

// A tool whose display candidates fell back still has mandatory V2 owner
// metadata, and is named when the replacement binding no longer allows it.
func TestAToolThatFellBackIsStillRemoved(t *testing.T) {
	narrow := strings.Replace(restrictedBinding, `"platform": "postgres"`, `"platform": "postgres2"`, 1)
	f := newConnectFixture(t, twoToolBinding, ``)
	if err := os.WriteFile(filepath.Join(f.catalog, "postgres2.json"), []byte(narrow), 0o644); err != nil {
		t.Fatal(err)
	}
	f.captured = `{"query":{"description":"Run a query"}}`
	if _, err := connect(context.Background(), f.request(), f.host, f.check); err != nil {
		t.Fatal(err)
	}
	req := f.request()
	req.replace, req.binding = true, "postgres2"
	out, err := connect(context.Background(), req, f.host, f.check)
	if err != nil {
		t.Fatal(err)
	}
	// The V2 snapshot retains its exact identity and owner declaration.
	if !hasLine(out.answers, "warehouse/live: descriptors: against the previous snapshot: explain removed") {
		t.Fatalf("%q", out.answers)
	}
}

// Historical V1 captures could omit a screened tool entirely. Keep those
// exact rendering semantics without granting that evidence current admission.
func historicalCapture(t *testing.T, tools, fallbacks string, allowed []string) (liveCapture, *operation) {
	t.Helper()
	op := &operation{name: "live", tools: allowed}
	ref := "postgres@" + digestOf(historicalRestrictedBinding)
	report := `{"check":{"descriptors":{"binding":"` + ref + `","capturedAt":"2026-09-15T00:00:00Z","platform":"warehouse","policy":1,"tools":` + tools + `},"fallbacks":` + fallbacks + `}}`
	capture, err := readCapture([]byte(report), "warehouse", ref, op)
	if err != nil {
		t.Fatal(err)
	}
	if capture.snap.version != "" {
		t.Fatal("historical probe must remain V1")
	}
	return capture, op
}

func TestTheComparisonNamesNoToolTheAdapterScreened(t *testing.T) {
	before, narrow := historicalCapture(t, capturedQuery, `[]`, []string{"query"})
	now, wide := historicalCapture(t, capturedQuery, `[{"tool":"lookup_[redacted]","allowed":1,"part":"tool","reason":"its name holds a value of the credentials"}]`, []string{"query", "lookup_swordfish"})
	added := compareLines(&before.snap, map[string]bool{"query": true}, now, wide)
	if !hasLine(added, "descriptors: against the previous snapshot: lookup_[redacted] added") {
		t.Fatalf("%q", added)
	}
	removed := compareLines(&now.snap, map[string]bool{"query": true, "lookup_swordfish": true}, before, narrow)
	if !hasLine(removed, "descriptors: against the previous snapshot: 1 tool no snapshot names removed") {
		t.Fatalf("%q", removed)
	}
	var stdout, stderr bytes.Buffer
	answers := append(captureLines(now, wide), added...)
	answers = append(answers, removed...)
	if printOutcome(&stdout, &stderr, "warehouse", connectOutcome{answers: answers}, nil) != 0 || stderr.Len() != 0 || strings.Contains(stdout.String(), "swordfish") {
		t.Fatalf("historical screened name printed: %q %q", stdout.String(), stderr.String())
	}
}

// Current registration exercises the actual adapter and server. A credential
// in an exact owner key refuses capture, rather than publishing a partial V2 map.
func TestV2ConnectRefusesACredentialBearingOwnerName(t *testing.T) {
	bin, _ := buildMCPStandIns(t, t.TempDir())
	server := newWriteStandIn(t, customerTools)
	f, req, initialCheck, adapt := customerFixture(t, bin, customerBinding(server.URL, ""), false)
	if _, err := connect(context.Background(), req, f.host, initialCheck); err != nil {
		t.Fatal(err)
	}
	inventory := func() map[string]string {
		t.Helper()
		entries, err := os.ReadDir(f.config + ".descriptors")
		if err != nil {
			t.Fatal(err)
		}
		files := map[string]string{}
		declarations, snapshots := 0, 0
		for _, entry := range entries {
			if !entry.Type().IsRegular() {
				t.Fatalf("unexpected evidence: %s", entry.Name())
			}
			data, err := os.ReadFile(filepath.Join(f.config+".descriptors", entry.Name()))
			if err != nil {
				t.Fatal(err)
			}
			files[entry.Name()] = digestOf(string(data))
			if bytes.Contains(data, []byte(`"declarationVersion":"1"`)) {
				declarations++
			}
			if bytes.Contains(data, []byte(`"snapshotVersion":"2"`)) {
				snapshots++
			}
		}
		if declarations != 1 || snapshots != 1 || len(files) != 2 {
			t.Fatalf("expected separate owner declaration and approved snapshot: %v", files)
		}
		return files
	}
	beforeInventory := inventory()
	before := f.fileText(t)
	req.replace = true
	check := func(ctx context.Context, spec sourceSpec) ([]byte, error) {
		f.asked = append(f.asked, spec)
		spec = adapt(spec)
		for _, arg := range spec.argv {
			if path, ok := strings.CutPrefix(arg, "--credentials="); ok {
				if err := os.WriteFile(path, []byte(`{"token":"query"}`), 0o600); err != nil {
					t.Fatal(err)
				}
			}
		}
		return runCheck(ctx, spec)
	}
	out, err := connect(context.Background(), req, f.host, check)
	if err == nil || !strings.Contains(err.Error(), "the server's answer repeats the credential") || f.fileText(t) != before || out.written != "" {
		t.Fatalf("credential-bearing owner capture must refuse before replacement: %v", err)
	}
	if targetCalls(server) != 0 {
		t.Fatal("refused capture called a tool")
	}
	if after := inventory(); !reflect.DeepEqual(beforeInventory, after) {
		t.Fatalf("refused replacement changed approved evidence or retained declaration: before %v after %v", beforeInventory, after)
	}
	var stdout, stderr bytes.Buffer
	if printOutcome(&stdout, &stderr, "warehouse", out, err) != 1 || strings.Contains(stdout.String()+stderr.String(), "query") {
		t.Fatalf("credential in diagnostics: %q %q", stdout.String(), stderr.String())
	}
}

// The server's identity is compared as the tools are: the words a
// description quotes change with it.
func TestTheServersIdentityIsCompared(t *testing.T) {
	f := newConnectFixture(t, restrictedBinding, ``)
	f.captured = capturedQuery
	if _, err := connect(context.Background(), f.request(), f.host, f.check); err != nil {
		t.Fatal(err)
	}
	req := f.request()
	req.replace = true
	base := `{"snapshotVersion":"2","operation":"live","binding":"postgres@` + digestOf(restrictedBinding) + `","capturedAt":"2026-09-15T00:00:00Z","platform":"warehouse","policy":1,`
	f.snapshotAs = base + `"server":{"name":"postgres-mcp","version":"0.4.0"},"tools":` + capturedOwnedQuery + `}`
	out, err := connect(context.Background(), req, f.host, f.check)
	if err != nil {
		t.Fatal(err)
	}
	if !hasLine(out.answers, "warehouse/live: descriptors: against the previous snapshot: the server's identity changed") {
		t.Fatalf("%q", out.answers)
	}
	before := f.fileText(t)
	_, pin, approved := pinnedSnapshot(t, f)
	f.snapshotAs = base + `"tools":` + capturedOwnedQuery + `}`
	if _, err := connect(context.Background(), req, f.host, f.check); err == nil || !strings.Contains(err.Error(), "complete V2 snapshot evidence") || f.fileText(t) != before {
		t.Fatalf("V2 missing server identity must refuse before replacement: %v", err)
	}
	_, afterPin, afterApproved := pinnedSnapshot(t, f)
	if afterPin != pin || !bytes.Equal(approved, afterApproved) {
		t.Fatal("refused identity fallback changed the approved snapshot")
	}

	// Historical V1 evidence allowed server identity fallback. Its comparison
	// remains readable, without granting current registration that authority.
	historical, op := historicalCapture(t, capturedQuery, `[]`, []string{"query"})
	withServer := historical
	withServer.snap.server = &snapshotServer{name: "postgres-mcp", version: "0.4.0"}
	for _, tc := range []struct {
		previous *snapshot
		now      liveCapture
		want     string
	}{
		{&withServer.snap, historical, "the server's identity now fallen back"},
		{&historical.snap, withServer, "the server's identity no longer fallen back"},
	} {
		lines := compareLines(tc.previous, map[string]bool{"query": true}, tc.now, op)
		if !hasLine(lines, "descriptors: against the previous snapshot: "+tc.want) {
			t.Fatalf("%q", lines)
		}
	}
}

// What the signer reads is compared as the file holds it: an environment
// given in another order, and a credentials path the judging resolved
// through a link, change nothing.
func TestRestartAdviceComparesWhatIsWritten(t *testing.T) {
	f := newConnectFixture(t, restrictedBinding, ``)
	root := filepath.VolumeName(f.dir) + string(filepath.Separator)
	// A root-owned link among the components, where no real temporary
	// directory lies (macOS keeps them under /var, itself a link).
	linked := filepath.Join(root, "linked-secrets", "warehouse")
	target := filepath.Join(root, "real-secrets", "warehouse")
	f.fs = goodFilesystem(f.seed, target, 1000, 1001)
	f.fs[filepath.Join(root, "linked-secrets")] = fileOwnership{uid: 0, mode: 0o755, link: true}
	linkTargets[filepath.Join(root, "linked-secrets")] = filepath.Join(root, "real-secrets")
	t.Cleanup(func() { delete(linkTargets, filepath.Join(root, "linked-secrets")) })
	f.credentials = linked
	req := f.request()
	req.environment = []string{"A=1", "B=2"}
	if _, err := connect(context.Background(), req, f.host, f.check); err != nil {
		t.Fatal(err)
	}
	req.replace = true
	req.environment = []string{"B=2", "A=1"}
	out, err := connect(context.Background(), req, f.host, f.check)
	if err != nil {
		t.Fatal(err)
	}
	if !hasLine(out.after, "restart: nothing either process reads changed") {
		t.Fatalf("%q", out.after)
	}
}

// A catalog file updated in place no longer digests to the old pin, and
// what the old binding allowed is then not known: the comparison says so,
// and says neither that a tool was added nor that nothing changed.
func TestAComparisonWithoutThePreviousBindingSaysWhatItCannotKnow(t *testing.T) {
	f := newConnectFixture(t, twoToolBinding, ``)
	f.captured = `{"query":{"description":"Run a query"}}` // explain retains owner metadata only
	if _, err := connect(context.Background(), f.request(), f.host, f.check); err != nil {
		t.Fatal(err)
	}
	req := f.request()
	req.replace = true
	// The binding rewritten in place with its tools as they were: explain
	// now has display text too; the previous approved owner entry is known.
	rewritten := strings.Replace(twoToolBinding, `"licence": "MIT"`, `"licence": "MIT-0"`, 1)
	if rewritten == twoToolBinding {
		t.Fatal("the rewrite changed nothing")
	}
	if err := os.WriteFile(filepath.Join(f.catalog, "postgres.json"), []byte(rewritten), 0o644); err != nil {
		t.Fatal(err)
	}
	f.captured = `{"explain":{"description":"Explain"},"query":{"description":"Run a query"}}`
	out, err := connect(context.Background(), req, f.host, f.check)
	if err != nil {
		t.Fatal(err)
	}
	if !hasLine(out.answers, "warehouse/live: descriptors: against the previous snapshot (the previous binding cannot be read, so which tools it allowed is not known): explain changed") {
		t.Fatalf("%q", out.answers)
	}
	// Rewritten again, explain is gone; the comparison still must not
	// claim an addition or unchanged approval without the previous binding.
	if err := os.WriteFile(filepath.Join(f.catalog, "postgres.json"), []byte(strings.Replace(restrictedBinding, `"licence": "MIT"`, `"licence": "MIT-0"`, 1)), 0o644); err != nil {
		t.Fatal(err)
	}
	f.captured = `{"query":{"description":"Run a query"}}`
	req2 := f.request()
	req2.replace = true
	out, err = connect(context.Background(), req2, f.host, f.check)
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range out.answers {
		if strings.Contains(line, "nothing changed") || strings.Contains(line, "added") {
			t.Fatalf("a claim the snapshots cannot support: %q", line)
		}
	}
}

// A fallback is the tool at its position among the allowed tools, whatever
// its label: the adapter redacts and cuts the label, and connect prints the
// label, never the name the adapter screened.
func TestFallbacksAreMatchedByPosition(t *testing.T) {
	f := newConnectFixture(t, twoToolBinding, ``)
	f.captured = `{"query":{"description":"Run a query"}}`
	f.capturedExtra = `"fallbacks":[{"tool":"que[redacted]","allowed":0,"part":"inputSchema","reason":"the tool declares no inputSchema"}],`
	out, err := connect(context.Background(), f.request(), f.host, f.check)
	if err != nil {
		t.Fatal(err)
	}
	if !hasLine(out.answers, "warehouse/live: descriptors: query captured (description 11 bytes); fell back: input schema: the tool declares no inputSchema") || !hasLine(out.answers, "warehouse/live: descriptors: explain captured ()") {
		t.Fatalf("%q", out.answers)
	}
	// V1 alone could fall back a whole screened tool. Position, rather
	// than the redacted or truncated label, identifies that historical tool.
	historical, op := historicalCapture(t, `{"query":{"description":"Run a query"}}`, `[{"tool":"que[redacted]","allowed":0,"part":"inputSchema","reason":"the tool declares no inputSchema"},{"tool":"exp…","allowed":1,"part":"tool","reason":"its name holds a value of the credentials"}]`, []string{"query", "explain"})
	lines := captureLines(historical, op)
	if !hasLine(lines, "descriptors: query captured (description 11 bytes); fell back: input schema: the tool declares no inputSchema") || !hasLine(lines, "descriptors: exp… fell back: tool: its name holds a value of the credentials") {
		t.Fatalf("%q", lines)
	}
	var stdout, stderr bytes.Buffer
	if printOutcome(&stdout, &stderr, "warehouse", connectOutcome{answers: lines}, nil) != 0 || strings.Contains(stdout.String(), "explain") || stderr.Len() != 0 {
		t.Fatalf("screened historical name printed: %q", stdout.String())
	}
	f = newConnectFixture(t, twoToolBinding, ``)
	f.capturedExtra = `"fallbacks":[{"tool":"x","allowed":2,"part":"tool","reason":"r"}],`
	if _, err := connect(context.Background(), f.request(), f.host, f.check); err == nil || !strings.Contains(err.Error(), "names no tool the described operation allows") {
		t.Fatalf("%v", err)
	}
}
