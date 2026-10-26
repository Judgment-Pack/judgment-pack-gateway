package main

// gateway posture (#314): the report's shape, the lines judged the same way
// on every platform, the values stated for the platforms that do not check,
// the command and the endpoint.

import (
	"bytes"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

var postureOrder = []string{protectionSourceUser, protectionDescendants, protectionContainerCustody, protectionSeedFile, protectionOperatorPrograms}

// A report is canonical JSON (SPEC.md §1.1): members in code-point order,
// strings as raw UTF-8 with the short escapes. The vector is written by
// hand.
func TestPostureJSONIsCanonical(t *testing.T) {
	report := postureReport{platform: "linux", lines: []postureLine{
		{"source-user-switch", postureNotEnforced, `source "a" runs as the signer's own user`},
		{"seed-file-protection", postureEnforced, "é\tand <done>"},
	}}
	want := `{"platform":"linux","protections":[` +
		`{"name":"source-user-switch","reason":"source \"a\" runs as the signer's own user","state":"not-enforced"},` +
		`{"name":"seed-file-protection","reason":"é\tand <done>","state":"enforced"}]}`
	if got := string(report.canonical()); got != want {
		t.Fatalf("canonical report:\n got %s\nwant %s", got, want)
	}
	// This host's report is canonical too: canonicalizing it again changes
	// nothing, and it has exactly the members stated, in the stated order.
	out := hostPosture(postureInput{}).canonical()
	again, err := canonText(out)
	if err != nil || !bytes.Equal(again, out) {
		t.Fatalf("the host's report is not canonical: %v\n%s", err, out)
	}
	parsed, err := parseJSON(out)
	if err != nil {
		t.Fatal(err)
	}
	top := parsed.(*vObject)
	if len(top.byName) != 2 || top.byName["platform"] != vString(runtime.GOOS) {
		t.Fatalf("the report's members: %s", out)
	}
	protections, _ := top.byName["protections"].(vArray)
	if len(protections) != len(postureOrder) {
		t.Fatalf("one line per protection: %s", out)
	}
	for i, entry := range protections {
		line := entry.(*vObject)
		state := line.byName["state"]
		reason, _ := line.byName["reason"].(vString)
		if len(line.byName) != 3 || line.byName["name"] != vString(postureOrder[i]) || reason == "" ||
			(state != vString(postureEnforced) && state != vString(postureNotEnforced) && state != vString(postureNotApplicable)) {
			t.Fatalf("line %d: %s", i, canon(line))
		}
	}
}

// The values this reference states, rather than checks, for a platform
// other than Linux: a source's descendants not reached, the engine image
// not applicable, and on a platform without a Unix credential model the
// seed's owner and mode not checked. A Unix other than Linux checks its
// seed, so it states nothing for it.
func TestPostureStatementsForOtherPlatforms(t *testing.T) {
	want := map[string]map[string]string{
		"unix": {
			protectionDescendants:      postureNotEnforced,
			protectionContainerCustody: postureNotApplicable,
		},
		"windows": {
			protectionDescendants:      postureNotEnforced,
			protectionContainerCustody: postureNotApplicable,
			protectionSeedFile:         postureNotEnforced,
		},
	}
	if len(postureStatements) != len(want) {
		t.Fatalf("stated families: %v", postureStatements)
	}
	for family, lines := range want {
		stated := postureStatements[family]
		if len(stated) != len(lines) {
			t.Fatalf("%s states %d lines, want %d", family, len(stated), len(lines))
		}
		for name, state := range lines {
			line := stated[name]
			if line.name != name || line.state != state || line.reason == "" || strings.Contains(line.reason, ". ") || strings.HasSuffix(line.reason, ".") {
				t.Fatalf("%s %s: %+v", family, name, line)
			}
		}
	}
	if !strings.Contains(postureStatements["windows"][protectionDescendants].reason, "no process group") {
		t.Fatal("Windows states that it has no process group")
	}
	if !strings.Contains(postureStatements["unix"][protectionDescendants].reason, "elsewhere than Linux") {
		t.Fatal("a Unix other than Linux states that it does not reach a descendant that left the group")
	}
	// The running platform reports its own row where it states one.
	if runtime.GOOS == "linux" {
		return
	}
	report := hostPosture(postureInput{configured: true, seed: filepath.Join(t.TempDir(), "absent.seed")})
	for _, line := range report.lines {
		if stated, ok := postureStatements[postureFamily][line.name]; ok && line != stated {
			t.Fatalf("%s reports %+v, not its stated %+v", runtime.GOOS, line, stated)
		}
	}
}

// The source-user line, flipped one condition at a time: what serve's own
// start check says (switching) and whether a user is root are given, so
// each branch is reached on any host.
func TestPostureSourceUserFlips(t *testing.T) {
	allowed := func(map[string]sourceSpec) error { return nil }
	refused := func(map[string]sourceSpec) error { return errors.New("--source-user a=x: the switch is refused") }
	notRoot := func(string) bool { return false }
	rootIs := func(name string) bool { return name == "root" }
	switched := map[string]sourceSpec{"a": {user: "x"}, "b": {user: "y"}}
	for _, tc := range []struct {
		name      string
		in        postureInput
		switching func(map[string]sourceSpec) error
		isRoot    func(string) bool
		state     string
		reason    string
	}{
		{"no configuration", postureInput{}, allowed, notRoot, postureNotApplicable, "no configuration was named"},
		{"no source", postureInput{configured: true}, allowed, notRoot, postureNotApplicable, "names no source"},
		{"every source switched", postureInput{configured: true, sources: switched}, allowed, notRoot, postureEnforced, "every source runs as a user of its own"},
		{"a source as the signer", postureInput{configured: true, sources: map[string]sourceSpec{"a": {user: "x"}, "b": {}}}, allowed, notRoot, postureNotEnforced, `source "b" runs as the signer's own user`},
		{"two as the signer", postureInput{configured: true, sources: map[string]sourceSpec{"z": {}, "b": {}}}, allowed, notRoot, postureNotEnforced, `sources "b", "z" run as the signer's own user`},
		{"the switch refused", postureInput{configured: true, sources: switched}, refused, notRoot, postureNotEnforced, "serve refuses this configuration here: --source-user a=x"},
		{"a source as root", postureInput{configured: true, sources: map[string]sourceSpec{"a": {user: "root"}, "b": {user: "y"}}}, allowed, rootIs, postureNotEnforced, `source "a" runs as root`},
	} {
		line := sourceUserPosture(tc.in, tc.switching, tc.isRoot)
		if line.name != protectionSourceUser || line.state != tc.state || !strings.Contains(line.reason, tc.reason) {
			t.Fatalf("%s: %+v", tc.name, line)
		}
	}
}

// The seed line with no seed to judge, and the operator programs' line,
// which is the same everywhere.
func TestPostureLinesWithNothingToJudge(t *testing.T) {
	report := hostPosture(postureInput{})
	for i, line := range report.lines {
		if line.name != postureOrder[i] {
			t.Fatalf("line %d is %s, want %s", i, line.name, postureOrder[i])
		}
	}
	if seed := report.lines[3]; seed.state != postureNotApplicable || !strings.Contains(seed.reason, "no seed to judge") {
		t.Fatalf("no configuration, no seed: %+v", seed)
	}
	if seed := hostPosture(postureInput{configured: true}).lines[3]; seed.state != postureNotApplicable || !strings.Contains(seed.reason, "names no seed") {
		t.Fatalf("a configuration naming no seed: %+v", seed)
	}
	if programs := report.lines[4]; programs != operatorProgramsLine || programs.state != postureNotEnforced {
		t.Fatalf("operator programs are never confined: %+v", programs)
	}
}

// The command: the report on stdout and exit 0 whatever it says; a
// command line it cannot read is usage, a configuration it cannot read an
// error.
func TestPostureCommand(t *testing.T) {
	run := func(args ...string) (int, string, string) {
		var stdout, stderr bytes.Buffer
		code := cmdPosture(args, &stdout, &stderr)
		return code, stdout.String(), stderr.String()
	}
	code, out, _ := run()
	if code != 0 || strings.Count(out, "\n") != len(postureOrder) || !strings.HasPrefix(out, protectionSourceUser+" ") {
		t.Fatalf("text report: %d %q", code, out)
	}
	code, out, _ = run("--json")
	if code != 0 || out != string(hostPosture(postureInput{}).canonical()) {
		t.Fatalf("--json writes exactly the canonical bytes: %d %q", code, out)
	}
	dir := t.TempDir()
	seed := filepath.Join(dir, "absent.seed")
	code, out, _ = run("--json", filepath.Join(dir, "store"), seed, "gateway:test", filepath.Join(dir, "registry.jsonl"), "--source", "a="+os.Args[0])
	if code != 0 || !strings.Contains(out, `{"name":"seed-file-protection","reason":"`) || !strings.Contains(out, `source \"a\" runs as the signer's own user`) {
		t.Fatalf("serve's command line is judged: %d %s", code, out)
	}
	if _, err := os.Stat(filepath.Join(dir, "store")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("the posture of a command line makes nothing it names")
	}
	for _, args := range [][]string{{"--bogus"}, {"--config"}, {"--config", "a", "b"}, {"--json", "--json"}, {"a", "b"}} {
		if code, _, stderr := run(args...); code != 2 || stderr == "" {
			t.Fatalf("%q is usage: %d %q", args, code, stderr)
		}
	}
	if code, out, stderr := run("--config", filepath.Join(dir, "absent.json")); code != 1 || out != "" || !strings.HasPrefix(stderr, "posture: ") {
		t.Fatalf("an unreadable configuration is an error: %d %q %q", code, out, stderr)
	}
}

// serve answers the same report at /posture, judging the seed it was
// started with, and holds it to a token where an issuer is configured.
func TestPostureEndpoint(t *testing.T) {
	service, server := testService(t)
	get := func(authorization string) (int, []byte) {
		t.Helper()
		req, err := http.NewRequest(http.MethodGet, server.URL+"/posture", nil)
		if err != nil {
			t.Fatal(err)
		}
		if authorization != "" {
			req.Header.Set("Authorization", authorization)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, body
	}
	code, body := get("")
	want := hostPosture(postureInput{configured: true, sources: service.sources}).canonical()
	if code != http.StatusOK || !bytes.Equal(body, want) {
		t.Fatalf("/posture: %d\n got %s\nwant %s", code, body, want)
	}
	service.seedPath = filepath.Join(t.TempDir(), "absent.seed")
	if _, body := get(""); bytes.Equal(body, want) || !bytes.Contains(body, []byte(`"name":"seed-file-protection"`)) {
		t.Fatalf("the seed serve was started with is judged at each request: %s", body)
	}
	issuer := newIssuer(t)
	id := identityFor(t, issuer)
	service.identity = &id
	if code, _ := get(""); code != http.StatusUnauthorized {
		t.Fatalf("/posture without a token under an issuer: %d", code)
	}
	token := issuer.mint(t, "ec-1", nil, goodClaims(time.Now()))
	if code, _ := get("Bearer " + token); code != http.StatusOK {
		t.Fatalf("/posture with the token: %d", code)
	}
}

// An inherited probe marker makes an ordinary invocation refuse to run, as
// the anchor's does.
func TestStrayPostureProbeMarkerIsRefused(t *testing.T) {
	stderr := captureStderr(t)
	t.Setenv(envPostureProbe, "1")
	if !refuseStrayAnchorMarker() {
		t.Fatal("the marker must be refused")
	}
	if out := stderr(); !strings.Contains(out, envPostureProbe) {
		t.Fatalf("the refusal must name the marker; stderr was %q", out)
	}
}
