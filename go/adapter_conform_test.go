package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// In these tests the adapter is this test binary as the source helper
// (TestMain), each of its modes declared to it with --env, since
// adapter-conform hands an adapter the declared environment alone, as serve
// hands a source.

// conformRun runs gateway adapter-conform in this process.
func conformRun(t *testing.T, stdin string, args ...string) (code int, stdout, stderr string) {
	t.Helper()
	var out, errOut bytes.Buffer
	code = adapterConform(context.Background(), args, strings.NewReader(stdin), &out, &errOut)
	return code, out.String(), errOut.String()
}

// helperArgs declares the helper and its modes, then names this binary as
// the adapter after "--", options first.
func helperArgs(options []string, modes ...string) []string {
	args := append([]string{}, options...)
	args = append(args, "--env", envSourceHelper+"=1")
	for _, mode := range modes {
		args = append(args, "--env", mode)
	}
	return append(args, "--", os.Args[0])
}

func writeCase(t *testing.T, dir, name, text string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
}

func vectorText(t *testing.T, kind, name string) []byte {
	t.Helper()
	text, err := os.ReadFile(filepath.Join(envelopeVectors, kind, name+".json"))
	if err != nil {
		t.Fatal(err)
	}
	return text
}

type conformReport struct {
	Shape string `json:"shape"`
	Cases []struct {
		Case       string `json:"case"`
		Expect     string `json:"expect"`
		Outcome    string `json:"outcome"`
		Reason     string `json:"reason"`
		Unexpected bool   `json:"unexpected"`
	} `json:"cases"`
	Unexpected int `json:"unexpected"`
}

// Every vector that a request can carry is sent as the request to an
// adapter that writes its request back: what adapter-conform makes of each
// answer is what the vector's directory says, refused for the reason the
// vector was written for. Under another shape than mcp, the valid vectors of
// a remote server are refused, and nothing else changes.
func TestAdapterConformReadsTheVectorsAsServeDoes(t *testing.T) {
	dir := t.TempDir()
	want := map[string]string{}
	remote := 0
	for _, kind := range []string{"valid", "invalid"} {
		for _, name := range vectorNames(t, filepath.Join(envelopeVectors, kind)) {
			text := vectorText(t, kind, name)
			if _, err := conformRequest(text); err != nil {
				// Outside the canonical domain, so no request carries it;
				// TestAdapterConformReportsTheSourcesOwnFailures sends one
				// as the adapter's output.
				continue
			}
			expect := map[string]string{"valid": "accepted", "invalid": "refused"}[kind]
			file := kind + "-" + name + ".json"
			writeCase(t, dir, file, fmt.Sprintf(`{"request": %s, "expect": %q}`, text, expect))
			want[file] = name
			if kind == "valid" && strings.Contains(string(text), `"transport"`) {
				remote++
			}
		}
	}
	code, out, errOut := conformRun(t, "", helperArgs([]string{"--shape", "mcp", "--vectors", dir, "--json"}, envSourceEchoStdin+"=1")...)
	if code != 0 {
		t.Fatalf("exit %d: %s %s", code, out, errOut)
	}
	var report conformReport
	if err := json.Unmarshal([]byte(out), &report); err != nil {
		t.Fatalf("%v: %s", err, out)
	}
	if len(report.Cases) != len(want) || report.Unexpected != 0 || report.Shape != "mcp" {
		t.Fatalf("%d cases of %d, %d unexpected: %s", len(report.Cases), len(want), report.Unexpected, out)
	}
	for _, c := range report.Cases {
		name, known := want[c.Case]
		switch {
		case !known:
			t.Errorf("a case not written: %s", c.Case)
		case c.Outcome != c.Expect || c.Unexpected:
			t.Errorf("%s: %s, expected %s: %s", c.Case, c.Outcome, c.Expect, c.Reason)
		case c.Outcome == "refused" && (!strings.HasPrefix(c.Reason, "the adapter's result is not an envelope: ") || !strings.Contains(c.Reason, envelopeRefusals[name])):
			t.Errorf("%s: refused for another reason: %s", c.Case, c.Reason)
		case c.Outcome == "accepted" && c.Reason != "":
			t.Errorf("%s: accepted with a reason: %s", c.Case, c.Reason)
		}
	}

	code, out, _ = conformRun(t, "", helperArgs([]string{"--shape", "http", "--vectors", dir, "--json"}, envSourceEchoStdin+"=1")...)
	report = conformReport{}
	if err := json.Unmarshal([]byte(out), &report); err != nil || code != 1 || report.Unexpected != remote || remote == 0 {
		t.Fatalf("under shape http: exit %d, %d unexpected of %d remote vectors (%v): %s", code, report.Unexpected, remote, err, out)
	}
	for _, c := range report.Cases {
		if c.Unexpected && (!strings.HasPrefix(c.Case, "valid-remote-") || c.Reason != "the adapter's result is not an envelope: acquisition: transport and server are members of shape mcp alone") {
			t.Errorf("under shape http: %s: %s", c.Case, c.Reason)
		}
	}
}

// What the source itself does wrong is a refusal as serve would make it:
// a failure, with the start of what it said; output past the bound; output
// that is no JSON, or outside the canonical domain; time past the timeout;
// and JSON that is not an envelope. A request on stdin is one case,
// expected to be accepted, so each is unexpected and the exit is 1.
func TestAdapterConformReportsTheSourcesOwnFailures(t *testing.T) {
	never := filepath.Join(t.TempDir(), "never")
	for _, c := range []struct {
		name    string
		options []string
		modes   []string
		reason  string
	}{
		{"a failure", nil, []string{envSourceFail + "=1"}, "source failed: source refused"},
		{"output past the bound", []string{"--max-output", "1024"}, []string{envSourceBig + "=2048"}, "source output exceeds 1024 bytes"},
		{"no JSON", nil, []string{envSourceEnvelope + "=not json"}, "source did not return a canonical JSON value: "},
		{"a fraction", nil, []string{envSourceEnvelope + "=" + string(vectorText(t, "invalid", "result-fraction"))}, "source did not return a canonical JSON value: non-integer number is outside the canonical domain"},
		{"past the timeout", []string{"--timeout", "1"}, []string{envSourceWait + "=" + never}, "source did not finish within its 1-second timeout"},
		{"JSON that is no envelope", nil, nil, `the adapter's result is not an envelope: unknown member "checkedSuccessfully"`},
	} {
		t.Run(c.name, func(t *testing.T) {
			options := append([]string{"--shape", "airbyte"}, c.options...)
			code, out, errOut := conformRun(t, `{"stream":"decisions"}`, helperArgs(options, c.modes...)...)
			if code != 1 || errOut != "" {
				t.Fatalf("exit %d: %s %s", code, out, errOut)
			}
			if want := "  UNEXPECTED stdin: refused: " + c.reason; !strings.Contains(out, want) || !strings.HasSuffix(out, "\n1 case(s), 1 unexpected\n") {
				t.Fatalf("want %q in:\n%s", want, out)
			}
		})
	}
}

// The report, for a person and for a program: a case accepted, a case
// refused with its reason, the unexpected one marked, and the count; the
// program's in canonical JSON, a reason only where there is a refusal.
func TestAdapterConformReports(t *testing.T) {
	dir := t.TempDir()
	writeCase(t, dir, "a.json", fmt.Sprintf(`{"request": %s, "expect": "accepted"}`, vectorText(t, "valid", "one-row")))
	writeCase(t, dir, "b.json", `{"expect": "accepted", "request": {}}`)
	writeCase(t, dir, "c.json", `{"request": [], "expect": "refused"}`)
	writeCase(t, dir, "notes.txt", `not a case`)
	code, out, errOut := conformRun(t, "", helperArgs([]string{"--shape", "http", "--vectors", dir, "--json"}, envSourceEchoStdin+"=1")...)
	want := `{"cases":[` +
		`{"case":"a.json","expect":"accepted","outcome":"accepted","unexpected":false},` +
		`{"case":"b.json","expect":"accepted","outcome":"refused","reason":"the adapter's result is not an envelope: missing member \"result\"","unexpected":true},` +
		`{"case":"c.json","expect":"refused","outcome":"refused","reason":"the adapter's result is not an envelope: not an object","unexpected":false}` +
		`],"shape":"http","unexpected":1}`
	if code != 1 || out != want || errOut != "" {
		t.Fatalf("exit %d:\n%s\nwant\n%s\n%s", code, out, want, errOut)
	}
	code, out, _ = conformRun(t, "", helperArgs([]string{"--vectors", dir, "--shape", "http"}, envSourceEchoStdin+"=1")...)
	want = "gateway adapter-conform: shape http, 3 case(s)\n" +
		"  a.json: accepted\n" +
		"  UNEXPECTED b.json: refused: the adapter's result is not an envelope: missing member \"result\" (expected accepted)\n" +
		"  c.json: refused: the adapter's result is not an envelope: not an object\n" +
		"3 case(s), 1 unexpected\n"
	if code != 1 || out != want {
		t.Fatalf("exit %d:\n%s\nwant\n%s", code, out, want)
	}
	// Every case as expected, the expected refusal among them, is exit 0.
	if err := os.Remove(filepath.Join(dir, "b.json")); err != nil {
		t.Fatal(err)
	}
	if code, out, _ := conformRun(t, "", helperArgs([]string{"--vectors", dir, "--shape", "http"}, envSourceEchoStdin+"=1")...); code != 0 || !strings.HasSuffix(out, "\n2 case(s), 0 unexpected\n") {
		t.Fatalf("exit %d: %s", code, out)
	}
}

// The request reaches the adapter in its canonical form, as serve sends a
// source its arguments: an adapter writing back what it was sent shows the
// members in code point order, which the envelope's first unknown member
// names.
func TestAdapterConformSendsTheRequestInItsCanonicalForm(t *testing.T) {
	dir := t.TempDir()
	writeCase(t, dir, "a.json", `{"request": {"zeta": [ 2 ], "alpha": 1}, "expect": "refused"}`)
	code, out, errOut := conformRun(t, "", helperArgs([]string{"--shape", "http", "--vectors", dir}, envSourceEchoStdin+"=1")...)
	if code != 0 || !strings.Contains(out, `a.json: refused: the adapter's result is not an envelope: unknown member "alpha"`) {
		t.Fatalf("exit %d: %s %s", code, out, errOut)
	}
}

// The adapter is handed the declared environment and nothing else: a
// variable named alone carries this process's value, one this process has
// that is not declared does not reach it. The command may be one argument,
// split on white space as --source splits it, with the options on either
// side.
func TestAdapterConformHandsTheAdapterTheDeclaredEnvironment(t *testing.T) {
	envelope := vectorText(t, "valid", "page")
	t.Setenv(envSourceEnvelope, string(envelope))
	t.Setenv(envSourceFail, "1")
	code, out, errOut := conformRun(t, "{}", "--shape", "airbyte", "--env", envSourceHelper+"=1", "--env", envSourceEnvelope, os.Args[0]+" --unused-argument", "--max-output", "4096")
	if code != 0 || out != "gateway adapter-conform: shape airbyte, 1 case(s)\n  stdin: accepted\n1 case(s), 0 unexpected\n" {
		t.Fatalf("exit %d: %s %s", code, out, errOut)
	}
	// Undeclared, the envelope does not reach the helper, which then
	// answers as it does by default.
	code, out, _ = conformRun(t, "{}", "--shape", "airbyte", "--env", envSourceHelper+"=1", os.Args[0])
	if code != 1 || !strings.Contains(out, `unknown member "checkedSuccessfully"`) {
		t.Fatalf("exit %d: %s", code, out)
	}
}

// A command line that is not one, and a case that cannot be read, stop
// before the adapter is started, with exit 2: a case not run is not a case
// passed.
func TestAdapterConformRefusesBeforeRunning(t *testing.T) {
	argv := filepath.Join(t.TempDir(), "argv")
	started := func(t *testing.T) {
		t.Helper()
		if _, err := os.Stat(argv); err == nil {
			t.Fatal("the adapter was started")
		}
	}
	adapter := []string{"--env", envSourceHelper + "=1", "--env", envSourceArgv + "=" + argv, "--env", envSourceEchoStdin + "=1"}
	for _, c := range []struct {
		name string
		args []string
		want string
	}{
		{"no shape", append(append([]string{}, adapter...), "--", os.Args[0]), "--shape is required"},
		{"a shape outside the three", append([]string{"--shape", "command"}, adapter...), `--shape "command" is not airbyte, mcp or http`},
		{"a shape twice", append([]string{"--shape", "http", "--shape", "mcp"}, adapter...), "duplicate --shape option"},
		{"a value missing", []string{"--shape"}, "--shape requires a following value"},
		{"no command", append([]string{"--shape", "http"}, adapter...), "no adapter command is given"},
		{"an empty command", append(append([]string{"--shape", "http"}, adapter...), " "), "no adapter command is given"},
		{"two commands", append(append([]string{"--shape", "http"}, adapter...), os.Args[0], os.Args[0]), "unexpected argument"},
		{"a command and words after --", append(append([]string{"--shape", "http"}, adapter...), os.Args[0], "--", os.Args[0]), "the adapter's command is given once"},
		{"an adapter's own option", append(append([]string{"--shape", "http"}, adapter...), os.Args[0], "--endpoint"), `unknown option "--endpoint"`},
		{"a command not found", append(append([]string{"--shape", "http"}, adapter...), "--", filepath.Join(t.TempDir(), "absent")), "cannot be resolved"},
		{"an environment with no key", append(append([]string{"--shape", "http", "--env", "=x"}, adapter...), "--", os.Args[0]), "--env expects KEY or KEY=VALUE"},
		{"a timeout of nothing", append(append([]string{"--shape", "http", "--timeout", "0"}, adapter...), "--", os.Args[0]), `--timeout "0" is not a whole number of seconds`},
		{"output past the ceiling", append(append([]string{"--shape", "http", "--max-output", "67108865"}, adapter...), "--", os.Args[0]), `--max-output "67108865" is not a number of bytes`},
		{"json twice", append(append([]string{"--shape", "http", "--json", "--json"}, adapter...), "--", os.Args[0]), "duplicate --json option"},
	} {
		t.Run(c.name, func(t *testing.T) {
			code, out, errOut := conformRun(t, "{}", c.args...)
			if code != 2 || out != "" || !strings.Contains(errOut, c.want) || !strings.Contains(errOut, adapterConformUsage) {
				t.Fatalf("exit %d: %q %q", code, out, errOut)
			}
			started(t)
		})
	}

	empty := t.TempDir()
	for _, c := range []struct {
		name  string
		files map[string]string
		stdin string
		dir   string
		want  string
	}{
		{"an empty request", nil, "", "-", "adapter-conform: stdin: the request is not one an acquire request carries: unexpected end of input"},
		{"a request outside the domain", nil, `{"amount":1.5}`, "-", "the request is not one an acquire request carries: non-integer number"},
		{"no directory", nil, "", filepath.Join(empty, "absent"), "absent"},
		{"a directory with no case", nil, "", empty, "holds no case"},
		{"no request", map[string]string{"a.json": `{"expect":"accepted"}`}, "", "", `a.json: no member "request"`},
		{"no expectation", map[string]string{"a.json": `{"request":{}}`}, "", "", `a.json: member "expect" is neither "accepted" nor "refused"`},
		{"another expectation", map[string]string{"a.json": `{"request":{},"expect":"ok"}`}, "", "", `member "expect" is neither`},
		{"an unknown member", map[string]string{"a.json": `{"request":{},"expect":"accepted","about":"x"}`}, "", "", `a.json: json: unknown field "about"`},
		{"a member twice", map[string]string{"a.json": `{"request":{},"request":[],"expect":"accepted"}`}, "", "", `a.json: the member "request" is given twice in one object`},
		{"two values", map[string]string{"a.json": `{"request":{},"expect":"accepted"} {}`}, "", "", "a.json: data follows"},
		{"a request outside the domain", map[string]string{"a.json": `{"request":{"n":1e3},"expect":"accepted"}`}, "", "", "a.json: the request is not one an acquire request carries"},
		{"one bad case among good ones", map[string]string{"a.json": `{"request":{},"expect":"refused"}`, "b.json": `{}`}, "", "", `b.json: no member "request"`},
	} {
		t.Run(c.name, func(t *testing.T) {
			args := []string{"--shape", "http"}
			switch c.dir {
			case "-":
			case "":
				dir := t.TempDir()
				for name, text := range c.files {
					writeCase(t, dir, name, text)
				}
				args = append(args, "--vectors", dir)
			default:
				args = append(args, "--vectors", c.dir)
			}
			code, out, errOut := conformRun(t, c.stdin, append(append(args, adapter...), "--", os.Args[0])...)
			if code != 2 || out != "" || !strings.Contains(errOut, c.want) {
				t.Fatalf("exit %d: %q %q", code, out, errOut)
			}
			started(t)
		})
	}

	// An interruption before a case stops the run, as one.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	var out, errOut bytes.Buffer
	code := adapterConform(ctx, append([]string{"--shape", "http"}, append(adapter, "--", os.Args[0])...), strings.NewReader("{}"), &out, &errOut)
	if code != 2 || out.Len() != 0 || errOut.String() != "adapter-conform: interrupted after 0 of 1 case(s)\n" {
		t.Fatalf("exit %d: %q %q", code, out.String(), errOut.String())
	}
	started(t)
}
