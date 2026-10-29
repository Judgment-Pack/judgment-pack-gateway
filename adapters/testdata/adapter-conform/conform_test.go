// Package adapterconform runs gateway adapter-conform over every program of
// adapters/cmd that writes an envelope, as the adapter-conform step of
// dev.json (scripts/checks/adapter-conform.sh) runs it: the gateway and the
// programs are built from this checkout, and each program is run by the
// gateway's own command as serve would run it, against the hand-written
// cases under cases/.
//
// Three adapters are run to accepted envelopes against stand-ins served here:
// adapter-airbyte through a stand-in for the container runtime,
// adapter-mcp over stdio to a stand-in server and over Streamable HTTP to a
// remote one over TLS and one in the clear on loopback, and adapter-http
// against a stand-in provider over TLS. The connection programs reach
// providers no stand-in can take the place of from outside their process,
// by design, so each envelope source of the connection local plan is run as
// the plan runs it, with an empty connections directory, to a request it
// refuses before any provider is reached; and the envelope its own code
// writes against the provider stand-ins of its package's tests (written
// there when JPACK_TEST_ENVELOPES names a directory) is handed to the
// gateway's reading by a program that writes it back, under the shape the
// plan declares. That is the source's envelope as its code writes it, not
// as its shipped binary reached a real provider.
//
// It is under testdata so that go test ./... does not run it: the step does,
// with ADAPTER_CONFORM_ENVELOPES naming where the envelopes were written.
package adapterconform

import (
	"bytes"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"testing"

	"adapters/connections"
	"adapters/internal/fakemcp"
	"adapters/internal/fakeruntime"
)

const (
	// envStandIn makes this test binary the stand-in it names: the
	// container runtime adapter-airbyte runs, the MCP server adapter-mcp
	// runs over stdio, or a program that writes back an envelope.
	envStandIn = "ADAPTER_CONFORM_STANDIN"
	// envReplay names the envelope the replaying program writes.
	envReplay = "ADAPTER_CONFORM_REPLAY"
	// envEnvelopes names the directory the envelopes were written to.
	envEnvelopes = "ADAPTER_CONFORM_ENVELOPES"
)

func TestMain(m *testing.M) {
	switch os.Getenv(envStandIn) {
	case "runtime":
		os.Exit(fakeruntime.Run(os.Args[1:]))
	case "server":
		os.Exit(fakemcp.Run(os.Args[1:]))
	case "replay":
		// The request is read, as an adapter reads it, and not looked at.
		_, _ = io.Copy(io.Discard, os.Stdin)
		envelope, err := os.ReadFile(os.Getenv(envReplay))
		if err != nil {
			fmt.Fprintln(os.Stderr, "replay:", err)
			os.Exit(1)
		}
		os.Stdout.Write(envelope)
		os.Exit(0)
	}
	os.Exit(m.Run())
}

// noEnvelope are the programs of adapters/cmd that write no envelope, and
// why. A program in neither this nor a run below fails the test, so a
// program added to the release is run here or said not to be a source of an
// adapter shape.
var noEnvelope = map[string]string{
	"adapter-sandbox":     "a native process launcher and posture/policy reporter; its child remains responsible for the source envelope",
	"adapter-document":    "a bare source, of the command shape: what it writes is the attachment record itself (ADR-0004)",
	"adapter-render":      "a bare source, of the command shape: what it writes is the render record itself (ADR-0006)",
	"gateway-connections": "the connection companion over its parent's pipe, not a source",
	"ocr-cloud":           "an OCR program the document adapters run, not a source",
	"ocr-tesseract":       "an OCR program the document adapters run, not a source",
}

// conformRun is one run of gateway adapter-conform.
type conformRun struct {
	label   string
	program string // under adapters/cmd; "" for this test binary
	shape   string
	cases   string
	env     []string
	args    []string // the program's own
	timeout int      // seconds; 0 for the gateway's default
	// accepts is whether the cases include one the program answers with an
	// envelope the gateway accepts; refusesOnly, whether every case is one
	// the program refuses itself.
	accepts, refusesOnly bool
}

type conformReport struct {
	Shape string `json:"shape"`
	Cases []struct {
		Case       string `json:"case"`
		Expect     string `json:"expect"`
		Outcome    string `json:"outcome"`
		Refusal    string `json:"refusal"`
		Reason     string `json:"reason"`
		Unexpected bool   `json:"unexpected"`
	} `json:"cases"`
	Unexpected int `json:"unexpected"`
}

func exe(name string) string {
	if runtime.GOOS == "windows" {
		return name + ".exe"
	}
	return name
}

func goBuild(t *testing.T, dir string, args ...string) {
	t.Helper()
	goTool, err := exec.LookPath("go")
	if err != nil {
		t.Fatal("the go toolchain builds what is run here:", err)
	}
	build := exec.Command(goTool, append([]string{"build", "-buildvcs=false"}, args...)...)
	build.Dir = dir
	build.Env = append(os.Environ(), "GOWORK=off")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("go build %v: %v\n%s", args, err, out)
	}
}

func writeFile(t *testing.T, path string, data []byte) string {
	t.Helper()
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func absolute(t *testing.T, path string) string {
	t.Helper()
	abs, err := filepath.Abs(path)
	if err != nil {
		t.Fatal(err)
	}
	return abs
}

func TestEveryShippedAdapterConforms(t *testing.T) {
	bin := t.TempDir()
	work := t.TempDir()
	module := absolute(t, filepath.Join("..", ".."))
	plan := connections.ConnectionLocalPlan()

	// Which programs are run, derived from adapters/cmd and the plan.
	entries, err := os.ReadDir(filepath.Join(module, "cmd"))
	if err != nil {
		t.Fatal(err)
	}
	adapters := map[string]bool{"adapter-airbyte": true, "adapter-mcp": true, "adapter-http": true}
	fromPlan := map[string]bool{}
	for _, source := range plan.Sources {
		if source.Shape != "command" {
			fromPlan[source.Executable] = true
		}
	}
	var programs []string
	for _, entry := range entries {
		name := entry.Name()
		if !entry.IsDir() {
			continue
		}
		if _, why := noEnvelope[name]; why {
			if adapters[name] || fromPlan[name] {
				t.Errorf("%s is said to write no envelope, and is run as a source of an adapter shape", name)
			}
			continue
		}
		if !adapters[name] && !fromPlan[name] {
			t.Errorf("adapters/cmd/%s is a shipped program adapter-conform does not run: give it a run here, or say in noEnvelope why it writes no envelope", name)
			continue
		}
		programs = append(programs, name)
	}
	for name := range noEnvelope {
		if _, err := os.Stat(filepath.Join(module, "cmd", name)); err != nil {
			t.Errorf("noEnvelope names %s, which is not a program of adapters/cmd", name)
		}
	}
	sort.Strings(programs)
	if t.Failed() {
		t.FailNow()
	}

	gateway := filepath.Join(bin, exe("gateway"))
	goBuild(t, filepath.Join(module, "..", "go"), "-o", gateway, ".")
	targets := []string{"-o", bin + string(os.PathSeparator)}
	for _, name := range programs {
		targets = append(targets, "./cmd/"+name)
	}
	goBuild(t, module, targets...)

	// The stand-ins served here.
	provider := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer provider-token" || r.URL.Path != "/read" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("ETag", `"decisions-v3"`)
		io.WriteString(w, `{"id":101,"amount":12,"status":"approved"}`)
	}))
	defer provider.Close()
	providerCA := writeFile(t, filepath.Join(work, "provider-ca.pem"), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: provider.Certificate().Raw}))
	providerCredentials := writeFile(t, filepath.Join(work, "provider.json"), []byte(`{"PROVIDER_KEY":"provider-token"}`))
	remoteTLS := fakemcp.NewHTTP(true, fakemcp.Script{})
	defer remoteTLS.Close()
	remoteCA := filepath.Join(work, "remote-ca.pem")
	if err := remoteTLS.WriteCA(remoteCA); err != nil {
		t.Fatal(err)
	}
	remoteClear := fakemcp.NewHTTP(false, fakemcp.Script{})
	defer remoteClear.Close()
	warehouse := writeFile(t, filepath.Join(work, "warehouse.json"), []byte(`{"host":"warehouse.internal","password":"warehouse-secret"}`))
	standins := absolute(t, "standins")
	const image = "airbyte/source-postgres:3.6.1@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

	runs := []conformRun{
		{label: "adapter-airbyte through a stand-in runtime", program: "adapter-airbyte", shape: "airbyte", cases: "airbyte", accepts: true,
			env:  []string{envStandIn + "=runtime", fakeruntime.EnvDiscover + "=" + filepath.Join(standins, "airbyte-discover.jsonl"), fakeruntime.EnvRead + "=" + filepath.Join(standins, "airbyte-read.jsonl")},
			args: []string{"--image", image, "--credentials", warehouse, "--runtime", os.Args[0], "--endpoint", "warehouse.internal:5432"}},
		{label: "adapter-mcp over stdio to a stand-in server", program: "adapter-mcp", shape: "mcp", cases: "mcp", accepts: true,
			env:  []string{envStandIn + "=server"},
			args: []string{"--endpoint", "api.example", "--tools", "query", "--", os.Args[0]}},
		{label: "adapter-mcp to a remote server over TLS", program: "adapter-mcp", shape: "mcp", cases: "mcp", accepts: true,
			args: []string{"--url", remoteTLS.URL, "--ca-file", remoteCA, "--tools", "query"}},
		{label: "adapter-mcp to a remote server in the clear on loopback", program: "adapter-mcp", shape: "mcp", cases: "mcp", accepts: true,
			args: []string{"--url", remoteClear.URL, "--tools", "query"}},
		{label: "adapter-http to a stand-in provider over TLS", program: "adapter-http", shape: "http", cases: "http", accepts: true,
			args: []string{"--endpoint", provider.URL, "--paths", "/read", "--methods", "GET,POST", "--credentials", providerCredentials, "--bearer", "PROVIDER_KEY", "--ca-file", providerCA}},
	}
	// Each envelope source of the plan, as the plan runs it, with a
	// connections directory of its own that holds no connection.
	for _, source := range plan.Sources {
		if source.Shape == "command" {
			continue
		}
		run := conformRun{label: source.ID + ", as the connection local plan runs it, with no connection", program: source.Executable,
			shape: source.Shape, cases: filepath.Join("sources", source.ID), args: source.Args, timeout: source.Timeout, refusesOnly: true}
		if source.Connections {
			state := filepath.Join(work, "connections-"+source.ID)
			if err := os.Mkdir(state, 0o700); err != nil {
				t.Fatal(err)
			}
			run.env = []string{"JPACK_CONNECTIONS_DIR=" + state}
		}
		runs = append(runs, run)
	}
	// Each envelope a source's code wrote, under the shape the plan
	// declares for that source.
	if dir := os.Getenv(envEnvelopes); dir != "" {
		shapes := map[string]string{}
		for _, source := range plan.Sources {
			if source.Shape != "command" {
				shapes[source.ID] = source.Shape
			}
		}
		written, err := filepath.Glob(filepath.Join(dir, "*.json"))
		if err != nil {
			t.Fatal(err)
		}
		sort.Strings(written)
		covered := map[string]bool{}
		for _, path := range written {
			name := strings.TrimSuffix(filepath.Base(path), ".json")
			id, _, _ := strings.Cut(name, ".")
			shape, known := shapes[id]
			if !known {
				t.Errorf("%s: an envelope of no envelope source of the plan", filepath.Base(path))
				continue
			}
			covered[id] = true
			runs = append(runs, conformRun{label: name + ", the envelope its source's code wrote", shape: shape, cases: "replay", accepts: true,
				env: []string{envStandIn + "=replay", envReplay + "=" + absolute(t, path)}})
		}
		for id := range shapes {
			if !covered[id] {
				t.Errorf("no envelope of %s was written to %s: its package's tests write one where JPACK_TEST_ENVELOPES names a directory", id, dir)
			}
		}
	} else {
		t.Logf("%s is not set: the envelopes the sources' code writes are not run here (scripts/checks/adapter-conform.sh sets it)", envEnvelopes)
	}

	cases, unexpected, refusals := 0, 0, 0
	ran := map[string]bool{}
	for _, run := range runs {
		argv := []string{"adapter-conform", "--shape", run.shape, "--vectors", absolute(t, filepath.Join("cases", run.cases)), "--json"}
		if run.timeout > 0 {
			argv = append(argv, "--timeout", strconv.Itoa(run.timeout))
		}
		for _, e := range run.env {
			argv = append(argv, "--env", e)
		}
		program := os.Args[0]
		if run.program != "" {
			program = filepath.Join(bin, exe(run.program))
			ran[run.program] = true
		}
		argv = append(append(argv, "--", program), run.args...)
		cmd := exec.Command(gateway, argv...)
		var stdout, stderr bytes.Buffer
		cmd.Stdout, cmd.Stderr = &stdout, &stderr
		err := cmd.Run()
		var report conformReport
		if decodeErr := json.Unmarshal(stdout.Bytes(), &report); decodeErr != nil {
			t.Errorf("%s: no report (%v, %v): %s", run.label, err, decodeErr, stderr.String())
			continue
		}
		accepted := 0
		for _, c := range report.Cases {
			line := fmt.Sprintf("%s: %s: %s", run.label, c.Case, c.Outcome)
			if c.Refusal != "" {
				line += ": " + c.Refusal + ": " + c.Reason
			}
			if c.Unexpected {
				t.Errorf("UNEXPECTED %s (expected %s)", line, c.Expect)
			} else {
				t.Log(line)
			}
			switch {
			case c.Outcome == "accepted":
				accepted++
			case c.Refusal != "source-failed" || !strings.HasPrefix(c.Reason, "source failed: "):
				// Every refusal a case here expects is the program's own;
				// a timeout, a start that failed, or an answer the gateway
				// would not take is a defect of the program, whatever the
				// gateway's command compared it with.
				t.Errorf("%s: %s: refused, and not by the program itself: %s: %s", run.label, c.Case, c.Refusal, c.Reason)
			default:
				refusals++
			}
		}
		if run.refusesOnly && (accepted != 0 || len(report.Cases) == 0) {
			t.Errorf("%s: %d of %d cases accepted, where each is one the program refuses before reaching a provider", run.label, accepted, len(report.Cases))
		}
		if err != nil && report.Unexpected == 0 {
			t.Errorf("%s: %v: %s", run.label, err, stderr.String())
		}
		if run.accepts && accepted == 0 {
			t.Errorf("%s: no case was accepted", run.label)
		}
		cases += len(report.Cases)
		unexpected += report.Unexpected
	}
	for _, name := range programs {
		if !ran[name] {
			t.Errorf("%s was not run", name)
		}
	}
	t.Logf("adapter-conform: %d runs over %d programs, %d cases, %d unexpected; %d refusals, each the program's own (source-failed)", len(runs), len(programs), cases, unexpected, refusals)
}
