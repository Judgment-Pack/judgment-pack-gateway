package main

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"adapters/attachment"
	"adapters/render"
)

const request = `{"format":"docx","document":{"title":"Refund decision","blocks":[{"type":"paragraph","runs":[{"text":"The refund is approved."}]}]}}`

// readCounter counts the reads made of it.
type readCounter struct{ reads int }

func (r *readCounter) Read([]byte) (int, error) {
	r.reads++
	return 0, io.EOF
}

// A command line the adapter does not accept is exit 2 before the request is
// read: nothing of stdin is consumed and nothing is written on stdout.
func TestRunUsage(t *testing.T) {
	for _, args := range [][]string{
		{"positional"},
		{"--unknown"},
		{"--renderer", "two words"},
		{"--renderer"},
		{"--max-request", "0"},
		{"--max-blocks", "0"},
		{"--max-file", "0"},
		{"--max-output", "0"},
		{"--timeout", "0s"},
		{"--timeout", "1500us"},
		{"--max-request", "67108865"},
		{"--max-blocks", "100001"},
		{"--max-file", "67108865"},
		{"--max-output", "1099511627777"},
		{"--timeout", "10m0.001s"},
	} {
		var stdout, stderr bytes.Buffer
		stdin := &readCounter{}
		if code := run(args, stdin, &stdout, &stderr); code != 2 || stdout.Len() != 0 || stdin.reads != 0 || stderr.Len() == 0 {
			t.Errorf("%v: exit %d with %d reads, want 2 with nothing read and nothing on stdout (%s)", args, code, stdin.reads, stderr.String())
		}
	}
	// Every bound at its ceiling is accepted, and the record states them.
	var stdout, stderr bytes.Buffer
	ceilings := []string{"--max-request", "67108864", "--max-blocks", "100000", "--max-file", "67108864", "--max-output", "1099511627776", "--timeout", "10m"}
	if code := run(ceilings, strings.NewReader(request), &stdout, &stderr); code != 0 || !strings.Contains(stdout.String(), `"bounds":{"maxBlocks":100000,"maxFileBytes":67108864,"maxOutputBytes":1099511627776,"maxRequestBytes":67108864,"timeoutMs":600000}`) {
		t.Fatalf("at the ceilings: exit %d: %s %s", code, stderr.String(), stdout.String())
	}
}

// A request rendered is exit 0, nothing on stderr, and on stdout one record
// in canonical form that passes the reference check and names this adapter.
func TestRunWritesARecord(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := run(nil, strings.NewReader(request), &stdout, &stderr); code != 0 || stderr.Len() != 0 {
		t.Fatalf("exit %d: %s", code, stderr.String())
	}
	out := stdout.Bytes()
	if err := render.Check(out); err != nil {
		t.Fatalf("the record does not pass its check: %v: %s", err, out)
	}
	for _, want := range []string{`"renderVersion":"1"`, `"title":"Refund decision"`, `"status":"complete"`, `"adapter":{"digest":"sha256:`, `"name":"adapter-render","version":"` + render.Version + `"`} {
		if !bytes.Contains(out, []byte(want)) {
			t.Errorf("the record does not hold %s: %s", want, out)
		}
	}
	// The record is in the form the gateway attests: members in order, no
	// space between them, and no line ending after it.
	var value any
	dec := json.NewDecoder(bytes.NewReader(out))
	dec.UseNumber()
	if err := dec.Decode(&value); err != nil {
		t.Fatal(err)
	}
	again, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(again, out) {
		t.Errorf("the record is not in canonical form:\n%s\n%s", out, again)
	}
}

// A refused request is exit 1, nothing on stdout, and one refusal line: its
// code first, ASCII, at most 160 bytes.
func TestRunRefusesWithOneLine(t *testing.T) {
	for _, c := range []struct {
		args []string
		in   string
		code string
	}{
		{nil, `not json`, "arguments-invalid"},
		{nil, ``, "arguments-invalid"},
		{nil, `{"format":"docx","document":{"title":"T","blocks":[{"type":"paragraph","runs":[]}]},"éé":1}`, "arguments-invalid"},
		{nil, request + `{}`, "arguments-invalid"},
		{nil, `{"format":"docx","document":{"title":"T","blocks":[{"type":"paragraph","runs":[{"text":"x","é` + strings.Repeat("z", 400) + `":1}]}]}}`, "content-invalid"},
		{[]string{"--max-blocks", "1"}, `{"format":"docx","document":{"title":"T","blocks":[{"type":"paragraph","runs":[]},{"type":"paragraph","runs":[]}]}}`, "content-over-bound"},
		{[]string{"--max-request", "100"}, request, "request-over-bound"},
		{nil, strings.Replace(request, `"docx"`, `"pdf"`, 1), "renderer-not-configured"},
		{[]string{"--renderer", "a-program-that-is-not-there"}, strings.Replace(request, `"docx"`, `"pdf"`, 1), "renderer-failed"},
		{[]string{"--max-file", "100"}, request, "file-over-bound"},
		{[]string{"--max-output", "100"}, request, "record-over-bound"},
	} {
		var stdout, stderr bytes.Buffer
		code := run(c.args, strings.NewReader(c.in), &stdout, &stderr)
		line := stderr.String()
		if code != 1 || stdout.Len() != 0 || !strings.HasPrefix(line, c.code+": ") || strings.Count(line, "\n") != 1 || len(line) > 161 {
			t.Errorf("%s: exit %d stdout %d stderr %q", c.code, code, stdout.Len(), line)
			continue
		}
		for i := 0; i < len(line)-1; i++ {
			if line[i] < 0x20 || line[i] > 0x7e {
				t.Errorf("%s: byte %d of the refusal line is %#x", c.code, i, line[i])
			}
		}
	}
}

// Help that is asked for is written whole: it names every flag and says of
// each what the contract says. It is a usage
// error like any other: exit 2, nothing read and nothing on stdout.
func TestRunWritesItsHelpWhole(t *testing.T) {
	for _, args := range [][]string{{"--help"}, {"-h"}, {"--renderer", "a-rendering-program", "--help"}} {
		var stdout, stderr bytes.Buffer
		stdin := &readCounter{}
		if code := run(args, stdin, &stdout, &stderr); code != 2 || stdout.Len() != 0 || stdin.reads != 0 {
			t.Fatalf("%v: exit %d with %d reads and %d bytes on stdout", args, code, stdin.reads, stdout.Len())
		}
		help := stderr.String()
		if !strings.HasPrefix(help, usage+"\n") || strings.Count(help, usage) != 1 {
			t.Errorf("%v: the help does not begin with the usage, once:\n%s", args, help)
		}
		for _, says := range []string{
			"-max-request", "-max-blocks", "-max-file", "-max-output", "-timeout", "-renderer",
			"keep it under the gateway's timeout for the source, thirty seconds by default",
			"the rendering program for a PDF",
			"none by default, and a PDF is then refused\n",
		} {
			if !strings.Contains(help, says) {
				t.Errorf("%v: the help does not say %q:\n%s", args, says, help)
			}
		}
		if strings.Contains(help, "a-rendering-program") {
			t.Errorf("%v: the help quotes the command line:\n%s", args, help)
		}
		// It is written once, and not again in part. The flags are in the
		// order of their names, so the deadline's is the last.
		if strings.Count(help, "  -max-blocks int") != 1 || !strings.HasSuffix(help, "with room to spare (default 25s)\n") {
			t.Errorf("%v: the help is not written once and whole:\n%s", args, help)
		}
	}
}

// A diagnostic names the fault, and is not the help in its place.
func TestRunNamesTheFaultOfACommandLine(t *testing.T) {
	for says, args := range map[string][]string{
		"flag provided but not defined: -unknown":  {"--unknown"},
		"flag needs an argument: -renderer":        {"--renderer"},
		"invalid value \"soon\" for flag -timeout": {"--timeout", "soon"},
		usage + "\n": {"positional"},
		"adapter-render: max-blocks must be positive and at most 100000\n": {"--max-blocks", "0"},
	} {
		var stdout, stderr bytes.Buffer
		if code := run(args, strings.NewReader(""), &stdout, &stderr); code != 2 || !strings.HasPrefix(stderr.String(), says) {
			t.Errorf("%v: exit %d: %s", args, code, stderr.String())
		}
	}
}

func TestRunBoundsTheUsageDiagnostic(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := run([]string{"--" + strings.Repeat("z", 5000)}, strings.NewReader(""), &stdout, &stderr); code != 2 || stderr.Len() > 1100 {
		t.Fatalf("%d: %d bytes", code, stderr.Len())
	}
}

// failingWriter takes the first bytes it is given, as many as it has room
// for, and refuses the rest.
type failingWriter struct {
	room  int
	taken bytes.Buffer
}

func (w *failingWriter) Write(p []byte) (int, error) {
	n := min(len(p), w.room-w.taken.Len())
	w.taken.Write(p[:n])
	return n, io.ErrClosedPipe
}

// A record that cannot be written is a failure, exit 1, and the adapter says
// so. What stdout had taken by then is not a record, and the gateway reads
// none of the output of a source that failed.
func TestRunSaysSoWhereTheRecordCannotBeWritten(t *testing.T) {
	for _, room := range []int{0, 10} {
		var stderr bytes.Buffer
		stdout := &failingWriter{room: room}
		if code := run(nil, strings.NewReader(request), stdout, &stderr); code != 1 || stderr.String() != "adapter-failed: stdout could not be written\n" || stdout.taken.Len() != room {
			t.Fatalf("with room for %d bytes: exit %d, %d bytes taken: %s", room, code, stdout.taken.Len(), stderr.String())
		}
	}
}

// A refusal is written as its line and not as it stands: a reason that is
// long, that holds a line feed, or that holds a byte outside ASCII reaches
// stderr as one line of ASCII of at most 160 bytes. No reason the adapter
// gives today is any of those, so the refusal is given here.
func TestARefusalReachesStderrAsItsLine(t *testing.T) {
	var stderr bytes.Buffer
	reason := "the title is \u201cna\u00efve\u201d\nand a second line " + strings.Repeat("x", 300)
	if code := refused(&stderr, &render.Refusal{Code: render.CodeContentInvalid, Reason: reason}); code != 1 {
		t.Fatalf("exit %d", code)
	}
	line := stderr.String()
	if len(line) != 161 || strings.Count(line, "\n") != 1 || !strings.HasSuffix(line, "\n") || !strings.HasPrefix(line, "content-invalid: the title is ???na??ve????and a second line xxx") {
		t.Fatalf("stderr holds %d bytes: %q", len(line), line)
	}
	for i := 0; i < len(line)-1; i++ {
		if line[i] < 0x20 || line[i] > 0x7e {
			t.Fatalf("byte %d of the line is %#x", i, line[i])
		}
	}
	// An error that is no refusal is reported as a failure of the adapter,
	// in the adapter's words and not the error's.
	stderr.Reset()
	if code := refused(&stderr, io.ErrUnexpectedEOF); code != 1 || stderr.String() != "adapter-failed: the adapter could not continue\n" {
		t.Fatalf("exit %d: %q", code, stderr.String())
	}
}

// TestMain lets the test's own executable stand in for the adapter's: run
// with asCommand set, it is the command and runs no test.
func TestMain(m *testing.M) {
	if os.Getenv(asCommand) == "1" {
		main()
	}
	os.Exit(m.Run())
}

const asCommand = "ADAPTER_RENDER_TEST_AS_COMMAND"

// A stdout that is a pipe whose reader has gone is a record that cannot be
// written, and the adapter says so and exits 1: it is not ended by the
// signal such a write raises.
func TestAStdoutWhoseReaderHasGoneIsAFailure(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("a pipe whose reader has gone raises no signal on Windows")
	}
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	reader.Close()
	defer writer.Close()
	cmd := exec.Command(self)
	cmd.Env = append(os.Environ(), asCommand+"=1")
	cmd.Stdin = strings.NewReader(request)
	var stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = writer, &stderr
	err = cmd.Run()
	if exit := cmd.ProcessState.ExitCode(); exit != 1 || stderr.String() != "adapter-failed: stdout could not be written\n" {
		t.Fatalf("exit %d (%v): %q", exit, err, stderr.String())
	}
}

// An adapter that cannot read its own executable cannot say what it is, and
// refuses: nothing is rendered by an adapter the record could not identify.
// The executable here may be run and may not be read.
func TestAnExecutableThatCannotBeReadRefuses(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the permissions of a file are not these on Windows")
	}
	if os.Geteuid() == 0 {
		t.Skip("root reads a file whatever its permissions")
	}
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	image, err := os.ReadFile(self)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "adapter-render")
	if err := os.WriteFile(path, image, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		mode   os.FileMode
		exit   int
		stderr string
	}{
		{0o500, 0, ""},
		{0o100, 1, "adapter-failed: the adapter's own executable could not be read\n"},
	} {
		if err := os.Chmod(path, c.mode); err != nil {
			t.Fatal(err)
		}
		cmd := exec.Command(path)
		cmd.Env = append(os.Environ(), asCommand+"=1")
		cmd.Stdin = strings.NewReader(request)
		var stdout, stderr bytes.Buffer
		cmd.Stdout, cmd.Stderr = &stdout, &stderr
		err := cmd.Run()
		if exit := cmd.ProcessState.ExitCode(); exit != c.exit || stderr.String() != c.stderr || (stdout.Len() == 0) != (c.exit != 0) {
			t.Fatalf("mode %o: exit %d (%v) with %d bytes of record: %q", c.mode, exit, err, stdout.Len(), stderr.String())
		}
		if c.exit == 0 {
			if err := render.Check(stdout.Bytes()); err != nil {
				t.Fatalf("mode %o: the record does not pass its check: %v", c.mode, err)
			}
		}
	}
}

var testIdentity = attachment.Identity{Name: "adapter-render", Version: render.Version, Digest: "sha256:" + strings.Repeat("a", 64)}

// The deadline runs from the adapter's start: time spent reading its own
// executable for its identity is inside it, not added to it. A rendering is
// whole or it is refused, so a deadline that has passed writes no record.
func TestDeadlineRunsFromTheStart(t *testing.T) {
	defer func(saved func() (attachment.Identity, error)) { ownIdentity = saved }(ownIdentity)
	for _, c := range []struct {
		delay time.Duration
		exit  int
		want  string
	}{
		{0, 0, `"status":"complete"`},
		{600 * time.Millisecond, 1, ""},
	} {
		ownIdentity = func() (attachment.Identity, error) {
			time.Sleep(c.delay)
			return testIdentity, nil
		}
		var stdout, stderr bytes.Buffer
		code := run([]string{"--timeout", "500ms"}, strings.NewReader(request), &stdout, &stderr)
		if code != c.exit || !strings.Contains(stdout.String(), c.want) {
			t.Fatalf("delay %v: exit %d, want %d: %s %s", c.delay, code, c.exit, stderr.String(), stdout.String())
		}
		if c.exit == 1 && (stdout.Len() != 0 || !strings.HasPrefix(stderr.String(), "timeout: ") && !strings.HasPrefix(stderr.String(), "adapter-failed: the deadline passed")) {
			t.Errorf("delay %v: stdout holds %d bytes and stderr %q", c.delay, stdout.Len(), stderr.String())
		}
	}
}

// durationMs is the wall time from reading the request to writing the
// record: reading the adapter's own executable for its identity happens
// before the request is read, inside the deadline and outside the duration.
func TestDurationRunsFromReadingTheRequest(t *testing.T) {
	defer func(saved func() (attachment.Identity, error)) { ownIdentity = saved }(ownIdentity)
	const delay = 300 * time.Millisecond
	ownIdentity = func() (attachment.Identity, error) {
		time.Sleep(delay)
		return testIdentity, nil
	}
	var stdout, stderr bytes.Buffer
	if code := run([]string{"--timeout", "20s"}, strings.NewReader(request), &stdout, &stderr); code != 0 {
		t.Fatalf("exit %d: %s", code, stderr.String())
	}
	var rec render.Record
	if err := json.Unmarshal(stdout.Bytes(), &rec); err != nil {
		t.Fatalf("%v: %s", err, stdout.String())
	}
	if rec.Rendering.DurationMs >= delay.Milliseconds() {
		t.Fatalf("durationMs is %d after an identity step of %v before the request was read", rec.Rendering.DurationMs, delay)
	}
}

// An identity the adapter cannot read of itself is a refusal, and nothing is
// read of the request.
func TestRunRefusesWithoutItsOwnIdentity(t *testing.T) {
	defer func(saved func() (attachment.Identity, error)) { ownIdentity = saved }(ownIdentity)
	ownIdentity = func() (attachment.Identity, error) {
		return attachment.Identity{}, &render.Refusal{Code: render.CodeAdapterFailed, Reason: "the adapter's own executable could not be read"}
	}
	var stdout, stderr bytes.Buffer
	stdin := &readCounter{}
	if code := run(nil, stdin, &stdout, &stderr); code != 1 || stdout.Len() != 0 || stdin.reads != 0 || !strings.HasPrefix(stderr.String(), "adapter-failed: ") {
		t.Fatalf("exit %d with %d reads: %s", code, stdin.reads, stderr.String())
	}
}
