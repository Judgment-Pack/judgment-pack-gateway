package main

import (
	"bytes"
	"encoding/json"
	"io"
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
		// This release has no rendering program to be given.
		{"--renderer", "soffice"},
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

func TestRunBoundsTheUsageDiagnostic(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := run([]string{"--" + strings.Repeat("z", 5000)}, strings.NewReader(""), &stdout, &stderr); code != 2 || stderr.Len() > 1100 {
		t.Fatalf("%d: %d bytes", code, stderr.Len())
	}
}

// failingWriter refuses every write.
type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) { return 0, io.ErrClosedPipe }

func TestRunSaysSoWhereTheRecordCannotBeWritten(t *testing.T) {
	var stderr bytes.Buffer
	if code := run(nil, strings.NewReader(request), failingWriter{}, &stderr); code != 1 || !strings.HasPrefix(stderr.String(), "adapter-failed: ") {
		t.Fatalf("exit %d: %s", code, stderr.String())
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
