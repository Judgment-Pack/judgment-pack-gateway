package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"io"
	"strings"
	"testing"
	"time"

	"adapters/attachment"
	"adapters/document"
	"adapters/internal/pdfgen"
)

func request(t *testing.T, name, mediaType string, data []byte) string {
	t.Helper()
	args := map[string]any{"document": map[string]any{"name": name, "mediaType": mediaType, "bytes": base64.StdEncoding.EncodeToString(data)}}
	out, err := json.Marshal(args)
	if err != nil {
		t.Fatal(err)
	}
	return string(out)
}

// readCounter counts the reads made of it.
type readCounter struct{ reads int }

func (r *readCounter) Read([]byte) (int, error) {
	r.reads++
	return 0, io.EOF
}

func TestRunUsage(t *testing.T) {
	for _, args := range [][]string{
		{"positional"},
		{"--unknown"},
		{"--max-bytes", "0"},
		{"--timeout", "0s"},
		{"--ocr", "two words"},
		{"--timeout", "1500us"},
		// Past a ceiling: the first overflowed the read bound and refused
		// every request, the second wrote a record outside the canonical
		// domain.
		{"--max-bytes", "6917529027641081856"},
		{"--max-inflate", "9007199254740992"},
		{"--max-bytes", "1073741825"},
		{"--max-pages", "1000001"},
		{"--max-text", "1073741825"},
		{"--max-inflate", "4294967297"},
		{"--ocr-max-output", "1073741825"},
		{"--max-output", "1099511627777"},
		{"--timeout", "10m0.001s"},
	} {
		var stdout, stderr bytes.Buffer
		stdin := &readCounter{}
		if code := run(args, stdin, &stdout, &stderr); code != 2 || stdout.Len() != 0 || stdin.reads != 0 {
			t.Errorf("%v: exit %d with %d reads, want 2 with nothing read or written (%s)", args, code, stdin.reads, stderr.String())
		}
	}
	// Every bound at its ceiling is accepted.
	in := request(t, "a.txt", "text/plain", []byte("hello"))
	var stdout, stderr bytes.Buffer
	ceilings := []string{"--max-bytes", "1073741824", "--max-pages", "1000000", "--max-text", "1073741824", "--max-inflate", "4294967296", "--ocr-max-output", "1073741824", "--max-output", "1099511627776", "--timeout", "10m"}
	if code := run(ceilings, strings.NewReader(in), &stdout, &stderr); code != 0 || !strings.Contains(stdout.String(), `"bounds":{"maxBytes":1073741824,"maxInflateBytes":4294967296,"maxOcrOutputBytes":1073741824,"maxPages":1000000,"maxTextBytes":1073741824,"timeoutMs":600000}`) {
		t.Fatalf("at the ceilings: exit %d: %s %s", code, stderr.String(), stdout.String())
	}
}

func TestRunWritesARecord(t *testing.T) {
	b := &pdfgen.Builder{Compress: true}
	f := b.Font("Helvetica", "WinAnsiEncoding", "")
	b.Catalog(b.Pages([]pdfgen.Page{{Content: pdfgen.Text("F1", 12, []string{"Hello record"}), Fonts: map[string]int{"F1": f}}}))
	var stdout, stderr bytes.Buffer
	if code := run(nil, strings.NewReader(request(t, "hello.pdf", "application/pdf", b.Bytes())), &stdout, &stderr); code != 0 {
		t.Fatalf("exit %d: %s", code, stderr.String())
	}
	out := stdout.String()
	if !strings.HasPrefix(out, `{"attachmentVersion":"1","content":{`) || !strings.Contains(out, `"text":"Hello record"`) || !strings.Contains(out, `"status":"complete"`) || !strings.Contains(out, `"name":"adapter-document","version":"`) {
		t.Fatalf("record: %s", out)
	}
	// Every number in the record is an integer: the gateway's canon
	// refuses a fraction.
	var generic map[string]any
	dec := json.NewDecoder(strings.NewReader(out))
	dec.UseNumber()
	if err := dec.Decode(&generic); err != nil {
		t.Fatal(err)
	}
	walkNumbers(t, generic)
}

func walkNumbers(t *testing.T, v any) {
	switch x := v.(type) {
	case json.Number:
		if strings.ContainsAny(string(x), ".eE") {
			t.Errorf("non-integer number in the record: %s", x)
		}
	case map[string]any:
		for _, item := range x {
			walkNumbers(t, item)
		}
	case []any:
		for _, item := range x {
			walkNumbers(t, item)
		}
	}
}

// A refused request is exit 1, nothing on stdout, and one refusal line: its
// code first, ASCII, at most 160 bytes.
func TestRunRefusesWithOneLine(t *testing.T) {
	big := bytes.Repeat([]byte("x"), 2000)
	for _, c := range []struct {
		args []string
		in   string
		code string
	}{
		{nil, `not json`, "arguments-invalid"},
		{nil, `{"document":{"name":"a","mediaType":"text/plain","bytes":"AAAA","extra":1}}`, "arguments-invalid"},
		{nil, `{"document":{"name":"a","mediaType":"text/plain","bytes":"***"}}`, "arguments-invalid"},
		{nil, `{"document":{"name":"a","mediaType":"text/plain","bytes":"AAAA","\u00e9\u00e9":1}}`, "arguments-invalid"},
		{[]string{"--max-bytes", "1000"}, request(t, "big.txt", "text/plain", bytes.Repeat([]byte("x"), 60000)), "request-over-bound"},
		{[]string{"--max-bytes", "1999"}, request(t, "big.txt", "text/plain", big[:1999+1]), "document-over-bound"},
		{nil, `{"document":{"name":"a","mediaType":"text/plain","bytes":"aGk=","sha256":"sha256:` + strings.Repeat("0", 64) + `"}}`, "digest-mismatch"},
		{[]string{"--max-output", "100"}, request(t, "n.txt", "text/plain", []byte("hello")), "record-over-bound"},
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

// The deadline runs from the adapter's start: time spent reading its own
// executable for its identity is inside it, not added to it.
func TestDeadlineRunsFromTheStart(t *testing.T) {
	identity, err := document.OwnIdentity()
	if err != nil {
		t.Fatal(err)
	}
	defer func(saved func() (attachment.Identity, error)) { ownIdentity = saved }(ownIdentity)
	b := &pdfgen.Builder{Compress: true}
	f := b.Font("Helvetica", "WinAnsiEncoding", "")
	b.Catalog(b.Pages([]pdfgen.Page{{Content: pdfgen.Text("F1", 12, []string{"Hello record"}), Fonts: map[string]int{"F1": f}}}))
	in := request(t, "hello.pdf", "application/pdf", b.Bytes())
	for _, c := range []struct {
		delay time.Duration
		want  string
	}{
		// Within the deadline, the document is read whole.
		{0, `"status":"complete"`},
		// An identity step past the deadline leaves no time for the walk.
		{600 * time.Millisecond, `"code":"timeout"`},
	} {
		ownIdentity = func() (attachment.Identity, error) {
			time.Sleep(c.delay)
			return identity, nil
		}
		var stdout, stderr bytes.Buffer
		if code := run([]string{"--timeout", "500ms"}, strings.NewReader(in), &stdout, &stderr); code != 0 {
			t.Fatalf("delay %v: exit %d: %s", c.delay, code, stderr.String())
		}
		if !strings.Contains(stdout.String(), c.want) {
			t.Errorf("delay %v: the record does not carry %s: %s", c.delay, c.want, stdout.String())
		}
	}
}

// durationMs is the wall time from reading the request to writing the
// record: reading the adapter's own executable for its identity happens
// before the request is read, inside the deadline and outside the duration.
func TestDurationRunsFromReadingTheRequest(t *testing.T) {
	identity, err := document.OwnIdentity()
	if err != nil {
		t.Fatal(err)
	}
	defer func(saved func() (attachment.Identity, error)) { ownIdentity = saved }(ownIdentity)
	const delay = 300 * time.Millisecond
	ownIdentity = func() (attachment.Identity, error) {
		time.Sleep(delay)
		return identity, nil
	}
	var stdout, stderr bytes.Buffer
	in := request(t, "a.txt", "text/plain", []byte("abc"))
	if code := run([]string{"--timeout", "20s"}, strings.NewReader(in), &stdout, &stderr); code != 0 {
		t.Fatalf("exit %d: %s", code, stderr.String())
	}
	var rec struct {
		Processing struct {
			DurationMs int64 `json:"durationMs"`
		} `json:"processing"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &rec); err != nil {
		t.Fatalf("%v: %s", err, stdout.String())
	}
	if rec.Processing.DurationMs >= delay.Milliseconds() {
		t.Fatalf("durationMs is %d after an identity step of %v before the request was read", rec.Processing.DurationMs, delay)
	}
}
