package pdf_test

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"adapters/attachment"
	"adapters/document"
	"adapters/document/pdf"
	"adapters/internal/pdfgen"
)

// These tests hold the record the document adapter writes of an encrypted
// PDF to what the readings of its encryption dictionary established, at
// every point a deadline can stop them. What the record should say at each
// point is derived from a run with no deadline, from the events of the
// readings alone -- when each began, reached the dictionary, read each of its
// fields, opened it or met the failure it met, and ended, and when the
// cross-reference was replaced -- and from the rule of which field
// establishes which failure, and not from what the reader keeps of the
// readings or from where it decides them.

// recordReadings is a deadline that passes at the reading of it numbered n
// and at every reading after it, counting every reading; with n of zero it
// never passes.
type recordReadings struct {
	context.Context
	n, reads int
}

func (c *recordReadings) Err() error {
	c.reads++
	if c.n > 0 && c.reads >= c.n {
		return context.DeadlineExceeded
	}
	return nil
}

func (c *recordReadings) Deadline() (time.Time, bool) { return time.Time{}, false }

// traced is one event of a run: the readings of the deadline made before
// it, what it was, the reading of the dictionary it belongs to, the field
// read, what the reading had read of the declaration, and the error given.
type traced struct {
	at       int
	event    pdf.EncryptionEvent
	reading  int
	field    string
	handler  *string
	revision *int64
	info     bool
	err      error
}

// expected is what a record declares of the encryption, and the code of the
// error it ends at: "" for none.
type expected struct {
	declared  bool
	handler   *string
	revision  *int64
	opened    bool
	code      string
	whereFrom string
}

func (e expected) String() string {
	if !e.declared {
		return fmt.Sprintf("encryption null, %q (%s)", e.code, e.whereFrom)
	}
	h, r := "null", "null"
	if e.handler != nil {
		h = strconv.Quote(*e.handler)
	}
	if e.revision != nil {
		r = fmt.Sprint(*e.revision)
	}
	return fmt.Sprintf("{%s %s opened %v}, %q (%s)", h, r, e.opened, e.code, e.whereFrom)
}

// establishedBy is the field of the dictionary whose reading establishes the
// failure a reading met, by the rule the failure is: the one read last of the
// fields it depends on. A handler that is not the standard one is /Filter; a
// revision the reader does not implement, or one /V does not go with, is /R,
// read after /V; a key length out of range is /Length; a password string too
// short is that string; an absent /P is /P; the empty user password that does
// not open the document is /U under revisions 5 and 6, which check it against
// /U alone, /ID under revisions 2 and 3, whose key is /O, /P, /ID and the
// key length, and /EncryptMetadata under revision 4, whose key is those and
// it; an /UE too short is /UE; and a crypt filter that is missing, not in /CF
// or of a method the reader does not implement is the field naming it, the
// filter it names, or that filter's /CFM.
func establishedBy(t *testing.T, err error, revision *int64) string {
	msg := err.Error()
	role := regexp.MustCompile(`/(StrF|StmF)`).FindStringSubmatch(msg)
	switch {
	case strings.Contains(msg, "is not a dictionary"):
		return "Encrypt"
	case strings.Contains(msg, `security handler "`):
		return "Filter"
	case strings.Contains(msg, "no integer revision"), strings.Contains(msg, "with /V"), strings.Contains(msg, "security handler revision"):
		return "R"
	case strings.Contains(msg, "/Length"):
		return "Length"
	case strings.Contains(msg, "/O shorter"):
		return "O"
	case strings.Contains(msg, "/UE shorter"):
		return "UE"
	case strings.Contains(msg, "/U shorter"):
		return "U"
	case strings.Contains(msg, "no /P"):
		return "P"
	case strings.Contains(msg, "password") && revision != nil && *revision >= 5:
		return "U"
	case strings.Contains(msg, "password") && revision != nil && *revision == 4:
		return "EncryptMetadata"
	case strings.Contains(msg, "password"):
		return "ID"
	case role != nil && strings.Contains(msg, "/CF is missing"):
		return role[1]
	case role != nil && strings.Contains(msg, "is not in /CF"):
		return role[1] + " filter"
	case role != nil && strings.Contains(msg, "method"):
		return role[1] + " CFM"
	}
	t.Fatalf("no rule says which field establishes the failure %q", msg)
	return ""
}

// oracle is what a record stopped at the reading numbered n says, from the
// events of a run with no deadline, by the rule of the design note: the last
// complete reading of the dictionary -- one that opened it, met a failure
// other than the deadline, or found that the trailer names none -- as it was
// read before the stop, a failure it met standing; where none completed, the
// last reading that reached the dictionary, as far as it had read it, not
// opened; where none reached it, a dictionary declared with nothing of it
// read, if a trailer named one.
//
// A failure is complete once the field that establishes it has been read
// (establishedBy), wherever the reader decides it; an opening once it is
// made; a trailer that names none once the reading ends. A reading counts
// where it began before the stop and the cross-reference it began under was
// not replaced before it ended -- by a replacement made before the stop,
// since after it none is. Every event made before the reading numbered n is
// made in the stopped run as in this one.
func oracle(t *testing.T, events []traced, n int) expected {
	type reading struct {
		began, reached, ended, complete int
		fields                          map[string]int
		failure                         error
		revision                        *int64
		h                               *string
		r                               *int64
		opened, none, named             bool
	}
	readings := map[int]*reading{}
	var order []int
	var replacements []int
	for i, e := range events {
		if e.event == pdf.EncryptionGeneration {
			if e.at < n {
				replacements = append(replacements, i)
			}
			continue
		}
		r := readings[e.reading]
		if r == nil {
			r = &reading{began: -1, reached: -1, ended: -1, complete: -1, fields: map[string]int{}}
			readings[e.reading] = r
			order = append(order, e.reading)
		}
		// How the reading ends with no deadline, and the revision it read,
		// are what establishedBy needs of it, wherever the stop is.
		switch {
		case e.event == pdf.EncryptionDecided && e.err != nil:
			r.failure = e.err
		case e.event == pdf.EncryptionField && e.field == "R":
			r.revision = e.revision
		case e.event == pdf.EncryptionEnded:
			r.ended = i
		}
		if e.at >= n {
			continue
		}
		switch e.event {
		case pdf.EncryptionBegan:
			r.began = i
		case pdf.EncryptionNamed:
			r.named = true
		case pdf.EncryptionReached:
			r.reached = i
		case pdf.EncryptionField:
			if _, ok := r.fields[e.field]; !ok {
				r.fields[e.field] = i
			}
			switch e.field {
			case "Filter":
				r.h = e.handler
			case "R":
				r.r = e.revision
			}
		case pdf.EncryptionDecided:
			if e.err == nil {
				r.opened, r.complete = true, i
			}
		case pdf.EncryptionEnded:
			if !e.info && e.err == nil {
				r.none, r.complete = true, i
			}
		}
	}
	for _, r := range readings {
		if r.failure != nil {
			if i, ok := r.fields[establishedBy(t, r.failure, r.revision)]; ok {
				r.complete = i
			}
		}
	}
	replaced := func(r *reading) bool {
		for _, g := range replacements {
			if g > r.began && (r.ended < 0 || g < r.ended) {
				return true
			}
		}
		return false
	}
	var complete, partial *reading
	named := false
	for _, id := range order {
		r := readings[id]
		if r.began < 0 {
			continue
		}
		named = named || r.named
		if replaced(r) {
			continue
		}
		switch {
		case r.complete >= 0:
			if complete == nil || r.complete > complete.complete {
				complete = r
			}
		case r.reached >= 0:
			if partial == nil || r.reached > partial.reached {
				partial = r
			}
		}
	}
	switch {
	case complete != nil && complete.none:
		return expected{code: "timeout", whereFrom: "a complete reading of a trailer that names none"}
	case complete != nil && complete.opened:
		return expected{declared: true, handler: complete.h, revision: complete.r, opened: true, code: "timeout", whereFrom: "a complete reading that opened"}
	case complete != nil:
		return expected{declared: true, handler: complete.h, revision: complete.r, code: "pdf-encrypted", whereFrom: "a complete reading that failed: " + complete.failure.Error()}
	case partial != nil:
		return expected{declared: true, handler: partial.h, revision: partial.r, code: "timeout", whereFrom: "a partial reading"}
	case named:
		return expected{declared: true, code: "timeout", whereFrom: "a dictionary named and not reached"}
	}
	return expected{code: "timeout", whereFrom: "no reading"}
}

// recordOf runs the document adapter over data under ctx, holds the record
// to attachment.Check, and returns what it declares of the encryption.
func recordOf(t *testing.T, ctx context.Context, data []byte) expected {
	t.Helper()
	req := document.Request{Name: "e.pdf", MediaType: "application/pdf", Bytes: data, OCR: "never", ReceivedAt: time.Date(2026, 9, 16, 14, 5, 11, 0, time.UTC)}
	out, err := document.Process(ctx, document.DefaultConfig(), req, attachment.Identity{Name: "adapter-document", Version: "test", Digest: "sha256:" + strings.Repeat("ab", 32)}, req.ReceivedAt)
	if err != nil {
		t.Fatal(err)
	}
	if err := attachment.Check(out); err != nil {
		t.Fatalf("the record breaks the note's rules: %v\n%s", err, out)
	}
	var rec attachment.Record
	if err := json.Unmarshal(out, &rec); err != nil {
		t.Fatal(err)
	}
	got := expected{}
	if len(rec.Processing.Errors) > 0 {
		got.code = rec.Processing.Errors[0].Code
	}
	if e := rec.Document.Encryption; e != nil {
		got.declared, got.handler, got.revision, got.opened = true, e.Handler, e.Revision, e.Opened
	}
	return got
}

func sameString(a, b *string) bool { return a == nil && b == nil || a != nil && b != nil && *a == *b }
func sameInt(a, b *int64) bool     { return a == nil && b == nil || a != nil && b != nil && *a == *b }

// encryptionRecordFiles are every file the reviews of #160 found a record of
// the encryption wrong on, named by what the review found, and the
// encryption files of the tests before them.
func encryptionRecordFiles(t *testing.T) []struct {
	name string
	data []byte
} {
	type file = struct {
		name string
		data []byte
	}
	rep := func(old, new string) func(string) string {
		return func(d string) string {
			if !strings.Contains(d, old) {
				t.Fatalf("the dictionary does not hold %q: %s", old, d)
			}
			return strings.Replace(d, old, new, 1)
		}
	}
	both := func(fs ...func(string) string) func(string) string {
		return func(d string) string {
			for _, f := range fs {
				d = f(d)
			}
			return d
		}
	}
	hello := func(b *pdfgen.Builder) {
		f := b.Font("Helvetica", "WinAnsiEncoding", "")
		b.Catalog(b.Pages([]pdfgen.Page{{Content: pdfgen.Text("F1", 12, []string{"Hello"}), Fonts: map[string]int{"F1": f}}}))
	}
	encrypted := func(change func(string) string, build func(*pdfgen.Builder)) []byte {
		b := &pdfgen.Builder{Encrypt: &pdfgen.Encryption{Revision: 4, Permissions: -4, Dictionary: change}}
		if build != nil {
			build(b)
		}
		hello(b)
		return b.Bytes()
	}
	// held makes the field given an object of its own, its value followed by
	// a comment of 40,000 bytes the lexer reads the deadline in.
	held := func(field, value string, change func(string) string, build func(*pdfgen.Builder)) []byte {
		b := &pdfgen.Builder{Encrypt: &pdfgen.Encryption{Revision: 4, Permissions: -4}}
		if build != nil {
			build(b)
		}
		hello(b)
		h := b.Add(pdfgen.Object{Body: value + " %" + strings.Repeat("x", 40000) + "\n"})
		b.Encrypt.Dictionary = func(d string) string {
			if change != nil {
				d = change(d)
			}
			return rep(fmt.Sprintf("/%s %s ", field, value), fmt.Sprintf("/%s %d 0 R ", field, h))(d)
		}
		return b.Bytes()
	}
	streams := func(b *pdfgen.Builder) { b.XrefStream, b.ObjectStreams = true, true }
	offByOne := func(b *pdfgen.Builder) { b.BrokenOffsets = 1 }
	streamOffByOne := func(b *pdfgen.Builder) { b.XrefStream, b.BrokenOffsets = true, 1 }
	rebuilt := func(b *pdfgen.Builder) { b.XrefStream, b.ObjectStreams, b.BrokenOffsets = true, true, 1 }
	startxref := func(data []byte) int {
		m := regexp.MustCompile(`startxref\n(\d+)\n%%EOF\n$`).FindSubmatch(data)
		if m == nil {
			t.Fatal("no startxref")
		}
		n, _ := strconv.Atoi(string(m[1]))
		return n
	}
	brokenStartxref := func(data []byte) []byte {
		return append(append([]byte{}, data[:bytes.LastIndex(data, []byte("startxref"))]...), "startxref\n1\n%%EOF\n"...)
	}
	// entry sets the table's entry for object num to the offset given, or to
	// one byte past its own where at is negative.
	entry := func(data []byte, num, at int) []byte {
		x := bytes.LastIndex(data, []byte("xref\n0 "))
		first := bytes.IndexByte(data[x+5:], '\n') + x + 6
		pos := first + 20*num
		if at < 0 {
			old, err := strconv.Atoi(string(data[pos : pos+10]))
			if err != nil {
				t.Fatal(err)
			}
			at = old + 1
		}
		out := append([]byte{}, data...)
		copy(out[pos:], fmt.Sprintf("%010d", at))
		return out
	}
	// streamEntry sets the cross-reference stream's entry for object num to
	// one byte past its own; the stream is written with /W [1 4 4], and not
	// compressed.
	streamEntry := func(data []byte, num int) []byte {
		x := bytes.LastIndex(data, []byte("/Type /XRef"))
		row := bytes.Index(data[x:], []byte("stream\n")) + x + len("stream\n") + 9*num
		out := append([]byte{}, data...)
		binary.BigEndian.PutUint32(out[row+1:row+5], binary.BigEndian.Uint32(data[row+1:row+5])+1)
		return out
	}
	objectNumber := func(data []byte, body string) int {
		m := regexp.MustCompile(`(\d+) 0 obj\n` + regexp.QuoteMeta(body)).FindSubmatch(data)
		if m == nil {
			t.Fatalf("no object %q", body)
		}
		n, _ := strconv.Atoi(string(m[1]))
		return n
	}
	var files []file
	add := func(name string, data []byte) { files = append(files, file{name, data}) }

	// A rebuild open() began, reading the dictionary its trailer names.
	add("a rebuild open() began meets a /P that is not an integer", brokenStartxref(encrypted(rep("/P -4 ", "/P /NotAnInteger "), streams)))
	add("a rebuild open() began opens the dictionary", brokenStartxref(encrypted(nil, streams)))
	// A failure a dictionary's fields establish, then a field held.
	add("/Filter /Other, then /R held", held("R", "4", rep("/Filter /Standard", "/Filter /Other"), nil))
	add("/Filter /Other, then /V held", held("V", "4", rep("/Filter /Standard", "/Filter /Other"), nil))
	add("/R 7, then /P held", held("P", "-4", rep("/R 4 ", "/R 7 "), nil))
	add("/V 3, then /P held", held("P", "-4", rep("/V 4 ", "/V 3 "), nil))
	add("no /R, then /P held", held("P", "-4", rep("/R 4 ", ""), nil))
	add("/R 4.0, then /P held", held("P", "-4", rep("/R 4 ", "/R 4.0 "), nil))
	add("/R 7, then /Length held", held("Length", "128", rep("/R 4 ", "/R 7 "), nil))
	add("/R 1, then /Length held", held("Length", "128", rep("/R 4 ", "/R 1 "), nil))
	add("/CF that cannot be read, then /StmF held", held("StmF", "/StdCF", func(d string) string {
		return regexp.MustCompile(`/CF << /StdCF << [^>]*>> >>`).ReplaceAllString(d, "/CF 999 0 R")
	}, nil))
	add("/CFM not implemented, then /StmF held", held("StmF", "/StdCF", rep("/CFM /V2", "/CFM /Unknown"), nil))
	add("/StrF not in /CF, then /StmF held", held("StmF", "/StdCF", rep("/StrF /StdCF", "/StrF /Nope"), nil))
	add("/Filter /#FF", encrypted(rep("/Filter /Standard ", "/Filter /#FF "), nil))
	add("/P not an integer, then /V held", held("V", "4", rep("/P -4 ", "/P /NotAnInteger "), nil))
	add("/Filter 5, then /V held", held("V", "4", rep("/Filter /Standard ", "/Filter 5 "), nil))
	// A rebuild in the middle of establishEncryption's reading.
	add("/R held, /P not an integer, every offset one byte off", held("R", "4", rep("/P -4 ", "/P /NotAnInteger "), offByOne))
	add("/R held, every offset one byte off", held("R", "4", nil, offByOne))
	add("/R held, every offset of a cross-reference stream one byte off", held("R", "4", nil, streamOffByOne))
	add("/R held, /Filter /Other, every offset of a cross-reference stream one byte off", held("R", "4", rep("/Filter /Standard", "/Filter /Other"), streamOffByOne))
	add("/P not an integer, then /Length held", held("Length", "128", rep("/P -4 ", "/P /NotAnInteger "), nil))
	func() {
		data := held("R", "4", nil, nil)
		root := regexp.MustCompile(`/Root \d+ 0 R`).Find(data)
		data = bytes.Replace(data, root, bytes.Repeat([]byte(" "), len(root)), 1)
		add("no catalog, /R held", bytes.Replace(data, []byte("/Type /Catalog"), []byte("/Type /Catalox"), 1))
	}()
	// An update of the file names another dictionary under the same number.
	func() {
		b := &pdfgen.Builder{Encrypt: &pdfgen.Encryption{Revision: 4, Permissions: -4}, BrokenOffsets: 1}
		hello(b)
		data := b.Bytes()
		other := b.Next()
		add("an update names a dictionary of /Filter /Other", append(data, fmt.Sprintf("%d 0 obj\n<< /Filter /Other %%%s\n>>\nendobj\ntrailer\n<< /Encrypt %d 0 R >>\nstartxref\n%d\n%%%%EOF\n", other, strings.Repeat("x", 40000), other, startxref(data))...))
	}()
	func() {
		var real string
		b := &pdfgen.Builder{Encrypt: &pdfgen.Encryption{Revision: 4, Permissions: -4, Dictionary: func(d string) string { real = d; return "<< /Filter /Other >>" }}, BrokenOffsets: 1}
		hello(b)
		data := b.Bytes()
		other := b.Next()
		body := strings.TrimSuffix(strings.TrimSpace(real), ">>") + " %" + strings.Repeat("x", 40000) + "\n>>"
		add("an update names the dictionary that opens, the file's own /Filter /Other", append(data, fmt.Sprintf("%d 0 obj\n%s\nendobj\ntrailer\n<< /Encrypt %d 0 R >>\nstartxref\n%d\n%%%%EOF\n", other, body, other, startxref(data))...))
	}()
	func() {
		b := &pdfgen.Builder{Encrypt: &pdfgen.Encryption{Revision: 4, Permissions: -4}}
		hello(b)
		h := b.Add(pdfgen.Object{Body: "4"})
		b.Encrypt.Dictionary = rep("/R 4 ", fmt.Sprintf("/R %d 0 R ", h))
		enc := b.Next()
		data := entry(b.Bytes(), h, -1)
		add("/R's entry one byte off, and a later copy of the dictionary with /Filter /Other", append(data, fmt.Sprintf("%d 0 obj\n<< /Filter /Other %%%s\n>>\nendobj\nstartxref\n%d\n%%%%EOF\n", enc, strings.Repeat("x", 40000), startxref(data))...))
	}()
	// A rebuild the walk begins.
	func() {
		b := &pdfgen.Builder{Encrypt: &pdfgen.Encryption{Revision: 4, Permissions: -4}}
		hello(b)
		data := b.Bytes()
		add("the catalog's entry one byte off", entry(data, b.Root, -1))
		add("the page tree's entry one byte off", entry(data, objectNumber(data, "<< /Type /Pages"), -1))
		add("the font's entry one byte off", entry(data, objectNumber(data, "<< /Type /Font"), -1))
	}()
	// A rebuild a field of the dictionary begins.
	for _, c := range []struct {
		name, field, value string
		change             func(string) string
	}{
		{"/Filter an object whose entry is one byte off", "Filter", "/Standard", nil},
		{"/R an object whose entry is one byte off", "R", "4", nil},
		{"/R an object whose entry is one byte off, /Filter /Other", "R", "4", rep("/Filter /Standard", "/Filter /Other")},
		{"/R an object whose entry is one byte off, /P not an integer", "R", "4", rep("/P -4 ", "/P /NotAnInteger ")},
	} {
		b := &pdfgen.Builder{Encrypt: &pdfgen.Encryption{Revision: 4, Permissions: -4}}
		hello(b)
		h := b.Add(pdfgen.Object{Body: c.value})
		b.Add(pdfgen.Object{Body: "<< /Type /ObjStm /N 0 /First 0 >>", Stream: []byte(" ")})
		change := c.change
		b.Encrypt.Dictionary = func(d string) string {
			if change != nil {
				d = change(d)
			}
			return rep(fmt.Sprintf("/%s %s ", c.field, c.value), fmt.Sprintf("/%s %d 0 R ", c.field, h))(d)
		}
		add(c.name, entry(b.Bytes(), h, -1))
	}
	func() {
		b := &pdfgen.Builder{Encrypt: &pdfgen.Encryption{Revision: 4, Permissions: -4}}
		hello(b)
		x := b.Next()
		h := x + 1
		b.Add(pdfgen.Object{Body: fmt.Sprintf("null\nendobj\n%d 0 obj\n/Other", h)})
		b.Add(pdfgen.Object{Body: "/Standard"})
		r := b.Add(pdfgen.Object{Body: "4"})
		b.Add(pdfgen.Object{Body: "<< /Type /ObjStm /N 0 /First 0 >>", Stream: []byte(" ")})
		b.Encrypt.Dictionary = both(rep("/Filter /Standard ", fmt.Sprintf("/Filter %d 0 R ", h)), rep("/R 4 ", fmt.Sprintf("/R %d 0 R ", r)))
		data := b.Bytes()
		stale := bytes.Index(data, []byte(fmt.Sprintf("%d 0 obj\n/Other", h)))
		add("/Filter's entry names a stale copy /Other, /R's entry one byte off", entry(entry(data, h, stale), r, -1))
	}()
	// /R an object of its own outside the object stream -- written as a
	// stream, then rewritten in place as an object followed by a comment --
	// whose entry in the cross-reference stream is one byte off.
	for _, c := range []struct{ name, from, to string }{
		{"/R an object whose entry in a cross-reference stream is one byte off, /Filter /Other", "/Filter /Standard", "/Filter /Other"},
		{"/R an object whose entry in a cross-reference stream is one byte off, /P not an integer", "/P -4 ", "/P /NotAnInteger "},
	} {
		b := &pdfgen.Builder{XrefStream: true, ObjectStreams: true, Encrypt: &pdfgen.Encryption{Revision: 4, Permissions: -4}}
		hello(b)
		h := b.Add(pdfgen.Object{Body: "4", Stream: []byte{}})
		b.Encrypt.Dictionary = both(rep("/R 4 ", fmt.Sprintf("/R %d 0 R ", h)), rep(c.from, c.to))
		data := b.Bytes()
		old := fmt.Sprintf("%d 0 obj\n4 /Length 0 >>\nstream\n\nendstream\nendobj\n", h)
		short := fmt.Sprintf("%d 0 obj\n4 %%\nendobj\n", h)
		if bytes.Count(data, []byte(old)) != 1 {
			t.Fatalf("no object %d as written", h)
		}
		data = bytes.Replace(data, []byte(old), []byte(fmt.Sprintf("%d 0 obj\n4 %%%s\nendobj\n", h, strings.Repeat("x", len(old)-len(short)))), 1)
		add(c.name, streamEntry(data, h))
	}
	func() {
		b := &pdfgen.Builder{Encrypt: &pdfgen.Encryption{Revision: 4, Permissions: -4}}
		hello(b)
		a := b.Add(pdfgen.Object{Body: "4"})
		h := b.Add(pdfgen.Object{Body: "4 %" + strings.Repeat("x", 40000) + "\n"})
		b.Encrypt.Dictionary = both(rep("/V 4 ", fmt.Sprintf("/V %d 0 R ", a)), rep("/R 4 ", fmt.Sprintf("/R %d 0 R ", h)))
		add("/V's entry one byte off, then /R held", entry(b.Bytes(), a, -1))
	}()
	// The encryption files of the tests before these.
	for name, data := range pdf.RebuiltEncryptionFiles() {
		add("two dictionaries under one number: "+name, data)
	}
	add("the sweep's encrypted file", pdf.StopCryptFile())
	add("the sweep's encrypted file whose cross-reference is rebuilt", pdf.StopRebuiltCryptFile())
	add("/StmF held", held("StmF", "/StdCF", nil, nil))
	add("/R held", held("R", "4", nil, nil))
	add("/Filter held", held("Filter", "/Standard", nil, nil))
	add("/Filter /Other", encrypted(rep("/Filter /Standard", "/Filter /Other"), nil))
	add("/P not an integer", encrypted(rep("/P -4 ", "/P /NotAnInteger "), nil))
	add("/Filter /Other, rebuilt", encrypted(rep("/Filter /Standard", "/Filter /Other"), rebuilt))
	add("/P not an integer, rebuilt", encrypted(rep("/P -4 ", "/P /NotAnInteger "), rebuilt))
	add("rebuilt", encrypted(nil, rebuilt))
	add("rebuilt, the dictionary long", encrypted(func(d string) string {
		i := strings.LastIndex(d, ">>")
		return d[:i] + "%" + strings.Repeat("x", 40000) + "\n" + d[i:]
	}, rebuilt))
	return files
}

// At every reading of the deadline a run of each file makes, the record the
// adapter writes when the deadline passes there passes the check and
// declares of the encryption what the oracle derives from the readings of
// the run: the handler, the revision, whether it opened, and the code of the
// error the record ends at.
func TestTheEncryptionRecordIsWhatItsReadingsEstablished(t *testing.T) {
	for _, f := range encryptionRecordFiles(t) {
		t.Run(f.name, func(t *testing.T) {
			var events []traced
			live := &recordReadings{Context: context.Background()}
			undo := pdf.TraceEncryption(func(event pdf.EncryptionEvent, reading, _ int, field string, info *pdf.Encryption, err error) {
				e := traced{at: live.reads, event: event, reading: reading, field: field, err: err, info: info != nil}
				if info != nil {
					if info.Handler != nil {
						h := *info.Handler
						e.handler = &h
					}
					if info.Revision != nil {
						r := *info.Revision
						e.revision = &r
					}
				}
				events = append(events, e)
			})
			whole := recordOf(t, live, f.data)
			undo()
			t.Logf("%d readings, %d events of readings of the dictionary, the record %v", live.reads, len(events), whole)
			wrong := 0
			for n := 1; n <= live.reads+1; n++ {
				want := whole
				if n <= live.reads {
					want = oracle(t, events, n)
				}
				got := recordOf(t, &recordReadings{Context: context.Background(), n: n}, f.data)
				if got.declared != want.declared || !sameString(got.handler, want.handler) || !sameInt(got.revision, want.revision) || got.opened != want.opened || got.code != want.code {
					t.Errorf("deadline at reading %d of %d: the record says %v, and the readings established %v", n, live.reads, got, want)
					if wrong++; wrong == 3 {
						t.FailNow()
					}
				}
			}
		})
	}
}
