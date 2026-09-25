package pdf

import (
	"bytes"
	"context"
	"crypto/md5"
	"crypto/rc4"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"hash"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"
)

// stopReads is a deadline that passes at the reading of it numbered n and at
// every reading after it, counting every reading; with n of zero it never
// passes. With done set, its Done channel is closed once the reading before
// the nth has been made, as a context's is closed when its deadline passes
// before the next reading of it; without, it is never closed. asked holds
// the readings Done was asked for before: those the interpreter makes, which
// look at Done first.
type stopReads struct {
	context.Context
	n, reads int
	done     bool
	asked    map[int]bool
}

func (c *stopReads) Err() error {
	c.reads++
	if c.n > 0 && c.reads >= c.n {
		return context.DeadlineExceeded
	}
	return nil
}

func (c *stopReads) Deadline() (time.Time, bool) { return time.Time{}, false }

// stopClosed is a closed channel: the Done of a context whose deadline has
// passed.
var stopClosed = func() chan struct{} {
	c := make(chan struct{})
	close(c)
	return c
}()

func (c *stopReads) Done() <-chan struct{} {
	if c.asked == nil {
		c.asked = map[int]bool{}
	}
	c.asked[c.reads+1] = true
	if c.done && c.n > 0 && c.reads >= c.n-1 {
		return stopClosed
	}
	return nil
}

// stopObject is an object of a file the tests below assemble: its number,
// its dictionary or other body, and the data of the stream it is, where it is
// one.
type stopObject struct {
	num  int
	body string
	data []byte
}

// stopWrite writes the objects given, in order, after a header, and returns
// the file and the offset of each object by number.
func stopWrite(objects []stopObject) (*bytes.Buffer, map[int]int) {
	var out bytes.Buffer
	out.WriteString("%PDF-1.7\n")
	offsets := map[int]int{}
	for _, o := range objects {
		offsets[o.num] = out.Len()
		if o.data == nil {
			fmt.Fprintf(&out, "%d 0 obj\n%s\nendobj\n", o.num, o.body)
			continue
		}
		fmt.Fprintf(&out, "%d 0 obj\n%s\nstream\n", o.num, o.body)
		out.Write(o.data)
		out.WriteString("\nendstream\nendobj\n")
	}
	return &out, offsets
}

// stopTable is a file of the objects given read through a cross-reference
// table, whose entry for the object numbered broken, where it is not zero,
// names an offset that holds no object, so that reading it rebuilds the
// cross-reference by scanning.
func stopTable(objects []stopObject, trailer string, broken int) []byte {
	out, offsets := stopWrite(objects)
	nums := make([]int, 0, len(offsets))
	for num := range offsets {
		nums = append(nums, num)
	}
	sort.Ints(nums)
	at := out.Len()
	out.WriteString("xref\n0 1\n0000000000 65535 f \n")
	for _, num := range nums {
		offset := offsets[num]
		if num == broken {
			offset = 3
		}
		fmt.Fprintf(out, "%d 1\n%010d 00000 n \n", num, offset)
	}
	fmt.Fprintf(out, "trailer\n%s\nstartxref\n%d\n%%%%EOF\n", trailer, at)
	return out.Bytes()
}

// stopObjectStream is an object stream of the members given, numbered num,
// whose dictionary carries the fields given, and where each member is placed
// in it; first is where its first member begins in its data.
func stopObjectStream(num int, members []stopObject, fields string) (stream stopObject, placed map[int][2]int, first int) {
	var header, bodies strings.Builder
	placed = map[int][2]int{}
	for i, m := range members {
		fmt.Fprintf(&header, "%d %d ", m.num, bodies.Len())
		bodies.WriteString(m.body + "\n")
		placed[m.num] = [2]int{num, i}
	}
	data := header.String() + bodies.String()
	return stopObject{num: num, body: "<< /Type /ObjStm " + fields + " >>", data: []byte(data)}, placed, header.Len()
}

// stopXrefStream is a file of the objects given read through a
// cross-reference stream numbered num, whose dictionary is dict with LENGTH
// standing for its data's length: /W is [1 4 2] wherever dict gives it. The
// objects placed in object streams are declared there.
func stopXrefStream(objects []stopObject, placed map[int][2]int, num int, dict string, size int) []byte {
	out, offsets := stopWrite(objects)
	at := out.Len()
	offsets[num] = at
	var data bytes.Buffer
	for i := 0; i < size; i++ {
		entry := make([]byte, 7)
		switch {
		case placed[i] != [2]int{}:
			entry[0] = 2
			binary.BigEndian.PutUint32(entry[1:5], uint32(placed[i][0]))
			binary.BigEndian.PutUint16(entry[5:7], uint16(placed[i][1]))
		case offsets[i] != 0:
			entry[0] = 1
			binary.BigEndian.PutUint32(entry[1:5], uint32(offsets[i]))
		}
		data.Write(entry)
	}
	fmt.Fprintf(out, "%d 0 obj\n%s\nstream\n", num, strings.ReplaceAll(dict, "LENGTH", fmt.Sprint(data.Len())))
	out.Write(data.Bytes())
	fmt.Fprintf(out, "\nendstream\nendobj\nstartxref\n%d\n%%%%EOF\n", at)
	return out.Bytes()
}

// stopPages are the objects of a one-page document whose page shows "Hello"
// in a font mapped through a ToUnicode CMap, and an inline image, each
// reached through a reference, and whose page dictionary carries a comment
// long enough that its parse reads the deadline. The content's length is
// object 7.
func stopPages() []stopObject {
	content := "BT /F1 12 Tf 72 700 Td (Hello) Tj ET BI /W 1 /H 1 /BPC 8 /CS /G /F /AHx ID 00> EI"
	cmap := "/CIDInit /ProcSet findresource begin 12 dict begin begincmap 1 begincodespacerange <00> <FF> endcodespacerange 1 beginbfchar <48> <0048> endbfchar endcmap CMapName currentdict /CMap defineresource pop end end"
	return []stopObject{
		{num: 1, body: "<< /Type /Catalog /Pages 2 0 R >>"},
		{num: 2, body: "<< /Type /Pages /Kids [3 0 R] /Count 1 >>"},
		{num: 3, body: "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] %" + strings.Repeat("x", 20000) + "\n/Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >>"},
		{num: 4, body: "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding /ToUnicode 6 0 R >>"},
		{num: 5, body: "<< /Length 7 0 R >>", data: []byte(content)},
		{num: 6, body: fmt.Sprintf("<< /Length %d >>", len(cmap)), data: []byte(cmap)},
		{num: 7, body: fmt.Sprint(len(content))},
	}
}

// stopFiles are the structured files every reading position is tried on.
func stopFiles(t *testing.T) []struct {
	name string
	data []byte
	// every is the step between the reading positions tried: one for every
	// position, more for a file whose reading makes many.
	every int
} {
	t.Helper()
	pages := stopPages()

	// A cross-reference stream whose /W, /Size and /Index are each an object
	// of their own.
	indirect := append(append([]stopObject{}, pages...),
		stopObject{num: 8, body: "[1 4 2]"},
		stopObject{num: 9, body: "12"},
		stopObject{num: 10, body: "[0 12]"})
	xrefStream := stopXrefStream(indirect, nil, 11, "<< /Type /XRef /W 8 0 R /Size 9 0 R /Index 10 0 R /Root 1 0 R /Length LENGTH >>", 12)

	// The catalog, the pages, the page and the font in an object stream whose
	// /N, /First and /Length are objects of their own.
	members := pages[:4]
	objStm, placed, first := stopObjectStream(12, members, "/N 13 0 R /First 14 0 R /Length 15 0 R")
	inStreams := append(append([]stopObject{}, pages[4:]...), objStm,
		stopObject{num: 13, body: fmt.Sprint(len(members))},
		stopObject{num: 14, body: fmt.Sprint(first)},
		stopObject{num: 15, body: fmt.Sprint(len(objStm.data))})
	objectStream := stopXrefStream(inStreams, placed, 16, "<< /Type /XRef /W [1 4 2] /Size 17 /Root 1 0 R /Length LENGTH >>", 17)

	// A cross-reference table whose entry for the font names no object, so
	// that the page's reading of it rebuilds the cross-reference.
	rebuilt := stopTable(pages, "<< /Size 8 /Root 1 0 R >>", 4)

	// A page tree whose /Kids names an object the cross-reference does not
	// name: with no deadline, a defect of the file, and with the deadline
	// found passed once that is known, the deadline.
	missingKids := stopTable([]stopObject{
		{num: 1, body: "<< /Type /Catalog /Pages 2 0 R >>"},
		{num: 2, body: "<< /Type /Pages /Kids 99 0 R /Count 1 >>"},
	}, "<< /Size 3 /Root 1 0 R >>", 0)

	files := []struct {
		name  string
		data  []byte
		every int
	}{
		{"a cross-reference stream with indirect /W, /Size and /Index", xrefStream, 1},
		{"an object stream with indirect /N, /First and /Length", objectStream, 1},
		{"a table whose font's entry rebuilds the cross-reference", rebuilt, 1},
		{"the xref-W file of the review", reviewXrefWFile(), 1},
		{"the catalog file of the review", reviewCatalogFile(), 1},
		{"the nested rebuild of the second review", nestedRebuildFile(), 1},
		{"an encrypted file whose stream filter is read past a comment", stopCryptFile(), 1},
		{"a page tree whose /Kids names no object", missingKids, 1},
	}
	if !testing.Short() && raceFactor == 1 {
		// A trailer at the bound, parsed at over a second a reading: one
		// reading position in every 350 of the 1,400 or so it makes. Under
		// the race detector each trial of it costs ten seconds, and it is
		// left out, as from a short run.
		files = append(files, struct {
			name  string
			data  []byte
			every int
		}{"a trailer one member past the bound", lastMemberFile(), 350})
	}
	return files
}

// reviewXrefWFile is the file the first review found a deadline in an
// indirect /W rebuild from: a table whose /XRefStm is a stream with /W 10 0 R,
// object 10 holding [1 1 1] and a comment its lexer reads the deadline in.
func reviewXrefWFile() []byte {
	var b bytes.Buffer
	b.WriteString("%PDF-1.7\n")
	one := b.Len()
	b.WriteString("1 0 obj << /Type /Catalog /Pages 2 0 R >> endobj\n")
	two := b.Len()
	b.WriteString("2 0 obj << /Type /Pages /Kids [] >> endobj\n")
	ten := b.Len()
	b.WriteString("10 0 obj [1 1 1] %" + strings.Repeat("x", 20000) + "\nendobj\n")
	nine := b.Len()
	b.WriteString("9 0 obj << /Type /XRef /W 10 0 R /Size 1 /Length 3 >> stream\n\x00\x00\x00\nendstream\nendobj\n")
	x := b.Len()
	fmt.Fprintf(&b, "xref\n1 2\n%d 0 n\n%d 0 n\n9 2\n%d 0 n\n%d 0 n\ntrailer << /Root 1 0 R /XRefStm %d >>\nstartxref\n%d\n%%%%EOF", one, two, nine, ten, nine, x)
	return b.Bytes()
}

// reviewCatalogFile is the file the first review found a deadline in the
// catalog rebuild from: a catalog holding a string its lexer reads the
// deadline in.
func reviewCatalogFile() []byte {
	var b bytes.Buffer
	b.WriteString("%PDF-1.7\n")
	one := b.Len()
	b.WriteString("1 0 obj << /Type /Catalog /Pages 2 0 R /A (" + strings.Repeat("s", 40000) + ") >> endobj\n")
	two := b.Len()
	b.WriteString("2 0 obj << /Type /Pages /Kids [] >> endobj\n")
	x := b.Len()
	fmt.Fprintf(&b, "xref\n1 2\n%d 0 n\n%d 0 n\ntrailer << /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF", one, two, x)
	return b.Bytes()
}

// nestedRebuildFile is the file the second review found a deadline in a
// nested rebuild lost from: a table naming object 99999 at byte 1, whose
// /Prev is a cross-reference stream with /Length 99999 0 R -- reading it
// rebuilds the cross-reference -- and an object stream of 65,536 places with
// a recoverable page tree after it.
func nestedRebuildFile() []byte {
	var b bytes.Buffer
	b.Write(rebuildLoops()[2].data)
	b.WriteString("70000 0 obj << /Type /Catalog /Pages 70001 0 R >>endobj\n70001 0 obj << /Type /Pages /Kids [70002 0 R] /Count 1 >>endobj\n70002 0 obj << /Type /Page /Parent 70001 0 R >>endobj\n")
	prev := b.Len()
	b.WriteString("70003 0 obj << /Type /XRef /Size 1 /W [1 1 1] /Length 99999 0 R >>stream\n\nendstream\nendobj\n")
	xref := b.Len()
	fmt.Fprintf(&b, "xref\n99999 1\n0000000001 00000 n \ntrailer << /Prev %d >>\nstartxref\n%d\n%%%%EOF\n", prev, xref)
	return b.Bytes()
}

// stopCryptFile is the file of the second review whose encryption handler
// was installed after the deadline stopped the document: the pages of
// stopPages, their streams encrypted with RC4 under the empty user password,
// through a revision 4 dictionary whose strings are read through Identity and
// whose streams through the crypt filter object 10 names -- /StdCF, followed
// by a comment of 40,000 bytes the lexer reads the deadline in. Stopped
// there, the name is unread, and it is not Identity.
func stopCryptFile() []byte {
	id := []byte("0123456789abcdef")
	o := bytes.Repeat([]byte{42}, 32)
	key := computeLegacyKey(nil, o, -4, id, 4, 16, true)
	sum := md5.Sum(append(append([]byte{}, passwordPad...), id...))
	u := append([]byte{}, sum[:]...)
	for i := 0; i < 20; i++ {
		k := append([]byte{}, key...)
		for j := range k {
			k[j] ^= byte(i)
		}
		c, _ := rc4.NewCipher(k)
		c.XORKeyStream(u, u)
	}
	u = append(u, make([]byte, 16)...)
	pages := stopPages()
	h := &cryptHandler{key: key, streams: cryptRC4}
	for i := range pages {
		if pages[i].data != nil {
			pages[i].data, _ = h.decrypt(cryptRC4, pages[i].data, pages[i].num, 0)
		}
	}
	pages = append(pages,
		stopObject{num: 8, body: fmt.Sprintf("<< /Filter /Standard /V 4 /R 4 /Length 128 /P -4 /O <%x> /U <%x> /CF << /StdCF << /CFM /V2 >> >> /StrF /Identity /StmF 10 0 R >>", o, u)},
		stopObject{num: 10, body: "/StdCF %" + strings.Repeat("x", 40000) + "\n"})
	return stopTable(pages, fmt.Sprintf("<< /Root 1 0 R /Size 11 /Encrypt 8 0 R /ID [<%x> <%x>] >>", id, id), 0)
}

// stopIdentity names a value the document holds by what it is and what it
// holds: a reference type by where it lies, how long it is and a digest of
// everything it reaches, and anything else by its value, so that two states
// can be told apart by what they hold, down to the contents of what they
// hold, and not only by what they hold it under.
func stopIdentity(v any) string {
	if v == nil {
		return "nil"
	}
	rv := reflect.ValueOf(v)
	switch rv.Kind() {
	case reflect.Pointer, reflect.Map, reflect.Slice:
		h := sha256.New()
		stopDigest(h, rv, map[uintptr]bool{})
		return fmt.Sprintf("%T@%x#%d:%x", v, rv.Pointer(), stopLen(rv), h.Sum(nil)[:12])
	}
	return fmt.Sprintf("%T:%#v", v, v)
}

func stopLen(rv reflect.Value) int {
	switch rv.Kind() {
	case reflect.Map, reflect.Slice:
		return rv.Len()
	}
	return 0
}

// stopDigest writes everything v holds to h: what a pointer, an interface, a
// slice or a map holds, and every field of a struct, unexported ones
// included, each pointer followed once.
func stopDigest(h hash.Hash, v reflect.Value, seen map[uintptr]bool) {
	switch v.Kind() {
	case reflect.Invalid:
		h.Write([]byte("nil;"))
	case reflect.Pointer:
		if v.IsNil() {
			h.Write([]byte("nil;"))
			return
		}
		if seen[v.Pointer()] {
			fmt.Fprintf(h, "@%x;", v.Pointer())
			return
		}
		seen[v.Pointer()] = true
		h.Write([]byte("&"))
		stopDigest(h, v.Elem(), seen)
	case reflect.Interface:
		if v.IsNil() {
			h.Write([]byte("nil;"))
			return
		}
		fmt.Fprintf(h, "%s(", v.Elem().Type())
		stopDigest(h, v.Elem(), seen)
		h.Write([]byte(")"))
	case reflect.Slice:
		if v.IsNil() {
			h.Write([]byte("nil;"))
			return
		}
		fmt.Fprintf(h, "[%d:", v.Len())
		if v.Type().Elem().Kind() == reflect.Uint8 {
			h.Write(v.Bytes())
		} else {
			for i := 0; i < v.Len(); i++ {
				stopDigest(h, v.Index(i), seen)
			}
		}
		h.Write([]byte("]"))
	case reflect.Array:
		h.Write([]byte("["))
		for i := 0; i < v.Len(); i++ {
			stopDigest(h, v.Index(i), seen)
		}
		h.Write([]byte("]"))
	case reflect.Map:
		if v.IsNil() {
			h.Write([]byte("nil;"))
			return
		}
		keys := v.MapKeys()
		sort.Slice(keys, func(i, j int) bool {
			a, b := keys[i], keys[j]
			switch a.Kind() {
			case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
				return a.Int() < b.Int()
			case reflect.String:
				return a.String() < b.String()
			}
			return fmt.Sprint(a) < fmt.Sprint(b)
		})
		fmt.Fprintf(h, "{%d:", v.Len())
		for _, k := range keys {
			stopDigest(h, k, seen)
			h.Write([]byte("="))
			stopDigest(h, v.MapIndex(k), seen)
		}
		h.Write([]byte("}"))
	case reflect.Struct:
		h.Write([]byte("{"))
		for i := 0; i < v.NumField(); i++ {
			fmt.Fprintf(h, "%s:", v.Type().Field(i).Name)
			stopDigest(h, v.Field(i), seen)
		}
		h.Write([]byte("}"))
	case reflect.Bool:
		fmt.Fprintf(h, "%v;", v.Bool())
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		h.Write(binary.AppendVarint([]byte{'i'}, v.Int()))
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr:
		h.Write(binary.AppendUvarint([]byte{'u'}, v.Uint()))
	case reflect.Float32, reflect.Float64:
		fmt.Fprintf(h, "%v;", v.Float())
	case reflect.Complex64, reflect.Complex128:
		fmt.Fprintf(h, "%v;", v.Complex())
	case reflect.String:
		fmt.Fprintf(h, "%q;", v.String())
	default:
		// A function, a channel or an unsafe pointer: where it lies.
		fmt.Fprintf(h, "%s@%x;", v.Kind(), v.Pointer())
	}
}

// stopState is what the document holds, by name: its objects, its object
// streams and their headers, its fonts, its CMaps, the heads it has settled,
// its index of stream ends, its encryption handler, the failures it has kept,
// its generation, its cross-reference and its trailer, each with what it
// holds.
func stopState(d *Document) map[string]string {
	s := map[string]string{}
	for k, v := range d.cache {
		s[fmt.Sprintf("object %d", k)] = stopIdentity(v)
	}
	for k, v := range d.objStms {
		s[fmt.Sprintf("object stream %d", k)] = stopIdentity(v)
	}
	for k, v := range d.objStmHeaders {
		s[fmt.Sprintf("object stream header %d", k)] = stopIdentity(v)
	}
	for k, v := range d.fontRefs {
		s[fmt.Sprintf("font %v", k)] = stopIdentity(v)
	}
	for k, v := range d.cmaps {
		s[fmt.Sprintf("CMap %p", k)] = stopIdentity(v)
	}
	for k, v := range d.headTypes {
		s[fmt.Sprintf("head %d", k)] = stopIdentity(v)
	}
	if d.endstream != nil {
		s["stream ends"] = stopIdentity(d.endstream)
	}
	if d.crypt != nil {
		s["handler"] = stopIdentity(d.crypt)
	}
	for name, err := range map[string]error{"bound": d.bound, "file bound": d.fileBound, "undecoded": d.undecoded, "no objects": d.noObjects, "scan unfinished": d.scanUnfinished} {
		if err != nil {
			s[name] = err.Error()
		}
	}
	s["generation"] = fmt.Sprint(d.generation)
	for k, v := range d.xref {
		s[fmt.Sprintf("entry %d", k)] = fmt.Sprint(v)
	}
	for k, v := range d.trailer {
		s["trailer "+string(k)] = stopIdentity(v)
	}
	return s
}

// stopTrial is one extraction under a deadline that passes at the reading of
// it numbered n: the record, the document the deadline stopped, what it held
// when it was stopped, the reading it was stopped at, the readings the
// context was asked for in all, and whether a rebuild began after the stop:
// a document is rebuilt once at most, and the rebuild marks it the moment it
// begins.
type stopTrial struct {
	r                *Result
	d                *Document
	held             map[string]string
	stoppedAt, reads int
	rebuiltAfter     bool
}

// stopRun extracts data under a deadline that passes at the reading of it
// numbered n, its Done channel closed before that reading where done is set.
func stopRun(data []byte, n int, done bool) stopTrial {
	var trial stopTrial
	ctx := &stopReads{Context: context.Background(), n: n, done: done}
	rebuiltBefore := false
	docExpired = func(stopped *Document) {
		if trial.d == nil {
			trial.d, trial.held, trial.stoppedAt, rebuiltBefore = stopped, stopState(stopped), ctx.reads, stopped.reconstructed
		}
	}
	defer func() { docExpired = nil }()
	trial.r = Extract(ctx, data, testOptions())
	trial.reads = ctx.reads
	trial.rebuiltAfter = trial.d != nil && trial.d.reconstructed && !rebuiltBefore
	return trial
}

// stopReadAgain reads a document again from its page tree, as Extract reads
// one whose cross-reference was rebuilt, under the context given.
func stopReadAgain(ctx context.Context, d *Document) *Result {
	r := &Result{}
	if w, generation, stop := walkPages(ctx, d, testOptions(), r); stop == nil && d.generation == generation {
		extractPages(ctx, w, testOptions(), r)
	}
	return r
}

// Once a reading of the deadline has found it passed, the document keeps
// nothing more and publishes nothing more, and the reading ends at the
// deadline and nothing else. Driven through every reading position of each
// file -- the deadline passing at the first reading, the second, and so on
// until the document is read whole, with the context's Done channel closed
// before that reading and without, where the reading asks for it -- the
// reading at that position stops the document, whatever made it: the
// document's loops and lexers, the walk, a page, the interpreter. The record
// says timeout and is neither malformed nor a bound, and says the encryption
// opened only where its handler was installed before the stop; no context is
// asked anything after the stop; no rebuild begins after it; everything the
// document holds at the end it held, with what it held in it, when it was
// stopped, what a rebuild's own end drops being the only change; the stopped
// document read again under a context with time left is the stop still, asks
// that context nothing and keeps nothing; and the file read again with time
// left reads as it reads with no deadline at all.
func TestADocumentKeepsNothingAfterTheDeadline(t *testing.T) {
	for _, f := range stopFiles(t) {
		t.Run(f.name, func(t *testing.T) {
			live := &stopReads{Context: context.Background()}
			whole := Extract(live, f.data, testOptions())
			if whole.TimedOut {
				t.Fatalf("read with no deadline, the file timed out: %+v", whole)
			}
			t.Logf("read whole: %d pages, fatal %v, %d readings of the deadline", len(whole.Pages), whole.Fatal, live.reads)
			tried := 0
			// Under the race detector one position in raceFactor of those
			// the ordinary run tries is tried: the reader and these tests
			// run on one goroutine, so the positions differ in nothing the
			// detector looks for, and each costs it several times what it
			// costs off it.
			for n := 1; n <= live.reads; n += f.every * raceFactor {
				// A reading Done was not asked for before is made the same
				// way with Done closed, and is tried without it only.
				dones := []bool{false}
				if live.asked[n] {
					dones = append(dones, true)
				}
				for _, done := range dones {
					at := fmt.Sprintf("deadline at reading %d, Done closed %v", n, done)
					trial := stopRun(f.data, n, done)
					r, d := trial.r, trial.d
					if !r.TimedOut || r.Fatal != nil || len(r.Pages) != 0 {
						t.Fatalf("%s: timedOut %v fatal %+v pages %+v problems %+v", at, r.TimedOut, r.Fatal, r.Pages, r.Problems)
					}
					if d == nil || trial.stoppedAt != n {
						t.Fatalf("%s: the reading that found it passed did not stop the document: stopped %v, at reading %d", at, d != nil, trial.stoppedAt)
					}
					if _, installed := trial.held["handler"]; r.Encryption != nil && r.Encryption.Opened && !installed {
						t.Fatalf("%s: the record says the encryption opened, and no handler was installed before the stop", at)
					}
					if trial.reads != n {
						t.Fatalf("%s: the context was asked %d times, %d of them after the stop", at, trial.reads, trial.reads-n)
					}
					if trial.rebuiltAfter {
						t.Fatalf("%s: a rebuild began after the document was stopped", at)
					}
					end := stopState(d)
					for key, now := range end {
						if then, ok := trial.held[key]; !ok || then != now {
							t.Fatalf("%s: after the stop the document came to hold %s as %s, where it held %q", at, key, now, then)
						}
					}
					again := &stopReads{Context: context.Background()}
					if r := stopReadAgain(again, d); !r.TimedOut || r.Fatal != nil || len(r.Pages) != 0 || again.reads != 0 {
						t.Fatalf("%s: the stopped document read again with time left: timedOut %v fatal %+v pages %+v, the context asked %d times", at, r.TimedOut, r.Fatal, r.Pages, again.reads)
					}
					if after := stopState(d); !reflect.DeepEqual(after, end) {
						t.Fatalf("%s: the stopped document read again kept what it read", at)
					}
					if raceFactor == 1 {
						if fresh := Extract(context.Background(), f.data, testOptions()); !reflect.DeepEqual(fresh, whole) {
							t.Fatalf("%s: read again with time left, the file reads %+v, and %+v with no deadline", at, fresh, whole)
						}
					}
					tried++
				}
			}
			// Under the race detector the file is read again with time left
			// once, after every trial, rather than after each.
			if fresh := Extract(context.Background(), f.data, testOptions()); !reflect.DeepEqual(fresh, whole) {
				t.Fatalf("read again with time left after the trials, the file reads %+v, and %+v with no deadline", fresh, whole)
			}
			t.Logf("%d trials, each stopping the document at its reading", tried)
			if tried == 0 {
				t.Fatal("no reading position was tried")
			}
		})
	}
}
