package pdf

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"runtime"
	"runtime/metrics"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"adapters/internal/pdfgen"
)

// boundsRepeatedContent is a one-page document whose /Contents is an array
// naming one stream times times: every element is a stream of its own to
// decode, although the file carries the bytes once.
func boundsRepeatedContent(stream pdfgen.Object, times int) []byte {
	b := &pdfgen.Builder{}
	content := b.Add(stream)
	refs := make([]string, times)
	for i := range refs {
		refs[i] = fmt.Sprintf("%d 0 R", content)
	}
	pages := b.Next()
	b.Add(pdfgen.Object{Body: "placeholder"})
	page := b.Add(pdfgen.Object{Body: fmt.Sprintf("<< /Type /Page /Parent %d 0 R /MediaBox [0 0 612 792] /Resources << >> /Contents [%s] >>", pages, strings.Join(refs, " "))})
	b.Set(pages, pdfgen.Object{Body: fmt.Sprintf("<< /Type /Pages /Kids [%d 0 R] /Count 1 >>", page)})
	b.Catalog(pages)
	return b.Bytes()
}

// boundsFirstPage is the first page of a document opened for a test that
// reads it directly.
func boundsFirstPage(t *testing.T, d *Document) Dict {
	t.Helper()
	root := d.dictOf(d.dictOf(d.trailer["Root"])["Pages"])
	if root == nil {
		t.Fatal("the document names no page tree")
	}
	kids := d.arrayOf(root["Kids"])
	if len(kids) == 0 {
		t.Fatal("the page tree holds no page")
	}
	page := d.dictOf(kids[0])
	if page == nil {
		t.Fatal("the first page could not be read")
	}
	return page
}

// boundsPeakHeap runs f and reports the largest heap of objects seen while
// it ran, the heap collected first so that what earlier tests left on it is
// not read as f's.
func boundsPeakHeap(f func()) uint64 {
	runtime.GC()
	var peak atomic.Uint64
	done := make(chan struct{})
	stopped := make(chan struct{})
	go func() {
		defer close(stopped)
		sample := []metrics.Sample{{Name: "/memory/classes/heap/objects:bytes"}}
		for {
			select {
			case <-done:
				return
			default:
			}
			metrics.Read(sample)
			if v := sample[0].Value.Uint64(); v > peak.Load() {
				peak.Store(v)
			}
			time.Sleep(time.Millisecond)
		}
	}()
	f()
	close(done)
	<-stopped
	return peak.Load()
}

// The deadline is read before each element of a page's /Contents: one
// element is a whole stream to decode, and a page that names the same stream
// a hundred times decodes it a hundred times. Past the deadline no element
// is decoded at all, which the inflation budget the decoders charge reports.
func TestBoundsContentStreamsReadTheDeadline(t *testing.T) {
	data := boundsRepeatedContent(pdfgen.Object{Body: "<< /Filter /FlateDecode >>", Stream: flateOf(bytes.Repeat([]byte(" "), 64<<10)), Raw: true}, 40)
	d := openGenerated(t, data)
	page := boundsFirstPage(t, d)
	spent := d.budget.used
	passed, cancel := context.WithCancel(context.Background())
	cancel()
	d.ctx = passed
	out, err := pageContent(d, page)
	if !errors.Is(err, context.Canceled) {
		t.Errorf("a page's content read past the deadline yielded %d bytes and %v, not the deadline", len(out), err)
	}
	if d.budget.used != spent {
		t.Errorf("%d bytes were inflated past the deadline; the deadline is read before each content stream", d.budget.used-spent)
	}
}

// A page's content streams are bounded by the bytes of the file they hold as
// well as by what they inflate to: a /Contents array may name one stream any
// number of times, and a filter that yields nothing charges the inflation
// budget nothing for each of them.
func TestBoundsContentStreamsAreBoundedByTheFileTheyHold(t *testing.T) {
	const one = 1 << 20
	// ASCIIHexDecode over whitespace yields nothing: the page's concatenated
	// content stays empty however many elements are read.
	stream := pdfgen.Object{Body: "<< /Filter /ASCIIHexDecode >>", Stream: bytes.Repeat([]byte(" "), one), Raw: true}
	within := maxContentRawBytes / one
	for _, c := range []struct {
		times  int
		failed bool
	}{
		{within, false},
		{within + 1, true},
	} {
		r := extract(t, boundsRepeatedContent(stream, c.times))
		if r.Fatal != nil || len(r.Pages) != 1 {
			t.Fatalf("%d elements: fatal %+v pages %+v", c.times, r.Fatal, r.Pages)
		}
		failed := r.Pages[0].Status == PageFailed
		if failed != c.failed {
			t.Errorf("%d elements of %d bytes: page %s with problems %+v; the bound is %d bytes", c.times, one, r.Pages[0].Status, r.Problems, maxContentRawBytes)
		}
		if c.failed && (len(r.Problems) != 1 || r.Problems[0].Code != "pdf-page-failed") {
			t.Errorf("%d elements: problems %+v", c.times, r.Problems)
		}
	}
}

// boundsNamePile is a content stream of arrays of names: no operator
// consumes them, so the interpreter holds every one of them at once.
func boundsNamePile(arrays, perArray int) []byte {
	one := "[" + strings.Repeat("/a", perArray) + "]"
	return []byte(strings.Repeat(one, arrays))
}

// The operand stack is bounded by what its operands hold and not only by how
// many there are: an array of names is one operand and holds a million
// items, and the file that carries it is a fraction of what holding it
// costs. A page whose operands hold more than the bound fails; one within it
// is read.
func TestBoundsOperandStackIsBoundedByWhatItHolds(t *testing.T) {
	const perArray = 600_000
	for _, c := range []struct {
		arrays int
		failed bool
	}{
		{1, false},
		{2, true},
	} {
		b := &pdfgen.Builder{}
		helv := b.Font("Helvetica", "WinAnsiEncoding", "")
		content := append(boundsNamePile(c.arrays, perArray), []byte("\n"+pdfgen.Text("F1", 12, []string{"shown"}))...)
		b.Catalog(b.Pages([]pdfgen.Page{{Content: string(content), Fonts: map[string]int{"F1": helv}}}))
		r := extract(t, b.Bytes())
		if r.Fatal != nil || len(r.Pages) != 1 {
			t.Fatalf("%d arrays: fatal %+v pages %+v", c.arrays, r.Fatal, r.Pages)
		}
		page := r.Pages[0]
		if failed := page.Status == PageFailed; failed != c.failed {
			t.Errorf("%d arrays of %d names: page %s %q, problems %+v; the operand stack holds %d items", c.arrays, perArray, page.Status, page.Text, r.Problems, maxOperandItems)
		}
		if !c.failed && page.Text != "shown" {
			t.Errorf("%d arrays of %d names: the page reads %q", c.arrays, perArray, page.Text)
		}
	}
}

// boundsCMapSource is a CMap of the ranges and single mappings given.
func boundsCMapSource(ranges, chars int) []byte {
	var src strings.Builder
	src.WriteString("begincmap\n1 begincodespacerange <0000> <FFFF> endcodespacerange\n")
	if ranges > 0 {
		fmt.Fprintf(&src, "%d beginbfrange\n", ranges)
		for i := 0; i < ranges; i++ {
			fmt.Fprintf(&src, "<%04X><%04X><0041>\n", 2*i, 2*i+1)
		}
		src.WriteString("endbfrange\n")
	}
	if chars > 0 {
		fmt.Fprintf(&src, "%d beginbfchar\n", chars)
		for i := 0; i < chars; i++ {
			fmt.Fprintf(&src, "<%04X><0042>\n", 0x8000+i)
		}
		src.WriteString("endbfchar\n")
	}
	src.WriteString("endcmap\n")
	return []byte(src.String())
}

// A CMap range is held as its endpoints with an index beside them, which
// costs several times what one mapped code costs: it is charged that, so
// that the entries a document's fonts may hold bound what holding them
// costs. The budget then holds a quarter as many ranges as single mappings.
func TestBoundsCMapRangeIsChargedWhatItCosts(t *testing.T) {
	budget := &fontBudget{}
	c := parseCMap(boundsCMapSource(3, 2), budget, nil)
	if c == nil {
		t.Fatal("the CMap was not used")
	}
	want := 3*cmapRangeEntries + 2
	if budget.used != want || c.entries != want {
		t.Errorf("three ranges and two mapped codes charged %d to the document and %d to the CMap, want %d", budget.used, c.entries, want)
	}
	// What is left of the budget decides how many ranges a CMap may hold: a
	// CMap whose ranges would take it past the bound is not used at all.
	for _, c := range []struct {
		left   int
		usable bool
	}{
		{cmapRangeEntries, true},
		{cmapRangeEntries - 1, false},
	} {
		budget := &fontBudget{used: maxFontEntries - c.left}
		if usable := parseCMap(boundsCMapSource(1, 0), budget, nil) != nil; usable != c.usable {
			t.Errorf("one range with %d entries left: used %v", c.left, usable)
		}
	}
}

// A CMap holds a destination of exactly the characters it decoded: the
// decoder hands back room for sixty-four of them, and a document's fonts may
// hold millions of destinations, each of which would hold that room.
func TestBoundsCMapDestinationsHoldWhatTheyDecoded(t *testing.T) {
	for _, c := range []struct {
		name string
		src  []byte
		want int
	}{
		{"one character", []byte{0x00, 0x42}, 1},
		{"a surrogate pair", []byte{0xD8, 0x3D, 0xDE, 0x00}, 1},
		{"two characters", []byte{0x00, 0x42, 0x00, 0x43}, 2},
	} {
		rs := utf16Runes(c.src)
		if len(rs) != c.want || cap(rs) != c.want {
			t.Errorf("%s: %d runes held in room for %d, want %d in room for %d", c.name, len(rs), cap(rs), c.want, c.want)
		}
	}
}

// The deadline is read while a CMap is parsed, on the cadence the reader
// reads it elsewhere: a section of a million ranges never returns to the
// loop that reads one object at a time, so every mapping charged reads it.
// A CMap the deadline interrupted is not used: the codes it had read map and
// the codes it had not do not, and a font that used it would carry text the
// deadline decided rather than the text the page shows.
func TestBoundsCMapParsingReadsTheDeadline(t *testing.T) {
	src := boundsCMapSource(64, 64)
	if parseCMap(src, &fontBudget{}, func() bool { return false }) == nil {
		t.Fatal("a CMap read within the deadline was not used")
	}
	if c := parseCMap(src, &fontBudget{}, func() bool { return true }); c != nil {
		t.Errorf("a CMap read past the deadline holds %d mappings; it is not used", c.entries)
	}
	// A deadline that passes while the mappings are read: those already read
	// are not kept either.
	for _, after := range []int{1, 8, 64} {
		left := after
		stop := func() bool {
			left--
			return left < 0
		}
		if c := parseCMap(src, &fontBudget{}, stop); c != nil {
			t.Errorf("a CMap whose deadline passed at check %d holds %d mappings", after, c.entries)
		}
	}
}

// boundsOverlappingObjects is a file of objects that each hold the rest of
// it: an object header, then a literal string that is never closed, so that
// the reader's copy of each object is as long as what follows it. Each
// object's first bytes carry the text given, which is what the rebuild looks
// for when it hunts for a catalog.
func boundsOverlappingObjects(size int, mention string) []byte {
	var out bytes.Buffer
	out.WriteString("%PDF-1.7\n")
	for i := 1; out.Len() < size; i++ {
		fmt.Fprintf(&out, "\n%d 0 obj (%s ", i, mention)
	}
	return out.Bytes()
}

// The objects a document holds are bounded by the bytes of the file, so that
// a file whose objects all hold the rest of it costs the reader a multiple
// of the file and not the square of it. The rebuild's hunt for a catalog is
// where every object of such a file is read.
func TestBoundsObjectsHeldAreBoundedByTheFile(t *testing.T) {
	const size = 64 << 10
	data := boundsOverlappingObjects(size, "/Catalog")
	declared := bytes.Count(data, []byte(" 0 obj "))
	parsed := 0
	peak := boundsPeakHeap(func() {
		d, _ := open(context.Background(), data, &inflateBudget{total: 64 << 20, one: 16 << 20})
		if d != nil {
			parsed = d.parsed
		}
	})
	t.Logf("a %d-byte file declaring %d objects that each hold the rest of it: %d were parsed, peak heap %d MiB", len(data), declared, parsed, peak>>20)
	// Each object holds about the whole file, so the bytes the document may
	// hold are spent after a few of them and the rest are not parsed at all.
	if parsed > 2*parsedBytesPerFileByte {
		t.Errorf("%d of the %d objects declared were parsed; each holds about the whole of a %d-byte file", parsed, declared, len(data))
	}
	if peak > 32<<20 {
		t.Errorf("a %d-byte file left the reader holding %d MiB", len(data), peak>>20)
	}
}

// Looking for the page tree among a document's objects parses only objects
// whose first bytes name one, as the hunt for a catalog parses only those
// that name a catalog: without that, a file of objects that each hold the
// rest of it is read whole once for every object it declares.
func TestBoundsPageTreeSearchParsesOnlyCandidates(t *testing.T) {
	data := boundsOverlappingObjects(64<<10, "")
	d, err := open(context.Background(), data, &inflateBudget{total: 64 << 20, one: 16 << 20})
	if d == nil {
		t.Fatalf("not opened: %v", err)
	}
	if root := d.pagesRoot(); root != nil {
		t.Fatalf("a file that holds no page tree yielded one: %v", root)
	}
	if d.parsed != 0 {
		t.Errorf("%d objects were parsed to find a page tree in a file that names none in any of them", d.parsed)
	}
}

// boundsTrailerCandidates is a file of one object and many "trailer"
// keywords, each followed by the bytes given: a rebuild reads the trailer
// from every one of them.
func boundsTrailerCandidates(size int, after string) []byte {
	head := "%PDF-1.7\n1 0 obj<< /Type /Catalog >>endobj\n"
	unit := "trailer" + after
	n := (size - len(head)) / len(unit)
	if n < 1 {
		n = 1
	}
	return []byte(head + strings.Repeat(unit, n))
}

// Rebuilding the cross-reference reads the deadline before each trailer it
// finds, and not once per so many of them: one of them may read the rest of
// the file, so a cadence counted in trailers is a cadence counted in whole
// readings of the file. A document the deadline stopped is a document whose
// record says the deadline passed, not one whose record says the file has a
// structure past a bound, which is what the bytes those readings cost say.
func TestBoundsTrailerRescanReadsTheDeadlineBeforeEachTrailer(t *testing.T) {
	data := boundsTrailerCandidates(128<<10, "<< /A (")
	passed, cancel := context.WithCancel(context.Background())
	cancel()
	d := &Document{ctx: passed, data: data, xref: map[int]xrefEntry{}, trailer: Dict{}, cache: map[int]object{}, objStms: map[int]*objStm{}, budget: &inflateBudget{total: 1 << 20, one: 1 << 20}, resolving: map[int]bool{}}
	err := d.reconstruct()
	if !isDeadline(err) {
		t.Errorf("a rebuild past the deadline ended with %v, not the deadline", err)
	}
}

// What a rebuild reads of the file is bounded whether or not a deadline
// bounds the time it takes: every trailer candidate is charged what it read,
// so a file of candidates that each run to its end is read a few times over
// and not once for each of them.
func TestBoundsTrailerRescanIsBoundedByWhatItReads(t *testing.T) {
	const size = 128 << 10
	for _, c := range []struct {
		after string
		bound bool
	}{
		// A "trailer" the file does not follow with a dictionary is not a
		// trailer, and is not parsed at all.
		{"(", false},
		// One that is followed by a dictionary is parsed, and the bytes it
		// read are charged: a few of them spend what the file may hold.
		{"<< /A (", true},
	} {
		data := boundsTrailerCandidates(size, c.after)
		started := time.Now()
		_, err := open(context.Background(), data, &inflateBudget{total: 1 << 20, one: 1 << 20})
		took := time.Since(started)
		t.Logf("%d bytes of %q candidates: %v (%v)", len(data), "trailer"+c.after, took, err)
		if bound := errors.Is(err, errStructureBound); bound != c.bound {
			t.Errorf("%q candidates ended with %v", "trailer"+c.after, err)
		}
		// Reading the file once takes a few milliseconds; reading it once for
		// each candidate takes seconds.
		if took > 3*time.Second {
			t.Errorf("rebuilding from %d bytes of %q candidates took %v", len(data), "trailer"+c.after, took)
		}
	}
}

// boundsTabledWith writes the objects given with a cross-reference table
// naming them, the extra entries given past them, and a trailer naming root:
// an entry a writer never meant, in a file that is otherwise readable.
func boundsTabledWith(objects []string, extra []string, root string) []byte {
	var out bytes.Buffer
	out.WriteString("%PDF-1.7\n")
	offsets := make([]int, 0, len(objects))
	for _, body := range objects {
		offsets = append(offsets, out.Len())
		out.WriteString(body)
	}
	at := out.Len()
	fmt.Fprintf(&out, "xref\n0 %d\n0000000000 65535 f \n", 1+len(objects)+len(extra))
	for _, off := range offsets {
		fmt.Fprintf(&out, "%010d 00000 n \n", off)
	}
	for _, e := range extra {
		out.WriteString(e)
	}
	fmt.Fprintf(&out, "trailer<< /Size %d /Root %s >>\nstartxref\n%d\n%%%%EOF\n", 1+len(objects)+len(extra), root, at)
	return out.Bytes()
}

// A cross-reference entry may name an offset that is not in the file at all,
// and the rebuild looks at the bytes of every entry it has: the window it
// looks at is computed so that it stays within the file, whatever the entry
// says. A readable document with one such entry reads as the document it is,
// rather than being refused because a row of its cross-reference is junk.
func TestBoundsCrossReferenceOffsetOutsideTheFile(t *testing.T) {
	objects := []string{
		"1 0 obj<< /Type /Catalog /Pages 2 0 R >>endobj\n",
		"2 0 obj<< /Type /Pages /Kids [3 0 R] /Count 1 >>endobj\n",
		"3 0 obj<< /Type /Page /Parent 2 0 R /Contents 4 0 R /Resources << /Font << /F1 5 0 R >> >> >>endobj\n",
		"4 0 obj<< /Length 44 >>stream\nBT /F1 12 Tf 10 700 Td (Hello world) Tj ET\nendstream\nendobj\n",
		"5 0 obj<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>endobj\n",
	}
	for _, c := range []struct {
		name  string
		extra []string
	}{
		{"no entry past the end", nil},
		{"an entry past the end of the file", []string{"9999999999 00000 n \n"}},
		{"an entry whose offset plus a window overflows", []string{"9223372036854775807 00000 n \n"}},
	} {
		t.Run(c.name, func(t *testing.T) {
			data := boundsTabledWith(objects, c.extra, "1 0 R")
			// Object 1's entry names the wrong place, so reading the catalog
			// fails and the reader rebuilds by scanning; the rebuild is where
			// the entries' bytes are looked at.
			data = bytes.Replace(data, []byte("0000000009 00000 n"), []byte("0000000123 00000 n"), 1)
			r := extract(t, data)
			if r.Fatal != nil || len(r.Pages) != 1 || r.Pages[0].Text != "Hello world" {
				t.Fatalf("fatal %+v pages %+v problems %+v", r.Fatal, r.Pages, r.Problems)
			}
		})
	}
}

// An entry whose offset lies outside the file reaches the reader through a
// cross-reference stream too, where a /W of eight-byte fields carries any
// number at all, and the rebuild must not read the file at it.
func TestBoundsCrossReferenceStreamOffsetOutsideTheFile(t *testing.T) {
	var out bytes.Buffer
	out.WriteString("%PDF-1.7\n")
	first := out.Len()
	out.WriteString("1 0 obj<< /Type /Catalog /Pages 2 0 R >>endobj\n")
	second := out.Len()
	out.WriteString("2 0 obj<< /Type /Pages /Kids [] /Count 0 >>endobj\n")
	at := out.Len()
	be8 := func(v uint64) []byte {
		return []byte{byte(v >> 56), byte(v >> 48), byte(v >> 40), byte(v >> 32), byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)}
	}
	var entries []byte
	put := func(typ byte, f2, f3 uint64) {
		entries = append(entries, typ)
		entries = append(entries, be8(f2)...)
		entries = append(entries, be8(f3)...)
	}
	put(0, 0, 65535)
	// Object 1 is named three bytes past its header, so the catalog is not
	// where the cross-reference says and the reader rebuilds by scanning.
	put(1, uint64(first)+3, 0)
	put(1, uint64(second), 0)
	put(1, 1<<40, 0)
	put(1, uint64(at), 0)
	fmt.Fprintf(&out, "4 0 obj<< /Type /XRef /Size 5 /W [1 8 8] /Root 1 0 R /Length %d >>stream\n", len(entries))
	out.Write(entries)
	out.WriteString("\nendstream endobj\n")
	fmt.Fprintf(&out, "startxref\n%d\n%%%%EOF\n", at)
	d, err := open(context.Background(), out.Bytes(), &inflateBudget{total: 1 << 20, one: 1 << 20})
	if d == nil {
		t.Fatalf("not opened: %v", err)
	}
	if root := d.pagesRoot(); root == nil {
		t.Fatalf("the page tree was not found: %v", err)
	}
}

// adapters/README.md states the bounds this file holds the reader to with
// the values the constants hold, as it states the rest of them.
func TestBoundsREADMEStatesTheBoundsOnWhatIsHeld(t *testing.T) {
	raw, err := os.ReadFile("../../README.md")
	if err != nil {
		t.Fatal(err)
	}
	readme := string(raw)
	for label, value := range map[string]string{
		"the bytes of the file a page's content streams hold, before any filter":                          mib(maxContentRawBytes),
		"items the operand stack holds, the elements and members of its operands counted":                 grouped(maxOperandItems),
		"the entries one `bfrange` or `cidrange` is charged":                                              grouped(cmapRangeEntries),
		"bytes of parsed objects held, for each byte of the file and of each byte its streams inflate to": grouped(parsedBytesPerFileByte),
	} {
		if row := readmeRow(t, readme, label); row[1] != value {
			t.Errorf("%s: adapters/README.md says %q, the reader holds %q", label, row[1], value)
		}
	}
}
