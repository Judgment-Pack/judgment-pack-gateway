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

// boundsPeakLiveHeap runs f and reports the largest heap of live objects
// seen while it ran: the heap is collected before each reading, so what is
// measured is what was still held and not what had been allocated and
// dropped. It costs a collection for each reading, which is why it is used
// where what matters is what is held rather than what was allocated.
func boundsPeakLiveHeap(f func()) uint64 {
	runtime.GC()
	var peak atomic.Uint64
	done := make(chan struct{})
	stopped := make(chan struct{})
	go func() {
		defer close(stopped)
		for {
			select {
			case <-done:
				return
			default:
			}
			if v := boundsLiveHeap(); v > peak.Load() {
				peak.Store(v)
			}
			time.Sleep(2 * time.Millisecond)
		}
	}()
	f()
	close(done)
	<-stopped
	return peak.Load()
}

// boundsRetained is what holding the values f returns costs: the heap with
// them alive, less the heap once they are dropped, the heap collected on
// both sides so that what is measured is what is held and not what was
// allocated on the way.
func boundsRetained(f func() []object) (retained uint64, charged int64) {
	held := f()
	with := boundsLiveHeap()
	for _, v := range held {
		charged += parsedSlotBytes + parsedBytesOf(v)
	}
	runtime.KeepAlive(held)
	held = nil
	return with - boundsLiveHeap(), charged
}

func boundsLiveHeap() uint64 {
	runtime.GC()
	runtime.GC()
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	return m.HeapAlloc
}

// What the reader charges for holding a parsed value is at or above what Go
// retains for it. The charge is the bound the budget enforces, so the bound
// is a bound on memory only while this holds; every shape the parser builds
// is measured here, and the constants are set from these measurements.
func TestBoundsChargeCoversWhatIsRetained(t *testing.T) {
	if boundsInstrumented {
		t.Skip("the race detector's own allocations are not the reader's, and what it retains is not what this measures")
	}
	const n = 20000
	text := func(l int) string {
		b := make([]byte, l)
		for i := range b {
			b[i] = 'a' + byte(i%26)
		}
		return string(b)
	}
	shapes := []struct {
		name string
		make func(i int) object
	}{
		{"a small integer", func(i int) object { return int64(i % 256) }},
		{"a large integer", func(i int) object { return int64(i) + 1<<40 }},
		{"a real", func(i int) object { return float64(i) + 0.5 }},
		{"a boolean", func(i int) object { return i%2 == 0 }},
		{"a reference", func(i int) object { return ref{i, 0} }},
		{"a name of one byte", func(i int) object { return Name(text(1)) }},
		{"a name of forty bytes", func(i int) object { return Name(text(40)) }},
		{"a string of one byte", func(i int) object { return String(text(1)) }},
		{"a string of two hundred bytes", func(i int) object { return String(text(200)) }},
		{"an empty array", func(i int) object { return Array{} }},
		{"a pair of coordinates", func(i int) object { return Array{int64(0), int64(0)} }},
		{"an array of eight", func(i int) object {
			var a Array
			for k := 0; k < 8; k++ {
				a = append(a, int64(k)+1<<40)
			}
			return a
		}},
		{"an array of a hundred", func(i int) object {
			var a Array
			for k := 0; k < 100; k++ {
				a = append(a, int64(k)+1<<40)
			}
			return a
		}},
		{"a dictionary of one member", func(i int) object {
			return Dict{Name(text(1)): int64(1 << 40)}
		}},
		{"a dictionary of eight members", func(i int) object {
			d := Dict{}
			for k := 0; k < 8; k++ {
				d[Name(fmt.Sprintf("K%06d", k))] = int64(1 << 40)
			}
			return d
		}},
		{"a dictionary of sixty-five members", func(i int) object {
			d := Dict{}
			for k := 0; k < 65; k++ {
				d[Name(fmt.Sprintf("K%06d", k))] = int64(1 << 40)
			}
			return d
		}},
		{"a page dictionary", func(i int) object {
			return Dict{"Type": Name("Page"), "Parent": ref{2, 0}, "MediaBox": Array{int64(0), int64(0), int64(612), int64(792)},
				"Resources": Dict{"Font": Dict{"F1": ref{5, 0}}}, "Contents": ref{4, 0}}
		}},
	}
	for _, s := range shapes {
		count := n
		if strings.Contains(s.name, "hundred") || strings.Contains(s.name, "sixty-five") {
			count = n / 10
		}
		retained, charged := boundsRetained(func() []object {
			held := make([]object, 0, count)
			for i := 0; i < count; i++ {
				held = append(held, s.make(i))
			}
			return held
		})
		t.Logf("%-36s %6d retained, %6d charged, each", s.name, int(retained)/count, int(charged)/count)
		if int64(retained) > charged {
			t.Errorf("%s: %d bytes retained for each, %d charged; the charge must cover what is held", s.name, int(retained)/count, int(charged)/count)
		}
	}
}

// boundsDense is a one-page document whose page names a resource holding
// count copies of the value given: dense, ordinary structure that overlaps
// nothing, which the budget must admit with room to spare.
func boundsDense(value string, count int, inObjectStream bool) []byte {
	b := &pdfgen.Builder{}
	if inObjectStream {
		b.XrefStream, b.ObjectStreams, b.Compress = true, true, true
	}
	helv := b.Font("Helvetica", "WinAnsiEncoding", "")
	var dense strings.Builder
	dense.WriteString("[")
	for i := 0; i < count; i++ {
		dense.WriteString(value)
		dense.WriteString(" ")
	}
	dense.WriteString("]")
	props := b.Add(pdfgen.Object{Body: "<< /Dense " + dense.String() + " >>"})
	pages := b.Next()
	b.Add(pdfgen.Object{Body: "placeholder"})
	cs := b.Add(pdfgen.Object{Body: "<< >>", Stream: []byte(pdfgen.Text("F1", 12, []string{"dense"}))})
	page := b.Add(pdfgen.Object{Body: fmt.Sprintf("<< /Type /Page /Parent %d 0 R /MediaBox [0 0 612 792] /Resources << /Font << /F1 %d 0 R >> /Properties %d 0 R >> /Contents %d 0 R >>", pages, helv, props, cs)})
	b.Set(pages, pdfgen.Object{Body: fmt.Sprintf("<< /Type /Pages /Kids [%d 0 R] /Count 1 >>", page)})
	b.Catalog(pages)
	return b.Bytes()
}

// Dense structure that overlaps nothing is read, and read with room to
// spare: a file of coordinate pairs, of integers or of small dictionaries
// costs the reader many times its own length -- a Go map of about 370 bytes
// for the eight bytes of "<</A 1>>" -- and the allowance is set against
// that, not against the file's length alone.
func TestBoundsDenseStructureIsReadWithHeadroom(t *testing.T) {
	for _, c := range []struct {
		name  string
		value string
		count int
	}{
		{"pairs of coordinates", "[0 0]", 10000},
		{"integers", "1", 25000},
		{"dictionaries of one member", "<</A 1>>", 10000},
	} {
		for _, inStream := range []bool{false, true} {
			where := "at an offset"
			if inStream {
				where = "in an object stream"
			}
			t.Run(c.name+" "+where, func(t *testing.T) {
				data := boundsDense(c.value, c.count, inStream)
				r := extract(t, data)
				if r.Fatal != nil || len(r.Pages) != 1 || r.Pages[0].Text != "dense" {
					t.Fatalf("%d bytes: fatal %+v pages %+v", len(data), r.Fatal, r.Pages)
				}
				// The page tree, and then the resource the page names, which
				// is where the dense structure is: it must be read whole.
				d := openGenerated(t, data)
				w := &walker{d: d, ctx: context.Background(), visited: map[ref]bool{}, limit: 100}
				w.node(d.pagesRoot(), inherited{}, 0)
				props := d.dictOf(d.dictOf(boundsFirstPage(t, d)["Resources"])["Properties"])
				if props == nil {
					t.Fatal("the dense resource could not be read")
				}
				if held := d.arrayOf(props["Dense"]); len(held) != c.count {
					t.Fatalf("the dense resource holds %d of its %d values", len(held), c.count)
				}
				budget, held := d.parsedBudget(), d.parsedBytes
				t.Logf("%d bytes of %s %s: %d charged of %d allowed (%.1f times the room needed)", len(data), c.name, where, held, budget, float64(budget)/float64(max(held, 1)))
				if held*2 > budget {
					t.Errorf("%d bytes of %s %s: %d bytes charged against an allowance of %d; ordinary structure must be read with room to spare", len(data), c.name, where, held, budget)
				}
			})
		}
	}
}

// The trailer, the headers of object streams and everything else the reader
// keeps outside its object cache are charged, and a charge is given back
// only where the storage is: a rebuild empties the cache, but a walk may
// hold what the cache no longer names, so the charge stays.
func TestBoundsEverythingHeldIsCharged(t *testing.T) {
	b := &pdfgen.Builder{XrefStream: true, ObjectStreams: true, Compress: true}
	helv := b.Font("Helvetica", "WinAnsiEncoding", "")
	b.Catalog(b.Pages([]pdfgen.Page{{Content: pdfgen.Text("F1", 12, []string{"held"}), Fonts: map[string]int{"F1": helv}}}))
	d := openGenerated(t, b.Bytes())
	if d.parsedBytes < parsedBytesOf(d.trailer) {
		t.Errorf("the trailer holds %d bytes and the document has charged %d in all", parsedBytesOf(d.trailer), d.parsedBytes)
	}
	page := boundsFirstPage(t, d)
	before := d.parsedBytes
	if err := d.reconstruct(); err != nil {
		t.Fatalf("reconstruct: %v", err)
	}
	if d.parsedBytes < before {
		t.Errorf("a rebuild gave back %d bytes of charge while the page it collected is still held", before-d.parsedBytes)
	}
	if page["Type"] != Name("Page") {
		t.Errorf("the page the walk holds is %v", page["Type"])
	}
}

// An object whose parsed form is past what the document may hold is stopped
// while it is built, not after: the reader never holds what it will refuse.
// A file of objects that each hold the rest of it is the shape that makes
// the difference visible.
func TestBoundsObjectsHeldAreBoundedByTheFile(t *testing.T) {
	const size = 64 << 10
	data := boundsOverlappingObjects(size)
	declared := bytes.Count(data, []byte(" 0 obj "))
	parsed := 0
	peak := boundsPeakHeap(func() {
		d, _ := open(context.Background(), data, &inflateBudget{total: 64 << 20, one: 16 << 20})
		if d != nil {
			parsed = d.parsed
		}
	})
	t.Logf("a %d-byte file declaring %d objects that each hold the rest of it: %d were parsed, peak heap %d MiB", len(data), declared, parsed, peak>>20)
	if parsed > 2*parsedBytesPerFileByte {
		t.Errorf("%d of the %d objects declared were parsed; each holds about the whole of a %d-byte file", parsed, declared, len(data))
	}
	if peak > 48<<20 {
		t.Errorf("a %d-byte file left the reader holding %d MiB", len(data), peak>>20)
	}
}

// boundsOverlappingObjects is a file of objects that each hold the rest of
// it: an object header, then a dictionary whose first member is a literal
// string that is never closed, so that the reader's copy of each object is
// as long as what follows it. None of them says what it is within the window
// the rebuild reads, so each is a candidate the rebuild parses.
func boundsOverlappingObjects(size int) []byte {
	var out bytes.Buffer
	out.WriteString("%PDF-1.7\n")
	for i := 1; out.Len() < size; i++ {
		fmt.Fprintf(&out, "\n%d 0 obj << /A (", i)
	}
	return out.Bytes()
}

// boundsNamePile is one array wrapping arrays of names: no operator consumes
// them, so the interpreter would hold every one of them at once, and the
// outer array means the whole pile is one operand for the parser to build.
func boundsNamePile(arrays, perArray int) []byte {
	one := "[" + strings.Repeat("/a", perArray) + "]"
	return []byte("[" + strings.Repeat(one, arrays) + "]")
}

// An operand is bounded while it is built and not once it exists: an array
// of arrays of names is one operand, and a reader that checked it after
// parsing would have allocated all of it first. The page fails at the bound
// and the heap stays near what the bound allows.
func TestBoundsOperandsAreBoundedWhileTheyAreBuilt(t *testing.T) {
	// Four million names, which cost far more than one page's operands may
	// hold: the parse must stop part way through the first operand.
	b := &pdfgen.Builder{}
	content := boundsNamePile(40, 100_000)
	b.Catalog(b.Pages([]pdfgen.Page{{Content: string(content)}}))
	data := b.Bytes()
	var r *Result
	peak := boundsPeakHeap(func() { r = extract(t, data) })
	t.Logf("one operand of %d names in a %d-byte file: peak heap %d MiB, pages %+v problems %+v", 40*100_000, len(data), peak>>20, r.Pages, r.Problems)
	if r.Fatal != nil || len(r.Pages) != 1 || r.Pages[0].Status != PageFailed {
		t.Fatalf("fatal %+v pages %+v", r.Fatal, r.Pages)
	}
	if peak > 160<<20 {
		t.Errorf("building one operand past the bound peaked at %d MiB; the bound is %d MiB", peak>>20, maxOperandBytes>>20)
	}
}

// The slots of consumed operands are cleared with their charge: a stream
// that pushes a pile, has an operator consume it, and pushes another pile
// holds only the second, since the first is no longer reachable from the
// backing array the interpreter reuses.
func TestBoundsConsumedOperandsAreReleased(t *testing.T) {
	// Sixty arrays of fifteen thousand names, consumed by an operator, then
	// one array of nine hundred thousand: both piles are the same size, so a
	// reader that keeps the first holds twice what it charges.
	var content strings.Builder
	for i := 0; i < 60; i++ {
		content.WriteString("[" + strings.Repeat("/a", 15_000) + "]")
	}
	content.WriteString(" n\n")
	content.WriteString("[" + strings.Repeat("/a", 900_000) + "]\n")
	b := &pdfgen.Builder{}
	b.Catalog(b.Pages([]pdfgen.Page{{Content: content.String()}}))
	data := b.Bytes()
	var r *Result
	peak := boundsPeakLiveHeap(func() { r = extract(t, data) })
	t.Logf("two piles of nine hundred thousand names, one consumed: most held at once %d MiB, pages %+v", peak>>20, r.Pages)
	if r.Fatal != nil || len(r.Pages) != 1 {
		t.Fatalf("fatal %+v pages %+v", r.Fatal, r.Pages)
	}
	if peak > 56<<20 {
		t.Errorf("the page held %d MiB at once; one pile of that size is about half of it, and the pile an operator consumed is not held", peak>>20)
	}
}

// A page's content streams are bounded by the work they cost as well as by
// what they inflate to: a /Contents array may name one stream any number of
// times, and a filter that yields nothing charges the inflation budget
// nothing for each of them.
func TestBoundsContentStreamsAreBoundedByTheWorkTheyCost(t *testing.T) {
	const one = 1 << 20
	// ASCIIHexDecode over whitespace yields nothing: the page's concatenated
	// content stays empty however many elements are read.
	stream := pdfgen.Object{Body: "<< /Filter /ASCIIHexDecode >>", Stream: bytes.Repeat([]byte(" "), one), Raw: true}
	within := maxPageWorkBytes/one - 1
	for _, c := range []struct {
		times  int
		failed bool
	}{
		{within, false},
		{within + 2, true},
	} {
		r := extract(t, boundsRepeatedContent(stream, c.times))
		if r.Fatal != nil || len(r.Pages) != 1 {
			t.Fatalf("%d elements: fatal %+v pages %+v", c.times, r.Fatal, r.Pages)
		}
		failed := r.Pages[0].Status == PageFailed
		if failed != c.failed {
			t.Errorf("%d elements of %d bytes: page %s with problems %+v; the bound is %d bytes", c.times, one, r.Pages[0].Status, r.Problems, maxPageWorkBytes)
		}
		if c.failed && (len(r.Problems) != 1 || r.Problems[0].Code != "pdf-page-failed") {
			t.Errorf("%d elements: problems %+v", c.times, r.Problems)
		}
	}
}

// The deadline is read before each element of a page's /Contents, and not
// only before the first: one element is a whole stream to decode, and a page
// that names the same stream a hundred times decodes it a hundred times.
func TestBoundsContentStreamsReadTheDeadline(t *testing.T) {
	data := boundsRepeatedContent(pdfgen.Object{Body: "<< /Filter /FlateDecode >>", Stream: flateOf(bytes.Repeat([]byte(" "), 64<<10)), Raw: true}, 40)
	d := openGenerated(t, data)
	page := boundsFirstPage(t, d)
	spent := d.budget.used
	// A deadline that passes at the second reading of it: the first element
	// is decoded, and the deadline stops the rest.
	d.ctx = newCountdown(1)
	out, err := pageContent(d, page)
	if !isDeadline(err) {
		t.Errorf("a page's content read past the deadline yielded %d bytes and %v, not the deadline", len(out), err)
	}
	if decoded := d.budget.used - spent; decoded != 64<<10 {
		t.Errorf("%d bytes were inflated; the first element is one stream of %d bytes and no element after it is decoded", decoded, 64<<10)
	}
}

// A form drawn again and again is work the page answers for: an unfiltered
// form charges the inflation budget nothing, and a page that draws a large
// one two thousand times would otherwise read gigabytes with no bound met.
func TestBoundsFormsAreChargedEachTimeTheyAreDrawn(t *testing.T) {
	const size, draws = 2 << 20, 2000
	b := &pdfgen.Builder{}
	body := append([]byte("% "), bytes.Repeat([]byte("x"), size)...)
	form := b.Add(pdfgen.Object{Body: "<< /Type /XObject /Subtype /Form /BBox [0 0 10 10] >>", Stream: body, Raw: true})
	pages := b.Next()
	b.Add(pdfgen.Object{Body: "placeholder"})
	cs := b.Add(pdfgen.Object{Body: "<< >>", Stream: []byte(strings.Repeat("/X Do\n", draws))})
	page := b.Add(pdfgen.Object{Body: fmt.Sprintf("<< /Type /Page /Parent %d 0 R /MediaBox [0 0 612 792] /Resources << /XObject << /X %d 0 R >> >> /Contents %d 0 R >>", pages, form, cs)})
	b.Set(pages, pdfgen.Object{Body: fmt.Sprintf("<< /Type /Pages /Kids [%d 0 R] /Count 1 >>", page)})
	b.Catalog(pages)
	started := time.Now()
	r := extract(t, b.Bytes())
	took := time.Since(started)
	t.Logf("%d draws of a %d-byte form: %v, pages %+v problems %+v", draws, size, took, r.Pages, r.Problems)
	if r.Fatal != nil || len(r.Pages) != 1 || r.Pages[0].Status != PageFailed {
		t.Fatalf("fatal %+v pages %+v", r.Fatal, r.Pages)
	}
	if took > 3*time.Second {
		t.Errorf("%d draws of a %d-byte form took %v", draws, size, took)
	}
}

// Applying a filter is work too: a list of a hundred thousand filters over
// an empty stream yields nothing, charges the inflation budget nothing, and
// is walked again for every stream of the page that names it.
func TestBoundsFilterStepsAreCharged(t *testing.T) {
	b := &pdfgen.Builder{}
	filters := b.Add(pdfgen.Object{Body: "[" + strings.Repeat("/Crypt ", 100_000) + "]"})
	content := b.Add(pdfgen.Object{Body: fmt.Sprintf("<< /Filter %d 0 R >>", filters), Stream: []byte{}, Raw: true})
	refs := make([]string, 8)
	for i := range refs {
		refs[i] = fmt.Sprintf("%d 0 R", content)
	}
	pages := b.Next()
	b.Add(pdfgen.Object{Body: "placeholder"})
	page := b.Add(pdfgen.Object{Body: fmt.Sprintf("<< /Type /Page /Parent %d 0 R /MediaBox [0 0 612 792] /Resources << >> /Contents [%s] >>", pages, strings.Join(refs, " "))})
	b.Set(pages, pdfgen.Object{Body: fmt.Sprintf("<< /Type /Pages /Kids [%d 0 R] /Count 1 >>", page)})
	b.Catalog(pages)
	started := time.Now()
	r := extract(t, b.Bytes())
	took := time.Since(started)
	t.Logf("eight streams of a hundred thousand filters: %v, pages %+v problems %+v", took, r.Pages, r.Problems)
	if r.Fatal != nil || len(r.Pages) != 1 || r.Pages[0].Status != PageFailed {
		t.Fatalf("fatal %+v pages %+v", r.Fatal, r.Pages)
	}
	if took > 3*time.Second {
		t.Errorf("the page took %v", took)
	}
}

// boundsCMapSource is a CMap of the ranges and single mappings given, and of
// the entries given that map nothing at all.
func boundsCMapSource(ranges, chars, rejected int) []byte {
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
	if rejected > 0 {
		// Destinations no code maps to: read, examined and charged nothing.
		fmt.Fprintf(&src, "%d begincidchar\n", rejected)
		for i := 0; i < rejected; i++ {
			fmt.Fprintf(&src, "<%04X> -1\n", i)
		}
		src.WriteString("endcidchar\n")
	}
	src.WriteString("endcmap\n")
	return []byte(src.String())
}

// A CMap range is held as its endpoints with an index beside them, and is
// charged what that costs, each kind of destination on its own: an integer
// destination as a cidrange or a bfrange, and a string destination, which
// holds the characters it decodes to as well.
func TestBoundsCMapRangeIsChargedWhatItCosts(t *testing.T) {
	head := "begincmap\n1 begincodespacerange <0000> <FFFF> endcodespacerange\n"
	for _, c := range []struct {
		name, body string
		want       int
	}{
		{"an integer destination in a cidrange", "1 begincidrange\n<0000><00FF> 1\nendcidrange\n", cmapRangeEntries},
		{"an integer destination in a bfrange", "1 beginbfrange\n<0000><00FF> 65\nendbfrange\n", cmapRangeEntries},
		{"a string destination", "1 beginbfrange\n<0000><00FF><0041>\nendbfrange\n", cmapRangeEntries},
		{"a destination of two hundred and fifty-six characters", "1 beginbfrange\n<0000><00FF><" + strings.Repeat("0041", 256) + ">\nendbfrange\n", cmapRangeEntries + 256/cmapRunsPerEntry},
		{"a code mapped on its own", "1 beginbfchar\n<0000><0041>\nendbfchar\n", 1},
		{"a code mapped to two hundred and fifty-six characters", "1 beginbfchar\n<0000><" + strings.Repeat("0041", 256) + ">\nendbfchar\n", 1 + 256/cmapRunsPerEntry},
	} {
		budget := &fontBudget{}
		if parseCMap([]byte(head+c.body+"endcmap\n"), budget, nil) == nil {
			t.Fatalf("%s: the CMap was not used", c.name)
		}
		if budget.used != c.want {
			t.Errorf("%s: charged %d entries, want %d", c.name, budget.used, c.want)
		}
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
		if usable := parseCMap(boundsCMapSource(1, 0, 0), budget, nil) != nil; usable != c.usable {
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

// The deadline is read while a CMap is parsed, on the cadence of the entries
// examined and not of the entries kept: a section of entries the CMap maps
// none of is a section it read.
func TestBoundsCMapParsingReadsTheDeadline(t *testing.T) {
	src := boundsCMapSource(64, 64, 0)
	if parseCMap(src, &fontBudget{}, func() bool { return false }) == nil {
		t.Fatal("a CMap read within the deadline was not used")
	}
	if c := parseCMap(src, &fontBudget{}, func() bool { return true }); c != nil {
		t.Errorf("a CMap read past the deadline holds %d mappings; it is not used", c.entries)
	}
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
	// A hundred thousand entries that map nothing: the deadline is read for
	// each of them, since reading an entry is the work being bounded.
	calls := 0
	parseCMap(boundsCMapSource(0, 0, 100_000), &fontBudget{}, func() bool { calls++; return false })
	if calls < 100_000 {
		t.Errorf("the deadline was offered %d times while a hundred thousand entries were examined", calls)
	}
}

// A font whose CMap the deadline stopped carries the deadline out of the
// font: the page it shows ends at the deadline, rather than being listed as
// a page whose glyphs happen not to map.
func TestBoundsADeadlineInAFontEndsThePage(t *testing.T) {
	b := &pdfgen.Builder{}
	tu := b.Add(pdfgen.Object{Body: "<< >>", Stream: boundsCMapSource(64, 64, 0)})
	f := cidFont(b, "", tu)
	b.Catalog(b.Pages([]pdfgen.Page{{Content: "BT /F1 12 Tf 1 0 0 1 72 700 Tm <0000> Tj ET\n", Fonts: map[string]int{"F1": f}}}))
	d := openGenerated(t, b.Bytes())
	page := boundsFirstPage(t, d)
	content, err := pageContent(d, page)
	if err != nil {
		t.Fatalf("content: %v", err)
	}
	resources := d.dictOf(page["Resources"])
	// The document's own resources are read past the deadline; the
	// interpreter's deadline has not passed, so nothing but the font can end
	// the page here.
	passed, cancel := context.WithCancel(context.Background())
	cancel()
	d.ctx = passed
	pr := d.interpretPage(context.Background(), content, resources, 1<<20, map[ref]*font{})
	t.Logf("page interpreted with a font read past the deadline: text %q err %v", pr.text, pr.err)
	if !isDeadline(pr.err) {
		t.Errorf("the page ended with %v and text %q; a font the deadline stopped ends the page at the deadline", pr.err, pr.text)
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
// the file. A document the deadline stopped is a document whose record says
// the deadline passed, not one whose record says the file has a structure
// past a bound.
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

// Every byte a rebuild examines is charged, whatever becomes of the
// candidate it was examining: a comment it skipped, a dictionary it parsed,
// an object it gave up on. Without that a file of candidates that each read
// the rest of it is read once for every one of them.
func TestBoundsTrailerRescanIsBoundedByWhatItExamines(t *testing.T) {
	for _, c := range []struct {
		name  string
		data  []byte
		bound bool
	}{
		{"candidates no dictionary follows", boundsTrailerCandidates(512<<10, "("), false},
		{"candidates a dictionary follows", boundsTrailerCandidates(128<<10, "<< /A ("), true},
		{"candidates on one comment line", boundsTrailerCandidates(512<<10, "%"), false},
		{"candidates whose dictionary holds a comment", boundsTrailerCandidates(128<<10, "<< %"), true},
		{"objects whose parse is given up on", boundsOverlappingObjects(128 << 10), true},
	} {
		t.Run(c.name, func(t *testing.T) {
			started := time.Now()
			d, err := open(context.Background(), c.data, &inflateBudget{total: 1 << 20, one: 1 << 20})
			took := time.Since(started)
			t.Logf("%d bytes: %v (%v)", len(c.data), took, err)
			// A candidate that holds the rest of the file spends the allowance
			// after a few of them, and what it spent is the measure of the work
			// done; a candidate that holds nothing is examined once and the
			// scan does not come back to it.
			bound := errors.Is(err, errStructureBound) || (d != nil && d.bound != nil)
			if bound != c.bound {
				t.Errorf("rebuilding from %d bytes ended with %v (bound noted %v)", len(c.data), err, d != nil && d.bound != nil)
			}
			// Reading the file a few times over takes milliseconds; reading it
			// once for each candidate takes tens of seconds, which is what
			// this catches with room for a machine reading it with the race
			// detector on.
			if took > 8*time.Second {
				t.Errorf("rebuilding from %d bytes took %v", len(c.data), took)
			}
		})
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

// boundsLostCatalog writes a one-page document whose catalog names no page
// tree, so that the page tree is looked for among the objects, with the page
// tree's and the catalog's own dictionaries written as given. When root is
// empty the trailer names no catalog either, so the catalog is looked for
// among the objects as well and a catalog the search passes over is a
// document with no page.
func boundsLostCatalog(t *testing.T, tree, catalog, root string) []byte {
	t.Helper()
	objects := []string{
		"1 0 obj" + catalog + "endobj\n",
		"2 0 obj" + tree + "endobj\n",
		"3 0 obj<< /Type /Page /Parent 2 0 R /Contents 4 0 R /Resources << /Font << /F1 5 0 R >> >> >>endobj\n",
		"4 0 obj<< /Length 44 >>stream\nBT /F1 12 Tf 10 700 Td (Hello world) Tj ET\nendstream\nendobj\n",
		"5 0 obj<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>endobj\n",
	}
	data := boundsTabledWith(objects, nil, "1 0 R")
	if root == "" {
		// The trailer names no catalog: /Root is written as a member the
		// reader does not read, so that the file is the same length.
		data = bytes.Replace(data, []byte("/Root 1 0 R"), []byte("/Rxxt 1 0 R"), 1)
	}
	return data
}

// The page tree and the catalog are looked for by reading the head of each
// object, not by searching its first bytes for a word: a name is read with
// its escapes resolved, a dictionary is read member by member, and an object
// the head cannot settle is parsed rather than passed over.
func TestBoundsPageTreeAndCatalogAreFoundByReadingTheirHeads(t *testing.T) {
	filler := strings.Repeat("/Pad"+strings.Repeat("x", 60)+" 1 ", 6)
	pages := "<< /Type /Pages /Kids [3 0 R] /Count 1 >>"
	catalog := "<< /Type /Catalog >>"
	// A window's worth of space, and a comment as long, before the dictionary
	// the object holds: what the object is begins past what the head reads.
	spaces := strings.Repeat(" ", headWindow+76)
	comment := "%" + strings.Repeat("c", headWindow+76) + "\n"
	// A head that ends between the two angle brackets of the dictionary: the
	// object's number and generation, then space enough that "<<" straddles
	// the end of the window.
	split := strings.Repeat(" ", headWindow-len("1 0 obj")-1)
	for _, c := range []struct {
		name, tree, catalog, root string
	}{
		{"an escape in the page tree's type", "<< /Type /Pa#67es /Kids [3 0 R] /Count 1 >>", catalog, "1 0 R"},
		{"a page tree whose type comes late", "<< " + filler + " /Kids [3 0 R] /Count 1 /Type /Pages >>", catalog, "1 0 R"},
		{"a page tree behind a window of space", spaces + pages, catalog, "1 0 R"},
		{"a page tree behind a comment as long as the window", comment + pages, catalog, "1 0 R"},
		{"a page tree whose opening straddles the window", split + pages, catalog, "1 0 R"},
		{"an escape in the catalog's type", pages, "<< /Type /Cat#61log >>", ""},
		{"a catalog whose type comes late", pages, "<< " + filler + " /Type /Catalog >>", ""},
		{"a catalog behind a window of space", pages, spaces + catalog, ""},
		{"a catalog behind a comment as long as the window", pages, comment + catalog, ""},
		{"a catalog whose opening straddles the window", pages, split + catalog, ""},
	} {
		t.Run(c.name, func(t *testing.T) {
			data := boundsLostCatalog(t, c.tree, c.catalog, c.root)
			r := extract(t, data)
			if r.Fatal != nil || len(r.Pages) != 1 || r.Pages[0].Text != "Hello world" {
				t.Fatalf("fatal %+v pages %+v", r.Fatal, r.Pages)
			}
		})
	}
}

// Looking for the page tree still reads only what it must: a file of objects
// that each hold the rest of it is not read whole once for every object it
// declares.
func TestBoundsPageTreeSearchParsesOnlyCandidates(t *testing.T) {
	data := boundsOverlappingObjects(64 << 10)
	var d *Document
	peak := boundsPeakHeap(func() {
		var err error
		d, err = open(context.Background(), data, &inflateBudget{total: 64 << 20, one: 16 << 20})
		if d == nil {
			t.Fatalf("not opened: %v", err)
		}
		if root := d.pagesRoot(); root != nil {
			t.Fatalf("a file that holds no page tree yielded one: %v", root)
		}
	})
	t.Logf("a %d-byte file of objects that each hold the rest of it: %d parsed, peak heap %d MiB", len(data), d.parsed, peak>>20)
	if peak > 48<<20 {
		t.Errorf("looking for a page tree in a %d-byte file left the reader holding %d MiB", len(data), peak>>20)
	}
}

// boundsStaleDeadline is a context whose deadline has passed and whose error
// is not set: the timer that would cancel it has not run.
type boundsStaleDeadline struct{ context.Context }

func (boundsStaleDeadline) Err() error { return nil }

func (boundsStaleDeadline) Deadline() (time.Time, bool) {
	return time.Now().Add(-time.Second), true
}

// Every check of the deadline reads the clock as well as the context: a
// document whose deadline the clock has reached is given up on although
// nothing has cancelled its context.
func TestBoundsDeadlineIsReadFromTheClock(t *testing.T) {
	if deadlineMet(boundsStaleDeadline{context.Background()}) == nil {
		t.Error("a deadline the clock has passed, whose context is not cancelled, was not read as passed")
	}
	live, cancel := context.WithDeadline(context.Background(), time.Now().Add(time.Hour))
	defer cancel()
	if deadlineMet(live) != nil {
		t.Error("a deadline an hour away was read as passed")
	}
	if deadlineMet(nil) != nil {
		t.Error("a document with no context has a deadline")
	}
	// The whole of an extraction is given up on: a document opened under such
	// a context ends at the deadline, as it does under a cancelled one.
	b := &pdfgen.Builder{}
	helv := b.Font("Helvetica", "WinAnsiEncoding", "")
	b.Catalog(b.Pages([]pdfgen.Page{{Content: pdfgen.Text("F1", 12, []string{"hello"}), Fonts: map[string]int{"F1": helv}}}))
	r := Extract(boundsStaleDeadline{context.Background()}, b.Bytes(), testOptions())
	if !r.TimedOut || len(r.Pages) != 0 {
		t.Errorf("a document read past a deadline the clock had reached: timedOut %v pages %+v", r.TimedOut, r.Pages)
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
		"the work one page may cost: the bytes its content streams and the forms it draws hold, and each entry of a filter list read": mib(maxPageWorkBytes) + "; " + grouped(filterStepBytes) + " bytes an entry",
		"bytes the operands of a page hold at one time, the forms it draws included":                                                  mib(maxOperandBytes),
		"the entries one `bfrange` or `cidrange` is charged":                                                                          grouped(cmapRangeEntries) + "; one more for each " + grouped(cmapRunsPerEntry) + " characters of its destination",
		"bytes read and held for each byte of the file and of each byte its streams inflate to":                                       grouped(parsedBytesPerFileByte),
		"bytes read and held in all":                                                       gib(maxParsedBytesHeld),
		"the bytes the values one CMap is read through may hold":                           mib(maxCMapEntries * cmapEntryBytes),
		"the bytes of an object read to decide whether it is the page tree or the catalog": grouped(headWindow) + " bytes",
	} {
		if row := readmeRow(t, readme, label); row[1] != value {
			t.Errorf("%s: adapters/README.md says %q, the reader holds %q", label, row[1], value)
		}
	}
}

// gib writes n, a whole number of gibibytes, as adapters/README.md does.
func gib(n int64) string { return fmt.Sprintf("%d GiB", n>>30) }

// boundsCommentedObjects is a file whose every object is followed by a
// comment with no line end: the comment runs to the end of the file, so
// whatever reads the token after an object's value reads the rest of the
// file to find it, once for every object the reader asks for.
func boundsCommentedObjects(size int, body string) []byte {
	var out bytes.Buffer
	out.WriteString("%PDF-1.7\n")
	for i := 1; out.Len() < size; i++ {
		fmt.Fprintf(&out, "%d 0 obj %s%%", i, body)
	}
	fmt.Fprintf(&out, "\n%d 0 obj << /Type /Catalog >> endobj\n", 1<<20)
	return out.Bytes()
}

// The bytes a lexer advances over are charged, not only the bytes a value
// holds: a file whose objects are each followed by a comment that runs to
// its end is read once for every object it declares, and nothing it holds
// would show that. The charge grows with the file and not with the square
// of it, and a file large enough meets the bound.
func TestBoundsBytesReadAreCharged(t *testing.T) {
	// A value followed by a comment, a dictionary followed by a comment, and
	// a value followed by a string with no end: the last is read to the end
	// of the file as the token after the value and stepped back over.
	for _, body := range []string{"0 ", "<< /A 1 >>", "0 ("} {
		boundsChargeGrowsWithTheFile(t, body)
	}
}

// boundsChargeGrowsWithTheFile reads every object of files of three sizes
// whose objects end in a comment with no line end, and holds the bytes
// charged to growing with the file rather than with the square of it.
func boundsChargeGrowsWithTheFile(t *testing.T, body string) {
	t.Helper()
	type run struct {
		size    int
		charged int64
		took    time.Duration
		bound   bool
	}
	var runs []run
	for _, size := range []int{64 << 10, 128 << 10, 256 << 10} {
		data := boundsCommentedObjects(size, body)
		started := time.Now()
		d, err := open(context.Background(), data, &inflateBudget{total: 64 << 20, one: 16 << 20})
		if d == nil {
			t.Fatalf("%d bytes: not opened: %v", size, err)
		}
		// Every object the cross-reference names is asked for, as a walk
		// looking for a page tree asks.
		for num := range d.xref {
			d.objectRead(num)
		}
		took := time.Since(started)
		runs = append(runs, run{size: len(data), charged: d.parsedBytes, took: took, bound: d.bound != nil || d.parsedSpent()})
		t.Logf("%-12q %7d bytes: %9d charged of %9d allowed, %v (bound met %v)", body, len(data), d.parsedBytes, d.parsedBudget(), took, d.bound != nil || d.parsedSpent())
	}
	// Doubling the file at most doubles what is charged, up to the bound: a
	// reader that charged only what it held would charge about the same for
	// all three while reading four times as much.
	for i := 1; i < len(runs); i++ {
		before, now := runs[i-1], runs[i]
		if now.bound {
			continue
		}
		if now.charged > 3*before.charged {
			t.Errorf("%d bytes charged %d and %d bytes charged %d: the charge grows faster than the file",
				before.size, before.charged, now.size, now.charged)
		}
	}
	// The largest file is read once for every object in it, which is far
	// more than its allowance whatever the clock says: a reader that charged
	// what it read meets the bound there, and one that did not would read
	// on, quadratically -- so the bound, not the time, is what is asserted,
	// and the time is a second guard for a machine under load.
	last := runs[len(runs)-1]
	if !last.bound {
		t.Errorf("%-12q %d bytes: %d charged in %v, and no bound met", body, last.size, last.charged, last.took)
	}
	if last.took > 5*time.Second {
		t.Errorf("%-12q %d bytes took %v", body, last.size, last.took)
	}
}

// An object stream is read by a lexer of its own per object, and the same
// holds of it: an object whose value is followed by an unterminated string
// has the rest of the stream's data read past it, once for every object the
// stream holds, and the charge on the bytes read is what bounds that.
func TestBoundsBytesReadFromAnObjectStreamAreCharged(t *testing.T) {
	type run struct {
		objects int
		charged int64
		took    time.Duration
		bound   bool
	}
	var runs []run
	for _, n := range []int{2000, 4000, 8000} {
		b := &pdfgen.Builder{XrefStream: true, ObjectStreams: true}
		for i := 0; i < n; i++ {
			b.Add(pdfgen.Object{Body: "0 ("})
		}
		b.Root = b.Add(pdfgen.Object{Body: "<< /Type /Catalog >>"})
		data := b.Bytes()
		started := time.Now()
		d, err := open(context.Background(), data, &inflateBudget{total: 64 << 20, one: 16 << 20})
		if d == nil {
			t.Fatalf("%d objects: not opened: %v", n, err)
		}
		for num := range d.xref {
			d.objectRead(num)
		}
		took := time.Since(started)
		bound := d.bound != nil || d.parsedSpent()
		runs = append(runs, run{objects: n, charged: d.parsedBytes, took: took, bound: bound})
		t.Logf("%5d objects in a stream: %9d charged of %9d allowed, %v (bound met %v)", n, d.parsedBytes, d.parsedBudget(), took, bound)
	}
	for i := 1; i < len(runs); i++ {
		before, now := runs[i-1], runs[i]
		if !now.bound && now.charged > 3*before.charged {
			t.Errorf("%d objects charged %d and %d objects charged %d: the charge grows faster than the stream",
				before.objects, before.charged, now.objects, now.charged)
		}
	}
	// The largest stream is read once for every object it holds, which is
	// far more than its allowance whatever the clock says: a reader that
	// charged what it read meets the bound there, and one that did not
	// would read on, quadratically, and finish within a second at this
	// size -- so the bound, not the time, is what is asserted.
	if last := runs[len(runs)-1]; !last.bound {
		t.Errorf("%d objects: %d charged in %v, and no bound met", last.objects, last.charged, last.took)
	}
}

// A comment with no line end after the other words a file is read by: the
// keyword that begins a cross-reference, the offset that follows startxref,
// and an entry of a cross-reference table.
func TestBoundsCommentsWhereTheFileIsRead(t *testing.T) {
	objects := []string{
		"1 0 obj<< /Type /Catalog /Pages 2 0 R >>endobj\n",
		"2 0 obj<< /Type /Pages /Kids [3 0 R] /Count 1 >>endobj\n",
		"3 0 obj<< /Type /Page /Parent 2 0 R /Contents 4 0 R /Resources << /Font << /F1 5 0 R >> >> >>endobj\n",
		"4 0 obj<< /Length 44 >>stream\nBT /F1 12 Tf 10 700 Td (Hello world) Tj ET\nendstream\nendobj\n",
		"5 0 obj<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>endobj\n",
	}
	sound := boundsTabledWith(objects, nil, "1 0 R")
	for _, c := range []struct {
		name, at string
	}{
		{"after the cross-reference keyword", "xref\n"},
		{"after startxref", "startxref\n"},
		{"in a cross-reference entry", "0000000000 65535 f \n"},
	} {
		t.Run(c.name, func(t *testing.T) {
			data := bytes.Replace(sound, []byte(c.at), append([]byte(c.at), '%'), 1)
			started := time.Now()
			r := extract(t, data)
			t.Logf("%d bytes: %v fatal %+v pages %+v", len(data), time.Since(started), r.Fatal, r.Pages)
			if took := time.Since(started); took > 3*time.Second {
				t.Errorf("a comment %s took %v to read past", c.name, took)
			}
		})
	}
}

// boundsOverlongStrings is a file of trailer candidates each followed by a
// string longer than the bound on a string token: the token is read to that
// bound and refused, so the bytes are read for every candidate and held for
// none of them. The string is written in the form given, a literal or a hex.
func boundsOverlongStrings(candidates int, hex bool) []byte {
	var out bytes.Buffer
	out.WriteString("%PDF-1.7\n1 0 obj<< /Type /Catalog >>endobj\n")
	for i := 0; i < candidates; i++ {
		if hex {
			out.WriteString("trailer<< /A <")
		} else {
			out.WriteString("trailer<< /A (")
		}
	}
	// More bytes than one string token may hold, so every candidate reads its
	// way to the bound before refusing.
	if hex {
		out.Write(bytes.Repeat([]byte("41"), maxStringBytes+64))
	} else {
		out.Write(bytes.Repeat([]byte("a"), maxStringBytes+64))
	}
	return out.Bytes()
}

// A token reader that refuses what it read still charges it: a string past
// the bound on a string token is read to that bound, and a file of trailer
// candidates each followed by such a string would otherwise be read once for
// every candidate at no cost. The bound is met, and it is met as a bound
// rather than as a candidate the scan passes over.
func TestBoundsOverlongTokensAreCharged(t *testing.T) {
	for _, hex := range []bool{false, true} {
		kind := "a literal string"
		if hex {
			kind = "a hex string"
		}
		t.Run(kind, func(t *testing.T) {
			data := boundsOverlongStrings(4, hex)
			started := time.Now()
			d, err := open(context.Background(), data, &inflateBudget{total: 64 << 20, one: 16 << 20})
			took := time.Since(started)
			charged := int64(0)
			if d != nil {
				charged = d.parsedBytes
			}
			t.Logf("%d candidates before %s of %d bytes: %v, %d charged (%v)", 4, kind, len(data), took, charged, err)
			if !errors.Is(err, errStructureBound) {
				t.Errorf("reading %d bytes of candidates ended with %v", len(data), err)
			}
			// The bound above is what this establishes: the scan ends at the
			// first candidate, where a reader that charged nothing for a token
			// it refused would read the file again for each of them. The time
			// is logged rather than held to a figure: this file is tens of
			// megabytes, which is slow to read once under the race detector,
			// and the shapes whose time says something are the smaller ones
			// above.
		})
	}
}

// boundsAliasedOffsets is a file whose cross-reference stream gives many
// object numbers the same offset, where the object of that offset holds the
// dictionary given: the reader reads what is at that offset once for the
// offset, not once for every number that names it.
func boundsAliasedOffsets(aliases, members int) []byte {
	var out bytes.Buffer
	out.WriteString("%PDF-1.7\n")
	catalog := out.Len()
	out.WriteString("1 0 obj<< /Type /Catalog >>endobj\n")
	pages := out.Len()
	out.WriteString("2 0 obj<< /Type /Nothing >>endobj\n")
	other := out.Len()
	out.WriteString("3 0 obj<< /Type /Other " + strings.Repeat("/A <</B 1>> ", members) + ">>endobj\n")
	at := out.Len()
	var entries []byte
	put := func(typ byte, f2, f3 int) {
		entries = append(entries, typ, byte(f2>>16), byte(f2>>8), byte(f2), byte(f3))
	}
	put(0, 0, 255)
	put(1, catalog, 0)
	put(1, pages, 0)
	for i := 0; i < aliases; i++ {
		put(1, other, 0)
	}
	fmt.Fprintf(&out, "4 0 obj<< /Type /XRef /Size %d /W [1 3 1] /Root 1 0 R /Length %d >>stream\n", 3+aliases, len(entries))
	out.Write(entries)
	out.WriteString("\nendstream endobj\n")
	fmt.Fprintf(&out, "startxref\n%d\n%%%%EOF\n", at)
	return out.Bytes()
}

// Reading an object's head is charged, and what it settled is kept by the
// offset it was read at: a cross-reference that gives thousands of object
// numbers one offset costs one reading of that head where the head settles
// what the object is, and where it cannot, the reading of the object itself
// spends the allowance and meets the bound instead of running on.
func TestBoundsHeadInspectionIsChargedAndKept(t *testing.T) {
	for _, c := range []struct {
		name    string
		members int
		settled bool
	}{
		{"a head the window settles", 40, true},
		{"a head the window cannot settle", 100, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			for _, aliases := range []int{8000, 32000} {
				data := boundsAliasedOffsets(aliases, c.members)
				d, err := open(context.Background(), data, &inflateBudget{total: 64 << 20, one: 16 << 20})
				if d == nil {
					t.Fatalf("not opened: %v", err)
				}
				started := time.Now()
				// The page tree is looked for among the objects the
				// cross-reference names, which is where each entry's head is
				// inspected. It is asked for directly, since rebuilding by
				// scanning would replace the cross-reference whose aliases
				// are the point.
				root := d.findPagesRoot()
				took := time.Since(started)
				t.Logf("%d bytes, %d aliases of one offset: %v, %d charged of %d allowed (bound %v)", len(data), aliases, took, d.parsedBytes, d.parsedBudget(), d.bound != nil || d.parsedSpent())
				if root != nil {
					t.Error("a file that holds no page tree yielded one")
				}
				if took > 3*time.Second {
					t.Errorf("%d aliases of one offset took %v", aliases, took)
				}
				// The head at that offset is read, and charged: a search that
				// read it for nothing would charge nothing at all.
				if d.parsedBytes < int64(headWindow) {
					t.Errorf("%d aliases of one offset charged %d bytes; reading one head costs more than that", aliases, d.parsedBytes)
				}
				if c.settled {
					// Read once for the offset, not once for every number.
					if d.parsedBytes > int64(headWindow)*64 {
						t.Errorf("%d aliases of one offset charged %d bytes; the head at that offset is read once", aliases, d.parsedBytes)
					}
				} else if !d.parsedSpent() {
					// Nothing the window settles, so every alias is a whole
					// object to read: the allowance is what ends that.
					t.Errorf("%d aliases of an object the window cannot settle charged %d of %d without meeting the bound", aliases, d.parsedBytes, d.parsedBudget())
				}
			}
		})
	}
}

// The allowance is one balance, and every reading of it is a reading of what
// is left: two parses of one document that each took what was there when
// they began would spend the same bytes twice.
func TestBoundsOneBalanceIsAuthoritative(t *testing.T) {
	d := &Document{data: make([]byte, 1<<10), budget: &inflateBudget{}}
	d.parsedBytes = d.parsedBudget() - 3000
	first, second := d.budgeted(), d.budgeted()
	if !first.take(2000) {
		t.Fatal("the first take of 2,000 did not fit in 3,000")
	}
	if second.take(2000) {
		t.Error("a second allowance spent the same bytes over again")
	}
	if d.parsedBytes > d.parsedBudget() {
		t.Errorf("the document has spent %d of %d", d.parsedBytes, d.parsedBudget())
	}
}

// What a document may hold is the smaller of the ratio and the ceiling: the
// ratio binds a small file, and the ceiling every file past a few megabytes.
func TestBoundsCeilingBindsPastTheRatio(t *testing.T) {
	for _, c := range []struct {
		name string
		size int
		want int64
	}{
		{"a small file", 1 << 20, parsedBytesPerFileByte << 20},
		{"a file past the ceiling's crossing", 8 << 20, maxParsedBytesHeld},
	} {
		d := &Document{data: make([]byte, c.size), budget: &inflateBudget{}}
		if got := d.parsedBudget(); got != c.want {
			t.Errorf("%s of %d bytes: %d allowed, want %d", c.name, c.size, got, c.want)
		}
	}
}

// Every way out of a lexer charges what it read, including the ways out at
// the end of the data, where nothing after them would charge it: a token
// that ends there, whitespace that ends there, and a token refused there.
func TestBoundsTerminalLexerPathsAreCharged(t *testing.T) {
	for _, c := range []struct {
		name string
		data string
		read func(*lexer)
	}{
		{"a token at the end of the data", "  /Name", func(l *lexer) { l.next() }},
		{"whitespace at the end of the data", strings.Repeat(" ", 4096), func(l *lexer) { l.skipSpace() }},
		{"a token refused at the end of the data", "(" + strings.Repeat("a", maxStringBytes+8), func(l *lexer) { l.next() }},
	} {
		t.Run(c.name, func(t *testing.T) {
			d := &Document{data: make([]byte, 1<<20), budget: &inflateBudget{}}
			lex := newLexer([]byte(c.data), 0).within(d.budgeted())
			c.read(lex)
			if d.parsedBytes < int64(lex.pos) {
				t.Errorf("%d bytes were read and %d charged", lex.pos, d.parsedBytes)
			}
		})
	}
}

// boundsDensePages is a document of pages each naming a resource of count
// one-member dictionaries: the shape an ordinary document of many pages
// takes, which the ceiling must leave readable.
func boundsDensePages(pages, perPage int, inObjectStream bool) []byte {
	b := &pdfgen.Builder{}
	if inObjectStream {
		b.XrefStream, b.ObjectStreams, b.Compress = true, true, true
	}
	helv := b.Font("Helvetica", "WinAnsiEncoding", "")
	var dense strings.Builder
	dense.WriteString("[")
	for i := 0; i < perPage; i++ {
		dense.WriteString("<</A 1>>")
	}
	dense.WriteString("]")
	body := "<< /Dense " + dense.String() + " >>"
	root := b.Next()
	b.Add(pdfgen.Object{Body: "placeholder"})
	kids := make([]string, 0, pages)
	for i := 0; i < pages; i++ {
		props := b.Add(pdfgen.Object{Body: body})
		cs := b.Add(pdfgen.Object{Body: "<< >>", Stream: []byte(pdfgen.Text("F1", 12, []string{"dense"}))})
		page := b.Add(pdfgen.Object{Body: fmt.Sprintf("<< /Type /Page /Parent %d 0 R /MediaBox [0 0 612 792] /Resources << /Font << /F1 %d 0 R >> /Properties %d 0 R >> /Contents %d 0 R >>", root, helv, props, cs)})
		kids = append(kids, fmt.Sprintf("%d 0 R", page))
	}
	b.Set(root, pdfgen.Object{Body: fmt.Sprintf("<< /Type /Pages /Kids [%s] /Count %d >>", strings.Join(kids, " "), pages)})
	b.Catalog(root)
	return b.Bytes()
}

// An ordinary document of many pages, each holding as much structure as the
// densest shape the reader admits, is read whole: the ceiling is set above
// what such a document costs, where the ratio would allow far more, and a
// document of twice that structure meets it.
func TestBoundsAnOrdinaryDenseDocumentIsReadWhole(t *testing.T) {
	for _, inStream := range []bool{false, true} {
		where := "at an offset"
		if inStream {
			where = "in an object stream"
		}
		t.Run(where, func(t *testing.T) {
			data := boundsDensePages(500, 2000, inStream)
			d := openGenerated(t, data)
			w := &walker{d: d, ctx: context.Background(), visited: map[ref]bool{}, limit: 1000}
			if ending := w.node(d.pagesRoot(), inherited{}, 0); ending != walkComplete {
				t.Fatalf("%d bytes: the walk ended at %v (%q)", len(data), ending, w.defect)
			}
			distinct := map[ref]bool{}
			for i, pn := range w.pages {
				props := d.dictOf(pn.dict["Resources"])["Properties"]
				if r, ok := props.(ref); ok {
					distinct[r] = true
				}
				dense := d.arrayOf(d.dictOf(props)["Dense"])
				if len(dense) != 2000 {
					t.Fatalf("%d bytes: page %d holds %d of its 2,000 dictionaries, with %d charged of %d", len(data), i+1, len(dense), d.parsedBytes, d.parsedBudget())
				}
			}
			// Every page is its own, and so is every resource: an index the
			// generator wrote in too few bytes would give many pages one.
			if len(w.pages) != 500 || len(distinct) != 500 {
				t.Errorf("%d pages and %d distinct resources, of 500 each", len(w.pages), len(distinct))
			}
			t.Logf("%d pages of 2,000 one-member dictionaries %s: %d bytes, %d charged of %d allowed", len(w.pages), where, len(data), d.parsedBytes, d.parsedBudget())
			if d.bound != nil {
				t.Errorf("an ordinary document met %v", d.bound)
			}
		})
	}
	// The densest ordinary document the ceiling admits: five hundred pages of
	// three thousand six hundred one-member dictionaries each, a fourteen
	// megabyte file, read whole at just under the ceiling.
	dense := boundsDensePages(500, 3600, false)
	d := openGenerated(t, dense)
	w := &walker{d: d, ctx: context.Background(), visited: map[ref]bool{}, limit: 1000}
	if ending := w.node(d.pagesRoot(), inherited{}, 0); ending != walkComplete {
		t.Fatalf("%d bytes: the walk ended at %v", len(dense), ending)
	}
	whole := 0
	for _, pn := range w.pages {
		if len(d.arrayOf(d.dictOf(d.dictOf(pn.dict["Resources"])["Properties"])["Dense"])) == 3600 {
			whole++
		}
	}
	t.Logf("500 pages of 3,600 one-member dictionaries: %d bytes, %d pages whole, %d charged of %d", len(dense), whole, d.parsedBytes, d.parsedBudget())
	if whole != 500 || d.bound != nil {
		t.Errorf("the densest document the ceiling admits read %d pages whole, bound %v", whole, d.bound)
	}
	// The same shape at an offset, in the page count and per-page structure
	// the ceiling was set from, costs more than the ceiling this bound held
	// before it was measured against a document like this.
	data := boundsDensePages(500, 2000, false)
	d = openGenerated(t, data)
	w = &walker{d: d, ctx: context.Background(), visited: map[ref]bool{}, limit: 1000}
	w.node(d.pagesRoot(), inherited{}, 0)
	for _, pn := range w.pages {
		d.resolve(d.dictOf(pn.dict["Resources"])["Properties"])
	}
	if d.parsedBytes <= 512<<20 {
		t.Errorf("the document the ceiling was set from costs %d bytes, which the ceiling before it did not have to admit", d.parsedBytes)
	}
	// A little more of it is past the ceiling: what the reader cannot hold it
	// does not hold, and the bound says so.
	big := boundsDensePages(500, 4000, false)
	d = openGenerated(t, big)
	w = &walker{d: d, ctx: context.Background(), visited: map[ref]bool{}, limit: 1000}
	w.node(d.pagesRoot(), inherited{}, 0)
	whole = 0
	for _, pn := range w.pages {
		if len(d.arrayOf(d.dictOf(d.dictOf(pn.dict["Resources"])["Properties"])["Dense"])) == 4000 {
			whole++
		}
	}
	t.Logf("500 pages of 4,000 one-member dictionaries: %d bytes, %d pages whole, %d charged of %d, bound %v", len(big), whole, d.parsedBytes, d.parsedBudget(), d.bound != nil)
	if d.bound == nil || whole == len(w.pages) {
		t.Errorf("a document past the ceiling read %d of %d pages whole with bound %v", whole, len(w.pages), d.bound)
	}
}

// What a parse actually spends of the allowance covers what Go retains for
// the values it built: the hand-built shapes above are one half of that
// claim, and this is the other, through the reader's own parser, where a
// string or a name holds the room the builder grew into and a null is a
// value the slot holding it pays for.
func TestBoundsParsedValuesCostWhatIsCharged(t *testing.T) {
	if boundsInstrumented {
		t.Skip("the race detector's own allocations are not the reader's, and what it retains is not what this measures")
	}
	text := func(l int) string { return strings.Repeat("a", l) }
	for _, c := range []struct {
		name   string
		source string
		count  int
	}{
		{"literal strings of 4,097 bytes", "(" + text(4097) + ")", 10000},
		{"hex strings of 4,097 bytes", "<" + strings.Repeat("41", 4097) + ">", 10000},
		{"names of 3,073 bytes", "/" + text(3073), 10000},
		{"arrays of seventeen nulls", "[null null null null null null null null null null null null null null null null null]", 20000},
		{"dictionaries of one member", "<</A 1>>", 50000},
	} {
		t.Run(c.name, func(t *testing.T) {
			source := []byte(strings.Repeat(c.source+" ", c.count))
			// A document large enough that the allowance is not what stops
			// this: what is measured is what a parse spends.
			d := &Document{data: make([]byte, 64<<20), budget: &inflateBudget{}}
			held := make([]object, 0, c.count)
			boundsLiveHeap()
			spent := d.parsedBytes
			lex := newLexer(source, 0)
			p := &parser{lex: lex, allow: d.budgeted()}
			for i := 0; i < c.count; i++ {
				v, err := p.parseObject(0)
				if err != nil {
					t.Fatalf("value %d of %d: %v", i+1, c.count, err)
				}
				held = append(held, v)
			}
			with := boundsLiveHeap()
			runtime.KeepAlive(held)
			held = nil
			after := boundsLiveHeap()
			// Everything but the values stays alive across both readings, so
			// what the difference holds is the values and nothing else.
			charged := d.parsedBytes - spent
			runtime.KeepAlive(source)
			runtime.KeepAlive(p)
			retained := with - after
			t.Logf("%-32s %6d retained, %6d charged, each", c.name, int(retained)/c.count, int(charged)/c.count)
			if int64(retained) > charged {
				t.Errorf("%s: %d bytes retained for each, %d charged", c.name, int(retained)/c.count, int(charged)/c.count)
			}
		})
	}
}

// A string is charged the room it takes as it takes it: a string past what
// is left is stopped where the room runs out, not read and allocated whole
// and refused after.
func TestBoundsAStringIsChargedAsItGrows(t *testing.T) {
	for _, c := range []struct{ name, source string }{
		{"a literal string", "(" + strings.Repeat("a", 8<<20) + ")"},
		{"a hex string", "<" + strings.Repeat("41", 8<<20) + ">"},
	} {
		t.Run(c.name, func(t *testing.T) {
			d := &Document{data: make([]byte, 1<<10), budget: &inflateBudget{}}
			// A thousand bytes of allowance against a string of eight
			// mebibytes.
			d.parsedBytes = d.parsedBudget() - 1024
			lex := newLexer([]byte(c.source), 0).within(d.budgeted())
			p := &parser{lex: lex, allow: d.budgeted()}
			grew := allocated(func() {
				if _, err := p.parseObject(0); err == nil {
					t.Errorf("a string of %d bytes was read with 1,024 bytes of allowance", len(c.source))
				}
			})
			t.Logf("%s of %d bytes with 1,024 allowed: %d KiB allocated while it was refused", c.name, len(c.source), grew>>10)
			// Reading it whole and refusing it after would allocate the whole
			// of it; stopping where the room runs out allocates a little.
			if grew > 1<<20 {
				t.Errorf("%s allocated %d KiB while being refused", c.name, grew>>10)
			}
		})
	}
}

// An operand that holds more than one page's operands may hold stops the
// page, whatever shape it takes: fifteen thousand strings of four kilobytes
// each are past the bound although each string and the stream that carries
// them are within theirs.
func TestBoundsAnOperandOfStringsStopsThePage(t *testing.T) {
	// Four streams, so that no stream inflates past its own bound and the
	// page's content stays within what a page's content may hold: what is
	// past a bound here is the operand the four of them spell together.
	const streams, each = 4, 3750
	b := &pdfgen.Builder{}
	refs := make([]string, streams)
	for i := range refs {
		var content strings.Builder
		if i == 0 {
			content.WriteString("[")
		}
		for k := 0; k < each; k++ {
			content.WriteString("(" + strings.Repeat("a", 4097) + ")")
		}
		if i == streams-1 {
			content.WriteString("]")
		}
		refs[i] = fmt.Sprintf("%d 0 R", b.Add(pdfgen.Object{Body: "<< /Filter /FlateDecode >>", Stream: flateOf([]byte(content.String())), Raw: true}))
	}
	pages := b.Next()
	b.Add(pdfgen.Object{Body: "placeholder"})
	page := b.Add(pdfgen.Object{Body: fmt.Sprintf("<< /Type /Page /Parent %d 0 R /MediaBox [0 0 612 792] /Resources << >> /Contents [%s] >>", pages, strings.Join(refs, " "))})
	b.Set(pages, pdfgen.Object{Body: fmt.Sprintf("<< /Type /Pages /Kids [%d 0 R] /Count 1 >>", page)})
	b.Catalog(pages)
	data := b.Bytes()
	var r *Result
	peak := boundsPeakLiveHeap(func() { r = extract(t, data) })
	t.Logf("one operand of 15,000 strings of 4,097 bytes (%d bytes): most held at once %d MiB, pages %+v problems %+v", len(data), peak>>20, r.Pages, r.Problems)
	if r.Fatal != nil || len(r.Pages) != 1 || r.Pages[0].Status != PageFailed {
		t.Fatalf("fatal %+v pages %+v", r.Fatal, r.Pages)
	}
	if len(r.Problems) != 1 || r.Problems[0].Code != "pdf-page-failed" {
		t.Errorf("the page failed with %+v; what it met is the bound on what its operands hold", r.Problems)
	}
	// The content itself is sixty megabytes, and the operands the bound
	// admits another sixty-four: what this catches is a page that holds the
	// whole of an operand past the bound as well.
	if peak > 256<<20 {
		t.Errorf("the page held %d MiB at once; the bound on what its operands hold is %d MiB", peak>>20, maxOperandBytes>>20)
	}
}

// A decrypted stream is a copy the reader holds, and it is charged before it
// is made: an encrypted document whose object streams decrypt to more than
// the document may hold is left unread rather than held.
func TestBoundsDecryptedStreamsAreCharged(t *testing.T) {
	b := &pdfgen.Builder{Encrypt: &pdfgen.Encryption{Revision: 4, Owner: "owner", Permissions: -1}}
	helv := b.Font("Helvetica", "WinAnsiEncoding", "")
	// A stream of half a mebibyte, decrypted into a copy of its own.
	body := b.Add(pdfgen.Object{Body: "<< >>", Stream: bytes.Repeat([]byte("x"), 512<<10)})
	b.Catalog(b.Pages([]pdfgen.Page{{Content: pdfgen.Text("F1", 12, []string{"encrypted"}), Fonts: map[string]int{"F1": helv}}}))
	data := b.Bytes()
	d := openGenerated(t, data)
	if _, err := d.openEncryption(); err != nil {
		t.Fatalf("encryption: %v", err)
	}
	before := d.parsedBytes
	s, ok := d.resolve(ref{body, 0}).(*stream)
	if !ok {
		t.Fatalf("object %d is not a stream", body)
	}
	if _, err := d.decodeStream(s, false); err != nil {
		t.Fatalf("decode: %v", err)
	}
	charged := d.parsedBytes - before
	t.Logf("a decrypted stream of %d bytes: %d charged", len(s.raw), charged)
	if charged < int64(len(s.raw)) {
		t.Errorf("a decrypted copy of %d bytes was charged %d", len(s.raw), charged)
	}
}

// An inline image's dictionary is read and dropped, and what it holds while
// it is read is bounded: a dictionary value of hundreds of thousands of
// small dictionaries fails the page rather than being built whole.
func TestBoundsInlineImageDictionaryIsBounded(t *testing.T) {
	var content strings.Builder
	content.WriteString("BI /W 4 /H 4 /BPC 8 /CS /G /Junk [")
	for i := 0; i < 220_000; i++ {
		content.WriteString("<</A 1>>")
	}
	content.WriteString("] ID \x41\x41\x41\x41 EI\n")
	b := &pdfgen.Builder{Compress: true}
	b.Catalog(b.Pages([]pdfgen.Page{{Content: content.String()}}))
	data := b.Bytes()
	var r *Result
	peak := boundsPeakLiveHeap(func() { r = extract(t, data) })
	t.Logf("an inline image's dictionary of 220,000 dictionaries (%d bytes): most held at once %d MiB, pages %+v problems %+v", len(data), peak>>20, r.Pages, r.Problems)
	if r.Fatal != nil || len(r.Pages) != 1 || r.Pages[0].Status != PageFailed {
		t.Fatalf("fatal %+v pages %+v", r.Fatal, r.Pages)
	}
	if peak > 192<<20 {
		t.Errorf("the page held %d MiB at once while reading an inline image's dictionary", peak>>20)
	}
}

// A CMap's own values are bounded by what the document's fonts may hold: a
// destination array of hundreds of thousands of dictionaries is not built
// and then ignored.
func TestBoundsCMapValuesAreBounded(t *testing.T) {
	var src strings.Builder
	src.WriteString("begincmap\n1 begincodespacerange <0000> <FFFF> endcodespacerange\n1 beginbfrange\n<0000><0001>[")
	for i := 0; i < 800_000; i++ {
		src.WriteString("<</A 1>>")
	}
	src.WriteString("]\nendbfrange\nendcmap\n")
	budget := &fontBudget{}
	var c *cmap
	grew := allocated(func() { c = parseCMap([]byte(src.String()), budget, nil) })
	t.Logf("a CMap whose destination holds 800,000 dictionaries (%d bytes): %d MiB allocated, used %v", src.Len(), grew>>20, c != nil)
	// Eight hundred thousand one-member dictionaries hold more than one
	// CMap's mappings may: the CMap is abandoned while the value is built,
	// rather than built whole and then ignored.
	if c != nil {
		t.Errorf("a CMap whose destination holds more than its mappings may was used")
	}
	if grew > 384<<20 {
		t.Errorf("reading the CMap allocated %d MiB", grew>>20)
	}
}

// What a document holds outside its object cache is charged and kept: the
// headers of its object streams are cleared where the charge for them is,
// and neither outlives the other.
func TestBoundsObjectStreamHeadersAreChargedAndCleared(t *testing.T) {
	b := &pdfgen.Builder{XrefStream: true, ObjectStreams: true, Compress: true}
	helv := b.Font("Helvetica", "WinAnsiEncoding", "")
	b.Catalog(b.Pages([]pdfgen.Page{{Content: pdfgen.Text("F1", 12, []string{"held"}), Fonts: map[string]int{"F1": helv}}}))
	d := openGenerated(t, b.Bytes())
	boundsFirstPage(t, d)
	if len(d.objStmHeaders) == 0 {
		t.Fatal("the document holds no object-stream header")
	}
	before := d.parsedBytes
	// An object stream's header is charged as it is read: reading one again
	// costs again.
	d.objStms, d.objStmHeaders = map[int]*objStm{}, nil
	d.cache = map[int]object{}
	boundsFirstPage(t, d)
	if d.parsedBytes <= before {
		t.Errorf("reading the object-stream headers again charged %d bytes", d.parsedBytes-before)
	}
}

// Whitespace is read like anything else: a file whose objects are each
// followed by a stretch of it that reaches the next object, or the end of
// the file, is read once for every object and charged for it.
func TestBoundsWhitespaceBetweenObjectsIsCharged(t *testing.T) {
	var out bytes.Buffer
	out.WriteString("%PDF-1.7\n")
	// Every object is one integer, and the whitespace after the last of them
	// runs to the end of the file, where nothing follows to charge it.
	for i := 1; i <= 2000; i++ {
		fmt.Fprintf(&out, "%d 0 obj 0 ", i)
	}
	out.Write(bytes.Repeat([]byte(" "), 64<<10))
	data := out.Bytes()
	d, err := open(context.Background(), data, &inflateBudget{total: 64 << 20, one: 16 << 20})
	if d == nil {
		t.Fatalf("not opened: %v", err)
	}
	started := time.Now()
	for num := range d.xref {
		d.objectRead(num)
	}
	took := time.Since(started)
	t.Logf("%d bytes, 2,000 objects before %d bytes of whitespace: %v, %d charged of %d allowed", len(data), 64<<10, took, d.parsedBytes, d.parsedBudget())
	// Each object reads the whitespace after it, so what is charged is far
	// more than the objects themselves hold; without that it is a few
	// thousand bytes and the file is read again for every object.
	if d.parsedBytes < 64<<10 {
		t.Errorf("reading 2,000 objects across %d bytes of whitespace charged %d bytes", 64<<10, d.parsedBytes)
	}
	if took > 3*time.Second {
		t.Errorf("reading them took %v", took)
	}
}

// Reading an object's head is charged to the document, and not only bounded
// by the window: the bytes the head reader lexes are the document's to pay
// for, as every other reading of the file is.
func TestBoundsReadingAHeadIsCharged(t *testing.T) {
	data := boundsAliasedOffsets(1, 40)
	d, err := open(context.Background(), data, &inflateBudget{total: 64 << 20, one: 16 << 20})
	if d == nil {
		t.Fatalf("not opened: %v", err)
	}
	before := d.parsedBytes
	e := xrefEntry{offset: int64(bytes.Index(data, []byte("3 0 obj")))}
	if known := d.readHeadType(e); !known.settled || known.typ != "Other" {
		t.Fatalf("the head read %+v", known)
	}
	charged := d.parsedBytes - before
	t.Logf("reading one head: %d charged", charged)
	if charged < 64 {
		t.Errorf("reading a head charged %d bytes", charged)
	}
}

// A parse whose reading has run out of allowance ends where it stands: the
// token after it is an error, and a lookahead that would throw that error
// away does not read on at no cost.
func TestBoundsExhaustionEndsTheParse(t *testing.T) {
	// An integer, then a string longer than what is left to read with.
	source := []byte("1 (" + strings.Repeat("a", 1<<20) + ")")
	d := &Document{data: make([]byte, 1<<10), budget: &inflateBudget{}}
	d.parsedBytes = d.parsedBudget() - 512
	lex := newLexer(source, 0).within(d.budgeted())
	p := &parser{lex: lex, allow: d.budgeted()}
	v, err := p.parseObject(0)
	// The integer itself is within what is left; the string the lookahead
	// reads after it is not, and is stopped where the room runs out.
	t.Logf("with 512 bytes to read with: %v %v (charged to byte %d of %d)", v, err, lex.charged, len(source))
	if lex.charged > 8192 {
		t.Errorf("a lookahead past what it may read went on to byte %d of %d", lex.charged, len(source))
	}
	// And the parse after it ends rather than reading on for nothing.
	if _, err := p.parseObject(0); err == nil {
		t.Error("a parse whose reading is spent returned a value")
	}
}

// An object read out of an object stream is built within the allowance too:
// a value past what the document may hold is stopped while it is built, not
// allocated whole out of the decoded stream and refused after.
func TestBoundsObjectStreamValuesAreBuiltWithinTheAllowance(t *testing.T) {
	// One object of an array of a quarter of a million one-member
	// dictionaries, in an object stream of two megabytes.
	var body strings.Builder
	body.WriteString("[")
	for i := 0; i < 250_000; i++ {
		body.WriteString("<</A 1>>")
	}
	body.WriteString("]")
	header := "9 0 "
	payload := header + body.String()
	var out bytes.Buffer
	out.WriteString("%PDF-1.7\n")
	out.WriteString("1 0 obj<< /Type /Catalog >>endobj\n")
	at := out.Len()
	fmt.Fprintf(&out, "2 0 obj<< /Type /ObjStm /N 1 /First %d /Length %d >>stream\n%s\nendstream endobj\n", len(header), len(payload), payload)
	fmt.Fprintf(&out, "trailer<< /Root 1 0 R /Size 3 >>\nstartxref\n%d\n%%%%EOF\n", at)
	data := out.Bytes()
	d, err := open(context.Background(), data, &inflateBudget{total: 64 << 20, one: 16 << 20})
	if d == nil {
		t.Fatalf("not opened: %v", err)
	}
	st, lerr := d.loadObjStm(2, d.resolve(ref{2, 0}).(*stream))
	if lerr != nil {
		t.Fatalf("loadObjStm: %v", lerr)
	}
	// What is left to hold with, against a value that holds far more.
	d.parsedBytes = d.parsedBudget() - 1<<20
	grew := allocated(func() {
		if v, read := d.objectFromStream(xrefEntry{inStream: true, stmNum: 2, stmIndex: 0}); read {
			t.Errorf("a value past what the document may hold was read: %T", v)
		}
	})
	t.Logf("an object-stream value of 250,000 dictionaries with a mebibyte to hold with: %d MiB allocated", grew>>20)
	_ = st
	if grew > 16<<20 {
		t.Errorf("reading it allocated %d MiB", grew>>20)
	}
}

// boundsStringOperand is a page whose content is one array of count strings
// of the length given, spread across the number of streams given so that no
// stream inflates past its own bound.
func boundsStringOperand(count, length, streams int) []byte {
	b := &pdfgen.Builder{}
	refs := make([]string, streams)
	each := count / streams
	for i := range refs {
		var content strings.Builder
		if i == 0 {
			content.WriteString("[")
		}
		for k := 0; k < each; k++ {
			content.WriteString("(" + strings.Repeat("a", length) + ")")
		}
		if i == streams-1 {
			content.WriteString("]")
		}
		refs[i] = fmt.Sprintf("%d 0 R", b.Add(pdfgen.Object{Body: "<< /Filter /FlateDecode >>", Stream: flateOf([]byte(content.String())), Raw: true}))
	}
	pages := b.Next()
	b.Add(pdfgen.Object{Body: "placeholder"})
	page := b.Add(pdfgen.Object{Body: fmt.Sprintf("<< /Type /Page /Parent %d 0 R /MediaBox [0 0 612 792] /Resources << >> /Contents [%s] >>", pages, strings.Join(refs, " "))})
	b.Set(pages, pdfgen.Object{Body: fmt.Sprintf("<< /Type /Pages /Kids [%d 0 R] /Count 1 >>", page)})
	b.Catalog(pages)
	return b.Bytes()
}

// A string past the sizes Go rounds to powers of two is charged the room its
// buffer grew into, on the content parser's route as on the document's: a
// thousand strings of 64 KiB hold more than one page's operands may, and the
// page fails rather than reading as a page with no text.
func TestBoundsLargeStringsAreChargedTheirRoom(t *testing.T) {
	data := boundsStringOperand(1000, 65536, 4)
	r := extract(t, data)
	t.Logf("1,000 strings of 65,536 bytes (%d bytes): pages %+v problems %+v", len(data), r.Pages, r.Problems)
	if r.Fatal != nil || len(r.Pages) != 1 || r.Pages[0].Status != PageFailed {
		t.Fatalf("fatal %+v pages %+v", r.Fatal, r.Pages)
	}
	if len(r.Problems) != 1 || r.Problems[0].Code != "pdf-page-failed" {
		t.Errorf("problems %+v", r.Problems)
	}
	// What the reader holds for such a string is the room the builder grew
	// into, which is more than its bytes.
	if held := parsedBytesOf(String(make([]byte, 65536))); held <= parsedStringBytes+65536 {
		t.Errorf("a string of 65,536 bytes is charged %d", held)
	}
}

// Every parser reserves the memory of the token it is building, whichever
// parser it is: a string far past what is left is stopped where the room
// runs out, on the content parser, in an inline image's dictionary and in a
// CMap alike.
func TestBoundsEveryParserReservesItsTokens(t *testing.T) {
	huge := strings.Repeat("a", 8<<20)
	// The sources are built here, so that what the measurement sees is what
	// the reader allocated and not what this test did.
	operand := []byte("(" + huge + ") Tj")
	inline := []byte("/A (" + huge + ") ID  EI")
	cmapSource := []byte("begincmap\n1 beginbfchar <0000> (" + huge + ") endbfchar\nendcmap\n")
	it := &interp{d: budgeted(64<<20, 16<<20), ctx: context.Background(), fonts: map[string]*font{}}
	for _, c := range []struct {
		name string
		read func() error
	}{
		{"a content stream's operand", func() error {
			it.err, it.operandBytes = nil, maxOperandBytes-1024
			it.run(operand, Dict{}, gstate{ctm: identity, hscale: 1}, 0)
			return it.err
		}},
		{"an inline image's dictionary", func() error {
			it.err, it.operandBytes = nil, maxOperandBytes-1024
			return it.skipInlineImage(newLexer(inline, 0))
		}},
		{"a CMap's destination", func() error {
			// A font budget with a kilobyte of room left in it.
			budget := &fontBudget{used: maxFontEntries - 1024/cmapEntryBytes}
			if c := parseCMap(cmapSource, budget, nil); c != nil {
				return nil
			}
			return errCMapBudget()
		}},
	} {
		t.Run(c.name, func(t *testing.T) {
			var err error
			grew := allocated(func() { err = c.read() })
			t.Logf("%s of 8 MiB with a kilobyte of room: %d KiB allocated (%v)", c.name, grew>>10, err)
			if grew > 2<<20 {
				t.Errorf("%s allocated %d KiB before refusing a string of 8 MiB", c.name, grew>>10)
			}
		})
	}
}

// A CMap whose reading meets the bound is not used at all, wherever the
// reading met it: in a section of mappings, or at the top level between
// them, where the mappings read so far would otherwise be kept.
func TestBoundsACMapPastItsBoundIsAbandoned(t *testing.T) {
	junk := "[" + strings.Repeat("<</A 1>>", 210_000) + "]"
	for _, c := range []struct{ name, src string }{
		{"in a section of mappings", "begincmap\n1 beginbfchar <0041> <0042>\nendbfchar\n1 beginbfrange\n<0000><0001>" + junk + "\nendbfrange\nendcmap\n"},
		{"at the top level", "begincmap\n1 beginbfchar <0041> <0042>\nendbfchar\n/Junk " + junk + " def\nendcmap\n"},
	} {
		t.Run(c.name, func(t *testing.T) {
			if got := parseCMap([]byte(c.src), &fontBudget{}, nil); got != nil {
				runes, ok := got.toUnicode(0x41)
				t.Errorf("a CMap past its bound was used, and maps 0x41 to %q (%v)", string(runes), ok)
			}
		})
	}
}

// A decrypted copy made for a page is the page's to answer for and is
// released with it: an encrypted document that draws one large form on every
// page reads every page, where a copy charged for the life of the document
// would exhaust what the document may hold part way through.
func TestBoundsDecryptedPageCopiesAreReleasedWithThePage(t *testing.T) {
	const pages = 500
	b := &pdfgen.Builder{Encrypt: &pdfgen.Encryption{Revision: 4, Owner: "owner", Permissions: -1}}
	var form strings.Builder
	for i := 0; i < 12000; i++ {
		fmt.Fprintf(&form, "%d %d 3 3 re f\n", i%600, (i*7)%780)
	}
	formNum := b.Add(pdfgen.Object{Body: "<< /Type /XObject /Subtype /Form /BBox [0 0 612 792] >>", Stream: []byte(form.String()), Raw: true})
	list := make([]pdfgen.Page, pages)
	for i := range list {
		list[i] = pdfgen.Page{Content: "/X Do\n", XObjects: map[string]int{"X": formNum}}
	}
	b.Catalog(b.Pages(list))
	data := b.Bytes()
	// Five hundred pages of vector drawing take their time under the race
	// detector, and what this measures is the charge and not the clock.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	r := Extract(ctx, data, testOptions())
	failed := 0
	for _, p := range r.Pages {
		if p.Status == PageFailed {
			failed++
		}
	}
	t.Logf("%d encrypted pages each drawing a %d-byte form (%d bytes): %d pages, %d failed, problems %d", pages, form.Len(), len(data), len(r.Pages), failed, len(r.Problems))
	if r.Fatal != nil || len(r.Pages) != pages || failed != 0 {
		t.Fatalf("fatal %+v pages %d failed %d problems %+v", r.Fatal, len(r.Pages), failed, r.Problems[:min(len(r.Problems), 3)])
	}
}

// An object stream's header is read within the document's allowance: a file
// of many object streams whose header regions run into a shared tail is read
// a bounded number of times and meets the bound, rather than being read once
// for every stream that names those bytes.
func TestBoundsObjectStreamHeadersAreReadWithinTheAllowance(t *testing.T) {
	const streams, tailBytes = 256, 1 << 20
	var out bytes.Buffer
	out.WriteString("%PDF-1.7\n")
	out.WriteString("1 0 obj<< /Type /Catalog >>endobj\n")
	at := out.Len()
	// Every stream's data begins at its own header and runs a mebibyte, so
	// they all share one tail; each header region begins with a literal that
	// never ends, and reading one to its end is reading the tail.
	for i := 0; i < streams; i++ {
		fmt.Fprintf(&out, "%d 0 obj<< /Type /ObjStm /N 4 /First %d /Length %d >>stream\n(", i+2, tailBytes, tailBytes)
	}
	out.Write(bytes.Repeat([]byte("x"), tailBytes))
	fmt.Fprintf(&out, "trailer<< /Root 1 0 R /Size %d >>\nstartxref\n%d\n%%%%EOF\n", streams+2, at)
	data := out.Bytes()
	started := time.Now()
	d, err := open(context.Background(), data, &inflateBudget{total: 64 << 20, one: 16 << 20})
	bound := errors.Is(err, errStructureBound)
	loaded := 0
	if d != nil {
		for num := 2; num < streams+2; num++ {
			if s, ok := d.resolve(ref{num, 0}).(*stream); ok {
				if _, err := d.loadObjStm(num, s); err == nil {
					loaded++
				}
			}
		}
		bound = bound || d.bound != nil || d.parsedSpent()
	}
	took := time.Since(started)
	t.Logf("%d object streams over a shared %d-byte tail (%d bytes): %v, %d loaded, bound %v (%v)", streams, tailBytes, len(data), took, loaded, bound, err)
	// Reading that tail once for every stream is a quarter of a gigabyte at
	// no charge; the allowance is what ends it.
	if !bound {
		t.Errorf("%d headers over a shared tail met no bound", streams)
	}
	// Reading that tail for every stream is a quarter of a gigabyte, which
	// takes minutes under the race detector; the bound above is what this
	// establishes, and the time is a guard against a reader that does not
	// meet it at all.
	if took > 20*time.Second {
		t.Errorf("reading them took %v", took)
	}
}

// A header token the window cuts in two settles nothing: an object whose
// number, generation or "obj" ends exactly at the window's edge stays a
// candidate, and the document it belongs to is read.
func TestBoundsAHeaderCutByTheWindowIsInconclusive(t *testing.T) {
	pages := "<< /Type /Pages /Kids [3 0 R] /Count 1 >>"
	catalog := "<< /Type /Catalog >>"
	// "2 0" then the spaces then "obj": the window's edge falls inside that
	// keyword, on either side of it, and a byte either way.
	for _, gap := range []int{headWindow - len("2 0") - 4, headWindow - len("2 0") - 3, headWindow - len("2 0") - 2, headWindow - len("2 0") - 1, headWindow - len("2 0")} {
		t.Run(fmt.Sprintf("a header cut after %d spaces", gap), func(t *testing.T) {
			// The spaces lie between the generation and "obj", so the window
			// ends inside "obj" or just after it.
			space := strings.Repeat(" ", gap)
			objects := []string{
				"1 0 obj" + catalog + "endobj\n",
				"2 0" + space + "obj" + pages + "endobj\n",
				"3 0 obj<< /Type /Page /Parent 2 0 R /Contents 4 0 R /Resources << /Font << /F1 5 0 R >> >> >>endobj\n",
				"4 0 obj<< /Length 44 >>stream\nBT /F1 12 Tf 10 700 Td (Hello world) Tj ET\nendstream\nendobj\n",
				"5 0 obj<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>endobj\n",
			}
			data := bytes.Replace(boundsTabledWith(objects, nil, "1 0 R"), []byte("/Root 1 0 R"), []byte("/Rxxt 1 0 R"), 1)
			r := extract(t, data)
			if r.Fatal != nil || len(r.Pages) != 1 || r.Pages[0].Text != "Hello world" {
				t.Fatalf("fatal %+v pages %+v", r.Fatal, r.Pages)
			}
		})
	}
}

// Work done on streams while the document is opened or rebuilt is charged
// too: a file whose object streams share a list of tens of thousands of
// filters is refused at a bound rather than applying them for every stream.
func TestBoundsFilterWorkAtOpeningIsCharged(t *testing.T) {
	b := &pdfgen.Builder{}
	filters := b.Add(pdfgen.Object{Body: "[" + strings.Repeat("/LZWDecode ", 16384) + "]"})
	for i := 0; i < 64; i++ {
		b.Add(pdfgen.Object{Body: fmt.Sprintf("<< /Type /ObjStm /N 0 /First 0 /Filter %d 0 R >>", filters), Stream: []byte{}, Raw: true})
	}
	helv := b.Font("Helvetica", "WinAnsiEncoding", "")
	b.Catalog(b.Pages([]pdfgen.Page{{Content: pdfgen.Text("F1", 12, []string{"open"}), Fonts: map[string]int{"F1": helv}}}))
	// The offsets are damaged, so the document is rebuilt by scanning and the
	// object streams are loaded on the way.
	b.BrokenOffsets = 7
	data := b.Bytes()
	started := time.Now()
	r := extract(t, data)
	took := time.Since(started)
	t.Logf("64 object streams over a list of 16,384 filters (%d bytes): %v, fatal %+v pages %+v", len(data), took, r.Fatal, r.Pages)
	// The bound is what ends it: applying those lists for every stream is a
	// million applications and fifteen seconds without one.
	if r.Fatal == nil || r.Fatal.Code != "pdf-malformed" {
		t.Errorf("a document whose object streams share a list of 16,384 filters: fatal %+v", r.Fatal)
	}
	if took > 10*time.Second {
		t.Errorf("opening it took %v", took)
	}
}

// Every entry of a filter list is charged as it is read, before it is known
// to name a filter at all: a page whose streams share a list of tens of
// thousands of entries rejected at the last one fails at the bound.
func TestBoundsFilterListEntriesAreCharged(t *testing.T) {
	b := &pdfgen.Builder{}
	names := "[" + strings.Repeat("/Crypt ", 65536) + " null]"
	filters := b.Add(pdfgen.Object{Body: names})
	fonts := map[string]int{}
	var content strings.Builder
	for i := 0; i < 512; i++ {
		tu := b.Add(pdfgen.Object{Body: fmt.Sprintf("<< /Filter %d 0 R >>", filters), Stream: []byte{}, Raw: true})
		f := b.Add(pdfgen.Object{Body: fmt.Sprintf("<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /ToUnicode %d 0 R >>", tu)})
		name := fmt.Sprintf("F%d", i)
		fonts[name] = f
		fmt.Fprintf(&content, "BT /%s 12 Tf 1 0 0 1 72 700 Tm (a) Tj ET\n", name)
	}
	b.Catalog(b.Pages([]pdfgen.Page{{Content: content.String(), Fonts: fonts}}))
	data := b.Bytes()
	started := time.Now()
	r := extract(t, data)
	took := time.Since(started)
	t.Logf("512 fonts over a list of 65,536 entries (%d bytes): %v, pages %+v problems %+v", len(data), took, r.Pages, r.Problems)
	if r.Fatal != nil || len(r.Pages) != 1 {
		t.Fatalf("fatal %+v pages %+v", r.Fatal, r.Pages)
	}
	// The page reads: a font whose own stream meets a bound is no error of
	// the page (step 5 of the note), and what the bound stops is the reading
	// of those lists over and over. Reading them all takes seconds; charging
	// them as they are read stops within the page's allowance.
	if took > 10*time.Second {
		t.Errorf("the page took %v; its filter lists are read within what one page may cost", took)
	}
	// What the charge is, read directly: an entry costs one step as it is
	// read, the rejected last one included, and is not charged again when it
	// is applied. Three readings of the list charge exactly three times its
	// entries; the fourth meets the page's allowance before it reaches the
	// entry that rejects the list.
	d, err := open(context.Background(), data, &inflateBudget{total: 64 << 20, one: 16 << 20})
	if err != nil {
		t.Fatal(err)
	}
	d.startPageWork()
	// A list every entry of which is applied costs one step an entry and
	// nothing more: a thousand ASCIIHex filters over no bytes are a thousand
	// steps, applied or not.
	applied := make(Array, 1000)
	for i := range applied {
		applied[i] = Name("ASCIIHexDecode")
	}
	if _, err := d.decodeStream(&stream{dict: Dict{"Filter": applied}, raw: []byte{}}, false); err != nil {
		t.Fatalf("a list of a thousand filters over no bytes: %v", err)
	}
	if d.pageWork != int64(len(applied))*filterStepBytes {
		t.Errorf("a thousand filters applied charge %d, want %d: one step an entry, not one read and one applied", d.pageWork, int64(len(applied))*filterStepBytes)
	}
	d.startPageWork()
	s, ok := d.resolve(d.dictOf(ref{fonts["F0"], 0})["ToUnicode"]).(*stream)
	if !ok {
		t.Fatal("the font's ToUnicode is not a stream")
	}
	const entries = 65536 + 1
	for i := int64(1); i <= 3; i++ {
		if _, err := d.decodeStream(s, false); err == nil || isBound(err) {
			t.Fatalf("reading %d of the list: err %v, want the list rejected at its last entry", i, err)
		}
		if d.pageWork != i*entries*filterStepBytes {
			t.Errorf("after reading %d of the list the page's work is %d, want %d (one step an entry)", i, d.pageWork, i*entries*filterStepBytes)
		}
	}
	if _, err := d.decodeStream(s, false); !isBound(err) {
		t.Errorf("a fourth reading of the list: err %v, want the page's work allowance met", err)
	}
}

// What a lexer advanced over is charged apart from what its tokens hold:
// bytes read and memory taken are two costs, and a reader that charged only
// the second would read a file over and over for values it never keeps.
func TestBoundsWorkIsChargedApartFromMemory(t *testing.T) {
	for _, c := range []struct {
		name, source string
	}{
		// A token past the bound on its kind: read to that bound, held not
		// at all.
		{"an overlong hex string", "<" + strings.Repeat("41", maxStringBytes+64) + ">"},
		// Whitespace at the end of the data: read, and nothing to hold.
		{"whitespace with nothing after it", strings.Repeat(" ", 64<<10)},
		// A comment to the end of the data: the same.
		{"a comment with no line end", "%" + strings.Repeat("c", 64<<10)},
	} {
		t.Run(c.name, func(t *testing.T) {
			d := &Document{data: make([]byte, 64<<20), budget: &inflateBudget{}}
			lex := newLexer([]byte(c.source), 0).within(d.budgeted())
			before := d.parsedBytes
			lex.next()
			charged := d.parsedBytes - before
			t.Logf("%s of %d bytes: read to %d, charged %d", c.name, len(c.source), lex.charged, charged)
			// The work charge is the bytes advanced over, whatever the token
			// held: the reservation cannot stand in for it.
			if int64(lex.charged) > charged {
				t.Errorf("%s: read %d bytes and charged %d", c.name, lex.charged, charged)
			}
			if lex.charged < len(c.source)/2 {
				t.Errorf("%s: the lexer stopped at %d of %d bytes", c.name, lex.charged, len(c.source))
			}
		})
	}
}

// An object stream's header entries are charged as they are read, each of
// them: a header of many entries costs what holding them costs, and one
// whose entries would take the document past what it may hold is refused
// rather than held in part.
func TestBoundsObjectStreamHeaderEntriesAreCharged(t *testing.T) {
	const entries = 4096
	var header strings.Builder
	for i := 0; i < entries; i++ {
		fmt.Fprintf(&header, "%d %d ", 100+i, i*8)
	}
	payload := header.String() + strings.Repeat("x", entries*8)
	s := &stream{dict: Dict{"Type": Name("ObjStm"), "N": int64(entries), "First": int64(header.Len())}, raw: []byte(payload)}
	// Room enough: every entry is charged, and the header is read whole.
	d := &Document{data: make([]byte, 16<<20), budget: &inflateBudget{total: 64 << 20, one: 16 << 20}, objStms: map[int]*objStm{}, cache: map[int]object{}}
	before := d.parsedBytes
	st, err := d.loadObjStm(1, s)
	if err != nil || st == nil || len(st.order) != entries {
		t.Fatalf("loaded %v (%v)", st, err)
	}
	charged := d.parsedBytes - before
	t.Logf("a header of %d entries: %d charged", entries, charged)
	if want := int64(entries) * (parsedMemberBytes + parsedSlotBytes); charged < want {
		t.Errorf("a header of %d entries charged %d, where its entries alone cost %d", entries, charged, want)
	}
	// One byte less than those entries cost: the header is refused.
	tight := &Document{data: make([]byte, 16<<20), budget: &inflateBudget{total: 64 << 20, one: 16 << 20}, objStms: map[int]*objStm{}, cache: map[int]object{}}
	tight.parsedBytes = tight.parsedBudget() - charged/2
	if st, err := tight.loadObjStm(1, s); err == nil {
		t.Errorf("a header of %d entries was read with half of what it costs: %d entries", entries, len(st.order))
	}
}
