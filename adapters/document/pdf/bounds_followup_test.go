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
// tree's and the catalog's own dictionaries written as given.
func boundsLostCatalog(t *testing.T, tree, catalog string) []byte {
	t.Helper()
	objects := []string{
		"1 0 obj" + catalog + "endobj\n",
		"2 0 obj" + tree + "endobj\n",
		"3 0 obj<< /Type /Page /Parent 2 0 R /Contents 4 0 R /Resources << /Font << /F1 5 0 R >> >> >>endobj\n",
		"4 0 obj<< /Length 44 >>stream\nBT /F1 12 Tf 10 700 Td (Hello world) Tj ET\nendstream\nendobj\n",
		"5 0 obj<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>endobj\n",
	}
	return boundsTabledWith(objects, nil, "1 0 R")
}

// The page tree and the catalog are looked for by reading the head of each
// object, not by searching its first bytes for a word: a name is read with
// its escapes resolved, a dictionary is read member by member, and an object
// the head cannot settle is parsed rather than passed over.
func TestBoundsPageTreeAndCatalogAreFoundByReadingTheirHeads(t *testing.T) {
	filler := strings.Repeat("/Pad"+strings.Repeat("x", 60)+" 1 ", 6)
	for _, c := range []struct {
		name, tree, catalog string
	}{
		{"an escape in the page tree's type", "<< /Type /Pa#67es /Kids [3 0 R] /Count 1 >>", "<< /Type /Catalog >>"},
		{"a page tree whose type comes late", "<< " + filler + " /Kids [3 0 R] /Count 1 /Type /Pages >>", "<< /Type /Catalog >>"},
		{"an escape in the catalog's type", "<< /Type /Pages /Kids [3 0 R] /Count 1 >>", "<< /Type /Cat#61log >>"},
		{"a catalog whose type comes late", "<< /Type /Pages /Kids [3 0 R] /Count 1 >>", "<< " + filler + " /Type /Catalog >>"},
	} {
		t.Run(c.name, func(t *testing.T) {
			data := boundsLostCatalog(t, c.tree, c.catalog)
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
		"the work one page may cost: the bytes its content streams and the forms it draws hold, and each filter applied": mib(maxPageWorkBytes) + "; " + grouped(filterStepBytes) + " bytes a filter",
		"bytes the operands of a page hold at one time, the forms it draws included":                                     mib(maxOperandBytes),
		"the entries one `bfrange` or `cidrange` is charged":                                                             grouped(cmapRangeEntries) + "; one more for each " + grouped(cmapRunsPerEntry) + " characters of its destination",
		"bytes read and held for each byte of the file and of each byte its streams inflate to":                          grouped(parsedBytesPerFileByte),
		"bytes of parsed objects held in all":                                                                            mib(maxParsedBytesHeld),
		"the bytes of an object read to decide whether it is the page tree or the catalog":                               grouped(headWindow) + " bytes",
	} {
		if row := readmeRow(t, readme, label); row[1] != value {
			t.Errorf("%s: adapters/README.md says %q, the reader holds %q", label, row[1], value)
		}
	}
}

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
