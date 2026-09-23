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
// allocated on the way. The values are held in an array and charged as the
// reader charges one, its slots included, so that what is measured against
// the charge is the whole of what is held: f must grow that array by
// appending, as the parser does, since a slice made at a capacity keeps the
// block the allocator rounded that capacity up to while one grown by
// appending carries the rounding in the capacity itself.
func boundsRetained(f func() Array) (retained uint64, charged int64) {
	held := f()
	with := boundsLiveHeap()
	charged = parsedBytesOf(held)
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
		retained, charged := boundsRetained(func() Array {
			var held Array
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

// An array is charged the room it grows to and not the elements put in it.
// Go's append leaves room past the length, by a policy of its own: thirty-three
// elements are held in a backing array of seventy-one slots, a hundred and
// forty-four in three hundred and three, and an array charged a slot for each
// element would be charged less than it holds. These are the lengths either
// side of each growth, where the room the array has just taken is furthest
// from the elements in it, and both reckonings are measured at each: what a
// parse spends as it builds the array, and what parsedBytesOf makes of the
// array it built, which must agree and must cover what Go retains.
//
// The three kinds of element are the ones whose elements leave the array's own
// charge to do the covering, by decreasing margin. An integer is charged
// sixteen bytes and holds eight, so those rows have room to spare; an array of
// no elements is charged sixty-four and holds twenty-four, since the charge on
// an array covers the allocator's rounding on a backing array it may not have;
// and a reference is charged sixteen and holds sixteen, so a reference row is
// covered by the array's own charge and by nothing else -- some two or three
// dozen bytes for the whole array, whatever its length.
//
// What a parse spends is the same as what the built array reckons for these
// three kinds and for arrays of them, and that is claimed of them and not
// generally. It holds because none of their tokens carries a buffer: the array
// loop reads the token after each element to see whether the array has closed
// and steps back over it, so every element's first token is read twice, and a
// token with a buffer -- a string or a name -- has that buffer reserved on
// both readings. Thirty-three one-byte strings are charged eight bytes twice
// each for it, so the parse spends 2,784 where the array it built reckons
// 2,256. That way round is the safe one, and it is the one that counts: the
// parse is what spends the balance, and a page gives back what its operands
// spent rather than what a value reckons, so its count of what it holds is
// right either way.
func TestBoundsAnArrayIsChargedTheRoomItGrowsTo(t *testing.T) {
	if boundsInstrumented {
		t.Skip("the race detector's own allocations are not the reader's, and what it retains is not what this measures")
	}
	for _, element := range []struct {
		name, source string
		// content is set where the elements are read as a content stream's
		// operands are. A reference is not one: in content mode "R" is an
		// operator, so a reference is read the way a document's own objects
		// are read.
		content bool
	}{
		{"integers", "1000000000000 ", true},
		{"arrays of no elements", "[] ", true},
		{"references", "1 0 R ", false},
	} {
		for _, n := range []int{32, 33, 71, 72, 143, 144, 303, 304, 591, 592, 1023, 1024, 1535, 1536, 2560, 2561} {
			t.Run(fmt.Sprintf("%s/%d", strings.ReplaceAll(element.name, " ", "_"), n), func(t *testing.T) {
				const count = 1000
				source := []byte("[" + strings.Repeat(element.source, n) + "]")
				// A document large enough that the allowance is not what stops
				// this: what is measured is what a parse spends.
				d := &Document{data: make([]byte, 64<<20), budget: &inflateBudget{}}
				var spent, modeled int64
				var capacity int
				retained, charged := boundsRetained(func() Array {
					before := d.parsedBytes
					var held Array
					for i := 0; i < count; i++ {
						p := &parser{lex: newLexer(source, 0).reserving(d.budgeted()), allow: d.budgeted(), contentMode: element.content}
						v, err := p.parseObject(0)
						if err != nil {
							t.Fatalf("copy %d of %d: %v", i+1, count, err)
						}
						held = append(held, v)
					}
					spent = d.parsedBytes - before
					for _, v := range held {
						modeled += parsedBytesOf(v)
					}
					capacity = cap(held[0].(Array))
					return held
				})
				runtime.KeepAlive(source)
				t.Logf("%d %s in %d slots: %d retained, %d charged as it was built, %d reckoned from it, each", n, element.name, capacity, int(retained)/count, int(spent)/count, int(modeled)/count)
				if spent != modeled {
					t.Errorf("%d %s: the parse spent %d and the array it built reckons %d; the two must agree", n, element.name, spent/count, modeled/count)
				}
				if int64(retained) > charged {
					t.Errorf("%d %s in %d slots: %d bytes retained for each, %d charged; the charge must cover what is held", n, element.name, capacity, int(retained)/count, int(charged)/count)
				}
			})
		}
	}
}

// boundsREADMESays requires that adapters/README.md's prose holds the
// sentence given, whatever line ends its wrapping put in the middle of it: the
// tables are checked cell by cell elsewhere, and this is what holds a figure
// written into a paragraph to the measurement it came from.
func boundsREADMESays(t *testing.T, want string) {
	t.Helper()
	raw, err := os.ReadFile("../../README.md")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(strings.Join(strings.Fields(string(raw)), " "), want) {
		t.Errorf("adapters/README.md does not say %q; the figures it states for these documents are the ones measured here", want)
	}
}

// roundedMB writes bytes as adapters/README.md's prose does, in millions of
// bytes rounded to the nearest.
func roundedMB(n int64) int64 { return (n + 500_000) / 1_000_000 }

// spelledOut writes n, below ten thousand, the way adapters/README.md's prose
// writes a count: "three thousand seven hundred and ninety".
func spelledOut(n int) string {
	small := []string{"zero", "one", "two", "three", "four", "five", "six", "seven", "eight", "nine", "ten",
		"eleven", "twelve", "thirteen", "fourteen", "fifteen", "sixteen", "seventeen", "eighteen", "nineteen"}
	tens := []string{"", "", "twenty", "thirty", "forty", "fifty", "sixty", "seventy", "eighty", "ninety"}
	below100 := func(n int) string {
		if n < 20 {
			return small[n]
		}
		if n%10 == 0 {
			return tens[n/10]
		}
		return tens[n/10] + "-" + small[n%10]
	}
	if n <= 0 || n >= 10000 {
		return fmt.Sprint(n)
	}
	var parts []string
	if n >= 1000 {
		parts = append(parts, below100(n/1000)+" thousand")
		n %= 1000
	}
	if n >= 100 {
		parts = append(parts, small[n/100]+" hundred")
		n %= 100
	}
	if n > 0 {
		if len(parts) > 0 {
			parts = append(parts, "and")
		}
		parts = append(parts, below100(n))
	}
	return strings.Join(parts, " ")
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
				w := &walker{d: d, ctx: context.Background(), path: map[ref]bool{}, generation: d.generation, limit: 100}
				root, rootRef := d.pagesRoot()
				if rootRef != (ref{}) {
					w.path[rootRef] = true
				}
				w.node(root, inherited{}, 0)
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

// An operand is bounded while it is built and not once it exists: one array
// is one operand, and a reader that checked it after parsing would have
// allocated all of it first. The page fails at the bound and the heap stays
// near what the bound allows, and the text the page shows before the operand
// is not what the page reads: a reader that built the operand whole would
// read it.
//
// The two shapes are stopped by two different things, and each is here for
// its own. An array of empty dictionaries carries no token for the lexer to
// reserve room for and spells each member in four bytes, so nothing but the
// parser's own allowance, spent member by member, can stop it. An array of
// names is stopped before that allowance is reached at all, by the room the
// lexer reserves for the buffer of every name it reads.
func TestBoundsOperandsAreBoundedWhileTheyAreBuilt(t *testing.T) {
	for _, c := range []struct {
		name    string
		of      string
		content string
	}{
		{
			"the parser's own allowance",
			"200,000 empty dictionaries",
			// Two hundred thousand empty dictionaries: a Go map's smallest
			// form costs more than three hundred bytes to hold, and the
			// element holding it more again, so they are past the page's
			// operand allowance several times over.
			"[" + strings.Repeat("<<>>", 200_000) + "]",
		},
		{
			"the lexer's reservations",
			"4,000,000 names",
			string(boundsNamePile(40, 100_000)),
		},
	} {
		t.Run(c.name, func(t *testing.T) {
			b := &pdfgen.Builder{}
			helv := b.Font("Helvetica", "WinAnsiEncoding", "")
			// The page's text stands before the operand, so a reader that
			// built the operand and only then looked at what it cost reads
			// the page rather than failing it.
			content := pdfgen.Text("F1", 12, []string{"ordinary"}) + c.content
			b.Catalog(b.Pages([]pdfgen.Page{{Content: content, Fonts: map[string]int{"F1": helv}}}))
			data := b.Bytes()
			var r *Result
			peak := boundsPeakHeap(func() { r = extract(t, data) })
			t.Logf("one operand of %s in a %d-byte file: peak heap %d MiB, pages %+v problems %+v", c.of, len(data), peak>>20, r.Pages, r.Problems)
			if r.Fatal != nil || len(r.Pages) != 1 {
				t.Fatalf("fatal %+v pages %+v", r.Fatal, r.Pages)
			}
			if r.Pages[0].Status != PageFailed || r.Pages[0].Text != "" {
				t.Fatalf("an operand of %s past the bound left the page %q (%v)", c.of, r.Pages[0].Text, r.Pages[0].Status)
			}
			if len(r.Problems) != 1 || r.Problems[0].Code != "pdf-page-failed" || r.Problems[0].Page != 1 {
				t.Errorf("problems %+v", r.Problems)
			}
			if peak > 160<<20 {
				t.Errorf("building one operand past the bound peaked at %d MiB; the bound is %d MiB", peak>>20, maxOperandBytes>>20)
			}
		})
	}
}

// The slots of consumed operands are cleared with their charge: a stream
// that pushes a pile, has an operator consume it, and pushes another pile
// holds only the second, since the first is no longer reachable from the
// backing array the interpreter reuses.
func TestBoundsConsumedOperandsAreReleased(t *testing.T) {
	// Sixty arrays of short strings, consumed by an operator, then one array
	// of as many: each pile is within the page's operand allowance on its own
	// -- the growth that builds it included, which holds the array it is
	// copying from beside the one it is copying into -- so the page reads, and
	// the two are the same size, so a reader that keeps the first while it
	// builds the second holds twice what it charges. The page's text is shown
	// before either pile, so what the page reads does not depend on them.
	const perPile, arrays = 700_000, 60
	var content strings.Builder
	content.WriteString(pdfgen.Text("F1", 12, []string{"released"}))
	for i := 0; i < arrays; i++ {
		content.WriteString("[" + strings.Repeat("(aaaa)", perPile/arrays) + "]")
	}
	content.WriteString(" n\n")
	content.WriteString("[" + strings.Repeat("(aaaa)", perPile) + "]\n")
	b := &pdfgen.Builder{}
	helv := b.Font("Helvetica", "WinAnsiEncoding", "")
	b.Catalog(b.Pages([]pdfgen.Page{{Content: content.String(), Fonts: map[string]int{"F1": helv}}}))
	data := b.Bytes()
	var r *Result
	peak := boundsPeakLiveHeap(func() { r = extract(t, data) })
	t.Logf("two piles of %d strings, the first consumed by an operator: most held at once %d MiB, pages %+v problems %+v", perPile, peak>>20, r.Pages, r.Problems)
	// The page is read: the operator that consumes the first pile is reached,
	// and the text before them is what the page says.
	if r.Fatal != nil || len(r.Pages) != 1 || len(r.Problems) != 0 || r.Pages[0].Status != PageOK || r.Pages[0].Text != "released" {
		t.Fatalf("fatal %+v pages %+v problems %+v", r.Fatal, r.Pages, r.Problems)
	}
	// One pile of this size is held at about 56 MiB and the two together at
	// about 97 MiB: the threshold lies between them, so a reader that left
	// the consumed slots pointing at the first pile fails here.
	if peak > 84<<20 {
		t.Errorf("the page held %d MiB at once; one pile of that size is about 56 MiB, and the pile an operator consumed is not held beside the second", peak>>20)
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
	if took > raceFactor*3*time.Second {
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
	if took > raceFactor*3*time.Second {
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
	// Ranges the CMap keeps none of never reach the charge, where the entries
	// above read the deadline: the loop over a section of ranges reads it
	// itself, so a section of a hundred thousand ranges whose high code is
	// below their low one is a section that read the deadline as it read them.
	for _, kind := range []string{"bfrange", "cidrange"} {
		src := boundsCMapRejectedRanges(kind, 100_000)
		calls := 0
		if parseCMap(src, &fontBudget{}, func() bool { calls++; return false }) == nil {
			t.Errorf("%s: a CMap of rejected ranges read within the deadline was not used", kind)
		}
		if calls < 100_000 {
			t.Errorf("%s: the deadline was offered %d times while a hundred thousand rejected ranges were examined", kind, calls)
		}
		if c := parseCMap(src, &fontBudget{}, func() bool { return true }); c != nil {
			t.Errorf("%s: a CMap of rejected ranges read past the deadline holds %d mappings; it is not used", kind, c.entries)
		}
	}
}

// boundsCMapRejectedRanges is a CMap of one mapped code and count ranges of
// the kind named whose high code is below their low one: each is read, and
// none of them is ever charged, so nothing but the loop over them reads the
// deadline on their account.
func boundsCMapRejectedRanges(kind string, count int) []byte {
	var src strings.Builder
	src.WriteString("begincmap\n1 begincodespacerange <0000> <FFFF> endcodespacerange\n")
	src.WriteString("1 beginbfchar\n<0041><0041>\nendbfchar\n")
	fmt.Fprintf(&src, "%d begin%s\n", count, kind)
	for i := 0; i < count; i++ {
		fmt.Fprintf(&src, "<%04X><%04X> 1\n", 0x1001+i%0x1000, 0x1000+i%0x1000)
	}
	fmt.Fprintf(&src, "end%s\nendcmap\n", kind)
	return []byte(src.String())
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
	pr := d.interpretPage(context.Background(), content, resources, 1<<20)
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
			bound := errors.Is(err, errStructureBound) || (d != nil && (d.bound != nil || d.fileBound != nil))
			if bound != c.bound {
				t.Errorf("rebuilding from %d bytes ended with %v (bound noted %v)", len(c.data), err, bound)
			}
			// Reading the file a few times over takes milliseconds; reading it
			// once for each candidate takes tens of seconds, which is what
			// this catches; the room a machine reading it under the race
			// detector needs is the factor the allowance is scaled by.
			if took > raceFactor*8*time.Second {
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
	if root, _ := d.pagesRoot(); root == nil {
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
		if root, _ := d.pagesRoot(); root != nil {
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
		"the work one page may cost: the bytes its content streams and the forms it draws hold, the decrypted copies made for it, and each entry of a filter list read": mib(maxPageWorkBytes) + "; " + grouped(filterStepBytes) + " bytes an entry",
		"bytes the operands of a page hold at one time, the forms it draws included":                                                                                    mib(maxOperandBytes),
		"the entries one `bfrange` or `cidrange` is charged":                                                                                                            grouped(cmapRangeEntries) + "; one more for each " + grouped(cmapRunsPerEntry) + " characters of its destination",
		"bytes read and held for each byte of the file and of each byte its streams inflate to":                                                                         grouped(parsedBytesPerFileByte),
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
	if last.took > raceFactor*5*time.Second {
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
			// What the comment swallows is read past, and the document is the
			// document it is: the outcome, not the clock, is what this says.
			data := bytes.Replace(sound, []byte(c.at), append([]byte(c.at), '%'), 1)
			r := extract(t, data)
			t.Logf("%d bytes: fatal %+v pages %+v", len(data), r.Fatal, r.Pages)
			if r.Fatal != nil || len(r.Pages) != 1 || r.Pages[0].Text != "Hello world" {
				t.Fatalf("fatal %+v pages %+v problems %+v", r.Fatal, r.Pages, r.Problems)
			}
		})
	}
	// And reading past one is charged. Where the word a comment follows is one
	// a rebuild looks for, a file of them reads the rest of itself once for
	// each: a trailer candidate whose dictionary begins with a comment that
	// has no line end swallows every candidate after it, so a file of a
	// hundred and twenty-eight kilobytes is read gigabytes over, and the
	// allowance is what ends it. A reader that charged nothing for the bytes
	// its lexers advance over reads them all for nothing and meets no bound.
	const size = 128 << 10
	piled := boundsTrailerCandidates(size, "<< /A %")
	d, err := open(context.Background(), piled, &inflateBudget{total: 64 << 20, one: 16 << 20})
	spent := errors.Is(err, errStructureBound)
	charged := int64(0)
	if d != nil {
		spent = spent || d.bound != nil || d.parsedSpent()
		charged = d.parsedBytes
	}
	t.Logf("%d bytes of trailer candidates whose dictionaries begin with a comment with no line end: charged %d, bound %v (%v)", len(piled), charged, spent, err)
	if !spent {
		t.Errorf("candidates that each read the rest of the file charged %d and met no bound", charged)
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
	// way to the bound before refusing. The hex digits are not decimal ones:
	// what a decimal run of tens of megabytes costs is the scan for object
	// heads reading it as one number, which is a different bound's business
	// and seconds of this test's time.
	if hex {
		out.Write(bytes.Repeat([]byte("AA"), maxStringBytes+64))
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

// boundsDistinctCandidates is a file whose cross-reference stream names as
// many objects as there are candidates, each an object of its own: its own
// header, its own offset and a dictionary of the members given. Nothing here
// is aliased, so no entry sends the reader to another object's header, the
// cross-reference is never rebuilt, and what the candidates cost is what
// reading each of them once costs. Its offsets are written four bytes wide,
// since a file of this many objects is past the three the aliased file needs.
func boundsDistinctCandidates(candidates, members int) []byte {
	var out bytes.Buffer
	out.WriteString("%PDF-1.7\n")
	catalog := out.Len()
	out.WriteString("1 0 obj<< /Type /Catalog >>endobj\n")
	pages := out.Len()
	out.WriteString("2 0 obj<< /Type /Nothing >>endobj\n")
	body := "<< /Type /Other " + strings.Repeat("/A <</B 1>> ", members) + ">>"
	offsets := make([]int, 0, candidates)
	for i := 0; i < candidates; i++ {
		offsets = append(offsets, out.Len())
		fmt.Fprintf(&out, "%d 0 obj%sendobj\n", 3+i, body)
	}
	at := out.Len()
	var entries []byte
	put := func(typ byte, f2, f3 int) {
		entries = append(entries, typ, byte(f2>>24), byte(f2>>16), byte(f2>>8), byte(f2), byte(f3))
	}
	put(0, 0, 255)
	put(1, catalog, 0)
	put(1, pages, 0)
	for _, off := range offsets {
		put(1, off, 0)
	}
	fmt.Fprintf(&out, "%d 0 obj<< /Type /XRef /Size %d /W [1 4 1] /Root 1 0 R /Length %d >>stream\n", 3+candidates, 4+candidates, len(entries))
	out.Write(entries)
	out.WriteString("\nendstream endobj\n")
	fmt.Fprintf(&out, "startxref\n%d\n%%%%EOF\n", at)
	return out.Bytes()
}

// Reading an object's head is charged, and what it settled is kept by the
// offset it was read at: a cross-reference that gives thousands of object
// numbers one offset costs one reading of that head, and not one for every
// number that names it. Where the window cannot settle what the object is,
// those numbers cost nothing further either -- but for a reason of the
// cross-reference and not of the search. Reading one of them finds the header
// of another object, which is a damaged cross-reference, and the rebuilt one
// is the scan's alone: the aliases go with the cross-reference that invented
// them, so the whole reads they would have cost are never done and the
// allowance is not what ends the search. What that search costs where the
// candidates are objects the file really holds is below.
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
				// Opening reads the cross-reference and nothing it names, so
				// whatever the search below meets, it meets there.
				if d.reconstructed {
					t.Fatal("the document was rebuilt before the search began")
				}
				started := time.Now()
				// The page tree is looked for among the objects the
				// cross-reference names, which is where each entry's head is
				// inspected. It is asked for directly, so that what the search
				// costs is what this measures.
				root := d.findPagesRoot()
				took := time.Since(started)
				t.Logf("%d bytes, %d aliases of one offset: %v, %d charged of %d allowed (bound %v, rebuilt %v, %d entries)",
					len(data), aliases, took, d.parsedBytes, d.parsedBudget(), d.bound != nil || d.parsedSpent(), d.reconstructed, len(d.xref))
				if root != nil {
					t.Error("a file that holds no page tree yielded one")
				}
				if took > raceFactor*3*time.Second {
					t.Errorf("%d aliases of one offset took %v", aliases, took)
				}
				// The head at that offset is read, and charged: a search that
				// read it for nothing would charge nothing at all.
				if d.parsedBytes < int64(headWindow) {
					t.Errorf("%d aliases of one offset charged %d bytes; reading one head costs more than that", aliases, d.parsedBytes)
				}
				if c.settled {
					// The window settles what the object at that offset is, so
					// no alias is read as an object and nothing is rebuilt: the
					// head is read once for the offset, not once for every
					// number.
					if d.reconstructed {
						t.Error("a search that settled every candidate in the window rebuilt the cross-reference")
					}
					if d.parsedBytes > int64(headWindow)*64 {
						t.Errorf("%d aliases of one offset charged %d bytes; the head at that offset is read once", aliases, d.parsedBytes)
					}
					continue
				}
				// The window settles nothing, so the first alias is read as an
				// object -- and the object at that offset carries another
				// number's header. That is a damaged cross-reference, and the
				// rebuilt one holds the objects the scan found and no aliases
				// at all: objects 1, 2, 3 and the cross-reference stream.
				if !d.reconstructed {
					t.Error("an entry naming another object's header did not rebuild the cross-reference")
				}
				if len(d.xref) != 4 {
					t.Errorf("the rebuilt cross-reference holds %d entries, want the 4 objects the file's headers declare", len(d.xref))
				}
				if _, named := d.xref[2+aliases]; named {
					t.Errorf("the rebuilt cross-reference names object %d; the only cross-reference that declared it is the one the rebuild replaced", 2+aliases)
				}
				// The work the aliases would have cost is never done, so the
				// allowance is not what ends the search.
				if d.parsedSpent() {
					t.Errorf("%d aliases charged %d of %d and met the bound; the aliases went with the cross-reference that invented them", aliases, d.parsedBytes, d.parsedBudget())
				}
			}
		})
	}
}

// A candidate whose head the window cannot settle is a whole object to read,
// and the allowance the document holds its parsed objects under is what ends
// a search through thousands of them. The candidates below are objects the
// file really holds -- each its own header at its own offset, named by an
// entry of its own -- so nothing sends the reader to another object's header
// and no rebuild replaces them: what the search costs is what reading each of
// them costs, and it costs everything the document may hold.
func TestBoundsCandidatesTheWindowCannotSettleAreReadWhole(t *testing.T) {
	if testing.Short() {
		t.Skip("writes a file of fifteen megabytes")
	}
	// Twelve thousand of them. Reading one charges about 107,000 bytes -- a
	// hundred members, each a dictionary of its own, charged as the parser
	// builds them -- so the whole of them is about 1.29 GB against the
	// ceiling of maxParsedBytesHeld, which a file this long puts the
	// allowance at: 160 bytes for each of its own would be more still.
	const candidates = 12000
	data := boundsDistinctCandidates(candidates, 100)
	d, err := open(context.Background(), data, &inflateBudget{total: 64 << 20, one: 16 << 20})
	if d == nil {
		t.Fatalf("not opened: %v", err)
	}
	started := time.Now()
	root := d.findPagesRoot()
	took := time.Since(started)
	t.Logf("%d bytes, %d candidates of their own: %v, %d charged of %d allowed (rebuilt %v, %d entries)",
		len(data), candidates, took, d.parsedBytes, d.parsedBudget(), d.reconstructed, len(d.xref))
	if root != nil {
		t.Error("a file that holds no page tree yielded one")
	}
	if took > raceFactor*30*time.Second {
		t.Errorf("%d candidates of their own took %v", candidates, took)
	}
	// Every entry holds the object its number names, so nothing here is a
	// damaged cross-reference and the candidates are the file's own.
	if d.reconstructed || len(d.xref) != candidates+3 {
		t.Errorf("rebuilt %v with %d entries; every entry names the object whose header stands at its offset", d.reconstructed, len(d.xref))
	}
	// Nothing the window settles, so every candidate is a whole object to
	// read: the allowance is what ends that.
	if !d.parsedSpent() {
		t.Errorf("%d candidates the window cannot settle charged %d of %d without meeting the bound", candidates, d.parsedBytes, d.parsedBudget())
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

// A refusal is final. Once a charge has been refused, the balance it was
// refused by is closed: nothing charged after it is admitted, and nothing
// given back after it reopens it -- not a refund from the allowance that met
// the refusal, and not one from another allowance that was reading beside it
// and had every right to its own refund. A reader that gave room back after
// saying it had none would go on reading the file it has just refused.
func TestBoundsARefusalIsFinal(t *testing.T) {
	t.Run("a document's balance", func(t *testing.T) {
		d := &Document{data: make([]byte, 10), budget: &inflateBudget{}}
		limit := d.parsedBudget()
		first, second := d.budgeted(), d.budgeted()
		if !first.take(100) {
			t.Fatal("the first take of 100 did not fit")
		}
		if second.take(limit) {
			t.Fatal("a take of the whole budget fitted beside the first")
		}
		if d.parsedBytes != limit {
			t.Errorf("a refused charge left %d of %d spent; a refusal spends the balance", d.parsedBytes, limit)
		}
		first.give(100)
		if d.parsedBytes != limit {
			t.Errorf("a refund after the refusal left %d of %d spent; what was refused stays refused", d.parsedBytes, limit)
		}
		if third := d.budgeted(); third.take(16) {
			t.Errorf("16 bytes were charged after the balance was refused, leaving %d of %d", d.parsedBytes, limit)
		}
		if d.chargeParsed(16) {
			t.Errorf("the document charged 16 bytes after refusing, leaving %d of %d", d.parsedBytes, limit)
		}
	})
	t.Run("an allowance of its own", func(t *testing.T) {
		a := &allowance{left: 100}
		if !a.take(60) {
			t.Fatal("the take of 60 did not fit in 100")
		}
		if a.take(1000) {
			t.Fatal("a take of 1,000 fitted in what was left of 100")
		}
		a.give(60)
		if a.left != 0 {
			t.Errorf("a refund after the refusal left %d to spend; what was refused stays refused", a.left)
		}
		if a.take(1) {
			t.Errorf("one byte was taken after the refusal, leaving %d", a.left)
		}
	})
}

// A refund gives back what was taken and never more. An allowance that gives
// back more than it spent would hand the reader room no one charged for, and
// on a document, where every parse spends the one balance, it would hand back
// room another parse is still holding.
func TestBoundsARefundIsBoundedByWhatWasTaken(t *testing.T) {
	t.Run("more than was taken", func(t *testing.T) {
		a := &allowance{left: 100}
		if !a.take(60) {
			t.Fatal("the take of 60 did not fit in 100")
		}
		a.give(1000)
		if a.left != 100 || a.taken != 0 {
			t.Errorf("a refund of 1,000 against 60 spent left %d to spend and %d taken; a refund is bounded by what was taken", a.left, a.taken)
		}
	})
	t.Run("twice over", func(t *testing.T) {
		a := &allowance{left: 100}
		if !a.take(60) {
			t.Fatal("the take of 60 did not fit in 100")
		}
		a.give(60)
		a.give(60)
		if a.left != 100 || a.taken != 0 {
			t.Errorf("the same 60 given back twice left %d to spend and %d taken", a.left, a.taken)
		}
	})
	t.Run("nothing at all", func(t *testing.T) {
		a := &allowance{left: 100}
		if !a.take(60) {
			t.Fatal("the take of 60 did not fit in 100")
		}
		a.give(0)
		a.give(-1000)
		if a.left != 40 || a.taken != 60 {
			t.Errorf("a refund of nothing left %d to spend and %d taken; it must change neither", a.left, a.taken)
		}
	})
	t.Run("on a balance two allowances share", func(t *testing.T) {
		d := &Document{data: make([]byte, 1<<20), budget: &inflateBudget{}}
		first, second := d.budgeted(), d.budgeted()
		if !first.take(100) || !second.take(200) {
			t.Fatal("300 bytes did not fit in a megabyte's worth of allowance")
		}
		second.give(1000)
		if d.parsedBytes != 100 {
			t.Errorf("one allowance's refund of 1,000 against 200 spent left the document charged %d; the other allowance's 100 is still held", d.parsedBytes)
		}
	})
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
			// The reading of the file and the memory of the token are two
			// allowances here, where a document gives one allowance to both.
			// What the assertion is about is the reading: a token's buffer of
			// sixteen megabytes would otherwise stand in for the bytes
			// advanced over, and a path that charged its reading nowhere
			// would look paid for by the room the token reserved.
			const room, work = 1 << 26, 1 << 26
			held, read := &allowance{left: room}, &allowance{left: work}
			lex := newLexer([]byte(c.data), 0).reserving(held)
			lex.work = read
			c.read(lex)
			advanced, reserved := work-read.remaining(), room-held.remaining()
			t.Logf("%d bytes read: %d charged to the reading, %d to the room", lex.pos, advanced, reserved)
			if advanced < int64(lex.pos) {
				t.Errorf("%d bytes were read and %d charged to the reading of them", lex.pos, advanced)
			}
			if reserved >= room {
				t.Errorf("the room ran out (%d of %d reserved), so what the reading was charged is not what this measures", reserved, room)
			}
		})
	}
}

// boundsDensePages is a document of pages whose own /Resources dictionary
// holds count one-member dictionaries, in the graphics-state subdictionary a
// resource dictionary carries: the shape an ordinary document of many pages
// takes, which the ceiling must leave readable, and one the extraction itself
// parses, since a page's /Resources is read while the page tree is walked and
// read whole when it is.
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
	root := b.Next()
	b.Add(pdfgen.Object{Body: "placeholder"})
	kids := make([]string, 0, pages)
	for i := 0; i < pages; i++ {
		res := b.Add(pdfgen.Object{Body: fmt.Sprintf("<< /Font << /F1 %d 0 R >> /ExtGState << /Dense %s >> >>", helv, dense.String())})
		cs := b.Add(pdfgen.Object{Body: "<< >>", Stream: []byte(pdfgen.Text("F1", 12, []string{"dense"}))})
		page := b.Add(pdfgen.Object{Body: fmt.Sprintf("<< /Type /Page /Parent %d 0 R /MediaBox [0 0 612 792] /Resources %d 0 R /Contents %d 0 R >>", root, res, cs)})
		kids = append(kids, fmt.Sprintf("%d 0 R", page))
	}
	b.Set(root, pdfgen.Object{Body: fmt.Sprintf("<< /Type /Pages /Kids [%s] /Count %d >>", strings.Join(kids, " "), pages)})
	b.Catalog(root)
	return b.Bytes()
}

// boundsDenseExtract extracts a dense document with time enough for five
// hundred pages of it under the race detector: what these cases establish is
// the outcome and the charge, not the clock.
func boundsDenseExtract(t *testing.T, data []byte) *Result {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	return Extract(ctx, data, testOptions())
}

// boundsDenseWalk opens a dense document and walks its page tree, and reports
// the pages read, how many distinct resource dictionaries they name, the
// pages whose dense array was read whole, and what the document was charged.
func boundsDenseWalk(t *testing.T, data []byte, perPage int) (pages, distinct, whole int, charged, budget int64, bound error) {
	t.Helper()
	d := openGenerated(t, data)
	w := &walker{d: d, ctx: context.Background(), path: map[ref]bool{}, generation: d.generation, limit: 1000}
	root, rootRef := d.pagesRoot()
	if rootRef != (ref{}) {
		w.path[rootRef] = true
	}
	w.node(root, inherited{}, 0)
	seen := map[ref]bool{}
	for _, pn := range w.pages {
		if r, ok := pn.dict["Resources"].(ref); ok {
			seen[r] = true
		}
		if len(d.arrayOf(d.dictOf(d.dictOf(pn.dict["Resources"])["ExtGState"])["Dense"])) == perPage {
			whole++
		}
	}
	return len(w.pages), len(seen), whole, d.parsedBytes, d.parsedBudget(), d.bound
}

// boundsExtractLeaving walks a document and extracts its pages with the
// balance left what leave says, or with all of it where leave is negative. It
// reports the result and what the extraction itself spent. The walk and the
// extraction are the ones Extract does, in the order it does them: what is
// arranged is the balance they meet, which the calibration below arranges
// with a million dictionaries and sixteen megabytes of file instead.
func boundsExtractLeaving(t *testing.T, data []byte, leave int64) (*Result, int64) {
	t.Helper()
	ctx := context.Background()
	result := &Result{}
	doc, stop := openDocument(ctx, data, testOptions(), result)
	if stop != nil {
		t.Fatalf("the fixture was not opened: fatal %+v problems %+v", result.Fatal, result.Problems)
	}
	w, generation, stop := walkPages(ctx, doc, testOptions(), result)
	if stop != nil || doc.generation != generation {
		t.Fatalf("the page tree was not walked: fatal %+v problems %+v", result.Fatal, result.Problems)
	}
	if leave >= 0 {
		if left := w.doc.parsedBudget() - w.doc.parsedBytes; left > leave {
			w.doc.chargeParsed(left - leave)
		}
	}
	before := w.doc.parsedBytes
	extractPages(ctx, w, testOptions(), result)
	return result, w.doc.parsedBytes - before
}

// Where the balance runs out part way through extraction, the pages read come
// first and the pages that could not be read follow them, listed as failed
// with a problem each rather than as pages that hold no text: a reader that
// listed them as empty would report a document of blank pages where what
// happened is that it stopped reading. This is that shape at a size a default
// run can afford -- the balance is left half of what extracting these pages
// costs -- and the calibration below is where the figure that balance takes
// in an ordinary document is established.
func TestBoundsPagesPastTheBalanceAreFailedRatherThanEmpty(t *testing.T) {
	const pages = 8
	data := boundsDensePages(pages, 400, false)
	whole, cost := boundsExtractLeaving(t, data, -1)
	t.Logf("%d pages of 400 one-member dictionaries (%d bytes) with the balance whole: %d pages, extraction spent %d", pages, len(data), len(whole.Pages), cost)
	if whole.Fatal != nil || len(whole.Pages) != pages || len(whole.Problems) != 0 {
		t.Fatalf("with the balance whole: fatal %+v pages %+v problems %+v", whole.Fatal, whole.Pages, whole.Problems)
	}
	for _, p := range whole.Pages {
		if p.Status != PageOK || p.Text != "dense" {
			t.Fatalf("with the balance whole: page %d read as %q (%v)", p.Number, p.Text, p.Status)
		}
	}
	// Half of what extracting them costs: some of them are read and the rest
	// are not, whatever a page costs on this build.
	r, spent := boundsExtractLeaving(t, data, cost/2)
	read := 0
	for read < len(r.Pages) && r.Pages[read].Status == PageOK {
		read++
	}
	done, failed := r.Pages[:read], r.Pages[read:]
	t.Logf("the same pages with %d of the balance left: %d listed (%d read, %d failed), %d spent, problems %+v", cost/2, len(r.Pages), len(done), len(failed), spent, r.Problems)
	if r.Fatal != nil || len(r.Pages) != pages {
		t.Fatalf("fatal %+v pages %+v", r.Fatal, r.Pages)
	}
	if len(done) == 0 || len(failed) == 0 {
		t.Fatalf("%d pages read and %d failed; this is the shape where the balance runs out part way", len(done), len(failed))
	}
	for _, p := range done {
		if p.Text != "dense" {
			t.Errorf("page %d, read before the balance ran out, holds %q", p.Number, p.Text)
		}
	}
	reported := map[int]string{}
	for _, pr := range r.Problems {
		reported[pr.Page] = pr.Code
	}
	for _, p := range failed {
		if p.Status != PageFailed || p.Text != "" {
			t.Errorf("page %d, past where the balance ran out, is listed as %v (%q)", p.Number, p.Status, p.Text)
		}
		if reported[p.Number] != "pdf-page-failed" {
			t.Errorf("page %d, past where the balance ran out, is reported as %q", p.Number, reported[p.Number])
		}
	}
	if len(r.Problems) != len(failed) {
		t.Errorf("%d pages failed and %d problems are reported: %+v", len(failed), len(r.Problems), r.Problems)
	}
}

// An ordinary document of many pages, each holding as much structure as the
// densest shape the reader admits, is read whole: the ceiling is set above
// what such a document costs, where the ratio would allow far more, and a
// document a little denser than the densest it admits is refused. Every case
// is settled through Extract, which is what a caller sees: the dense
// dictionaries lie in each page's own /Resources, which the walk reads whole
// before the page is extracted, so nothing here is read only because the test
// asked for it.
//
// This is the calibration of the ceiling against a real document, and it
// costs what such a document costs: five hundred pages of up to one million
// eight hundred and ninety-five thousand dictionaries, a file of sixteen
// megabytes, and the better part of a gigabyte held while it is read. The run
// that skips the long tests skips it; what it establishes about the shape of
// the outcome -- pages read, then pages failed -- is held by the small test
// above on every run.
//
// It is also what holds adapters/README.md's prose to the reader: the figures
// the README states for these documents are the ones measured here, checked
// against what each case charged. The tables are checked against the constants
// elsewhere, cell by cell, but a figure written into a sentence is held by
// nothing unless it is held here, and a charge that drifts from the prose is a
// README that describes a reader the caller does not have.
func TestBoundsAnOrdinaryDenseDocumentIsReadWhole(t *testing.T) {
	if testing.Short() {
		t.Skip("walks and extracts five hundred-page documents of up to sixteen megabytes")
	}
	for _, inStream := range []bool{false, true} {
		where := "at an offset"
		if inStream {
			where = "in an object stream"
		}
		t.Run(where, func(t *testing.T) {
			data := boundsDensePages(500, 2000, inStream)
			r := boundsDenseExtract(t, data)
			t.Logf("500 pages of 2,000 one-member dictionaries %s: %d bytes, %d pages, problems %+v", where, len(data), len(r.Pages), r.Problems)
			if r.Fatal != nil || len(r.Pages) != 500 || len(r.Problems) != 0 {
				t.Fatalf("fatal %+v pages %d problems %+v", r.Fatal, len(r.Pages), r.Problems)
			}
			for _, p := range r.Pages {
				if p.Status != PageOK || p.Text != "dense" {
					t.Fatalf("page %d read as %q (%v)", p.Number, p.Text, p.Status)
				}
			}
			// Every page is its own, and so is every resource dictionary: an
			// index the generator wrote in too few bytes would give many pages
			// one, and the walk would read far less than the file declares.
			pages, distinct, whole, charged, budget, bound := boundsDenseWalk(t, data, 2000)
			t.Logf("the same document walked: %d pages, %d distinct resources, %d whole, %d charged of %d", pages, distinct, whole, charged, budget)
			if pages != 500 || distinct != 500 || whole != 500 || bound != nil {
				t.Errorf("%d pages, %d distinct resources, %d whole, bound %v", pages, distinct, whole, bound)
			}
			if !inStream {
				boundsREADMESays(t, fmt.Sprintf("five hundred pages of %s each, an eight-megabyte file, are charged about %s MB", spelledOut(2000), grouped(int(roundedMB(charged)))))
			}
		})
	}
	// Five hundred pages of three thousand six hundred one-member dictionaries
	// each, a fourteen-megabyte file, are read whole under the ceiling: every
	// page is listed with its text and nothing is reported.
	{
		const per = 3600
		data := boundsDensePages(500, per, false)
		r := boundsDenseExtract(t, data)
		pages, _, whole, charged, budget, bound := boundsDenseWalk(t, data, per)
		t.Logf("500 pages of %d one-member dictionaries: %d bytes, %d pages extracted, %d walked whole, %d charged of %d", per, len(data), len(r.Pages), whole, charged, budget)
		if r.Fatal != nil || len(r.Pages) != 500 || len(r.Problems) != 0 {
			t.Errorf("%d a page: fatal %+v pages %d problems %+v", per, r.Fatal, len(r.Pages), r.Problems)
		}
		if pages != 500 || whole != 500 || bound != nil {
			t.Errorf("%d a page: %d pages, %d whole, bound %v", per, pages, whole, bound)
		}
		boundsREADMESays(t, fmt.Sprintf("five hundred pages of %s each, fourteen megabytes, about %s MB", spelledOut(per), grouped(int(roundedMB(charged)))))
	}
	// The densest the ceiling admits at all: at three thousand seven hundred
	// and ninety a page -- one million eight hundred and ninety-five thousand
	// dictionaries -- the page tree is walked whole and every page is
	// listed, with what is left of the balance too little for the content of
	// the later ones, which are listed as failed rather than left out; one
	// dictionary a page more and the document itself is refused. Where exactly
	// that falls is a figure of the build: what a token's buffer is charged
	// follows what Go's allocator gives it, and an instrumented build gives it
	// something else, so this pair is asserted where the allocator is the
	// ordinary one. The cases either side of it hold on any build.
	if !boundsInstrumented {
		const per = 3790
		data := boundsDensePages(500, per, false)
		r := boundsDenseExtract(t, data)
		pages, _, whole, charged, budget, bound := boundsDenseWalk(t, data, per)
		// The pages that are read come first and the pages that fail follow
		// them: the walk spends what the resources cost, and from wherever
		// that leaves too little for a page's content, the pages are listed
		// as failed. Where the two meet is a figure of the build; that each
		// page is one or the other, and that a failed page is reported as a
		// failed page rather than as one holding no text, is not.
		read := 0
		for read < len(r.Pages) && r.Pages[read].Status == PageOK {
			read++
		}
		done, failed := r.Pages[:read], r.Pages[read:]
		t.Logf("500 pages of %d one-member dictionaries: %d bytes, %d pages extracted (%d read, %d failed), %d walked whole, %d charged of %d", per, len(data), len(r.Pages), len(done), len(failed), whole, charged, budget)
		if r.Fatal != nil || len(r.Pages) != 500 {
			t.Errorf("%d a page: fatal %+v pages %d", per, r.Fatal, len(r.Pages))
		}
		if pages != 500 || whole != 500 || bound != nil {
			t.Errorf("%d a page: %d pages, %d whole, bound %v", per, pages, whole, bound)
		}
		if len(done) == 0 || len(failed) == 0 {
			t.Errorf("%d a page: %d pages read and %d failed; this is the shape where the balance runs out part way", per, len(done), len(failed))
		}
		// One message for each way the pages could be wrong, naming the
		// first page that is: five hundred of them would otherwise be five
		// hundred lines.
		reported := map[int]string{}
		for _, pr := range r.Problems {
			reported[pr.Page] = pr.Code
		}
		var unread, listed, unreported int
		var firstUnread, firstListed, firstUnreported Page
		count := func(wrong bool, n *int, first *Page, p Page) {
			if !wrong {
				return
			}
			if *n == 0 {
				*first = p
			}
			*n++
		}
		for _, p := range done {
			count(p.Text != "dense", &unread, &firstUnread, p)
		}
		for _, p := range failed {
			count(p.Status != PageFailed || p.Text != "", &listed, &firstListed, p)
			count(reported[p.Number] != "pdf-page-failed", &unreported, &firstUnreported, p)
		}
		if unread > 0 {
			t.Errorf("%d a page: %d of the %d pages before the balance ran out did not read their text, the first being page %d as %q", per, unread, len(done), firstUnread.Number, firstUnread.Text)
		}
		if listed > 0 {
			t.Errorf("%d a page: %d of the %d pages past where the balance ran out are listed as something other than failed, the first being page %d as %v (%q)", per, listed, len(failed), firstListed.Number, firstListed.Status, firstListed.Text)
		}
		if unreported > 0 {
			t.Errorf("%d a page: %d of the %d failed pages are not reported as pdf-page-failed, the first being page %d as %q", per, unreported, len(failed), firstUnreported.Number, reported[firstUnreported.Number])
		}
		// And nothing else is reported: one problem for each failed page.
		if len(r.Problems) != len(failed) {
			t.Errorf("%d a page: %d pages failed and %d problems are reported: %+v", per, len(failed), len(r.Problems), r.Problems)
		}
		next := boundsDensePages(500, per+1, false)
		rn := boundsDenseExtract(t, next)
		t.Logf("500 pages of %d one-member dictionaries: %d bytes, fatal %+v, %d pages", per+1, len(next), rn.Fatal, len(rn.Pages))
		if rn.Fatal == nil || rn.Fatal.Code != "pdf-malformed" || len(rn.Pages) != 0 {
			t.Errorf("%d a page: fatal %+v, %d pages listed", per+1, rn.Fatal, len(rn.Pages))
		}
		boundsREADMESays(t, fmt.Sprintf("five hundred pages of about %s each, fifteen megabytes, about %s MB, which is the densest the ceiling admits at all", spelledOut(per), grouped(int(roundedMB(charged)))))
	}
	// A little more of it is past the ceiling, on any build: what the reader
	// cannot hold it does not hold, and the record says so rather than listing
	// pages whose resources were read in part.
	for _, per := range []int{4000} {
		data := boundsDensePages(500, per, false)
		r := boundsDenseExtract(t, data)
		t.Logf("500 pages of %d one-member dictionaries: %d bytes, fatal %+v, %d pages", per, len(data), r.Fatal, len(r.Pages))
		if r.Fatal == nil || r.Fatal.Code != "pdf-malformed" || len(r.Pages) != 0 {
			t.Errorf("%d a page: fatal %+v, %d pages listed", per, r.Fatal, len(r.Pages))
		}
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

// An operand of many short arrays is past the bound on what a page's operands
// hold, although the elements in those arrays are not: a twenty-five-kilobyte
// file whose content names one array of forty-eight thousand arrays of
// thirty-three integers holds sixty-seven megabytes of backing arrays, since
// Go grows an array of thirty-three elements to seventy-one slots, and a
// reader charging a slot for each element would say it held sixty-three. The
// page fails and is reported; the same shape a little under the bound is read,
// and is the control that says the bound and not the shape is what stopped the
// other.
func TestBoundsAnOperandOfArraysStopsThePage(t *testing.T) {
	arrayPage := func(arrays int) []byte {
		b := &pdfgen.Builder{Compress: true}
		helv := b.Font("Helvetica", "WinAnsiEncoding", "")
		content := pdfgen.Text("F1", 12, []string{"ordinary"}) + "[" + strings.Repeat("["+strings.Repeat("256 ", 33)+"]", arrays) + "]"
		b.Catalog(b.Pages([]pdfgen.Page{{Content: content, Fonts: map[string]int{"F1": helv}}}))
		return b.Bytes()
	}
	t.Run("past the bound", func(t *testing.T) {
		data := arrayPage(48000)
		r := extract(t, data)
		t.Logf("one operand of 48,000 arrays of 33 integers (%d bytes): pages %+v problems %+v", len(data), r.Pages, r.Problems)
		if r.Fatal != nil || len(r.Pages) != 1 || r.Pages[0].Status != PageFailed || r.Pages[0].Text != "" {
			t.Fatalf("fatal %+v pages %+v", r.Fatal, r.Pages)
		}
		if len(r.Problems) != 1 || r.Problems[0].Code != "pdf-page-failed" {
			t.Errorf("the page failed with %+v; what it met is the bound on what its operands hold", r.Problems)
		}
	})
	t.Run("under the bound", func(t *testing.T) {
		data := arrayPage(36000)
		r := extract(t, data)
		t.Logf("one operand of 36,000 arrays of 33 integers (%d bytes): pages %+v problems %+v", len(data), r.Pages, r.Problems)
		if r.Fatal != nil || len(r.Pages) != 1 || r.Pages[0].Status != PageOK || r.Pages[0].Text != "ordinary" || len(r.Problems) != 0 {
			t.Fatalf("fatal %+v pages %+v problems %+v", r.Fatal, r.Pages, r.Problems)
		}
	})
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
	if _, err := d.decodeStream(s, false, heldByDocument); err != nil {
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
	// An object stream's header is charged as it is read: reading one again
	// costs again, and costs the same again, since the same bytes are read
	// and the same entries kept.
	reread := func() int64 {
		before := d.parsedBytes
		d.objStms, d.objStmHeaders = map[int]*objStm{}, nil
		d.cache = map[int]object{}
		boundsFirstPage(t, d)
		return d.parsedBytes - before
	}
	second, third := reread(), reread()
	t.Logf("reading the object-stream headers again charged %d bytes, and again %d", second, third)
	if second <= 0 {
		t.Errorf("reading the object-stream headers again charged %d bytes", second)
	}
	if second != third {
		t.Errorf("two readings of the same headers charged %d and %d", second, third)
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
	if took > raceFactor*3*time.Second {
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
	// A reading that spends the allowance without building anything ends the
	// parse too. Whitespace is the shape that does it: a run of it charges
	// what it passed over and reserves nothing, so nothing a token holds can
	// stand in for the flag the lexer sets. The value after it would be read
	// for free otherwise, and at the end of the data the reading would be an
	// end of data rather than a bound.
	for _, c := range []struct {
		name, source string
	}{
		{"whitespace and then a value", strings.Repeat(" ", 100) + "null"},
		{"whitespace with nothing after it", strings.Repeat(" ", 100)},
	} {
		t.Run(c.name, func(t *testing.T) {
			d := &Document{data: make([]byte, 1<<10), budget: &inflateBudget{}}
			// Ten bytes to read with: less than the whitespace takes, and the
			// value after it holds little enough to be admitted on its own.
			d.parsedBytes = d.parsedBudget() - 10
			allow := d.budgeted()
			lex := newLexer([]byte(c.source), 0).within(allow)
			p := &parser{lex: lex, allow: allow}
			v, err := p.parseObject(0)
			if err == nil {
				t.Errorf("%s: a value was read once the reading had run out: %v", c.name, v)
			}
			// The reading after it is the bound, and not an end of data: the
			// whitespace spent the allowance, and a lexer that did not record
			// that would offer the end of the data as though nothing were
			// wrong.
			_, next := p.parseObject(0)
			t.Logf("%s with ten bytes to read with: %v, then %v (spent %v)", c.name, err, next, lex.spent)
			if next == nil || !isBound(next) {
				t.Errorf("%s: the reading after the allowance ran out returned %v", c.name, next)
			}
		})
	}
}

// An object read out of an object stream is built within the allowance too:
// a value past what the document may hold is stopped while it is built, not
// allocated whole out of the decoded stream and refused after.
func TestBoundsObjectStreamValuesAreBuiltWithinTheAllowance(t *testing.T) {
	// One object of an array of two hundred thousand empty dictionaries. The
	// shape is chosen so that nothing but the parser's own allowance stops it:
	// an empty dictionary carries no token to reserve room for, and four bytes
	// of stream for the three hundred and eighty-four a Go map costs means the
	// bytes read do not stop it either.
	const members = 200_000
	var body strings.Builder
	body.WriteString("[")
	for i := 0; i < members; i++ {
		body.WriteString("<<>>")
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
	// What is left to hold with, against a value that holds far more: a
	// mebibyte is more than the stream's own bytes cost to read, so the
	// reading of them is not what ends this, and less than a fortieth of what
	// the dictionaries cost to hold.
	d.parsedBytes = d.parsedBudget() - 1<<20
	var read bool
	var v object
	grew := allocated(func() { v, read = d.objectFromStream(st.order[0], xrefEntry{inStream: true, stmNum: 2, stmIndex: 0}) })
	held := 0
	if arr, ok := v.(Array); ok {
		held = len(arr)
	}
	t.Logf("an object-stream value of %d empty dictionaries with a mebibyte to hold with: read %v (%d members), %d MiB allocated", members, read, held, grew>>20)
	if read {
		t.Errorf("a value past what the document may hold was read: %T of %d members", v, held)
	}
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
			return it.skipInlineImage(newLexer(inline, 0), nil)
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
				runes, ok := got.toUnicode(0x41, 2)
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
	if took > raceFactor*20*time.Second {
		t.Errorf("reading them took %v", took)
	}
}

// A header token the window cuts in two settles nothing, through the two
// searches that read heads: an object whose generation, "obj" or "<<" ends at
// the window's edge stays a candidate, and the document it belongs to is
// read. Both searches are covered -- the catalog looked for because the
// trailer names none, and the page tree looked for because the catalog names
// none -- and in each the cut is made in the header of the object that search
// is looking for.
//
// Each search here reaches its heads through a rebuilt cross-reference, whose
// offset for an object is the offset of the object's number: padding written
// before the number is therefore read past rather than looked at, and the
// window for those cases begins at the number as it would with no padding at
// all. They are kept as the ordinary heads they are, and the cases that put
// the window's edge inside a number are made directly on the head reader
// below, where the entry's offset is the test's to name.
func TestBoundsAHeaderCutByTheWindowIsInconclusive(t *testing.T) {
	pages := "<< /Type /Pages /Kids [3 0 R] /Count 1 >>"
	catalog := "<< /Type /Catalog /Pages 2 0 R >>"
	rest := []string{
		"3 0 obj<< /Type /Page /Parent 2 0 R /Contents 4 0 R /Resources << /Font << /F1 5 0 R >> >> >>endobj\n",
		"4 0 obj<< /Length 44 >>stream\nBT /F1 12 Tf 10 700 Td (Hello world) Tj ET\nendstream\nendobj\n",
		"5 0 obj<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>endobj\n",
	}
	// header writes "num gen obj<<...>>" with the padding at the place named,
	// and cuts names where the padding goes, what stands before it and the
	// token that follows it, so that a gap can be chosen to put the window's
	// edge anywhere in that token.
	header := func(num int, body, where string, gap int) string {
		space := strings.Repeat(" ", gap)
		switch where {
		case "the number":
			return space + fmt.Sprintf("%d 0 obj", num) + body + "endobj\n"
		case "the generation":
			return fmt.Sprintf("%d%s0 obj", num, space) + body + "endobj\n"
		case "obj":
			return fmt.Sprintf("%d 0%sobj", num, space) + body + "endobj\n"
		default: // "<<"
			return fmt.Sprintf("%d 0 obj%s", num, space) + body + "endobj\n"
		}
	}
	// What stands before the padding, and how long the token after it is: the
	// window ends headWindow bytes from the object's offset, so a gap of
	// headWindow - before - k puts its edge k bytes into that token. The
	// number is the one token the rebuilt cross-reference's own offset stands
	// at, so its case is an ordinary head read from the number, and the
	// window's edge inside a number is settled directly below.
	cuts := []struct {
		token         string
		before, width int
	}{
		{"the number", 0, 1},
		{"the generation", 1, 1},
		{"obj", 3, 3},
		{"<<", 7, 2},
	}
	for _, search := range []struct {
		name string
		// cut names the object whose header carries the padding: the one the
		// search that reads heads is looking for.
		cut int
	}{
		{"the catalog is looked for", 1},
		{"the page tree is looked for", 2},
	} {
		for _, cut := range cuts {
			for k := -1; k <= cut.width+1; k++ {
				where, gap := cut.token, headWindow-cut.before-k
				t.Run(fmt.Sprintf("%s, the window ends %d bytes into %s (%d spaces)", search.name, k, where, gap), func(t *testing.T) {
					// The catalog names no page tree where the page tree is
					// the one looked for; the trailer names no catalog where
					// the catalog is.
					cat := catalog
					if search.cut == 2 {
						cat = "<< /Type /Catalog >>"
					}
					// Only the header of the object the search is looking for
					// is cut; the other is written plainly.
					padded := func(num int, body string) string {
						if num == search.cut {
							return header(num, body, where, gap)
						}
						return header(num, body, "obj", 1)
					}
					objects := append([]string{padded(1, cat), padded(2, pages)}, rest...)
					data := boundsTabledWith(objects, nil, "1 0 R")
					if search.cut == 1 {
						data = bytes.Replace(data, []byte("/Root 1 0 R"), []byte("/Rxxt 1 0 R"), 1)
					}
					r := extract(t, data)
					if r.Fatal != nil || len(r.Pages) != 1 || r.Pages[0].Text != "Hello world" {
						t.Fatalf("fatal %+v pages %+v problems %+v", r.Fatal, r.Pages, r.Problems)
					}
				})
			}
		}
	}
}

// boundsDirectHead lays out one object at the offset a cross-reference entry
// names, with the padding written where the case asks for it. The offset is
// the start of the whole region, padding and all, which is what a
// cross-reference the reader did read may name and what a rebuilt one never
// does: the window's edge then falls where the case puts it rather than at
// the head of a number. The object's number and its generation are several
// digits long, so that an edge inside one of them is an edge inside a token
// and not between two.
func boundsDirectHead(where string, gap int, body string) []byte {
	space := strings.Repeat(" ", gap)
	var head string
	switch where {
	case "the number":
		head = space + boundsHeadNumber + " " + boundsHeadGen + " obj" + body
	case "the generation":
		head = boundsHeadNumber + space + boundsHeadGen + " obj" + body
	case "obj":
		head = boundsHeadNumber + " " + boundsHeadGen + space + "obj" + body
	default: // "<<"
		head = boundsHeadNumber + " " + boundsHeadGen + " obj" + space + body
	}
	// The file runs on past the window, so that a head the window cuts is cut
	// by the window and not by the end of the file.
	return append([]byte(head+"endobj\n"), bytes.Repeat([]byte("%"), headWindow)...)
}

// The object's number and generation, long enough for the window's edge to
// fall inside either of them.
const (
	boundsHeadNumber = "123456789012"
	boundsHeadGen    = "345678"
)

// A header token the window cuts in two settles nothing, read directly: the
// entry's offset stands before the padding, as an offset a cross-reference
// the reader did read may name, so the window's edge falls inside the
// object's number, inside its generation, inside the "obj" that follows them
// and inside the "<<" that opens its dictionary. In each the object stays a
// candidate -- to be parsed under the document's allowance, as it was before
// any head was read -- and the searches that read heads exclude nothing on
// the strength of a token they only half read.
//
// The same header with the window's edge well past it is settled, and
// settled as what it is: the padding is not what makes a head inconclusive,
// the cut is.
func TestBoundsACutHeaderReadDirectlyIsInconclusive(t *testing.T) {
	const pages = "<< /Type /Pages /Kids [3 0 R] /Count 1 >>"
	// The entry names the start of the region: a document of the bytes alone,
	// read at offset zero, is the head reader's whole world here.
	head := func(data []byte) (*Document, xrefEntry) {
		return &Document{data: data, budget: &inflateBudget{}}, xrefEntry{offset: 0}
	}
	for _, cut := range []struct {
		token         string
		before, width int
	}{
		{"the number", 0, len(boundsHeadNumber)},
		{"the generation", len(boundsHeadNumber), len(boundsHeadGen)},
		{"obj", len(boundsHeadNumber) + 1 + len(boundsHeadGen), 3},
		{"<<", len(boundsHeadNumber) + 1 + len(boundsHeadGen) + 4, 2},
	} {
		// A byte either side of the token as well as every byte inside it:
		// the edge before it, at each of its bytes, at its end and a byte
		// past its end.
		for k := -1; k <= cut.width+1; k++ {
			gap := headWindow - cut.before - k
			t.Run(fmt.Sprintf("the window ends %d bytes into %s (%d spaces)", k, cut.token, gap), func(t *testing.T) {
				d, e := head(boundsDirectHead(cut.token, gap, pages))
				known := d.readHeadType(e)
				if known.settled {
					t.Errorf("a head with the window's edge %d bytes into %s was settled as %q", k, cut.token, known.typ)
				}
				if d.notOfType(e, "Pages") {
					t.Errorf("a head with the window's edge %d bytes into %s excluded the page tree it belongs to", k, cut.token)
				}
			})
		}
		// And the same header, padded but whole within the window: what it
		// declares is read, the page tree it is stays a candidate, and the
		// catalog it is not is excluded.
		gap := headWindow - cut.before - cut.width - 80
		t.Run(fmt.Sprintf("the window ends well past %s (%d spaces)", cut.token, gap), func(t *testing.T) {
			d, e := head(boundsDirectHead(cut.token, gap, pages))
			if known := d.readHeadType(e); !known.settled || known.typ != "Pages" {
				t.Errorf("a whole head padded before %s read as %+v", cut.token, known)
			}
			if d.notOfType(e, "Pages") {
				t.Errorf("a whole head of a page tree excluded the page tree")
			}
			if !d.notOfType(e, "Catalog") {
				t.Errorf("a whole head of a page tree was left a candidate for the catalog")
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
	if took > raceFactor*10*time.Second {
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
	if took > raceFactor*10*time.Second {
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
	if _, err := d.decodeStream(&stream{dict: Dict{"Filter": applied}, raw: []byte{}}, false, heldByPage); err != nil {
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
		if _, err := d.decodeStream(s, false, heldByPage); err == nil || isBound(err) {
			t.Fatalf("reading %d of the list: err %v, want the list rejected at its last entry", i, err)
		}
		if d.pageWork != i*entries*filterStepBytes {
			t.Errorf("after reading %d of the list the page's work is %d, want %d (one step an entry)", i, d.pageWork, i*entries*filterStepBytes)
		}
	}
	if _, err := d.decodeStream(s, false, heldByPage); !isBound(err) {
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
	// The charge is exactly what reading this header cost: the bytes of the
	// header region the lexer advanced over, which is all of it but the space
	// after its last token, since nothing follows that to charge it, and what
	// each entry costs to keep. The stream itself has no filter, so no decoder
	// was handed anything and nothing is charged for one.
	want := int64(header.Len()-1) + int64(entries)*(2*parsedMemberBytes+2*parsedSlotBytes)
	t.Logf("a header of %d entries over %d bytes: %d charged, %d expected", entries, len(payload), charged, want)
	if charged != want {
		t.Errorf("a header of %d entries charged %d, want %d: %d for the header region, %d for the entries", entries, charged, want, header.Len()-1, int64(entries)*(2*parsedMemberBytes+2*parsedSlotBytes))
	}
	// One byte less than those entries cost: the header is refused.
	tight := &Document{data: make([]byte, 16<<20), budget: &inflateBudget{total: 64 << 20, one: 16 << 20}, objStms: map[int]*objStm{}, cache: map[int]object{}}
	tight.parsedBytes = tight.parsedBudget() - charged/2
	if st, err := tight.loadObjStm(1, s); err == nil {
		t.Errorf("a header of %d entries was read with half of what it costs: %d entries", entries, len(st.order))
	}
}

// boundsSharedLabelledContent is a document of pages that all name one
// unfiltered stream as their content, where that stream's dictionary calls
// itself an object stream although no cross-reference entry names an object
// inside it: a label a file wrote, which says nothing about who holds the
// bytes the reader decodes from it.
func boundsSharedLabelledContent(aes bool, pages, size int) []byte {
	b := &pdfgen.Builder{Encrypt: &pdfgen.Encryption{Revision: 4, AES: aes, Owner: "owner", Permissions: -1}}
	content := b.Add(pdfgen.Object{Body: "<< /Type /ObjStm /N 0 /First 0 >>", Stream: bytes.Repeat([]byte(" "), size), Raw: true})
	root := b.Next()
	b.Add(pdfgen.Object{Body: "placeholder"})
	kids := make([]string, 0, pages)
	for i := 0; i < pages; i++ {
		page := b.Add(pdfgen.Object{Body: fmt.Sprintf("<< /Type /Page /Parent %d 0 R /MediaBox [0 0 612 792] /Resources << >> /Contents %d 0 R >>", root, content)})
		kids = append(kids, fmt.Sprintf("%d 0 R", page))
	}
	b.Set(root, pdfgen.Object{Body: fmt.Sprintf("<< /Type /Pages /Kids [%s] /Count %d >>", strings.Join(kids, " "), pages)})
	b.Catalog(root)
	return b.Bytes()
}

// Who a decrypted copy is charged to is settled by the caller that asked for
// the decoding and not by the stream's own label: a page whose content
// declares itself an object stream is still a page's content, dropped when
// the page is done, and five hundred pages that share one such stream read as
// five hundred pages rather than exhausting what the document may hold.
func TestBoundsDecryptionOwnershipIsSettledByTheCaller(t *testing.T) {
	for _, aes := range []bool{false, true} {
		name := "RC4"
		if aes {
			name = "AES"
		}
		t.Run(name, func(t *testing.T) {
			const pages, size = 500, 1 << 20
			data := boundsSharedLabelledContent(aes, pages, size)
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
			defer cancel()
			r := Extract(ctx, data, testOptions())
			failed := 0
			for _, p := range r.Pages {
				if p.Status == PageFailed {
					failed++
				}
			}
			t.Logf("%d pages sharing one %d-byte stream labelled /Type /ObjStm (%d bytes): %d pages, %d failed, %d problems", pages, size, len(data), len(r.Pages), failed, len(r.Problems))
			if r.Fatal != nil || len(r.Pages) != pages || failed != 0 || len(r.Problems) != 0 {
				t.Fatalf("fatal %+v pages %d failed %d problems %+v", r.Fatal, len(r.Pages), failed, r.Problems[:min(len(r.Problems), 3)])
			}
		})
	}
}

// A decrypted copy is charged to whoever keeps it, in both directions: the
// decoded data of an object stream, which the document's caches hold for its
// life, is the document's however a page came to ask for it, and a copy made
// for a page is the page's however the stream's dictionary describes itself.
func TestBoundsADecryptedCopyIsChargedToWhoeverKeepsIt(t *testing.T) {
	b := &pdfgen.Builder{XrefStream: true, ObjectStreams: true, Compress: true, Encrypt: &pdfgen.Encryption{Revision: 4, AES: true, Owner: "owner", Permissions: -1}}
	helv := b.Font("Helvetica", "WinAnsiEncoding", "")
	// Filler enough that the object stream's own bytes are unmistakable
	// beside what reading its filter list costs.
	var filler strings.Builder
	filler.WriteString("[")
	for i := 0; i < 40_000; i++ {
		fmt.Fprintf(&filler, "%d ", i*7919)
	}
	filler.WriteString("]")
	b.Add(pdfgen.Object{Body: filler.String()})
	page := b.Add(pdfgen.Object{Body: "<< >>", Stream: bytes.Repeat([]byte(" "), 1<<20), Raw: true})
	b.Catalog(b.Pages([]pdfgen.Page{{Content: pdfgen.Text("F1", 12, []string{"owned"}), Fonts: map[string]int{"F1": helv}}}))
	data := b.Bytes()
	d := openGenerated(t, data)
	if _, err := d.openEncryption(); err != nil {
		t.Fatalf("encryption: %v", err)
	}
	// An object stream, loaded while a page is being worked.
	stmNum := 0
	for _, e := range d.xref {
		if e.inStream {
			stmNum = e.stmNum
			break
		}
	}
	if stmNum == 0 {
		t.Fatal("the document holds no object stream")
	}
	s, ok := d.resolve(ref{stmNum, 0}).(*stream)
	if !ok {
		t.Fatalf("object %d is not a stream", stmNum)
	}
	copied := goSizeClass(int64(len(s.raw)))
	d.startPageWork()
	beforeParsed, beforeWork := d.parsedBytes, d.pageWork
	if _, err := d.loadObjStm(stmNum, s); err != nil {
		t.Fatalf("loadObjStm: %v", err)
	}
	docCharge, pageCharge := d.parsedBytes-beforeParsed, d.pageWork-beforeWork
	t.Logf("an object stream of %d bytes loaded while a page is worked: %d charged to the document, %d to the page (the copy is %d)", len(s.raw), docCharge, pageCharge, copied)
	if docCharge < copied {
		t.Errorf("the object stream's decrypted copy of %d bytes charged the document %d", copied, docCharge)
	}
	if pageCharge >= copied {
		t.Errorf("the object stream's decrypted copy charged the page %d bytes", pageCharge)
	}
	// And a stream decoded for the page is the page's, charged to its work
	// and not to the balance the document keeps.
	ps, ok := d.resolve(ref{page, 0}).(*stream)
	if !ok {
		t.Fatalf("object %d is not a stream", page)
	}
	pageCopied := goSizeClass(int64(len(ps.raw)))
	d.startPageWork()
	beforeParsed, beforeWork = d.parsedBytes, d.pageWork
	if _, err := d.decodeStream(ps, false, heldByPage); err != nil {
		t.Fatalf("decode: %v", err)
	}
	docCharge, pageCharge = d.parsedBytes-beforeParsed, d.pageWork-beforeWork
	t.Logf("a stream of %d bytes decoded for the page: %d charged to the document, %d to the page (the copy is %d)", len(ps.raw), docCharge, pageCharge, pageCopied)
	if pageCharge < pageCopied {
		t.Errorf("the page's decrypted copy of %d bytes charged the page %d", pageCopied, pageCharge)
	}
	if docCharge >= pageCopied {
		t.Errorf("the page's decrypted copy charged the document %d bytes", docCharge)
	}
}

// An encrypted page whose decrypted copies are more than one page may make
// fails at the work allowance: the copies are charged as they are made, so a
// page that names one large stream again and again is stopped part way rather
// than holding them all.
func TestBoundsDecryptedPageCopiesMeetTheWorkAllowance(t *testing.T) {
	const times, size = 40, 1 << 20
	b := &pdfgen.Builder{Encrypt: &pdfgen.Encryption{Revision: 4, AES: true, Owner: "owner", Permissions: -1}}
	content := b.Add(pdfgen.Object{Body: "<< >>", Stream: bytes.Repeat([]byte(" "), size), Raw: true})
	refs := make([]string, times)
	for i := range refs {
		refs[i] = fmt.Sprintf("%d 0 R", content)
	}
	pages := b.Next()
	b.Add(pdfgen.Object{Body: "placeholder"})
	page := b.Add(pdfgen.Object{Body: fmt.Sprintf("<< /Type /Page /Parent %d 0 R /MediaBox [0 0 612 792] /Resources << >> /Contents [%s] >>", pages, strings.Join(refs, " "))})
	b.Set(pages, pdfgen.Object{Body: fmt.Sprintf("<< /Type /Pages /Kids [%d 0 R] /Count 1 >>", page)})
	b.Catalog(pages)
	data := b.Bytes()
	r := extract(t, data)
	t.Logf("a page naming one encrypted %d-byte stream %d times (%d bytes): pages %+v problems %+v", size, times, len(data), r.Pages, r.Problems)
	// The raw bytes and the copies made of them together are more than the
	// page's work allowance; the raw bytes alone are not.
	if int64(times)*int64(size) >= maxPageWorkBytes {
		t.Fatalf("the fixture's raw bytes alone are %d, past the %d one page may cost", int64(times)*int64(size), int64(maxPageWorkBytes))
	}
	if r.Fatal != nil || len(r.Pages) != 1 || r.Pages[0].Status != PageFailed {
		t.Fatalf("fatal %+v pages %+v", r.Fatal, r.Pages)
	}
	if len(r.Problems) != 1 || r.Problems[0].Code != "pdf-page-failed" {
		t.Errorf("problems %+v", r.Problems)
	}
}

// An object stream's header is read pair by pair within the document's
// allowance, and the reading of either token of a pair may be what spends it.
// A header read in part is not a header: none of it is kept, and the document
// is refused at the bound rather than reading the objects a header that was
// cut short happens to name.
func TestBoundsAPartialObjectStreamHeaderIsNotKept(t *testing.T) {
	for _, c := range []struct{ name, second string }{
		{"an offset that runs into a literal with no end", "2 (" + strings.Repeat("x", 8<<10) + ")"},
		{"whitespace and then something that is not an offset", "2 " + strings.Repeat(" ", 8<<10) + "x"},
	} {
		t.Run(c.name, func(t *testing.T) {
			header := "1 0 " + c.second
			payload := header + "<< >>"
			var out bytes.Buffer
			out.WriteString("%PDF-1.7\n")
			out.WriteString("1 0 obj<< /Type /Catalog >>endobj\n")
			at := out.Len()
			fmt.Fprintf(&out, "2 0 obj<< /Type /ObjStm /N 2 /First %d /Length %d >>stream\n%s\nendstream endobj\n", len(header), len(payload), payload)
			fmt.Fprintf(&out, "trailer<< /Root 1 0 R /Size 3 >>\nstartxref\n%d\n%%%%EOF\n", at)
			data := out.Bytes()
			d, err := open(context.Background(), data, &inflateBudget{total: 64 << 20, one: 16 << 20})
			if d == nil {
				t.Fatalf("not opened: %v", err)
			}
			s, ok := d.resolve(ref{2, 0}).(*stream)
			if !ok {
				t.Fatal("object 2 is not a stream")
			}
			// Rebuilding read this header already, with the whole balance to
			// read it with; what is kept of that reading is dropped, so that
			// what is cached after the reading below is that reading's.
			d.objStms, d.objStmHeaders = map[int]*objStm{}, nil
			// A kilobyte to read the header with: the first pair of it fits,
			// and the second does not.
			d.parsedBytes = d.parsedBudget() - 1024
			st, lerr := d.loadObjStm(2, s)
			t.Logf("a header of two pairs whose second is %d bytes, with a kilobyte to read it with: %v (%v)", len(c.second), st != nil, lerr)
			if lerr == nil || !isBound(lerr) {
				t.Errorf("a header the allowance cut short returned %v", lerr)
			}
			if st != nil {
				t.Errorf("a header read in part was returned, with %d entries", len(st.order))
			}
			if d.objStmHeaders[2] != nil || d.objStms[2] != nil {
				t.Errorf("a header read in part was cached: header %v, stream %v", d.objStmHeaders[2], d.objStms[2])
			}
		})
	}
}

// A hex string's odd last nibble is padded into a byte of its own, and that
// byte is reserved like every other append: a token at a growth boundary is
// refused rather than returned past the room it was charged for, whether the
// string ended at a '>' or at the end of the data.
func TestBoundsHexStringPaddingIsReserved(t *testing.T) {
	const room = 4096
	body := strings.Repeat("41", room) + "4"
	for _, c := range []struct{ name, source string }{
		{"ended by '>'", "<" + body + ">"},
		{"ended by the end of the data", "<" + body},
	} {
		t.Run(c.name, func(t *testing.T) {
			allow := &allowance{left: room, past: errOperandBudget}
			lex := newLexer([]byte(c.source), 0).reserving(allow)
			tok, err := lex.next()
			t.Logf("%d complete bytes and a last nibble with %d bytes of room: %d bytes held, %v (%d left, spent %v)", room, room, len(tok.str), err, allow.left, lex.spent)
			if err == nil {
				t.Errorf("a token of %d bytes was returned with %d of its room left", len(tok.str), allow.left)
			}
			if allow.left != 0 {
				t.Errorf("the room left is %d; the token that did not fit spent it", allow.left)
			}
		})
	}
}

// boundsHexOperandPages is a page whose content holds one hex string of
// complete bytes, and a last nibble where nibble is set, as an operand no
// operator is applied to: it is parsed, charged and dropped, which is what
// makes what the reader does with the string itself the outcome. The hex
// digits are written across streams Flate content streams, since a page's
// content is joined from them and no one stream may inflate past the bound;
// whitespace between them is skipped inside a hex string as any other is.
func boundsHexOperandPages(complete int, nibble bool, streams int) []byte {
	digits := bytes.Repeat([]byte("AA"), complete)
	if nibble {
		digits = append(digits, 'A')
	}
	b := &pdfgen.Builder{}
	refs := make([]string, streams)
	each := (len(digits) + streams - 1) / streams
	for i := range refs {
		var content bytes.Buffer
		if i == 0 {
			content.WriteString("[<")
		}
		from := i * each
		to := from + each
		if to > len(digits) {
			to = len(digits)
		}
		if from < len(digits) {
			content.Write(digits[from:to])
		}
		if i == streams-1 {
			content.WriteString(">]")
		}
		refs[i] = fmt.Sprintf("%d 0 R", b.Add(pdfgen.Object{Body: "<< /Filter /FlateDecode >>", Stream: flateOf(content.Bytes()), Raw: true}))
	}
	pages := b.Next()
	b.Add(pdfgen.Object{Body: "placeholder"})
	page := b.Add(pdfgen.Object{Body: fmt.Sprintf("<< /Type /Page /Parent %d 0 R /MediaBox [0 0 612 792] /Resources << >> /Contents [%s] >>", pages, strings.Join(refs, " "))})
	b.Set(pages, pdfgen.Object{Body: fmt.Sprintf("<< /Type /Pages /Kids [%d 0 R] /Count 1 >>", page)})
	b.Catalog(pages)
	return b.Bytes()
}

// The byte an odd last nibble is padded into is a byte of the string, and the
// bound on a string counts it: a hex string of the bound exactly and one
// nibble more holds one byte more than the reader may hold, so it is refused
// like any other string past the bound -- at a '>' and at the end of the data
// alike, where a reader that padded without looking again would hand back a
// token of 16,777,217 bytes.
func TestBoundsHexStringPaddingMeetsTheStringBound(t *testing.T) {
	for _, ended := range []struct{ name, tail string }{
		{"ended by '>'", ">"},
		{"ended by the end of the data", ""},
	} {
		for _, c := range []struct {
			name   string
			nibble bool
		}{
			{"the bound exactly", false},
			{"the bound and a last nibble", true},
		} {
			t.Run(ended.name+", "+c.name, func(t *testing.T) {
				source := make([]byte, 0, 2*maxStringBytes+3)
				source = append(source, '<')
				source = append(source, bytes.Repeat([]byte("AA"), maxStringBytes)...)
				if c.nibble {
					source = append(source, 'A')
				}
				source = append(source, ended.tail...)
				// No allowance: what this establishes is the bound on the
				// string, which holds whatever room the reading was given.
				lex := newLexer(source, 0)
				tok, err := lex.next()
				t.Logf("%d complete bytes, a last nibble %v, %s: %d bytes held, %v", maxStringBytes, c.nibble, ended.name, len(tok.str), err)
				if !c.nibble {
					if err != nil || len(tok.str) != maxStringBytes {
						t.Fatalf("a hex string of the bound exactly was read as %d bytes (%v)", len(tok.str), err)
					}
					return
				}
				if !errors.Is(err, errStructureBound) {
					t.Fatalf("a hex string of %d bytes and a last nibble was read as %d bytes (%v)", maxStringBytes, len(tok.str), err)
				}
				if len(tok.str) != 0 {
					t.Errorf("the token refused carries %d bytes", len(tok.str))
				}
			})
		}
	}
}

// And what that is worth to a caller: a page whose content holds such an
// operand fails, as one holding a complete byte past the bound already does.
// The two are one byte apart in what they hold and are the same page to read.
func TestBoundsAHexOperandPastTheStringBoundFailsThePage(t *testing.T) {
	for _, c := range []struct {
		name     string
		complete int
		nibble   bool
	}{
		{"a last nibble past the bound", maxStringBytes, true},
		{"a complete byte past the bound", maxStringBytes + 1, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			data := boundsHexOperandPages(c.complete, c.nibble, 4)
			r := extract(t, data)
			t.Logf("a hex operand of %d complete bytes and a last nibble %v (%d bytes): pages %+v problems %+v", c.complete, c.nibble, len(data), r.Pages, r.Problems)
			if r.Fatal != nil || len(r.Pages) != 1 || r.Pages[0].Status != PageFailed || r.Pages[0].Text != "" {
				t.Fatalf("fatal %+v pages %+v", r.Fatal, r.Pages)
			}
			if len(r.Problems) != 1 || r.Problems[0].Code != "pdf-page-failed" || r.Problems[0].Page != 1 {
				t.Errorf("problems %+v", r.Problems)
			}
		})
	}
}

// A name is charged the room its buffer grows into as it grows: an escaped
// name far past what is left is stopped where the room ran out, with a few
// kilobytes allocated and the allowance spent, rather than built whole and
// handed back for the parser to refuse.
func TestBoundsANameIsChargedAsItGrows(t *testing.T) {
	const room = 1024
	source := []byte("/" + strings.Repeat("#41", maxNameBytes))
	allow := &allowance{left: room, past: errOperandBudget}
	lex := newLexer(source, 0).reserving(allow)
	var tok token
	var err error
	grew := allocated(func() { tok, err = lex.next() })
	t.Logf("a %d-byte escaped name with %d bytes of room: %d bytes held, %v, %d bytes allocated (%d left, spent %v)", maxNameBytes, room, len(tok.name), err, grew, allow.left, lex.spent)
	if err == nil {
		t.Errorf("a name of %d bytes was returned with %d of its room left", len(tok.name), allow.left)
	}
	if !lex.spent || allow.left != 0 {
		t.Errorf("the lexer is spent %v with %d left", lex.spent, allow.left)
	}
	if grew > 64<<10 {
		t.Errorf("refusing it allocated %d bytes", grew)
	}
}

// boundsSharedDecoderSuffix is a file of object-stream starts that all share
// one tail of whitespace under ASCII85: each declares the same length, so each
// decoder is handed about that many bytes, and the tail yields nothing at all,
// since ASCII85 skips every byte up to the space. Every byte of the region the
// decoders read is either skipped or a character of the encoding -- /Type is
// spelled with an escape for that reason -- so what they do is read.
func boundsSharedDecoderSuffix(streams, tail int) []byte {
	var out bytes.Buffer
	out.WriteString("%PDF-1.7\n")
	out.WriteString("1 0 obj<< /Type /Catalog >>endobj\n")
	at := out.Len()
	for i := 0; i < streams; i++ {
		fmt.Fprintf(&out, "%d 0 obj<< /T#79pe /ObjStm /N 0 /First 0 /Filter /ASCII85Decode /Length %d >>stream\n", i+2, tail)
	}
	out.Write(bytes.Repeat([]byte(" "), tail))
	fmt.Fprintf(&out, "trailer<< /Root 1 0 R /Size %d >>\nstartxref\n%d\n%%%%EOF\n", streams+2, at)
	return out.Bytes()
}

// The bytes a decoder is handed while the document is opened or rebuilt are
// charged to the document's balance, as a page's content is charged to that
// page's work: a file of object streams that share one long tail is decoded
// once for every stream that names those bytes, and nothing the decoders
// yield would show it. The document is refused at the bound.
func TestBoundsStreamsReadWhileOpeningAreCharged(t *testing.T) {
	const streams, tail = 320, 3 << 20
	data := boundsSharedDecoderSuffix(streams, tail)
	started := time.Now()
	// Near a gigabyte of ASCII85 takes its time under the race detector, and
	// what this establishes is the charge and not the clock.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	r := Extract(ctx, data, testOptions())
	took := time.Since(started)
	t.Logf("%d object streams over a shared %d-byte tail (%d bytes): %v, fatal %+v, %d pages", streams, tail, len(data), took, r.Fatal, len(r.Pages))
	// Reading that tail once for every stream is near a gigabyte at no
	// charge; the balance is what ends it.
	if r.Fatal == nil || r.Fatal.Code != "pdf-malformed" || r.Fatal.Message != boundMessage {
		t.Fatalf("fatal %+v, want the bound met while the document was opened", r.Fatal)
	}
	if len(r.Pages) != 0 {
		t.Errorf("%d pages listed for a document refused at the bound", len(r.Pages))
	}
}

// A cross-reference stream skips decryption, not the charge: what its filters
// are handed is read like anything else, and a megabyte of whitespace under
// ASCIIHex costs the megabyte although it yields nothing.
func TestBoundsCrossReferenceStreamBytesAreCharged(t *testing.T) {
	const size = 1 << 20
	raw := bytes.Repeat([]byte(" "), size)
	s := &stream{dict: Dict{"Type": Name("XRef"), "Filter": Name("ASCIIHexDecode")}, raw: raw}
	d := &Document{data: make([]byte, 8<<20), budget: &inflateBudget{total: 64 << 20, one: 16 << 20}}
	before := d.parsedBytes
	out, err := d.decodeStream(s, true, heldByDocument)
	charged := d.parsedBytes - before
	t.Logf("a %d-byte cross-reference stream of whitespace under ASCIIHex: %d bytes decoded, %d charged (%v)", size, len(out), charged, err)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if charged < size {
		t.Errorf("a megabyte read charged %d bytes", charged)
	}
	// And a quarter of a gigabyte read that way is a quarter of a gigabyte
	// charged: the balance ends it rather than the readings going on for the
	// nothing each of them yields.
	small := &Document{data: make([]byte, size), budget: &inflateBudget{total: 64 << 20, one: 16 << 20}}
	decoded := 0
	for i := 0; i < 256; i++ {
		if _, err := small.decodeStream(s, true, heldByDocument); err != nil {
			break
		}
		decoded++
	}
	t.Logf("256 such readings against a %d-byte file: %d admitted, %d charged of %d", size, decoded, small.parsedBytes, small.parsedBudget())
	if decoded >= 256 {
		t.Errorf("256 readings of a megabyte were all admitted, charging %d of %d", small.parsedBytes, small.parsedBudget())
	}
}

// An ordinary document opened by rebuilding is still read whole: what the
// readings of its streams cost is charged, and what an ordinary file's
// streams cost is far below what it may hold, rebuilt cross-reference and
// all -- and the rebuild may happen twice.
func TestBoundsAnOrdinaryRebuiltDocumentIsStillRead(t *testing.T) {
	const pages = 500
	b := &pdfgen.Builder{XrefStream: true, ObjectStreams: true, Compress: true, BrokenOffsets: 3}
	helv := b.Font("Helvetica", "WinAnsiEncoding", "")
	list := make([]pdfgen.Page, pages)
	for i := range list {
		list[i] = pdfgen.Page{Content: pdfgen.Text("F1", 12, []string{fmt.Sprintf("page %d", i+1)}), Fonts: map[string]int{"F1": helv}}
	}
	b.Catalog(b.Pages(list))
	data := b.Bytes()
	r := extract(t, data)
	failed := 0
	for _, p := range r.Pages {
		if p.Status == PageFailed {
			failed++
		}
	}
	t.Logf("%d pages in object streams with damaged offsets (%d bytes): %d pages, %d failed, %d problems", pages, len(data), len(r.Pages), failed, len(r.Problems))
	if r.Fatal != nil || len(r.Pages) != pages || failed != 0 || len(r.Problems) != 0 {
		t.Fatalf("fatal %+v pages %d failed %d problems %+v", r.Fatal, len(r.Pages), failed, r.Problems[:min(len(r.Problems), 3)])
	}
	if r.Pages[0].Text != "page 1" || r.Pages[pages-1].Text != fmt.Sprintf("page %d", pages) {
		t.Errorf("first page %q, last page %q", r.Pages[0].Text, r.Pages[pages-1].Text)
	}
}

// Every entry of a filter list costs one step of the page's work, whatever
// shape the list takes and wherever the entry falls, and the allowance is met
// at the entry that would take it past and not at the one before: a list of
// exactly as many entries as the allowance pays for is applied, and one entry
// more is refused.
func TestBoundsFilterStepsAreChargedExactly(t *testing.T) {
	steps := func(dict Dict) (int64, error) {
		d := &Document{data: make([]byte, 1<<20), budget: &inflateBudget{total: 64 << 20, one: 16 << 20}}
		d.startPageWork()
		_, err := d.decodeStream(&stream{dict: dict, raw: nil}, false, heldByPage)
		return d.pageWork, err
	}
	for _, c := range []struct {
		name string
		dict Dict
		want int64
	}{
		{"a standalone name", Dict{"Filter": Name("ASCIIHexDecode")}, filterStepBytes},
		{"a one-element array", Dict{"Filter": Array{Name("ASCIIHexDecode")}}, filterStepBytes},
		{"the abbreviated key", Dict{"F": Name("AHx")}, filterStepBytes},
	} {
		got, err := steps(c.dict)
		if err != nil {
			t.Errorf("%s: %v", c.name, err)
		}
		if got != c.want {
			t.Errorf("%s charged %d bytes of work, want %d", c.name, got, c.want)
		}
	}
	// The boundary: the allowance pays for exactly this many entries, and the
	// entry after them is what meets it.
	const admitted = maxPageWorkBytes / filterStepBytes
	list := make(Array, admitted)
	for i := range list {
		list[i] = Name("ASCIIHexDecode")
	}
	got, err := steps(Dict{"Filter": list})
	t.Logf("%d entries of a filter list: %d bytes of work (%v)", admitted, got, err)
	if err != nil || got != maxPageWorkBytes {
		t.Errorf("%d entries charged %d of work (%v), want %d and no error", admitted, got, err, int64(maxPageWorkBytes))
	}
	got, err = steps(Dict{"Filter": append(list, Name("ASCIIHexDecode"))})
	t.Logf("%d entries of a filter list: %d bytes of work (%v)", admitted+1, got, err)
	if !isBound(err) {
		t.Errorf("%d entries charged %d of work and returned %v, want the work allowance met", admitted+1, got, err)
	}
}
