package pdf

import (
	"bytes"
	"context"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"
)

// rebuildHead is a small object the files below begin with, so that each has
// an object for the scan to find.
const rebuildHead = "%PDF-1.7\n1 0 obj<< /A 1 >>endobj\n"

// rebuildSearches are files with no startxref whose rebuild searches a large
// part of the file for a keyword: 64 MiB with no "trailer" in it, one
// stream whose /Length locates nothing and whose "endstream" lies 64 MiB on,
// and one whose data holds an "endstream" every 50,000 bytes, so that the
// index of stream ends searches again after every one it finds.
func rebuildSearches() []struct {
	name string
	data []byte
	// searched is at least what the searches examine.
	searched int
} {
	const stream = "%PDF-1.7\n1 0 obj<< /Type /XRef /Length -1 >>stream\n"
	var every bytes.Buffer
	every.WriteString(stream)
	for every.Len() < 64<<20 {
		every.WriteString(strings.Repeat(" ", 50000) + "endstream")
	}
	return []struct {
		name     string
		data     []byte
		searched int
	}{
		{"64 MiB with no trailer", append([]byte(rebuildHead), bytes.Repeat([]byte("x"), 64<<20)...), 64 << 20},
		{"one endstream 64 MiB on", append(append([]byte(stream), bytes.Repeat([]byte(" "), 64<<20)...), "endstream\nendobj\n"...), 64 << 20},
		{"an endstream every 50,000 bytes", every.Bytes(), 64 << 20},
	}
}

// No more than searchBytesPerCheck bytes, and the keyword's length less one
// past them, are searched for "trailer" or "endstream" between two readings
// of the deadline: counted as the searches examine them, and not as they are
// charged against the part.
func TestTheRebuildSearchesNoMoreThanAPartBetweenReadings(t *testing.T) {
	bound := searchBytesPerCheck + len(endstreamKeyword) - 1
	for _, c := range rebuildSearches() {
		t.Run(c.name, func(t *testing.T) {
			stretch, most, searched := 0, 0, 0
			ctx := &lexReadings{Context: context.Background(), onRead: func() { stretch = 0 }}
			searchInspected = func(from, to int) {
				stretch += to - from
				searched += to - from
				most = max(most, stretch)
			}
			defer func() { searchInspected = nil }()
			if _, err := open(ctx, c.data, &inflateBudget{total: 64 << 20, one: 16 << 20}); isDeadline(err) || isBound(err) {
				t.Fatalf("opening ended with %v under a deadline that never passes, within every bound", err)
			}
			t.Logf("%d bytes: at most %d searched between two readings, %d readings, %d searched in all", len(c.data), most, ctx.reads, searched)
			if searched < c.searched {
				t.Fatalf("the searches were told of %d bytes, and the file makes them search at least %d", searched, c.searched)
			}
			if most > bound {
				t.Fatalf("%d bytes searched between two readings of the deadline, at most %d", most, bound)
			}
		})
	}
}

// rebuildLoops are files whose opening runs a loop whose work grows with a
// structure the file declares, each named by the loops it runs: a quarter
// million objects, whose numbers are gathered, sorted in runs and merged; a
// trailer of a million members found by the rebuild, which it copies; an
// object stream whose header declares 65,536 places, which are read and
// mapped and then registered, one that declares as many and holds none of
// them, which are filled in, and one whose places are two bytes each, more of
// them than a lexer's reading of the deadline spans; a trailer of a million
// members read through startxref, which is merged into the document's; a
// cross-reference stream whose /Index holds a million elements, each
// resolved, making half a million ranges of no entries; and a stream whose
// /Length locates nothing, with its "endstream" 64 MiB on, whose index of
// stream ends is set up and filled a block at a time.
func rebuildLoops() []struct {
	name  string
	data  []byte
	loops map[string]int
} {
	var keys bytes.Buffer
	keys.WriteString("%PDF-1.7\n")
	for i := 1; i <= maxScanObjects; i++ {
		fmt.Fprintf(&keys, "%d 0 obj\nnull\nendobj\n", i)
	}
	var members strings.Builder
	members.WriteString("<< ")
	for i := 0; i < maxContainerItems; i++ {
		fmt.Fprintf(&members, "/K%d 1 ", i)
	}
	members.WriteString(">>")
	var header strings.Builder
	for i := 0; i < maxObjStmObjects; i++ {
		fmt.Fprintf(&header, "%d 0 ", i+2)
	}
	// The body is padded, so that the file is large enough for the reader to
	// hold the places its header declares.
	objStm := func(pairs string) []byte {
		body := pairs + "null" + strings.Repeat(" ", 64<<10)
		return []byte(fmt.Sprintf("%%PDF-1.7\n1 0 obj<< /Type /ObjStm /N %d /First %d /Length %d >>stream\n%s\nendstream\nendobj\n", maxObjStmObjects, len(pairs), len(body), body))
	}
	var table bytes.Buffer
	table.WriteString("%PDF-1.7\n")
	at := table.Len()
	table.WriteString("1 0 obj\n<< /Type /Catalog >>\nendobj\n")
	xref := table.Len()
	fmt.Fprintf(&table, "xref\n0 2\n0000000000 65535 f \n%010d 00000 n \ntrailer\n%s\nstartxref\n%d\n%%%%EOF\n", at, members.String(), xref)
	var index bytes.Buffer
	index.WriteString("%PDF-1.7\n")
	at = index.Len()
	fmt.Fprintf(&index, "1 0 obj\n<< /Type /XRef /W [1 1 1] /Size 1 /Index [%s] /Length 0 >>stream\n\nendstream\nendobj\nstartxref\n%d\n%%%%EOF\n", strings.Repeat("0 ", maxContainerItems), at)
	return []struct {
		name  string
		data  []byte
		loops map[string]int
	}{
		{"a quarter million objects", keys.Bytes(), map[string]int{"gather": maxScanObjects, "sort": maxScanObjects, "merge": maxScanObjects}},
		{"a trailer of a million members found by the rebuild", []byte(rebuildHead + "trailer\n" + members.String() + "\n"), map[string]int{"copy": maxContainerItems}},
		{"an object stream of 65,536 places", objStm(header.String()), map[string]int{"pairs": maxObjStmObjects, "mapped": maxObjStmObjects, "register": maxObjStmObjects}},
		{"an object stream declaring 65,536 places and holding none", objStm(""), map[string]int{"filled": maxObjStmObjects, "mapped": maxObjStmObjects}},
		{"an object stream whose header's places are delimiters", objStm(strings.Repeat("[]", maxObjStmObjects)), map[string]int{"pairs": maxObjStmObjects}},
		{"a trailer of a million members read through startxref", table.Bytes(), map[string]int{"merge trailer": maxContainerItems}},
		{"a cross-reference stream whose /Index holds a million elements", index.Bytes(), map[string]int{"index": maxContainerItems, "ranges": maxContainerItems / 2}},
		{"a stream whose end is indexed over 64 MiB", append(append([]byte("%PDF-1.7\n1 0 obj<< /Type /XRef /Length -1 >>stream\n"), bytes.Repeat([]byte(" "), 64<<20)...), "endstream\nendobj\n"...), map[string]int{"blocks": (64 << 20) / endstreamBlock, "blocks filled": (64 << 20) / endstreamBlock}},
	}
}

// rebuildSteps opens data under ctx, counting the steps each loop takes
// through loopStepped, and returns the steps each took in all and the most any
// took between two readings of the deadline. ctx is told of every step, so
// that it can decide on it.
func rebuildSteps(t *testing.T, data []byte, ctx *rebuildDeadline) (steps, most map[string]int, err error) {
	t.Helper()
	steps, most = map[string]int{}, map[string]int{}
	stretch := map[string]int{}
	ctx.onRead = func() { clear(stretch) }
	loopStepped = func(loop string, n int) {
		ctx.stepped(loop, n)
		steps[loop] += n
		stretch[loop] += n
		most[loop] = max(most[loop], stretch[loop])
	}
	defer func() { loopStepped = nil }()
	_, err = open(ctx, data, &inflateBudget{total: 64 << 20, one: 16 << 20})
	return steps, most, err
}

// rebuildDeadline counts the readings of the deadline, and passes at the
// first reading made once the loop it is armed for has taken a step, and at
// every reading after it; armed for no loop, it never passes. after counts
// the steps that loop takes once it has passed.
type rebuildDeadline struct {
	context.Context
	loop    string
	onRead  func()
	began   bool
	expired bool
	after   int
}

func (c *rebuildDeadline) stepped(loop string, n int) {
	if loop != c.loop {
		return
	}
	if c.expired {
		c.after += n
	}
	c.began = true
}

func (c *rebuildDeadline) Err() error {
	if c.onRead != nil {
		c.onRead()
	}
	if c.began {
		c.expired = true
	}
	if c.expired {
		return context.DeadlineExceeded
	}
	return nil
}

func (c *rebuildDeadline) Deadline() (time.Time, bool) { return time.Time{}, false }

// Each loop of opening whose work grows with a structure the file declares
// takes no more than entriesPerCheck steps between two readings of the
// deadline, counted as it takes them and not as it reads the deadline; and a
// deadline that passes at the first reading the loop makes stops it there,
// with no step taken after it, and the opening ends at the deadline.
func TestTheRebuildReadsTheDeadlineAsItsLoopsRun(t *testing.T) {
	for _, c := range rebuildLoops() {
		t.Run(c.name, func(t *testing.T) {
			steps, most, err := rebuildSteps(t, c.data, &rebuildDeadline{Context: context.Background()})
			if isDeadline(err) {
				t.Fatalf("opening ended with %v under a deadline that never passes", err)
			}
			for loop, want := range c.loops {
				t.Logf("%s: %d steps, at most %d between two readings", loop, steps[loop], most[loop])
				if steps[loop] < want {
					t.Fatalf("%s took %d steps, and the file makes it take at least %d", loop, steps[loop], want)
				}
				if most[loop] > entriesPerCheck {
					t.Fatalf("%s took %d steps between two readings of the deadline, at most %d", loop, most[loop], entriesPerCheck)
				}
			}
			for loop := range c.loops {
				ctx := &rebuildDeadline{Context: context.Background(), loop: loop}
				_, _, err := rebuildSteps(t, c.data, ctx)
				if !ctx.expired {
					t.Fatalf("%s: the deadline was never read after the loop began", loop)
				}
				if ctx.after != 0 {
					t.Fatalf("%s took %d steps after a reading found the deadline passed", loop, ctx.after)
				}
				if !isDeadline(err) {
					t.Fatalf("%s: opening ended with %v, and the deadline passed while it ran", loop, err)
				}
			}
		})
	}
}

// The search for the page tree after a rebuild gathers and orders the numbers
// the rebuilt cross-reference names as the rebuild does, and ends at a
// deadline met there as it ends at one met between its objects.
func TestTheSearchForThePageTreeReadsTheDeadlineAsItOrdersNumbers(t *testing.T) {
	data := rebuildLoops()[0].data
	d, err := open(context.Background(), data, &inflateBudget{total: 64 << 20, one: 16 << 20})
	if d == nil {
		t.Fatalf("opening the file: %v", err)
	}
	// With time left, the numbers come back as the whole set of them the
	// cross-reference names, each once, in order.
	want := make([]int, 0, len(d.xref))
	for num := range d.xref {
		want = append(want, num)
	}
	slices.Sort(want)
	nums, ok := d.xrefNumbers()
	if !ok || !slices.Equal(nums, want) {
		t.Fatalf("ordered %d numbers, ok %v; they are not the %d the cross-reference names, in order", len(nums), ok, len(want))
	}
	for _, loop := range []string{"gather", "sort", "merge"} {
		ctx := &rebuildDeadline{Context: context.Background(), loop: loop}
		d.ctx = ctx
		steps := 0
		loopStepped = func(l string, n int) {
			ctx.stepped(l, n)
			if l == loop {
				steps += n
			}
		}
		root := d.findPagesRoot()
		loopStepped = nil
		if root != nil || !ctx.expired || ctx.after != 0 {
			t.Fatalf("%s: root %v, deadline passed %v, %d steps after it", loop, root, ctx.expired, ctx.after)
		}
		if steps > entriesPerCheck {
			t.Fatalf("%s took %d steps before the reading that found the deadline passed, at most %d", loop, steps, entriesPerCheck)
		}
	}
}
