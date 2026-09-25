package pdf

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

// lexReadings is a deadline that never passes and counts every reading of it,
// telling onRead of each: the tests below count what a lexer advances over
// between two readings without taking the lexer's word for either.
type lexReadings struct {
	context.Context
	reads  int
	onRead func()
}

func (c *lexReadings) Err() error {
	c.reads++
	if c.onRead != nil {
		c.onRead()
	}
	return nil
}

func (c *lexReadings) Deadline() (time.Time, bool) { return time.Time{}, false }

// lexOpenings are files with no startxref whose rebuild parses, after the word
// "trailer", one structure that runs through a large part of the file within
// every bound the reader holds: the trailer of #157, a run of whitespace and
// a comment of 64 MiB each, the longest string the reader admits, arrays
// nested deep holding as many empty arrays as one array may, written with no
// whitespace between them, so that the reading of the deadline between them
// can only come where a token ends, and an array of keywords as long as a
// keyword may be, back to back, each of them read whole with no reading
// inside it.
func lexOpenings() []struct {
	name string
	data []byte
	// advanced is at least what the lexer advances over reading it.
	advanced int
} {
	const head = "%PDF-1.7\n1 0 obj<< /A 1 >>endobj\n"
	var trailer strings.Builder
	trailer.WriteString(head + "trailer\n<< ")
	for i := 0; i < maxContainerItems; i++ {
		fmt.Fprintf(&trailer, "/K%d 1 ", i)
	}
	trailer.WriteString(">>\n")
	const depth = 200
	var nested strings.Builder
	nested.WriteString(head + "trailer\n<< /A " + strings.Repeat("[", depth))
	for i := 0; i < maxContainerItems-1; i++ {
		nested.WriteString("[]")
	}
	nested.WriteString(strings.Repeat("]", depth) + " >>\n")
	return []struct {
		name     string
		data     []byte
		advanced int
	}{
		{"the trailer of #157, a million one-member entries", []byte(trailer.String()), trailer.Len() - len(head)},
		{"64 MiB of spaces after trailer", append([]byte(head+"trailer"), bytes.Repeat([]byte(" "), 64<<20)...), 64 << 20},
		{"a 64 MiB comment with no line end after trailer%", append([]byte(head+"trailer%"), bytes.Repeat([]byte("x"), 64<<20)...), 64 << 20},
		{"a single 16 MiB string", []byte(head + "trailer\n<< /A (" + strings.Repeat("s", maxStringBytes) + ") >>\n"), maxStringBytes},
		{"arrays nested deep and within their bounds", []byte(nested.String()), nested.Len() - len(head)},
		{"keywords of 4,096 bytes back to back", []byte(head + "trailer\n<< /A [" + strings.Repeat("k", 4096*maxNameBytes) + "] >>\n"), 4096 * maxNameBytes},
	}
}

// lexStretches opens data under a deadline that never passes and returns,
// for every lexer that reads the deadline, the most it advanced over between
// two of its readings, or before its first, what it had advanced over by its
// last reading, all lexers together, and the readings of the deadline made.
// What a lexer has advanced over is counted through lexTrace, from where it
// began, where it stands at each reading and every step back it makes, and
// not from due, which decides when the reading falls due. What a lexer
// advances over after its last reading is not told to anything, which is why
// what was advanced over is compared with what the file makes a lexer advance
// over less a stretch.
func lexStretches(t *testing.T, data []byte) (most, advanced, reads int) {
	t.Helper()
	ctx := &lexReadings{Context: context.Background()}
	began, back, last := map[*allowance]int{}, map[*allowance]int{}, map[*allowance]int{}
	lexTrace = func(l *allowance, event lexEvent, n int) {
		switch event {
		case lexBegan:
			began[l] = n
		case lexSteppedBack:
			if n < 0 {
				t.Fatalf("a lexer stepped back by %d", n)
			}
			back[l] += n
		case lexReadAt:
			total := n - began[l] + back[l]
			if total < last[l] {
				t.Fatalf("a lexer had advanced over %d bytes and then over %d", last[l], total)
			}
			most = max(most, total-last[l])
			advanced += total - last[l]
			last[l] = total
		}
	}
	defer func() { lexTrace = nil }()
	if _, err := open(ctx, data, &inflateBudget{total: 64 << 20, one: 16 << 20}); isDeadline(err) || isBound(err) {
		t.Fatalf("opening ended with %v under a deadline that never passes, within every bound", err)
	}
	return most, advanced, ctx.reads
}

// No more than lexBytesPerCheck bytes, and the bytes of a keyword read whole,
// are advanced over between two readings of the deadline while a document's
// lexer reads it, however long one structure of it runs: counted from where
// the lexer began, where it stands and what it has stepped back over, and not
// from due.
func TestTheLexerAdvancesNoMoreThanItsStretchBetweenReadings(t *testing.T) {
	bound := lexBytesPerCheck + maxNameBytes
	for _, c := range lexOpenings() {
		t.Run(c.name, func(t *testing.T) {
			most, advanced, reads := lexStretches(t, c.data)
			t.Logf("%d bytes: at most %d advanced over between two readings, %d advanced over by the last reading, %d readings", len(c.data), most, advanced, reads)
			if advanced < c.advanced-bound {
				t.Fatalf("the lexers had advanced over %d bytes by their last readings, and reading the file advances over at least %d: more than %d were read after the last reading", advanced, c.advanced, bound)
			}
			if most > bound {
				t.Fatalf("%d bytes advanced over between two readings of the deadline, at most %d", most, bound)
			}
		})
	}
}

// Every step back a lexer makes is made through back, so that what it reads
// again is counted toward the reading of the deadline and told to lexTrace. Setting a lexer's position anywhere else is a step back neither
// counts: the reader's sources set it in two places only, where a token ends
// past where the lexer stands and where a page's inline image ends past its
// data, and this holds them to that.
func TestALexerStepsBackOnlyThroughBack(t *testing.T) {
	allowed := map[string]int{
		"lexer.go\tl.pos = to":     1,
		"lexer.go\tl.pos = end":    2,
		"content.go\tlex.pos = at": 1,
	}
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	assignment := regexp.MustCompile(`\bpos = [^=]`)
	found := map[string]int{}
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		raw, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		for _, line := range strings.Split(string(raw), "\n") {
			code := strings.TrimSpace(line)
			if strings.HasPrefix(code, "//") || !assignment.MatchString(code) {
				continue
			}
			key := f + "\t" + code
			if allowed[key] == 0 {
				t.Errorf("%s sets a lexer's position outside back: %s", f, code)
			}
			found[key]++
		}
	}
	for key, n := range allowed {
		if found[key] != n {
			t.Errorf("%q appears %d times, want %d", key, found[key], n)
		}
	}
}

// lexCountdown is a deadline that passes at the reading of it numbered n and
// at every reading after it.
type lexCountdown struct {
	context.Context
	n, reads int
}

func (c *lexCountdown) Err() error {
	c.reads++
	if c.reads >= c.n {
		return context.DeadlineExceeded
	}
	return nil
}

func (c *lexCountdown) Deadline() (time.Time, bool) { return time.Time{}, false }

// A deadline that passes while one object is parsed ends the parse at the
// deadline, and the reading of the document ends there as the deadline and as
// nothing else: not a trailer that cannot be read, which would send the reader
// rebuilding a cross-reference it had not found damaged, and not a bound the
// parse would have met had it gone on. Where the deadline and a bound are both
// met, the one met first in reading order is what the reading ends at.
func TestADeadlineThatPassesWhileAnObjectIsParsedEndsTheReading(t *testing.T) {
	var trailer strings.Builder
	members := func(n int) string {
		trailer.Reset()
		trailer.WriteString("<< ")
		for i := 0; i < n; i++ {
			fmt.Fprintf(&trailer, "/K%d 1 ", i)
		}
		trailer.WriteString(">>")
		return trailer.String()
	}
	// A file read through its startxref, whose cross-reference table holds
	// the catalog and free entries past it, and whose trailer is the table's
	// own: a table or a trailer read as damaged would be rebuilt.
	table := func(free int, dict string) []byte {
		var out bytes.Buffer
		out.WriteString("%PDF-1.7\n")
		at := out.Len()
		out.WriteString("1 0 obj\n<< /Type /Catalog >>\nendobj\n")
		xref := out.Len()
		fmt.Fprintf(&out, "xref\n0 %d\n0000000000 65535 f \n%010d 00000 n \n", free+2, at)
		out.WriteString(strings.Repeat("0000000000 65535 f \n", free))
		fmt.Fprintf(&out, "trailer\n%s\nstartxref\n%d\n%%%%EOF\n", dict, xref)
		return out.Bytes()
	}
	scans := 0
	scanObserved = func(int) { scans++ }
	defer func() { scanObserved = nil }()
	for _, c := range []struct {
		name string
		data []byte
		// n is the reading of the deadline that finds it passed, or zero for
		// a deadline that never passes.
		n        int
		deadline bool
		bound    bool
	}{
		// The first reading is the one made before the section; the second
		// is the lexer's, 16 KiB into the table's entries, fewer than the
		// entries the table reads the deadline after.
		{"a table of entries, the deadline passing as they are read", table(entriesPerCheck-2, "<< /Root 1 0 R >>"), 2, true, false},
		{"a trailer within its bounds, the deadline passing in its parse", table(0, members(maxContainerItems)), 3, true, false},
		{"a trailer a member past its bound, the deadline passing in its parse before the bound", table(0, members(maxContainerItems+1)), 3, true, false},
		{"a trailer a member past its bound, and no deadline", table(0, members(maxContainerItems+1)), 0, false, true},
	} {
		t.Run(c.name, func(t *testing.T) {
			scans = 0
			var ctx context.Context = &lexCountdown{Context: context.Background(), n: c.n}
			if c.n == 0 {
				ctx = context.Background()
			}
			_, err := open(ctx, c.data, &inflateBudget{total: 64 << 20, one: 16 << 20})
			t.Logf("opening ended with %v", err)
			if isDeadline(err) != c.deadline || isBound(err) != c.bound {
				t.Fatalf("opening ended with %v: deadline %v bound %v, want deadline %v bound %v", err, isDeadline(err), isBound(err), c.deadline, c.bound)
			}
			if c.deadline && errors.Is(err, errMalformed) {
				t.Fatalf("opening ended with %v, the deadline taken for a defect of the file", err)
			}
			if scans != 0 {
				t.Fatalf("the reader rebuilt the cross-reference %d times; the one it read is not damaged", scans)
			}
		})
	}
}

// An object whose parse the deadline ended is unread, not unreadable: the
// read publishes nothing of it and does not take the cross-reference that
// named it for damaged, so it is neither cached as an object the reader could
// not read nor the start of a rebuild.
func TestAnObjectTheDeadlineEndedIsNotPublishedOrRebuiltFrom(t *testing.T) {
	var out bytes.Buffer
	out.WriteString("%PDF-1.7\n")
	catalog := out.Len()
	out.WriteString("1 0 obj\n<< /Type /Catalog >>\nendobj\n")
	long := out.Len()
	out.WriteString("2 0 obj\n(" + strings.Repeat("s", 4*lexBytesPerCheck) + ")\nendobj\n")
	xref := out.Len()
	fmt.Fprintf(&out, "xref\n0 3\n0000000000 65535 f \n%010d 00000 n \n%010d 00000 n \ntrailer\n<< /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF\n", catalog, long, xref)
	d, err := open(context.Background(), out.Bytes(), &inflateBudget{total: 64 << 20, one: 16 << 20})
	if err != nil {
		t.Fatalf("opening the file: %v", err)
	}
	scans := 0
	scanObserved = func(int) { scans++ }
	defer func() { scanObserved = nil }()
	ctx := &lexCountdown{Context: context.Background(), n: 1}
	d.ctx = ctx
	if v, read := d.objectRead(2); read || v != nil {
		t.Fatalf("the object read as %T, read %v, with the deadline passed inside it", v, read)
	}
	if ctx.reads == 0 {
		t.Fatal("the parse read no deadline")
	}
	if cached, ok := d.cache[2]; ok {
		t.Fatalf("the reader cached %#v for an object the deadline ended", cached)
	}
	if scans != 0 || d.reconstructed {
		t.Fatalf("the reader rebuilt the cross-reference (%d scans) for an object the deadline ended", scans)
	}
	d.ctx = context.Background()
	if v, read := d.objectRead(2); !read || len(v.(String)) != 4*lexBytesPerCheck {
		t.Fatalf("read again with time left, the object read as %T, read %v", v, read)
	}
}
