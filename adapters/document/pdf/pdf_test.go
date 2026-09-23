package pdf

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"math/rand"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"adapters/attachment"
	"adapters/internal/pdfgen"
)

func testOptions() Options {
	return Options{MaxPages: 500, MaxTextBytes: 8 << 20, MaxInflateTotal: 64 << 20, MaxInflateOne: 16 << 20}
}

// normalDocument is three pages: a WinAnsi Helvetica page with accents
// and a ligature by Differences, a composite-font page with a ToUnicode
// map, and a blank page.
func normalDocument(b *pdfgen.Builder) []byte {
	helv := b.Font("Helvetica", "WinAnsiEncoding", "")
	// A Differences entry mapping code 1 to the fi ligature.
	lig := b.Font("Times-Roman", "WinAnsiEncoding", "1 /fi")
	t0 := b.Type0Font([]rune("Composite text"))
	page1 := pdfgen.Text("F1", 12, []string{"Federal Skilled Worker Program", "Minimum requirements", "caf\xe9 na\xefve"}) +
		"BT /F2 12 Tf 1 0 0 1 72 600 Tm (\\001nal) Tj ET\n"
	var codes strings.Builder
	for i := range "Composite text" {
		codes.WriteString(string([]byte{0, byte(i + 1)}))
	}
	page2 := "BT /F3 14 Tf 1 0 0 1 72 700 Tm <" + hexOf(codes.String()) + "> Tj ET\n"
	pages := b.Pages([]pdfgen.Page{
		{Content: page1, Fonts: map[string]int{"F1": helv, "F2": lig}},
		{Content: page2, Fonts: map[string]int{"F3": t0}},
		{Content: ""},
	})
	b.Catalog(pages)
	return b.Bytes()
}

func hexOf(s string) string {
	const digits = "0123456789ABCDEF"
	var sb strings.Builder
	for i := 0; i < len(s); i++ {
		sb.WriteByte(digits[s[i]>>4])
		sb.WriteByte(digits[s[i]&15])
	}
	return sb.String()
}

func extract(t *testing.T, data []byte) *Result {
	t.Helper()
	// The deadline the tests that call this share, scaled like the allowances
	// some of them hold their readings to. An allowance says how long a
	// reading may take; a deadline below it answers instead with a reading
	// that timed out and carries no page, and what fails is the page rather
	// than the clock. The allowance is what bounds the reading here, so the
	// deadline stays above it.
	ctx, cancel := context.WithTimeout(context.Background(), raceFactor*10*time.Second)
	defer cancel()
	return Extract(ctx, data, testOptions())
}

func TestNormalDocumentEveryLayout(t *testing.T) {
	layouts := map[string]func(*pdfgen.Builder){
		"table":              func(b *pdfgen.Builder) {},
		"table-compressed":   func(b *pdfgen.Builder) { b.Compress = true },
		"xref-stream":        func(b *pdfgen.Builder) { b.XrefStream = true; b.Compress = true },
		"object-streams":     func(b *pdfgen.Builder) { b.XrefStream = true; b.ObjectStreams = true; b.Compress = true },
		"junk-before-header": func(b *pdfgen.Builder) { b.Junk = []byte("garbage\r\n") },
		"broken-offsets":     func(b *pdfgen.Builder) { b.BrokenOffsets = 7 },
		"encrypted-rc4-r2":   func(b *pdfgen.Builder) { b.Encrypt = &pdfgen.Encryption{Revision: 2, Owner: "owner", Permissions: -1} },
		"encrypted-rc4-r3": func(b *pdfgen.Builder) {
			b.Compress = true
			b.Encrypt = &pdfgen.Encryption{Revision: 3, Owner: "owner", Permissions: -3904}
		},
		"encrypted-rc4-r4": func(b *pdfgen.Builder) { b.Encrypt = &pdfgen.Encryption{Revision: 4, Owner: "owner", Permissions: -1} },
		"encrypted-aes-r4": func(b *pdfgen.Builder) {
			b.Compress = true
			b.Encrypt = &pdfgen.Encryption{Revision: 4, AES: true, Owner: "owner", Permissions: -1}
		},
		"encrypted-aes-objstm": func(b *pdfgen.Builder) {
			b.XrefStream = true
			b.ObjectStreams = true
			b.Compress = true
			b.Encrypt = &pdfgen.Encryption{Revision: 4, AES: true, Owner: "owner", Permissions: -1}
		},
	}
	for name, configure := range layouts {
		t.Run(name, func(t *testing.T) {
			b := &pdfgen.Builder{}
			configure(b)
			data := normalDocument(b)
			r := extract(t, data)
			if r.Fatal != nil {
				t.Fatalf("fatal: %+v", *r.Fatal)
			}
			if len(r.Pages) != 3 || r.PageCount != 3 || r.Truncated {
				t.Fatalf("pages: %d/%d truncated=%v problems=%v", len(r.Pages), r.PageCount, r.Truncated, r.Problems)
			}
			p1 := r.Pages[0]
			// The last line sits far below the others, which the layout heuristic
			// reads as a paragraph break.
			want := "Federal Skilled Worker Program\nMinimum requirements\ncafé naïve\n\nﬁnal"
			if p1.Text != want || p1.Status != PageOK || p1.Unmapped != 0 {
				t.Errorf("page 1: %q (%s, unmapped %d), want %q", p1.Text, p1.Status, p1.Unmapped, want)
			}
			if r.Pages[1].Text != "Composite text" || r.Pages[1].Status != PageOK {
				t.Errorf("page 2: %q (%s)", r.Pages[1].Text, r.Pages[1].Status)
			}
			if r.Pages[2].Status != PageNoText || r.Pages[2].Text != "" {
				t.Errorf("page 3: %q (%s)", r.Pages[2].Text, r.Pages[2].Status)
			}
			if b.Encrypt != nil && (r.Encryption == nil || !r.Encryption.Opened || r.Encryption.Handler == nil || *r.Encryption.Handler != "Standard" || r.Encryption.Revision == nil || *r.Encryption.Revision != int64(b.Encrypt.Revision)) {
				t.Errorf("encryption: %+v", r.Encryption)
			}
			if b.Encrypt == nil && r.Encryption != nil {
				t.Errorf("encryption reported for a plain document: %+v", r.Encryption)
			}
			if len(r.Problems) != 0 {
				t.Errorf("problems: %+v", r.Problems)
			}
			crossCheckWithPoppler(t, data, []string{"Federal Skilled Worker Program", "Minimum requirements", "café naïve", "Composite text"})
		})
	}
}

// crossCheckWithPoppler holds the generator's output to an independent
// reader when one is on the machine: pdftotext must find the same words.
// Skipped, not failed, where it is absent (CI has none).
func crossCheckWithPoppler(t *testing.T, data []byte, words []string) {
	t.Helper()
	tool, err := exec.LookPath("pdftotext")
	if err != nil {
		return
	}
	dir := t.TempDir()
	file := filepath.Join(dir, "doc.pdf")
	if err := os.WriteFile(file, data, 0o600); err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command(tool, file, "-").CombinedOutput()
	if err != nil {
		t.Fatalf("pdftotext refused the generated document: %v\n%s", err, out)
	}
	for _, w := range words {
		if !bytes.Contains(out, []byte(w)) {
			t.Errorf("pdftotext did not find %q in the generated document:\n%s", w, out)
		}
	}
}

func TestUserPasswordIsNotOpened(t *testing.T) {
	b := &pdfgen.Builder{Encrypt: &pdfgen.Encryption{Revision: 3, User: "secret", Owner: "owner", Permissions: -1}}
	data := normalDocument(b)
	r := extract(t, data)
	if r.Fatal == nil || r.Fatal.Code != "pdf-encrypted" || !strings.Contains(r.Fatal.Message, "user password") {
		t.Fatalf("fatal: %+v", r.Fatal)
	}
	if r.Encryption == nil || r.Encryption.Opened || r.Encryption.Revision == nil || *r.Encryption.Revision != 3 {
		t.Fatalf("encryption: %+v", r.Encryption)
	}
	if len(r.Pages) != 0 {
		t.Fatal("pages listed for a document that was not opened")
	}
}

func TestScannedPagesNeedOCR(t *testing.T) {
	b := &pdfgen.Builder{}
	img := b.Image()
	helv := b.Font("Helvetica", "WinAnsiEncoding", "")
	pages := b.Pages([]pdfgen.Page{
		{Content: "q 612 0 0 792 0 0 cm /Im1 Do Q\n", XObjects: map[string]int{"Im1": img}},
		{Content: pdfgen.Text("F1", 12, []string{"A text page"}), Fonts: map[string]int{"F1": helv}},
		{Content: "q 100 0 0 100 0 0 cm BI /W 2 /H 2 /CS /G /BPC 8 ID \x00\xff\xff\x00 EI Q\n"},
		{Content: "0 0 m 100 100 l S\n"},
	})
	b.Catalog(pages)
	r := extract(t, b.Bytes())
	if r.Fatal != nil {
		t.Fatalf("fatal: %+v", *r.Fatal)
	}
	want := []PageStatus{PageNeedsOCR, PageOK, PageNeedsOCR, PageNoText}
	for i, p := range r.Pages {
		if p.Status != want[i] {
			t.Errorf("page %d: %s, want %s (%q)", i+1, p.Status, want[i], p.Text)
		}
	}
	if r.Pages[1].Text != "A text page" {
		t.Errorf("page 2 text %q", r.Pages[1].Text)
	}
}

func TestInflateBombIsStopped(t *testing.T) {
	b := &pdfgen.Builder{Compress: true}
	helv := b.Font("Helvetica", "WinAnsiEncoding", "")
	// A content stream of 40 MiB of spaces compresses to a few kilobytes.
	bomb := strings.Repeat(" ", 40<<20)
	pages := b.Pages([]pdfgen.Page{{Content: bomb, Fonts: map[string]int{"F1": helv}}, {Content: pdfgen.Text("F1", 12, []string{"after"}), Fonts: map[string]int{"F1": helv}}})
	b.Catalog(pages)
	data := b.Bytes()
	if len(data) > 1<<20 {
		t.Fatalf("the bomb did not compress: %d bytes", len(data))
	}
	ctx, cancel := context.WithTimeout(context.Background(), raceFactor*10*time.Second)
	defer cancel()
	opt := testOptions()
	opt.MaxInflateOne = 1 << 20
	r := Extract(ctx, data, opt)
	if r.Fatal != nil {
		t.Fatalf("fatal: %+v", *r.Fatal)
	}
	if len(r.Pages) != 2 || r.Pages[0].Status != PageFailed || r.Pages[1].Text != "after" {
		t.Fatalf("pages: %+v", r.Pages)
	}
	if len(r.Problems) != 1 || r.Problems[0].Code != "stream-over-bound" || r.Problems[0].Page != 1 {
		t.Fatalf("problems: %+v", r.Problems)
	}
}

func TestPageBoundTruncates(t *testing.T) {
	document := func(n int) []byte {
		b := &pdfgen.Builder{}
		helv := b.Font("Helvetica", "WinAnsiEncoding", "")
		var pages []pdfgen.Page
		for i := 0; i < n; i++ {
			pages = append(pages, pdfgen.Page{Content: pdfgen.Text("F1", 12, []string{"Page"}), Fonts: map[string]int{"F1": helv}})
		}
		b.Catalog(b.Pages(pages))
		return b.Bytes()
	}
	opt := testOptions()
	opt.MaxPages = 50
	for _, n := range []int{51, 60} {
		r := Extract(context.Background(), document(n), opt)
		if r.Fatal != nil || len(r.Pages) != 50 || r.PageCount != 50 || !r.Truncated {
			t.Fatalf("%d pages: listed %d count %d truncated %v fatal %+v", n, len(r.Pages), r.PageCount, r.Truncated, r.Fatal)
		}
		if len(r.Problems) != 1 || r.Problems[0].Code != "pdf-pages-over-bound" {
			t.Fatalf("%d pages: problems %+v", n, r.Problems)
		}
	}
	// A document of exactly maxPages pages is not past the bound.
	r := Extract(context.Background(), document(50), opt)
	if r.Fatal != nil || len(r.Pages) != 50 || r.PageCount != 50 || r.Truncated || len(r.Problems) != 0 {
		t.Fatalf("50 pages: listed %d count %d truncated %v problems %+v", len(r.Pages), r.PageCount, r.Truncated, r.Problems)
	}
}

func TestTextBoundCutsWholePages(t *testing.T) {
	b := &pdfgen.Builder{}
	helv := b.Font("Helvetica", "WinAnsiEncoding", "")
	b.Catalog(b.Pages([]pdfgen.Page{
		{Content: pdfgen.Text("F1", 12, []string{strings.Repeat("a", 40)}), Fonts: map[string]int{"F1": helv}},
		{Content: pdfgen.Text("F1", 12, []string{strings.Repeat("b", 40)}), Fonts: map[string]int{"F1": helv}},
		{Content: pdfgen.Text("F1", 12, []string{"c"}), Fonts: map[string]int{"F1": helv}},
	}))
	opt := testOptions()
	opt.MaxTextBytes = 64
	r := Extract(context.Background(), b.Bytes(), opt)
	if r.Fatal != nil || len(r.Pages) != 1 || r.Pages[0].Chars() != 40 || !r.Truncated {
		t.Fatalf("pages %+v truncated %v fatal %+v", r.Pages, r.Truncated, r.Fatal)
	}
	if len(r.Problems) != 1 || r.Problems[0].Code != "text-over-bound" || r.Problems[0].Page != 2 {
		t.Fatalf("problems: %+v", r.Problems)
	}
	// Exactly at the bound is within it.
	opt.MaxTextBytes = 40
	r = Extract(context.Background(), b.Bytes(), opt)
	if len(r.Pages) != 1 || r.Problems[0].Page != 2 {
		t.Fatalf("at the bound: %+v %+v", r.Pages, r.Problems)
	}
}

func TestMalformedInputsNeverPanic(t *testing.T) {
	good := normalDocument(&pdfgen.Builder{Compress: true})
	inputs := map[string][]byte{
		"empty":         {},
		"not-a-pdf":     []byte("hello world, this is text"),
		"header-only":   []byte("%PDF-1.4\n"),
		"truncated-1/2": good[:len(good)/2],
		"truncated-3/4": good[:len(good)*3/4],
		"no-trailer":    good[:bytes.LastIndex(good, []byte("xref"))],
		"nul-filled":    append([]byte("%PDF-1.4\n"), make([]byte, 4096)...),
	}
	for name, data := range inputs {
		t.Run(name, func(t *testing.T) {
			r := extract(t, data)
			if r == nil {
				t.Fatal("no result")
			}
			if r.Fatal == nil && len(r.Pages) == 0 {
				t.Fatalf("neither fatal nor pages: %+v", r)
			}
			if r.Fatal != nil && (len(r.Pages) != 0 || r.PageCount != 0 || r.Truncated) {
				t.Fatalf("a fatal result lists, counts or truncates: %+v", r)
			}
		})
	}
}

func TestTruncatedDocumentRecoversPagesThatSurvive(t *testing.T) {
	b := &pdfgen.Builder{}
	data := normalDocument(b)
	cut := data[:bytes.LastIndex(data, []byte("xref"))]
	r := extract(t, cut)
	if r.Fatal != nil {
		t.Fatalf("fatal: %+v", *r.Fatal)
	}
	if len(r.Pages) != 3 || !strings.HasPrefix(r.Pages[0].Text, "Federal Skilled Worker Program") {
		t.Fatalf("pages: %+v", r.Pages)
	}
}

// A deadline already passed ends the walk at its first check: nothing is
// counted or listed, and the record is truncated.
func TestDeadlinePassedBeforeTheWalk(t *testing.T) {
	b := &pdfgen.Builder{}
	data := normalDocument(b)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	r := Extract(ctx, data, testOptions())
	if r.Fatal != nil || !r.TimedOut || !r.Truncated || r.PageCount != 0 || len(r.Pages) != 0 || len(r.Problems) != 1 || r.Problems[0].Code != "timeout" {
		t.Fatalf("fatal %+v timedOut %v truncated %v count %d pages %d problems %+v", r.Fatal, r.TimedOut, r.Truncated, r.PageCount, len(r.Pages), r.Problems)
	}
}

// countdown is a context whose deadline passes at its nth check.
type countdown struct {
	context.Context
	left int
	done chan struct{}
}

func newCountdown(n int) *countdown {
	return &countdown{Context: context.Background(), left: n, done: make(chan struct{})}
}

func (c *countdown) Err() error {
	c.left--
	if c.left < 0 {
		select {
		case <-c.done:
		default:
			close(c.done)
		}
		return context.DeadlineExceeded
	}
	return nil
}

func (c *countdown) Done() <-chan struct{} { return c.done }

// doneAfter is a context whose deadline passes at the nth call of Done: the
// channel Done returns is closed from that call, and Err reports the deadline
// once it is. In this package only the interpreter's checkpoints call Done --
// the one between operators, the one within an operator that shows a string,
// and the one before a form is read -- so the deadline passes at one of those
// and at no other. The checks made while a document is opened read Err.
type doneAfter struct {
	context.Context
	n, calls int
	done     chan struct{}
}

func newDoneAfter(n int) *doneAfter {
	return &doneAfter{Context: context.Background(), n: n, done: make(chan struct{})}
}

func (c *doneAfter) Done() <-chan struct{} {
	c.calls++
	if c.calls == c.n {
		close(c.done)
	}
	return c.done
}

func (c *doneAfter) Err() error {
	select {
	case <-c.done:
		return context.DeadlineExceeded
	default:
		return nil
	}
}

// A deadline that passes at a checkpoint inside a page's content interrupts
// that page: it and every later page are not listed, one timeout is
// recorded, and the pages before it are listed -- whether or not the page's
// text had already gone past the budget. A page whose content fails at the
// operator just before a checkpoint that would find the deadline passed is
// failed, not interrupted, and the deadline interrupts the page after it.
func TestDeadlineBetweenOperators(t *testing.T) {
	b := &pdfgen.Builder{}
	helv := b.Font("Helvetica", "WinAnsiEncoding", "")
	fonts := map[string]int{"F1": helv}
	first := pdfgen.Page{Content: pdfgen.Text("F1", 12, []string{"one"}), Fonts: fonts}
	// The text, then enough operators to reach several checkpoints.
	operators := strings.Repeat("q Q ", 2*operatorsPerCheck)
	long := pdfgen.Page{Content: pdfgen.Text("F1", 12, []string{"two"}) + operators, Fonts: fonts}
	// The text is five operators; the graphics state saved past its bound is
	// the last operator before the checkpoint at operatorsPerCheck.
	failing := pdfgen.Page{Content: pdfgen.Text("F1", 12, []string{"two"}) + strings.Repeat("q Q ", (operatorsPerCheck-5-maxGraphicsStates-1)/2) + strings.Repeat("q ", maxGraphicsStates+1) + "\n" + operators, Fonts: fonts}
	document := func(pages ...pdfgen.Page) []byte {
		b.Catalog(b.Pages(pages))
		return b.Bytes()
	}
	// The checkpoints the first page reaches, and those the first two reach.
	calibrate := func(data []byte) int {
		c := newDoneAfter(-1)
		if r := Extract(c, data, testOptions()); r.Fatal != nil || len(r.Problems) != 0 {
			t.Fatalf("calibration: fatal %+v problems %+v", r.Fatal, r.Problems)
		}
		return c.calls
	}
	firstCalls := calibrate(document(first))
	if both := calibrate(document(first, long)); both <= firstCalls+2 {
		t.Fatalf("the second page reaches %d checkpoints; the test needs more than 2", both-firstCalls)
	}
	// The second checkpoint of the second page.
	at := firstCalls + 2

	interrupted := func(t *testing.T, opt Options) {
		c := newDoneAfter(at)
		r := Extract(c, document(first, long, first), opt)
		if c.calls != at {
			t.Fatalf("the deadline passed at checkpoint %d and interpretation went on to %d", at, c.calls)
		}
		if !r.TimedOut || !r.Truncated || r.Fatal != nil || r.PageCount != 3 {
			t.Fatalf("timedOut %v truncated %v fatal %+v count %d", r.TimedOut, r.Truncated, r.Fatal, r.PageCount)
		}
		if len(r.Pages) != 1 || r.Pages[0].Number != 1 || r.Pages[0].Text != "one" {
			t.Fatalf("pages %+v", r.Pages)
		}
		if len(r.Problems) != 1 || r.Problems[0].Code != "timeout" {
			t.Fatalf("problems %+v", r.Problems)
		}
	}
	t.Run("within the budget", func(t *testing.T) { interrupted(t, testOptions()) })
	t.Run("past the budget", func(t *testing.T) {
		opt := testOptions()
		opt.MaxTextBytes = len("one")
		interrupted(t, opt)
	})
	t.Run("after the content failed", func(t *testing.T) {
		c := newDoneAfter(at)
		r := Extract(c, document(first, failing, first), testOptions())
		if !r.TimedOut || r.Fatal != nil || c.calls != at || len(r.Pages) != 2 || r.Pages[0].Text != "one" || r.Pages[1].Status != PageFailed {
			t.Fatalf("timedOut %v fatal %+v checkpoints %d pages %+v problems %+v", r.TimedOut, r.Fatal, c.calls, r.Pages, r.Problems)
		}
		if len(r.Problems) != 2 || r.Problems[0].Code != "pdf-page-failed" || r.Problems[0].Page != 2 || r.Problems[1].Code != "timeout" {
			t.Fatalf("problems %+v", r.Problems)
		}
	})
}

// A form is read each time it is drawn, and the deadline is checked before
// each reading: a page that draws a form ten times more checks it ten times
// more, and a deadline that passes at the check before a draw interrupts the
// page.
func TestDeadlineBeforeEachFormIsRead(t *testing.T) {
	b := &pdfgen.Builder{}
	helv := b.Font("Helvetica", "WinAnsiEncoding", "")
	form := b.Add(pdfgen.Object{Body: "<< /Type /XObject /Subtype /Form /BBox [0 0 1 1] >>", Stream: []byte("q Q\n")})
	document := func(draws int) []byte {
		page := pdfgen.Page{Content: pdfgen.Text("F1", 12, []string{"one"}) + strings.Repeat("/X1 Do\n", draws), Fonts: map[string]int{"F1": helv}, XObjects: map[string]int{"X1": form}}
		b.Catalog(b.Pages([]pdfgen.Page{page}))
		return b.Bytes()
	}
	checks := func(data []byte) int {
		c := newDoneAfter(-1)
		if r := Extract(c, data, testOptions()); r.Fatal != nil || len(r.Pages) != 1 || len(r.Problems) != 0 {
			t.Fatalf("fatal %+v pages %+v problems %+v", r.Fatal, r.Pages, r.Problems)
		}
		return c.calls
	}
	base := checks(document(10))
	if more := checks(document(20)); more != base+10 {
		t.Fatalf("ten draws more made %d checks more", more-base)
	}
	c := newDoneAfter(base - 5)
	r := Extract(c, document(10), testOptions())
	if !r.TimedOut || r.Fatal != nil || len(r.Pages) != 0 || len(r.Problems) != 1 || r.Problems[0].Code != "timeout" || c.calls != base-5 {
		t.Fatalf("timedOut %v fatal %+v checks %d pages %+v problems %+v", r.TimedOut, r.Fatal, c.calls, r.Pages, r.Problems)
	}
}

// One operator that shows a long string reads the deadline within itself, on
// the cadence the operator loop uses: a page whose one Tj shows far more
// glyphs than that cadence is interrupted where the deadline falls, and a
// page the deadline does not interrupt reads it once per that many glyphs.
func TestDeadlineWithinOneOperatorThatShowsAString(t *testing.T) {
	const glyphs = 5 * operatorsPerCheck
	b := &pdfgen.Builder{}
	helv := b.Font("Helvetica", "WinAnsiEncoding", "")
	b.Catalog(b.Pages([]pdfgen.Page{{
		Content: shown(strings.Repeat("A", glyphs), 700),
		Fonts:   map[string]int{"F1": helv},
	}}))
	data := b.Bytes()
	// With no deadline: the page is listed, and the deadline was read once
	// between operators and once per operatorsPerCheck glyphs shown.
	whole := newDoneAfter(-1)
	r := Extract(whole, data, testOptions())
	if r.Fatal != nil || len(r.Pages) != 1 || r.Pages[0].Chars() != glyphs || len(r.Problems) != 0 {
		t.Fatalf("fatal %+v pages %+v problems %+v", r.Fatal, r.Pages, r.Problems)
	}
	if want := 1 + glyphs/operatorsPerCheck; whole.calls != want {
		t.Fatalf("%d checks, want %d", whole.calls, want)
	}
	// A deadline that passes at the first check within the operator: the page
	// is not listed, and the string was not shown to its end.
	cut := newDoneAfter(2)
	r = Extract(cut, data, testOptions())
	if !r.TimedOut || !r.Truncated || r.Fatal != nil || len(r.Pages) != 0 {
		t.Fatalf("timedOut %v truncated %v fatal %+v pages %+v", r.TimedOut, r.Truncated, r.Fatal, r.Pages)
	}
	if len(r.Problems) != 1 || r.Problems[0].Code != "timeout" || cut.calls != 2 {
		t.Fatalf("problems %+v after %d checks", r.Problems, cut.calls)
	}
}

// Wherever the deadline falls -- at every check in turn -- the result is
// one the note allows: timeout once, no page past the one the deadline
// interrupted, truncated, and a walk that ended at the deadline lists
// nothing. Some check falls between two pages, and there the pages before
// it are listed.
func TestDeadlineAtEveryCheck(t *testing.T) {
	b := &pdfgen.Builder{}
	helv := b.Font("Helvetica", "WinAnsiEncoding", "")
	var pages []pdfgen.Page
	for i := 0; i < 3; i++ {
		pages = append(pages, pdfgen.Page{Content: pdfgen.Text("F1", 12, []string{"Page text"}), Fonts: map[string]int{"F1": helv}})
	}
	b.Catalog(b.Pages(pages))
	data := b.Bytes()
	sawBetweenPages := false
	for n := 0; n < 40; n++ {
		r := Extract(newCountdown(n), data, testOptions())
		if !r.TimedOut {
			if r.Fatal != nil || len(r.Pages) != 3 || r.Truncated {
				t.Fatalf("check %d: no timeout and an incomplete result: %+v", n, r)
			}
			continue
		}
		timeouts := 0
		for _, p := range r.Problems {
			if p.Code == "timeout" {
				timeouts++
			}
		}
		if timeouts != 1 || !r.Truncated || r.Fatal != nil || len(r.Pages) >= 3 {
			t.Fatalf("check %d: timeouts %d truncated %v fatal %+v listed %d", n, timeouts, r.Truncated, r.Fatal, len(r.Pages))
		}
		if r.PageCount < 3 && len(r.Pages) != 0 {
			t.Fatalf("check %d: the walk ended at the deadline and pages are listed", n)
		}
		if r.PageCount == 3 && len(r.Pages) > 0 {
			sawBetweenPages = true
		}
	}
	if !sawBetweenPages {
		t.Fatal("no check fell between two pages")
	}
}

// The page builder's streaming normalisation is the note's: for the vectors
// and for random texts it keeps exactly attachment.NormalizeText's result,
// and it says the text is past a limit exactly when that result is longer.
func TestStreamNormalizerIsTheNormalisation(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "..", "testdata", "attachments", "normalisation-v1.json"))
	if err != nil {
		t.Fatal(err)
	}
	var file struct {
		Vectors []struct{ Name, Input, Output string }
	}
	if err := json.Unmarshal(data, &file); err != nil || len(file.Vectors) == 0 {
		t.Fatalf("vectors: %v", err)
	}
	stream := func(text string, limit int) (string, bool) {
		s := streamNormalizer{limit: limit}
		for _, r := range text {
			s.write(r)
		}
		return s.text(), s.over
	}
	for _, v := range file.Vectors {
		if got, over := stream(v.Input, 1<<20); over || got != v.Output {
			t.Errorf("%s: %q (over %v), want %q", v.Name, got, over, v.Output)
		}
	}
	alphabet := []string{"a", "\xc3\xa9", " ", "\t", "\n", "\r", "\x00", "\x0b", "\x7f", "\xef\xbb\xbf", "\xc2\xa0", "\xef\xbf\xbd"}
	rng := rand.New(rand.NewSource(7))
	for i := 0; i < 50000; i++ {
		var sb strings.Builder
		for n := rng.Intn(14); n > 0; n-- {
			sb.WriteString(alphabet[rng.Intn(len(alphabet))])
		}
		text := sb.String()
		want := attachment.NormalizeText(text)
		limit := rng.Intn(12)
		got, over := stream(text, limit)
		if over != (len(want) > limit) {
			t.Fatalf("%q under limit %d: over %v, and the normalisation is %d bytes", text, limit, over, len(want))
		}
		if !over && got != want {
			t.Fatalf("%q: kept %q, want %q", text, got, want)
		}
	}
}

// The text budget is decided on the normalised text: blank lines and
// spaces the normalisation removes do not count against it.
func TestBudgetIsDecidedOnNormalisedText(t *testing.T) {
	b := &pdfgen.Builder{}
	helv := b.Font("Helvetica", "WinAnsiEncoding", "")
	b.Catalog(b.Pages([]pdfgen.Page{
		{Content: pdfgen.Text("F1", 12, []string{"      ", "      ", "ab", "      "}), Fonts: map[string]int{"F1": helv}},
	}))
	opt := testOptions()
	opt.MaxTextBytes = 2
	r := Extract(context.Background(), b.Bytes(), opt)
	if r.Fatal != nil || len(r.Pages) != 1 || r.Pages[0].Text != "ab" || len(r.Problems) != 0 {
		t.Fatalf("pages %+v problems %+v", r.Pages, r.Problems)
	}
	opt.MaxTextBytes = 1
	r = Extract(context.Background(), b.Bytes(), opt)
	if len(r.Pages) != 0 || len(r.Problems) != 1 || r.Problems[0].Code != "text-over-bound" || !r.Truncated {
		t.Fatalf("past the budget: pages %+v problems %+v", r.Pages, r.Problems)
	}
}

// A page of blank text over an image needs OCR; a page whose only glyph is
// a no-break space is text, since U+00A0 is not blank.
func TestPageOutcomesFollowTheNormalisedText(t *testing.T) {
	b := &pdfgen.Builder{}
	img := b.Image()
	helv := b.Font("Helvetica", "WinAnsiEncoding", "")
	// WinAnsi maps its code for a no-break space to the space glyph; a
	// composite font's ToUnicode map says U+00A0 itself.
	nbsp := b.Type0Font([]rune{0xA0})
	b.Catalog(b.Pages([]pdfgen.Page{
		{Content: pdfgen.Text("F1", 12, []string{"   "}) + "q 612 0 0 792 0 0 cm /Im1 Do Q\n", Fonts: map[string]int{"F1": helv}, XObjects: map[string]int{"Im1": img}},
		{Content: "BT /F2 12 Tf 1 0 0 1 72 700 Tm <0001> Tj ET\n", Fonts: map[string]int{"F2": nbsp}},
		{Content: pdfgen.Text("F1", 12, []string{"   "}), Fonts: map[string]int{"F1": helv}},
	}))
	r := extract(t, b.Bytes())
	want := []PageStatus{PageNeedsOCR, PageOK, PageNoText}
	if r.Fatal != nil || len(r.Pages) != 3 {
		t.Fatalf("fatal %+v pages %+v", r.Fatal, r.Pages)
	}
	for i, p := range r.Pages {
		if p.Status != want[i] {
			t.Errorf("page %d: %s %q, want %s", i+1, p.Status, p.Text, want[i])
		}
	}
}

// A walk that meets a defect ends the document: a page-tree node that is
// not a dictionary, or a tree deeper than the reader walks.
func TestPageTreeDefectsArePDFMalformed(t *testing.T) {
	// An unreadable node beside a readable subtree: skipping it would still
	// count the readable page, so only refusing the document passes.
	unreadable := func() []byte {
		b := &pdfgen.Builder{}
		helv := b.Font("Helvetica", "WinAnsiEncoding", "")
		good := b.Pages([]pdfgen.Page{{Content: pdfgen.Text("F1", 12, []string{"readable"}), Fonts: map[string]int{"F1": helv}}})
		bad := b.Add(pdfgen.Object{Body: "(not a node)"})
		root := b.Add(pdfgen.Object{Body: fmt.Sprintf("<< /Type /Pages /Kids [%d 0 R %d 0 R] /Count 2 >>", good, bad)})
		b.Catalog(root)
		return b.Bytes()
	}
	deep := func() []byte {
		b := &pdfgen.Builder{}
		helv := b.Font("Helvetica", "WinAnsiEncoding", "")
		leaf := b.Pages([]pdfgen.Page{{Content: pdfgen.Text("F1", 12, []string{"deep"}), Fonts: map[string]int{"F1": helv}}})
		node := leaf
		for i := 0; i < maxPageTreeDepth+2; i++ {
			node = b.Add(pdfgen.Object{Body: fmt.Sprintf("<< /Type /Pages /Kids [%d 0 R] /Count 1 >>", node)})
		}
		b.Catalog(node)
		return b.Bytes()
	}
	// A node whose /Kids is present and cannot be read, or is not an array,
	// beside a readable page.
	kids := func(node string) []byte {
		b := &pdfgen.Builder{}
		helv := b.Font("Helvetica", "WinAnsiEncoding", "")
		good := b.Pages([]pdfgen.Page{{Content: pdfgen.Text("F1", 12, []string{"readable"}), Fonts: map[string]int{"F1": helv}}})
		bad := b.Add(pdfgen.Object{Body: strings.ReplaceAll(node, "FONT", fmt.Sprint(helv))})
		root := b.Add(pdfgen.Object{Body: fmt.Sprintf("<< /Type /Pages /Kids [%d 0 R %d 0 R] /Count 2 >>", good, bad)})
		b.Catalog(root)
		return b.Bytes()
	}
	defects := map[string][]byte{
		"unreadable node":                     unreadable(),
		"deep tree":                           deep(),
		"kids naming no object":               kids("<< /Type /Pages /Kids 999 0 R /Count 1 >>"),
		"kids naming no object, with no type": kids("<< /Kids 999 0 R /Count 1 >>"),
		"kids that are a string":              kids("<< /Type /Pages /Kids (not an array) /Count 1 >>"),
		"kids that are a dictionary":          kids("<< /Type /Pages /Kids FONT 0 R /Count 1 >>"),
	}
	for name, data := range defects {
		r := extract(t, data)
		if r.Fatal == nil || r.Fatal.Code != "pdf-malformed" || len(r.Pages) != 0 || r.PageCount != 0 || r.Truncated {
			t.Errorf("%s: fatal %+v pages %d count %d truncated %v", name, r.Fatal, len(r.Pages), r.PageCount, r.Truncated)
		}
	}
	// A /Kids that is null or empty holds no page, and is no defect.
	for name, data := range map[string][]byte{
		"null kids":  kids("<< /Type /Pages /Kids null /Count 0 >>"),
		"empty kids": kids("<< /Type /Pages /Kids [] /Count 0 >>"),
	} {
		r := extract(t, data)
		if r.Fatal != nil || r.PageCount != 1 || len(r.Pages) != 1 || r.Pages[0].Text != "readable" || len(r.Problems) != 0 {
			t.Errorf("%s: fatal %+v pages %+v count %d problems %+v", name, r.Fatal, r.Pages, r.PageCount, r.Problems)
		}
	}
}

// A page past the operators the reader interprets is a failed page, and the
// pages around it are read.
func TestOperatorBoundFailsThePage(t *testing.T) {
	if testing.Short() {
		t.Skip("interprets eight million operators")
	}
	// A page of exactly the bound's operators, and one operator more.
	document := func(extra string) []byte {
		b := &pdfgen.Builder{Compress: true}
		helv := b.Font("Helvetica", "WinAnsiEncoding", "")
		b.Catalog(b.Pages([]pdfgen.Page{
			{Content: strings.Repeat("q Q ", maxOperators/2) + extra, Fonts: map[string]int{"F1": helv}},
			{Content: pdfgen.Text("F1", 12, []string{"after"}), Fonts: map[string]int{"F1": helv}},
		}))
		return b.Bytes()
	}
	opt := testOptions()
	opt.MaxInflateOne = 64 << 20
	r := Extract(context.Background(), document(""), opt)
	if r.Fatal != nil || len(r.Pages) != 2 || r.Pages[0].Status != PageNoText || r.Pages[1].Text != "after" || len(r.Problems) != 0 {
		t.Fatalf("at the bound: fatal %+v pages %+v problems %+v", r.Fatal, r.Pages, r.Problems)
	}
	r = Extract(context.Background(), document("q "), opt)
	if r.Fatal != nil || len(r.Pages) != 2 || r.Pages[0].Status != PageFailed || r.Pages[1].Text != "after" {
		t.Fatalf("one operator past it: fatal %+v pages %+v", r.Fatal, r.Pages)
	}
	if len(r.Problems) != 1 || r.Problems[0].Code != "pdf-page-failed" || r.Problems[0].Page != 1 {
		t.Fatalf("one operator past it: problems %+v", r.Problems)
	}
}

// The deadline is consulted between operators often enough to interrupt a
// page: 32,768 operators more reach at least eight checkpoints more, so no
// more than 4,096 operators run between two checks. adapters/README.md
// states that interval, and TestREADMEStatesTheStructureBounds holds it to
// operatorsPerCheck.
func TestTheDeadlineIsCheckedEveryFewThousandOperators(t *testing.T) {
	const added, least = 32768, 8
	b := &pdfgen.Builder{Compress: true}
	helv := b.Font("Helvetica", "WinAnsiEncoding", "")
	document := func(ops int) []byte {
		b.Catalog(b.Pages([]pdfgen.Page{{Content: pdfgen.Text("F1", 12, []string{"one"}) + strings.Repeat("q Q ", ops/2), Fonts: map[string]int{"F1": helv}}}))
		return b.Bytes()
	}
	checks := func(data []byte) int {
		c := newDoneAfter(-1)
		if r := Extract(c, data, testOptions()); r.Fatal != nil || len(r.Pages) != 1 || len(r.Problems) != 0 {
			t.Fatalf("fatal %+v pages %+v problems %+v", r.Fatal, r.Pages, r.Problems)
		}
		return c.calls
	}
	base := checks(document(0))
	if more := checks(document(added)) - base; more < least {
		t.Fatalf("%d operators more made %d checks more, want at least %d", added, more, least)
	}
}
