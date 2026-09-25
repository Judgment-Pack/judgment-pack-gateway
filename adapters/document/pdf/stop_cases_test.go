package pdf

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

// The cases below are the files the reviews of #160 found a deadline lost
// in, each read the way the review read it, with what the document holds
// after it and what it says checked.

// stopDoc is a document built by hand over data, reading the deadline of
// ctx, with room enough to read what the cases hold.
func stopDoc(data string, ctx context.Context) *Document {
	return &Document{data: []byte(data), ctx: ctx, xref: map[int]xrefEntry{}, trailer: Dict{}, cache: map[int]object{}, objStms: map[int]*objStm{}, resolving: map[int]bool{}, budget: &inflateBudget{total: 64 << 20, one: 16 << 20}}
}

// The integer lookahead: object 4, in an object stream whose header the
// document holds, is the integer 1 followed by a comment the lookahead for a
// reference reads the deadline in. The integer is not published as the
// object, nor anything else of it.
func TestStopScalarLookahead(t *testing.T) {
	raw := "4 0 1 %" + strings.Repeat("x", 40000) + "\n"
	d := stopDoc(strings.Repeat(" ", len(raw)), &stopReads{Context: context.Background(), n: 1})
	d.xref[4] = xrefEntry{inStream: true, stmNum: 9}
	d.objStmHeaders = map[int]*objStmParsed{9: {data: []byte(raw), offsets: map[int]int{4: 4}, order: []int{4}, offsetAt: []int{4}}}
	v, read := d.objectRead(4)
	if read || v != nil || len(d.cache) != 0 || d.stopped() == nil {
		t.Fatalf("read %v object %#v cache %v stopped %v: the deadline's partial scalar was taken for the object", read, v, d.cache, d.stopped())
	}
}

// The integer lookahead's third token: "1 2", a comment of 40,000 bytes and
// then "R", the deadline passing inside the comment, which the lookahead for
// the keyword that would make the integers a reference reads. The parse ends
// at the deadline, and the integer is not taken for the object.
func TestStopLookaheadThirdToken(t *testing.T) {
	d := stopDoc("1 2 %"+strings.Repeat("x", 40000)+"\nR", &stopReads{Context: context.Background(), n: 1})
	p := &parser{lex: newLexer(d.data, 0).within(d.budgeted()), allow: d.budgeted()}
	if v, err := p.parseObject(0); v != nil || !isDeadline(err) || d.stopped() == nil {
		t.Fatalf("parsed %#v, %v, stopped %v: the deadline in the third token was lost", v, err, d.stopped())
	}
}

// Resolving an object stream the deadline stops: stream 9 carries a string
// its lexer reads the deadline in. Object 4 in it is unread, nothing is
// cached, and the stream is not marked tried. The same object read again in
// the same document, with time left, is the stop still; read in a document
// made again over the same bytes, it reads.
func TestStopResolveStream(t *testing.T) {
	raw := "9 0 obj << /Type /ObjStm /N 1 /First 4 /A (" + strings.Repeat("x", 40000) + ") /Length 5 >>stream\n4 0 1\nendstream\nendobj\n"
	made := func(ctx context.Context) *Document {
		d := stopDoc(raw, ctx)
		d.xref[9] = xrefEntry{offset: 0}
		d.xref[4] = xrefEntry{inStream: true, stmNum: 9}
		return d
	}
	d := made(&stopReads{Context: context.Background(), n: 1})
	v, read := d.objectRead(4)
	_, tried := d.objStms[9]
	if read || v != nil || tried || len(d.cache) != 0 {
		t.Fatalf("read %v object %#v tried %v cache %v: the deadline was kept as a stream that could not be read", read, v, tried, d.cache)
	}
	d.ctx = context.Background()
	if v, read = d.objectRead(4); read || v != nil || len(d.cache) != 0 || len(d.objStms) != 0 || d.stopped() == nil {
		t.Fatalf("read again in the stopped document with time left: %#v, read %v, cached %v, streams %v", v, read, d.cache, d.objStms)
	}
	if v, read = made(context.Background()).objectRead(4); !read || v != int64(1) {
		t.Fatalf("read again in a document made again: %#v, read %v", v, read)
	}
}

// A /Length the deadline stops: stream 9's /Length is object 10, the integer
// 1 followed by a comment its lookahead reads the deadline in, and the file's
// stream ends are already indexed. The stream is not read, and nothing is
// cached of it or of its length.
func TestStopNestedLength(t *testing.T) {
	b := "9 0 obj << /Length 10 0 R >>stream\nx\nendstream\nendobj\n"
	at := len(b)
	b += "10 0 obj 1 %" + strings.Repeat("x", 20000) + "\nendobj\n"
	d := stopDoc(b, context.Background())
	d.xref[9] = xrefEntry{offset: 0}
	d.xref[10] = xrefEntry{offset: int64(at)}
	if err := d.indexEndstreams(); err != nil {
		t.Fatal(err)
	}
	d.ctx = &stopReads{Context: context.Background(), n: 1}
	if v, read := d.objectRead(9); read || v != nil || len(d.cache) != 0 {
		t.Fatalf("read %v stream %T cache %v: the parent was read with its length's deadline lost", read, v, d.cache)
	}
}

// An object stream's /N or /First the deadline stops: the header is not read
// on the strength of a zero, and the deadline is what loading it returns.
func TestStopObjectStreamHeaderFields(t *testing.T) {
	for _, field := range []Name{"N", "First"} {
		t.Run(string(field), func(t *testing.T) {
			d := stopDoc("10 0 obj 1 %"+strings.Repeat("x", 20000)+"\nendobj\n", &stopReads{Context: context.Background(), n: 1})
			d.xref[10] = xrefEntry{offset: 0}
			dict := Dict{"Type": Name("ObjStm"), "N": int64(1), "First": int64(4)}
			dict[field] = ref{10, 0}
			st, err := d.loadObjStm(9, &stream{dict: dict, raw: []byte("4 0 1")})
			if st != nil || !isDeadline(err) || len(d.objStms) != 0 || len(d.objStmHeaders) != 0 {
				t.Fatalf("header %#v error %v held %v: the field's deadline was lost", st, err, d.objStms)
			}
		})
	}
}

// A cross-reference stream's /W the deadline stops is the deadline, and not
// a /W that is not an array of three.
func TestStopXrefField(t *testing.T) {
	b := "10 0 obj [1 1 1] %" + strings.Repeat("x", 20000) + "\nendobj\n"
	d := stopDoc(b, &stopReads{Context: context.Background(), n: 1})
	d.xref[10] = xrefEntry{offset: 0}
	s := &stream{dict: Dict{"Type": Name("XRef"), "W": ref{10, 0}, "Size": int64(1)}, raw: []byte{0, 0, 0}}
	if _, err := d.readXrefStream(s, 0); !isDeadline(err) || errors.Is(err, errMalformed) {
		t.Fatalf("the field's deadline became %v", err)
	}
}

// A catalog the deadline stops does not send the reader rebuilding the
// cross-reference to look for another.
func TestStopPagesRoot(t *testing.T) {
	data := "1 0 obj << /Type /Catalog /Pages 2 0 R /A (" + strings.Repeat("s", 40000) + ") >> endobj\n"
	at := len(data)
	data += "2 0 obj << /Type /Pages /Kids [] >> endobj\n"
	d := stopDoc(data, &stopReads{Context: context.Background(), n: 1})
	d.xref[1] = xrefEntry{offset: 0}
	d.xref[2] = xrefEntry{offset: int64(at)}
	d.trailer["Root"] = ref{1, 0}
	if root, _ := d.pagesRoot(); root != nil || d.reconstructed {
		t.Fatalf("root %v, rebuilt %v: the catalog's deadline began a rebuild", root, d.reconstructed)
	}
}

// The files the first review read whole: a /XRefStm whose /W is stopped, and
// a catalog that is. Each ends at the deadline, and neither is rebuilt.
func TestStopNestedResolutionRecords(t *testing.T) {
	for _, c := range []struct {
		name string
		data []byte
		n    int
	}{
		{"an indirect /W", reviewXrefWFile(), 3},
		{"a catalog", reviewCatalogFile(), 2},
	} {
		t.Run(c.name, func(t *testing.T) {
			trial := stopRun(c.data, c.n, false)
			if trial.d == nil || !trial.r.TimedOut || trial.r.Fatal != nil || trial.rebuiltAfter {
				t.Fatalf("stopped %v timedOut %v fatal %+v rebuilt after the stop %v", trial.d != nil, trial.r.TimedOut, trial.r.Fatal, trial.rebuiltAfter)
			}
		})
	}
}

// A deadline read before a bound is what the reading ends at. The trailer
// holds /Root, 1,048,575 other members and then /Last 1 and a comment, one
// member past the bound; the deadline passes at the lexer's first reading
// inside that comment, which its lookahead for a reference reads, and the
// dictionary would meet its member bound only after it. The record says
// timeout; with no deadline, it says the bound.
func TestStopLastMemberPrecedence(t *testing.T) {
	if testing.Short() {
		t.Skip("the trailer is a million members")
	}
	data := lastMemberFile()
	comment := bytes.Index(data, []byte("/Last 1 %")) + len("/Last 1 %")
	// Which reading falls inside the comment, found by where the lexers stand
	// at each reading.
	ctx := &stopReads{Context: context.Background()}
	target := 0
	lexTrace = func(_ *allowance, event lexEvent, at int) {
		if event == lexReadAt && target == 0 && at > comment && at < comment+40000 {
			target = ctx.reads + 1
		}
	}
	_, err := open(ctx, data, &inflateBudget{total: 64 << 20, one: 16 << 20})
	lexTrace = nil
	if !isBound(err) || target == 0 {
		t.Fatalf("with no deadline: %v, reading inside the comment %d", err, target)
	}
	r := Extract(&stopReads{Context: context.Background(), n: target}, data, testOptions())
	if !r.TimedOut || r.Fatal != nil {
		t.Fatalf("deadline at reading %d: timedOut %v fatal %+v; the deadline was read before the bound was met", target, r.TimedOut, r.Fatal)
	}
}

// stopArmed is a deadline that passes at the first reading made once it has
// been armed, and at every reading after it.
type stopArmed struct {
	context.Context
	armed, expired bool
}

func (c *stopArmed) Err() error {
	if c.armed {
		c.expired = true
	}
	if c.expired {
		return context.DeadlineExceeded
	}
	return nil
}

func (c *stopArmed) Deadline() (time.Time, bool) { return time.Time{}, false }

// armedAt arms ctx when the loop named takes its first step, or, for
// "trailer", when the search for the word first examines the file.
func armedAt(ctx *stopArmed, loop string) func() {
	loopStepped = func(l string, _ int) {
		if l == loop {
			ctx.armed = true
		}
	}
	searchInspected = func(int, int) {
		if loop == "trailer" {
			ctx.armed = true
		}
	}
	return func() { loopStepped, searchInspected = nil, nil }
}

// A deadline in a rebuild a /Length began, inside the reading of a /Prev
// section: the file of the second review, which with no deadline reads its
// page. Stopped in the object stream's pairs, in its mapping, or in its
// registration, the record says timeout, and is not a file with no usable
// cross-reference.
func TestStopNestedRebuildRecord(t *testing.T) {
	data := nestedRebuildFile()
	if r := Extract(context.Background(), data, testOptions()); r.Fatal != nil || len(r.Pages) != 1 {
		t.Fatalf("with no deadline: %+v", r)
	}
	for _, loop := range []string{"pairs", "mapped", "register"} {
		t.Run(loop, func(t *testing.T) {
			ctx := &stopArmed{Context: context.Background()}
			defer armedAt(ctx, loop)()
			r := Extract(ctx, data, testOptions())
			if !ctx.expired || !r.TimedOut || r.Fatal != nil {
				t.Fatalf("expired %v timedOut %v fatal %+v", ctx.expired, r.TimedOut, r.Fatal)
			}
		})
	}
}

// The read a rebuild abandoned publishes nothing when it resumes. Object
// 99999's entry names byte 1, which holds no object, so reading it rebuilds
// the cross-reference, and the rebuild is stopped in its search for trailers,
// the copy of one, or the gathering, sorting or merging of the numbers. The
// abandoned read caches nothing when it resumes: not the object's failure.
// The stronger case: a stream whose /Length is 99999 0 R, the file's stream
// ends already indexed, is not published when its length's rebuild stops.
func TestStopAbandonedReadPublishesNothing(t *testing.T) {
	var b strings.Builder
	b.WriteString("%PDF-1.7\n")
	for i := 1; i <= 12000; i++ {
		fmt.Fprintf(&b, "%d 0 obj null endobj\n", i)
	}
	b.WriteString("trailer << ")
	for i := 0; i < 12000; i++ {
		fmt.Fprintf(&b, "/K%d 1 ", i)
	}
	b.WriteString(">>\n")
	for _, loop := range []string{"trailer", "copy", "gather", "sort", "merge"} {
		t.Run(loop, func(t *testing.T) {
			ctx := &stopArmed{Context: context.Background()}
			defer armedAt(ctx, loop)()
			d := stopDoc(b.String(), ctx)
			d.xref[99999] = xrefEntry{offset: 1}
			d.cache[7] = Name("old")
			_, read := d.objectRead(99999)
			if !ctx.expired || read {
				t.Fatalf("expired %v read %v", ctx.expired, read)
			}
			if _, cached := d.cache[99999]; cached {
				t.Fatalf("the abandoned read published %#v after the rebuild stopped", d.cache[99999])
			}
		})
	}
	t.Run("a stream whose length is rebuilt for", func(t *testing.T) {
		objects := []string{"<< /Length 99999 0 R >>stream\nOLD\nendstream"}
		for i := 0; i < 12000; i++ {
			objects = append(objects, "null")
		}
		data := bytes.Replace(tabled(objects, 0), []byte("trailer\n"), []byte("99999 1\n0000000001 00000 n \ntrailer\n"), 1)
		d, err := open(context.Background(), data, &inflateBudget{total: 64 << 20, one: 16 << 20})
		if err != nil {
			t.Fatal(err)
		}
		if err := d.indexEndstreams(); err != nil {
			t.Fatal(err)
		}
		ctx := &stopArmed{Context: context.Background()}
		defer armedAt(ctx, "gather")()
		d.ctx = ctx
		body, read := d.objectRead(1)
		if !ctx.expired || read || body != nil {
			t.Fatalf("expired %v read %v body %T", ctx.expired, read, body)
		}
		if _, cached := d.cache[1]; cached {
			t.Fatal("the stream was published after its length's rebuild stopped")
		}
	})
}

// A cross-reference stream of half a million ranges of no entries, the last
// of them past the bound on entries: with no deadline, the bound; with a
// deadline read as the ranges are, before the last one is reached, the
// deadline.
func TestStopIndexRangesBeforeTheirBound(t *testing.T) {
	var b bytes.Buffer
	b.WriteString("%PDF-1.7\n")
	at := b.Len()
	ranges := strings.Repeat("0 0 ", maxContainerItems/2-1) + fmt.Sprint(maxXrefEntries+1) + " 0"
	fmt.Fprintf(&b, "1 0 obj\n<< /Type /XRef /W [1 1 1] /Size 1 /Index [%s] /Length 0 >>stream\n\nendstream\nendobj\nstartxref\n%d\n%%%%EOF\n", ranges, at)
	data := b.Bytes()
	if _, err := open(context.Background(), data, &inflateBudget{total: 64 << 20, one: 16 << 20}); !isBound(err) {
		t.Fatalf("with no deadline: %v, want the bound", err)
	}
	ctx := &stopArmed{Context: context.Background()}
	defer armedAt(ctx, "ranges")()
	if _, err := open(ctx, data, &inflateBudget{total: 64 << 20, one: 16 << 20}); !isDeadline(err) || isBound(err) {
		t.Fatalf("with the deadline read among the ranges: %v, want the deadline", err)
	}
}

// The index of stream ends is not kept when the deadline passes while it is
// set up or filled, or before it is kept.
func TestStopStreamEndsIndex(t *testing.T) {
	data := append(append([]byte("%PDF-1.7\n1 0 obj << /Length -1 >>stream\n"), bytes.Repeat([]byte("x"), 1<<20)...), "\nendstream\nendobj\n"...)
	for _, loop := range []string{"blocks", "blocks filled"} {
		t.Run(loop, func(t *testing.T) {
			ctx := &stopArmed{Context: context.Background()}
			defer armedAt(ctx, loop)()
			d := stopDoc(string(data), ctx)
			if _, err := d.nextEndstream(0); !isDeadline(err) || d.endstream != nil {
				t.Fatalf("error %v, index kept %v", err, d.endstream != nil)
			}
		})
	}
	t.Run("before it is kept", func(t *testing.T) {
		// The deadline passes once the last block has been filled -- counted
		// from the work of filling, and not from the readings the index
		// makes -- so that only a reading made after the filling, before
		// the index is kept, can find it passed.
		filled := 0
		loopStepped = func(l string, _ int) {
			if l == "blocks filled" {
				filled++
			}
		}
		defer func() { loopStepped = nil }()
		d := stopDoc(string(data), context.Background())
		if _, err := d.nextEndstream(0); err != nil || d.endstream == nil || filled == 0 {
			t.Fatalf("with no deadline: %v, %d blocks filled", err, filled)
		}
		ctx := &stopArmed{Context: context.Background()}
		steps := 0
		loopStepped = func(l string, _ int) {
			if l == "blocks filled" {
				if steps++; steps == filled {
					ctx.armed = true
				}
			}
		}
		d = stopDoc(string(data), ctx)
		if _, err := d.nextEndstream(0); !isDeadline(err) || d.endstream != nil || !ctx.expired {
			t.Fatalf("armed after the last of %d blocks filled: error %v, index kept %v, deadline read after the filling %v", filled, err, d.endstream != nil, ctx.expired)
		}
	})
}

// A lexer stopped by the deadline returns the deadline at the call that read
// it and at every call after it, and reads nothing more: 16,384 spaces and
// then "[]", the deadline passing at the first reading, which the skip makes
// where the spaces end.
func TestStopLexerReturnsTheDeadlineAtEveryLaterCall(t *testing.T) {
	d := stopDoc(strings.Repeat(" ", lexBytesPerCheck)+"[]", &stopReads{Context: context.Background(), n: 1})
	l := newLexer(d.data, 0).within(d.budgeted())
	tok, err := l.next()
	if !isDeadline(err) {
		t.Fatalf("the call that read the deadline returned %v, %v", tok.kind, err)
	}
	at := l.pos
	for i := 0; i < 5; i++ {
		if tok, err := l.next(); !isDeadline(err) || l.pos != at {
			t.Fatalf("call %d after the stop returned %v, %v at %d, from %d", i+2, tok.kind, err, l.pos, at)
		}
	}
	l.back(0)
	if tok, err := l.next(); !isDeadline(err) || l.pos != 0 {
		t.Fatalf("after a step back the lexer returned %v, %v at %d", tok.kind, err, l.pos)
	}
}

// Every exit a deadline makes from a rebuild leaves nothing of the reading
// made under the cross-reference it replaced, and nothing is published after
// it. The file's table names the objects where they are, but for object 30,
// whose entry names byte 3, so that reading it rebuilds the cross-reference
// by scanning: 6,000 objects, a trailer and an object stream of 3,000 places
// for the rebuild to read. Before the read the document holds what a
// reading of it holds -- its catalog, its pages, its page, an object stream
// with its header, a font, a CMap -- and the deadline is then driven through
// every reading the rebuild makes -- each of the first and last eighty, and
// one in every so many between, where the rebuild reads one object a reading
// and every exit there is the same exit. At each exit none of what the document
// held before is held still, the generation is the one the reading began on
// or the next, and a read made after the exit publishes nothing.
func TestStopRebuildExitsKeepNothingOfTheOldReading(t *testing.T) {
	objects := []stopObject{
		{num: 1, body: "<< /Type /Catalog /Pages 2 0 R >>"},
		{num: 2, body: "<< /Type /Pages /Kids [3 0 R] /Count 1 >>"},
		{num: 3, body: "<< /Type /Page /Parent 2 0 R >>"},
	}
	var places []stopObject
	for i := 0; i < 3000; i++ {
		places = append(places, stopObject{num: 20000 + i, body: "null"})
	}
	objStm, _, first := stopObjectStream(4, places, "")
	objStm.body = fmt.Sprintf("<< /Type /ObjStm /N 3000 /First %d /Length %d >>", first, len(objStm.data))
	objects = append(objects, objStm)
	for i := 5; i < 6000; i++ {
		objects = append(objects, stopObject{num: i, body: "null"})
	}
	var trailer strings.Builder
	trailer.WriteString("<< /Root 1 0 R ")
	for i := 0; i < 5000; i++ {
		fmt.Fprintf(&trailer, "/K%d 1 ", i)
	}
	trailer.WriteString(">>")
	data := stopTable(objects, trailer.String(), 30)

	opened := func(ctx context.Context) (*Document, map[string]string) {
		d, err := open(context.Background(), data, &inflateBudget{total: 64 << 20, one: 16 << 20})
		if err != nil {
			t.Fatal(err)
		}
		for _, num := range []int{1, 2, 3, 4} {
			if _, read := d.objectRead(num); !read {
				t.Fatalf("object %d did not read", num)
			}
		}
		if _, err := d.loadObjStm(4, d.cache[4].(*stream)); err != nil {
			t.Fatal(err)
		}
		d.fontRefs = map[ref]*font{{3, 0}: {}}
		d.cmaps = map[*stream]*cmap{{}: {}}
		held := stopState(d)
		d.ctx = ctx
		return d, held
	}
	live := &stopReads{Context: context.Background()}
	d, _ := opened(live)
	if _, read := d.objectRead(30); !read || !d.reconstructed {
		t.Fatalf("with no deadline object 30 read %v, rebuilt %v", read, d.reconstructed)
	}
	t.Logf("the rebuild reads the deadline %d times", live.reads)
	// Under the race detector the stride is raceFactor times as long and the
	// edges raceFactor times as short, for the reason the sweep of
	// TestADocumentKeepsNothingAfterTheDeadline gives.
	stride, edge := max(1, live.reads/200)*raceFactor, 80/raceFactor
	for n := 1; n <= live.reads; n++ {
		if n > edge && n < live.reads-edge && n%stride != 0 {
			continue
		}
		d, held := opened(&stopReads{Context: context.Background(), n: n})
		generation := d.generation
		if _, read := d.objectRead(30); read || d.stopped() == nil {
			t.Fatalf("deadline at reading %d: object 30 read %v, stopped %v", n, read, d.stopped())
		}
		now := stopState(d)
		for key, then := range held {
			if strings.HasPrefix(key, "entry ") || strings.HasPrefix(key, "trailer ") || key == "generation" {
				continue
			}
			if now[key] == then {
				t.Fatalf("deadline at reading %d: the document still holds %s of the reading the rebuild replaced", n, key)
			}
		}
		if d.generation != generation && d.generation != generation+1 {
			t.Fatalf("deadline at reading %d: generation %d, from %d", n, d.generation, generation)
		}
		for _, num := range []int{1, 2, 3, 4, 5} {
			if _, read := d.objectRead(num); read {
				t.Fatalf("deadline at reading %d: object %d read after the stop", n, num)
			}
		}
		if after := stopState(d); len(after) != len(now) {
			t.Fatalf("deadline at reading %d: reads after the stop published %d entries", n, len(after)-len(now))
		}
	}
}

// lastMemberFile is a file whose trailer holds /Root, 1,048,575 other
// members and then /Last 1 and a comment of 40,000 bytes: one member past the
// bound, the last of them standing before a comment its lookahead reads.
func lastMemberFile() []byte {
	var b strings.Builder
	b.WriteString("<< /Root 1 0 R ")
	for i := 0; i < maxContainerItems-1; i++ {
		fmt.Fprintf(&b, "/K%d 0 ", i)
	}
	b.WriteString("/Last 1 %" + strings.Repeat("x", 40000) + "\n>>")
	return stopTable([]stopObject{
		{num: 1, body: "<< /Type /Catalog /Pages 2 0 R >>"},
		{num: 2, body: "<< /Type /Pages /Kids [3 0 R] /Count 1 >>"},
		{num: 3, body: "<< /Type /Page /Parent 2 0 R >>"},
	}, b.String(), 0)
}

// The encryption dictionary read past the deadline. In the file of the second
// review the crypt filter streams are read through is object 10, the name
// /StdCF followed by a comment of 40,000 bytes the lexer reads the deadline
// in: the name is unread, and Identity, the filter a dictionary that names
// none is read through, is not what it names. The dictionary is not opened
// and no handler is installed; the error is the deadline. And a stopped
// document whose dictionary's /P is an object of its own, which it can no
// longer read, returns the deadline and not a dictionary with no /P.
func TestStopEncryption(t *testing.T) {
	t.Run("the stream filter's name", func(t *testing.T) {
		data := stopCryptFile()
		if r := Extract(context.Background(), data, testOptions()); r.Fatal != nil || len(r.Pages) != 1 || r.Pages[0].Text != "Hello" || r.Encryption == nil || !r.Encryption.Opened {
			t.Fatalf("with no deadline: %+v", r)
		}
		d, err := open(context.Background(), data, &inflateBudget{total: 64 << 20, one: 16 << 20})
		if err != nil {
			t.Fatal(err)
		}
		d.ctx = &stopReads{Context: context.Background(), n: 1}
		info, err := d.openEncryption()
		if !isDeadline(err) || d.crypt != nil || info != nil && info.Opened || d.stopped() == nil {
			t.Fatalf("error %v, handler %v, record %+v, stopped %v: the handler was installed from a filter the deadline left unread", err, d.crypt != nil, info, d.stopped())
		}
	})
	t.Run("a /P the stopped document cannot read", func(t *testing.T) {
		d := stoppedDoc(t, "9 0 obj -4 endobj")
		d.xref[9] = xrefEntry{offset: 0}
		d.trailer["Encrypt"] = Dict{"Filter": Name("Standard"), "V": int64(2), "R": int64(3), "Length": int64(128), "O": String(bytes.Repeat([]byte{1}, 32)), "U": String(bytes.Repeat([]byte{2}, 32)), "P": ref{9, 0}}
		if info, err := d.openEncryption(); !isDeadline(err) || errors.Is(err, errMalformed) || d.crypt != nil {
			t.Fatalf("error %v, record %+v, handler %v: a field the stop left unread was taken for absent", err, info, d.crypt != nil)
		}
	})
}

// stopValueContext is a context that cannot be compared: a value holding a
// slice.
type stopValueContext struct {
	context.Context
	b []byte
}

// The stop is the document's, and final: it is set by a reading of the
// deadline made under whatever context the document is read under -- its
// own, the walk's, a page's, the interpreter's -- and every reading of the
// document after it, under any context, is the stop, and neither a partial
// reading nor a defect. Contexts are never compared, so one that cannot be
// is read as any other. A document is read again by opening it again.
func TestStopIsTheDocuments(t *testing.T) {
	pages := stopTable(stopPages(), "<< /Root 1 0 R /Size 8 >>", 0)
	opened := func(data []byte) *Document {
		d, err := open(context.Background(), data, &inflateBudget{total: 64 << 20, one: 16 << 20})
		if err != nil {
			t.Fatal(err)
		}
		return d
	}
	stopped := func(t *testing.T, at string, r *Result) {
		t.Helper()
		if !r.TimedOut || r.Fatal != nil || len(r.Pages) != 0 {
			t.Fatalf("%s: timedOut %v fatal %+v pages %+v problems %+v", at, r.TimedOut, r.Fatal, r.Pages, r.Problems)
		}
	}
	t.Run("a live context after a rebuild the deadline stopped", func(t *testing.T) {
		// The file of the second review: the font's entry names byte 3, so
		// that reading it rebuilds the cross-reference, and the deadline
		// passes at the scan's first reading of it.
		data := stopTable(stopPages(), "<< /Root 1 0 R /Size 8 >>", 4)
		d := opened(data)
		for _, num := range []int{1, 2, 3} {
			d.objectRead(num)
		}
		d.ctx = &stopReads{Context: context.Background(), n: 1}
		if _, read := d.objectRead(4); read || !d.reconstructed || d.stopped() == nil {
			t.Fatalf("read %v, rebuilt %v, stopped %v", read, d.reconstructed, d.stopped())
		}
		d.ctx = context.Background()
		stopped(t, "read again with time left", stopReadAgain(d.ctx, d))
		if r := Extract(context.Background(), data, testOptions()); r.Fatal != nil || len(r.Pages) != 1 || r.Pages[0].Text != "Hello" {
			t.Fatalf("opened again: %+v", r)
		}
	})
	t.Run("a context that cannot be compared", func(t *testing.T) {
		if r := Extract(stopValueContext{context.Background(), []byte{1}}, pages, testOptions()); r.Fatal != nil || len(r.Pages) != 1 || r.Pages[0].Text != "Hello" {
			t.Fatalf("with time left: %+v", r)
		}
		passed, cancel := context.WithTimeout(context.Background(), 0)
		defer cancel()
		stopped(t, "past the deadline", Extract(stopValueContext{passed, []byte{1}}, pages, testOptions()))
	})
	t.Run("a page's context whose deadline has passed", func(t *testing.T) {
		d := opened(pages)
		w, _, stop := walkPages(context.Background(), d, testOptions(), &Result{})
		if stop != nil {
			t.Fatal(stop)
		}
		r := &Result{}
		extractPages(&stopReads{Context: context.Background(), n: 1}, w, testOptions(), r)
		stopped(t, "the page read under it", r)
		if d.stopped() == nil {
			t.Fatal("the page's reading of the deadline did not stop the document")
		}
		if _, read := d.objectRead(6); read {
			t.Fatal("an object was read under the document's own context after the page's stop")
		}
	})
	t.Run("a live page context after the document's stop", func(t *testing.T) {
		d := opened(pages)
		w, _, stop := walkPages(context.Background(), d, testOptions(), &Result{})
		if stop != nil {
			t.Fatal(stop)
		}
		d.ctx = &stopReads{Context: context.Background(), n: 1}
		if !d.deadlineNow() {
			t.Fatal("the document did not stop")
		}
		r := &Result{}
		extractPages(context.Background(), w, testOptions(), r)
		stopped(t, "the page read under a live context", r)
	})
	t.Run("the interpreter's context", func(t *testing.T) {
		d := stopDoc("1 0 obj << /Subtype /Type1 /BaseFont /Helvetica >> endobj", context.Background())
		d.xref[1] = xrefEntry{offset: 0}
		pr := d.interpretPage(&stopReads{Context: context.Background(), n: 1}, []byte("q Q"), Dict{}, 100)
		if !isDeadline(pr.err) || d.stopped() == nil {
			t.Fatalf("page error %v, stopped %v: the interpreter's reading did not stop the document", pr.err, d.stopped())
		}
		if pr := d.interpretPage(context.Background(), []byte("BT /F1 12 Tf (Hello) Tj ET"), Dict{"Font": Dict{"F1": ref{1, 0}}}, 100); pr.text != "" || !isDeadline(pr.err) {
			t.Fatalf("a page read after the stop under a live context: text %q, error %v", pr.text, pr.err)
		}
		if _, read := d.objectRead(1); read {
			t.Fatal("an object was read after the interpreter's stop")
		}
	})
}

// What the sweep compares the document by sees into what it holds: a value
// changed in place, under the same number and at the same address, with the
// same length, is a change, and so is a handler installed or changed.
func TestStopStateSeesContents(t *testing.T) {
	d := stopDoc("", context.Background())
	held := Dict{"A": int64(1)}
	d.cache[1] = held
	d.crypt = &cryptHandler{key: []byte{1}}
	before := stopState(d)
	held["A"] = int64(2)
	if after := stopState(d); after["object 1"] == before["object 1"] {
		t.Fatalf("a dictionary changed in place reads as it did: %s", after["object 1"])
	}
	d.crypt.key[0] = 2
	if after := stopState(d); after["handler"] == before["handler"] {
		t.Fatalf("a handler changed in place reads as it did: %s", after["handler"])
	}
}
