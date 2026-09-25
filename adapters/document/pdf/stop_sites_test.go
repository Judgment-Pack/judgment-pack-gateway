package pdf

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

// Each site that keeps something, or that would take a read the deadline
// stopped for an absent value, a defect, a zero, no length or a reason to
// rebuild, holds its own part of the rule on its own: the tests below call
// each one directly on a document the deadline has stopped, so that no
// other site's part of the rule can stand in for it.

// stoppedDoc is a document over data whose deadline has passed and been
// read: stopped, as every reading of it after this finds it.
func stoppedDoc(t *testing.T, data string) *Document {
	t.Helper()
	d := stopDoc(data, &stopReads{Context: context.Background(), n: 1})
	if !d.deadlineNow() || d.stopped() == nil {
		t.Fatal("the document did not stop")
	}
	return d
}

// lexersBegun counts the lexers made for a document while f runs.
func lexersBegun(f func()) int {
	began := 0
	lexTrace = func(_ *allowance, event lexEvent, _ int) {
		if event == lexBegan {
			began++
		}
	}
	defer func() { lexTrace = nil }()
	f()
	return began
}

// What the document keeps: an object, a tried stream, a bound, a head, a CMap
// and a stream's failure to decode are kept by no call made after the stop.
func TestStopSitesKeepNothing(t *testing.T) {
	t.Run("publish", func(t *testing.T) {
		d := stoppedDoc(t, "")
		d.publish(d.generation, 1, int64(1))
		if len(d.cache) != 0 {
			t.Fatalf("published %v", d.cache)
		}
	})
	t.Run("markObjStm", func(t *testing.T) {
		d := stoppedDoc(t, "")
		d.markObjStm(d.generation, 9)
		if len(d.objStms) != 0 {
			t.Fatalf("marked %v", d.objStms)
		}
	})
	t.Run("noteBound", func(t *testing.T) {
		d := stoppedDoc(t, "")
		d.noteBound(structureBound("a bound"))
		if d.bound != nil {
			t.Fatalf("kept %v", d.bound)
		}
	})
	t.Run("noteFileBound", func(t *testing.T) {
		d := stoppedDoc(t, "")
		d.noteFileBound(structureBound("a bound"))
		if d.fileBound != nil {
			t.Fatalf("kept %v", d.fileBound)
		}
	})
	t.Run("notOfType", func(t *testing.T) {
		d := stoppedDoc(t, "1 0 obj << /Type /Font >> endobj")
		d.notOfType(xrefEntry{offset: 0}, "Pages")
		if len(d.headTypes) != 0 {
			t.Fatalf("kept %v", d.headTypes)
		}
	})
	t.Run("cmapOf", func(t *testing.T) {
		cmap := "begincmap 1 beginbfchar <48> <0048> endbfchar endcmap"
		d := stoppedDoc(t, "")
		d.cmapOf(&stream{dict: Dict{"Length": int64(len(cmap))}, raw: []byte(cmap)})
		if len(d.cmaps) != 0 {
			t.Fatalf("kept %v", d.cmaps)
		}
	})
	t.Run("an object stream's failure", func(t *testing.T) {
		// A stream the document read before the stop, which is no object
		// stream: its failure to be one, met after the stop, is not kept.
		d := stoppedDoc(t, "")
		d.xref[4] = xrefEntry{inStream: true, stmNum: 9}
		d.xref[9] = xrefEntry{offset: 0}
		d.cache[9] = &stream{dict: Dict{"Type": Name("XObject")}}
		if _, read, _ := d.objectFromStream(4, d.xref[4]); read || d.undecoded != nil || len(d.objStms) != 0 {
			t.Fatalf("read %v undecoded %v marked %v", read, d.undecoded, d.objStms)
		}
	})
}

// What the document reads: nothing is read after the stop, and a read that
// the stop ended is the deadline where it would otherwise be absent, zero,
// no length, or a malformed field.
func TestStopSitesReturnTheDeadline(t *testing.T) {
	t.Run("objectRead", func(t *testing.T) {
		d := stoppedDoc(t, "1 0 obj << /A 1 >> endobj\n")
		d.xref[1] = xrefEntry{offset: 0}
		var read bool
		if began := lexersBegun(func() { _, read = d.objectRead(1) }); read || began != 0 || d.parsed != 0 {
			t.Fatalf("read %v, %d lexers begun, %d objects parsed after the stop", read, began, d.parsed)
		}
	})
	t.Run("a lexer made after the stop", func(t *testing.T) {
		d := stoppedDoc(t, "<< /A 1 >>")
		l := newLexer(d.data, 0).within(d.budgeted())
		if tok, err := l.next(); !isDeadline(err) || l.pos != 0 {
			t.Fatalf("read %v, %v to %d", tok.kind, err, l.pos)
		}
	})
	t.Run("the integer lookahead", func(t *testing.T) {
		d := stopDoc("1 %"+strings.Repeat("x", 40000)+"\n", &stopReads{Context: context.Background(), n: 1})
		p := &parser{lex: newLexer(d.data, 0).within(d.budgeted()), allow: d.budgeted()}
		if v, err := p.parseObject(0); !isDeadline(err) || v != nil {
			t.Fatalf("parsed %#v, %v", v, err)
		}
	})
	t.Run("an object stream's /N", func(t *testing.T) {
		d := stopDoc("10 0 obj 1 %"+strings.Repeat("x", 20000)+"\nendobj\n", &stopReads{Context: context.Background(), n: 1})
		d.xref[10] = xrefEntry{offset: 0}
		var err error
		began := lexersBegun(func() {
			_, err = d.loadObjStm(9, &stream{dict: Dict{"Type": Name("ObjStm"), "N": ref{10, 0}, "First": int64(4)}, raw: []byte("4 0 1")})
		})
		if !isDeadline(err) || began != 1 {
			t.Fatalf("%v, %d lexers begun: the header was read on the strength of a zero", err, began)
		}
	})
	t.Run("resolveLength", func(t *testing.T) {
		d := stopDoc("10 0 obj 1 %"+strings.Repeat("x", 20000)+"\nendobj\n", &stopReads{Context: context.Background(), n: 1})
		d.xref[10] = xrefEntry{offset: 0}
		if _, ok, err := d.resolveLength(ref{10, 0}, 9); ok || !isDeadline(err) {
			t.Fatalf("length found %v, %v", ok, err)
		}
	})
	t.Run("a cross-reference stream decoded", func(t *testing.T) {
		// The file is long enough to hold what decoding costs, so that the
		// decoding reads the deadline before any bound is met.
		d := stoppedDoc(t, strings.Repeat(" ", 4096))
		s := &stream{dict: Dict{"Type": Name("XRef"), "Filter": Name("LZWDecode"), "W": Array{int64(1), int64(1), int64(1)}, "Size": int64(1)}, raw: []byte{0x80, 0x0b, 0x60, 0x50, 0x22, 0x0c, 0x0c, 0x85, 0x01}}
		if _, err := d.readXrefStream(s, 0); !isDeadline(err) || errors.Is(err, errMalformed) {
			t.Fatalf("%v", err)
		}
	})
	for _, c := range []struct {
		name  string
		field Name
		value object
	}{
		{"/W", "W", ref{10, 0}},
		{"a /W entry", "W", Array{int64(1), ref{10, 0}, int64(1)}},
		{"/Index", "Index", ref{10, 0}},
		{"an /Index element", "Index", Array{int64(0), ref{10, 0}}},
	} {
		t.Run("a cross-reference stream's "+c.name, func(t *testing.T) {
			d := stopDoc("10 0 obj 1 %"+strings.Repeat("x", 20000)+"\nendobj\n", &stopReads{Context: context.Background(), n: 1})
			d.xref[10] = xrefEntry{offset: 0}
			dict := Dict{"Type": Name("XRef"), "W": Array{int64(1), int64(1), int64(1)}, "Size": int64(1)}
			dict[c.field] = c.value
			if _, err := d.readXrefStream(&stream{dict: dict, raw: []byte{0, 0, 0}}, 0); !isDeadline(err) || errors.Is(err, errMalformed) {
				t.Fatalf("%v", err)
			}
		})
	}
	t.Run("open, where the cross-reference seemed to lack something", func(t *testing.T) {
		// No startxref: reading the cross-reference fails without a reading
		// of the deadline, on a document already stopped. It is neither
		// thrown away nor rebuilt.
		d := stoppedDoc(t, "%PDF-1.7\n1 0 obj << >> endobj\n")
		d.trailer["Info"] = int64(1)
		generation := d.generation
		if err := d.open(); !isDeadline(err) || d.generation != generation || len(d.trailer) != 1 || d.reconstructed {
			t.Fatalf("%v, generation %d from %d, trailer %v, rebuilt %v", err, d.generation, generation, d.trailer, d.reconstructed)
		}
	})
	t.Run("reconstruct", func(t *testing.T) {
		d := stoppedDoc(t, "%PDF-1.7\n1 0 obj << >> endobj\n")
		if err := d.reconstruct(); !isDeadline(err) || d.reconstructed {
			t.Fatalf("%v, rebuilt %v", err, d.reconstructed)
		}
	})
}

// The one state of the stop: a loop's reading answers at once; the walk's,
// a page's and the interpreter's readings stop the document, under the
// document's own context and under any other; and a stopped document asks
// no context again, its own or another.
func TestStopSitesAreOneState(t *testing.T) {
	t.Run("deadlinePassed", func(t *testing.T) {
		d := stoppedDoc(t, "")
		if !d.deadlinePassed() {
			t.Fatal("a loop's reading on a stopped document did not find the deadline at once")
		}
	})
	t.Run("deadlineFor", func(t *testing.T) {
		for _, own := range []bool{true, false} {
			ctx := &stopReads{Context: context.Background(), n: 1}
			d := stopDoc("", context.Background())
			if own {
				d.ctx = ctx
			}
			if err := d.deadlineFor(ctx); err == nil || d.stopped() == nil {
				t.Fatalf("the document's own context %v: %v: the walk's reading did not stop the document", own, err)
			}
		}
	})
	t.Run("deadlineNow", func(t *testing.T) {
		ctx := &stopOnce{Context: context.Background()}
		d := stopDoc("", ctx)
		if !d.deadlineNow() || !d.deadlineNow() || ctx.reads != 1 {
			t.Fatalf("a stopped document asked its context %d times, and was answered as the context now answers", ctx.reads)
		}
	})
	t.Run("another context after the stop", func(t *testing.T) {
		d := stoppedDoc(t, "")
		live := &stopReads{Context: context.Background()}
		if err := d.deadlineFor(live); err == nil || live.reads != 0 {
			t.Fatalf("%v: a stopped document asked another context %d times, and was answered as it answers", err, live.reads)
		}
	})
}

// stopOnce is a context whose deadline has passed at its first reading and
// not at any after it.
type stopOnce struct {
	context.Context
	reads int
}

func (c *stopOnce) Err() error {
	c.reads++
	if c.reads == 1 {
		return context.DeadlineExceeded
	}
	return nil
}

func (c *stopOnce) Deadline() (time.Time, bool) { return time.Time{}, false }

// Each place that reads a token of the cross-reference, the trailer, an
// object's header or an object stream's header, and would take a token the
// deadline ended for a defect, returns the deadline: called directly, with
// the deadline passing at the lexer's first reading, which the 20,000 bytes
// of whitespace or string before the token make it reach. An object's file
// has its stream ends indexed beforehand, so that where a stream ends is
// found without a reading of the deadline of its own. Nothing is cached and
// nothing is rebuilt.
func TestStopSitesReadTokens(t *testing.T) {
	space := strings.Repeat(" ", 20000)
	long := "(" + strings.Repeat("s", 20000) + ")"
	for _, c := range []struct {
		name, data, reader string
	}{
		{"the whitespace before a section", space + "xref\n0 1\n0 0 f\ntrailer << /Root 1 0 R >>", "section"},
		{"a cross-reference stream's object", "9 0 obj << /Type /XRef /A " + long + " >>", "section"},
		{"a subsection's start", long, "table"},
		{"a subsection's count", "0" + space + "1", "table"},
		{"an entry's offset", "0 1\n" + space + "0 0 f", "table"},
		{"an entry's generation", "0 1\n0" + space + "0 f", "table"},
		{"an entry's type", "0 1\n0 0" + space + "f", "table"},
		{"the whitespace before the trailer", space + "trailer << /Root 1 0 R >>", "table"},
		{"the trailer", "trailer << /A " + long + " >>", "table"},
		{"an object's number", space + "9 0 obj <<>> endobj", "object"},
		{"an object's generation", "9" + space + "0 obj <<>> endobj", "object"},
		{"an object's keyword", "9 0" + space + "obj <<>> endobj", "object"},
		{"the look for stream", "9 0 obj <<>>" + space + "stream\nendstream", "object"},
		{"the skip before stream", "9 0 obj << /Length 0 >>" + strings.Repeat(" ", 9000) + "stream\n\nendstream", "object"},
		{"an object stream header's number", space + "4 0 1", "header"},
		{"an object stream header's offset", "4 " + space + "0 1", "header"},
	} {
		t.Run(c.name, func(t *testing.T) {
			d := stopDoc(c.data, context.Background())
			if c.reader == "object" {
				if err := d.indexEndstreams(); err != nil {
					t.Fatal(err)
				}
			}
			d.ctx = &stopReads{Context: context.Background(), n: 1}
			var err error
			switch c.reader {
			case "section":
				_, err = d.readXrefSectionAt(0, 0)
			case "table":
				_, err = d.readXrefTable(newLexer(d.data, 0).within(d.budgeted()))
			case "object":
				_, _, _, err = d.parseIndirectAt(0)
			case "header":
				var st *objStmParsed
				st, err = d.loadObjStm(9, &stream{dict: Dict{"Type": Name("ObjStm"), "N": int64(1), "First": int64(len(c.data) - 1)}, raw: []byte(c.data)})
				if st != nil {
					t.Fatalf("a header was read: %#v", st)
				}
			}
			if !isDeadline(err) || errors.Is(err, errMalformed) || len(d.cache) != 0 || len(d.objStms) != 0 || d.reconstructed {
				t.Fatalf("%v; cached %v, held %v, rebuilt %v", err, d.cache, d.objStms, d.reconstructed)
			}
		})
	}
}

// A rebuild whose last parse or last object stream the deadline ends returns
// the deadline, and not a rebuild that finished: the file's trailer names its
// catalog, so nothing after those loops would read the deadline again. The
// deadline passes at the first reading a lexer makes, which is inside the
// object stream's dictionary, or inside its header.
func TestStopSitesRebuildLoops(t *testing.T) {
	space := strings.Repeat(" ", 20000)
	for _, c := range []struct{ name, stream string }{
		{"the object the rebuild parses", "<< /Type /ObjStm /N 1 /First 4 /A (" + strings.Repeat("s", 20000) + ") /Length 5 >>stream\n4 0 1\nendstream"},
		{"the object stream it loads", fmt.Sprintf("<< /Type /ObjStm /N 1 /First %d /Length %d >>stream\n%s4 0 1\nendstream", len(space)+4, len(space)+5, space)},
	} {
		t.Run(c.name, func(t *testing.T) {
			data := "%PDF-1.7\n1 0 obj << /Type /Catalog >> endobj\n9 0 obj " + c.stream + "\nendobj\ntrailer << /Root 1 0 R >>\n"
			ctx := &stopArmed{Context: context.Background()}
			lexTrace = func(_ *allowance, event lexEvent, _ int) {
				if event == lexReadAt {
					ctx.armed = true
				}
			}
			defer func() { lexTrace = nil }()
			d := stopDoc(data, ctx)
			if err := d.reconstruct(); !isDeadline(err) || !ctx.expired {
				t.Fatalf("the rebuild ended with %v, expired %v", err, ctx.expired)
			}
		})
	}
}
