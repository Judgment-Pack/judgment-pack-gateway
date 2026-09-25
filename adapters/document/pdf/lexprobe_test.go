//go:build pdflexprobe

package pdf

import (
	"context"
	"strings"
	"testing"
	"unsafe"
)

// These tests run in the build made with the pdflexprobe tag, where every
// byte a lexer loads through at, and every reading of tokens and every skip,
// are told to lexLoaded and lexEntered: see lexProbed. What reads a slice of
// the data once taken -- a keyword's string, a number's parsing -- loads
// nothing through at and is not counted. TestTheLexerProbesHold runs them
// from the ordinary build.

// probeLexer is what the probe has seen of one lexer and every copy of it:
// how deep in a reading of tokens or a skip it stands, the copy doing that
// reading, whether it reads a document's deadline, the furthest byte it has
// loaded in the reading under way, how far what it advanced over has been
// counted, and what it advanced over since its last reading of the
// deadline, the most of that between two readings or after the last, in
// all, and its readings.
type probeLexer struct {
	depth                   int
	current                 *lexer
	document                bool
	frontier, counted       int
	gap, most, total, reads int
	// loads is the bytes loaded through at since the last reading of the
	// deadline, each load counted, a byte loaded again counted again, and
	// mostLoads the most of them between two readings or after the last.
	loads, mostLoads int
}

// probe counts what each lexer advances over from what it loads and where it
// stands, and nothing else: a byte is advanced over when it has been loaded
// and the lexer has moved past it, counted when the reading of tokens or the
// skip that moved past it ends or a reading of the deadline is made. A
// reading of tokens begins where the lexer stands, however it came to stand
// there, so a byte read again after a step back is counted again, whatever
// the step back was spelled as. A lexer is known by the identity newLexer
// gave it, and not by where it lies, so that what a copy of it reads is
// counted as the lexer's own, in the same stretch: a copy that reads again
// what the lexer read, with a due of its own, is a step back like any other.
// So is a lexer made over the same data where the lexer last at work was
// last seen standing: it is that reader made again, and it is given that
// one's identity, so that a reader made again for every token, each with a
// due of its own, is counted in one stretch as well.
// Beside what a lexer advances over, every load it makes through at is
// counted, a byte loaded again counted again, between two readings of the
// deadline: a lexer that runs forward and is put back before any reading
// advances over nothing, and loads all it ran over. A keyword's or a
// number's bytes, once found, are taken as a slice, and what reads the slice
// loads nothing through at.
type probe struct {
	lexers map[int64]*probeLexer
	loads  int
	// last is the lexer last at work -- made, or beginning or ending a
	// reading -- and at the last two places it was seen standing.
	last   int64
	lastAt [2]probePlace
}

// probePlace is a place in some data: the data, by where it lies and how
// long it is, and a position in it.
type probePlace struct {
	data     *byte
	size, at int
}

func placeOf(data []byte, at int) probePlace {
	return probePlace{unsafe.SliceData(data), len(data), at}
}

// seen notes that the lexer known as id stands at pos in data and is the
// last at work.
func (p *probe) seen(id int64, data []byte, pos int) {
	place := placeOf(data, pos)
	if id != p.last {
		p.last, p.lastAt = id, [2]probePlace{place, place}
		return
	}
	p.lastAt = [2]probePlace{p.lastAt[1], place}
}

func newProbe() *probe {
	p := &probe{lexers: map[int64]*probeLexer{}}
	lexStanding = func(data []byte, pos int) int64 {
		id := lexIdentities.Add(1)
		if place := placeOf(data, pos); p.last != 0 && (p.lastAt[0] == place || p.lastAt[1] == place) {
			id = p.last
		}
		p.seen(id, data, pos)
		return id
	}
	lexLoaded = func(l *lexer, i int) {
		p.loads++
		if s := p.lexers[l.ident.id]; s != nil {
			s.frontier = max(s.frontier, i+1)
			s.loads++
			s.mostLoads = max(s.mostLoads, s.loads)
		}
	}
	lexEntered = func(l *lexer) func() {
		s := p.lexers[l.ident.id]
		if s == nil {
			s = &probeLexer{}
			p.lexers[l.ident.id] = s
		}
		outer := s.current
		if s.depth == 0 {
			s.frontier, s.counted = l.pos, l.pos
		}
		s.depth++
		s.current = l
		s.document = s.document || l.work != nil && l.work.doc != nil
		p.seen(l.ident.id, l.data, l.pos)
		return func() {
			p.count(s)
			p.seen(l.ident.id, l.data, l.pos)
			s.depth--
			s.current = outer
		}
	}
	return p
}

func (p *probe) count(s *probeLexer) {
	if n := min(s.current.pos, s.frontier) - s.counted; n > 0 {
		s.total += n
		s.gap += n
		s.counted += n
		s.most = max(s.most, s.gap)
	}
}

// read is a reading of the deadline: what every lexer in a reading of tokens
// has advanced over is counted up to it, and its stretch begins again.
func (p *probe) read() {
	for _, s := range p.lexers {
		if s.depth > 0 {
			p.count(s)
			s.gap, s.loads = 0, 0
			s.reads++
		}
	}
}

func (p *probe) close() { lexLoaded, lexEntered, lexStanding = nil, nil, nil }

// most is the longest stretch any lexer that reads the deadline advanced
// over with no reading of it, its last stretch -- to the last byte it
// consumed -- included, and what those lexers advanced over in all.
func (p *probe) most() (most, total int) {
	for _, s := range p.lexers {
		if s.document {
			most = max(most, s.most)
			total += s.total
		}
	}
	return most, total
}

// loadBound is the most loads through at a lexer may make between two
// readings of the deadline: eight to each byte it may advance over between
// them, lexBytesPerCheck and a keyword's bytes. It is a bound on the loads of
// a stretch and not on the loads of a byte, which are more: the loop that
// finds a number's end tests the byte after it for seven characters, and the
// skip, next and a keyword's scan load it again, so the ':' of "1:" is loaded
// ten times, and a byte the integer lookahead reaches is loaded again each
// time a lookahead reads it -- the "]" of "[1 2 3 4 5]" thirty-four times,
// the most found. Over a stretch those loads fall on few bytes: the most any
// case here makes between two readings is 90,113, about four and a half to
// each byte advanced over. Advancing is counted from where a lexer stands, and
// a lexer that ran forward and was put back before any reading of the
// deadline would advance over nothing it did not read again; its loads are
// counted as they are made, and grow with what it ran over.
const loadBound = 8 * (lexBytesPerCheck + maxNameBytes)

// mostLoads is the most loads through at any lexer that reads the deadline
// made with no reading of it between.
func (p *probe) mostLoads() (most int) {
	for _, s := range p.lexers {
		if s.document {
			most = max(most, s.mostLoads)
		}
	}
	return most
}

// No lexer that reads a document advances over more than lexBytesPerCheck and
// a keyword's bytes between two readings of the deadline, or after its last
// one: counted from the bytes it loads through at and where it stands, apart
// from due and from lexTrace, its copies with it, on the files of the counting
// test and on a long hex string, fully escaped names, literal escapes,
// integers the parser looks past, keywords at the worst alignment, short
// tokens and repeated peeks, and a hex string and names the integer lookahead
// reads and then reads again; and none loads through at more than loadBound
// with no reading of the deadline.
func TestLexerProbeAdvancement(t *testing.T) {
	bound := lexBytesPerCheck + maxNameBytes
	for _, c := range lexOpenings() {
		t.Run(c.name, func(t *testing.T) {
			p := newProbe()
			defer p.close()
			ctx := &lexReadings{Context: context.Background(), onRead: p.read}
			if _, err := open(ctx, c.data, &inflateBudget{total: 64 << 20, one: 16 << 20}); isDeadline(err) || isBound(err) {
				t.Fatal(err)
			}
			most, total := p.most()
			if loads := p.mostLoads(); loads > loadBound {
				t.Fatalf("%d loads through at with no reading of the deadline, at most %d", loads, loadBound)
			}
			t.Logf("%d bytes: at most %d advanced over between two readings or after the last, %d in all", len(c.data), most, total)
			if total < c.advanced {
				t.Fatalf("the probe saw %d bytes advanced over, and reading the file advances over at least %d", total, c.advanced)
			}
			if most > bound {
				t.Fatalf("%d bytes advanced over with no reading of the deadline, at most %d", most, bound)
			}
		})
	}
	for _, c := range []struct {
		name, data string
		mode       string
	}{
		{"a long hex string", "<" + strings.Repeat("4 1 ", 100000) + ">", "token"},
		{"fully escaped names", strings.Repeat("/"+strings.Repeat("#41", 4096)+" ", 10), "token"},
		{"literal escapes", "(" + strings.Repeat("\\101\\\r\n", 100000) + ")", "token"},
		{"integers the parser looks past", "[" + strings.Repeat("1 2 ", 20000) + "]", "parse"},
		{"an array ending at endobj", "[" + strings.Repeat("1 ", 20000) + "endobj", "parse"},
		{"keywords at the worst alignment", strings.Repeat(" ", lexBytesPerCheck-1) + strings.Repeat("k", maxNameBytes) + " []", "token"},
		{"short tokens", strings.Repeat("[]", 50000), "parse"},
		{"repeated peeks", strings.Repeat("obj endobj stream ", 6000), "peek"},
		{"a comment ending where the reading falls due", "%" + strings.Repeat("x", lexBytesPerCheck-1) + "\n" + strings.Repeat("[]", 20000), "token"},
		{"a long hex string the lookahead reads again", "[1 <" + strings.Repeat("4 1 ", 100000) + ">]", "parse"},
		{"escaped names the lookahead reads again", "[" + strings.Repeat("1 /"+strings.Repeat("#41", maxNameBytes)+" ", 10) + "]", "parse"},
	} {
		t.Run(c.name, func(t *testing.T) {
			p := newProbe()
			defer p.close()
			ctx := &lexReadings{Context: context.Background(), onRead: p.read}
			d := stopDoc(c.data, ctx)
			l := newLexer(d.data, 0).within(d.budgeted())
			parser := &parser{lex: l, allow: l.room}
			for l.pos < len(l.data) && !l.spent && !l.halted {
				before := l.pos
				var err error
				if c.mode == "peek" {
					l.peekKeyword("obj")
					l.peekKeyword("endobj")
				}
				if c.mode == "parse" {
					_, err = parser.parseObject(0)
				} else {
					_, err = l.next()
				}
				if isBound(err) || before == l.pos {
					break
				}
			}
			most, total := p.most()
			if loads := p.mostLoads(); loads > loadBound {
				t.Fatalf("%d loads through at with no reading of the deadline, at most %d", loads, loadBound)
			}
			t.Logf("%d bytes: at most %d advanced over between two readings or after the last, %d in all, %d readings", len(c.data), most, total, ctx.reads)
			if total < len(c.data)-1 {
				t.Fatalf("the probe saw %d bytes advanced over of %d", total, len(c.data))
			}
			if most > bound {
				t.Fatalf("%d bytes advanced over with no reading of the deadline, at most %d", most, bound)
			}
			if ctx.reads == 0 {
				t.Fatalf("%d bytes advanced over with no reading of the deadline at all", total)
			}
		})
	}
}

// A lexer stopped by the deadline loads nothing more through at: 16,384
// spaces and then "[]", the deadline passing at the first reading, which the
// skip makes where the spaces end. The call that read it and every call after
// it return the deadline, and the calls after it, a step back included, load
// no byte through at. Only loads through at are counted: see at.
func TestLexerProbeStoppedLoadsNothing(t *testing.T) {
	p := newProbe()
	defer p.close()
	d := stopDoc(strings.Repeat(" ", lexBytesPerCheck)+"[]", &stopReads{Context: context.Background(), n: 1})
	l := newLexer(d.data, 0).within(d.budgeted())
	if tok, err := l.next(); !isDeadline(err) {
		t.Fatalf("the call that read the deadline returned %v, %v", tok.kind, err)
	}
	loads := p.loads
	for i := 0; i < 5; i++ {
		if tok, err := l.next(); !isDeadline(err) {
			t.Fatalf("call %d after the stop returned %v, %v", i+2, tok.kind, err)
		}
	}
	l.back(0)
	if tok, err := l.next(); !isDeadline(err) {
		t.Fatalf("after a step back the lexer returned %v, %v", tok.kind, err)
	}
	if p.loads != loads {
		t.Fatalf("the stopped lexer loaded %d bytes", p.loads-loads)
	}
}

// A keyword of 4,096 bytes peeked at a hundred times: each peek reads the
// keyword and steps back over it, so the lexer advances over 409,600 bytes
// in all -- the figure the peeks make, and not one the lexer reports -- and
// it reads the deadline as it goes, never more than lexBytesPerCheck and a
// keyword's bytes between two readings, however the peek is made.
func TestLexerProbeRepeatedKeyword(t *testing.T) {
	const peeks = 100
	p := newProbe()
	defer p.close()
	ctx := &lexReadings{Context: context.Background(), onRead: p.read}
	d := stopDoc(strings.Repeat("k", maxNameBytes)+" ", ctx)
	l := newLexer(d.data, 0).within(d.budgeted())
	for i := 0; i < peeks; i++ {
		l.peekKeyword("x")
	}
	most, total := p.most()
	if loads := p.mostLoads(); loads > loadBound {
		t.Fatalf("%d loads through at with no reading of the deadline, at most %d", loads, loadBound)
	}
	t.Logf("%d peeks: %d bytes advanced over, at most %d between two readings or after the last, %d readings", peeks, total, most, ctx.reads)
	if want := peeks * maxNameBytes; total != want {
		t.Fatalf("the probe saw %d bytes advanced over, and %d peeks of a keyword of %d bytes advance over %d", total, peeks, maxNameBytes, want)
	}
	if ctx.reads == 0 {
		t.Fatalf("%d bytes advanced over with no reading of the deadline", total)
	}
	if bound := lexBytesPerCheck + maxNameBytes; most > bound {
		t.Fatalf("%d bytes advanced over with no reading of the deadline, at most %d", most, bound)
	}
}
