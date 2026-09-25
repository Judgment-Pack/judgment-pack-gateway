//go:build pdflexprobe

package pdf

import (
	"context"
	"strings"
	"testing"
)

// These tests run in the build made with the pdflexprobe tag, where every
// byte a lexer loads is told to lexLoaded and every reading of tokens and
// every skip to lexEntered: see lexProbed. TestTheLexerProbesHold runs them
// from the ordinary build.

// probeLexer is what the probe has seen of one lexer: how deep in a reading of
// tokens or a skip it stands, the furthest byte it has loaded in the reading
// under way, how far what it advanced over has been counted, and what it
// advanced over since its last reading of the deadline, the most of that
// between two readings or after the last, in all, and its readings.
type probeLexer struct {
	depth, frontier, counted int
	gap, most, total, reads  int
}

// probe counts what each lexer advances over from what it loads and where it
// stands, and nothing else: a byte is advanced over when it has been loaded
// and the lexer has moved past it, counted when the reading of tokens or the
// skip that moved past it ends or a reading of the deadline is made. A
// reading of tokens begins where the lexer stands, however it came to stand
// there, so a byte read again after a step back is counted again, whatever
// the step back was spelled as.
type probe struct {
	lexers map[*lexer]*probeLexer
	loads  int
}

func newProbe() *probe {
	p := &probe{lexers: map[*lexer]*probeLexer{}}
	lexLoaded = func(l *lexer, i int) {
		p.loads++
		if s := p.lexers[l]; s != nil {
			s.frontier = max(s.frontier, i+1)
		}
	}
	lexEntered = func(l *lexer) func() {
		s := p.lexers[l]
		if s == nil {
			s = &probeLexer{}
			p.lexers[l] = s
		}
		if s.depth == 0 {
			s.frontier, s.counted = l.pos, l.pos
		}
		s.depth++
		return func() {
			p.count(l, s)
			s.depth--
		}
	}
	return p
}

func (p *probe) count(l *lexer, s *probeLexer) {
	if n := min(l.pos, s.frontier) - s.counted; n > 0 {
		s.total += n
		s.gap += n
		s.counted += n
		s.most = max(s.most, s.gap)
	}
}

// read is a reading of the deadline: what every lexer in a reading of tokens
// has advanced over is counted up to it, and its stretch begins again.
func (p *probe) read() {
	for l, s := range p.lexers {
		if s.depth > 0 {
			p.count(l, s)
			s.gap = 0
			s.reads++
		}
	}
}

func (p *probe) close() { lexLoaded, lexEntered = nil, nil }

// most is the longest stretch any lexer that reads the deadline advanced
// over with no reading of it, its last stretch -- to the last byte it
// consumed -- included, and what those lexers advanced over in all.
func (p *probe) most() (most, total int) {
	for l, s := range p.lexers {
		if l.work != nil && l.work.doc != nil {
			most = max(most, s.most)
			total += s.total
		}
	}
	return most, total
}

// No lexer that reads a document advances over more than lexBytesPerCheck
// and a keyword's bytes between two readings of the deadline, or after its
// last one: counted from the bytes it loads and where it stands, apart from
// due and from lexTrace, on the files of the counting test and on a long hex
// string, fully escaped names, literal escapes, integers the parser looks
// past, keywords at the worst alignment, short tokens and repeated peeks.
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
			t.Logf("%d bytes: at most %d advanced over between two readings or after the last, %d in all, %d readings", len(c.data), most, total, ctx.reads)
			if total < len(c.data)-1 {
				t.Fatalf("the probe saw %d bytes advanced over of %d", total, len(c.data))
			}
			if most > bound {
				t.Fatalf("%d bytes advanced over with no reading of the deadline, at most %d", most, bound)
			}
		})
	}
}

// A lexer stopped by the deadline loads nothing more: 16,384 spaces and then
// "[]", the deadline passing at the first reading, which the skip makes where
// the spaces end. The call that read it and every call after it return the
// deadline, and the calls after it, a step back included, load no byte.
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
