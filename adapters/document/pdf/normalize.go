package pdf

import (
	"strings"
	"unicode/utf8"
)

// byteOrderMark is U+FEFF, which the normalisation's step 1 removes from
// the start of a text.
const byteOrderMark = 0xFEFF

// streamNormalizer yields attachment.NormalizeText's result for a text
// written to it one rune at a time, and says as soon as that result is
// certain to be longer than limit bytes -- which is what lets a page be refused by the
// text budget on its normalised length without holding more than the
// budget in memory.
//
// It keeps the normalised text so far (kept): everything from the start of
// the first line that is not blank to the end of the last character of a
// line that is not blank, spaces on such a line included. After kept comes
// pending blank material -- line feeds, and spaces and tabs on lines that
// are blank so far -- which a later character that is not blank would keep
// and the end of the text drops. Pending material is counted always and
// stored only while kept and it fit the limit: past that, any character
// that would keep it takes the text past the limit.
type streamNormalizer struct {
	limit    int
	kept     strings.Builder
	pending  []byte
	pendingN int
	started  bool // a rune has been written: step 1 looks at the first only
	afterCR  bool // the previous rune was a CR: step 2's CR LF is one break
	nonBlank bool // kept holds a character that is not blank
	lineKept bool // the current line holds a character that is not blank
	over     bool // the normalised text is longer than limit
}

func (s *streamNormalizer) write(r rune) {
	if s.over {
		return
	}
	first := !s.started
	s.started = true
	if first && r == byteOrderMark {
		return
	}
	if r == '\n' && s.afterCR {
		s.afterCR = false
		return
	}
	s.afterCR = r == '\r'
	switch {
	case r == '\r' || r == '\n':
		s.lineKept = false
		if !s.nonBlank {
			// The line that ends is blank and comes before any line that
			// is not: step 4 removes it.
			s.pending = s.pending[:0]
			s.pendingN = 0
			return
		}
		s.hold('\n')
	case r == ' ' || r == '\t':
		if s.lineKept {
			if s.kept.Len()+1 > s.limit {
				s.over = true
				return
			}
			s.kept.WriteByte(byte(r))
			return
		}
		s.hold(byte(r))
	case r < 0x20 || r == 0x7f:
		// Step 3.
	default:
		if s.kept.Len()+s.pendingN+utf8.RuneLen(r) > s.limit {
			s.over = true
			return
		}
		s.kept.Write(s.pending)
		s.pending = s.pending[:0]
		s.pendingN = 0
		s.kept.WriteRune(r)
		s.nonBlank, s.lineKept = true, true
	}
}

func (s *streamNormalizer) hold(c byte) {
	s.pendingN++
	if s.kept.Len()+s.pendingN <= s.limit {
		s.pending = append(s.pending, c)
	}
}

// text is the normalised text, pending blank material dropped.
func (s *streamNormalizer) text() string { return s.kept.String() }
