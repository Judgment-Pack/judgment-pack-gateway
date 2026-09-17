package attachment

import (
	"strings"
	"unicode/utf8"
)

// NormalizeText is the record's text normalisation
// (docs/design/attachments.md, "Text normalisation"), in its four steps:
//
//  1. a U+FEFF that is the first character is removed;
//  2. each CR LF becomes LF, and then each remaining CR becomes LF;
//  3. every character from U+0000 to U+0008, from U+000B to U+001F, and
//     U+007F is removed;
//  4. the text is split at each LF into lines, a line whose every character
//     is U+0020 or U+0009 (the empty line included) is blank, blank lines
//     are removed from the start and the end, and the rest are joined
//     with LF.
//
// testdata/attachments/normalisation-v1.json holds the vectors it answers
// to. It is not idempotent: a U+FEFF that step 4 brings to the start of
// the result stays, and a second pass would remove it. A byte that is not
// UTF-8 becomes U+FFFD; the note hands it valid UTF-8 only.
func NormalizeText(s string) string {
	s = strings.TrimPrefix(s, "\xEF\xBB\xBF")
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); {
		r, n := utf8.DecodeRuneInString(s[i:])
		switch {
		case r == '\r':
			b.WriteByte('\n')
			if i+1 < len(s) && s[i+1] == '\n' {
				n = 2
			}
		case r == '\n' || r == '\t':
			b.WriteByte(byte(r))
		case removedControl(r):
		case r == utf8.RuneError && n == 1:
			b.WriteRune(utf8.RuneError)
		default:
			b.WriteString(s[i : i+n])
		}
		i += n
	}
	lines := strings.Split(b.String(), "\n")
	start, end := 0, len(lines)
	for start < end && BlankLine(lines[start]) {
		start++
	}
	for end > start && BlankLine(lines[end-1]) {
		end--
	}
	return strings.Join(lines[start:end], "\n")
}

// removedControl is step 3's set, and also CR, which step 2 has replaced
// by the time step 3 runs.
func removedControl(r rune) bool {
	return (r >= 0 && r < 0x20 && r != '\t' && r != '\n') || r == 0x7f
}

// BlankLine is step 4's blank line: every character U+0020 or U+0009.
func BlankLine(line string) bool {
	for i := 0; i < len(line); i++ {
		if line[i] != ' ' && line[i] != '\t' {
			return false
		}
	}
	return true
}

// IsNormalized reports whether text is a string NormalizeText can return:
// valid UTF-8, no character step 2 or step 3 removes, and, unless empty, a
// first line and a last line that are not blank. Every such string is the
// normalisation of itself or, when it begins with U+FEFF, of itself behind
// one line feed.
func IsNormalized(text string) bool {
	if !utf8.ValidString(text) {
		return false
	}
	for _, r := range text {
		if r == '\r' || removedControl(r) {
			return false
		}
	}
	if text == "" {
		return true
	}
	first, last := text, text
	if i := strings.IndexByte(text, '\n'); i >= 0 {
		first = text[:i]
	}
	if i := strings.LastIndexByte(text, '\n'); i >= 0 {
		last = text[i+1:]
	}
	return !BlankLine(first) && !BlankLine(last)
}
