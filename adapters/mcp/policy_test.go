package mcp

import (
	"testing"
	"unicode"
)

// runtimeRefuses is policy 1 derived again, from Go's own tables and the
// definitions the character database states: Default_Ignorable_Code_Point
// is Other_Default_Ignorable_Code_Point, Cf and Variation_Selector, less
// White_Space, U+FFF9..U+FFFB, U+13430..U+13440 and
// Prepended_Concatenation_Mark; Cn is what no other category holds.
func runtimeRefuses(r rune) bool {
	if r == '\t' || r == '\n' {
		return false
	}
	assigned := false
	for _, table := range []*unicode.RangeTable{unicode.L, unicode.M, unicode.N, unicode.P, unicode.S, unicode.Z, unicode.Cc, unicode.Cf, unicode.Co, unicode.Cs} {
		if unicode.Is(table, r) {
			assigned = true
			break
		}
	}
	ignorable := (unicode.Is(unicode.Other_Default_Ignorable_Code_Point, r) || unicode.Is(unicode.Cf, r) || unicode.Is(unicode.Variation_Selector, r)) &&
		!unicode.Is(unicode.White_Space, r) && !(r >= 0xFFF9 && r <= 0xFFFB) && !(r >= 0x13430 && r <= 0x13440) &&
		!unicode.Is(unicode.Prepended_Concatenation_Mark, r)
	return unicode.Is(unicode.Cc, r) || unicode.Is(unicode.Bidi_Control, r) || ignorable ||
		unicode.Is(unicode.Co, r) || !assigned || unicode.Is(unicode.Noncharacter_Code_Point, r)
}

// The generated table is the policy over every code point, as a second
// derivation from Go's tables finds it -- when those tables are Unicode
// 15.0.0, the version the policy names. The table is generated from the
// database's files and never from the runtime, so a Go release on another
// version cannot move it; this check then has nothing to compare against.
func TestTheTableIsUnicode15Policy(t *testing.T) {
	if unicode.Version != "15.0.0" {
		t.Skipf("Go's tables are Unicode %s; the cross-check needs 15.0.0", unicode.Version)
	}
	mismatches := 0
	for r := rune(0); r <= unicode.MaxRune; r++ {
		if got, want := displayRefuses(r), runtimeRefuses(r); got != want {
			if mismatches++; mismatches <= 20 {
				t.Errorf("U+%04X: the table says refused=%v, Unicode 15.0.0 says %v", r, got, want)
			}
		}
	}
	if mismatches > 0 {
		t.Fatalf("%d code points disagree", mismatches)
	}
	for i := 1; i < len(displayRefused); i++ {
		if displayRefused[i].lo <= displayRefused[i-1].hi+1 {
			t.Fatalf("ranges %d and %d overlap or touch: the table is not in its stated form", i-1, i)
		}
	}
}

func TestVisibleEscapesWhatThePolicyRefusesAndEveryControl(t *testing.T) {
	for in, want := range map[string]string{
		"plain":                 "plain",
		"tab\there":             `tab\u{0009}here`,
		"line\nbreak":           `line\u{000A}break`,
		"del\x7f":               `del\u{007F}`,
		"rtl\u202eoverride":     `rtl\u{202E}override`,
		"zero\u200bwidth":       `zero\u{200B}width`,
		"tag\U000E0041":         `tag\u{E0041}`,
		"caf\u00e9\u00a0\u2028": "caf\u00e9\u00a0\u2028",
	} {
		if got := visible(in); got != want {
			t.Errorf("visible(%q) = %q, want %q", in, got, want)
		}
	}
}
