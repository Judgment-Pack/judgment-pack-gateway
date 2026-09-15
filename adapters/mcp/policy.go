package mcp

import (
	"fmt"
	"sort"
	"strings"
)

// Display policy 1 (docs/design/tool-descriptors.md) is what a string a
// model or a person could be shown may not hold: Cc but tab and line feed,
// Bidi_Control, Default_Ignorable_Code_Point, Co, Cn and
// Noncharacter_Code_Point, as the Unicode 15.0.0 character database
// assigns them. The classes come from the table generated from that
// database (policy_table.go), never from the runtime's own tables, so the
// adapter that captures and the frontend that serves judge alike whatever
// release of Go built either (gen_policy.go says how the table is made).
// The policy refuses; it never strips.
const displayPolicy = 1

// codeRange is an inclusive range of code points.
type codeRange struct{ lo, hi rune }

// displayRefuses reports whether policy 1 refuses r.
func displayRefuses(r rune) bool {
	i := sort.Search(len(displayRefused), func(i int) bool { return displayRefused[i].hi >= r })
	return i < len(displayRefused) && displayRefused[i].lo <= r
}

// displayRefusal is the first code point of s that policy 1 refuses, and
// whether there is one.
func displayRefusal(s string) (rune, bool) {
	for _, r := range s {
		if displayRefuses(r) {
			return r, true
		}
	}
	return 0, false
}

// visible writes s for an operator's terminal: every control character,
// tab and line feed included, and every character policy 1 refuses as a
// visible escape, \u{XXXX}, and everything else as it is.
func visible(s string) string {
	var b strings.Builder
	for _, r := range s {
		if r < 0x20 || r == 0x7f || displayRefuses(r) {
			fmt.Fprintf(&b, `\u{%04X}`, r)
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}
