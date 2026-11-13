package main

import (
	"strings"
	"testing"
)

// The scope identifier's form (SPEC.md §1.2a, scope), case by case: the
// corpus holds it in receipts (v3-scope-*), and this holds the one function
// the configuration and the verifier share to the same cases.
func TestTheScopeIdentifiersForm(t *testing.T) {
	for _, s := range []string{
		"a",
		"scope-a",
		"équipe 北",
		" leading and trailing ",
		strings.Repeat("\U0001F600", 4) + strings.Repeat("é", 56), // 128 bytes
		strings.Repeat("a", 128),
		"\u2028", // a line separator is no class of policy 1
	} {
		if !isScopeIdentifier(s) {
			t.Errorf("%q is refused, and is of the form", s)
		}
	}
	for _, s := range []string{
		"",
		strings.Repeat("a", 129),
		strings.Repeat("a", 127) + "é",         // 129 bytes, 128 code points
		strings.Repeat("\U0001F600", 32) + "a", // 129 bytes, 33 code points
		"scope\ta", "scope\na", "scope\ra",     // tab and line feed beside a control policy 1 refuses
		"scope\x00a", "scope\x7fa", "scope\u0085a", // C0, DEL, C1
		"scope\u00ada", "scope\u200ba", "scope\u200da", // invisible
		"scope\u202ea", "scope\u2066a", "scope\ufeffa", // bidi controls and the byte order mark
		"scope\ue000a", "scope\U000F0000a", // private use
		"scope\u2ffca", "scope\u0378a", // unassigned in Unicode 15.0.0
		"scope\ufdd0a", "scope\uffffa", "scope\U000E0001a", // noncharacters and a tag
		"scope\xffa", "scope\xed\xa0\x80a", // no UTF-8, a surrogate's encoding among it
	} {
		if isScopeIdentifier(s) {
			t.Errorf("%q is of the form, and is not", s)
		}
	}
}
