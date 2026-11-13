package main

// The scope identifier (SPEC.md §1.2a, `scope`;
// docs/adr/0026-a-scope-identifier-fixed-on-a-platform.md): an opaque label
// the operator fixes on a platform, which a request to the platform's sources
// repeats and their receipts carry. Its form is held in one place, here, by
// the configuration that fixes it and the verifier that reads it.

import "unicode/utf8"

// maxScopeBytes bounds a scope identifier, in bytes of UTF-8.
const maxScopeBytes = 128

// isScopeIdentifier is the form §1.2a states: 1 to 128 bytes of UTF-8 that
// hold no code point display policy 1 refuses (descriptor_policy.go), and
// neither tab nor line feed, which the policy admits in a description and a
// one-line identifier does not. Nothing is folded, trimmed or normalized: two
// identifiers are the same exactly when their bytes are.
func isScopeIdentifier(s string) bool {
	if len(s) == 0 || len(s) > maxScopeBytes || !utf8.ValidString(s) {
		return false
	}
	for _, r := range s {
		if r == '\t' || r == '\n' || policyRefuses(r) {
			return false
		}
	}
	return true
}

// scopeForm is what a refusal of a scope identifier out of form says of the
// form, quoting nothing of the value.
const scopeForm = "1 to 128 bytes of UTF-8 with no control, invisible, private-use, unassigned or noncharacter code point (display policy 1), and no tab or line feed"
