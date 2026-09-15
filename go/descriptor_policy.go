package main

// Display policy 1 and schema grammar 1 (docs/design/tool-descriptors.md),
// as the frontend judges a snapshot again at start: an implementation of
// its own, written apart from the adapter's, that answers to the same
// shared vectors (testdata/tool-descriptors). The frontend holds no
// credentials, so it cannot screen for them; the adapter that captured did.

// codeRange is an inclusive range of code points; policy_table.go holds the
// ranges policy 1 refuses, generated from the Unicode 15.0.0 character
// database by adapters/mcp/gen_policy.go:
//
//	go run ../adapters/mcp/gen_policy.go -ucd DIR -package main -o policy_table.go
type codeRange struct{ lo, hi rune }

// policyRefused holds a bit for every code point policy 1 refuses, set once
// from the generated table: the frontend's lookup is a bit, the adapter's a
// search, and both read the same database's ranges.
var policyRefused = func() []uint64 {
	bits := make([]uint64, (0x10FFFF+64)/64)
	for _, r := range displayRefused {
		for c := r.lo; c <= r.hi; c++ {
			bits[c/64] |= 1 << (uint(c) % 64)
		}
	}
	return bits
}()

// policyRefuses reports whether display policy 1 refuses r.
func policyRefuses(r rune) bool {
	if r < 0 || r > 0x10FFFF {
		return true
	}
	return policyRefused[r/64]&(1<<(uint(r)%64)) != 0
}

// firstRefused is the first code point of s policy 1 refuses.
func firstRefused(s string) (rune, bool) {
	for _, r := range s {
		if policyRefuses(r) {
			return r, true
		}
	}
	return 0, false
}
