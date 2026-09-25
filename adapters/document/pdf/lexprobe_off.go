//go:build !pdflexprobe

package pdf

// lexProbed is set in the build made for the tests with the pdflexprobe tag,
// where every byte a lexer loads, and every reading of tokens and every skip
// it makes, is told to the tests: see at. In every other build it is not, and
// what it guards is not compiled.
const lexProbed = false
