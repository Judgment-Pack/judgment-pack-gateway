//go:build !pdflexprobe

package pdf

// lexProbed is set in the build made for the tests with the pdflexprobe tag,
// where every byte a lexer loads through at, and every reading of tokens and
// every skip it makes, is told to the tests: see at. In every other build it
// is not, and what it guards is not compiled.
const lexProbed = false

// lexIdentity is what the probe build knows a lexer by. In every other build
// it is empty: a lexer holds it first, where it takes no room, and making it
// costs nothing.
type lexIdentity struct{}

func newLexIdentity(data []byte, pos int) lexIdentity { return lexIdentity{} }
