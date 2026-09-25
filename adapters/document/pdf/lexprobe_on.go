//go:build pdflexprobe

package pdf

import "sync/atomic"

// lexProbed: see lexprobe_off.go. This is the build made for the tests.
const lexProbed = true

// lexIdentity is what the probe knows a lexer by: a number newLexer gives
// each lexer it makes, which every copy of that lexer carries with it. A
// lexer made over the data another stands in, where it stands, is the same
// reader made again, and takes that one's number: lexStanding, where the
// probe sets it, says whose it is.
type lexIdentity struct{ id int64 }

var lexIdentities atomic.Int64

// lexStanding, where it is set, names the lexer that stands in data at pos,
// or zero for none.
var lexStanding func(data []byte, pos int) int64

func newLexIdentity(data []byte, pos int) lexIdentity {
	if lexStanding != nil {
		if id := lexStanding(data, pos); id != 0 {
			return lexIdentity{id: id}
		}
	}
	return lexIdentity{id: lexIdentities.Add(1)}
}
