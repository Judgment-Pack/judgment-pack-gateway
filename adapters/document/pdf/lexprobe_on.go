//go:build pdflexprobe

package pdf

import "sync/atomic"

// lexProbed: see lexprobe_off.go. This is the build made for the tests.
const lexProbed = true

// lexIdentity is what the probe knows a lexer by: a number newLexer gives
// each lexer it makes, which every copy of that lexer carries with it.
type lexIdentity struct{ id int64 }

var lexIdentities atomic.Int64

func newLexIdentity() lexIdentity { return lexIdentity{id: lexIdentities.Add(1)} }
