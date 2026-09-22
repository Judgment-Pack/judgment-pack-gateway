package pdf

import (
	"context"
	"errors"
	"testing"
)

// A shared allowance can be exhausted after a nested read rebuilt the
// cross-reference. Its charge survives, but an abandoned read must still
// publish neither a failure nor an object into the new generation.
func TestIntegrationSpentAllowanceDoesNotPublishAnAbandonedRead(t *testing.T) {
	d := &Document{data: []byte("1 0 obj 42 endobj"), xref: map[int]xrefEntry{1: {offset: 0}}, cache: map[int]object{}, resolving: map[int]bool{}}
	end := d.beginRead()
	d.forgetObjects()
	d.parsedBytes = d.parsedBudget()
	charged := d.parsedBytes
	if _, ok := d.objectRead(1); ok {
		t.Fatal("an exhausted reading returned an object")
	}
	if _, kept := d.cache[1]; kept || d.bound != nil {
		t.Fatalf("abandoned reading published cache %v or bound %v", d.cache, d.bound)
	}
	if d.parsedBytes != charged {
		t.Fatalf("abandoned reading refunded its charge: %d, want %d", d.parsedBytes, charged)
	}
	end()
	if _, ok := d.objectRead(1); ok || d.bound == nil {
		t.Fatalf("the new generation did not meet the retained bound: read %v, bound %v", ok, d.bound)
	}
}

// The read fix retains the /N places even when the header ends early. The
// bounds fix must reserve those placeholders as well as readable pairs.
func TestIntegrationUnreadObjectStreamPlacesAreBudgeted(t *testing.T) {
	d := &Document{data: []byte("a small PDF file"), cache: map[int]object{}, objStms: map[int]*objStm{}, resolving: map[int]bool{}}
	s := &stream{dict: Dict{"Type": Name("ObjStm"), "N": int64(maxObjStmObjects), "First": int64(0)}}
	st, err := d.loadObjStm(1, s)
	if st != nil || !isBound(err) {
		t.Fatalf("unread places exceeded the allowance: header %v, error %v", st != nil, err)
	}
	if _, kept := d.objStmHeaders[1]; kept {
		t.Fatal("a partial header was cached")
	}
}

// Framing added by the read fix uses the bounds fix's clock deadline even
// when the context's cancellation timer has not run.
func TestIntegrationInlineImageReturnsTheClockDeadline(t *testing.T) {
	ctx := boundsStaleDeadline{Context: context.Background()}
	d := &Document{ctx: ctx}
	it := &interp{d: d, ctx: ctx}
	err := it.skipInlineImage(newLexer([]byte("/W 1 /H 1 /BPC 8 /CS /G ID x EI"), 0), nil)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("clock deadline returned %v", err)
	}
}

// A strict inline-image dictionary temporarily borrows the lexer's memory
// allowance. Content after ID must return to the caller's allowance.
func TestIntegrationInlineDictionaryRestoresTheLexerAllowance(t *testing.T) {
	room := &allowance{left: 1024}
	lex := newLexer([]byte("/W 1 /H 1 /BPC 8 /CS /G ID"), 0).reserving(room)
	it := &interp{}
	if _, err := it.readInlineImage(lex); err != nil {
		t.Fatal(err)
	}
	if lex.room != room || lex.strict {
		t.Fatal("the inline dictionary left its parser scope installed")
	}
}
