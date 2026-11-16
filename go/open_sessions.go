package main

// A session another process left open (gateway #381). A gateway holds its
// sessions in memory -- each one's next callIndex and the signature its next
// receipt chains to -- and seals one only when asked (docs/design/mcp-server.md,
// "Sessions"). A gateway that stops, by a signal or a crash, leaves every
// session it had not sealed in the store with receipts and no seal: gateway
// verify reads it unregistered-session (SPEC.md §4 step 3), and observes it
// session-open while its receipts are whole.
//
// The process that starts next does not hold such a session, and takes none
// up: a read into it is refused before its source runs, and so is a seal.
// Where instances serve one PostgreSQL database beside one another
// (storage.instances "several"), each session is held by the instance that
// admitted its first call (store_pg_instances.go): another instance refuses
// a read into it, and a seal of it, 409 while that instance's row of the
// start lease is live (refusalHeldElsewhere), and once the row has expired
// judges it as one another process left open.
// Neither the chain nor the count can be had from the store alone. The store
// is outside the trust boundary, and the seal exists to anchor a session's
// final count outside it (SPEC.md §2, "Final-tail rollback"): a session whose
// last receipts were taken away between the stop and the start reads, on
// disk, as a whole shorter session, so a chain continued from the disk, or a
// seal of the count found there, would sign over that rollback -- the one a
// seal made from this process's own count catches -- and a chain continued
// from a receipt it lost would mint a second receipt at an index the session
// had already used. Before this, a read was admitted by memory alone: its
// source ran, and its stamp then found receipt 0 in place, or, in a session
// that had lost receipt 0, made a new one beside the old chain.
//
// A seal made after an interruption is a record of its own that says so, in
// the registry, under the gateway's signature (SPEC.md §3c): a seal of §3's
// form would say the same of a count read from the store as of one this
// process kept. /seal never makes one. gateway seal-open makes it, with the
// gateway stopped, and the start makes it with the switch on
// (seal_open.go), over a session whose receipts are whole; such a session
// is then sealed in the registry, never continued, and its store verifies.

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// The refusals of a session this process does not hold and may not take up,
// for a read's admission and for a seal: the same words for both, since the
// session's state is the same.
const (
	refusalLeftOpen = "session %s was left open by another process: the store holds receipts in it that this process did not mint, and no seal closes it; its chain is not continued from an empty memory, nor is it sealed here from a count on disk, so acquire into a new session (gateway verify reports this one unregistered-session, and observes it session-open while its receipts are whole; gateway seal-open, with the gateway stopped, seals it as sealed after an interruption)"
	refusalNotADir  = "session %s is in the store as something other than a session directory, which this process did not make; nothing is taken up there"
	refusalUnread   = "session %s could not be read in the store, so whether another process left receipts in it is not known; it is refused rather than taken for empty"
	// refusalOtherScope is an acquisition's into a session whose receipts
	// are of another scope than the source's: on every kind, one this
	// process holds (ADR-0036), and on a kind that keeps each scope
	// identifier's rows apart (scopeKeeper) one left in the store too, with
	// receipts or none. It names neither scope.
	refusalOtherScope = "session %s holds the receipts of a scope other than this source's (another scope identifier, or none): a session's receipts are of one scope, so acquire into a new session"
	// refusalActionInScope is an action's into a session of a scope
	// identifier: an action receipt carries no scope (ADR-0026), and a
	// session's receipts are of one scope (ADR-0036). It is the acquisition's
	// sentence, which names no scope and does not say whether the session's
	// is another identifier or none.
	refusalActionInScope = refusalOtherScope
	// refusalHeldElsewhere is a read's and a seal's, where instances serve
	// one database beside one another, into a session another instance
	// holds whose row of the start lease is live. It names no instance.
	refusalHeldElsewhere = "session %s is held by another gateway instance serving this database: a session is served by the instance that admitted its first call, so send its calls and its seal to that instance, or acquire into a new session"
)

// sessionHeldElsewhere is refusalHeldElsewhere: answered 409, before the
// source runs.
type sessionHeldElsewhere struct{ error }

// leftInStore is why this process may not take up a session it does not
// hold -- a badRequest, or, where another live instance holds it, a
// sessionHeldElsewhere -- or nil when the store holds nothing in it that this process could
// collide with: no entry at all, or a directory holding no receipt. A
// receipt is any entry whose name ends in ".json", whatever it holds: every
// one verification counts (verifySessionUnder), a torn receipt or a junk
// file in a receipt's place among them, and a directory so named too, which
// verification does not count and a stamp at its index would collide with.
// A staging file an interrupted write left behind is no receipt. An entry
// of another kind where the session's directory would be -- a file, a link,
// one that leads nowhere among them -- is refused, as an action's session
// step refuses it (sessionMintedHere): the stamp could not put a receipt
// there that verification enumerates. A look that fails for any reason but
// absence is a refusal, never an empty session.
//
// Called under the service's lock, by a read's admission and by a seal, for
// a session not in its map: a session this process has minted into stays
// in the map (release) -- but for one whose first receipt's write reported an
// error although the file landed, which is refused here too -- so what the store holds in one that is not there
// is another process's. The directory is read only as far as its first
// receipt.
// leftInStoreBatch is how many directory entries one read of the look takes.
// A variable so a test can make a receipt fall past the first read on any
// file system, whatever order it lists entries in.
var leftInStoreBatch = 64

// leftInStore's scope is the scope identifier of the source an acquisition
// is for ("" for none), and acquiring says it is one; a seal names no
// scope. On a kind that keeps each scope's rows apart (scopeKeeper), a
// session of the name is looked for in every scope the kind records, since
// a session's name is one across scopes: an acquisition into one of another
// scope is refused whatever it holds (refusalOtherScope), since its stamp
// could not be made there; one of its own scope, and a seal, are judged by
// its receipts.
func (g *gatewayService) leftInStore(sessionID, scope string, acquiring bool) error {
	if g.claimer != nil {
		return g.heldInStore(sessionID, scope, acquiring)
	}
	if refusal := g.leftInStoreRefusal(sessionID, scope, acquiring); refusal != "" {
		return badRequest{errors.New(refusal)}
	}
	return nil
}

// heldInStore is leftInStore where instances serve one database beside one
// another: an acquisition claims the session's series for this instance, or
// takes it up from an instance whose row has expired, where it holds no
// receipt (claimSeries); a seal reads who holds it and changes nothing.
func (g *gatewayService) heldInStore(sessionID, scope string, acquiring bool) error {
	var claim seriesClaim
	var err error
	if acquiring {
		claim, err = g.claimer.claimSeries(sessionID, scope)
	} else {
		claim, err = g.claimer.seriesHolding(sessionID)
	}
	switch {
	case err != nil:
		return badRequest{fmt.Errorf(refusalUnread, sessionID)}
	case claim == seriesOfOtherScope:
		return badRequest{fmt.Errorf(refusalOtherScope, sessionID)}
	case claim == seriesHeldElsewhere:
		return sessionHeldElsewhere{fmt.Errorf(refusalHeldElsewhere, sessionID)}
	case claim == seriesLeftOpen:
		return badRequest{fmt.Errorf(refusalLeftOpen, sessionID)}
	}
	return nil
}

func (g *gatewayService) leftInStoreRefusal(sessionID, scope string, acquiring bool) string {
	refused := func(why string) string { return fmt.Sprintf(why, sessionID) }
	if g.keeper != nil {
		held, ofScope, receipts, err := g.keeper.seriesHeld(sessionID, scope)
		switch {
		case err != nil:
			return refused(refusalUnread)
		case !held:
			return ""
		case acquiring && !ofScope:
			return refused(refusalOtherScope)
		case receipts:
			return refused(refusalLeftOpen)
		}
		return ""
	}
	if g.kind != nil {
		// the kind's series, through the contract: no series is no receipt
		entries, err := g.store.receipts.listEntries(sessionID)
		switch {
		case faultOf(err) == faultAbsent:
			return ""
		case err != nil:
			return refused(refusalUnread)
		case len(entries) > 0:
			return refused(g.leftOpenRefusal(sessionID, scope, acquiring))
		}
		return ""
	}
	path := filepath.Join(g.storeRoot, "receipts", sessionID)
	entry, err := os.Lstat(path)
	switch {
	case err != nil && absent(err):
		return ""
	case err != nil:
		return refused(refusalUnread)
	case !entry.IsDir():
		return refused(refusalNotADir)
	}
	dir, err := os.Open(path)
	if err != nil {
		return refused(refusalUnread)
	}
	defer dir.Close()
	for {
		entries, err := dir.ReadDir(leftInStoreBatch)
		for _, e := range entries {
			if strings.HasSuffix(e.Name(), ".json") {
				return refused(g.leftOpenRefusal(sessionID, scope, acquiring))
			}
		}
		if err == io.EOF {
			return ""
		}
		if err != nil {
			return refused(refusalUnread)
		}
	}
}

// leftOpenRefusal is the refusal of a session another process left receipts
// in, on a kind that keeps no scope's rows apart: an acquisition into one
// whose receipts are of a scope other than the source's is refused as one
// into another scope's session is on every kind (refusalOtherScope), whatever
// else it holds, so the answer says nothing of the state of a session of
// another scope identifier (ADR-0037); a seal, and an acquisition of the
// session's own scope, are told it was left open.
func (g *gatewayService) leftOpenRefusal(sessionID, scope string, acquiring bool) string {
	if acquiring {
		if held, of, known := g.storedScope(sessionID); held && known && of != scope {
			return refusalOtherScope
		}
	}
	return refusalLeftOpen
}

// receiptScopeLimit bounds the receipt storedScope reads for its scope.
const receiptScopeLimit = 8 << 20

// storedScope is, of a session this process does not hold, whether the
// store holds it, the scope identifier it is of ("" for none), and whether
// that scope is known. On a kind that keeps each scope's rows apart the
// kind says it (seriesScope), whatever the session holds; on any other the
// first receipt's scope member does (a session's receipts are of one scope,
// ADR-0036), and a session holding no receipt is not held. A look that fails,
// a receipt that does not read as one JSON object, and an entry that is not
// a session's directory leave the scope unknown.
func (g *gatewayService) storedScope(sessionID string) (held bool, scope string, known bool) {
	if g.keeper != nil {
		held, scope, err := g.keeper.seriesScope(sessionID)
		return held, scope, err == nil
	}
	if g.kind != nil {
		entries, err := g.store.receipts.listEntries(sessionID)
		switch {
		case faultOf(err) == faultAbsent:
			return false, "", true
		case err != nil:
			return true, "", false
		case len(entries) == 0:
			return false, "", true
		}
		data, err := g.store.receipts.getEntry(sessionID, entries[0])
		if err != nil {
			return true, "", false
		}
		scope, known := receiptScope(data)
		return true, scope, known
	}
	path := filepath.Join(g.storeRoot, "receipts", sessionID)
	entry, err := os.Lstat(path)
	switch {
	case err != nil && absent(err):
		return false, "", true
	case err != nil || !entry.IsDir():
		return true, "", false
	}
	dir, err := os.Open(path)
	if err != nil {
		return true, "", false
	}
	defer dir.Close()
	for {
		entries, err := dir.ReadDir(leftInStoreBatch)
		for _, e := range entries {
			if strings.HasSuffix(e.Name(), ".json") {
				// a regular file alone, opened without blocking (readBounded)
				data, err := readBounded(filepath.Join(path, e.Name()), receiptScopeLimit)
				if err != nil {
					return true, "", false
				}
				scope, known := receiptScope(data)
				return true, scope, known
			}
		}
		if err == io.EOF {
			return false, "", true
		}
		if err != nil {
			return true, "", false
		}
	}
}

// receiptScope is a receipt's top-level scope member ("" where it holds
// none), and whether the receipt read as one JSON object whose scope, where
// it holds one, is a string.
func receiptScope(data []byte) (string, bool) {
	v, err := parseJSON(data)
	if err != nil {
		return "", false
	}
	obj, isObject := v.(*vObject)
	if !isObject {
		return "", false
	}
	if _, present := obj.get("scope"); !present {
		return "", true
	}
	return memberString(obj, "scope")
}
