package main

// A session an earlier process left open (gateway #381). A gateway holds its
// sessions in memory -- each one's next callIndex and the signature its next
// receipt chains to -- and seals one only when asked (docs/design/mcp-server.md,
// "Sessions"). A gateway that stops, by a signal or a crash, leaves every
// session it had not sealed in the store with receipts and no seal: gateway
// verify reads it unregistered-session (SPEC.md §4 step 3), and observes it
// session-open while its receipts are whole.
//
// The process that starts next does not hold such a session, and takes none
// up: a read into it is refused before its source runs, and so is a seal.
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
// A seal made after an interruption needs a record of its own that says so,
// in the registry, under the gateway's signature: a seal of today's form
// would say the same of a count read from the store as of one this process
// kept, and nothing else of the format can carry the difference
// (SPEC.md §3). Until the format has one, such a session stays open and the
// verdict over its store stays false.

import (
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
	refusalLeftOpen = "session %s was left open by an earlier process: the store holds receipts in it that this process did not mint, and no seal closes it; its chain is not continued from an empty memory, nor is it sealed from a count on disk, so acquire into a new session (gateway verify reports this one unregistered-session, and observes it session-open while its receipts are whole)"
	refusalNotADir  = "session %s is in the store as something other than a session directory, which this process did not make; nothing is taken up there"
	refusalUnread   = "session %s could not be read in the store, so whether an earlier process left receipts in it is not known; it is refused rather than taken for empty"
)

// leftInStore is why this process may not take up a session it does not
// hold, or "" when the store holds nothing in it that this process could
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
// in the map (release), so what the store holds in one that is not there
// is another process's. The directory is read only as far as its first
// receipt.
func (g *gatewayService) leftInStore(sessionID string) string {
	refused := func(why string) string { return fmt.Sprintf(why, sessionID) }
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
		entries, err := dir.ReadDir(64)
		for _, e := range entries {
			if strings.HasSuffix(e.Name(), ".json") {
				return refused(refusalLeftOpen)
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
