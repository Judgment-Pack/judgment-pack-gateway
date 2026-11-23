package main

// Delivery version "3" at the receipt sink (ADR-0059, section 9): with
// receiptSink.deliveryVersion "3", the sink is sent one envelope,
// {deliveryVersion, kind, digest, ...}, for each acquisition receipt, action
// receipt, seal and refusal entry, and acknowledges each by its digest. The
// digest is taken over a domain prefix of its own, the kind and the record's
// line (condition C4), so no "3" digest is ever a "1" receiptDigest or a "2"
// sealDigest, and an acknowledgment computed the older way names no digest
// the gateway sent: a sink moved to "3" before it reads "3" acknowledges
// nothing, and every acquisition is refused with the fixed sentence. Without
// the member a sink is sent exactly what it is sent today.

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"math"
)

// sinkDeliveryV3Version is the engine configuration version that admits
// receiptSink.deliveryVersion and receiptSink.refusalEntries. Its number is a
// placeholder, assigned at merge: ADR-0059 section 9 gives the member the
// refusal journal's version, 48, which the journal's own change takes, and 49
// is expected for the call reference, so this change reads 50 until the
// merge order fixes it. engine.go lists it in engineVersions, so a merge that
// keeps another change's number without renumbering one of them does not
// compile.
const sinkDeliveryV3Version = "50"

const (
	// sinkDeliveryV3 is the one value receiptSink.deliveryVersion takes;
	// versions "1" and "2" are chosen by its absence and by seals, as before.
	sinkDeliveryV3 = "3"
	// sinkDeliveryV3Domain prefixes what a "3" digest is taken over
	// (condition C4).
	sinkDeliveryV3Domain = "judgment-pack-gateway/sink-delivery/3:"
	// the kinds a "3" envelope names
	sinkKindAcquisitionReceipt = "acquisition-receipt"
	sinkKindActionReceipt      = "action-receipt"
	sinkKindSeal               = "seal"
	sinkKindRefusalEntry       = "refusal-entry"
)

// sinkDeliveryV3Digest is the digest a "3" delivery is acknowledged by:
// SHA-256 over the domain prefix, the kind, a line feed and the record's line
// without its line feed (condition C4). receiptDigestOf, the "1" and "2"
// digest, is taken over the line alone, so no digest of one form is ever the
// other's.
func sinkDeliveryV3Digest(kind string, line []byte) string {
	h := sha256.New()
	h.Write([]byte(sinkDeliveryV3Domain))
	h.Write([]byte(kind))
	h.Write([]byte{'\n'})
	h.Write(line)
	return "sha256:" + hex.EncodeToString(h.Sum(nil))
}

// sinkDeliveryV3Envelope is the canonical bytes of one "3" delivery,
// {deliveryVersion, kind, digest} and the members kind carries, and the digest
// its acknowledgment names.
func sinkDeliveryV3Envelope(kind string, line []byte, members func(*vObject)) ([]byte, string) {
	digest := sinkDeliveryV3Digest(kind, line)
	request := newObject()
	request.set("deliveryVersion", vString(sinkDeliveryV3))
	request.set("kind", vString(kind))
	request.set("digest", vString(digest))
	members(request)
	return canon(request), digest
}

// heldAction is the action receipt at index, ready for the sink under "3":
// it travels as actionReceipt, a member of its own, so that no reader of an
// acquisition's receipt takes it for one (condition C4). Under "1" and "2"
// no action receipt is delivered, as before.
func (f *receiptForwarder) heldAction(index int64, stored *vObject) heldReceipt {
	body, digest := sinkDeliveryV3Envelope(sinkKindActionReceipt, canon(stored), func(r *vObject) {
		r.set("actionReceipt", stored)
	})
	return heldReceipt{index: index, body: body, digest: digest}
}

// heldRefusalEntry is one refusal entry of the named journal, its line
// without the line feed, ready for the sink under "3". The entry is carried
// as the journal holds it, parsed; a line that does not parse is not sent.
func (f *receiptForwarder) heldRefusalEntry(journal string, line []byte) (heldReceipt, error) {
	entry, err := parseJSON(line)
	if err != nil {
		return heldReceipt{}, err
	}
	body, digest := sinkDeliveryV3Envelope(sinkKindRefusalEntry, line, func(r *vObject) {
		r.set("journal", vString(journal))
		r.set("entry", entry)
	})
	return heldReceipt{body: body, digest: digest}, nil
}

// actionReceiptNotForwarded is the refusal of an /act whose receipt the sink
// did not acknowledge under "3". Unlike an acquisition's, the write has
// happened: the sentence says so, and, for an action sent under an actionKey,
// that the same key answers it once the receipt is acknowledged (ADR-0059
// section 9). An action sent under no key has no evidence to answer a retry
// from, so its sentence promises none.
type actionReceiptNotForwarded struct{ keyed bool }

func (r actionReceiptNotForwarded) Error() string {
	sentence := "action receipt not forwarded: the receipt sink did not acknowledge this action's receipt; the action was carried out and its receipt is in the store; nothing was answered, and the receipt is held to be delivered again before the session's next acquisition, action or seal"
	if r.keyed {
		sentence += "; the same actionKey answers it once it is acknowledged"
	}
	return sentence
}

// redeliverAnswered is, under "3", what a retry that an action key's retained
// evidence answers waits for, whether that evidence is the action's response
// or its uncertain record: the receipt it carries is acknowledged before the
// evidence is answered or reconciled, so the write is never repeated and
// never answered unacknowledged.
//   - Where this process minted the receipt (its session is held here, at a
//     later index), the session's queue holds it until the sink acknowledges
//     it: what the queue holds is delivered, and an empty queue is a receipt
//     acknowledged.
//   - Otherwise the process that minted it stopped, or never held it here:
//     what it held for the sink is gone with it, so the receipt the evidence
//     keeps is delivered, alone, before anything is answered. The sink keeps
//     one receipt per digest, so one it acknowledged before is taken as it
//     was.
//
// The session's queue orders a delivery by itself (its send token), and a
// seal refuses under the gateway's lock while anything of it is held, so the
// retry need not hold the session's admission. Evidence whose receipt cannot
// be read is refused, never answered past the sink. Under "1" and "2" it is
// nil, as before.
func (g *gatewayService) redeliverAnswered(response map[string]any) error {
	if g.forwarder == nil || !g.forwarder.v3 {
		return nil
	}
	refused := actionReceiptNotForwarded{keyed: true}
	receipt, _ := response["receipt"].(map[string]any)
	sessionID, _ := receipt["sessionId"].(string)
	index, counted := receipt["callIndex"].(float64)
	if sessionID == "" || !counted || index < 0 || index != math.Trunc(index) {
		return refused
	}
	g.mu.Lock()
	state, seen := g.sessions[sessionID]
	var q *forwardQueue
	mintedHere := seen && state.forward != nil && int64(index) < state.index
	if mintedHere {
		q = state.forward
	}
	g.mu.Unlock()
	if mintedHere {
		if err := g.forwarder.deliver(g.forwardingContext(), q, sealIndex-1); err != nil {
			return refused
		}
		return nil
	}
	raw, err := json.Marshal(receipt)
	if err != nil {
		return refused
	}
	parsed, err := parseJSON(raw)
	if err != nil {
		return refused
	}
	stored, ok := parsed.(*vObject)
	if !ok {
		return refused
	}
	alone := newForwardQueue()
	alone.add(g.forwarder.heldAction(int64(index), stored))
	if err := g.forwarder.deliver(g.forwardingContext(), alone, math.MaxInt64); err != nil {
		return refused
	}
	return nil
}
