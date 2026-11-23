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
