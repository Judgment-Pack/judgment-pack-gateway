package main

// `gateway export --scope S` (SPEC.md §5a, "An export by scope"; ADR-0042,
// decision 8): the export's cut attributed by scope_cut.go's rule, from the
// cut's own bytes on either kind, and the files written of the sessions of S
// alone: their receipts, the artifacts those receipts name, the registry's
// rotation statements and the seal lines of S's sessions, and the removal
// records of S. A session the rule attributes to none refuses the export,
// by name, before a file is written: an export that left it out could not
// say so in any file a verifier reads. So does a session of S holding a
// receipt the gateway signed of another scope, or of none, which only an
// earlier release mints; and so does a session of S holding a receipt file
// that fails the signed orders, whose scope nothing shows: the export
// carries nothing of another scope.

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"strings"
)

// attributionProbe is the probe the export's attribution reads receipts
// with: it holds no artifact, so a receipt's ladder answer is past the
// signed orders exactly where it would be with the store's bytes, which is
// all attribute reads of it.
var attributionProbe = storeProbe{
	artifact: func(string) (string, bool, bool) { return "", false, true },
	provenance: func(descriptorProvenance, string, string, string, bool, []reachedKey) string {
		return "ok"
	},
}

// exportSelection attributes the cut's sessions, and the sealed sessions it
// does not hold, to in.scope, reading the registry under the gateway's own
// walk (engineWalk) and the removal records the cut gives (removals, present
// whether there are any). A walk that does not hold, or a session it cannot
// attribute, refuses the export. The cut it gives holds the digest of each
// receipt file's bytes as it judged them (scopeCut.judged), which are the
// bytes the export writes and takes artifact digests from.
func exportSelection(in exportInputs, cut *storeCut, removals []byte, present bool) (*scopeCut, error) {
	var log []byte
	if cut.logPresent {
		log = cut.log
	}
	walk, err := engineWalk(log, heldKey{alg: in.keyAlg, key: in.publicKey})
	if err != nil {
		return nil, fmt.Errorf("an export by scope walks the registry: %w", err)
	}
	records := newRemovalRecords()
	if present {
		if records, _, err = scanRecords(bytes.NewReader(removals), walk.keys); err != nil {
			return nil, fmt.Errorf("removal records: %w", err)
		}
	}
	ret := &retention{removals: records.artifacts, sessions: records.sessions}
	holdings := map[string]*scopeHolding{}
	// unproven are each session's receipt files that fail the signed orders
	unproven := map[string][]string{}
	judged := map[string][sha256.Size]byte{}
	for _, series := range cut.series {
		h, signatures := newScopeHolding(), map[string]string{}
		for _, entry := range cut.entries[series] {
			data, err := cut.entry(series, entry)
			if err != nil {
				return nil, fmt.Errorf("receipt %s/%s.json: %w", series, entry, err)
			}
			if signature, ok := topLevelSignature(data); ok {
				signatures[entry] = signature
			}
			r, status, err := checkReceiptProbed(data, attributionProbe, series, entry+".json", in.authority, walk.keys, nil)
			if err != nil {
				return nil, err
			}
			if !pastSignedOrders(r, status) {
				unproven[series] = append(unproven[series], series+"/"+entry+".json")
			}
			judged[series+"/"+entry] = sha256.Sum256(data)
			h.take(r, status)
		}
		h.done(signatures)
		holdings[series] = h
	}
	sel := cutOf(in.scope, holdings, walk.seals, ret)
	if len(sel.Unattributed) > 0 {
		return nil, fmt.Errorf("the store holds sessions an export by scope cannot attribute to the scope or to another: %s; gateway verify --scope names what it finds of each, and nothing was written",
			strings.Join(sel.Unattributed, ", "))
	}
	// A session of the scope holding a receipt file that fails the signed
	// orders (SPEC.md §1.4, orders 1 to 6) -- one copied into it from another
	// session among them -- refuses the export: nothing shows what scope it
	// carries, and written it would carry the file and the artifacts it
	// names, which may be another scope's.
	var unsigned []string
	for _, sessionID := range sel.Sessions {
		unsigned = append(unsigned, unproven[sessionID]...)
	}
	if len(unsigned) > 0 {
		return nil, fmt.Errorf("the store holds sessions of the scope with receipt files that fail the signed orders, whose scope an export by scope cannot show: %s; gateway verify --scope names what it finds of each, the whole store exports them, and nothing was written",
			strings.Join(unsigned, ", "))
	}
	// A session of the scope holding a receipt the gateway signed of another
	// scope, or of none -- an earlier release's, which did not hold a
	// session to one scope -- refuses the export: written whole it would
	// carry what is not of the scope, and written in part its chain would
	// not hold.
	var mixed []string
	for _, sessionID := range sel.Sessions {
		if h := holdings[sessionID]; h != nil && h.carriesOtherThan(in.scope) {
			mixed = append(mixed, sessionID)
		}
	}
	if len(mixed) > 0 {
		return nil, fmt.Errorf("the store holds sessions of the scope whose receipts carry another scope, or none, which an export by scope would carry: %s; the whole store exports them, and nothing was written",
			strings.Join(mixed, ", "))
	}
	sel.judged = judged
	return sel, nil
}

// registryOfCut is the registry's lines an export by scope keeps, in their
// order and byte for byte: every rotation statement, which is of the key
// and of no scope, so the walk from the key pinned reaches what it reached,
// and every line naming a session of the cut, its seals among them. A line
// naming another session, or none, is left out.
func registryOfCut(log []byte, sel *scopeCut) []byte {
	of := map[string]bool{}
	for _, id := range sel.Sessions {
		of[id] = true
	}
	var out []byte
	for _, line := range strings.SplitAfter(string(log), "\n") {
		text := strings.TrimSuffix(line, "\n")
		if strings.TrimSpace(text) == "" {
			continue
		}
		if kind, _ := rotationKindOf(text); kind != "" || of[sessionIDOfLine(text)] {
			out = append(out, line...)
		}
	}
	return out
}

// removalsOfCut is the removal file's lines an export by scope keeps, in
// their order and byte for byte: an artifact-removal or session-removal
// record naming a session of the cut, and a scope-removal record of the
// scope. Every other line, and an unfinished last one, is left out.
func removalsOfCut(data []byte, sel *scopeCut) []byte {
	of := map[string]bool{}
	for _, id := range sel.Sessions {
		of[id] = true
	}
	var out []byte
	for _, line := range strings.SplitAfter(string(data), "\n") {
		if !strings.HasSuffix(line, "\n") {
			continue
		}
		v, err := parseJSON([]byte(strings.TrimSuffix(line, "\n")))
		if err != nil {
			continue
		}
		obj, isObject := v.(*vObject)
		if !isObject {
			continue
		}
		kind, _ := memberString(obj, "kind")
		sessionID, _ := memberString(obj, "sessionId")
		scope, _ := memberString(obj, "scope")
		switch {
		case (kind == removalKind || kind == sessionRemovalKind) && of[sessionID]:
		case kind == scopeRemovalKind && scope == sel.Scope:
		default:
			continue
		}
		out = append(out, line...)
	}
	return out
}

// sessionIDOfLine is the sessionId member of a registry line read as one
// JSON object, "" for any other line.
func sessionIDOfLine(line string) string {
	v, err := parseJSON([]byte(line))
	if err != nil {
		return ""
	}
	obj, isObject := v.(*vObject)
	if !isObject {
		return ""
	}
	id, _ := memberString(obj, "sessionId")
	return id
}

// digestsNamed adds to into the lowercase hexadecimal of each artifact a
// receipt's bytes name: the artifacts an export by scope holds are those its
// receipts name. A receipt names an artifact by the members whose digest the
// store keeps bytes under, and by no other:
//   - resultDigest, the result at artifacts/<hex> (SPEC.md §1.3, §1.3a);
//   - acquisition.descriptorProvenance's snapshot and statement (§9).
//
// The other digests a receipt carries name no artifact: argumentsCommitment,
// acquisition.statement and action.request are salted commitments to values
// never kept (§1.2a); acquisition.schema, adapter.digest, snapshot and every
// other member a source or adapter reports, and caller's tokenDigest, are
// what they say and are kept nowhere; pageItems digest items within the
// result. A digest written in one of them pulls in no artifact, whatever
// artifact of another scope it is the digest of.
//
// A receipt the canonical parser does not read names none: it is written as
// it is, and verification finds it malformed.
func digestsNamed(data []byte, into map[string]bool) {
	v, err := parseJSON(data)
	if err != nil {
		return
	}
	obj, isObject := v.(*vObject)
	if !isObject {
		return
	}
	take := func(o *vObject, name string) {
		if digest, held := memberString(o, name); held {
			if hexSum, ok := blobHex(digest); ok {
				into[hexSum] = true
			}
		}
	}
	take(obj, "resultDigest")
	a, _ := obj.get("acquisition")
	if acq, isObject := a.(*vObject); isObject {
		p, _ := acq.get("descriptorProvenance")
		if provenance, isObject := p.(*vObject); isObject {
			take(provenance, "snapshot")
			take(provenance, "statement")
		}
	}
}
