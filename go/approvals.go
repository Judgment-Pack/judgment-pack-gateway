package main

// The approval citation (SPEC.md §1.2a, action.approvals; ADR-0054
// decision 3): the records, kept outside the gateway, that the requester
// says approved a write. A citation is the requester's claim. Its form is
// checked here and nothing else: no record is read, fetched or compared.

import (
	"errors"
	"fmt"
)

const (
	// approvalSingle is a record that approves one action.
	approvalSingle = "single"
	// approvalStanding is a standing promotion record, which authorizes an
	// automation to make writes of a class over time.
	approvalStanding = "standing"
	// maxApprovals bounds action.approvals.
	maxApprovals = 8
	// observationApprovalCitedAgain is §4's observation on an action receipt
	// that cites a single approval another action receipt of the store also
	// cites, by id and digest.
	observationApprovalCitedAgain = "approval-cited-again"
)

// approvalCitation is one entry of action.approvals.
type approvalCitation struct {
	kind, id, digest string
}

// parseApprovals holds action.approvals to its form: an array of 1 to 8
// entries, each exactly {kind, id, digest}; kind "single" or "standing"; id
// of the scope identifier's form, and no id twice; digest "sha256:" and 64
// lowercase hexadecimal characters. The entries keep the order given.
func parseApprovals(v value) ([]approvalCitation, error) {
	arr, ok := v.(vArray)
	if !ok || len(arr) == 0 || len(arr) > maxApprovals {
		return nil, fmt.Errorf("action: approvals is an array of 1 to %d entries", maxApprovals)
	}
	seen := map[string]bool{}
	out := make([]approvalCitation, 0, len(arr))
	for i, entry := range arr {
		obj, ok := entry.(*vObject)
		if !ok {
			return nil, fmt.Errorf("action: approvals[%d] is not an object", i)
		}
		if err := exactlyMembers(obj, map[string]bool{"kind": true, "id": true, "digest": true}, fmt.Sprintf("action.approvals[%d]", i)); err != nil {
			return nil, err
		}
		kind, _ := memberString(obj, "kind")
		if kind != approvalSingle && kind != approvalStanding {
			return nil, fmt.Errorf(`action: approvals[%d].kind is "single" or "standing"`, i)
		}
		id, ok := memberString(obj, "id")
		if !ok || !isScopeIdentifier(id) {
			return nil, fmt.Errorf("action: approvals[%d].id is not of its form: %s", i, scopeForm)
		}
		digest, ok := memberString(obj, "digest")
		if !ok || !isDigest(digest) {
			return nil, fmt.Errorf(`action: approvals[%d].digest is not "sha256:" and 64 lowercase hexadecimal characters`, i)
		}
		if seen[id] {
			return nil, errors.New("action: approvals names one id twice")
		}
		seen[id] = true
		out = append(out, approvalCitation{kind: kind, id: id, digest: digest})
	}
	return out, nil
}

// approvalObservations is §4's approval-cited-again, once on each action
// receipt that passed the ladder and cites a single approval whose id and
// digest another action receipt of the store also cites. It is not a
// finding, and only the one store is seen.
func approvalObservations(actions []*receipt) []finding {
	citing := map[[2]string]int{}
	for _, a := range actions {
		for _, c := range a.approvals {
			citing[[2]string{c.id, c.digest}]++
		}
	}
	var out []finding
	for _, a := range actions {
		for _, c := range a.approvals {
			if c.kind == approvalSingle && citing[[2]string{c.id, c.digest}] > 1 {
				out = append(out, finding{"sessionId": a.sessionID, "callIndex": a.callIndex, "observation": observationApprovalCitedAgain})
				break
			}
		}
	}
	return out
}
