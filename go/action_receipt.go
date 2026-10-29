package main

import "errors"

type actionDelivery struct{ key, contract, outcome string }
type actionReconciliation struct {
	action                 citation
	key, contract, outcome string
}

func parseActionDelivery(v value) (*actionDelivery, error) {
	o, err := requireObject(v, "action.delivery")
	if err != nil {
		return nil, err
	}
	if err = exactlyMembers(o, map[string]bool{"key": true, "contract": true, "outcome": true}, "action.delivery"); err != nil {
		return nil, err
	}
	key, _ := memberString(o, "key")
	contract, _ := memberString(o, "contract")
	outcome, _ := memberString(o, "outcome")
	if !isLowerHexOfLen(key, 64) || !isDigest(contract) || (outcome != "response" && outcome != "uncertain") {
		return nil, errors.New("invalid action.delivery")
	}
	return &actionDelivery{key, contract, outcome}, nil
}
func parseActionReconciliation(v value) (*actionReconciliation, error) {
	o, err := requireObject(v, "acquisition.reconciliation")
	if err != nil {
		return nil, err
	}
	if err = exactlyMembers(o, map[string]bool{"key": true, "contract": true, "outcome": true, "action": true}, "acquisition.reconciliation"); err != nil {
		return nil, err
	}
	key, _ := memberString(o, "key")
	contract, _ := memberString(o, "contract")
	outcome, _ := memberString(o, "outcome")
	if !isLowerHexOfLen(key, 64) || !isDigest(contract) || (outcome != "committed" && outcome != "unknown") {
		return nil, errors.New("invalid acquisition.reconciliation")
	}
	av, _ := o.get("action")
	action, err := requireObject(av, "reconciliation.action")
	if err != nil {
		return nil, err
	}
	if err = exactlyMembers(action, map[string]bool{"sessionId": true, "callIndex": true, "signature": true}, "reconciliation.action"); err != nil {
		return nil, err
	}
	cites, err := parseCitations(vArray{action}, "reconciliation")
	if err != nil {
		return nil, err
	}
	return &actionReconciliation{cites[0], key, contract, outcome}, nil
}
func reconciliationMatches(read, action *receipt) bool {
	r := read.reconciliation
	if r == nil || action == nil || action.delivery == nil || action.kind != "action" {
		return false
	}
	d := action.delivery
	if r.action.signature != action.signature || r.key != d.key || r.contract != d.contract || d.outcome != "uncertain" || read.authority != action.authority {
		return false
	}
	av, _ := action.obj.get("action")
	ao, _ := requireObject(av, "action")
	identity, _ := ao.get("requester")
	caller, _ := read.obj.get("caller")
	a, err := requireObject(identity, "requester")
	if err != nil {
		return false
	}
	b, err := requireObject(caller, "caller")
	if err != nil {
		return false
	}
	for _, name := range []string{"issuer", "subject"} {
		x, _ := memberString(a, name)
		y, _ := memberString(b, name)
		if x != y {
			return false
		}
	}
	return true
}
