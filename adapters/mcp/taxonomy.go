package mcp

import (
	"adapters/internal/canon"
	"encoding/json"
	"fmt"
)

// ToolTaxonomy is an owner declaration, never an execution grant.
type ToolTaxonomy struct {
	Operation    string `json:"operation"`
	Effect       string `json:"effect"`
	CheckKind    string `json:"checkKind,omitempty"`
	Experimental bool   `json:"experimental,omitempty"`
}
type CapabilityProfile struct {
	Effect     string   `json:"effect"`
	Operations []string `json:"operations"`
}

var taxonomyEffects = []string{"pure", "read", "read-external", "propose", "act"}
var taxonomyOperations = []string{"discover", "read", "answer", "check", "transform", "evaluate", "propose", "act", "run", "own-state", "ask"}

func (t ToolTaxonomy) Valid() bool {
	allowed := false
	switch t.Operation {
	case "discover", "answer", "check":
		allowed = t.Effect == "pure" || t.Effect == "read" || t.Effect == "read-external"
	case "read":
		allowed = t.Effect == "read" || t.Effect == "read-external"
	case "transform", "ask":
		allowed = t.Effect == "pure"
	case "propose":
		allowed = t.Effect == "propose"
	case "act":
		allowed = t.Effect == "act"
	case "run":
		allowed = t.Effect == "read" || t.Effect == "read-external" || t.Effect == "propose" || t.Effect == "act"
	case "own-state":
		allowed = t.Effect == "pure" || t.Effect == "read"
	}
	if !allowed {
		return false
	}
	if t.Operation != "check" {
		return t.CheckKind == ""
	}
	switch t.CheckKind {
	case "validate", "check", "verify", "test", "analyze", "advise":
		return true
	}
	return false
}
func (t ToolTaxonomy) External() bool {
	return t.Valid() && (t.Effect == "read-external" || t.Effect == "propose" || t.Effect == "act")
}
func (t ToolTaxonomy) Annotations() map[string]bool {
	act := t.Effect == "act"
	return map[string]bool{"readOnlyHint": !act, "destructiveHint": act, "idempotentHint": !act, "openWorldHint": act || t.Effect == "read-external"}
}
func (t ToolTaxonomy) Contradiction(hints map[string]bool) bool {
	if t.Effect == "act" {
		return false
	}
	readOnly, present := hints["readOnlyHint"]
	return hints["destructiveHint"] || (present && !readOnly)
}
func DeriveProfile(tools map[string]ToolTaxonomy) (CapabilityProfile, error) {
	p := CapabilityProfile{Effect: "pure", Operations: []string{}}
	ops := map[string]bool{}
	strength := 0
	for _, t := range tools {
		if !t.Valid() {
			return p, fmt.Errorf("invalid owner taxonomy")
		}
		ops[t.Operation] = true
		for rank, effect := range taxonomyEffects {
			if effect == t.Effect && rank > strength {
				strength = rank
				p.Effect = effect
			}
		}
	}
	for _, op := range taxonomyOperations {
		if ops[op] {
			p.Operations = append(p.Operations, op)
		}
	}
	return p, nil
}

func decodeTaxonomy(raw []byte) (ToolTaxonomy, error) {
	canonical, err := canon.Canonicalize(raw, canon.RefuseNumbers)
	if err != nil {
		return ToolTaxonomy{}, err
	}
	raw = canonical
	var fields map[string]json.RawMessage
	if json.Unmarshal(raw, &fields) != nil || fields == nil {
		return ToolTaxonomy{}, fmt.Errorf("taxonomy is not an object")
	}
	for k := range fields {
		if k != "operation" && k != "effect" && k != "checkKind" && k != "experimental" {
			return ToolTaxonomy{}, fmt.Errorf("unknown taxonomy member")
		}
	}
	if fields["operation"] == nil || fields["effect"] == nil {
		return ToolTaxonomy{}, fmt.Errorf("missing owner taxonomy")
	}
	if value, ok := fields["experimental"]; ok && string(value) != "true" && string(value) != "false" {
		return ToolTaxonomy{}, fmt.Errorf("experimental is not boolean")
	}
	if _, present := fields["checkKind"]; present {
		var operation, kind string
		if json.Unmarshal(fields["operation"], &operation) != nil || operation != "check" || string(fields["checkKind"]) == "null" || json.Unmarshal(fields["checkKind"], &kind) != nil {
			return ToolTaxonomy{}, fmt.Errorf("checkKind contradicts operation")
		}
	}
	var t ToolTaxonomy
	if json.Unmarshal(raw, &t) != nil || !t.Valid() {
		return t, fmt.Errorf("invalid owner taxonomy")
	}
	return t, nil
}

// Group summaries never replace a selected leaf's authority or approval.
func SummarizeTaxonomies(tools map[string]ToolTaxonomy) (ToolTaxonomy, CapabilityProfile, error) {
	profile, err := DeriveProfile(tools)
	if err != nil || len(tools) == 0 {
		return ToolTaxonomy{}, profile, fmt.Errorf("empty or invalid group")
	}
	summary := ToolTaxonomy{Operation: "run", Effect: profile.Effect}
	family, kind := "", ""
	same := true
	for _, t := range tools {
		if family == "" {
			family, kind = t.Operation, t.CheckKind
		} else if family != t.Operation || kind != t.CheckKind {
			same = false
		}
		summary.Experimental = summary.Experimental || t.Experimental
	}
	if same {
		summary.Operation, summary.CheckKind = family, kind
	}
	if !summary.Valid() {
		return summary, profile, fmt.Errorf("invalid derived group")
	}
	return summary, profile, nil
}
