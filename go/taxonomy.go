package main

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
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
	parsed, err := parseJSON(raw)
	if err != nil {
		return ToolTaxonomy{}, err
	}
	raw = canon(parsed)
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

func taxonomyValue(v value) (ToolTaxonomy, error) {
	if v == nil {
		return ToolTaxonomy{}, fmt.Errorf("missing owner taxonomy")
	}
	return decodeTaxonomy(canon(v))
}
func taxonomyAsValue(t ToolTaxonomy) value {
	raw, _ := json.Marshal(t)
	v, _ := parseJSON(raw)
	return v
}
func taxonomyMapValue(tools map[string]ToolTaxonomy) value {
	raw, _ := json.Marshal(tools)
	v, _ := parseJSON(raw)
	return v
}

func annotationKey(k string) bool {
	return k == "readOnlyHint" || k == "destructiveHint" || k == "idempotentHint" || k == "openWorldHint"
}

// A V2 binding pins the declaration; only exact resolved allowed names may enter a dispatcher.
func parseTaxonomyOperation(raw *vObject, name string) (operation, error) {
	plain := &vObject{byName: map[string]value{}}
	for _, key := range raw.names {
		if key != "taxonomy" && key != "toolTaxonomies" {
			v, _ := raw.get(key)
			plain.set(key, v)
		}
	}
	op, err := parseOperation(plain, name)
	op.name = name
	if err != nil {
		return op, err
	}
	if op.shape == "airbyte" {
		if _, present := raw.get("toolTaxonomies"); present {
			return op, fmt.Errorf("history accepts taxonomy, not toolTaxonomies")
		}
		v, _ := raw.get("taxonomy")
		op.taxonomy, err = taxonomyValue(v)
		if err != nil || !op.taxonomy.External() {
			return op, fmt.Errorf("history requires an external owner taxonomy")
		}
		op.profile, err = DeriveProfile(map[string]ToolTaxonomy{"history": op.taxonomy})
		return op, err
	}
	if _, present := raw.get("taxonomy"); present {
		return op, fmt.Errorf("MCP operation taxonomy is derived from its exact toolTaxonomies")
	}
	v, _ := raw.get("toolTaxonomies")
	tools, ok := v.(*vObject)
	if !ok || len(tools.names) != len(op.tools) {
		return op, fmt.Errorf("toolTaxonomies must cover exactly the allowed tools")
	}
	op.taxonomies = map[string]ToolTaxonomy{}
	for _, tool := range op.tools {
		if _, duplicate := op.taxonomies[tool]; duplicate {
			return op, fmt.Errorf("duplicate allowed tool")
		}
		v, present := tools.get(tool)
		t, e := taxonomyValue(v)
		if !present || e != nil || !t.External() {
			return op, fmt.Errorf("missing or invalid owner taxonomy for allowed tool")
		}
		// A write operation is the executor's write-back through /act: each of
		// its tools is an act, whatever weaker family an owner might write.
		if name == "write" && (t.Operation != "act" || t.Effect != "act") {
			return op, fmt.Errorf("operation write: every allowed tool is a write-back and declares operation act and effect act")
		}
		op.taxonomies[tool] = t
	}
	if _, err := ownerDeclaration(op); err != nil {
		return op, err
	}
	op.taxonomy, op.profile, err = SummarizeTaxonomies(op.taxonomies)
	if err != nil {
		return op, err
	}

	if op.probe != "" && op.taxonomies[op.probe].Effect == "act" {
		return op, fmt.Errorf("a connection probe cannot execute an act tool")
	}
	return op, nil
}

func snapshotOwners(s snapshot, op *operation) error {
	if op.taxonomies == nil {
		if s.version != "" {
			return fmt.Errorf("V2 snapshot requires a V2 owner binding")
		}
		return nil
	}
	// Version 3 is a customer binding's; version 4 a customer command's,
	// which also binds the command's executable. A version-3 snapshot of a
	// command predates that binding and is never read as approved.
	version := "2"
	if op.customer {
		version = "3"
		if len(op.command) > 0 {
			version = "4"
			if s.version == "3" {
				return fmt.Errorf("mcp-approval-reapproval-required: this approval of a customer command predates executable binding (snapshot version 3); approve the source again with connect --replace")
			}
		}
	}
	if (s.executable != nil) != (version == "4") {
		return fmt.Errorf("V2 owner binding requires complete V2 snapshot evidence")
	}
	if s.version != version || s.operation != op.name || s.server == nil || len(s.tools) != len(op.taxonomies) {
		return fmt.Errorf("V2 owner binding requires complete V2 snapshot evidence")
	}
	for name, t := range op.taxonomies {
		entry, ok := s.tools[name]
		if !ok || entry.taxonomy != t {
			return fmt.Errorf("snapshot owner map differs from approved binding")
		}
	}
	return nil
}

// Bounded chunks avoid a single oversized OS argument. The decoded map is a snapshot subset.
const ownerChunkBytes = 16 << 10

func ownerDeclaration(op operation) ([]byte, error) {
	raw, _ := json.Marshal(map[string]any{"version": "1", "tools": op.taxonomies})
	v, err := parseJSON(raw)
	if err != nil {
		return nil, err
	}
	raw = canon(v)
	if len(raw) > maxSnapshotBytes {
		return nil, fmt.Errorf("owner declaration exceeds complete snapshot bound")
	}
	return raw, nil
}
func ownerArguments(op operation) []string {
	if op.taxonomies == nil {
		return nil
	}
	raw, err := ownerDeclaration(op)
	if err != nil {
		panic("validated owner declaration exceeded bound")
	}
	encoded := base64.RawURLEncoding.EncodeToString(raw)
	var args []string
	for len(encoded) > 0 {
		n := len(encoded)
		if n > ownerChunkBytes {
			n = ownerChunkBytes
		}
		args = append(args, "--tool-taxonomies="+encoded[:n])
		encoded = encoded[n:]
	}
	return args
}
func approvedArguments(cfg engineConfig, p platformConfig, op *operation) []string {
	pin := p.operationDescriptors[op.name]
	if op.taxonomies == nil || pin == "" {
		return nil
	}
	return []string{"--descriptor-snapshot=" + cfg.configPath + ".descriptors/" + strings.TrimPrefix(pin, "sha256:") + ".json", "--descriptor-pin=" + pin, "--approved-operation=" + op.name, "--approved-platform=" + p.name, "--approved-binding=" + p.binding}
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

// Declaration identity includes the exact resolved source operation, apart from observation bytes.
func ownerFileDeclaration(p platformConfig, op *operation) ([]byte, error) {
	raw, err := json.Marshal(map[string]any{"declarationVersion": "1", "platform": p.name, "binding": p.binding, "operation": op.name, "tools": op.taxonomies})
	if err != nil {
		return nil, err
	}
	v, err := parseJSON(raw)
	if err != nil {
		return nil, err
	}
	raw = canon(v)
	if len(raw) > maxSnapshotBytes {
		return nil, fmt.Errorf("complete owner declaration exceeds snapshot bound")
	}
	return raw, nil
}
func ownerFileArguments(cfg engineConfig, p platformConfig, op *operation) []string {
	if op.taxonomies == nil {
		return nil
	}
	raw, err := ownerFileDeclaration(p, op)
	if err != nil {
		return nil
	}
	sum := sha256.Sum256(raw)
	pin := "sha256:" + hex.EncodeToString(sum[:])
	return []string{"--owner-declaration-file=" + cfg.configPath + ".descriptors/" + strings.TrimPrefix(pin, "sha256:") + ".json", "--owner-declaration-pin=" + pin}
}

func currentToolOwners(op *operation) error {
	if op == nil {
		return nil
	}
	if len(op.tools) == 0 || len(op.taxonomies) != len(op.tools) {
		return fmt.Errorf("current MCP admission requires complete owner declarations: migrate the binding to bindingVersion2 with toolTaxonomies and explicitly recapture V2 per-operation approvals using connect --replace; V1 remains readable for historical inspection")
	}
	names := slices.Clone(op.tools)
	slices.Sort(names)
	for i, name := range names {
		owner, ok := op.taxonomies[name]
		if (i > 0 && name == names[i-1]) || !ok || !owner.External() {
			return fmt.Errorf("current MCP admission requires valid owner taxonomy for every exact allowed tool; migrate and recapture V2 per-operation approvals")
		}
	}

	return nil
}
func currentBindingOwners(cfg engineConfig, bindings map[string]binding) error {
	for _, p := range cfg.platforms {
		b := bindings[p.name]
		for _, op := range enabledMCPOperations(p, b) {
			if err := currentToolOwners(op); err != nil {
				return fmt.Errorf("platform %s: %w", p.name, err)
			}
		}
	}
	return nil
}
