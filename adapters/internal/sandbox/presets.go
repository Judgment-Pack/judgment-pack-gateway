package sandbox

import (
	"bytes"
	"encoding/json"
	"errors"
	"slices"

	"adapters/internal/canon"
)

// Settings records the filesystem mode and the companion host's approval and
// operation-family settings together. The sandbox enforces Mode only; the host
// still enforces approvals and tool availability, and no setting bypasses the
// gateway's existing write authorization or receipt checks.
type Settings struct {
	Mode       string   `json:"mode"`
	Approval   string   `json:"approval"`
	Operations []string `json:"operations"`
}

type expandedPolicy struct {
	Version string              `json:"policyVersion"`
	Default Settings            `json:"default"`
	Sources map[string]Settings `json:"sources"`
}

// ExpandPreset returns a complete policy, not a persistent preset selector.
// Full access is available only by explicitly naming full; it does not remove
// effect approvals. ask is available in every preset and is itself pure.
func ExpandPreset(name string) ([]byte, error) {
	s, err := presetSettings(name)
	if err != nil {
		return nil, err
	}
	raw, err := json.Marshal(expandedPolicy{Version: "2", Default: s, Sources: map[string]Settings{}})
	if err != nil {
		return nil, err
	}
	return canon.Canonicalize(raw, canon.RefuseNumbers)
}

func presetSettings(name string) (Settings, error) {
	s := Settings{Mode: ReadOnly, Approval: "always", Operations: []string{"ask", "check", "discover", "read"}}
	switch name {
	case "review":
	case "work", "full":
		s.Mode, s.Approval = WorkspaceWrite, "policy"
		s.Operations = []string{"act", "ask", "check", "discover", "propose", "read"}
		if name == "full" {
			s.Mode = FullAccess
		}
	default:
		return Settings{}, errors.New("sandbox-policy-invalid: unknown permission preset")
	}
	return s, nil
}

func (s Settings) Preset() string {
	for _, name := range []string{"review", "work", "full"} {
		p, _ := presetSettings(name)
		if s.Mode == p.Mode && s.Approval == p.Approval && slices.Equal(s.Operations, p.Operations) {
			return name
		}
	}
	return "custom"
}

func (s Settings) valid() bool {
	if !ValidMode(s.Mode) || (s.Approval != "always" && s.Approval != "policy") || len(s.Operations) == 0 {
		return false
	}
	previous := ""
	for _, op := range s.Operations {
		if op <= previous {
			return false
		}
		switch op {
		case "act", "answer", "ask", "check", "discover", "evaluate", "own-state", "propose", "read", "run", "transform":
		default:
			return false
		}
		previous = op
	}
	return slices.Contains(s.Operations, "ask")
}

func resolveExpanded(raw []byte, source string) (Settings, error) {
	var p expandedPolicy
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&p) != nil || canon.ExactNames(raw, &p) != nil || p.Version != "2" || !p.Default.valid() || p.Sources == nil {
		return Settings{}, errors.New("sandbox-policy-invalid: expected complete expanded policyVersion 2 settings")
	}
	for name, settings := range p.Sources {
		if name == "" || !settings.valid() {
			return Settings{}, errors.New("sandbox-policy-invalid: invalid expanded source settings")
		}
	}
	if settings, ok := p.Sources[source]; ok {
		return settings, nil
	}
	return p.Default, nil
}
