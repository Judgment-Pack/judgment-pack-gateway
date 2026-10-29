// Package sandbox applies an operator's filesystem policy before a local
// customer program starts. Network access and the truth of its answers are
// outside this policy.
package sandbox

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"adapters/internal/canon"
)

const (
	ReadOnly       = "read-only"
	WorkspaceWrite = "workspace-write"
	FullAccess     = "danger-full-access"
)

type Report struct {
	Mode    string       `json:"mode"`
	Backend string       `json:"backend"`
	State   string       `json:"state"`
	Reason  string       `json:"reason"`
	cleanup func() error // platform resources; an error leaves temporary files in place
}

type policy struct {
	Version string            `json:"policyVersion"`
	Default string            `json:"defaultMode"`
	Sources map[string]string `json:"sources"`
}

func ValidMode(mode string) bool {
	return mode == ReadOnly || mode == WorkspaceWrite || mode == FullAccess
}

// ModeForWorkspace keeps the policy home outside the source's writable tree.
// The deployment must also protect its ancestors from other local writers.
func ModeForWorkspace(path, source, workspace string) (string, error) {
	settings, err := SettingsForWorkspace(path, source, workspace)
	return settings.Mode, err
}

func SettingsForWorkspace(path, source, workspace string) (Settings, error) {
	if path != "" {
		policyPath, err := filepath.EvalSymlinks(path)
		if err != nil {
			return Settings{}, errors.New("sandbox-policy-invalid: policy is unavailable")
		}
		workPath, err := filepath.EvalSymlinks(workspace)
		if err != nil {
			return Settings{}, errors.New("sandbox-policy-invalid: workspace is unavailable")
		}
		rel, err := filepath.Rel(workPath, policyPath)
		if err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) && !filepath.IsAbs(rel) {
			return Settings{}, errors.New("sandbox-policy-invalid: policy home must be outside the source workspace")
		}
	}
	return Resolve(path, source)
}

// Mode reads the separate policy home. A source cannot request escalation in
// a tool argument: only the operator-owned launch configuration selects this.
func Mode(path, source string) (string, error) {
	selection, err := Resolve(path, source)
	return selection.Mode, err
}

// Resolve reads expanded settings. Preset names are derived, never admitted as
// policy input. Legacy policies record no approval or operation-family claim.
func Resolve(path, source string) (Settings, error) {
	if path == "" {
		return Settings{Mode: WorkspaceWrite}, nil
	}
	file, err := os.Open(path)
	if err != nil {
		return Settings{}, fmt.Errorf("sandbox-policy-invalid: %w", err)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return Settings{}, errors.New("sandbox-policy-invalid: policy must be a regular file")
	}
	raw, err := io.ReadAll(io.LimitReader(file, (64<<10)+1))
	if err != nil || len(raw) > 64<<10 {
		return Settings{}, errors.New("sandbox-policy-invalid: policy exceeds its bound or could not be read")
	}
	if _, err := canon.Canonicalize(raw, canon.RefuseNumbers); err != nil {
		return Settings{}, errors.New("sandbox-policy-invalid: malformed policy")
	}
	var header struct {
		Version string `json:"policyVersion"`
	}
	if err := json.Unmarshal(raw, &header); err != nil {
		return Settings{}, errors.New("sandbox-policy-invalid: malformed policy")
	}
	if header.Version == "2" {
		return resolveExpanded(raw, source)
	}
	var p policy
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&p) != nil || canon.ExactNames(raw, &p) != nil || p.Version != "1" || !ValidMode(p.Default) {
		return Settings{}, errors.New("sandbox-policy-invalid: expected policyVersion 1 and a valid defaultMode")
	}
	for name, mode := range p.Sources {
		if name == "" || !ValidMode(mode) {
			return Settings{}, errors.New("sandbox-policy-invalid: invalid source override")
		}
	}
	if mode, ok := p.Sources[source]; ok {
		return Settings{Mode: mode}, nil
	}
	return Settings{Mode: p.Default}, nil
}
