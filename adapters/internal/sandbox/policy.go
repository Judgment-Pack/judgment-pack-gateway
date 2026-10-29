// Package sandbox applies an operator's filesystem policy before a local
// customer program starts. Network access and the truth of its answers are
// outside this policy.
package sandbox

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
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
	Mode      string       `json:"mode"`
	Backend   string       `json:"backend"`
	State     string       `json:"state"`
	Reason    string       `json:"reason"`
	cleanup   func() error // platform resources; an error leaves temporary files in place
	exactFile bool         // the digested descriptor is what runs (Launch.File)
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
	settings, _, err := SelectionForWorkspace(path, source, workspace)
	return settings, err
}

// NoPolicyDigest is the policy digest when no policy file is named: the
// built-in workspace-write default.
const NoPolicyDigest = "none"

// SelectionForWorkspace is SettingsForWorkspace with the digest of the policy
// bytes the settings were resolved from ("sha256:" and lowercase hex, or
// NoPolicyDigest). The file is read once: the digest names exactly the bytes
// that decided the settings, so a launch can be bound to what a probe used.
func SelectionForWorkspace(path, source, workspace string) (Settings, string, error) {
	if path != "" {
		policyPath, err := filepath.EvalSymlinks(path)
		if err != nil {
			return Settings{}, "", errors.New("sandbox-policy-invalid: policy is unavailable")
		}
		workPath, err := filepath.EvalSymlinks(workspace)
		if err != nil {
			return Settings{}, "", errors.New("sandbox-policy-invalid: workspace is unavailable")
		}
		rel, err := filepath.Rel(workPath, policyPath)
		if err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) && !filepath.IsAbs(rel) {
			return Settings{}, "", errors.New("sandbox-policy-invalid: policy home must be outside the source workspace")
		}
	}
	raw, err := readPolicy(path)
	if err != nil {
		return Settings{}, "", err
	}
	if raw == nil {
		settings, err := resolveRaw(nil, source)
		return settings, NoPolicyDigest, err
	}
	sum := sha256.Sum256(raw)
	settings, err := resolveRaw(raw, source)
	return settings, "sha256:" + hex.EncodeToString(sum[:]), err
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
	raw, err := readPolicy(path)
	if err != nil {
		return Settings{}, err
	}
	return resolveRaw(raw, source)
}

// readPolicy reads the policy file's bytes once, within its bound; nil when
// no file is named.
func readPolicy(path string) ([]byte, error) {
	if path == "" {
		return nil, nil
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("sandbox-policy-invalid: %w", err)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return nil, errors.New("sandbox-policy-invalid: policy must be a regular file")
	}
	raw, err := io.ReadAll(io.LimitReader(file, (64<<10)+1))
	if err != nil || len(raw) > 64<<10 {
		return nil, errors.New("sandbox-policy-invalid: policy exceeds its bound or could not be read")
	}
	return raw, nil
}

// resolveRaw resolves settings from policy bytes; nil bytes are the built-in
// workspace-write default.
func resolveRaw(raw []byte, source string) (Settings, error) {
	if raw == nil {
		return Settings{Mode: WorkspaceWrite}, nil
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
