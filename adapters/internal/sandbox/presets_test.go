package sandbox

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSharedPermissionSettings(t *testing.T) {
	raw, err := os.ReadFile("../../../testdata/sandbox-policy/settings.json")
	if err != nil {
		t.Fatal(err)
	}
	var rows []struct {
		Preset   string   `json:"preset"`
		Settings Settings `json:"settings"`
	}
	if err = json.Unmarshal(raw, &rows); err != nil {
		t.Fatal(err)
	}
	for _, row := range rows {
		if row.Settings.Approval != "" && !row.Settings.valid() {
			t.Fatalf("invalid shared settings: %+v", row)
		}
		if row.Settings.Preset() != row.Preset {
			t.Fatalf("preset divergence: %+v", row)
		}
	}
}

func TestPermissionPresetExpandedVectors(t *testing.T) {
	for _, tc := range []struct{ name, raw string }{
		{"review", `{"default":{"approval":"always","mode":"read-only","operations":["ask","check","discover","read"]},"policyVersion":"2","sources":{}}`},
		{"work", `{"default":{"approval":"policy","mode":"workspace-write","operations":["act","ask","check","discover","propose","read"]},"policyVersion":"2","sources":{}}`},
		{"full", `{"default":{"approval":"policy","mode":"danger-full-access","operations":["act","ask","check","discover","propose","read"]},"policyVersion":"2","sources":{}}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw, err := ExpandPreset(tc.name)
			if err != nil || string(raw) != tc.raw {
				t.Fatalf("expansion: %s %v", raw, err)
			}
			file := filepath.Join(t.TempDir(), "policy.json")
			if err = os.WriteFile(file, []byte(tc.raw), 0600); err != nil {
				t.Fatal(err)
			}
			s, err := Resolve(file, "source/live")
			if err != nil || s.Preset() != tc.name {
				t.Fatalf("selection: %+v %v", s, err)
			}
			mode, err := Mode(file, "source/live")
			if err != nil || mode != s.Mode {
				t.Fatalf("mode diverged from expanded settings: %s %v", mode, err)
			}
		})
	}
	if _, err := ExpandPreset(""); err == nil {
		t.Fatal("implicit preset accepted")
	}
	if _, err := ExpandPreset("danger-full-access"); err == nil {
		t.Fatal("mode treated as preset")
	}
}

func TestExpandedPolicyStrictnessAndOverrides(t *testing.T) {
	settings := `{"mode":"read-only","approval":"always","operations":["ask","check","discover","read"]}`
	custom := `{"mode":"workspace-write","approval":"always","operations":["act","answer","ask","check","discover","evaluate","own-state","propose","read","run","transform"]}`
	valid := `{"policyVersion":"2","default":` + settings + `,"sources":{"source/live":` + custom + `}}`
	for _, tc := range []struct {
		raw      string
		accepted bool
	}{
		{valid, true},
		{strings.Replace(valid, `"approval":"always"`, `"approval":"never"`, 1), false},
		{strings.Replace(valid, `"mode":"read-only"`, `"mode":"work"`, 1), false},
		{strings.Replace(valid, `"ask","check"`, `"check","ask"`, 1), false},
		{strings.Replace(valid, `"ask","check"`, `"ask","ask"`, 1), false},
		{strings.Replace(valid, `"ask","check"`, `"ask","unknown"`, 1), false},
		{strings.Replace(valid, `"ask",`, ``, 1), false},
		{strings.Replace(valid, `"mode":`, `"Mode":`, 1), false},
		{strings.Replace(valid, `"default":`, `"preset":"full","default":`, 1), false},
		{strings.Replace(valid, `"source/live":`, `"":`, 1), false},
		{`{"policyVersion":"2","default":` + settings + `,"sources":null}`, false},
		{`{"policyVersion":"2","default":` + settings + `}`, false},
	} {
		file := filepath.Join(t.TempDir(), "policy.json")
		if err := os.WriteFile(file, []byte(tc.raw), 0600); err != nil {
			t.Fatal(err)
		}
		s, err := Resolve(file, "source/live")
		if (err == nil) != tc.accepted {
			t.Fatalf("policy accepted=%v: %s; %v", tc.accepted, tc.raw, err)
		}
		if tc.accepted && (s.Preset() != "custom" || s.Mode != WorkspaceWrite || s.Approval != "always" || len(s.Operations) != 11) {
			t.Fatalf("override lost: %+v", s)
		}
	}
}

func TestLegacyPolicyDoesNotInventApprovalSettings(t *testing.T) {
	s, err := Resolve("", "source/live")
	if err != nil || s.Mode != WorkspaceWrite || s.Approval != "" || len(s.Operations) != 0 || s.Preset() != "custom" {
		t.Fatal(s, err)
	}
}
