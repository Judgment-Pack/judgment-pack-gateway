package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"adapters/internal/canon"
	"adapters/internal/fakemcp"
)

func TestV2OwnerFileMaximumSnapshotThroughCLIProcess(t *testing.T) {
	const maximum = 327680
	owner := map[string]any{"operation": "check", "effect": "read-external", "checkKind": "analyze", "experimental": true}
	tools := map[string]any{}
	names := []string{}
	for n := 0; n < 2900; n++ {
		name := fmt.Sprintf("n%04d", n)
		names = append(names, name)
		tools[name] = map[string]any{"taxonomy": owner}
	}
	server := fakemcp.NewHTTP(false, fakemcp.Script{})
	defer server.Close()
	snap := map[string]any{"snapshotVersion": "2", "operation": "live", "binding": "tickets@" + digest, "platform": "tickets", "policy": 1, "capturedAt": "2026-01-01T00:00:00Z", "server": map[string]string{"name": "fake-remote-mcp", "version": "2.0"}, "endpoint": server.URL, "tools": tools}
	encode := func(v any) []byte {
		t.Helper()
		raw, err := canon.EncodeJSON(v)
		if err != nil {
			t.Fatal(err)
		}
		raw, err = canon.Canonicalize(raw, canon.RefuseNumbers)
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	padding := maximum - len(encode(snap))
	if padding <= 0 {
		t.Fatal("capacity fixture no longer fits")
	}
	delete(tools, names[0])
	names[0] += strings.Repeat("z", padding)
	tools[names[0]] = map[string]any{"taxonomy": owner}
	if len(encode(snap)) != maximum {
		t.Fatal("fixture must reach exact supported snapshot ceiling")
	}
	declarations := map[string]any{}
	offered := []map[string]string{}
	for _, name := range names {
		declarations[name] = owner
		offered = append(offered, map[string]string{"name": name})
	}
	offeredRaw, _ := json.Marshal(offered)
	server.Set(func(s *fakemcp.Script) { s.Tools = string(offeredRaw) })
	declaration := encode(map[string]any{"declarationVersion": "1", "platform": "tickets", "binding": "tickets@" + digest, "operation": "live", "tools": declarations})
	file := filepath.Join(t.TempDir(), "owner.json")
	if err := os.WriteFile(file, declaration, 0o600); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(declaration)
	args := []string{"--check", "--url=" + server.URL, "--tools=" + strings.Join(names, ","), "--owner-declaration-file=" + file, "--owner-declaration-pin=sha256:" + hex.EncodeToString(sum[:]), "--descriptors-platform=tickets", "--descriptors-binding=tickets@" + digest, "--descriptors-operation=live"}
	argvBytes := 0
	for _, arg := range args {
		argvBytes += len(arg) + 1
	}
	cmd := exec.Command(os.Args[0], args...)
	cmd.Env = append(os.Environ(), "GATEWAY_TEST_OWNER_PROCESS=1")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("real CLI process: %v %s", err, &stderr)
	}
	var report struct {
		Check struct {
			Descriptors json.RawMessage `json:"descriptors"`
		}
	}
	if json.Unmarshal(out, &report) != nil || len(report.Check.Descriptors) != maximum {
		t.Fatalf("maximum snapshot missing: %d bytes: %s", len(report.Check.Descriptors), stderr.String())
	}
	t.Logf("native CLI: declaration=%d bytes, approved snapshot=%d bytes, executable arguments=%d bytes, direct base64 owner expansion would be>%d characters", len(declaration), len(report.Check.Descriptors), argvBytes, len(declaration)*4/3)
}
