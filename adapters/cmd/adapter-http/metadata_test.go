package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"adapters/httpsource"
)

// A metadata token step is given by its audience alone: beside another
// kind of assertion, or with an audience out of form, the command refuses
// before it reads a credential or asks anything, and no flag of the command
// names the metadata server's address.
func TestRunTakesTheMetadataStepByItsAudienceAlone(t *testing.T) {
	dir := t.TempDir()
	creds := filepath.Join(dir, "credentials.json")
	if err := os.WriteFile(creds, []byte(`{"sealKey":"0123456789abcdef0123456789abcdef"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	federated := filepath.Join(dir, "federated")
	if err := os.WriteFile(federated, []byte("federated-token-text\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	base := []string{"--endpoint=http://127.0.0.1:9", "--paths=/read", "--methods=GET", "--credentials=" + creds,
		"--token-endpoint=http://127.0.0.1:9/token", "--client-id=client-7", "--token-only"}
	run1 := func(extra ...string) (int, string) {
		var stdout, stderr bytes.Buffer
		code := run(append(append([]string(nil), base...), extra...), strings.NewReader(""), &stdout, &stderr)
		if stdout.Len() != 0 {
			t.Fatalf("%q wrote stdout: %q", extra, stdout.String())
		}
		return code, stderr.String()
	}
	exactlyOne := "exactly one of --assertion-key, --federated-token-file and --federated-token-metadata-audience"
	for _, c := range []struct {
		name  string
		extra []string
		want  string
	}{
		{"beside a federated token file", []string{"--federated-token-metadata-audience=api://records", "--federated-token-file=" + federated}, exactlyOne},
		{"beside a key", []string{"--federated-token-metadata-audience=api://records", "--assertion-key=KEY"}, exactlyOne},
		{"an audience adding a query member", []string{"--federated-token-metadata-audience=api://records&audience=other"}, "--federated-token-metadata-audience is 1 to 256 ASCII letters"},
		{"an audience of 257 bytes", []string{"--federated-token-metadata-audience=" + strings.Repeat("a", 257)}, "--federated-token-metadata-audience is 1 to 256 ASCII letters"},
		{"a directory beside it", []string{"--federated-token-metadata-audience=api://records", "--federated-token-dir=" + dir}, "--federated-token-dir is the directory of --federated-token-file"},
	} {
		code, stderr := run1(c.extra...)
		if code != 1 || !strings.Contains(stderr, c.want) || strings.Contains(stderr, "audience=other") {
			t.Fatalf("%s: %d %q", c.name, code, stderr)
		}
	}
	// No sealKey in the credentials file is no credential, before anything
	// is asked.
	if err := os.WriteFile(creds, []byte(`{"other":"0123456789abcdef0123456789abcdef"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if code, stderr := run1("--federated-token-metadata-audience=api://records"); code != int(httpsource.TokenNoCredential) || !strings.Contains(stderr, "sealKey") {
		t.Fatalf("no sealKey: %d %q", code, stderr)
	}
	// The command's flags: the metadata server is named by none but the
	// audience's.
	var stdout, stderr bytes.Buffer
	run([]string{"-h"}, strings.NewReader(""), &stdout, &stderr)
	var named []string
	for _, line := range strings.Split(stderr.String(), "\n") {
		if name, ok := strings.CutPrefix(line, "  -"); ok && strings.Contains(strings.ToLower(line), "metadata") {
			named = append(named, strings.Fields(name)[0])
		}
	}
	if len(named) != 1 || named[0] != "federated-token-metadata-audience" {
		t.Fatalf("the flags naming the metadata server: %q", named)
	}
}
