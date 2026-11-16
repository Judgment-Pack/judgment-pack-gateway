package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The command's statuses that need no platform: usage, a request refused
// before any credential is used, and no credential. The statuses a platform
// answers (8, 9 and the token step's) are held end to end by the gateway's
// test of this adapter, which builds it with the test endpoints.
func TestStatusesBeforeThePlatform(t *testing.T) {
	dir := t.TempDir()
	seal := filepath.Join(dir, "seal.json")
	if err := os.WriteFile(seal, []byte(`{"sealKey":"0123456789abcdef0123456789abcdef"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	base := []string{"--parents=projects/example-project-1", "--asset-types=storage.googleapis.com/Bucket", "--content-types=RESOURCE", "--token-source=metadata", "--credentials=" + seal}
	run1 := func(args []string, stdin string) (int, string, string) {
		var stdout, stderr bytes.Buffer
		code := run(args, strings.NewReader(stdin), &stdout, &stderr)
		return code, stdout.String(), stderr.String()
	}
	if code, _, _ := run1(base[:2], ""); code != 2 {
		t.Fatalf("a command line naming too little: %d", code)
	}
	if code, _, _ := run1(append(append([]string{}, base...), "--check", "--token-only"), ""); code != 2 {
		t.Fatalf("--check and --token-only together: %d", code)
	}
	code, stdout, stderr := run1(base, `{"parent":"projects/example-project-2","contentType":"RESOURCE","assetTypes":["storage.googleapis.com/Bucket"]}`)
	if code != 1 || stdout != "" || !strings.Contains(stderr, "parent-not-configured") {
		t.Fatalf("a parent not configured: %d %q %q", code, stdout, stderr)
	}
	code, _, stderr = run1(base, `{"parent":"projects/example-project-1","contentType":"RESOURCE","assetTypes":["storage.googleapis.com/Bucket"],"x":1}`)
	if code != 1 || !strings.Contains(stderr, "does not take") {
		t.Fatalf("a request member not taken: %d %q", code, stderr)
	}
	missing := append(append([]string{}, base[:4]...), "--credentials="+filepath.Join(dir, "absent.json"), "--token-only")
	if code, _, _ := run1(missing, ""); code != 3 {
		t.Fatalf("no credential: %d", code)
	}
	folder := append([]string{"--parents=folders/200000000001"}, base[1:]...)
	if code, _, stderr := run1(append(folder, "--token-only"), ""); code != 1 || !strings.Contains(stderr, "folder") {
		t.Fatalf("a folder parent: %d %q", code, stderr)
	}
}
