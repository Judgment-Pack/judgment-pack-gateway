package connections

import (
	"os"
	"path/filepath"
	"testing"
)

// writeEnvelope writes an envelope a source's own code wrote in a test,
// against the test's stand-in for the provider, to the directory
// JPACK_TEST_ENVELOPES names, as NAME.json: NAME is the source's id in the
// connection local plan, then "." and what tells two reads of it apart where
// a test writes more than one. The adapter-conform step
// (scripts/checks/adapter-conform.sh) hands each to gateway adapter-conform
// under the shape the plan declares, and to the published envelope schema.
// The envelope is consumed as the code wrote it, not a hand-authored
// substitute; this is a test-only export, and production has no output-path
// option.
func writeEnvelope(t *testing.T, name string, raw []byte) {
	t.Helper()
	dir := os.Getenv("JPACK_TEST_ENVELOPES")
	if dir == "" {
		return
	}
	if err := os.WriteFile(filepath.Join(dir, name+".json"), raw, 0o600); err != nil {
		t.Fatal(err)
	}
}
