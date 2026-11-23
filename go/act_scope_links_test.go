package main

import (
	"os"
	"path/filepath"
	"testing"
)

// The start check of the decision-record directories follows a link above
// a directory not made yet (ADR-0054, decision 1): a scoped platform's
// directory spelled beneath a link to the gateway's directory, or beneath a
// link that leads nowhere yet but would be the gateway's, is refused.
func TestActScopeDecisionRecordsBeneathALink(t *testing.T) {
	root := t.TempDir()
	gateway := filepath.Join(root, "gateway")
	if err := os.Mkdir(gateway, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(gateway, filepath.Join(root, "link")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(gateway, "later"), filepath.Join(root, "dangling")); err != nil {
		t.Fatal(err)
	}
	for _, dir := range []string{filepath.Join(root, "link", "b"), filepath.Join(root, "link", "b", "c"), filepath.Join(root, "dangling", "b")} {
		platforms := []platformConfig{{name: "tickets-b", scope: callerScopeB, decisionRecords: dir}}
		if err := decisionRecordsApart(gateway, platforms, resolvedOrClean); err == nil {
			t.Errorf("%s: a directory beneath the gateway's through a link loaded", dir)
		}
	}
	apart := []platformConfig{{name: "tickets-b", scope: callerScopeB, decisionRecords: filepath.Join(root, "b", "records")}}
	if err := decisionRecordsApart(gateway, apart, resolvedOrClean); err != nil {
		t.Fatalf("a directory apart, not made yet: %v", err)
	}
}
