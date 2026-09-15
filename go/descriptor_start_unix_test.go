//go:build unix

package main

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

// The ownership invariants the MCP server holds a snapshot and its
// directory to, where a test can set them: neither writable by group or
// others, and a directory swapped for a link to itself once judged.
func TestTheStartHoldsModes(t *testing.T) {
	good := canonicalSnapshot(t, servedTools)
	for _, tc := range []struct {
		name  string
		setup func(t *testing.T, f *servedFixture)
		want  string
	}{
		{"a snapshot others could write", func(t *testing.T, f *servedFixture) {
			if err := os.Chmod(f.path(), 0o664); err != nil {
				t.Fatal(err)
			}
		}, "is writable beyond its owner"},
		{"a directory others could write", func(t *testing.T, f *servedFixture) {
			if err := os.Chmod(f.snapshots, 0o775); err != nil {
				t.Fatal(err)
			}
		}, "is writable beyond its owner"},
		{"a link to the same directory, put in its place once judged", func(t *testing.T, f *servedFixture) {
			entryJudged = func(name string) {
				if !strings.HasSuffix(name, ".descriptors") {
					return
				}
				entryJudged = nil
				if err := os.Rename(f.snapshots, f.snapshots+".moved"); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(filepath.Base(f.snapshots)+".moved", f.snapshots); err != nil {
					t.Fatal(err)
				}
			}
			t.Cleanup(func() { entryJudged = nil })
		}, "is not the directory its name held a moment ago"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newServedFixture(t, good)
			tc.setup(t, f)
			if _, err := readServedPlatforms(f.config, f.cfg, f.bindings); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("want %q: %v", tc.want, err)
			}
		})
	}
}

// Nothing the MCP server's own user or group holds is served from, even
// owned by root or by the configuration's owner.
func TestTheStartRefusesTheMCPServersOwn(t *testing.T) {
	for _, tc := range []struct {
		st    syscall.Stat_t
		owner fileOwnerIDs
	}{
		{syscall.Stat_t{Uid: frontendUID}, fileOwnerIDs{uid: frontendUID, known: true}},
		{syscall.Stat_t{Uid: 0, Gid: frontendUID}, fileOwnerIDs{uid: 1000, known: true}},
	} {
		st := tc.st
		if err := servedInvariant(fakeInfo{mode: 0o644, sys: &st}, tc.owner); err == nil || !strings.Contains(err.Error(), "belongs to the MCP server's own user or group") {
			t.Errorf("%+v: %v", tc.st, err)
		}
	}
	st := syscall.Stat_t{Uid: 4242}
	if err := servedInvariant(fakeInfo{mode: 0o644, sys: &st}, fileOwnerIDs{uid: 1000, known: true}); err == nil || !strings.Contains(err.Error(), "neither root nor the configuration's owner") {
		t.Errorf("another user's: %v", err)
	}
}
