//go:build unix

package main

// A session left in the store as a link, or where the store cannot be read
// (gateway #381): never taken up, never taken for empty.

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

// A link where a session's directory would be is refused as no session
// directory, whether it leads nowhere, to an empty directory or to one
// holding a receipt, and is not followed. A session whose directory cannot
// be listed, or whose entry cannot be looked at, is refused as unread,
// never taken for empty: its source does not run and its seal is refused in
// the same words.
func TestASessionTheStoreHoldsAsALinkOrCannotShowIsRefused(t *testing.T) {
	service, _ := testService(t)
	if _, err := service.acquire("minted", "screening", vString("x"), nil); err != nil {
		t.Fatal(err)
	}
	receipts := filepath.Join(service.storeRoot, "receipts")
	elsewhere := t.TempDir()
	if err := os.Mkdir(filepath.Join(elsewhere, "empty"), 0o700); err != nil {
		t.Fatal(err)
	}
	refusedAs := func(t *testing.T, session, text string) {
		t.Helper()
		started := filepath.Join(t.TempDir(), "source-started")
		t.Setenv(envSourceReady, started)
		before := service.started.Load()
		want := fmt.Sprintf(text, session)
		if _, err := service.acquire(session, "screening", vString("x"), nil); err == nil || err.Error() != want || !errors.As(err, new(badRequest)) {
			t.Fatalf("%s: %v, want %q", session, err, want)
		}
		if _, err := service.sealSession(session); err == nil || err.Error() != want || !errors.As(err, new(badRequest)) {
			t.Fatalf("%s: seal: %v, want %q", session, err, want)
		}
		if _, err := os.Stat(started); !errors.Is(err, os.ErrNotExist) || service.started.Load() != before {
			t.Fatalf("%s: the source ran (%v)", session, err)
		}
		service.mu.Lock()
		_, entered := service.sessions[session]
		service.mu.Unlock()
		if entered {
			t.Fatalf("%s: the refused session entered the map", session)
		}
	}
	for session, target := range map[string]string{
		"dangling":    filepath.Join(elsewhere, "nothing-here"),
		"to-empty":    filepath.Join(elsewhere, "empty"),
		"to-receipts": filepath.Join(receipts, "minted"),
	} {
		if err := os.Symlink(target, filepath.Join(receipts, session)); err != nil {
			t.Fatal(err)
		}
		refusedAs(t, session, notADirText)
	}
	if entries, err := os.ReadDir(filepath.Join(elsewhere, "empty")); err != nil || len(entries) != 0 {
		t.Fatalf("a refused link was followed: %v %v", entries, err)
	}

	if os.Geteuid() == 0 {
		t.Skip("permissions do not hold against root")
	}
	// a session directory that cannot be listed
	closed := filepath.Join(receipts, "closed")
	if err := os.Mkdir(closed, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(closed, "0.json"), []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(closed, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(closed, 0o700) })
	refusedAs(t, "closed", unreadText)
	// the same directory, empty: still unread, not empty
	os.Chmod(closed, 0o700)
	if err := os.Remove(filepath.Join(closed, "0.json")); err != nil {
		t.Fatal(err)
	}
	os.Chmod(closed, 0o000)
	refusedAs(t, "closed", unreadText)
	os.Chmod(closed, 0o700)
	// a store whose receipts directory cannot be searched: no session's
	// entry can be looked at, and one this process holds is still its own
	if err := os.Chmod(receipts, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(receipts, 0o700) })
	refusedAs(t, "unseen", unreadText)
	os.Chmod(receipts, 0o700)
}
