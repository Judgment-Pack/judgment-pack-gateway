//go:build unix

package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A pinned snapshot is read only when the file the pin names, as opened,
// is of the snapshot's mode and an owner the MCP server accepts: any other
// is unreadable, and none of its bytes are given. The export reads pins
// through the same space.
func TestAPinnedSnapshotIsReadOnlyAtItsModeAndOwner(t *testing.T) {
	dir := t.TempDir()
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	info, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	own := ownerIDsOf(info)
	pins := fsHeldPins{dir: root, name: "engine.json.descriptors", owner: own}
	snapshot := []byte(`{"descriptors":[]}`)
	sum := sha256.Sum256(snapshot)
	pin := "sha256:" + hex.EncodeToString(sum[:])
	path := filepath.Join(dir, hex.EncodeToString(sum[:])+".json")
	if err := os.WriteFile(path, snapshot, snapshotMode); err != nil {
		t.Fatal(err)
	}
	chmod := func(mode os.FileMode) {
		t.Helper()
		if err := os.Chmod(path, mode); err != nil {
			t.Fatal(err)
		}
	}
	refused := func(what, why string) {
		t.Helper()
		data, err := pins.getBlob(pin)
		requireFault(t, what, err, faultUnreadable)
		if data != nil || !strings.Contains(err.Error(), why) {
			t.Fatalf("%s: %q given, %v", what, data, err)
		}
	}

	chmod(snapshotMode)
	if data, err := pins.getBlob(pin); err != nil || !bytes.Equal(data, snapshot) {
		t.Fatalf("a snapshot at its mode and owner: %q %v", data, err)
	}
	chmod(0o600)
	refused("a snapshot the MCP server cannot read", "has mode 0600")
	chmod(0o664)
	refused("a snapshot its group may write", "has mode 0664")
	chmod(snapshotMode)

	if os.Geteuid() == 0 {
		t.Skip("a file root owns is held by any owner")
	}
	pins.owner = fileOwnerIDs{uid: own.uid + 1, gid: own.gid, known: true}
	refused("a snapshot of another owner than the configuration's", "neither root nor the configuration's owner")
}
