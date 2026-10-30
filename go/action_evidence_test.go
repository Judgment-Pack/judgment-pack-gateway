package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// actionSyncLog records every sync the journal makes, as the file it synced,
// and fails the first sync of the directory at fail when fail is set.
type actionSyncLog struct {
	mu     sync.Mutex
	synced []os.FileInfo
	names  []string
	fail   string
}

func (l *actionSyncLog) install(t *testing.T) {
	t.Helper()
	saved := syncActionFile
	syncActionFile = func(f *os.File) error {
		info, err := f.Stat()
		if err != nil {
			return err
		}
		l.mu.Lock()
		defer l.mu.Unlock()
		if l.fail != "" {
			if target, err := os.Stat(l.fail); err == nil && os.SameFile(info, target) {
				l.fail = ""
				return errors.New("injected sync failure")
			}
		}
		l.synced = append(l.synced, info)
		l.names = append(l.names, filepath.Base(f.Name()))
		return f.Sync()
	}
	t.Cleanup(func() { syncActionFile = saved })
}

// position is the index of the first sync of path at or after from, or -1.
func (l *actionSyncLog) position(t *testing.T, path string, from int) int {
	t.Helper()
	want, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	for i := from; i < len(l.synced); i++ {
		if os.SameFile(l.synced[i], want) {
			return i
		}
	}
	return -1
}

// #352 L4: before an action record is written, the directories the receipt
// it cites rests on are synced -- the result's blob directory, the session's
// directory and the receipts directory -- for a response and for an
// uncertain outcome alike.
func TestActionRecordFollowsItsReceiptsDurability(t *testing.T) {
	for _, mode := range []string{"respond", "drop"} {
		t.Run(mode, func(t *testing.T) {
			root, g, c := actionKeysSetup(t)
			actionKeysMode(t, root, "write", mode)
			var log actionSyncLog
			log.install(t)
			key := strings.Repeat("7", 64)
			if _, err := actionKeysAct(g, c, "act", key); err != nil {
				t.Fatal(err)
			}
			record := -1
			for i, name := range log.names {
				if name == "action.json" {
					record = i
				}
			}
			if record < 0 {
				t.Fatal("the action record was never synced")
			}
			for _, dir := range []string{filepath.Join(g.storeRoot, "artifacts"), filepath.Join(g.storeRoot, "receipts", "act"), filepath.Join(g.storeRoot, "receipts")} {
				if at := log.position(t, dir, 0); at < 0 || at > record {
					t.Errorf("%s was synced at %d, the action record at %d", filepath.Base(dir), at, record)
				}
			}
		})
	}
}

// #352 L4: when the receipt's durability cannot be established, no record
// cites it. The dispatch marker keeps the key uncertain: the retry records
// that, reads back, and the target sees one write.
func TestActionRecordRefusedWhenItsReceiptIsNotDurable(t *testing.T) {
	for _, dir := range []string{"artifacts", "receipts/act", "receipts"} {
		t.Run(dir, func(t *testing.T) {
			root, g, c := actionKeysSetup(t)
			key := strings.Repeat("6", 64)
			log := actionSyncLog{fail: filepath.Join(g.storeRoot, filepath.FromSlash(dir))}
			log.install(t)
			_, err := actionKeysAct(g, c, "act", key)
			if err == nil || !strings.Contains(err.Error(), "action-journal-unavailable") {
				t.Fatalf("a receipt that may not be durable was cited: %v", err)
			}
			if log.fail != "" {
				t.Fatal("the directory was never synced")
			}
			namespace := filepath.Join(g.storeRoot, "actions", g.actionNamespace(actionKeysWho, key))
			if _, err := os.Lstat(filepath.Join(namespace, "action.json")); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("an action record was written: %v", err)
			}
			restarted := actionKeysService(t, root, actionKeysSources(t, root, os.Args[0]))
			out, err := actionKeysAct(restarted, c, "retry", key)
			if err != nil || out["reconciliation"] == nil {
				t.Fatalf("the retry was not read back: %v %v", out, err)
			}
			if sent := actionKeysSent(root, key); sent != 1 {
				t.Fatalf("the target received %d writes", sent)
			}
		})
	}
}

// #352 L4: a directory of the receipt that cannot be held is refused like a
// failed sync: no record cites the receipt, and the retry reads back with one
// write at the target. The write program makes the directory unreadable to
// its owner after admission, so the store can still link into it.
func TestActionRecordRefusedWhenItsReceiptsDirectoryCannotBeHeld(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("permission bits do not hold the superuser")
	}
	for _, dir := range []string{"artifacts", "receipts/act"} {
		t.Run(dir, func(t *testing.T) {
			root, _, c := actionKeysSetup(t)
			key := strings.Repeat("5", 64)
			path := filepath.Join(root, "store", filepath.FromSlash(dir))
			t.Cleanup(func() { os.Chmod(path, 0o755) })
			g := actionKeysService(t, root, actionKeysSources(t, root, os.Args[0], "ACTION_KEYS_UNREADABLE="+path))
			_, err := actionKeysAct(g, c, "act", key)
			if f, openErr := os.Open(path); openErr == nil {
				f.Close()
				t.Skip("this platform reads a directory without its read permission")
			}
			if err == nil || !strings.Contains(err.Error(), "action-journal-unavailable") {
				t.Fatalf("a receipt whose directory could not be held was cited: %v", err)
			}
			namespace := filepath.Join(g.storeRoot, "actions", g.actionNamespace(actionKeysWho, key))
			if _, err := os.Lstat(filepath.Join(namespace, "action.json")); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("an action record was written: %v", err)
			}
			if err := os.Chmod(path, 0o755); err != nil {
				t.Fatal(err)
			}
			restarted := actionKeysService(t, root, actionKeysSources(t, root, os.Args[0]))
			out, err := actionKeysAct(restarted, c, "retry", key)
			if err != nil || out["reconciliation"] == nil {
				t.Fatalf("the retry was not read back: %v %v", out, err)
			}
			if sent := actionKeysSent(root, key); sent != 1 {
				t.Fatalf("the target received %d writes", sent)
			}
		})
	}
}
