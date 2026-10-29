package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
)

func TestActionJournalReservationSurvivesRestartAndConcurrency(t *testing.T) {
	if !actionJournalSupported {
		t.Skip("durable keyed dispatch is explicitly unsupported")
	}
	dir := t.TempDir()
	key, fingerprint := strings.Repeat("1", 64), strings.Repeat("2", 64)
	var started atomic.Int32
	var wg sync.WaitGroup
	for range 12 {
		wg.Go(func() {
			j, err := openActionJournal(dir)
			if err != nil {
				t.Error(err)
				return
			}
			defer j.close()
			c, err := j.reserve(key, fingerprint)
			if err != nil {
				return
			} // A racing partial intent is conservative uncertainty.
			defer c.close()
			if c.fresh {
				started.Add(1)
			}
		})
	}
	wg.Wait()
	if started.Load() != 1 {
		t.Fatalf("dispatch grants: %d", started.Load())
	}
	j, err := openActionJournal(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer j.close()
	c, err := j.reserve(key, fingerprint)
	if err != nil {
		t.Fatal(err)
	}
	defer c.close()
	if c.fresh {
		t.Fatal("restart granted a second dispatch")
	}
	if _, err = j.reserve(key, strings.Repeat("3", 64)); err == nil || !strings.Contains(err.Error(), "action-key-conflict") {
		t.Fatal("changed payload reused the key", err)
	}
	if err = c.put("response.json", []byte(`{"result":"committed"}`), actionJournalResponseLimit); err != nil {
		t.Fatal(err)
	}
	if err = c.put("response.json", []byte(`{"result":"changed"}`), actionJournalResponseLimit); err == nil {
		t.Fatal("retained response overwritten")
	}
	raw, err := c.read("response.json", actionJournalResponseLimit)
	if err != nil || string(raw) != `{"result":"committed"}` {
		t.Fatal(string(raw), err)
	}
}

func TestActionJournalSyncFailureNeverGrantsDispatch(t *testing.T) {
	if !actionJournalSupported {
		t.Skip("durable keyed dispatch is explicitly unsupported")
	}
	saved := syncActionFile
	total := 0
	syncActionFile = func(f *os.File) error { total++; return f.Sync() }
	baseline, err := openActionJournal(t.TempDir())
	if err != nil {
		syncActionFile = saved
		t.Fatal(err)
	}
	claim, err := baseline.reserve(strings.Repeat("1", 64), strings.Repeat("2", 64))
	baseline.close()
	syncActionFile = saved
	if err != nil {
		t.Fatal(err)
	}
	claim.close()
	for failAt := 1; failAt <= total; failAt++ {
		t.Run(string(rune('0'+failAt)), func(t *testing.T) {
			saved := syncActionFile
			defer func() { syncActionFile = saved }()
			calls := 0
			syncActionFile = func(f *os.File) error {
				calls++
				if calls == failAt {
					return errors.New("injected sync failure")
				}
				return f.Sync()
			}
			j, err := openActionJournal(t.TempDir())
			if err == nil {
				defer j.close()
				var c *actionClaim
				c, err = j.reserve(strings.Repeat("1", 64), strings.Repeat("2", 64))
				if c != nil {
					c.close()
				}
			}
			if err == nil {
				t.Fatalf("dispatch granted after sync failure %d", failAt)
			}
		})
	}
}

func TestActionJournalPartialAndMalformedEntriesRefuse(t *testing.T) {
	if !actionJournalSupported {
		t.Skip("durable keyed dispatch is explicitly unsupported")
	}
	key, fingerprint := strings.Repeat("1", 64), strings.Repeat("2", 64)
	for _, raw := range []string{"", `{`, `{"journalVersion":"1","fingerprint":"bad"}`, `{"journalVersion":"1","journalVersion":"1","fingerprint":"` + fingerprint + `"}`, strings.Repeat("x", 1025)} {
		dir := t.TempDir()
		j, err := openActionJournal(dir)
		if err != nil {
			t.Fatal(err)
		}
		entry := filepath.Join(dir, "actions", key)
		if err = os.Mkdir(entry, 0700); err != nil {
			t.Fatal(err)
		}
		if raw != "" {
			if err = os.WriteFile(filepath.Join(entry, "intent.json"), []byte(raw), 0600); err != nil {
				t.Fatal(err)
			}
		}
		if c, err := j.reserve(key, fingerprint); err == nil {
			c.close()
			t.Fatal("partial/corrupt reservation granted dispatch")
		}
		j.close()
	}
}

func TestActionJournalRejectsLinkedAndPublicEntries(t *testing.T) {
	if !actionJournalSupported {
		t.Skip("durable keyed dispatch is explicitly unsupported")
	}
	dir := t.TempDir()
	j, err := openActionJournal(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer j.close()
	key, fingerprint := strings.Repeat("1", 64), strings.Repeat("2", 64)
	if err = os.Symlink("absent", filepath.Join(dir, "actions", key)); err != nil {
		t.Fatal(err)
	}
	if c, err := j.reserve(key, fingerprint); err == nil {
		c.close()
		t.Fatal("dangling link was treated as absence")
	}
	other := strings.Repeat("3", 64)
	c, err := j.reserve(other, fingerprint)
	if err != nil {
		t.Fatal(err)
	}
	defer c.close()
	if err = os.Symlink("absent", filepath.Join(dir, "actions", other, "response.json")); err != nil {
		t.Fatal(err)
	}
	if _, err = c.read("response.json", 100); err == nil || errors.Is(err, os.ErrNotExist) {
		t.Fatal("linked response was treated as absence", err)
	}
	if err = os.Chmod(filepath.Join(dir, "actions", other, "intent.json"), 0644); err != nil {
		t.Fatal(err)
	}
	if _, err = c.read("intent.json", 1024); err == nil {
		t.Fatal("public intent accepted")
	}
}

func TestActionJournalUnsupportedHostRefuses(t *testing.T) {
	if actionJournalSupported {
		return
	}
	if j, err := openActionJournal(t.TempDir()); err == nil {
		j.close()
		t.Fatal("unsupported durability silently accepted")
	}
}

func TestActionJournalSyncsPhysicalStoreAncestry(t *testing.T) {
	if !actionJournalSupported {
		t.Skip("keyed dispatch unsupported")
	}
	base := t.TempDir()
	store := filepath.Join(base, "new", "nested", "store")
	if err := os.MkdirAll(store, 0700); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(base, "alias")
	if err := os.Symlink(filepath.Join(base, "new"), alias); err != nil {
		t.Fatal(err)
	}
	synced := map[string]bool{}
	saved := syncActionFile
	defer func() { syncActionFile = saved }()
	syncActionFile = func(f *os.File) error { synced[filepath.Clean(f.Name())] = true; return f.Sync() }
	j, err := openActionJournal(filepath.Join(alias, "nested", "store"))
	if err != nil {
		t.Fatal(err)
	}
	j.close()
	physical, err := filepath.EvalSymlinks(store)
	if err != nil {
		t.Fatal(err)
	}
	for parent := filepath.Dir(physical); ; parent = filepath.Dir(parent) {
		if !synced[parent] {
			t.Fatalf("store ancestor was not synced: %s", filepath.Base(parent))
		}
		if filepath.Dir(parent) == parent {
			break
		}
	}
}
