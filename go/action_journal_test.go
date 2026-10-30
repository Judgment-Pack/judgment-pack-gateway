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
			c, err := j.reserve(key, actionIdentity{fingerprint: fingerprint})
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
	c, err := j.reserve(key, actionIdentity{fingerprint: fingerprint})
	if err != nil {
		t.Fatal(err)
	}
	defer c.close()
	if c.fresh {
		t.Fatal("restart granted a second dispatch")
	}
	if _, err = j.reserve(key, actionIdentity{fingerprint: strings.Repeat("3", 64)}); err == nil || !strings.Contains(err.Error(), "action-key-conflict") {
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
	claim, err := baseline.reserve(strings.Repeat("1", 64), actionIdentity{fingerprint: strings.Repeat("2", 64)})
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
				c, err = j.reserve(strings.Repeat("1", 64), actionIdentity{fingerprint: strings.Repeat("2", 64)})
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
		if c, err := j.reserve(key, actionIdentity{fingerprint: fingerprint}); err == nil {
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
	if c, err := j.reserve(key, actionIdentity{fingerprint: fingerprint}); err == nil {
		c.close()
		t.Fatal("dangling link was treated as absence")
	}
	other := strings.Repeat("3", 64)
	c, err := j.reserve(other, actionIdentity{fingerprint: fingerprint})
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

// #351 L1: dispatch is granted by an exclusive marker; only a complete
// not-dispatched answer frees the next attempt, and anything else that may
// have begun stays begun.
func TestActionJournalDispatchMarkers(t *testing.T) {
	if !actionJournalSupported {
		t.Skip("durable keyed dispatch is explicitly unsupported")
	}
	dir := t.TempDir()
	key, fingerprint := strings.Repeat("1", 64), strings.Repeat("2", 64)
	open := func() (*actionJournal, *actionClaim) {
		t.Helper()
		j, err := openActionJournal(dir)
		if err != nil {
			t.Fatal(err)
		}
		c, err := j.reserve(key, actionIdentity{fingerprint: fingerprint})
		if err != nil {
			t.Fatal(err)
		}
		return j, c
	}
	expect := func(c *actionClaim, n int, begun bool) {
		t.Helper()
		gotN, gotBegun, err := c.attempt()
		if err != nil || gotN != n || gotBegun != begun {
			t.Fatalf("attempt %d begun %v, want %d %v: %v", gotN, gotBegun, n, begun, err)
		}
	}
	j, c := open()
	expect(c, 1, false)
	c.close()
	j.close()

	var granted atomic.Int32
	var wg sync.WaitGroup
	for range 12 {
		wg.Go(func() {
			j, err := openActionJournal(dir)
			if err != nil {
				t.Error(err)
				return
			}
			defer j.close()
			c, err := j.reserve(key, actionIdentity{fingerprint: fingerprint})
			if err != nil {
				t.Error(err)
				return
			}
			defer c.close()
			if err := c.claimDispatch(1); err == nil {
				granted.Add(1)
			} else if !errors.Is(err, errActionDispatchClaimed) {
				t.Error(err)
			}
		})
	}
	wg.Wait()
	if granted.Load() != 1 {
		t.Fatalf("dispatch grants: %d", granted.Load())
	}
	j, c = open()
	defer j.close()
	defer c.close()
	expect(c, 1, true)
	if err := c.releaseDispatch(1, "not started"); err != nil {
		t.Fatal(err)
	}
	expect(c, 2, false)
	if err := c.claimDispatch(2); err != nil {
		t.Fatal(err)
	}
	// An answer that is not a complete private record proves nothing.
	if err := os.WriteFile(filepath.Join(dir, "actions", key, "not-dispatched-2.json"), []byte(`{"attempt"`), 0600); err != nil {
		t.Fatal(err)
	}
	expect(c, 2, true)
	if err := c.releaseDispatch(2, "again"); err == nil {
		t.Fatal("an answer was overwritten")
	}
}

// A marker whose durability failed never permits a dispatch, and counts as
// begun afterwards.
func TestActionJournalDispatchMarkerSyncFailureNeverDispatches(t *testing.T) {
	if !actionJournalSupported {
		t.Skip("durable keyed dispatch is explicitly unsupported")
	}
	for failAt := 1; failAt <= 2; failAt++ {
		dir := t.TempDir()
		j, err := openActionJournal(dir)
		if err != nil {
			t.Fatal(err)
		}
		c, err := j.reserve(strings.Repeat("1", 64), actionIdentity{fingerprint: strings.Repeat("2", 64)})
		if err != nil {
			t.Fatal(err)
		}
		saved := syncActionFile
		calls := 0
		syncActionFile = func(f *os.File) error {
			if calls++; calls == failAt {
				return errors.New("injected sync failure")
			}
			return f.Sync()
		}
		err = c.claimDispatch(1)
		syncActionFile = saved
		if err == nil {
			t.Fatalf("dispatch granted after marker sync failure %d", failAt)
		}
		if _, begun, _ := c.attempt(); !begun {
			t.Fatalf("a marker whose durability failed was not treated as begun (%d)", failAt)
		}
		c.close()
		j.close()
	}
}

// A reservation written before dispatch markers existed cannot prove that
// nothing was sent, and is refused.
func TestActionJournalRefusesALegacyReservation(t *testing.T) {
	if !actionJournalSupported {
		t.Skip("durable keyed dispatch is explicitly unsupported")
	}
	dir := t.TempDir()
	key, fingerprint := strings.Repeat("1", 64), strings.Repeat("2", 64)
	j, err := openActionJournal(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer j.close()
	if err = os.Mkdir(filepath.Join(dir, "actions", key), 0700); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(dir, "actions", key, "intent.json"), []byte(`{"journalVersion":"1","fingerprint":"`+fingerprint+`"}`), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = j.reserve(key, actionIdentity{fingerprint: fingerprint}); err == nil {
		t.Fatal("a version 1 reservation was accepted")
	}
}
