//go:build linux || darwin

package connections

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// The engine's admission of a delegated write under a grant (gateway #368,
// SPEC.md §10 rule 3), in two parts around the delegation's counting
// admission: check is the grant's state alone, before it, with no owner read
// and no record; admit, after it, is the check every use of the custody's own
// credential passes, the owner read included, and the record of the use.

func admitDrive(t *testing.T, dir string, connection string) (map[string]any, error) {
	t.Helper()
	return grantOp(t, dir, "alice", "google-drive", "admit", map[string]any{"provider": "google-drive", "connection": connection})
}

// A live grant admits, and its use is recorded with no scope: the write's
// token is the platform's, so no declared scope of the connection is used.
func TestGrantAdmitRecordsTheUse(t *testing.T) {
	now := grantT0
	atClock(t, &now)
	_, count, dir, _ := driveGrant(t)
	read := count.Load()
	out, err := admitDrive(t, dir, "google-drive")
	if err != nil {
		t.Fatal(err)
	}
	if raw, _ := json.Marshal(out); string(raw) != `{"admission":"admit","connection":"google-drive","provider":"google-drive","version":1}` {
		t.Fatalf("the answer: %s", raw)
	}
	if count.Load() != read {
		t.Fatal("an admission read a file")
	}
	row := rowOf(t, mustReport(t, dir), "google-drive", "google-drive", "active")
	if row.LastUsedAt == nil || *row.LastUsedAt != grantTime(now) || len(row.Scopes.Used) != 0 {
		t.Fatalf("the use: %+v", row)
	}
}

// What admit refuses: no custody, no record, a quarantined, a revoked, an
// idle-expired grant, an owner whose standing is not answered, and a
// custody that cannot be read, which is never taken for one that is not
// there.
func TestGrantAdmitRefusals(t *testing.T) {
	t.Run("no custody", func(t *testing.T) {
		_, _, dir, _ := driveGrant(t)
		if _, err := grantOp(t, dir, "alice", "gmail", "admit", map[string]any{"provider": "gmail", "connection": "gmail"}); err != ErrGrantUnknown {
			t.Fatalf("a provider with no custody: %v", err)
		}
		if _, err := os.Lstat(filepath.Join(dir, "gmail")); !os.IsNotExist(err) {
			t.Fatalf("admit made a custody: %v", err)
		}
	})
	t.Run("no record", func(t *testing.T) {
		_, _, dir, _ := driveGrant(t)
		if _, err := admitDrive(t, dir, "another"); err != ErrGrantUnknown {
			t.Fatalf("a connection custody does not hold: %v", err)
		}
	})
	t.Run("quarantined", func(t *testing.T) {
		_, _, dir, _ := driveGrant(t)
		if _, err := grantOp(t, dir, "alice", "", "set-owner", map[string]any{"provider": "google-drive", "connection": "google-drive", "owner": owner, "ownerHost": "desk"}); err != nil {
			t.Fatal(err)
		}
		if _, err := grantOp(t, dir, "alice", "", "remove-owner", map[string]any{"owner": owner, "ownerHost": "desk", "removal": quarantineRemoval}); err != nil {
			t.Fatal(err)
		}
		if _, err := admitDrive(t, dir, "google-drive"); err != ErrGrantQuarantined {
			t.Fatalf("a quarantined grant: %v", err)
		}
	})
	t.Run("revoked", func(t *testing.T) {
		_, _, dir, _ := driveGrant(t)
		if _, err := grantOp(t, dir, "alice", "", "revoke", map[string]any{"provider": "google-drive", "connection": "google-drive"}); err != nil {
			t.Fatal(err)
		}
		if _, err := admitDrive(t, dir, "google-drive"); err != ErrGrantRevoked {
			t.Fatalf("a revoked grant: %v", err)
		}
	})
	t.Run("idle expired", func(t *testing.T) {
		now := grantT0
		atClock(t, &now)
		_, _, dir, _ := driveGrant(t)
		if _, err := grantOp(t, dir, "alice", "", "set-idle-expiry", map[string]any{"provider": "google-drive", "connection": "google-drive", "idleExpiry": 60_000}); err != nil {
			t.Fatal(err)
		}
		now = now.Add(time.Minute)
		if _, err := admitDrive(t, dir, "google-drive"); err != ErrGrantIdle {
			t.Fatalf("at the bound: %v", err)
		}
		rowOf(t, mustReport(t, dir), "google-drive", "google-drive", "revoked")
	})
	t.Run("owner read", func(t *testing.T) {
		_, _, dir, _ := driveGrant(t)
		standing := `{"standing":"current"}`
		asked, cfg := ownerHost(t, &standing, quarantineRemoval)
		if _, err := grantOp(t, dir, "alice", "", "set-owner", map[string]any{"provider": "google-drive", "connection": "google-drive", "owner": owner, "ownerHost": "desk"}); err != nil {
			t.Fatal(err)
		}
		if _, err := admitDrive(t, dir, "google-drive"); err != ErrOwnerUnknown || asked.Load() != 0 {
			t.Fatalf("no owner read configured: %v, %d reads", err, asked.Load())
		}
		if _, err := grantOp(t, dir, "alice", "", "owner-reads", cfg); err != nil {
			t.Fatal(err)
		}
		if _, err := admitDrive(t, dir, "google-drive"); err != nil || asked.Load() != 1 {
			t.Fatalf("a current owner: %v, %d reads", err, asked.Load())
		}
		standing = `{"standing":"removed"}`
		if _, err := admitDrive(t, dir, "google-drive"); err != ErrOwnerRemoved {
			t.Fatalf("a removed owner: %v", err)
		}
		rowOf(t, mustReport(t, dir), "google-drive", "google-drive", "quarantined")
	})
	t.Run("unreadable", func(t *testing.T) {
		_, _, dir, _ := driveGrant(t)
		if err := os.Chmod(dir, 0o750); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { os.Chmod(dir, 0o700) })
		if _, err := admitDrive(t, dir, "google-drive"); err != ErrStorage {
			t.Fatalf("a custody that cannot be opened: %v", err)
		}
	})
	t.Run("malformed", func(t *testing.T) {
		_, _, dir, _ := driveGrant(t)
		for _, request := range []any{
			map[string]any{"provider": "google-drive"},
			map[string]any{"provider": "obsidian", "connection": "vault"},
			map[string]any{"provider": "google-drive", "connection": "../x"},
			map[string]any{"provider": "google-drive", "connection": "google-drive", "extra": 1},
		} {
			if _, err := grantOp(t, dir, "alice", "google-drive", "admit", request); err != ErrRequest {
				t.Fatalf("%v: %v", request, err)
			}
		}
		if _, err := grantOp(t, dir, "alice", "gmail", "admit", map[string]any{"provider": "google-drive", "connection": "google-drive"}); err != ErrRequest {
			t.Fatalf("a request for another provider than --provider names: %v", err)
		}
	})
}

func checkDrive(t *testing.T, dir string, connection string) (map[string]any, error) {
	t.Helper()
	return grantOp(t, dir, "alice", "google-drive", "check", map[string]any{"provider": "google-drive", "connection": connection})
}

// check passes a live grant with no owner read and no record of a use, even
// where the owner's standing would refuse it: that read follows the
// delegation's admission (RFC 0030 §2), in admit.
func TestGrantCheckIsTheStateAlone(t *testing.T) {
	now := grantT0
	atClock(t, &now)
	_, _, dir, _ := driveGrant(t)
	standing := `{"standing":"removed"}`
	asked, cfg := ownerHost(t, &standing, quarantineRemoval)
	if _, err := grantOp(t, dir, "alice", "", "set-owner", map[string]any{"provider": "google-drive", "connection": "google-drive", "owner": owner, "ownerHost": "desk"}); err != nil {
		t.Fatal(err)
	}
	if _, err := grantOp(t, dir, "alice", "", "owner-reads", cfg); err != nil {
		t.Fatal(err)
	}
	out, err := checkDrive(t, dir, "google-drive")
	if err != nil {
		t.Fatal(err)
	}
	if raw, _ := json.Marshal(out); string(raw) != `{"check":"pass","connection":"google-drive","provider":"google-drive","version":1}` {
		t.Fatalf("the answer: %s", raw)
	}
	if asked.Load() != 0 {
		t.Fatalf("check made %d owner reads", asked.Load())
	}
	if row := rowOf(t, mustReport(t, dir), "google-drive", "google-drive", "active"); row.LastUsedAt != nil {
		t.Fatalf("check recorded a use: %+v", row)
	}
	// The owner read is admit's, and refuses there.
	if _, err := admitDrive(t, dir, "google-drive"); err != ErrOwnerRemoved || asked.Load() != 1 {
		t.Fatalf("admit after check: %v, %d reads", err, asked.Load())
	}
	// The grant quarantined by that read is refused by check, with no read.
	if _, err := checkDrive(t, dir, "google-drive"); err != ErrGrantQuarantined || asked.Load() != 1 {
		t.Fatalf("check of the quarantined grant: %v, %d reads", err, asked.Load())
	}
}

// What check refuses, as admit does: no custody, no record, a revoked and an
// idle-expired grant, a custody that cannot be read, a malformed request.
func TestGrantCheckRefusals(t *testing.T) {
	t.Run("no custody", func(t *testing.T) {
		_, _, dir, _ := driveGrant(t)
		if _, err := grantOp(t, dir, "alice", "gmail", "check", map[string]any{"provider": "gmail", "connection": "gmail"}); err != ErrGrantUnknown {
			t.Fatalf("a provider with no custody: %v", err)
		}
		if _, err := os.Lstat(filepath.Join(dir, "gmail")); !os.IsNotExist(err) {
			t.Fatalf("check made a custody: %v", err)
		}
	})
	t.Run("no record", func(t *testing.T) {
		_, _, dir, _ := driveGrant(t)
		if _, err := checkDrive(t, dir, "another"); err != ErrGrantUnknown {
			t.Fatalf("a connection custody does not hold: %v", err)
		}
	})
	t.Run("revoked", func(t *testing.T) {
		_, _, dir, _ := driveGrant(t)
		if _, err := grantOp(t, dir, "alice", "", "revoke", map[string]any{"provider": "google-drive", "connection": "google-drive"}); err != nil {
			t.Fatal(err)
		}
		if _, err := checkDrive(t, dir, "google-drive"); err != ErrGrantRevoked {
			t.Fatalf("a revoked grant: %v", err)
		}
	})
	t.Run("idle expired", func(t *testing.T) {
		now := grantT0
		atClock(t, &now)
		_, _, dir, _ := driveGrant(t)
		if _, err := grantOp(t, dir, "alice", "", "set-idle-expiry", map[string]any{"provider": "google-drive", "connection": "google-drive", "idleExpiry": 60_000}); err != nil {
			t.Fatal(err)
		}
		now = now.Add(time.Minute)
		if _, err := checkDrive(t, dir, "google-drive"); err != ErrGrantIdle {
			t.Fatalf("at the bound: %v", err)
		}
		rowOf(t, mustReport(t, dir), "google-drive", "google-drive", "revoked")
	})
	t.Run("unreadable", func(t *testing.T) {
		_, _, dir, _ := driveGrant(t)
		if err := os.Chmod(dir, 0o750); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { os.Chmod(dir, 0o700) })
		if _, err := checkDrive(t, dir, "google-drive"); err != ErrStorage {
			t.Fatalf("a custody that cannot be opened: %v", err)
		}
	})
	t.Run("malformed", func(t *testing.T) {
		_, _, dir, _ := driveGrant(t)
		if _, err := grantOp(t, dir, "alice", "gmail", "check", map[string]any{"provider": "google-drive", "connection": "google-drive"}); err != ErrRequest {
			t.Fatalf("a request for another provider than --provider names: %v", err)
		}
	})
}

// A grant holding a scope no operation declares refuses an admission as it
// refuses every use.
func TestGrantAdmitRefusesExcessScope(t *testing.T) {
	fields := dbPrincipalFields()
	fields["scope"] = "sql"
	dir := t.TempDir()
	os.Chmod(dir, 0700)
	s, err := OpenDatabricksStore(dir, "test")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	b := NewDatabricks(s, false)
	defer b.Close()
	if err := dbConfigure(b, fields); err != nil {
		t.Fatal(err)
	}
	if _, err := grantOp(t, dir, "test", "databricks", "admit", map[string]any{"provider": "databricks", "connection": "lake"}); err != nil {
		t.Fatal(err)
	}
	if err := s.locked(func(v *state) error {
		v.Databricks.Connections[0].Scope = "sql jobs"
		return s.write("state.json", v)
	}); err != nil {
		t.Fatal(err)
	}
	for _, operation := range []string{"check", "admit"} {
		if _, err := grantOp(t, dir, "test", "databricks", operation, map[string]any{"provider": "databricks", "connection": "lake"}); err == nil || err.Error() != "excess-scope: jobs" {
			t.Fatalf("%s of a grant holding jobs: %v", operation, err)
		}
	}
}
