//go:build unix

package main

// The witness's files are held, not followed: each is opened through its
// held directory as the entry it is, judged by its descriptor, private to
// the signer, and locked against a second writer (witness_log.go).

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// A link in place of any of the witness's files is refused, never followed,
// whether it was there when the witness looked or was put there between its
// look and its open; so is a FIFO, without the open waiting on it; and
// nothing the link pointed at is read or written.
func TestWitnessFilesAreHeldNotFollowed(t *testing.T) {
	for _, name := range []string{"log", "marks", "registrations"} {
		t.Run("a link in place of the "+name, func(t *testing.T) {
			tw := newTestWitness(t, testTrail)
			tw.open(t).close()
			path := map[string]string{"log": tw.paths.log, "marks": tw.paths.marks, "registrations": tw.paths.log + registrationsSuffix}[name]
			target := filepath.Join(filepath.Dir(path), "elsewhere")
			if err := os.Rename(path, target); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(filepath.Base(target), path); err != nil {
				t.Fatal(err)
			}
			before, _ := os.ReadFile(target)
			if _, err := openWitnessLog(tw.config()); err == nil || !strings.Contains(err.Error(), "symbolic link") {
				t.Fatalf("open: %v", err)
			}
			if _, err := tw.repair(osWitnessIO()); err == nil {
				t.Fatal("repair through a link")
			}
			if after, _ := os.ReadFile(target); string(after) != string(before) {
				t.Fatal("the link's target was written")
			}
		})
	}
	t.Run("a link put in place between the look and the open", func(t *testing.T) {
		tw := newTestWitness(t, testTrail)
		tw.open(t).close()
		witnessEntryJudged = func(name string) {
			if name == filepath.Base(tw.paths.log) {
				os.Rename(tw.paths.log, tw.paths.log+".moved")
				os.Symlink(filepath.Base(tw.paths.log)+".moved", tw.paths.log)
			}
		}
		defer func() { witnessEntryJudged = nil }()
		if _, err := openWitnessLog(tw.config()); err == nil {
			t.Fatal("a link swapped in after the look was opened")
		}
	})
	t.Run("a FIFO in place of the log", func(t *testing.T) {
		tw := newTestWitness(t, testTrail)
		if err := syscall.Mkfifo(tw.paths.log, 0o600); err != nil {
			t.Skip("no FIFO here:", err)
		}
		done := make(chan error, 1)
		go func() { _, err := openWitnessLog(tw.config()); done <- err }()
		select {
		case err := <-done:
			if err == nil || !strings.Contains(err.Error(), "not a regular file") {
				t.Fatalf("a FIFO in place of the log: %v", err)
			}
		case <-time.After(10 * time.Second):
			t.Fatal("the open waited on a FIFO")
		}
	})
}

// The witness's files are private to the signer: one opened to its group or
// to others is refused, and so is a directory others may replace an entry
// of; the files the witness makes are 0600 whatever the umask.
func TestWitnessFilesArePrivate(t *testing.T) {
	tw := newTestWitness(t, testTrail)
	old := syscall.Umask(0)
	tw.open(t).close()
	syscall.Umask(old)
	for _, path := range []string{tw.paths.log, tw.paths.marks, tw.paths.log + registrationsSuffix} {
		info, err := os.Stat(path)
		if err != nil || info.Mode().Perm() != 0o600 {
			t.Fatalf("%s: %v %v", filepath.Base(path), info.Mode(), err)
		}
	}
	if err := os.Chmod(tw.paths.marks, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := openWitnessLog(tw.config()); err == nil || !strings.Contains(err.Error(), "0644") {
		t.Fatalf("marks open to others: %v", err)
	}
	os.Chmod(tw.paths.marks, 0o600)
	if err := os.Chmod(filepath.Dir(tw.paths.log), 0o777); err != nil {
		t.Fatal(err)
	}
	if _, err := openWitnessLog(tw.config()); err == nil || !strings.Contains(err.Error(), "writable beyond its owner") {
		t.Fatalf("a log directory others may write: %v", err)
	}
	os.Chmod(filepath.Dir(tw.paths.log), 0o700)
	tw.open(t).close()
}

// One process at a time holds the witness's files: a second open, a repair
// or an offline registration while the first holds them is refused.
func TestWitnessOneWriterHoldsTheFiles(t *testing.T) {
	tw := newTestWitness(t, testTrail)
	w := tw.open(t)
	if _, err := openWitnessLog(tw.config()); err == nil || !strings.Contains(err.Error(), "held by another witness") {
		t.Fatalf("a second open: %v", err)
	}
	if _, err := tw.repair(osWitnessIO()); err == nil {
		t.Fatal("a repair while the witness runs")
	}
	if err := registerWitnessTrail(tw.paths, witnessRegistration{trail: trailB, issuer: witnessIssuer, subject: "b"}, tw.io(osWitnessIO())); err == nil {
		t.Fatal("an offline registration while the witness runs")
	}
	w.close()
	tw.open(t).close()
}

// linkWitness gives each of a witness's files a second name, a hard link,
// in a directory of its own, and gives those names as a witness's paths.
func linkWitness(t *testing.T, from witnessPaths) witnessPaths {
	t.Helper()
	to := newWitnessPaths(t)
	for src, dst := range map[string]string{from.log: to.log, from.marks: to.marks, from.log + registrationsSuffix: to.log + registrationsSuffix} {
		if err := os.Link(src, dst); err != nil {
			t.Fatal(err)
		}
	}
	return to
}

// linkWitnessDirectories names a witness's directories again through
// symbolic links to them, so its files are reached by other paths and each
// still has one name.
func linkWitnessDirectories(t *testing.T, from witnessPaths) witnessPaths {
	t.Helper()
	root := tempDirAt(t, 0o700)
	logDir, marksDir := filepath.Join(root, "log-alias"), filepath.Join(root, "marks-alias")
	if err := os.Symlink(filepath.Dir(from.log), logDir); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Dir(from.marks), marksDir); err != nil {
		t.Fatal(err)
	}
	return witnessPaths{log: filepath.Join(logDir, filepath.Base(from.log)), marks: filepath.Join(marksDir, filepath.Base(from.marks))}
}

// A second witness in this process, reaching a running witness's files by
// other names -- hard links to each, or its directories through linked
// directories -- is refused before it reads anything: the lock is on the
// files, not on their names. The fork the alias would have made, two
// statements at one index, is never signed.
func TestWitnessAliasesReachNoSecondWriter(t *testing.T) {
	for _, alias := range []struct {
		name string
		make func(*testing.T, witnessPaths) witnessPaths
		why  string
	}{
		{"hard-linked names", linkWitness, "names (hard links)"},
		{"linked directories", linkWitnessDirectories, "held by another witness"},
	} {
		t.Run(alias.name, func(t *testing.T) {
			tw := newTestWitness(t, testTrail)
			w := tw.open(t)
			defer w.close()
			cfg := tw.config()
			cfg.paths = alias.make(t, tw.paths)
			if second, err := openWitnessLog(cfg); err == nil {
				second.close()
				t.Fatal("a second witness opened the same files by other names")
			} else if !strings.Contains(err.Error(), alias.why) {
				t.Fatalf("refused, but not for %q: %v", alias.why, err)
			}
			mustSign(t, w, testTrail, 1)
		})
	}
}

// The lock is on the files themselves: with the hard links gone and the
// names counted no longer, a witness reached through linked directories
// while another holds the files is refused by the lock alone; and a
// witness's own files under two of its names -- the marks' directory a link
// to the log's, the marks named as the log -- are refused as one file.
func TestWitnessLockIsOnTheFiles(t *testing.T) {
	tw := newTestWitness(t, testTrail)
	tw.open(t).close()
	alias := linkWitnessDirectories(t, tw.paths)
	held, err := holdWitnessFiles(alias, osWitnessIO())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := openWitnessLog(tw.config()); err == nil || !strings.Contains(err.Error(), "held by another witness") {
		t.Fatalf("the files held through linked directories, a witness by their own names: %v", err)
	}
	held.close()
	tw.open(t).close()

	same := witnessPaths{log: tw.paths.log, marks: filepath.Join(filepath.Dir(alias.log), filepath.Base(tw.paths.log))}
	if _, err := holdWitnessFiles(same, osWitnessIO()); err == nil || !strings.Contains(err.Error(), "one file under two names") {
		t.Fatalf("the marks the log under another path: %v", err)
	}
}

// Every file of the witness's has exactly one name: a hard link anywhere to
// the log, the marks, the registrations or the set-aside file -- even with
// no other witness running, and even one outside the witness's directories
// -- refuses the witness, its repair and its registrations, before any file
// is read or written. Elsewhere such a name is a way to reach the file this
// witness never looked at.
func TestWitnessFilesHaveOneName(t *testing.T) {
	for _, which := range []string{"log", "marks", "registrations", "set-aside"} {
		t.Run(which, func(t *testing.T) {
			tw := newTestWitness(t, testTrail)
			w := tw.open(t)
			mustSign(t, w, testTrail, 1)
			w.close()
			if which == "set-aside" {
				tw.write(t, "log", tw.read(t, "log")+"torn")
				if _, err := tw.repair(osWitnessIO()); err != nil {
					t.Fatal(err)
				}
			}
			path := map[string]string{"log": tw.paths.log, "marks": tw.paths.marks, "registrations": tw.paths.log + registrationsSuffix, "set-aside": tw.paths.log + setAsideSuffix}[which]
			elsewhere := filepath.Join(tempDirAt(t, 0o700), "second-name")
			if err := os.Link(path, elsewhere); err != nil {
				t.Fatal(err)
			}
			if which == "set-aside" {
				tw.write(t, "log", tw.read(t, "log")+"torn again")
				before := tw.read(t, "log")
				if _, err := tw.repair(osWitnessIO()); err == nil || !strings.Contains(err.Error(), "names (hard links)") {
					t.Fatalf("repair with a set-aside file of two names: %v", err)
				}
				if tw.read(t, "log") != before {
					t.Fatal("the log was cut although its bytes could not be kept")
				}
				return
			}
			if _, err := openWitnessLog(tw.config()); err == nil || !strings.Contains(err.Error(), "names (hard links)") {
				t.Fatalf("open: %v", err)
			}
			if _, err := tw.repair(osWitnessIO()); err == nil {
				t.Fatal("repair with a file of two names")
			}
			if err := registerWitnessTrail(tw.paths, witnessRegistration{trail: trailB, issuer: witnessIssuer, subject: "b"}, tw.io(osWitnessIO())); err == nil {
				t.Fatal("an offline registration with a file of two names")
			}
		})
	}
}

// A set-aside file that is a hard link to the log -- the case where the
// kept bytes were appended to the log and then cut off with the rest -- is
// refused before anything is written: the log has two names. The torn bytes
// stay where they were, and nothing is set aside or cut.
func TestWitnessSetAsideLinkedToTheLogIsRefused(t *testing.T) {
	tw := newTestWitness(t, testTrail)
	w := tw.open(t)
	mustSign(t, w, testTrail, 1)
	w.close()
	torn := tw.read(t, "log") + "torn"
	tw.write(t, "log", torn)
	if err := os.Link(tw.paths.log, tw.paths.log+setAsideSuffix); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.repair(osWitnessIO()); err == nil || !strings.Contains(err.Error(), "names (hard links)") {
		t.Fatalf("repair: %v", err)
	}
	if tw.read(t, "log") != torn {
		t.Fatal("the log was written or cut")
	}
}

// Two processes never both write one witness's files, whatever names they
// reach them by: a second process given the same names, hard-linked names,
// or the files through linked directories, is refused while the first
// holds them, and signs nothing.
func TestWitnessTwoProcessesNeverBothWrite(t *testing.T) {
	if os.Getenv("WITNESS_SECOND_PROCESS") == "1" {
		tw := &testWitness{paths: witnessPaths{log: os.Getenv("WITNESS_LOG"), marks: os.Getenv("WITNESS_MARKS")}, signer: newWitnessSigner(t), now: new(time.Time), trace: newWitnessTrace()}
		*tw.now = testClock
		w, err := openWitnessLog(tw.config())
		if err != nil {
			fmt.Println("REFUSED:", err)
			return
		}
		defer w.close()
		answer, err := w.submit(witnessIssuer, subjectOf(testTrail), [][]byte{cpLine(testTrail, 2, "a")})
		fmt.Println("OPENED:", answer.kind, err)
		return
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		name  string
		paths func(*testing.T, witnessPaths) witnessPaths
		why   string
	}{
		{"the same names", func(_ *testing.T, p witnessPaths) witnessPaths { return p }, "held by another witness"},
		{"hard-linked names", linkWitness, "names (hard links)"},
		{"linked directories", linkWitnessDirectories, "held by another witness"},
	} {
		t.Run(c.name, func(t *testing.T) {
			tw := newTestWitness(t, testTrail)
			w := tw.open(t)
			defer w.close()
			p := c.paths(t, tw.paths)
			second := exec.Command(executable, "-test.run", "^TestWitnessTwoProcessesNeverBothWrite$", "-test.count=1")
			second.Env = append(os.Environ(), "WITNESS_SECOND_PROCESS=1", "WITNESS_LOG="+p.log, "WITNESS_MARKS="+p.marks)
			out, err := second.CombinedOutput()
			if err != nil {
				t.Fatalf("the second process: %v: %.400s", err, out)
			}
			if !strings.Contains(string(out), "REFUSED:") || !strings.Contains(string(out), c.why) {
				t.Fatalf("the second process was not refused for %q: %.400s", c.why, out)
			}
			if st, _ := parseWitnessStatement(mustSign(t, w, testTrail, 1)); st.index != 0 {
				t.Fatalf("the first process signed at index %d", st.index)
			}
		})
	}
}

// The paths a witness is given are checked before anything is opened: each
// absolute and clean, and the marks neither the log nor a file kept beside
// it.
func TestWitnessPathsAreChecked(t *testing.T) {
	dir := tempDirAt(t, 0o700)
	log := filepath.Join(dir, "witness.log")
	for _, p := range []witnessPaths{
		{log: "witness.log", marks: filepath.Join(dir, "m")},
		{log: log, marks: dir + "/../m"},
		{log: log, marks: log},
		{log: log, marks: log + registrationsSuffix},
		{log: log, marks: log + setAsideSuffix},
	} {
		if _, err := holdWitnessFiles(p, osWitnessIO()); err == nil {
			t.Errorf("%v was taken", p)
		} else if errors.Is(err, os.ErrNotExist) {
			t.Errorf("%v: refused only for a file that is not there", p)
		}
	}
}

// A lock that cannot be taken for any reason but another witness holding
// it -- here no lock to be had, as flock(2) answers when the system has
// none left -- refuses the start as surely as a held one: there is no
// fallback to going on unlocked.
func TestWitnessRefusesWhenNoLockCanBeTaken(t *testing.T) {
	tw := newTestWitness(t, testTrail)
	tw.open(t).close()
	cfg := tw.config()
	x := osWitnessIO()
	x.lock = func(_ string, f *os.File) error {
		return lockWitnessFile(f, func(int, int) error { return syscall.ENOLCK })
	}
	cfg.io = tw.io(x)
	if w, err := openWitnessLog(cfg); err == nil {
		w.close()
		t.Fatal("a witness started without its locks")
	} else if !strings.Contains(err.Error(), "could not be locked") {
		t.Fatalf("refused, but not for the lock: %v", err)
	}
	if _, err := repairWitnessLog(cfg); err == nil {
		t.Fatal("a repair without its locks")
	}
}
