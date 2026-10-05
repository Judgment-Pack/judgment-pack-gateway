//go:build unix

package main

// The witness's files are held, not followed: each is opened through its
// held directory as the entry it is, judged by its descriptor, private to
// the signer, and locked against a second writer (witness_log.go).

import (
	"errors"
	"os"
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
			if _, err := repairWitnessLog(tw.config(), osWitnessIO()); err == nil {
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
			if err == nil {
				t.Fatal("a FIFO was taken for the log")
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
// or an offline registration while the first holds them is refused; and two
// of the files that are one file under two names are refused.
func TestWitnessOneWriterHoldsTheFiles(t *testing.T) {
	tw := newTestWitness(t, testTrail)
	w := tw.open(t)
	if _, err := openWitnessLog(tw.config()); err == nil || !strings.Contains(err.Error(), "another witness holds") {
		t.Fatalf("a second open: %v", err)
	}
	if _, err := repairWitnessLog(tw.config(), osWitnessIO()); err == nil {
		t.Fatal("a repair while the witness runs")
	}
	if err := registerWitnessTrail(tw.paths, witnessRegistration{trail: trailB, issuer: witnessIssuer, subject: "b"}, osWitnessIO()); err == nil {
		t.Fatal("an offline registration while the witness runs")
	}
	w.close()
	tw.open(t).close()

	if err := os.Remove(tw.paths.log + registrationsSuffix); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(tw.paths.log, tw.paths.log+registrationsSuffix); err != nil {
		t.Fatal(err)
	}
	if _, err := openWitnessLog(tw.config()); err == nil || !strings.Contains(err.Error(), "one file under two names") {
		t.Fatalf("the registrations a link to the log: %v", err)
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
		{log: log + ".lock", marks: log},
	} {
		if _, err := holdWitnessFiles(p); err == nil {
			t.Errorf("%v was taken", p)
		} else if errors.Is(err, os.ErrNotExist) {
			t.Errorf("%v: refused only for a file that is not there", p)
		}
	}
}
