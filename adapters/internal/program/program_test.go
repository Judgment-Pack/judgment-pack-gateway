package program

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// The lifecycle of a run -- when a program has finished, when it is ended,
// how long its stdout is waited for, what a deadline makes of what it wrote
// -- is held by the document adapter's tests, which run the OCR program
// through this package (adapters/document/ocr_test.go, adapter_test.go).
// What is held here is what those do not need: that a run is given the
// arguments and the stdin it names, under the name it was configured by, and
// that a name is resolved on the PATH.

// asProgram is set in the environment of a run whose program is this test's
// own executable, and says what the executable is to do in place of running
// the tests.
const asProgram = "PROGRAM_TEST_AS_PROGRAM"

// TestMain lets the test's executable stand for a program that says what it
// was started as, which a shell script cannot: a script is told its own path.
func TestMain(m *testing.M) {
	if os.Getenv(asProgram) == "argv0" {
		io.WriteString(os.Stdout, os.Args[0])
		os.Exit(0)
	}
	os.Exit(m.Run())
}

// script writes a shell program, or skips the test where the shell or a
// utility the programs of these tests use is not there.
func script(t *testing.T, name, body string) string {
	t.Helper()
	if _, err := os.Stat("/bin/sh"); err != nil {
		t.Skip("no /bin/sh")
	}
	for _, utility := range []string{"cat", "sleep", "touch"} {
		if _, err := exec.LookPath(utility); err != nil {
			t.Skipf("no %s", utility)
		}
	}
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte("#!/bin/sh\n"+body), 0o755); err != nil {
		t.Fatal(err)
	}
	return path
}

func digestOf(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func TestARunIsGivenWhatItNames(t *testing.T) {
	path := script(t, "program", `printf '%s|' "$#" "$@"; cat`)
	out, digest, err := Run{Program: path, Args: []string{"--to", "pdf", "a b"}, Stdin: []byte("the stdin\n"), MaxOutput: 1 << 10}.Do(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if got, want := string(out), "3|--to|pdf|a b|the stdin\n"; got != want {
		t.Errorf("the program wrote %q, want %q", got, want)
	}
	if digest != digestOf(t, path) {
		t.Errorf("the digest is %s, and the file's is %s", digest, digestOf(t, path))
	}
	// A run that names no arguments and no stdin gives none.
	out, _, err = Run{Program: path, MaxOutput: 1 << 10}.Do(context.Background())
	if err != nil || string(out) != "0|" {
		t.Errorf("the program wrote %q: %v", out, err)
	}
}

// A name with no separator is looked for on the PATH, and the digest is of
// the file it resolved to.
func TestANameIsResolvedOnThePath(t *testing.T) {
	path := script(t, "render-program", `printf 'ran'`)
	t.Setenv("PATH", filepath.Dir(path)+string(os.PathListSeparator)+os.Getenv("PATH"))
	out, digest, err := Run{Program: "render-program", MaxOutput: 1 << 10}.Do(context.Background())
	if err != nil || string(out) != "ran" || digest != digestOf(t, path) {
		t.Fatalf("the program wrote %q with digest %s: %v", out, digest, err)
	}
	if _, digest, err := (Run{Program: "no-such-program", MaxOutput: 1 << 10}).Do(context.Background()); err == nil || digest != "" || err.Error() != "could not be resolved on the adapter's PATH" {
		t.Fatalf("a name that resolves to nothing: %q %v", digest, err)
	}
}

// A program is started under the name it was configured by, not under the
// path the name resolved to. The program here is this test's own executable,
// under another name in a directory on the PATH, since a native program is
// told what it was started as and a script is not.
func TestAProgramIsStartedUnderItsConfiguredName(t *testing.T) {
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	// A name is resolved on Windows by the endings a program may have, so
	// the name there has one.
	name := "configured-name"
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	dir := t.TempDir()
	if err := os.Symlink(self, filepath.Join(dir, name)); err != nil {
		t.Skipf("no symbolic link: %v", err)
	}
	t.Setenv("PATH", dir)
	t.Setenv(asProgram, "argv0")
	out, _, err := Run{Program: name, MaxOutput: 1 << 10}.Do(context.Background())
	if err != nil || string(out) != name {
		t.Fatalf("the program was started as %q: %v", out, err)
	}
}

// The bound on what a program may write is met at the byte: what is as long
// as the bound is taken, and a byte more is not.
func TestTheBoundOnOutputIsMetAtTheByte(t *testing.T) {
	path := script(t, "program", `printf '0123456789'`)
	if out, _, err := (Run{Program: path, MaxOutput: 10}).Do(context.Background()); err != nil || string(out) != "0123456789" {
		t.Fatalf("ten bytes within a bound of ten: %q %v", out, err)
	}
	if out, _, err := (Run{Program: path, MaxOutput: 9}).Do(context.Background()); err == nil || out != nil || err.Error() != "wrote past the output bound of 9 bytes" {
		t.Fatalf("ten bytes within a bound of nine: %q %v", out, err)
	}
	silent := script(t, "silent", `exit 0`)
	if out, _, err := (Run{Program: silent, MaxOutput: 0}).Do(context.Background()); err != nil || len(out) != 0 {
		t.Fatalf("nothing within a bound of nothing: %q %v", out, err)
	}
}

// The reader a run names is the one that reads its stdout, and what it
// fails with is the run's failure.
func TestARunReadsWithTheReaderItNames(t *testing.T) {
	path := script(t, "program", `printf 'answer'`)
	read := func(r io.Reader, limit int64) ([]byte, error) {
		if limit != 11 {
			t.Errorf("the reader is given the limit %d, want one past the bound of 10", limit)
		}
		io.Copy(io.Discard, r)
		return nil, errors.New("the pipe")
	}
	out, _, err := Run{Program: path, MaxOutput: 10, Read: read}.Do(context.Background())
	if err == nil || out != nil || err.Error() != "wrote a stdout that could not be read" {
		t.Fatalf("a read that failed: %q %v", out, err)
	}
}

// The outcomes a caller tells apart by identity are these two, and each is
// what a deadline makes of a run: one not started, one not finished. The
// second is ended only once the program is known to have started, so that a
// machine under load does not make of it a run that was not started.
func TestTheDeadlinesOutcomes(t *testing.T) {
	// The program marks that it started and becomes a sleep of a day, so
	// that the process the run started is the one that sleeps, and nothing
	// but the run's ending it brings the run back.
	started := filepath.Join(t.TempDir(), "started")
	path := script(t, "program", `touch '`+started+`'; exec sleep 86400`)
	passed, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancel()
	if out, digest, err := (Run{Program: path, MaxOutput: 10}).Do(passed); !errors.Is(err, ErrNotStarted) || out != nil || digest != digestOf(t, path) {
		t.Fatalf("a deadline passed before the start: %q %s %v", out, digest, err)
	}
	if _, err := os.Stat(started); err == nil {
		t.Fatal("the program was started after the deadline had passed")
	}
	running, end := context.WithCancel(context.Background())
	defer end()
	go func() {
		for {
			if _, err := os.Stat(started); err == nil {
				end()
				return
			}
			select {
			case <-running.Done():
				return
			case <-time.After(5 * time.Millisecond):
			}
		}
	}()
	// That the run comes back at all is what shows the program was ended:
	// no time is asked of it here, and a run that does not come back is for
	// the time the tests are given to find.
	if out, _, err := (Run{Program: path, MaxOutput: 10}).Do(running); !errors.Is(err, ErrTimeout) || out != nil {
		t.Fatalf("a program still running when its run was ended: %q %v", out, err)
	}
	if !strings.Contains(ErrTimeout.Error(), "deadline") || !strings.Contains(ErrNotStarted.Error(), "deadline") {
		t.Fatal("the outcomes do not say they are the deadline's")
	}
}
