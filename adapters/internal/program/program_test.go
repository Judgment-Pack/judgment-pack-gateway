package program

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
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

func script(t *testing.T, name, body string) string {
	t.Helper()
	if _, err := os.Stat("/bin/sh"); err != nil {
		t.Skip("no /bin/sh")
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

// A name with no separator is looked for on the PATH, and the program is
// started under the name it was configured by.
func TestANameIsResolvedOnThePath(t *testing.T) {
	path := script(t, "render-program", `printf '%s' "${0##*/}"`)
	t.Setenv("PATH", filepath.Dir(path))
	out, digest, err := Run{Program: "render-program", MaxOutput: 1 << 10}.Do(context.Background())
	if err != nil || string(out) != "render-program" || digest != digestOf(t, path) {
		t.Fatalf("the program wrote %q with digest %s: %v", out, digest, err)
	}
	if _, digest, err := (Run{Program: "no-such-program", MaxOutput: 1 << 10}).Do(context.Background()); err == nil || digest != "" || err.Error() != "could not be resolved on the adapter's PATH" {
		t.Fatalf("a name that resolves to nothing: %q %v", digest, err)
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
// what a deadline makes of a run: one not started, one not finished.
func TestTheDeadlinesOutcomes(t *testing.T) {
	path := script(t, "program", `sleep 5`)
	passed, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancel()
	if out, digest, err := (Run{Program: path, MaxOutput: 10}).Do(passed); !errors.Is(err, ErrNotStarted) || out != nil || digest != digestOf(t, path) {
		t.Fatalf("a deadline passed before the start: %q %s %v", out, digest, err)
	}
	soon, cancelSoon := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancelSoon()
	started := time.Now()
	if out, _, err := (Run{Program: path, MaxOutput: 10}).Do(soon); !errors.Is(err, ErrTimeout) || out != nil {
		t.Fatalf("a program still running at the deadline: %q %v", out, err)
	}
	if elapsed := time.Since(started); elapsed > PipeWait+2*time.Second {
		t.Fatalf("the run took %v", elapsed)
	}
	if !strings.Contains(ErrTimeout.Error(), "deadline") || !strings.Contains(ErrNotStarted.Error(), "deadline") {
		t.Fatal("the outcomes do not say they are the deadline's")
	}
}
