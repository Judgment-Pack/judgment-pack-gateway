//go:build !unix

package main

import (
	"errors"
	"path/filepath"
	"testing"
)

// Elsewhere than Unix no witness file is opened, made or written: the
// witness, its repair and an offline registration are each refused before
// anything is touched, with no fallback.
func TestWitnessKeepsNoFilesOffUnix(t *testing.T) {
	dir := t.TempDir()
	paths := witnessPaths{log: filepath.Join(dir, "witness.log"), marks: filepath.Join(dir, "witness.marks")}
	if _, err := openWitnessLog(witnessConfig{paths: paths}); !errors.Is(err, errWitnessFilesNotKept) {
		t.Errorf("open: %v", err)
	}
	if _, err := repairWitnessLog(witnessConfig{paths: paths}); !errors.Is(err, errWitnessFilesNotKept) {
		t.Errorf("repair: %v", err)
	}
	if err := registerWitnessTrail(paths, witnessRegistration{trail: "7d1f3b5a9c2e4f6a8b0d2c4e6f8a1b3c", issuer: "i", subject: "s"}, witnessIO{}); !errors.Is(err, errWitnessFilesNotKept) {
		t.Errorf("register: %v", err)
	}
}
