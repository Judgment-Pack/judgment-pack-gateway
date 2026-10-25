//go:build unix

package main

// The registry lock a running gateway holds (SPEC.md §3b, "Rotating"):
// rotate-key and --resume refuse while it is held, and a second holder is
// refused.

import (
	"crypto/rand"
	"errors"
	"os"
	"testing"
)

func TestRotateKeyRefusesWhileAGatewayHoldsTheRegistry(t *testing.T) {
	seedPath, registry, _, before := rotationFixture(t, false)
	hold, err := holdEngineRegistry(registry, testSeed)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := holdEngineRegistry(registry, testSeed); !errors.Is(err, errRegistryHeld) {
		t.Fatalf("a second gateway on a held registry: %v", err)
	}
	if _, err := rotateKey(seedPath, registry, fixedStamp("2026-10-25T00:00:00Z"), rand.Reader); !errors.Is(err, errRegistryHeld) {
		t.Fatalf("rotate-key while a gateway holds the registry: %v", err)
	}
	requireUnchanged(t, registry, string(before))
	for _, left := range []string{seedPath + ".next", seedPath + ".rotation"} {
		if _, err := os.Lstat(left); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("%s made while the registry was held", left)
		}
	}
	hold.Close()
	if _, err := rotateKey(seedPath, registry, fixedStamp("2026-10-25T00:00:00Z"), rand.Reader); err != nil {
		t.Fatalf("rotate-key once the gateway let go: %v", err)
	}
	if _, err := holdEngineRegistry(registry, testSeed); err == nil {
		t.Fatal("a gateway under the key it rotated from held the registry")
	}
}

func TestResumeRefusesWhileAGatewayHoldsTheRegistry(t *testing.T) {
	seedPath, registry, _, _ := rotationFixture(t, false)
	tornLog(t, 200, false)
	if _, err := rotateKey(seedPath, registry, fixedStamp("2026-10-25T00:00:00Z"), rand.Reader); !errors.Is(err, errRotationPending) {
		t.Fatal(err)
	}
	openRotationLog = func(path string) (*fsLog, error) { return openFsLog(path) }
	lock, err := lockRegistry(registry)
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Close()
	if _, err := resumeRotation(seedPath, registry, nil, nil); !errors.Is(err, errRegistryHeld) {
		t.Fatalf("--resume while the registry is held: %v", err)
	}
}
