//go:build unix

package main

import (
	"context"
	"os"
	"strings"
	"sync"
	"syscall"
	"testing"
)

// One connect at a time holds the file: a second one, while the first is
// still running its checks, refuses rather than waits.
func TestOneConnectAtATimeHoldsTheFile(t *testing.T) {
	f := newConnectFixture(t, restrictedBinding, ``)
	inChecks := make(chan struct{})
	release := make(chan struct{})
	first := make(chan error, 1)
	var once sync.Once
	go func() {
		_, err := connect(context.Background(), f.request(), f.host, func(ctx context.Context, spec sourceSpec) ([]byte, error) {
			once.Do(func() { close(inChecks) })
			<-release
			return f.check(ctx, spec)
		})
		first <- err
	}()
	<-inChecks
	second := f.request()
	second.platform = "replica"
	second.user = "engine-docs"
	_, err := connect(context.Background(), second, f.host, f.check)
	if err == nil || !strings.Contains(err.Error(), "another connect holds engine.json.lock") {
		t.Fatalf("the second connect is refused while the first holds the file: %v", err)
	}
	close(release)
	if err := <-first; err != nil {
		t.Fatalf("the first connect completes: %v", err)
	}
	if _, err := os.Stat(f.config + ".lock"); err != nil {
		t.Fatalf("the lock file stays beside the configuration: %v", err)
	}
}

// The replaced file keeps its mode whatever the umask narrows creation to.
func TestReplaceKeepsTheFilesModeUnderAUmask(t *testing.T) {
	f := newConnectFixture(t, restrictedBinding, ``)
	old := syscall.Umask(0o077)
	defer syscall.Umask(old)
	if _, err := connect(context.Background(), f.request(), f.host, f.check); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(f.config)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o640 {
		t.Fatalf("mode %v, want 0640 as it was", info.Mode().Perm())
	}
}
