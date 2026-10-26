//go:build unix

package main

import (
	"bytes"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"testing"
)

// The seed line, flipped one fact at a time: the seed serve accepts is
// enforced, and a seed readable by group or other, owned by another user,
// not a regular file or not there is not.
func TestPostureSeedFlips(t *testing.T) {
	dir := t.TempDir()
	seed := filepath.Join(dir, "gateway.seed")
	if err := os.WriteFile(seed, []byte(strings.Repeat("ab", 32)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	euid := os.Geteuid()
	judge := func(path string, owner int) postureLine { return judgeSeed(path, os.Stat, owner, false) }
	if line := judge(seed, euid); line.name != protectionSeedFile || line.state != postureEnforced {
		t.Fatalf("a 0600 seed of the signer's own: %+v", line)
	}
	if line := seedPosture(postureInput{configured: true, seed: seed}); line.state != postureEnforced {
		t.Fatalf("the seed line as the report makes it: %+v", line)
	}
	for _, mode := range []os.FileMode{0o644, 0o640, 0o604, 0o620} {
		if err := os.Chmod(seed, mode); err != nil {
			t.Fatal(err)
		}
		if line := judge(seed, euid); line.state != postureNotEnforced || !strings.Contains(line.reason, "readable by group or other") {
			t.Fatalf("mode %04o: %+v", mode, line)
		}
	}
	if err := os.Chmod(seed, 0o400); err != nil {
		t.Fatal(err)
	}
	if line := judge(seed, euid); line.state != postureEnforced {
		t.Fatalf("a 0400 seed is stricter than 0600: %+v", line)
	}
	if line := judge(seed, euid+1); line.state != postureNotEnforced || !strings.Contains(line.reason, "not owned by the gateway's own user") {
		t.Fatalf("a seed another user owns: %+v", line)
	}
	if line := judge(dir, euid); line.state != postureNotEnforced || !strings.Contains(line.reason, "regular file") {
		t.Fatalf("a directory at the seed's path: %+v", line)
	}
	fifo := filepath.Join(dir, "fifo.seed")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}
	if line := judge(fifo, euid); line.state != postureNotEnforced || !strings.Contains(line.reason, "regular file") {
		t.Fatalf("a FIFO at the seed's path is judged without blocking: %+v", line)
	}
	if line := judge(filepath.Join(dir, "absent.seed"), euid); line.state != postureNotEnforced || !strings.Contains(line.reason, "could not be examined") {
		t.Fatalf("no seed at the path: %+v", line)
	}
}

// The seed line reads the seed as serve does: through a link, as openSeed
// opens it, and refusing what openSeed refuses -- a seed a link names, a
// mounted secret say, is judged as the file it names.
func TestPostureSeedParityWithOpenSeed(t *testing.T) {
	dir := t.TempDir()
	write := func(name string, mode os.FileMode) string {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte(strings.Repeat("ab", 32)+"\n"), mode); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(path, mode); err != nil {
			t.Fatal(err)
		}
		return path
	}
	link := func(name, target string) string {
		path := filepath.Join(dir, name)
		if err := os.Symlink(target, path); err != nil {
			t.Fatal(err)
		}
		return path
	}
	good := write("good.seed", 0o600)
	loose := write("loose.seed", 0o644)
	fifo := filepath.Join(dir, "fifo.seed")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}
	cases := map[string]string{
		"good":            good,
		"loose":           loose,
		"link to good":    link("to-good.seed", good),
		"link to loose":   link("to-loose.seed", loose),
		"fifo":            fifo,
		"directory":       dir,
		"dangling link":   link("dangling.seed", filepath.Join(dir, "absent.seed")),
		"link to a link":  link("to-to-good.seed", filepath.Join(dir, "to-good.seed")),
		"link to the dir": link("to-dir.seed", dir),
	}
	for name, path := range cases {
		_, openErr := openSeed(path)
		line := seedPosture(postureInput{configured: true, seed: path})
		if (openErr == nil) != (line.state == postureEnforced) {
			t.Fatalf("%s: openSeed says %v, the seed line %+v", name, openErr, line)
		}
	}
	for _, name := range []string{"link to good", "link to a link"} {
		if line := seedPosture(postureInput{configured: true, seed: cases[name]}); line.state != postureEnforced {
			t.Fatalf("%s: %+v", name, line)
		}
	}
}

// The command judges the seed its command line names -- the second
// argument, as serve takes it -- and not another of them: here the seed is
// one serve accepts and the store is not there at all.
func TestPostureCommandJudgesTheSeedArgument(t *testing.T) {
	dir := t.TempDir()
	seed := filepath.Join(dir, "gateway.seed")
	if err := os.WriteFile(seed, []byte(strings.Repeat("ab", 32)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	args := []string{filepath.Join(dir, "store"), seed, "gateway:test", filepath.Join(dir, "registry.jsonl")}
	for _, typed := range [][]string{args, append([]string{"serve"}, args...)} {
		var stdout, stderr bytes.Buffer
		if code := cmdPosture(typed, &stdout, &stderr); code != 0 {
			t.Fatalf("%q: %d %s", typed, code, stderr.String())
		}
		if !strings.Contains(stdout.String(), "\n"+protectionSeedFile+" ") || !regexp.MustCompile(`(?m)^`+protectionSeedFile+` +enforced `).MatchString(stdout.String()) {
			t.Fatalf("%q: the seed serve would load is judged:\n%s", typed, stdout.String())
		}
	}
}
