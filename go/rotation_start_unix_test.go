//go:build unix

package main

// A gateway's start beside a rotation, through the two serve commands'
// entry points, run in this process (SPEC.md §3b,
// "Rotating"): a gateway refuses to start beside a rotation under way, found
// before it makes anything or found again under its registry lock; while it
// runs it holds the lock, so rotate-key and --resume are refused; and it lets
// the lock go when it stops.

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// startedGateway is a serve command run in this process: it refused to
// start, and exited with code, or it serves until stop.
type startedGateway struct {
	t      *testing.T
	done   chan int
	stderr func() string
	exited bool
	code   int
}

// serveInProcess runs `gateway serve` with args in this process and returns
// once it has exited or is serving: its address on stderr, which it writes
// once it holds its registry and listens, its signals bound.
func serveInProcess(t *testing.T, args []string) *startedGateway {
	t.Helper()
	g := &startedGateway{t: t, done: make(chan int, 1), stderr: captureStderr(t)}
	go func() { g.done <- cmdServe(args) }()
	t.Cleanup(func() { g.stop() })
	deadline := time.Now().Add(30 * time.Second)
	for {
		select {
		case g.code = <-g.done:
			g.exited = true
			return g
		default:
		}
		if strings.Contains(g.stderr(), "gateway on http://") {
			return g
		}
		if time.Now().After(deadline) {
			t.Fatalf("the gateway neither started nor exited: %s", g.stderr())
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// stop stops a gateway that serves as its operator stops it, with SIGTERM,
// and gives its exit code.
func (g *startedGateway) stop() int {
	if g.exited {
		return g.code
	}
	if err := syscall.Kill(os.Getpid(), syscall.SIGTERM); err != nil {
		g.t.Fatal(err)
	}
	select {
	case g.code = <-g.done:
	case <-time.After(30 * time.Second):
		g.t.Fatal("the gateway did not stop on SIGTERM")
	}
	g.exited = true
	return g.code
}

// rotateKeyCommand runs `gateway rotate-key` with args, and gives its exit
// code and what it wrote.
func rotateKeyCommand(args ...string) (int, string, string) {
	var stdout, stderr bytes.Buffer
	code := cmdRotateKey(args, &stdout, &stderr)
	return code, stdout.String(), stderr.String()
}

// gatewayFiles is where a gateway under test keeps its seed, under the test
// key, its registry, there and empty, and its store, not made yet.
type gatewayFiles struct{ seed, registry, store string }

// serveCommands are the two serve commands, each with the command line of a
// gateway that starts from files laid out for it.
var serveCommands = []struct {
	name  string
	start func(t *testing.T) ([]string, gatewayFiles)
}{
	{"serve", servedFiles},
	{"serve --config", engineFiles},
	{"serve --config, its seed a link", linkedEngineFiles},
}

func gatewayFilesIn(t *testing.T, dir string) gatewayFiles {
	t.Helper()
	f := gatewayFiles{seed: filepath.Join(dir, "gateway.seed"), registry: filepath.Join(dir, "registry.jsonl"), store: filepath.Join(dir, "store")}
	writeTestSeed(t, f.seed, testSeed)
	if err := os.WriteFile(f.registry, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	return f
}

// servedFiles is `gateway serve` from the command line, on a free port.
func servedFiles(t *testing.T) ([]string, gatewayFiles) {
	t.Helper()
	f := gatewayFilesIn(t, t.TempDir())
	return []string{f.store, f.seed, "gateway:test", f.registry, "--port", freePort(t)}, f
}

// engineFiles is `gateway serve --config` with an engine that is a witness
// and nothing else, which starts without switching users: its marks on
// /dev/shm, a device apart from its log's, as the engine requires, and the
// test skipped where there is none.
func engineFiles(t *testing.T) ([]string, gatewayFiles) {
	t.Helper()
	args, f, _ := engineFilesWith(t, false)
	return args, f
}

// linkedEngineFiles is engineFiles with the seed configured as a link, the
// signer's own, to the seed in a directory of its own: the configured name
// is the one gateway rotate-key --seed is given.
func linkedEngineFiles(t *testing.T) ([]string, gatewayFiles) {
	t.Helper()
	args, f, _ := engineFilesWith(t, true)
	return args, f
}

// engineFilesWith is engineFiles, the seed configured as a link when
// linked, and the name the seed resolves to.
func engineFilesWith(t *testing.T, linked bool) ([]string, gatewayFiles, string) {
	t.Helper()
	if os.Geteuid() == 0 {
		t.Skip("a root signer is refused first")
	}
	shm, err := os.MkdirTemp("/dev/shm", "rotation-marks-")
	if err != nil {
		t.Skipf("no /dev/shm to keep a witness's marks apart on: %v", err)
	}
	t.Cleanup(func() { os.RemoveAll(shm) })
	if err := os.Chmod(shm, 0o700); err != nil {
		t.Fatal(err)
	}
	dir := tempDirAt(t, 0o700)
	var a, b syscall.Stat_t
	if syscall.Stat(shm, &a) != nil || syscall.Stat(dir, &b) != nil || a.Dev == b.Dev {
		t.Skip("/dev/shm is on the temporary directory's device here")
	}
	f := gatewayFilesIn(t, dir)
	resolved := f.seed
	if linked {
		keys := filepath.Join(dir, "keys")
		if err := os.Mkdir(keys, 0o700); err != nil {
			t.Fatal(err)
		}
		resolved = filepath.Join(keys, "gateway.seed")
		if err := os.Rename(f.seed, resolved); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(resolved, f.seed); err != nil {
			t.Fatal(err)
		}
		var err error
		if resolved, err = filepath.EvalSymlinks(f.seed); err != nil {
			t.Fatal(err)
		}
	}
	for _, sub := range []string{"log", "decisions", "catalog"} {
		if err := os.Mkdir(filepath.Join(dir, sub), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	issuer, _ := edIssuer(t)
	keys := filepath.Join(dir, "keys.json")
	if err := os.WriteFile(keys, []byte(`{"keys":[{"kty":"OKP","kid":"ed-1","crv":"Ed25519","x":"`+b64(issuer.edPub)+`"}]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	config := `{"engineVersion":"6","authority":"gateway:rotation","seed":"` + f.seed + `","store":"` + f.store + `",` +
		`"registry":"` + f.registry + `","decisionRecords":"` + filepath.Join(dir, "decisions") + `","listen":"127.0.0.1:0",` +
		`"catalog":"` + filepath.Join(dir, "catalog") + `","identity":{"issuer":"` + witnessIssuer + `","audience":"gateway:rotation","keys":"` + keys + `"},` +
		`"witness":{"log":"` + filepath.Join(dir, "log", "witness.log") + `","marks":"` + filepath.Join(shm, "witness.marks") + `","audience":"witness:rotation"},"platforms":{}}`
	path := filepath.Join(dir, "engine.json")
	if err := os.WriteFile(path, []byte(config), 0o600); err != nil {
		t.Fatal(err)
	}
	return []string{"--config", path}, f, resolved
}

// A gateway does not start beside a rotation under way, a kept record or a
// next seed: either serve command refuses, naming rotate-key --resume, before
// it makes its store, and the registry is unchanged.
func TestServeRefusesToStartBesideAPendingRotation(t *testing.T) {
	for _, command := range serveCommands {
		for _, pending := range []string{".rotation", ".next"} {
			t.Run(command.name+" beside "+pending, func(t *testing.T) {
				args, f := command.start(t)
				if err := os.WriteFile(f.seed+pending, []byte("left by a rotation that stopped\n"), 0o600); err != nil {
					t.Fatal(err)
				}
				g := serveInProcess(t, args)
				if !g.exited {
					g.stop()
					t.Fatal("the gateway started beside a pending rotation")
				}
				out := g.stderr()
				if g.code != 1 || !strings.Contains(out, pending+" is there") || !strings.Contains(out, "rotate-key --resume") {
					t.Fatalf("exit %d: %s", g.code, out)
				}
				if _, err := os.Lstat(f.store); !errors.Is(err, os.ErrNotExist) {
					t.Fatal("the store was made beside a pending rotation")
				}
				requireUnchanged(t, f.registry, "")
			})
		}
	}
}

// A rotation begun while a gateway starts, after its first look for one and
// before it holds its registry, is found again under the lock: here a
// rotate-key whose append tears inside its key-rotation runs where the start
// makes its store, leaving a registry that holds no rotation statement and a
// rotation pending beside the seed. Either serve command refuses to start,
// naming rotate-key --resume, and lets the lock go, so --resume then
// finishes the rotation.
func TestServeLooksAgainUnderTheLockForARotationBegunAsItStarts(t *testing.T) {
	for _, command := range serveCommands {
		t.Run(command.name, func(t *testing.T) {
			args, f := command.start(t)
			tornLog(t, 200, false)
			began := false
			startHook = func() {
				_, err := rotateKey(f.seed, f.registry, fixedStamp("2026-10-25T00:00:00Z"), rand.Reader)
				began = errors.Is(err, errRotationPending)
			}
			t.Cleanup(func() { startHook = func() {} })
			g := serveInProcess(t, args)
			if !g.exited {
				g.stop()
				t.Fatal("the gateway started beside a rotation begun as it started")
			}
			if !began {
				t.Fatalf("no rotation was begun as the gateway started: %s", g.stderr())
			}
			out := g.stderr()
			if g.code != 1 || !strings.Contains(out, "a rotation is pending") || !strings.Contains(out, "rotate-key --resume") {
				t.Fatalf("exit %d: %s", g.code, out)
			}
			openRotationLog = func(path string) (*fsLog, error) { return openFsLog(path) }
			code, stdout, stderr := rotateKeyCommand("--resume", "--seed", f.seed, "--registry", f.registry)
			if code != 0 || !strings.HasPrefix(stdout, "rotation 1: ") {
				t.Fatalf("--resume after the refused start: %d %s %s", code, stdout, stderr)
			}
			if err := rotationPendingBeside(f.seed, f.registry); err != nil {
				t.Fatal(err)
			}
		})
	}
}

// While a gateway runs it holds its registry: rotate-key is refused, and so
// is --resume of a rotation laid beside its seed, the registry and the seed
// unchanged. Stopped, the gateway has let the lock go, and --resume finishes
// the rotation.
func TestServeHoldsTheRegistryWhileItRuns(t *testing.T) {
	for _, command := range serveCommands {
		t.Run(command.name, func(t *testing.T) {
			args, f := command.start(t)
			// a rotation of the same key over the same registry, made apart
			// and torn, its next seed and kept record laid beside the seed
			// once the gateway runs
			apart := gatewayFilesIn(t, t.TempDir())
			tornLog(t, 200, false)
			if _, err := rotateKey(apart.seed, apart.registry, fixedStamp("2026-10-25T00:00:00Z"), rand.Reader); !errors.Is(err, errRotationPending) {
				t.Fatal(err)
			}
			openRotationLog = func(path string) (*fsLog, error) { return openFsLog(path) }
			next, err := loadSeed(apart.seed + ".next")
			if err != nil {
				t.Fatal(err)
			}

			g := serveInProcess(t, args)
			if g.exited {
				t.Fatalf("the gateway did not start: exit %d: %s", g.code, g.stderr())
			}
			code, _, stderr := rotateKeyCommand("--seed", f.seed, "--registry", f.registry)
			if code != 1 || !strings.Contains(stderr, "held by a running gateway") {
				t.Fatalf("rotate-key while the gateway runs: %d %s", code, stderr)
			}
			for _, left := range []string{f.seed + ".next", f.seed + ".rotation"} {
				if _, err := os.Lstat(left); !errors.Is(err, os.ErrNotExist) {
					t.Fatalf("%s made while the gateway runs", left)
				}
			}
			for _, suffix := range []string{".next", ".rotation"} {
				data, err := os.ReadFile(apart.seed + suffix)
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(f.seed+suffix, data, 0o600); err != nil {
					t.Fatal(err)
				}
			}
			laid := resumeFiles(t, f.seed, f.registry)
			code, _, stderr = rotateKeyCommand("--resume", "--seed", f.seed, "--registry", f.registry)
			if code != 1 || !strings.Contains(stderr, "held by a running gateway") {
				t.Fatalf("--resume while the gateway runs: %d %s", code, stderr)
			}
			requireResumeChangedNothing(t, f.seed, f.registry, 1, laid)
			requireUnchanged(t, f.registry, "")

			if code := g.stop(); code != 0 {
				t.Fatalf("the gateway stopped with exit %d: %s", code, g.stderr())
			}
			code, stdout, stderr := rotateKeyCommand("--resume", "--seed", f.seed, "--registry", f.registry)
			if code != 0 || !strings.HasPrefix(stdout, "rotation 1: ") {
				t.Fatalf("--resume once the gateway stopped: %d %s %s", code, stdout, stderr)
			}
			k0, k1 := ed25519.NewKeyFromSeed(testSeed), ed25519.NewKeyFromSeed(next)
			requireUnchanged(t, f.registry, rotationLines(k0, k1, 1, "2026-10-25T00:00:00Z"))
		})
	}
}

// An engine whose seed is configured as a link looks for a rotation under way
// beside both of the seed's names, the one configured, which gateway
// rotate-key --seed is given, and the one the link resolves to: found beside
// either before the start, it refuses before it makes its store; found beside
// either as it starts, after its first look, it refuses under the lock.
func TestServeConfigLooksBesideBothNamesOfALinkedSeed(t *testing.T) {
	for _, when := range []string{"before the start", "as it starts"} {
		for _, name := range []string{"the configured name", "the resolved name"} {
			t.Run(when+", beside "+name, func(t *testing.T) {
				args, f, resolved := engineFilesWith(t, true)
				beside := f.seed
				if name == "the resolved name" {
					beside = resolved
				}
				plant := func() {
					if err := os.WriteFile(beside+".rotation", []byte("left by a rotation that stopped\n"), 0o600); err != nil {
						t.Error(err)
					}
				}
				if when == "before the start" {
					plant()
				} else {
					startHook = plant
					t.Cleanup(func() { startHook = func() {} })
				}
				g := serveInProcess(t, args)
				if !g.exited {
					g.stop()
					t.Fatalf("the engine started beside a rotation pending beside %s", name)
				}
				out := g.stderr()
				if g.code != 1 || !strings.Contains(out, beside+".rotation is there") || !strings.Contains(out, "rotate-key --resume") {
					t.Fatalf("exit %d: %s", g.code, out)
				}
				_, err := os.Lstat(f.store)
				if made := err == nil; made != (when == "as it starts") {
					t.Fatalf("the store made: %v, %s", made, when)
				}
				if lock, err := lockRegistry(f.registry); err != nil {
					t.Fatalf("the lock was kept: %v", err)
				} else {
					lock.Close()
				}
			})
		}
	}
}
