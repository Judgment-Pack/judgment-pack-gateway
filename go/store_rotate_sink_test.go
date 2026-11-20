package main

// gateway store rotate and the receipt sink (ADR-0049; #541, #558): a
// rotation shuts the old store for good, so what it holds for the sink is
// delivered before, or the rotation is refused with nothing rotated.

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// unrotated holds that a refused rotation rotated nothing: no new store
// directory or registry, no mark beside the old registry, the old registry
// the same bytes, and the old store's files the same ones.
func unrotated(t *testing.T, g *gatewayService, dir string, registry string, tree map[string]string) {
	t.Helper()
	for _, made := range []string{filepath.Join(dir, "store"), filepath.Join(dir, "registry.jsonl")} {
		if _, err := os.Lstat(made); !errors.Is(err, fs.ErrNotExist) {
			t.Fatalf("a refused rotation made %s: %v", made, err)
		}
	}
	if _, err := os.Lstat(rotatedMarkPath(g.regPath)); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("a refused rotation marked the old store: %v", err)
	}
	if readFile(t, g.regPath) != registry {
		t.Fatal("a refused rotation changed the old registry")
	}
	if after := storeTree(t, g.storeRoot); !maps.Equal(after, tree) {
		t.Fatalf("a refused rotation changed the old store: %d files, was %d", len(after), len(tree))
	}
}

// rotateArgs runs gateway store rotate with args and the new store and
// registry in dir.
func rotateArgs(dir string, args ...string) (int, string, string) {
	var stdout, stderr bytes.Buffer
	args = append(args, "--new-store", filepath.Join(dir, "store"), "--new-registry", filepath.Join(dir, "registry.jsonl"))
	code := cmdStoreRotateAt(args, &stdout, &stderr, fixedStamp("2026-11-20T00:00:01Z"))
	return code, stdout.String(), stderr.String()
}

// A store by its flags names no receipt sink: rotated without --no-sink it
// is refused by a fixed sentence, as seal-open refuses it, and nothing is
// rotated. --no-sink beside --config, which names the sink or none, is a
// usage error.
func TestStoreRotateByItsFlagsNeedsNoSink(t *testing.T) {
	g := leftOpenStore(t)
	seedPath := writeSeedFile(t, t.TempDir(), testSeed)
	dir := t.TempDir()
	registry, tree := readFile(t, g.regPath), storeTree(t, g.storeRoot)
	code, stdout, stderr := rotateArgs(dir, "--store", g.storeRoot, "--seed", seedPath, "--registry", g.regPath, "--authority", "gateway:test")
	if code != 1 || stdout != "" || stderr != "store rotate: "+storeRotateNeedsSink+"\n" {
		t.Fatalf("a store by its flags without --no-sink: %d %q %q", code, stdout, stderr)
	}
	unrotated(t, g, dir, registry, tree)

	code, stdout, stderr = rotateArgs(dir, "--config", filepath.Join(dir, "engine.json"), "--no-sink")
	if code != 2 || stdout != "" || !strings.HasPrefix(stderr, "store rotate: --config names the receipt sink, or none; --no-sink is not given beside it\n") {
		t.Fatalf("--no-sink beside --config: %d %q %q", code, stdout, stderr)
	}
	unrotated(t, g, dir, registry, tree)
}

// sealHeldStore is a store whose gateway forwarded seals: session sl-p
// sealed by /seal and its seal held, marked pending forwarding, and sl-q
// left open, its receipt acknowledged. It answers the sink, the service and
// a configuration of the store naming the sink with receiptSink.seals as
// seals says.
func sealHeldStore(t *testing.T) (*standInSink, *gatewayService, func(seals bool) string) {
	t.Helper()
	sink, service, server, sinkURL := sealSinkService(t)
	acquireOK(t, server, "sl-p", "p0")
	acquireOK(t, server, "sl-q", "q0")
	sink.setAnswer(refuseAcknowledgments)
	code, body := post(t, server, "/seal", `{"session":"sl-p"}`)
	refusedSealUnforwarded(t, "the seal held", code, body)
	server.Close()
	if pending := markedPending(t, fsSealForwarding{service.storeRoot}); len(pending) != 1 || pending[0] != "sl-p" {
		t.Fatalf("sl-p's seal alone is not marked: %v", pending)
	}
	configDir := t.TempDir()
	seedPath := writeSeedFile(t, configDir, testSeed)
	config := func(seals bool) string {
		path := filepath.Join(configDir, fmt.Sprintf("engine-%t.json", seals))
		text := fmt.Sprintf(`{"engineVersion":%q,"authority":"gateway:test","seed":%q,"store":%q,"registry":%q,"decisionRecords":%q,"listen":"127.0.0.1:8787","catalog":%q,"receiptSink":{"url":%q,"seals":%t},"platforms":{}}`,
			sealSinkVersion, seedPath, service.storeRoot, service.regPath, filepath.Join(configDir, "decisions"), filepath.Join(configDir, "catalog"), sinkURL, seals)
		if err := os.WriteFile(path, []byte(text), 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	return sink, service, config
}

// A seal held for the sink, pending forwarding, refuses a rotation that
// would not deliver it -- by the store's flags under --no-sink, or by a
// configuration whose sink takes no seals -- before anything is sealed: the
// session left open stays open, the marker stays, and nothing is rotated.
// --config with seals forwarded delivers the held seal first: while the
// sink does not acknowledge it the rotation is refused, the sentence true
// of a seal held, and nothing is sealed; once it does, the rotation seals
// what is open, delivers that seal too, and rotates, no marker left.
func TestStoreRotateRefusesASealHeldForTheSink(t *testing.T) {
	sink, g, config := sealHeldStore(t)
	seedPath := writeSeedFile(t, t.TempDir(), testSeed)
	dir := t.TempDir()
	registry, tree := readFile(t, g.regPath), storeTree(t, g.storeRoot)
	held := storeRotateSealsHeld([]string{"sl-p"}).Error()

	code, stdout, stderr := rotateArgs(dir, "--store", g.storeRoot, "--seed", seedPath, "--registry", g.regPath, "--authority", "gateway:test", "--no-sink")
	if code != 1 || stdout != "" || stderr != storeRotateNoSinkSaid+"store rotate: "+held+"\n" {
		t.Fatalf("a held seal under --no-sink: %d %q %q", code, stdout, stderr)
	}
	unrotated(t, g, dir, registry, tree)

	code, stdout, stderr = rotateArgs(dir, "--config", config(false))
	if code != 1 || stdout != "" || stderr != "store rotate: "+held+"\n" {
		t.Fatalf("a held seal past a sink that takes no seals: %d %q %q", code, stdout, stderr)
	}
	unrotated(t, g, dir, registry, tree)

	before, _ := sink.snapshot()
	code, stdout, stderr = rotateArgs(dir, "--config", config(true))
	if code != 1 || stdout != "" || stderr != "store rotate: "+fmt.Sprintf(storeRotateNotSealed, sealHeldRefusal("sl-p"))+"\n" {
		t.Fatalf("a held seal the sink does not acknowledge: %d %q %q", code, stdout, stderr)
	}
	// the held seal is delivered, each attempt of it, and no other
	seals, _ := sealsSince(t, sink, len(before))
	if len(seals) == 0 {
		t.Fatal("the held seal was not delivered")
	}
	for _, digest := range seals {
		if digest != registrySealDigest(t, registry, "sl-p") {
			t.Fatalf("a seal other than the held one was delivered: %v", seals)
		}
	}
	unrotated(t, g, dir, registry, tree)

	sink.setAnswer(nil)
	before, _ = sink.snapshot()
	code, stdout, stderr = rotateArgs(dir, "--config", config(true))
	if code != 0 || !strings.Contains(stdout, `"sessionId":"sl-q"`) || strings.TrimPrefix(stderr, sealOpenUnlocked()) != "" {
		t.Fatalf("the rotation with the sink acknowledging: %d %q %q", code, stdout, stderr)
	}
	sealed := readFile(t, g.regPath)
	if seals, _ := sealsSince(t, sink, len(before)); len(seals) != 2 || seals[0] != registrySealDigest(t, sealed, "sl-p") || seals[1] != registrySealDigest(t, sealed, "sl-q") {
		t.Fatalf("the seals delivered: %v", seals)
	}
	if pending := markedPending(t, fsSealForwarding{g.storeRoot}); len(pending) != 0 {
		t.Fatalf("a rotated store holds seals pending forwarding: %v", pending)
	}
	if _, err := os.Stat(rotatedMarkPath(g.regPath)); err != nil {
		t.Fatalf("the old store is not marked rotated: %v", err)
	}
}

// A rerun of a rotation stopped before its mark seals nothing, so delivers
// nothing: a seal held then -- one a marker names -- refuses it whatever the
// configuration's sink, and the old store is not marked.
func TestStoreRotateRerunRefusesASealHeldForTheSink(t *testing.T) {
	g := leftOpenStore(t)
	seedPath := writeSeedFile(t, t.TempDir(), testSeed)
	dir := t.TempDir()
	if code, stdout, stderr := rotateOn(t, g, seedPath, filepath.Join(dir, "store"), filepath.Join(dir, "registry.jsonl"), "2026-11-20T00:00:01Z"); code != 0 {
		t.Fatalf("the rotation: %d %q %q", code, stdout, stderr)
	}
	if err := os.Remove(rotatedMarkPath(g.regPath)); err != nil {
		t.Fatal(err)
	}
	if err := (fsSealForwarding{g.storeRoot}).mark("closed"); err != nil {
		t.Fatal(err)
	}
	code, _, stderr := rotateOn(t, g, seedPath, filepath.Join(dir, "store"), filepath.Join(dir, "registry.jsonl"), "2026-11-20T00:00:02Z")
	if code != 1 || stderr != storeRotateNoSinkSaid+"store rotate: "+storeRotateSealsHeld([]string{"closed"}).Error()+"\n" {
		t.Fatalf("a rerun past a held seal: %d %q", code, stderr)
	}
	if _, err := os.Lstat(rotatedMarkPath(g.regPath)); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("a refused rerun marked the old store: %v", err)
	}
}
