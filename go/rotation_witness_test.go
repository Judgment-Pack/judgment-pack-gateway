//go:build unix

package main

// The witness across a rotation of its gateway's key (SPEC.md §3b, §8.5): its
// chains go on under the key rotated to, its checks hold its log to the keys
// the walk reached in the order it reached them, and `gateway witness verify
// --registry` follows the rotations from the key given and refuses a walk that
// does not hold.

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// rotatedConfig is the test witness's configuration under the key rotated
// to, its log held to the key rotated from before it.
func rotatedConfig(tw *testWitness, next ed25519.PrivateKey) witnessConfig {
	cfg := tw.config()
	public, sign := witnessSeedSigner(next.Seed())
	cfg.publicKey, cfg.sign = public, sign
	cfg.earlier = []reachedKey{{key: tw.signer.public, keyID: keyIDFor(tw.signer.public)}}
	return cfg
}

func TestTheWitnessGoesOnAcrossARotation(t *testing.T) {
	tw := newTestWitness(t, testTrail)
	w := tw.open(t)
	first := mustSign(t, w, testTrail, 1)
	w.close()

	next := rotationKey("witness next")
	// Under the key rotated to alone, the statement the key rotated from
	// signed is no statement of this witness's, and it does not start.
	alone := rotatedConfig(tw, next)
	alone.earlier = nil
	if _, err := openWitnessLog(alone); err == nil {
		t.Fatal("a witness started under the key rotated to alone, over a log the key rotated from signed")
	}

	w, err := openWitnessLog(rotatedConfig(tw, next))
	if err != nil {
		t.Fatalf("the witness did not start across the rotation: %v", err)
	}
	*tw.now = tw.now.Add(time.Minute)
	second := mustSign(t, w, testTrail, 2)
	w.close()
	st, ok := parseWitnessStatement(second)
	if !ok || st.index != 1 || st.keyID != keyIDFor(publicOf(next)) {
		t.Fatalf("the statement after the rotation: %s", second)
	}
	before, _ := parseWitnessStatement(first)
	if st.prev != before.signature {
		t.Fatal("the chain does not go on across the rotation: the next statement names another previous signature")
	}
	// A reader supplied both keys reads one chain across the hop.
	reading := readWitness(witnessReading{trail: testTrail, keys: [][]byte{tw.signer.public, publicOf(next)}, files: [][]byte{file(string(first), string(second))}, head: append(append([]byte(nil), second...), '\n')})
	if len(reading.findings) > 0 || reading.refused != "" {
		t.Fatalf("a reader with both keys: %+v", reading)
	}

	// Held to the keys in the other order, the statement under the key
	// reached first sits below one under a key reached after it, and the
	// checks find it.
	files, err := holdWitnessFiles(tw.paths, osWitnessIO())
	if err != nil {
		t.Fatal(err)
	}
	defer files.close()
	j, err := files.judgeUnder([]reachedKey{{key: publicOf(next), keyID: keyIDFor(publicOf(next))}, {key: tw.signer.public, keyID: keyIDFor(tw.signer.public)}})
	if err != nil {
		t.Fatal(err)
	}
	if j.outcome == outcomeStart || !contains(j.findings.names(), findingWitnessSignatureInvalid) {
		t.Fatalf("a statement under a key reached before the key above it: %s %v", j.outcome, j.findings.names())
	}
}

func TestWitnessVerifyFollowsTheRegistry(t *testing.T) {
	tw := newTestWitness(t, testTrail)
	w := tw.open(t)
	mustSign(t, w, testTrail, 1)
	w.close()
	next := rotationKey("witness next")
	w, err := openWitnessLog(rotatedConfig(tw, next))
	if err != nil {
		t.Fatal(err)
	}
	mustSign(t, w, testTrail, 2)
	w.close()

	dir := t.TempDir()
	keyFile := filepath.Join(dir, "witness.key")
	if err := os.WriteFile(keyFile, []byte(hex.EncodeToString(tw.signer.public)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	k0 := tw.signer.private
	at := "2026-10-25T00:00:00Z"
	write := func(name, text string) string {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte(text), 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}

	// Without the registry, the statement under the key rotated to is under
	// no key given.
	out, err := witnessVerify(tw.paths.log, keyFile, tw.paths.marks)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(out, []byte(findingWitnessSignatureInvalid)) {
		t.Fatalf("without the registry: %s", out)
	}
	followed := write("followed", rotationLines(k0, next, 1, at))
	out, err = witnessVerifyFrom(tw.paths.log, keyFile, tw.paths.marks, followed)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(out, []byte(`{"ok":true,"findings":[],"outcome":"start","statements":2}`)) {
		t.Fatalf("with the rotation followed: %s", out)
	}
	for name, registry := range map[string]string{
		statusRotationBreak:  forwardLine(k0, 1, at, publicOf(next)) + "\n",
		statusRotationForged: reverseLine(next, 1, at, tw.signer.public) + "\n",
	} {
		out, err := witnessVerifyFrom(tw.paths.log, keyFile, tw.paths.marks, write(name, registry))
		if err != nil {
			t.Fatal(err)
		}
		if string(out) != `{"refused":"`+name+`"}` {
			t.Fatalf("a walk that is %s: %s", name, out)
		}
	}
	if _, err := witnessVerifyFrom(tw.paths.log, keyFile, tw.paths.marks, filepath.Join(dir, "absent")); err == nil || !strings.Contains(err.Error(), "not there") {
		t.Fatalf("a registry that is not there: %v", err)
	}
}

// An engine's witness is opened under the keys its gateway's own reading of
// the registry reached, and not at all under the key a rotation went from.
func TestTheEngineWitnessTakesItsKeysFromTheRegistry(t *testing.T) {
	tw := newTestWitness(t, testTrail)
	next := rotationKey("witness next")
	registry := filepath.Join(t.TempDir(), "registry.jsonl")
	spec := &witnessSpec{paths: tw.paths}
	cfg, err := witnessConfigOf(spec, tw.signer.seed, registry)
	if err != nil || len(cfg.earlier) != 0 {
		t.Fatalf("a registry not there yet: %v %d", err, len(cfg.earlier))
	}
	if err := os.WriteFile(registry, []byte(rotationLines(tw.signer.private, next, 1, "2026-10-25T00:00:00Z")), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err = witnessConfigOf(spec, next.Seed(), registry)
	if err != nil || len(cfg.earlier) != 1 || !bytes.Equal(cfg.earlier[0].key, tw.signer.public) {
		t.Fatalf("after a rotation: %v %+v", err, cfg.earlier)
	}
	if _, err := witnessConfigOf(spec, tw.signer.seed, registry); err == nil || !strings.Contains(err.Error(), "pending") {
		t.Fatalf("under the key rotated from: %v", err)
	}
}
