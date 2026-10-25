package main

// Key rotation (SPEC.md §3b): the walk of a registry's rotations from the key
// pinned, each finding it names, the gateway's own reading, and
// `gateway rotate-key`, a gateway going on under the next key.

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// rotationKey is a key made from a seed named by a word, for these tests.
func rotationKey(word string) ed25519.PrivateKey {
	seed := sha256.Sum256([]byte("rotation test key " + word))
	return ed25519.NewKeyFromSeed(seed[:])
}

func publicOf(k ed25519.PrivateKey) ed25519.PublicKey { return k.Public().(ed25519.PublicKey) }

// rotationLineBy is a rotation statement written by hand from SPEC.md §3b's
// signed bytes, not by the code under test: the members in code-point order,
// then the signature, which sorts after them. keyID is the signer's as
// stated; named is next for a key-rotation, previous for a key-continuation.
func rotationLineBy(signer ed25519.PrivateKey, keyID, kind string, ordinal int, at string, named []byte) string {
	var body string
	if kind == rotationKindForward {
		body = fmt.Sprintf(`{"keyId":"%s","kind":"key-rotation","next":"%x","nextKeyId":"%s","rotatedAt":"%s","rotation":%d,"rotationVersion":"1"}`, keyID, named, keyIDFor(named), at, ordinal)
	} else {
		body = fmt.Sprintf(`{"keyId":"%s","kind":"key-continuation","previous":"%x","previousKeyId":"%s","rotatedAt":"%s","rotation":%d,"rotationVersion":"1"}`, keyID, named, keyIDFor(named), at, ordinal)
	}
	signature := ed25519.Sign(signer, []byte("judgment-pack-gateway/rotation/1:"+body))
	return body[:len(body)-1] + fmt.Sprintf(`,"signature":"%x"}`, signature)
}

func forwardLine(from ed25519.PrivateKey, ordinal int, at string, to ed25519.PublicKey) string {
	return rotationLineBy(from, keyIDFor(publicOf(from)), rotationKindForward, ordinal, at, to)
}

func reverseLine(to ed25519.PrivateKey, ordinal int, at string, from ed25519.PublicKey) string {
	return rotationLineBy(to, keyIDFor(publicOf(to)), rotationKindReverse, ordinal, at, from)
}

// rotationLines is a whole rotation, its two lines.
func rotationLines(from, to ed25519.PrivateKey, ordinal int, at string) string {
	return forwardLine(from, ordinal, at, publicOf(to)) + "\n" + reverseLine(to, ordinal, at, publicOf(from)) + "\n"
}

// The signed bytes are SPEC.md §3b's, exactly: the code under test signs and
// verifies what the hand-written template states.
func TestTheRotationStatementSignsTheBytesTheSpecificationStates(t *testing.T) {
	k0, k1 := rotationKey("zero"), rotationKey("one")
	for _, line := range []string{forwardLine(k0, 1, "2026-10-25T00:00:00Z", publicOf(k1)), reverseLine(k1, 1, "2026-10-25T00:00:00Z", publicOf(k0))} {
		kind, obj := rotationKindOf(line)
		st, ok := rotationStatementOf(kind, obj)
		if !ok {
			t.Fatalf("a statement of the form is not one: %s", line)
		}
		if string(canon(obj)) != line {
			t.Fatalf("the hand-written line is not canonical:\n%s\n%s", line, canon(obj))
		}
		built := rotationStatementObject(kind, 1, "2026-10-25T00:00:00Z", st.keyID, st.named)
		if !bytes.Equal(rotationSigningInput(built), st.signingInput()) {
			t.Fatalf("the writer signs other bytes than the reader verifies:\n%s\n%s", rotationSigningInput(built), st.signingInput())
		}
	}
}

func TestTheRegistryWalk(t *testing.T) {
	k0, k1, k2, other := rotationKey("zero"), rotationKey("one"), rotationKey("two"), rotationKey("other")
	at, at2 := "2026-10-25T00:00:00Z", "2026-10-26T00:00:00Z"
	rot01, rot12 := rotationLines(k0, k1, 1, at), rotationLines(k1, k2, 2, at2)
	tamper := func(line, from, to string) string {
		if !strings.Contains(line, from) {
			t.Fatalf("%q is not in %s", from, line)
		}
		return strings.Replace(line, from, to, 1)
	}
	nonCanonical := mustHex(t, "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f")
	notOnCurve := mustHex(t, "0200000000000000000000000000000000000000000000000000000000000000")
	cases := []struct {
		name     string
		registry string
		status   string
		rotation int64
		keys     int    // keys reached, the pinned one included
		sealed   string // sessions whose seal loads, in order
	}{
		{"no rotation", sealLine(t, k0, "a", 1), "", 0, 1, "a"},
		{"two rotations, each seal under the key current at its line", sealLine(t, k0, "a", 1) + rot01 + sealLine(t, k1, "b", 1) + rot12 + sealLine(t, k2, "c", 1), "", 0, 3, "a b c"},
		{"a seal under a key rotated from, after the rotation", rot01 + sealLine(t, k0, "a", 1), "", 0, 2, ""},
		{"a seal under the next key, before the rotation", sealLine(t, k1, "a", 1) + rot01, "", 0, 2, ""},
		{"line endings converted to CRLF", strings.ReplaceAll(rot01+sealLine(t, k1, "b", 1), "\n", "\r\n"), "", 0, 2, "b"},
		{"a continuation alone", reverseLine(k1, 1, at, publicOf(k0)) + "\n" + sealLine(t, k1, "b", 1), statusRotationForged, 1, 1, ""},
		{"a rotation the key rotated from signs after it was rotated from", rot01 + forwardLine(k0, 2, at2, publicOf(k2)) + "\n" + reverseLine(k2, 2, at2, publicOf(k1)) + "\n", statusRotationForged, 2, 2, ""},
		{"a rotation naming the current key and signed by another", rotationLineBy(other, keyIDFor(publicOf(k0)), rotationKindForward, 1, at, publicOf(k1)) + "\n" + reverseLine(k1, 1, at, publicOf(k0)) + "\n", statusRotationForged, 1, 1, ""},
		{"a member beside the statement's", tamper(forwardLine(k0, 1, at, publicOf(k1)), `{"keyId"`, `{"extra":1,"keyId"`) + "\n", statusRotationBreak, 1, 1, ""},
		{"a nextKeyId not the next key's", tamper(forwardLine(k0, 1, at, publicOf(k1)), keyIDFor(publicOf(k1)), keyIDFor(publicOf(k2))) + "\n", statusRotationBreak, 1, 1, ""},
		{"a rotatedAt not of its form", rotationLines(k0, k1, 1, "2026-10-25 00:00:00Z"), statusRotationBreak, 1, 1, ""},
		{"an ordinal skipped", rotationLines(k0, k1, 2, at), statusRotationOrder, 1, 1, ""},
		{"an ordinal given again", rot01 + rotationLines(k1, k2, 1, at2), statusRotationOrder, 2, 2, ""},
		{"a rotation back to the key pinned", rot01 + rotationLines(k1, k0, 2, at2), statusRotationKeyRefused, 2, 2, ""},
		{"a rotation to a key not canonical", forwardLine(k0, 1, at, nonCanonical) + "\n", statusRotationKeyRefused, 1, 1, ""},
		{"a rotation to no point", forwardLine(k0, 1, at, notOnCurve) + "\n", statusRotationKeyRefused, 1, 1, ""},
		{"no continuation, the registry's end", forwardLine(k0, 1, at, publicOf(k1)) + "\n", statusRotationBreak, 1, 1, ""},
		{"no continuation, a seal after it", forwardLine(k0, 1, at, publicOf(k1)) + "\n" + sealLine(t, k0, "a", 1), statusRotationBreak, 1, 1, "a"},
		{"a blank line between the two", forwardLine(k0, 1, at, publicOf(k1)) + "\n\n" + reverseLine(k1, 1, at, publicOf(k0)) + "\n", statusRotationBreak, 1, 1, ""},
		{"a continuation at another time", forwardLine(k0, 1, at, publicOf(k1)) + "\n" + reverseLine(k1, 1, at2, publicOf(k0)) + "\n", statusRotationBreak, 1, 1, ""},
		{"a continuation of another ordinal", forwardLine(k0, 1, at, publicOf(k1)) + "\n" + reverseLine(k1, 2, at, publicOf(k0)) + "\n", statusRotationBreak, 1, 1, ""},
		{"a continuation naming another key it continues", forwardLine(k0, 1, at, publicOf(k1)) + "\n" + reverseLine(k1, 1, at, publicOf(other)) + "\n", statusRotationBreak, 1, 1, ""},
		{"a continuation another key signed", forwardLine(k0, 1, at, publicOf(k1)) + "\n" + reverseLine(other, 1, at, publicOf(k0)) + "\n", statusRotationBreak, 1, 1, ""},
		{"a continuation naming the next key and signed by another", forwardLine(k0, 1, at, publicOf(k1)) + "\n" + rotationLineBy(other, keyIDFor(publicOf(k1)), rotationKindReverse, 1, at, publicOf(k0)) + "\n", statusRotationBreak, 1, 1, ""},
		{"past a finding, nothing followed and seals under the last key reached", rot01 + rotationLines(k1, k2, 3, at2) + rot12 + sealLine(t, k1, "b", 1) + sealLine(t, k2, "c", 1), statusRotationOrder, 2, 2, "b"},
		{"a line the parser refuses is no statement", strings.Replace(forwardLine(k0, 1, at, publicOf(k1)), `"rotation":1`, `"rotation":1.0`, 1) + "\n" + sealLine(t, k0, "a", 1), "", 0, 1, "a"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			w := walkRegistry([]byte(c.registry), publicOf(k0))
			status, rotation := "", int64(0)
			if w.finding != nil {
				status, rotation = w.finding["status"].(string), w.finding["rotation"].(int64)
			}
			if status != c.status || rotation != c.rotation {
				t.Fatalf("finding %q at rotation %d, want %q at %d", status, rotation, c.status, c.rotation)
			}
			if len(w.keys) != c.keys {
				t.Fatalf("%d keys reached, want %d", len(w.keys), c.keys)
			}
			if got := strings.Join(w.order, " "); got != c.sealed {
				t.Fatalf("seals loaded for %q, want %q", got, c.sealed)
			}
		})
	}
}

// The gateway reads its own registry from the key its first rotation rotated
// from, and only a walk that holds and ends at its own key is one it takes.
func TestTheGatewaysOwnReading(t *testing.T) {
	k0, k1, k2 := rotationKey("zero"), rotationKey("one"), rotationKey("two")
	at := "2026-10-25T00:00:00Z"
	registry := []byte(sealLine(t, k0, "a", 1) + rotationLines(k0, k1, 1, at) + sealLine(t, k1, "b", 1))
	w, err := engineWalk(registry, publicOf(k1))
	if err != nil {
		t.Fatal(err)
	}
	if len(w.seals) != 2 {
		t.Fatalf("the gateway's own reading loads %d seals, want both", len(w.seals))
	}
	if _, err := engineWalk(registry, publicOf(k0)); err == nil || !strings.Contains(err.Error(), "pending") {
		t.Fatalf("the key rotated from read its registry: %v", err)
	}
	if _, err := engineWalk(registry, publicOf(k2)); err == nil {
		t.Fatal("a key the registry never names read it")
	}
	broken := append(append([]byte(nil), registry...), forwardLine(k1, 2, at, publicOf(k2))+"\n"...)
	if _, err := engineWalk(broken, publicOf(k1)); err == nil || !strings.Contains(err.Error(), statusRotationBreak) {
		t.Fatalf("a walk that does not hold: %v", err)
	}
	if _, err := engineWalk(nil, publicOf(k0)); err != nil {
		t.Fatalf("an empty registry: %v", err)
	}
}

// writeTestSeed writes a seed as keygen does, and returns its private key.
func writeTestSeed(t *testing.T, path string, seed []byte) ed25519.PrivateKey {
	t.Helper()
	if err := seedSecret(path).putSecret("seed", []byte(hex.EncodeToString(seed)+"\n")); err != nil {
		t.Fatal(err)
	}
	return ed25519.NewKeyFromSeed(seed)
}

func fixedStamp(at string) func() string { return func() string { return at } }

func mustAcquire(t *testing.T, g *gatewayService, session string) {
	t.Helper()
	if _, err := g.acquire(session, "screening", vString(session), nil); err != nil {
		t.Fatalf("acquire %s: %v", session, err)
	}
}

func mustSeal(t *testing.T, g *gatewayService, session string) {
	t.Helper()
	if _, err := g.sealSession(session); err != nil {
		t.Fatalf("seal %s: %v", session, err)
	}
}

// A gateway rotated by `gateway rotate-key` goes on under the next key: a
// session sealed before stays sealed, a session after it is minted and
// sealed under the next key, and a verifier holding only the first key
// verifies the whole store, the rotation named in its report. The gateway
// does not start again under the key it rotated from. (A session this
// reference holds never outlives its process, so none of its sessions runs
// across a rotation; the corpus holds one that does.)
func TestRotateKeyThenTheGatewayGoesOnUnderTheNextKey(t *testing.T) {
	t.Setenv(envSourceHelper, "1")
	root := t.TempDir()
	seedPath, registry, store := filepath.Join(root, "gateway.seed"), filepath.Join(root, "registry.jsonl"), filepath.Join(root, "store")
	sources := map[string]sourceSpec{"screening": {argv: []string{os.Args[0]}, env: helperEnv}}
	k0 := writeTestSeed(t, seedPath, testSeed)
	first, err := newGatewayService(store, testSeed, "gateway:test", registry, sources)
	if err != nil {
		t.Fatal(err)
	}
	mustAcquire(t, first, "before")
	mustSeal(t, first, "before")

	r, err := rotateKey(seedPath, registry, fixedStamp("2026-10-25T00:00:00Z"), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if r.ordinal != 1 || !bytes.Equal(r.from, publicOf(k0)) || r.kept != seedPath+".rotated-1" {
		t.Fatalf("the rotation: %+v", r)
	}
	if kept, err := loadSeed(r.kept); err != nil || !bytes.Equal(kept, testSeed) {
		t.Fatalf("the seed rotated from is not kept where the rotation says: %v", err)
	}
	if _, err := os.Lstat(seedPath + ".next"); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("the next seed is still beside the seed: %v", err)
	}
	next, err := loadSeed(seedPath)
	if err != nil {
		t.Fatal(err)
	}
	k1 := ed25519.NewKeyFromSeed(next)
	if !bytes.Equal(publicOf(k1), r.to) {
		t.Fatal("the seed switched to is not the key the rotation names")
	}
	// The registry's two new lines are the hand-written statements, byte for
	// byte: the next seed's signature is deterministic, as the first's is.
	data, err := os.ReadFile(registry)
	if err != nil {
		t.Fatal(err)
	}
	if want := rotationLines(k0, k1, 1, "2026-10-25T00:00:00Z"); !strings.HasSuffix(string(data), want) {
		t.Fatalf("the registry ends:\n%s\nwant:\n%s", data, want)
	}

	if _, err := newGatewayService(store, testSeed, "gateway:test", registry, sources); err == nil || !strings.Contains(err.Error(), "pending") {
		t.Fatalf("the gateway started again under the key it rotated from: %v", err)
	}
	second, err := newGatewayService(store, next, "gateway:test", registry, sources)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := second.acquire("before", "screening", vString("again"), nil); err == nil || !strings.Contains(err.Error(), "sealed") {
		t.Fatalf("an acquisition into a session sealed under the key rotated from: %v", err)
	}
	if _, err := second.registry.seal("before", 1, nowStamp()); err == nil || !strings.Contains(err.Error(), "already sealed") {
		t.Fatalf("a session sealed under the key rotated from was sealed again: %v", err)
	}
	mustAcquire(t, second, "after")
	mustSeal(t, second, "after")

	rep, err := verifyWithRegistry(store, registry, "gateway:test", publicOf(k0))
	if err != nil {
		t.Fatal(err)
	}
	if !rep.OK || rep.Rotations == nil || rep.Rotations.Count != 1 || rep.Rotations.KeyID != keyIDFor(publicOf(k1)) {
		t.Fatalf("verified from the first key: ok=%v rotations=%+v findings=%v", rep.OK, rep.Rotations, rep.Findings)
	}
	after, err := os.ReadFile(filepath.Join(store, "receipts", "after", "0.json"))
	if err != nil || !strings.Contains(string(after), `"keyId":"`+keyIDFor(publicOf(k1))+`"`) {
		t.Fatalf("the receipt after the rotation is not under the next key: %s %v", after, err)
	}
	engine, err := second.verify()
	if err != nil {
		t.Fatal(err)
	}
	if engine["ok"] != true || engine["rotations"] == nil {
		t.Fatalf("/verify: %v", engine)
	}
	// Pinned to the next key alone, the store does not verify: what the key
	// rotated from signed is reached from it by nothing.
	if rep, err := verifyWithRegistry(store, registry, "gateway:test", publicOf(k1)); err != nil || rep.OK {
		t.Fatalf("verified from the next key alone: %v %v", rep, err)
	}

	// A second rotation, from the key the first rotated to.
	r2, err := rotateKey(seedPath, registry, fixedStamp("2026-10-26T00:00:00Z"), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if r2.ordinal != 2 || r2.kept != seedPath+".rotated-2" {
		t.Fatalf("the second rotation: %+v", r2)
	}
	if rep, err := verifyWithRegistry(store, registry, "gateway:test", publicOf(k0)); err != nil || !rep.OK || rep.Rotations.Count != 2 {
		t.Fatalf("verified from the first key after two rotations: %+v %v", rep, err)
	}
}

// rotate-key refuses, before anything is written, a seed that cannot sign, a
// rotation pending, a registry that is not there and a registry whose walk
// does not end at the seed's key.
func TestRotateKeyRefuses(t *testing.T) {
	stamp := fixedStamp("2026-10-25T00:00:00Z")
	t.Run("no seed", func(t *testing.T) {
		root := t.TempDir()
		registry := filepath.Join(root, "registry.jsonl")
		if err := os.WriteFile(registry, nil, 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := rotateKey(filepath.Join(root, "gateway.seed"), registry, stamp, rand.Reader); err == nil || !strings.Contains(err.Error(), "cannot sign") {
			t.Fatalf("no seed: %v", err)
		}
		requireUnchanged(t, registry, "")
	})
	t.Run("a next seed made already", func(t *testing.T) {
		root := t.TempDir()
		seedPath, registry := filepath.Join(root, "gateway.seed"), filepath.Join(root, "registry.jsonl")
		writeTestSeed(t, seedPath, testSeed)
		writeTestSeed(t, seedPath+".next", bytes.Repeat([]byte{7}, 32))
		if err := os.WriteFile(registry, nil, 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := rotateKey(seedPath, registry, stamp, rand.Reader); !errors.Is(err, errRotationPending) {
			t.Fatalf("a next seed made already: %v", err)
		}
		requireUnchanged(t, registry, "")
	})
	t.Run("no registry", func(t *testing.T) {
		root := t.TempDir()
		seedPath := filepath.Join(root, "gateway.seed")
		writeTestSeed(t, seedPath, testSeed)
		if _, err := rotateKey(seedPath, filepath.Join(root, "registry.jsonl"), stamp, rand.Reader); err == nil || !strings.Contains(err.Error(), "not there") {
			t.Fatalf("no registry: %v", err)
		}
		if _, err := os.Lstat(seedPath + ".next"); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("a refused rotation made a next seed")
		}
	})
	t.Run("a rotation written and not switched to", func(t *testing.T) {
		root := t.TempDir()
		seedPath, registry := filepath.Join(root, "gateway.seed"), filepath.Join(root, "registry.jsonl")
		k0 := writeTestSeed(t, seedPath, testSeed)
		pending := rotationLines(k0, rotationKey("one"), 1, "2026-10-25T00:00:00Z")
		if err := os.WriteFile(registry, []byte(pending), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := rotateKey(seedPath, registry, stamp, rand.Reader); err == nil || !strings.Contains(err.Error(), "pending") {
			t.Fatalf("a rotation pending: %v", err)
		}
		requireUnchanged(t, registry, pending)
		if _, err := os.Lstat(seedPath + ".next"); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("a refused rotation made a next seed")
		}
	})
	t.Run("an unterminated last line is ended first", func(t *testing.T) {
		root := t.TempDir()
		seedPath, registry := filepath.Join(root, "gateway.seed"), filepath.Join(root, "registry.jsonl")
		k0 := writeTestSeed(t, seedPath, testSeed)
		torn := strings.TrimSuffix(sealLine(t, k0, "a", 1), "\n")
		if err := os.WriteFile(registry, []byte(torn), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := rotateKey(seedPath, registry, stamp, rand.Reader); err != nil {
			t.Fatal(err)
		}
		data, _ := os.ReadFile(registry)
		w := walkRegistry(data, publicOf(k0))
		if w.finding != nil || w.followed() != 1 || len(w.seals) != 1 {
			t.Fatalf("after a rotation appended to an unterminated line: %v %d %d", w.finding, w.followed(), len(w.seals))
		}
	})
}

func requireUnchanged(t *testing.T, path, want string) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != want {
		t.Fatalf("%s changed: %q", path, data)
	}
}

// The command line: its flags, and its report.
func TestRotateKeyCommandLine(t *testing.T) {
	root := t.TempDir()
	seedPath, registry := filepath.Join(root, "gateway.seed"), filepath.Join(root, "registry.jsonl")
	writeTestSeed(t, seedPath, testSeed)
	if err := os.WriteFile(registry, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{nil, {"--seed", seedPath}, {"--seed", seedPath, "--registry"}, {"--seed", seedPath, "--seed", seedPath, "--registry", registry}, {"--key", seedPath, "--registry", registry}} {
		var stdout, stderr bytes.Buffer
		if code := cmdRotateKey(args, &stdout, &stderr); code != 2 {
			t.Fatalf("%v: exit %d", args, code)
		}
	}
	var stdout, stderr bytes.Buffer
	if code := cmdRotateKey([]string{"--seed", seedPath, "--registry", registry}, &stdout, &stderr); code != 0 {
		t.Fatalf("exit %d: %s", code, stderr.String())
	}
	if !strings.HasPrefix(stdout.String(), "rotation 1: key "+keyIDFor(publicOf(ed25519.NewKeyFromSeed(testSeed)))) {
		t.Fatalf("report: %s", stdout.String())
	}
}
