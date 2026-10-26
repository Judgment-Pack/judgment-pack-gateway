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
		{"a rotation the current key signed naming another keyId", rotationLineBy(k0, keyIDFor(publicOf(other)), rotationKindForward, 1, at, publicOf(k1)) + "\n" + reverseLine(k1, 1, at, publicOf(k0)) + "\n", statusRotationForged, 1, 1, ""},
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
	for _, left := range []string{seedPath + ".next", seedPath + ".rotation"} {
		if _, err := os.Lstat(left); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("%s is still beside the seed: %v", left, err)
		}
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

// tornLog stands in the registry's log for rotate-key with one whose append
// writes the first cut bytes of a record and fails; with whole, it writes
// the record whole and fails to make it durable.
func tornLog(t *testing.T, cut int, whole bool) {
	t.Helper()
	saved := openRotationLog
	t.Cleanup(func() { openRotationLog = saved })
	openRotationLog = func(path string) (*fsLog, error) {
		log, err := openFsLog(path)
		if err != nil {
			return nil, err
		}
		log.write = func(f *os.File, data []byte) (int, error) {
			if whole {
				return f.Write(data)
			}
			n, _ := f.Write(data[:cut])
			return n, errors.New("the write was torn")
		}
		if whole {
			log.sync = func(*os.File) error { return errors.New("the disk would not sync") }
		}
		return log, nil
	}
}

// rotationFixture is a seed under the test key and a registry holding one
// seal, unterminated or not.
func rotationFixture(t *testing.T, unterminated bool) (seedPath, registry string, k0 ed25519.PrivateKey, before []byte) {
	t.Helper()
	root := t.TempDir()
	seedPath, registry = filepath.Join(root, "gateway.seed"), filepath.Join(root, "registry.jsonl")
	k0 = writeTestSeed(t, seedPath, testSeed)
	before = []byte(sealLine(t, k0, "a", 0))
	if unterminated {
		before = before[:len(before)-1]
	}
	if err := os.WriteFile(registry, before, 0o600); err != nil {
		t.Fatal(err)
	}
	return seedPath, registry, k0, before
}

// A rotation whose append is torn -- in the key-rotation, after it whole, in
// the key-continuation, or whole and not made durable -- is pending: the
// gateway starts under neither key, and rotate-key --resume cuts the part of
// the record, appends it whole and makes the switch, after which a verifier
// pinned at the first key follows it.
func TestRotateKeyResumesATornAppend(t *testing.T) {
	forwardLength := len(forwardLine(rotationKey("zero"), 1, "2026-10-25T00:00:00Z", publicOf(rotationKey("one"))))
	for _, c := range []struct {
		name         string
		cut          int
		whole        bool
		unterminated bool
	}{
		{"torn in the key-rotation", 200, false, false},
		{"torn in the key-rotation after an unterminated line", 200, false, true},
		{"the key-rotation alone", forwardLength + 1, false, false},
		{"torn in the key-continuation", forwardLength + 1 + 60, false, false},
		{"whole and not made durable", 0, true, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			seedPath, registry, k0, before := rotationFixture(t, c.unterminated)
			tornLog(t, c.cut, c.whole)
			_, err := rotateKey(seedPath, registry, fixedStamp("2026-10-25T00:00:00Z"), rand.Reader)
			if !errors.Is(err, errRotationPending) || !strings.Contains(err.Error(), "--resume") {
				t.Fatalf("a torn append: %v", err)
			}
			if kept, err := loadSeed(seedPath); err != nil || !bytes.Equal(kept, testSeed) {
				t.Fatal("the seed was switched over a torn append")
			}
			if err := rotationPendingBeside(seedPath, registry); !errors.Is(err, errRotationPending) || !strings.Contains(err.Error(), "--resume") {
				t.Fatalf("a gateway would start beside a pending rotation: %v", err)
			}
			next, err := loadSeed(seedPath + ".next")
			if err != nil {
				t.Fatal(err)
			}
			k1 := ed25519.NewKeyFromSeed(next)
			// With the key-rotation whole, the registry itself refuses the
			// gateway under either key; torn inside it, the registry holds no
			// rotation statement, and the record kept beside the seed is what
			// refuses it (above).
			data, _ := os.ReadFile(registry)
			if c.cut > forwardLength {
				for _, key := range []ed25519.PrivateKey{k0, k1} {
					if _, err := engineWalk(data, publicOf(key)); err == nil || !strings.Contains(err.Error(), "--resume") {
						t.Fatalf("the gateway's own reading of a rotation without its continuation, under %x: %v", publicOf(key)[:4], err)
					}
				}
			}

			openRotationLog = func(path string) (*fsLog, error) { return openFsLog(path) }
			r, err := resumeRotation(seedPath, registry, nil, nil)
			if err != nil {
				t.Fatal(err)
			}
			if r.ordinal != 1 || !bytes.Equal(r.from, publicOf(k0)) || !bytes.Equal(r.to, publicOf(k1)) {
				t.Fatalf("resumed: %+v", r)
			}
			data, _ = os.ReadFile(registry)
			at := "2026-10-25T00:00:00Z"
			want := string(before)
			if c.unterminated {
				want += "\n"
			}
			want += rotationLines(k0, k1, 1, at)
			if string(data) != want {
				t.Fatalf("the registry after --resume:\n%q\nwant:\n%q", data, want)
			}
			if switched, err := loadSeed(seedPath); err != nil || !bytes.Equal(switched, next) {
				t.Fatal("the switch was not made")
			}
			if err := rotationPendingBeside(seedPath, registry); err != nil {
				t.Fatalf("a rotation finished is still pending: %v", err)
			}
			w := walkRegistry(data, publicOf(k0))
			if w.finding != nil || w.followed() != 1 || len(w.seals) != 1 {
				t.Fatalf("walked from the first key: finding %v, %d followed, %d seals", w.finding, w.followed(), len(w.seals))
			}
			if _, err := engineWalk(data, publicOf(k1)); err != nil {
				t.Fatalf("the gateway's own reading under the next key: %v", err)
			}
		})
	}
}

// --resume cuts nothing but a part of the record it kept: other bytes after
// the rotation's place, or a kept record that is not the one the keys sign,
// are refused, and nothing is changed.
func TestResumeCutsNothingButTheRotationsOwnBytes(t *testing.T) {
	seedPath, registry, _, _ := rotationFixture(t, false)
	tornLog(t, 200, false)
	if _, err := rotateKey(seedPath, registry, fixedStamp("2026-10-25T00:00:00Z"), rand.Reader); !errors.Is(err, errRotationPending) {
		t.Fatal(err)
	}
	openRotationLog = func(path string) (*fsLog, error) { return openFsLog(path) }
	torn, _ := os.ReadFile(registry)
	other := append(append([]byte(nil), torn...), 'x')
	if err := os.WriteFile(registry, other, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := resumeRotation(seedPath, registry, nil, nil); err == nil || !strings.Contains(err.Error(), "not the rotation's") {
		t.Fatalf("other bytes after the rotation's place: %v", err)
	}
	requireUnchanged(t, registry, string(other))
	if err := os.WriteFile(registry, torn, 0o600); err != nil {
		t.Fatal(err)
	}
	// the kept record's last signature changed: a record no key of the
	// rotation signs, whose first bytes are still those the registry holds
	k, err := readKeptRecord(seedPath + ".rotation")
	if err != nil {
		t.Fatal(err)
	}
	last := len(k.record) - 4 // inside the key-continuation's signature
	k.record[last] ^= 0x01
	if err := os.WriteFile(seedPath+".rotation", k.bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := resumeRotation(seedPath, registry, nil, nil); err == nil {
		t.Fatal("a kept record not the one this rotation writes was resumed")
	}
	requireUnchanged(t, registry, string(torn))
}

// pendingResume is a rotation of the fixture's key torn in its key-rotation,
// left for --resume: the registry as the tear left it, and the key of the
// next seed.
func pendingResume(t *testing.T, seedPath, registry string) (torn []byte, k1 ed25519.PrivateKey) {
	t.Helper()
	tornLog(t, 200, false)
	if _, err := rotateKey(seedPath, registry, fixedStamp("2026-10-25T00:00:00Z"), rand.Reader); !errors.Is(err, errRotationPending) {
		t.Fatal(err)
	}
	openRotationLog = func(path string) (*fsLog, error) { return openFsLog(path) }
	torn, _ = os.ReadFile(registry)
	next, err := loadSeed(seedPath + ".next")
	if err != nil {
		t.Fatal(err)
	}
	return torn, ed25519.NewKeyFromSeed(next)
}

// resumeFiles is what a --resume may change, read byte for byte: the
// registry, the seed, the next seed and the kept record.
func resumeFiles(t *testing.T, seedPath, registry string) map[string]string {
	t.Helper()
	files := map[string]string{}
	for _, path := range []string{registry, seedPath, seedPath + ".next", seedPath + ".rotation"} {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		files[path] = string(data)
	}
	return files
}

// requireResumeChangedNothing holds a refused --resume to what it found:
// the registry, the seed, the next seed and the kept record byte for byte
// as they were before it, and no seed kept aside.
func requireResumeChangedNothing(t *testing.T, seedPath, registry string, ordinal int, before map[string]string) {
	t.Helper()
	for path, data := range resumeFiles(t, seedPath, registry) {
		if data != before[path] {
			t.Fatalf("a refused --resume changed %s", path)
		}
	}
	if _, err := os.Lstat(seedPath + ".rotated-" + fmt.Sprint(ordinal)); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("the seed was kept aside by a refused --resume")
	}
}

// --resume holds the registry before the rotation's place to the length and
// digest the record kept: a registry there that the rotation did not walk is
// refused, and nothing is changed, though it walks to the key rotated from
// and the record rebuilt over it is the one kept -- another seal of the same
// length in the first one's place, or a kept digest that is not the
// registry's -- and a registry shorter than the kept length is refused too.
func TestResumeHoldsTheRegistryBeforeTheRotationToTheKeptDigest(t *testing.T) {
	for _, c := range []string{"another seal in the first one's place", "another digest kept", "the registry shorter than the kept length"} {
		t.Run(c, func(t *testing.T) {
			seedPath, registry, k0, before := rotationFixture(t, false)
			torn, _ := pendingResume(t, seedPath, registry)
			other := []byte(sealLine(t, k0, "b", 0))
			if len(other) != len(before) || bytes.Equal(other, before) {
				t.Fatal("the other seal is not another of the same length")
			}
			switch c {
			case "another seal in the first one's place":
				torn = append(other, torn[len(before):]...)
				if err := os.WriteFile(registry, torn, 0o600); err != nil {
					t.Fatal(err)
				}
			case "another digest kept":
				k, err := readKeptRecord(seedPath + ".rotation")
				if err != nil {
					t.Fatal(err)
				}
				sum := sha256.Sum256(other)
				k.digest = "sha256:" + hex.EncodeToString(sum[:])
				if err := os.WriteFile(seedPath+".rotation", k.bytes(), 0o600); err != nil {
					t.Fatal(err)
				}
			case "the registry shorter than the kept length":
				torn = before[:len(before)-1]
				if err := os.WriteFile(registry, torn, 0o600); err != nil {
					t.Fatal(err)
				}
			}
			found := resumeFiles(t, seedPath, registry)
			if _, err := resumeRotation(seedPath, registry, nil, nil); err == nil || !strings.Contains(err.Error(), "is not the one the rotation walked") {
				t.Fatalf("--resume over a registry the rotation did not walk: %v", err)
			}
			requireResumeChangedNothing(t, seedPath, registry, 1, found)
		})
	}
}

// --resume holds the kept record's ordinal to the registry's walk before the
// rotation's place: a record kept for a second rotation over a registry that
// holds none -- its statements signed by the two keys for that ordinal, its
// length and digest the registry's, nothing of it appended -- is refused, and
// nothing is changed.
func TestResumeHoldsTheKeptOrdinalToTheWalk(t *testing.T) {
	seedPath, registry, k0, before := rotationFixture(t, false)
	_, k1 := pendingResume(t, seedPath, registry)
	// the rotation stopped after its record was kept and before a byte of it
	// was appended
	if err := os.WriteFile(registry, before, 0o600); err != nil {
		t.Fatal(err)
	}
	k, err := readKeptRecord(seedPath + ".rotation")
	if err != nil {
		t.Fatal(err)
	}
	k.rotation = 2
	k.record = []byte(rotationLines(k0, k1, 2, "2026-10-25T00:00:00Z"))
	if err := os.WriteFile(seedPath+".rotation", k.bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	found := resumeFiles(t, seedPath, registry)
	if _, err := resumeRotation(seedPath, registry, nil, nil); err == nil || !strings.Contains(err.Error(), "does not end at the key rotated from") {
		t.Fatalf("--resume of a rotation whose ordinal is not the next: %v", err)
	}
	requireResumeChangedNothing(t, seedPath, registry, 2, found)
}

// The switch stopped after the seed was moved aside: --resume moves the next
// seed into its place, and removes the kept record.
func TestResumeFinishesASwitchThatStopped(t *testing.T) {
	seedPath, registry, k0, _ := rotationFixture(t, false)
	tornLog(t, 0, true)
	if _, err := rotateKey(seedPath, registry, fixedStamp("2026-10-25T00:00:00Z"), rand.Reader); !errors.Is(err, errRotationPending) {
		t.Fatal(err)
	}
	openRotationLog = func(path string) (*fsLog, error) { return openFsLog(path) }
	if err := os.Rename(seedPath, seedPath+".rotated-1"); err != nil {
		t.Fatal(err)
	}
	r, err := resumeRotation(seedPath, registry, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(r.from, publicOf(k0)) {
		t.Fatalf("resumed from %x", r.from)
	}
	if _, err := loadSeed(seedPath); err != nil {
		t.Fatalf("no seed after the switch: %v", err)
	}
	if err := rotationPendingBeside(seedPath, registry); err != nil {
		t.Fatal(err)
	}
}

// Stopped before its record was kept, a rotation appended nothing: --resume
// removes the next seed it left, and says to rotate again.
func TestResumeWithoutAKeptRecord(t *testing.T) {
	seedPath, registry, _, before := rotationFixture(t, false)
	writeTestSeed(t, seedPath+".next", bytes.Repeat([]byte{9}, 32))
	if _, err := resumeRotation(seedPath, registry, nil, nil); err == nil || !strings.Contains(err.Error(), "run gateway rotate-key again") {
		t.Fatalf("no kept record: %v", err)
	}
	if _, err := os.Lstat(seedPath + ".next"); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("the next seed of a rotation that appended nothing is still there")
	}
	requireUnchanged(t, registry, string(before))
	if _, err := resumeRotation(seedPath, registry, nil, nil); err == nil || !strings.Contains(err.Error(), "no rotation is under way") {
		t.Fatalf("nothing under way: %v", err)
	}
}

// A registry written to between rotate-key's walk and its append is refused,
// and nothing of the rotation is written or kept.
func TestRotateKeyRefusesARegistryWrittenWhileItWorks(t *testing.T) {
	seedPath, registry, k0, before := rotationFixture(t, false)
	beside := sealLine(t, k0, "b", 0)
	saved := openRotationLog
	t.Cleanup(func() { openRotationLog = saved })
	openRotationLog = func(path string) (*fsLog, error) {
		f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0)
		if err != nil {
			return nil, err
		}
		f.WriteString(beside)
		f.Close()
		return openFsLog(path)
	}
	if _, err := rotateKey(seedPath, registry, fixedStamp("2026-10-25T00:00:00Z"), rand.Reader); err == nil || !strings.Contains(err.Error(), "changed while the rotation was made") {
		t.Fatalf("a registry written while rotate-key worked: %v", err)
	}
	requireUnchanged(t, registry, string(before)+beside)
	for _, left := range []string{seedPath + ".next", seedPath + ".rotation"} {
		if _, err := os.Lstat(left); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("%s left after a refusal", left)
		}
	}
}

// /act resolves a citation under every key the engine's own reading
// reached: a receipt minted before a rotation is cited after it, and a
// receipt under a key the walk never reached is not.
func TestAnActionCitesAReceiptMintedBeforeTheRotation(t *testing.T) {
	t.Setenv(envSourceHelper, "1")
	root := t.TempDir()
	seedPath, registry, store := filepath.Join(root, "gateway.seed"), filepath.Join(root, "registry.jsonl"), filepath.Join(root, "store")
	sources := map[string]sourceSpec{"screening": {argv: []string{os.Args[0]}, env: helperEnv}}
	writeTestSeed(t, seedPath, testSeed)
	first, err := newGatewayService(store, testSeed, "gateway:test", registry, sources)
	if err != nil {
		t.Fatal(err)
	}
	mustAcquire(t, first, "cited")
	mustSeal(t, first, "cited")
	if err := os.WriteFile(filepath.Join(root, "other-registry.jsonl"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	foreign, err := newGatewayService(store, bytes.Repeat([]byte{5}, 32), "gateway:test", filepath.Join(root, "other-registry.jsonl"), sources)
	if err != nil {
		t.Fatal(err)
	}
	mustAcquire(t, foreign, "foreign")
	if _, err := rotateKey(seedPath, registry, fixedStamp("2026-10-25T00:00:00Z"), rand.Reader); err != nil {
		t.Fatal(err)
	}
	next, err := loadSeed(seedPath)
	if err != nil {
		t.Fatal(err)
	}
	second, err := newGatewayService(store, next, "gateway:test", registry, sources)
	if err != nil {
		t.Fatal(err)
	}
	keys, err := second.reachedKeys()
	if err != nil || len(keys) != 2 {
		t.Fatalf("the engine's keys: %d %v", len(keys), err)
	}
	signatureOf := func(session string) string {
		data, err := os.ReadFile(filepath.Join(store, "receipts", session, "0.json"))
		if err != nil {
			t.Fatal(err)
		}
		s, _ := topLevelSignature(data)
		return s
	}
	if reason := second.resolveCitation(citation{sessionID: "cited", callIndex: 0, signature: signatureOf("cited")}, keys); reason != "" {
		t.Fatalf("a receipt minted before the rotation does not resolve after it: %s", reason)
	}
	if reason := second.resolveCitation(citation{sessionID: "foreign", callIndex: 0, signature: signatureOf("foreign")}, keys); !strings.Contains(reason, "key-mismatch") {
		t.Fatalf("a receipt under a key the walk never reached: %q", reason)
	}
}

// An acquisition refused for a walk that does not hold says so, not that
// the registry could not be read.
func TestAnAcquisitionRefusedForTheWalkSaysSo(t *testing.T) {
	t.Setenv(envSourceHelper, "1")
	root := t.TempDir()
	registry := filepath.Join(root, "registry.jsonl")
	g, err := newGatewayService(filepath.Join(root, "store"), testSeed, "gateway:test", registry, map[string]sourceSpec{"screening": {argv: []string{os.Args[0]}, env: helperEnv}})
	if err != nil {
		t.Fatal(err)
	}
	k0 := ed25519.NewKeyFromSeed(testSeed)
	if err := os.WriteFile(registry, []byte(forwardLine(k0, 1, "2026-10-25T00:00:00Z", publicOf(rotationKey("one")))+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if reason := g.sealedElsewhere("unheld"); !strings.Contains(reason, "--resume") || !strings.Contains(reason, statusRotationBreak) {
		t.Fatalf("the refusal: %q", reason)
	}
}

// After a rotation the export's manifest names, beside the signer's key,
// the registry's first key, the one a verifier pins; and an export check
// takes it.
func TestTheExportNamesTheFirstKeyAfterARotation(t *testing.T) {
	root := t.TempDir()
	seedPath, registry, store := filepath.Join(root, "gateway.seed"), filepath.Join(root, "registry.jsonl"), filepath.Join(root, "store")
	k0 := writeTestSeed(t, seedPath, testSeed)
	if err := os.WriteFile(registry, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	for _, rotated := range []bool{false, true} {
		key := k0
		if rotated {
			if _, err := rotateKey(seedPath, registry, fixedStamp("2026-10-25T00:00:00Z"), rand.Reader); err != nil {
				t.Fatal(err)
			}
			next, err := loadSeed(seedPath)
			if err != nil {
				t.Fatal(err)
			}
			key = ed25519.NewKeyFromSeed(next)
		}
		out := filepath.Join(t.TempDir(), "export")
		if _, err := writeExport(exportInputs{authority: "gateway:test", keyID: keyIDFor(publicOf(key)), publicKey: publicOf(key), kind: newFsKind(fsLayout{store: store, registry: registry})}, out); err != nil {
			t.Fatal(err)
		}
		manifest, err := os.ReadFile(filepath.Join(out, "manifest.json"))
		if err != nil {
			t.Fatal(err)
		}
		named := strings.Contains(string(manifest), `"firstKeyId":"`+keyIDFor(publicOf(k0))+`"`)
		if named != rotated || !strings.Contains(string(manifest), `"keyId":"`+keyIDFor(publicOf(key))+`"`) {
			t.Fatalf("rotated=%v, manifest: %s", rotated, manifest)
		}
		if _, err := checkExport(out); err != nil {
			t.Fatalf("the export check: %v", err)
		}
	}
}
