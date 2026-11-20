package main

// ADR-0053: the P-256 signer, the alg member, the verify-by-algorithm
// function, the pin and rotations across algorithms. Every key is
// synthetic: the scalars 01 and 02 repeated, or a seed of the tests.

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/asn1"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"os"
	"strings"
	"testing"
)

const (
	ksP256One = "projects/standin-project/locations/global/keyRings/receipts/cryptoKeys/hsm/cryptoKeyVersions/1"
	ksP256Two = "projects/standin-project/locations/global/keyRings/receipts/cryptoKeys/hsm/cryptoKeyVersions/2"
	p256At    = "2026-01-02T03:04:05Z"
)

// p256Key is the P-256 key of the scalar b repeated 32 times; 01 is the
// ADR's synthetic test scalar.
func p256Key(b byte) *ecdsa.PrivateKey {
	k, err := ecdsa.ParseRawPrivateKey(elliptic.P256(), bytes.Repeat([]byte{b}, 32))
	if err != nil {
		panic(err)
	}
	return k
}

func compressedOf(k *ecdsa.PrivateKey) []byte {
	raw, err := k.PublicKey.Bytes()
	if err != nil {
		panic(err)
	}
	return compressP256(raw)
}

type rsPair struct{ R, S *big.Int }

// highSDER is a DER signature with s replaced by n - s.
func highSDER(der []byte) []byte {
	var p rsPair
	if _, err := asn1.Unmarshal(der, &p); err != nil {
		panic(err)
	}
	p.S = new(big.Int).Sub(p256Order, p.S)
	out, _ := asn1.Marshal(p)
	return out
}

// highSOf is r||s with s replaced by n - s; derOf is r||s as DER.
func highSOf(sig []byte) []byte {
	s := new(big.Int).Sub(p256Order, new(big.Int).SetBytes(sig[32:]))
	out := bytes.Clone(sig)
	s.FillBytes(out[32:])
	return out
}

func derOf(sig []byte) []byte {
	out, _ := asn1.Marshal(rsPair{new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:])})
	return out
}

// p256Local signs in the test as the key service does: DER over SHA-256 of
// the input, turned into low-S r||s.
type p256Local struct{ k *ecdsa.PrivateKey }

func (s p256Local) publicKey() []byte { return compressedOf(s.k) }
func (s p256Local) algorithm() string { return algES256 }
func (s p256Local) sign(m []byte) ([]byte, error) {
	d := sha256.Sum256(m)
	der, err := ecdsa.SignASN1(rand.Reader, s.k, d[:])
	if err != nil {
		return nil, err
	}
	if rs, ok := p256SignatureOfDER(der); ok {
		return rs, nil
	}
	return nil, errors.New("not DER")
}

func mustP256Signer(t *testing.T, version string) *keyServiceSigner {
	t.Helper()
	k, _, err := newKeyServiceSigner(version, algES256)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func TestAP256DERAnswerIsTurnedIntoLowSAndAHighSOneNeverVerifies(t *testing.T) {
	key, input := p256Key(1), []byte("judgment-pack-gateway/test:{}")
	held := heldKey{alg: algES256, key: compressedOf(key)}
	d := sha256.Sum256(input)
	der, _ := ecdsa.SignASN1(rand.Reader, key, d[:])
	for _, answer := range [][]byte{der, highSDER(der)} {
		rs, ok := p256SignatureOfDER(answer)
		if !ok || new(big.Int).SetBytes(rs[32:]).Cmp(p256HalfOrder) > 0 || !verifyByAlgorithm(algES256, held, input, rs) {
			t.Fatalf("the answer was not normalized to a low-S r||s that verifies: %v", ok)
		}
		if verifyByAlgorithm(algES256, held, input, highSOf(rs)) {
			t.Fatal("a high-S signature verified")
		}
		if verifyByAlgorithm(algES256, held, input, derOf(rs)) {
			t.Fatal("a DER signature verified")
		}
	}
	for name, bad := range map[string][]byte{"a byte after it": append(bytes.Clone(der), 0), "empty": nil, "r||s": make([]byte, 64)} {
		if _, ok := p256SignatureOfDER(bad); ok {
			t.Fatalf("%s was taken as DER", name)
		}
	}
}

func TestVerifyByAlgorithmHoldsTheKeyToTheRecordsAlgorithm(t *testing.T) {
	input := []byte("judgment-pack-gateway/test:{}")
	p256 := p256Local{p256Key(1)}
	sig, _ := p256.sign(input)
	point := p256.publicKey()
	seed := ed25519.NewKeyFromSeed(testSeed)
	edSig := ed25519.Sign(seed, input)
	cases := []struct {
		name string
		alg  string
		key  heldKey
		sig  []byte
		want bool
	}{
		{"P-256 under its key", algES256, heldKey{algES256, point}, sig, true},
		{"Ed25519 under its key", algEd25519, edKey(seed.Public().(ed25519.PublicKey)), edSig, true},
		// a key of the other algorithm, with the same bytes and so the same keyId
		{"a P-256 record under the point given as Ed25519", algES256, heldKey{algEd25519, point}, sig, false},
		// a 33-byte key never reaches ed25519.Verify, which would panic
		{"an Ed25519 record under a 33-byte key", algEd25519, heldKey{algEd25519, point}, edSig, false},
		{"an Ed25519 record under a P-256 key", algEd25519, heldKey{algES256, point}, edSig, false},
		{"an unknown alg", "ES384", heldKey{"ES384", point}, sig, false},
		{"an uncompressed point", algES256, heldKey{algES256, append([]byte{4}, make([]byte, 64)...)}, sig, false},
	}
	for _, c := range cases {
		if got := verifyByAlgorithm(c.alg, c.key, input, c.sig); got != c.want {
			t.Errorf("%s: %v", c.name, got)
		}
	}
}

func TestTheP256KeyVersionIsTakenAtTheHSMLevelAloneAndSignsLowS(t *testing.T) {
	standIn := standInKeyService(t)
	for _, level := range []string{"SOFTWARE", "EXTERNAL", "EXTERNAL_VPC"} {
		standIn.set(func(s *keyServiceStandIn) { s.level = level })
		if _, _, err := newKeyServiceSigner(ksP256One, algES256); err == nil || !strings.Contains(err.Error(), "protection level "+level+" ") || !strings.Contains(err.Error(), "protection level HSM") {
			t.Fatalf("level %s: %v", level, err)
		}
	}
	standIn.set(func(s *keyServiceStandIn) { s.level = "" })
	if _, _, err := newKeyServiceSigner(ksVersion1, algES256); !errors.Is(err, errKeyServicePublicKeyP256) {
		t.Fatalf("an Ed25519 key version under ES256: %v", err)
	}
	if _, _, err := newKeyServiceSigner(ksP256One, algEd25519); !errors.Is(err, errKeyServicePublicKey) {
		t.Fatalf("a P-256 key version under Ed25519: %v", err)
	}
	k, line, err := newKeyServiceSigner(ksP256One, algES256)
	if err != nil || !strings.Contains(line, "(ES256, protection level HSM)") || !bytes.Equal(k.publicKey(), compressedOf(p256Key(1))) {
		t.Fatalf("the start: %v %q", err, line)
	}
	if _, _, err := newKeyServiceSignerPinned(ksP256One, hex.EncodeToString(compressedOf(p256Key(2))), algES256); !errors.Is(err, errKeyServiceNotExpected) {
		t.Fatalf("pinned to another point: %v", err)
	}
	signing := newSigningKey(k)
	for _, highS := range []bool{false, true} {
		standIn.set(func(s *keyServiceStandIn) { s.p256HighS = highS })
		sig, err := signing.signVerified([]byte("message"))
		if err != nil || len(sig) != 64 || new(big.Int).SetBytes(sig[32:]).Cmp(p256HalfOrder) > 0 {
			t.Fatalf("high-S answer %v: %v", highS, err)
		}
	}
	standIn.set(func(s *keyServiceStandIn) { s.p256HighS, s.p256SignBy = false, p256Key(9) })
	if _, err := signing.signVerified([]byte("message")); !errors.Is(err, errSignatureNotVerified) {
		t.Fatalf("a signature by another key: %v", err)
	}
}

func TestAP256StoreVerifiesUnderItsPinAndItsRecordsNameTheAlgorithm(t *testing.T) {
	standInKeyService(t)
	k := mustP256Signer(t, ksP256One)
	g, store, registry := ksService(t, k)
	mustAcquire(t, g, "served")
	mustAcquire(t, g, "served")
	mustSeal(t, g, "served")
	pin := heldKey{alg: algES256, key: k.publicKey()}
	if rep, err := verifySuppliedPin(store, registry, "gateway:test", "", "", pin, false, ""); err != nil || !rep.OK {
		t.Fatalf("the P-256 store: %v %+v", err, rep)
	}
	if _, err := verifySuppliedPin(store, registry, "gateway:test", "", "", heldKey{alg: algEd25519, key: k.publicKey()}, false, ""); err == nil {
		t.Fatal("a 33-byte key was taken as an Ed25519 pin")
	}
	files := storeFiles(t, store)
	var receipt string
	for name, text := range files {
		if strings.HasSuffix(name, "0.json") {
			receipt = name
		}
		if strings.HasSuffix(name, ".json") && !strings.Contains(text, `"alg":"ES256"`) {
			t.Fatalf("%s carries no alg: %s", name, text)
		}
	}
	regBytes, err := os.ReadFile(registry)
	if err != nil {
		t.Fatal(err)
	}
	reg := string(regBytes)
	if !strings.Contains(reg, `"alg":"ES256"`) {
		t.Fatalf("the seal carries no alg: %s", reg)
	}
	if doc := g.publicKeyDocument(); doc["algorithm"] != "ES256" || doc["publicKey"] != hex.EncodeToString(k.publicKey()) {
		t.Fatalf("/publickey: %v", doc)
	}
	// the seal of §3's form signs five members: with alg stripped it loads nothing
	stripped := strings.Replace(reg, `"alg":"ES256",`, "", 1)
	if w := walkRegistryFrom([]byte(stripped), pin); len(w.seals) != 0 {
		t.Fatal("a P-256 seal with alg stripped loaded")
	}
	if w := walkRegistryFrom([]byte(reg), pin); len(w.seals) != 1 {
		t.Fatal("the P-256 seal did not load")
	}
	// a receipt under the point given as Ed25519 is key-mismatch; its
	// signature uppercased or as DER is malformed
	data := []byte(files[receipt])
	session, name := receipt[:strings.LastIndex(receipt, "/")], receipt[strings.LastIndex(receipt, "/")+1:]
	session = session[strings.LastIndex(session, "/")+1:]
	if _, status := checkReceiptUnder(data, store, session, name, "gateway:test", []reachedKey{{key: pin.key, alg: algEd25519, keyID: pin.keyID()}}); status != "key-mismatch" {
		t.Fatalf("the point given as Ed25519: %s", status)
	}
	if _, status := checkReceiptUnder(data, store, session, name, "gateway:test", []reachedKey{{key: pin.key, alg: algES256, keyID: pin.keyID()}}); status != "ok" {
		t.Fatalf("the receipt under its key: %s", status)
	}
	obj, _ := parseJSON(data)
	sigHex, _ := memberString(obj.(*vObject), "signature")
	sig, _ := hex.DecodeString(sigHex)
	for what, other := range map[string]string{"uppercase": strings.ToUpper(sigHex), "DER": hex.EncodeToString(derOf(sig))} {
		bad := []byte(strings.Replace(string(data), sigHex, other, 1))
		if _, status := checkReceiptUnder(bad, store, session, name, "gateway:test", []reachedKey{{key: pin.key, alg: algES256, keyID: pin.keyID()}}); status != "malformed" {
			t.Fatalf("a %s signature: %s", what, status)
		}
	}
	high := []byte(strings.Replace(string(data), sigHex, hex.EncodeToString(highSOf(sig)), 1))
	if _, status := checkReceiptUnder(high, store, session, name, "gateway:test", []reachedKey{{key: pin.key, alg: algES256, keyID: pin.keyID()}}); status != "signature-mismatch" {
		t.Fatalf("a high-S signature: %s", status)
	}
}

func TestAVersion2ReceiptHoldingAlgIsMalformed(t *testing.T) {
	seed := ed25519.NewKeyFromSeed(testSeed)
	keys := []reachedKey{{key: seed.Public().(ed25519.PublicKey), keyID: keyIDFor(seed.Public().(ed25519.PublicKey))}}
	for _, alg := range []string{`,"alg":"ES256"`, `,"alg":"EdDSA"`, `,"alg":1`, ""} {
		data := []byte(`{"receiptVersion":"2","sessionId":"s","callIndex":0,"keyId":"` + keys[0].keyID + `","authority":"a","resultDigest":"sha256:` + strings.Repeat("0", 64) + `","argumentsDigest":"sha256:` + strings.Repeat("0", 64) + `","signature":"` + strings.Repeat("0", 128) + `","source":"x","servedAt":"2026-01-02T03:04:05Z","prevSignature":null` + alg + `}`)
		_, status := checkReceiptUnder(data, t.TempDir(), "s", "0.json", "a", keys)
		if (alg != "") != (status == "malformed") {
			t.Fatalf("a version 2 receipt with %q: %s", alg, status)
		}
	}
}

// p256SignedLine signs obj, under prefix, through key and answers its line.
func p256SignedLine(t *testing.T, key *signingKey, prefix string, obj *vObject) string {
	t.Helper()
	sig, err := key.signVerified(signedOver(prefix, obj))
	if err != nil {
		t.Fatal(err)
	}
	obj.set("signature", vString(hex.EncodeToString(sig)))
	return string(canon(obj))
}

func TestP256SealsRemovalsContinuationsAndDescriptorsVerifyByTheirAlg(t *testing.T) {
	key := newSigningKey(p256Local{p256Key(1)})
	pin := key.held()
	reached := []reachedKey{{key: key.public, alg: algES256, keyID: key.keyID}}
	asEd := []reachedKey{{key: key.public, alg: algEd25519, keyID: key.keyID}}
	scoped := func(withAlg bool) *vObject {
		o := newObject()
		o.set("finalCount", vInt(1))
		o.set("keyId", vString(key.keyID))
		setScopeNaming(o, "s1", "scope-a", strings.Repeat("ab", 32))
		o.set("sealedAt", vString(p256At))
		o.set("sessionId", vString("s1"))
		if withAlg {
			setAlg(o, "alg", key.alg)
		}
		return o
	}
	good := scoped(true)
	line := p256SignedLine(t, key, versionedSealContext(good), good)
	if w := walkRegistryFrom([]byte(line+"\n"), pin); len(w.seals) != 1 {
		t.Fatalf("a P-256 versioned seal did not load: %s", line)
	}
	if w := walkRegistryFrom([]byte(strings.Replace(line, `"alg":"ES256",`, "", 1)+"\n"), pin); len(w.seals) != 0 {
		t.Fatal("a versioned seal with alg stripped loaded")
	}
	if w := walkRegistryFrom([]byte(strings.Replace(line, `"alg":"ES256"`, `"alg":"ES384"`, 1)+"\n"), pin); len(w.seals) != 0 {
		t.Fatal("a versioned seal of another alg loaded")
	}
	if w := walkRegistryFrom([]byte(line+"\n"), heldKey{alg: algEd25519, key: key.public}); len(w.seals) != 0 {
		t.Fatal("a P-256 seal loaded under the point given as Ed25519")
	}
	// a removal record (retention.go) by the record's alg
	rec := newObject()
	rec.set("keyId", vString(key.keyID))
	setAlg(rec, "alg", key.alg)
	sig, _ := key.signVerified(recordSigningInput(sessionRemovalContext, rec))
	if signedByReachedKey(rec, sessionRemovalContext, key.keyID, hex.EncodeToString(sig), reached) != 0 {
		t.Fatal("a P-256 removal record did not verify")
	}
	if signedByReachedKey(rec, sessionRemovalContext, key.keyID, hex.EncodeToString(sig), asEd) != -1 ||
		signedByReachedKey(rec, sessionRemovalContext, key.keyID, strings.ToUpper(hex.EncodeToString(sig)), reached) != -1 ||
		signedByReachedKey(rec, sessionRemovalContext, key.keyID, hex.EncodeToString(highSOf(sig)), reached) != -1 {
		t.Fatal("a removal record verified under the other algorithm, uppercase or high-S")
	}
	// a store continuation
	c := newObject()
	c.set("continuationVersion", vString(continuationVersion))
	c.set("continuedAt", vString(p256At))
	c.set("keyHistoryDigest", vString(strings.Repeat("1", 64)))
	c.set("keyId", vString(key.keyID))
	c.set("kind", vString(continuationKind))
	c.set("previousDigest", vString(strings.Repeat("2", 64)))
	c.set("previousLines", vInt(3))
	setAlg(c, "alg", key.alg)
	csig, _ := key.signVerified(continuationSigningInput(c))
	c.set("signature", vString(hex.EncodeToString(csig)))
	if _, ok := continuationOf(c, reached[0]); !ok {
		t.Fatal("a P-256 store continuation did not load")
	}
	if _, ok := continuationOf(c, asEd[0]); ok {
		t.Fatal("a P-256 store continuation loaded under the point given as Ed25519")
	}
}

func TestRotationsAcrossAlgorithmsWalkAndAreKeptInTheKeyHistory(t *testing.T) {
	seed := newSigningKey(newSeedSigner(testSeed))
	p1, p2 := newSigningKey(p256Local{p256Key(1)}), newSigningKey(p256Local{p256Key(2)})
	ed := newSigningKey(newSeedSigner(bytes.Repeat([]byte{7}, 32)))
	var data []byte
	for i, step := range [][2]*signingKey{{seed, p1}, {p1, p2}, {p2, ed}} {
		record, err := rotationRecordSigned(data, i+1, p256At, step[0], step[1])
		if err != nil {
			t.Fatal(err)
		}
		data = append(data, record...)
	}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	// Ed25519 to P-256: the key-rotation names nextAlg and no alg; the
	// key-continuation alg and no previousAlg
	if !strings.Contains(lines[0], `"nextAlg":"ES256"`) || strings.Contains(lines[0], `"alg"`) ||
		!strings.Contains(lines[1], `"alg":"ES256"`) || strings.Contains(lines[1], "previousAlg") ||
		!strings.Contains(lines[2], `"nextAlg"`) || !strings.Contains(lines[3], `"previousAlg"`) ||
		!strings.Contains(lines[4], `"alg":"ES256"`) || strings.Contains(lines[4], "nextAlg") || strings.Contains(lines[5], `"alg"`) {
		t.Fatalf("the statements' members:\n%s", data)
	}
	w := walkRegistry(data, seed.public)
	if w.finding != nil || len(w.keys) != 4 || w.keys[1].alg != algES256 || w.keys[2].alg != algES256 || w.keys[3].alg != algEd25519 {
		t.Fatalf("the walk: %v %d", w.finding, len(w.keys))
	}
	if _, err := engineWalk(data, ed.held()); err != nil {
		t.Fatal(err)
	}
	if _, err := engineWalk(data, heldKey{alg: algES256, key: ed.public}); err == nil {
		t.Fatal("the own reading took the key under the other algorithm")
	}
	entries, err := registryKeyHistory(data, ed.held(), nil, false)
	if err != nil {
		t.Fatal(err)
	}
	doc := keyHistoryDocument(entries)
	if got, err := checkKeyHistory(doc, seed.public); err != nil || len(got) != 4 || got[1].alg != algES256 || strings.Count(string(doc), `"alg":"ES256"`) < 2 {
		t.Fatalf("the key history: %v\n%s", err, doc)
	}
	for name, c := range map[string]struct {
		line int
		old  string
		new  string
		want string
	}{
		"nextAlg missing":            {0, `"nextAlg":"ES256",`, "", statusRotationBreak},
		"continuation high-S":        {1, "", "", statusRotationBreak},
		"a P-256 key-rotation as Ed": {2, `"alg":"ES256",`, "", statusRotationForged},
	} {
		broken := []byte(lines[c.line])
		if c.old != "" {
			broken = []byte(strings.Replace(string(broken), c.old, c.new, 1))
		} else {
			obj, _ := parseJSON(broken)
			sigHex, _ := memberString(obj.(*vObject), "signature")
			sig, _ := hex.DecodeString(sigHex)
			broken = []byte(strings.Replace(string(broken), sigHex, hex.EncodeToString(highSOf(sig)), 1))
		}
		cut := append([]string{}, lines...)
		cut[c.line] = string(broken)
		w := walkRegistry([]byte(strings.Join(cut, "\n")+"\n"), seed.public)
		if w.finding == nil || w.finding["status"] != c.want {
			t.Errorf("%s: %v", name, w.finding)
		}
	}
	// a next whose x names no point of the curve
	off := append([]byte{2}, make([]byte, 32)...)
	for x := byte(0); ; x++ {
		off[32] = x
		if _, ok := p256PublicKey(off); !ok {
			break
		}
	}
	forward := rotationStatementObjectAlg(rotationKindForward, 1, p256At, seed.keyID, algEd25519, off, algES256)
	fsig, _ := seed.signVerified(rotationSigningInput(forward))
	forward.set("signature", vString(hex.EncodeToString(fsig)))
	if w := walkRegistry(append(canon(forward), '\n'), seed.public); w.finding == nil || w.finding["status"] != statusRotationKeyRefused {
		t.Fatalf("a next off the curve: %v", w.finding)
	}
}

func TestARotationWhileServingCrossesAlgorithmsAndNamesTheMoveFromHSM(t *testing.T) {
	standInKeyService(t)
	start := mustKeyServiceSigner(t, ksVersion1)
	g, store, registry := ksService(t, start)
	mustAcquire(t, g, "first")
	mustSeal(t, g, "first")
	var said bytes.Buffer
	for i, version := range []string{ksP256One, ksP256Two, ksVersion2} {
		alg, public := algES256, hex.EncodeToString(compressedOf(p256Key(byte(i+1))))
		if version == ksVersion2 {
			alg, public = algEd25519, hex.EncodeToString(ksKey("two").Public().(ed25519.PublicKey))
		}
		g.rereadConfig = func() (engineConfig, error) {
			return engineConfig{signingKeyVersion: version, signingPublicKey: public, signingKeyAlgorithm: alg}, nil
		}
		if g.answerHangup(func() string { return p256At }, &said, func(err error) { t.Fatal(err) }) {
			t.Fatalf("the rotation to %s stopped the gateway: %s", version, said.String())
		}
		mustAcquire(t, g, fmt.Sprintf("after-%d", i))
		mustSeal(t, g, fmt.Sprintf("after-%d", i))
	}
	if strings.Count(said.String(), "rotate: the gateway's key is rotated") != 3 || strings.Count(said.String(), hsmToSoftwareLine) != 1 ||
		!strings.HasSuffix(strings.TrimSpace(said.String()), hsmToSoftwareLine) {
		t.Fatalf("what the rotations said:\n%s", said.String())
	}
	if rep, err := verifyWithRegistry(store, registry, "gateway:test", start.publicKey()); err != nil || !rep.OK || rep.Rotations == nil || rep.Rotations.Count != 3 {
		t.Fatalf("the store across algorithms: %v %+v", err, rep)
	}
	doc, err := g.keyHistory()
	if err != nil || strings.Count(string(doc), `"alg":"ES256"`) != 2 {
		t.Fatalf("/publickey/history: %v\n%s", err, doc)
	}
	if g.publicKeyDocument()["algorithm"] != "ed25519" {
		t.Fatal("/publickey after the move back to Ed25519")
	}
}

func TestThePinOfAP256KeyIsExactly66LowercaseHex(t *testing.T) {
	point := hex.EncodeToString(compressedOf(p256Key(1)))
	if key, err := readPinnedKey(algES256, []byte(point)); err != nil || hex.EncodeToString(key) != point {
		t.Fatalf("the pin: %v", err)
	}
	for name, raw := range map[string]string{"uppercase": strings.ToUpper(point), "a newline": point + "\n", "64 hex": point[:64], "uncompressed": "04" + point[2:] + point[2:]} {
		if _, err := readPinnedKey(algES256, []byte(raw)); err == nil {
			t.Errorf("%s was pinned", name)
		}
	}
	if key, err := readPinnedKey(algEd25519, bytes.Repeat([]byte{1}, 32)); err != nil || len(key) != 32 {
		t.Fatalf("the Ed25519 pin: %v", err)
	}
}

func TestSigningKeyAlgorithmIsAVersion40MemberBesideAKeyVersion(t *testing.T) {
	point := hex.EncodeToString(compressedOf(p256Key(1)))
	ed := strings.Repeat("ab", 32)
	catalog := catalogWith(t, map[string]string{"records": tokenBinding})
	ref := "records@" + digestOf(tokenBinding)
	adapters := `,"adapters":"` + abs(t, t.TempDir(), "bin") + `"`
	platform := tokenPlatformJSON(t, "records", ref, "engine-docs", ``, ``)
	keyed := func(version, public, alg string) string {
		extra := adapters + `,"signingKeyVersion":"` + version + `","signingPublicKey":"` + public + `"`
		if alg != "" {
			extra += `,"signingKeyAlgorithm":` + alg
		}
		return extra
	}
	cases := []struct {
		name, version, extra, refusal string
	}{
		{"before version 40", labelsVersion, keyed(ksP256One, point, `"ES256"`), "version-40 member"},
		{"beside the seed alone", p256SignerVersion, adapters + `,"signingKeyAlgorithm":"ES256"`, "not given without it"},
		{"another value", p256SignerVersion, keyed(ksP256One, point, `"EdDSA"`), `is "ES256"`},
		{"a value not a string", p256SignerVersion, keyed(ksP256One, point, `1`), `is "ES256"`},
		{"an Ed25519 key under ES256", p256SignerVersion, keyed(ksP256One, ed, `"ES256"`), "66 lowercase"},
		{"a point under Ed25519", p256SignerVersion, keyed(ksVersion1, point, ""), "64 lowercase"},
	}
	for _, c := range cases {
		if _, _, err := load(t, atVersion(t, c.version, catalog, c.extra, platform)); err == nil || !strings.Contains(err.Error(), c.refusal) {
			t.Errorf("%s: %v", c.name, err)
		}
	}
	cfg, _, err := load(t, atVersion(t, p256SignerVersion, catalog, keyed(ksP256One, point, `"ES256"`), platform))
	if err != nil || cfg.signingKeyAlgorithm != algES256 || cfg.signingPublicKey != point {
		t.Fatalf("version 40 with ES256: %v", err)
	}
	if cfg, _, err := load(t, atVersion(t, p256SignerVersion, catalog, keyed(ksVersion1, ed, ""), platform)); err != nil || cfg.signingKeyAlgorithm != algEd25519 {
		t.Fatalf("version 40 with Ed25519: %v", err)
	}
}
