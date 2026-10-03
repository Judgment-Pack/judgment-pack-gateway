package main

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// A write held to a record a trusted runtime key signed (ADR-0012): a policy
// that sets requireSignedRecord refuses, at policy-signed and before
// anything else in the record is compared, a record that no readable line of
// the sidecar beside it signs under a key the policy names.

// The runtime's test vector, as its guide writes it ("Record signatures,
// exactly"): the keys are the seeds of RFC 8032's first two test vectors.
const (
	vectorSeed1  = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"
	vectorKey1   = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
	vectorKeyID1 = "21fe31dfa154a261626bf854046fd227"
	vectorSeed2  = "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb"
	vectorKey2   = "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c"
	vectorKeyID2 = "39f713d0a644253f04529421b9f51b9b"
	vectorTrail  = `{"recordVersion":"1","trail":"00112233445566778899aabbccddeeff","sequence":1,"previous":"sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855","kind":"evaluation"}
{"recordVersion":"1","trail":"00112233445566778899aabbccddeeff","sequence":2,"previous":"sha256:9305565078dd0531a50e67ee2d227d4fd0cd0d504541b92801660236a0f0eaed","kind":"evaluation"}
`
	vectorDigest1 = "sha256:9305565078dd0531a50e67ee2d227d4fd0cd0d504541b92801660236a0f0eaed"
	vectorDigest2 = "sha256:d927c7b963914116f0f47219b0564b40741ae2b56de1c38ccaf27fd0f0630702"
	vectorSigned1 = `judgment-pack-runtime/record-signature/1:{"record":"sha256:9305565078dd0531a50e67ee2d227d4fd0cd0d504541b92801660236a0f0eaed","sequence":1,"trail":"00112233445566778899aabbccddeeff"}`
	vectorSidecar = `{"keyId":"21fe31dfa154a261626bf854046fd227","kind":"record-signature","record":"sha256:9305565078dd0531a50e67ee2d227d4fd0cd0d504541b92801660236a0f0eaed","sequence":1,"sidecarVersion":"1","signature":"be509a591ce3d1ecc67a3bd2c35c914e001d2737a62ff8759e5be775448e5d5531370372971fdee8ac5b3c7c63fe16c9f83fed9243e114b8e6c02a2156ffbb0b","trail":"00112233445566778899aabbccddeeff"}
{"at":1,"keyId":"21fe31dfa154a261626bf854046fd227","kind":"key-rotation","next":"3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c","sidecarVersion":"1","signature":"d6cf4da642a0f84dbaaf03a88b7afe0d7eded03897301ac80ab26f7248631502ebc482063a0dc37a2234fff2c62f8bff35ae825261e9d0b6d7908495a7f21201","trail":"00112233445566778899aabbccddeeff"}
{"keyId":"39f713d0a644253f04529421b9f51b9b","kind":"record-signature","record":"sha256:d927c7b963914116f0f47219b0564b40741ae2b56de1c38ccaf27fd0f0630702","sequence":2,"sidecarVersion":"1","signature":"b28b5765844abecd9ca69b642ae1685597045babda87635b8760da9d747a6dc1c244cbbbb0b2c2d73766855665bad9487f61a373209244f7c41af0bb406d8400","trail":"00112233445566778899aabbccddeeff"}
`
)

// runtimeKey is a runtime signing key made from a seed in hex.
type runtimeKey struct {
	private ed25519.PrivateKey
	public  string // 64 lowercase hex
	keyID   string
}

func keyFromSeed(t *testing.T, seedHex string) runtimeKey {
	t.Helper()
	seed, err := hex.DecodeString(seedHex)
	if err != nil || len(seed) != ed25519.SeedSize {
		t.Fatalf("seed %q", seedHex)
	}
	private := ed25519.NewKeyFromSeed(seed)
	public := private.Public().(ed25519.PublicKey)
	return runtimeKey{private: private, public: hex.EncodeToString(public), keyID: keyIDFor(public)}
}

// signedLine is the sidecar line the runtime writes for a record: its
// canonical form, signed by key over the record's trail, sequence and digest.
// The runtime's vector pins it (TestTheRuntimesRecordSignatureVector).
func signedLine(key runtimeKey, trail string, sequence int64, record string) string {
	return sidecarLineOf(key.keyID, trail, sequence, record, ed25519.Sign(key.private, recordSignedBytes(trail, sequence, record)))
}

func sidecarLineOf(keyID, trail string, sequence int64, record string, signature []byte) string {
	line := newObject()
	line.set("kind", vString("record-signature"))
	line.set("sidecarVersion", vString("1"))
	line.set("keyId", vString(keyID))
	line.set("trail", vString(trail))
	line.set("sequence", vInt(sequence))
	line.set("record", vString(record))
	line.set("signature", vString(hex.EncodeToString(signature)))
	return string(canon(line))
}

// rotationLine is a key-rotation line as the runtime writes one: made with
// the key in force, naming the next key and the trail's last line.
func rotationLine(key runtimeKey, trail string, at int64, next string) string {
	signed := newObject()
	signed.set("at", vInt(at))
	signed.set("next", vString(next))
	signed.set("trail", vString(trail))
	line := newObject()
	line.set("kind", vString("key-rotation"))
	line.set("sidecarVersion", vString("1"))
	line.set("keyId", vString(key.keyID))
	line.set("trail", vString(trail))
	line.set("at", vInt(at))
	line.set("next", vString(next))
	line.set("signature", vString(hex.EncodeToString(ed25519.Sign(key.private, append([]byte("judgment-pack-runtime/key-rotation/1:"), canon(signed)...)))))
	return string(canon(line))
}

// The runtime's own vector, read by this engine's rule and nothing of the
// runtime's code: the keys and their keyIds, the record digests, the bytes a
// record signature signs, the lines this engine's signer writes for them
// byte for byte, and which records each set of trusted keys admits -- a
// rotation line followed by nobody here.
func TestTheRuntimesRecordSignatureVector(t *testing.T) {
	key1, key2 := keyFromSeed(t, vectorSeed1), keyFromSeed(t, vectorSeed2)
	if key1.public != vectorKey1 || key1.keyID != vectorKeyID1 || key2.public != vectorKey2 || key2.keyID != vectorKeyID2 {
		t.Fatalf("the vector's keys: %+v %+v", key1, key2)
	}
	lines := strings.Split(strings.TrimSuffix(vectorTrail, "\n"), "\n")
	if len(lines) != 2 || "sha256:"+hexOf([]byte(lines[0])) != vectorDigest1 || "sha256:"+hexOf([]byte(lines[1])) != vectorDigest2 {
		t.Fatal("the record digests are of the lines' exact bytes")
	}
	if !strings.Contains(lines[1], `"previous":"`+vectorDigest1+`"`) {
		t.Fatal("the second line chains to the first")
	}
	if got := string(recordSignedBytes("00112233445566778899aabbccddeeff", 1, vectorDigest1)); got != vectorSigned1 {
		t.Fatalf("the signed bytes:\n%s\nwant\n%s", got, vectorSigned1)
	}
	sidecar := strings.Split(strings.TrimSuffix(vectorSidecar, "\n"), "\n")
	if signedLine(key1, "00112233445566778899aabbccddeeff", 1, vectorDigest1) != sidecar[0] ||
		rotationLine(key1, "00112233445566778899aabbccddeeff", 1, vectorKey2) != sidecar[1] ||
		signedLine(key2, "00112233445566778899aabbccddeeff", 2, vectorDigest2) != sidecar[2] {
		t.Fatal("Ed25519 is deterministic: signing the vector's records with its seeds writes its lines")
	}
	records := map[string]*runtimeRecord{}
	for i, line := range lines {
		v, err := parseRecordJSON([]byte(line))
		if err != nil {
			t.Fatal(err)
		}
		records[[]string{vectorDigest1, vectorDigest2}[i]] = &runtimeRecord{obj: v.(*vObject)}
	}
	signer1 := recordSigner{keyID: key1.keyID, key: key1.private.Public().(ed25519.PublicKey)}
	signer2 := recordSigner{keyID: key2.keyID, key: key2.private.Public().(ed25519.PublicKey)}
	for _, tc := range []struct {
		name    string
		signers []recordSigner
		admits  map[string]bool
	}{
		// The runtime's verifier, given the first key alone, follows the
		// rotation and admits both; this engine trusts the keys it names.
		{"the first key alone", []recordSigner{signer1}, map[string]bool{vectorDigest1: true}},
		{"the second key alone", []recordSigner{signer2}, map[string]bool{vectorDigest2: true}},
		{"both keys", []recordSigner{signer1, signer2}, map[string]bool{vectorDigest1: true, vectorDigest2: true}},
	} {
		for _, digest := range []string{vectorDigest1, vectorDigest2} {
			found := recordSignaturesFor([]byte(vectorSidecar), digest)
			if len(found) != 1 {
				t.Fatalf("one readable record signature names %s, the rotation none: %+v", digest, found)
			}
			err := holdToSignature(records[digest], digest, sidecarEvidence{beside: true, lines: found}, tc.signers)
			if (err == nil) != tc.admits[digest] {
				t.Fatalf("%s, %s: %v", tc.name, digest, err)
			}
			if err != nil && !strings.Contains(err.Error(), "keys the tool's decision policy does not trust") {
				t.Fatalf("%s, %s: refused as signed by a key the policy does not name: %v", tc.name, digest, err)
			}
		}
	}
}

// A key a policy may name: a point of the curve, of the prime order a key
// the runtime generates has. One of small order is refused, since this
// engine's verifier admits a signature under it that no secret made.
func TestASigningKeyMustBeAPointOfLargeOrder(t *testing.T) {
	for _, seed := range []string{vectorSeed1, vectorSeed2} {
		if reason := unusableSigningKey(mustHex(t, keyFromSeed(t, seed).public)); reason != "" {
			t.Fatalf("an RFC 8032 key: %s", reason)
		}
	}
	for i := range 64 {
		sum := sha256.Sum256([]byte("seed " + strconv.Itoa(i)))
		if reason := unusableSigningKey(ed25519.NewKeyFromSeed(sum[:]).Public().(ed25519.PublicKey)); reason != "" {
			t.Fatalf("a generated key: %s", reason)
		}
	}
	// The eight points whose order divides 8, by their encodings, and two
	// encodings of a y past p.
	ff := strings.Repeat("ff", 30)
	smallOrder := []string{
		"01" + strings.Repeat("00", 31), // the identity
		"ec" + ff + "7f",                // (0, -1), order 2
		strings.Repeat("00", 32),        // (√-1, 0), order 4
		strings.Repeat("00", 31) + "80", // (-√-1, 0), order 4
		"26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05", // order 8
		"26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85",
		"c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
		"c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa",
		"ed" + ff + "7f", // y = p, read as 0
		"ee" + ff + "7f", // y = p + 1, read as 1
	}
	for _, key := range smallOrder {
		if reason := unusableSigningKey(mustHex(t, key)); !strings.Contains(reason, "small order") {
			t.Fatalf("%s: %q", key, reason)
		}
	}
	// Why it matters: under each, the standard library's verifier admits a
	// signature with s = 0 and R a point of small order, for most messages.
	for _, key := range smallOrder {
		forged := false
		for m := 0; m < 32 && !forged; m++ {
			message := []byte("a record no key signed " + strconv.Itoa(m))
			for _, r := range smallOrder[:8] {
				if ed25519.Verify(mustHex(t, key), message, append(mustHex(t, r), make([]byte, 32)...)) {
					forged = true
					break
				}
			}
		}
		if !forged {
			t.Fatalf("no forgery found under %s", key)
		}
	}
	// A y for which no x exists, found by Euler's criterion -- (y²-1)/(d·y²+1)
	// is no square -- and not by the square root the reader takes.
	p := curveP
	half := new(big.Int).Rsh(new(big.Int).Sub(p, big.NewInt(1)), 1)
	for y := int64(2); ; y++ {
		yy := big.NewInt(y * y)
		u := new(big.Int).Sub(yy, big.NewInt(1))
		v := new(big.Int).Add(new(big.Int).Mul(curveD, yy), big.NewInt(1))
		ratio := new(big.Int).Mul(u, new(big.Int).ModInverse(v.Mod(v, p), p))
		if new(big.Int).Exp(ratio.Mod(ratio, p), half, p).Cmp(big.NewInt(1)) == 0 {
			continue
		}
		raw := make([]byte, 32)
		raw[0], raw[1] = byte(y), byte(y>>8)
		if reason := unusableSigningKey(raw); !strings.Contains(reason, "not a point") {
			t.Fatalf("y = %d: %q", y, reason)
		}
		break
	}
}

// signedPolicy is the policy these tests hold update_ticket to, trusting the
// given keys.
func signedPolicy(keys ...string) string {
	return strings.TrimSuffix(policyText, "}") + `,"requireSignedRecord":["` + strings.Join(keys, `","`) + `"]}`
}

func TestActRequiresARecordSignedByATrustedKey(t *testing.T) {
	service, server := testService(t)
	key1, key2 := keyFromSeed(t, vectorSeed1), keyFromSeed(t, vectorSeed2)
	stranger := keyFromSeed(t, hex.EncodeToString(func() []byte { s := sha256.Sum256([]byte("a key no policy names")); return s[:] }()))
	policies := map[string]*decisionPolicy{
		"first":  mustPolicy(t, signedPolicy(key1.public)),
		"second": mustPolicy(t, signedPolicy(key2.public)),
		"both":   mustPolicy(t, signedPolicy(key1.public, key2.public)),
	}
	hold := func(name string) {
		service.sources["tickets/write"] = sourceSpec{argv: []string{os.Args[0], "--tools=update_ticket"}, env: helperEnv, shape: "mcp",
			tools: []string{"update_ticket"}, endpoint: "https://mcp.example/", policies: map[string]*decisionPolicy{"update_ticket": policies[name]}}
	}
	issuer := newIssuer(t)
	id := identityFor(t, issuer)
	service.identity = &id
	token := issuer.mint(t, "ec-1", nil, goodClaims(time.Now()))
	code, first := authed(t, server, "/acquire", `{"session":"act-s","source":"screening","arguments":{"q":"acme"}}`, token)
	if code != http.StatusOK {
		t.Fatalf("acquire: %d %v", code, first)
	}
	signature := first["receipt"].(map[string]any)["signature"].(string)
	env, _ := goodEnvelope()
	t.Setenv(envSourceEnvelope, envelopeText(t, env))

	trail, otherTrail := strings.Repeat("5a", 16), strings.Repeat("6b", 16)
	const sequence = 3
	// chained is the runtime's line as a chained trail writes it: the three
	// chain members right after recordVersion.
	chained := func(edits ...string) string {
		line := strings.Replace(runtimeLine(t, signature, edits...), `"recordVersion":"1",`,
			`"recordVersion":"1","trail":"`+trail+`","sequence":`+strconv.Itoa(sequence)+`,"previous":"sha256:`+strings.Repeat("7c", 32)+`",`, 1)
		line = strings.Replace(line, `"cites":[{"sessionId":"act-p"`, `"cites":[{"sessionId":"act-s"`, 1)
		return line
	}
	record := chained()
	digest := "sha256:" + hexOf([]byte(record))
	other := "sha256:" + hexOf([]byte(chained(`"amount":12.5`, `"amount":12.75`)))
	good := signedLine(key1, trail, sequence, digest)
	request := func(recordDigest, packDigest string) string {
		return `{"session":"act-s","platform":"tickets","tool":"update_ticket","arguments":{"id":"Q-7","revision":4,"status":"approved","customer":{"tier":2,"name":"Acme"}},` +
			`"decision":{"recordDigest":"` + recordDigest + `","packDigest":"` + packDigest + `"},` +
			`"cites":[{"sessionId":"act-s","callIndex":0,"signature":"` + signature + `"}]}`
	}
	// Each case is its own decision-record directory: files by their path
	// within it, "" for none.
	write := func(t *testing.T, files map[string]string) {
		t.Helper()
		service.decisionRecords = t.TempDir()
		for name, text := range files {
			path := filepath.Join(service.decisionRecords, filepath.FromSlash(name))
			if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, []byte(text), 0o600); err != nil {
				t.Fatal(err)
			}
		}
	}
	beside := func(sidecar string) map[string]string {
		return map[string]string{"evaluations.jsonl": record + "\n", sidecarName: sidecar}
	}
	tamper := func(line, from, to string) string {
		if !strings.Contains(line, from) {
			t.Fatalf("the line holds no %q", from)
		}
		return strings.Replace(line, from, to, 1)
	}
	goodSignature := ed25519.Sign(key1.private, recordSignedBytes(trail, sequence, digest))
	flipped := sidecarLineOf(key1.keyID, trail, sequence, digest, append([]byte{goodSignature[0] ^ 1}, goodSignature[1:]...))
	padTo := func(line string, n int) string {
		return strings.Replace(line, "{", "{"+strings.Repeat(" ", n-len(line)), 1)
	}
	// A rotation from the first key to the next after the line before the
	// record, the record then signed by the next key -- or, by a copy of
	// the first, by the key rotated away from.
	rotation := signedLine(key1, trail, sequence-1, other) + "\n" + rotationLine(key1, trail, sequence-1, key2.public) + "\n"
	rotated := rotation + signedLine(key2, trail, sequence, digest) + "\n"
	signedAfterRotation := rotation + good + "\n"
	unchained := runtimeLine(t, signature, `"sessionId":"act-p"`, `"sessionId":"act-s"`)
	upperTrail := strings.Replace(record, `"trail":"`+trail+`"`, `"trail":"`+strings.ToUpper(trail)+`"`, 1)
	textSequence := strings.Replace(record, `"sequence":3,`, `"sequence":"3",`, 1)
	// The record a case's request names, when it is not the signed one.
	names := map[string]string{"a record not chained": unchained, "a record whose trail is not 32 lowercase hex": upperTrail, "a record whose sequence is a string": textSequence}
	started := service.started.Load()

	for _, tc := range []struct {
		name   string
		policy string // "" is "first"
		files  map[string]string
		pack   string // "" is packA
		want   string // "" admits the write
	}{
		// What the policy requires: a readable line of the sidecar beside
		// the record, naming its trail, its sequence and its digest, signed
		// under a key the policy names.
		{"signed by the trusted key", "", beside(good + "\n"), "", ""},
		{"no sidecar beside the record", "", map[string]string{"evaluations.jsonl": record + "\n"}, "", "no signatures.jsonl lies beside the record"},
		{"an empty sidecar", "", beside(""), "", "no readable line"},
		{"the record's line torn, without its newline", "", beside(good), "", "no readable line"},
		{"a line past 4096 bytes", "", beside(padTo(good, maxSidecarLine+1) + "\n"), "", "no readable line"},
		{"a line of 4096 bytes", "", beside(padTo(good, maxSidecarLine) + "\n"), "", ""},
		{"a line respelled, its members in another order, whitespace between and an escape", "", beside("{ \"trail\" : \"" + trail + "\",\t\"signature\":\"" + hex.EncodeToString(goodSignature) + "\", \"sequence\": 3, \"sidecarVersion\":\"1\", \"record\":\"" + digest + "\", \"kind\":\"record\\u002dsignature\", \"keyId\":\"" + key1.keyID + "\" }\r\n"), "", ""},
		{"a bad signature", "", beside(flipped + "\n"), "", "does not verify"},
		{"another record's signature under this record's names", "", beside(tamper(signedLine(key1, trail, sequence, other), other, digest) + "\n"), "", "does not verify"},
		{"another trail's signature under this record's names", "", beside(tamper(signedLine(key1, otherTrail, sequence, digest), otherTrail, trail) + "\n"), "", "does not verify"},
		{"a key the policy does not trust", "", beside(signedLine(stranger, trail, sequence, digest) + "\n"), "", "does not trust"},
		{"a trusted keyId on a stranger's signature", "", beside(tamper(signedLine(stranger, trail, sequence, digest), stranger.keyID, key1.keyID) + "\n"), "", "does not verify"},
		{"the trusted key's signature under a stranger's keyId", "", beside(tamper(good, key1.keyID, stranger.keyID) + "\n"), "", "does not trust"},
		{"a line for another trail", "", beside(signedLine(key1, otherTrail, sequence, digest) + "\n"), "", "no readable line"},
		{"a line for another sequence", "", beside(signedLine(key1, trail, sequence+1, digest) + "\n"), "", "no readable line"},
		{"a line for another record", "", beside(signedLine(key1, trail, sequence, other) + "\n"), "", "no readable line"},
		{"a line with a member twice", "", beside(tamper(good, `"kind":"record-signature",`, `"kind":"record-signature","kind":"record-signature",`) + "\n"), "", "no readable line"},
		{"a line with a member beyond its seven", "", beside(tamper(good, `"kind":"record-signature",`, `"kind":"record-signature","note":"",`) + "\n"), "", "no readable line"},
		{"a line of another sidecar version", "", beside(tamper(good, `"sidecarVersion":"1"`, `"sidecarVersion":"2"`) + "\n"), "", "no readable line"},
		{"a line of another kind", "", beside(tamper(good, `"kind":"record-signature"`, `"kind":"key-rotation"`) + "\n"), "", "no readable line"},
		{"a line whose sequence is not an integer's spelling", "", beside(tamper(good, `"sequence":3`, `"sequence":3.0`) + "\n"), "", "no readable line"},
		{"a line whose keyId is not lowercase", "", beside(tamper(good, key1.keyID, strings.ToUpper(key1.keyID)) + "\n"), "", "no readable line"},
		{"a line whose signature is not lowercase", "", beside(tamper(good, hex.EncodeToString(goodSignature), strings.ToUpper(hex.EncodeToString(goodSignature))) + "\n"), "", "no readable line"},
		{"a signed line among others the record's checks refuse", "", beside(signedLine(stranger, trail, sequence, digest) + "\n" + flipped + "\n" + good + "\n" + signedLine(key1, trail, sequence, other) + "\n"), "", ""},
		// Where the sidecar is: beside a file the record is in, by its name.
		{"a sidecar in another directory", "", map[string]string{"evaluations.jsonl": record + "\n", "elsewhere/" + sidecarName: good + "\n"}, "", "no signatures.jsonl lies beside the record"},
		{"a sidecar of another name", "", map[string]string{"evaluations.jsonl": record + "\n", "signatures.json": good + "\n", "Signatures.jsonl": good + "\n"}, "", "no signatures.jsonl lies beside the record"},
		{"the record in two places, signed beside the second", "", map[string]string{"a-copy/evaluations.jsonl": record + "\n", "trail/evaluations.jsonl": record + "\n", "trail/" + sidecarName: good + "\n"}, "", ""},
		{"the record copied whole into a file of its own beside its sidecar", "", map[string]string{"record.json": record, sidecarName: good + "\n"}, "", ""},
		// A record no chain numbers carries nothing a signature names.
		{"a record not chained", "", map[string]string{"evaluations.jsonl": unchained + "\n", sidecarName: good + "\n"}, "", "no trail and sequence"},
		{"a record whose trail is not 32 lowercase hex", "", map[string]string{"evaluations.jsonl": upperTrail + "\n", sidecarName: good + "\n"}, "", "no trail and sequence"},
		{"a record whose sequence is a string", "", map[string]string{"evaluations.jsonl": textSequence + "\n", sidecarName: good + "\n"}, "", "no trail and sequence"},
		// Keys over time: a key signs here because the policy names it, and
		// a rotation line hands nothing on.
		{"signed by the next key after a rotation, held to the first key alone", "first", beside(rotated), "", "does not trust"},
		{"signed by the next key after a rotation, held to the next key", "second", beside(rotated), "", ""},
		{"signed by the key rotated away from, held to the next key alone", "second", beside(good + "\n"), "", "does not trust"},
		{"signed by the key rotated away from after its rotation, held to both: the rotation is not read", "both", beside(signedAfterRotation), "", ""},
		// The signature comes first: an unsigned record is refused there,
		// whatever else about it the later steps would refuse.
		{"an unsigned record whose pack is not the request's", "", map[string]string{"evaluations.jsonl": record + "\n"}, packB, "no signatures.jsonl lies beside the record"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			name := tc.policy
			if name == "" {
				name = "first"
			}
			hold(name)
			write(t, tc.files)
			pack := tc.pack
			if pack == "" {
				pack = packA
			}
			named := digest
			if text, other := names[tc.name]; other {
				named = "sha256:" + hexOf([]byte(text))
			}
			before := service.started.Load()
			code, answer := authed(t, server, "/act", request(named, pack), token)
			if tc.want == "" {
				if code != http.StatusOK {
					t.Fatalf("a record a trusted key signed: %d %v", code, answer)
				}
				inner := answer["receipt"].(map[string]any)["action"].(map[string]any)
				if inner["policy"] != policies[name].digest {
					t.Fatalf("the receipt names the policy the write was held to: %v", inner["policy"])
				}
				if service.started.Load() != before+1 {
					t.Fatal("the executor runs once for the write")
				}
				return
			}
			if code != http.StatusBadRequest || answer["refusedAt"] != "policy-signed" || !strings.Contains(fmt.Sprint(answer["error"]), tc.want) {
				t.Fatalf("want a refusal at policy-signed saying %q, got %d %v", tc.want, code, answer)
			}
			// A refusal names the check, never a value of the record's.
			text := fmt.Sprint(answer["error"])
			for _, quoted := range []string{trail, otherTrail, strings.TrimPrefix(digest, "sha256:"), key1.keyID, stranger.keyID, key1.public, "Q-7"} {
				if strings.Contains(text, quoted) {
					t.Fatalf("the refusal quotes the record or its signature: %v", text)
				}
			}
			if service.started.Load() != before {
				t.Fatal("an executor ran for a write its decision does not hold")
			}
		})
	}
	if service.started.Load() == started {
		t.Fatal("no write was admitted")
	}

	// A sidecar is found as a record is: a link is never followed, whatever
	// it points at.
	hold("first")
	elsewhere := filepath.Join(t.TempDir(), sidecarName)
	if err := os.WriteFile(elsewhere, []byte(good+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	write(t, map[string]string{"evaluations.jsonl": record + "\n"})
	if err := os.Symlink(elsewhere, filepath.Join(service.decisionRecords, sidecarName)); err != nil {
		t.Logf("no symbolic link here (%v); the link case is not run", err)
	} else {
		before := service.started.Load()
		code, answer := authed(t, server, "/act", request(digest, packA), token)
		if code != http.StatusBadRequest || answer["refusedAt"] != "policy-signed" || !strings.Contains(fmt.Sprint(answer["error"]), "no signatures.jsonl lies beside") || service.started.Load() != before {
			t.Fatalf("a sidecar that is a link: %d %v", code, answer)
		}
	}

	// A policy without the member reads no sidecar: an unsigned record
	// passes it as before.
	service.sources["tickets/write"] = sourceSpec{argv: []string{os.Args[0], "--tools=update_ticket"}, env: helperEnv, shape: "mcp",
		tools: []string{"update_ticket"}, endpoint: "https://mcp.example/", policies: map[string]*decisionPolicy{"update_ticket": mustPolicy(t, policyText)}}
	write(t, map[string]string{"evaluations.jsonl": unchained + "\n"})
	if code, answer := authed(t, server, "/act", request("sha256:"+hexOf([]byte(unchained)), packA), token); code != http.StatusOK {
		t.Fatalf("a policy that does not require a signature: %d %v", code, answer)
	}
}

// The digest names the policy as configured, the keys it trusts among it.
func TestASignedRecordPolicysDigestCoversItsKeys(t *testing.T) {
	key1, key2 := keyFromSeed(t, vectorSeed1).public, keyFromSeed(t, vectorSeed2).public
	canonical := strings.TrimSuffix(policyCanonical, `,"reviewed":true}`) + `,"requireSignedRecord":["` + key1 + `"],"reviewed":true}`
	sum := sha256.Sum256([]byte(canonical))
	policy := mustPolicy(t, signedPolicy(key1))
	if policy.digest != "sha256:"+hex.EncodeToString(sum[:]) {
		t.Fatalf("the digest is of the canonical form %s", canonical)
	}
	if len(policy.signers) != 1 || policy.signers[0].keyID != vectorKeyID1 || hex.EncodeToString(policy.signers[0].key) != key1 {
		t.Fatalf("the policy trusts the key it names, by its keyId: %+v", policy.signers)
	}
	seen := map[string]bool{policy.digest: true}
	for _, other := range []string{policyText, signedPolicy(key2), signedPolicy(key1, key2), signedPolicy(key2, key1)} {
		d := mustPolicy(t, other).digest
		if seen[d] {
			t.Fatalf("two policies, one digest: %s", other)
		}
		seen[d] = true
	}
}

// The configuration member: a version-5 member of a decision policy, a
// non-empty list of distinct Ed25519 public keys a signature can be made
// under only with a secret.
func TestRequireSignedRecordConfiguration(t *testing.T) {
	catalog := catalogWith(t, map[string]string{"postgres": postgresBinding})
	ref := "postgres@" + digestOf(postgresBinding)
	key1, key2 := keyFromSeed(t, vectorSeed1).public, keyFromSeed(t, vectorSeed2).public
	config := func(version, keys string) string {
		extra := `,"write":true,"decisionPolicy":{"execute":{"outcomes":["approve"],"requireSignedRecord":` + keys + `}}`
		text := engineJSON(t, catalog, ``, platformJSONFor(t, "warehouse", ref, "engine-warehouse", extra, "history", "live", "write"))
		return strings.Replace(text, `"engineVersion":"1"`, `"engineVersion":"`+version+`"`, 1)
	}
	cfg, sources, err := load(t, config("5", `["`+key1+`","`+key2+`"]`))
	if err != nil {
		t.Fatal(err)
	}
	signers := sources["warehouse/write"].policies["execute"].signers
	if cfg.version != "5" || len(signers) != 2 || signers[0].keyID != vectorKeyID1 || signers[1].keyID != vectorKeyID2 {
		t.Fatalf("version %s, signers %+v", cfg.version, signers)
	}
	if _, _, err := load(t, strings.Replace(engineJSON(t, catalog, ``, ``), `"engineVersion":"1"`, `"engineVersion":"5"`, 1)); err != nil {
		t.Fatalf("a version-5 file without the member: %v", err)
	}
	for _, tc := range []struct{ name, text, want string }{
		{"version 4", config("4", `["`+key1+`"]`), "requireSignedRecord is a version-5 member; engineVersion 4 has no requireSignedRecord"},
		{"version 3", config("3", `["`+key1+`"]`), "decisionPolicy is a version-4 member"},
		{"not an array", config("5", `"`+key1+`"`), "requireSignedRecord must be a non-empty array"},
		{"empty", config("5", `[]`), "requireSignedRecord must be a non-empty array"},
		{"a key that is not a string", config("5", `[1]`), "an Ed25519 public key, 64 lowercase hex"},
		{"a key in uppercase", config("5", `["`+strings.ToUpper(key1)+`"]`), "an Ed25519 public key, 64 lowercase hex"},
		{"a key too short", config("5", `["`+key1[:62]+`"]`), "an Ed25519 public key, 64 lowercase hex"},
		{"a keyId for a key", config("5", `["`+vectorKeyID1+`"]`), "an Ed25519 public key, 64 lowercase hex"},
		{"a key twice", config("5", `["`+key1+`","`+key2+`","`+key1+`"]`), "names one entry twice"},
		{"the all-zero key", config("5", `["`+strings.Repeat("00", 32)+`"]`), "small order"},
		{"the identity", config("5", `["01`+strings.Repeat("00", 31)+`"]`), "small order"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := parseEngineConfig([]byte(tc.text)); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("want a refusal saying %q, got %v", tc.want, err)
			}
		})
	}
}

// connect keeps a version-5 policy, its keys among it, and the version.
func TestConnectKeepsASignedRecordPolicyAndTheVersion(t *testing.T) {
	policy := `{"execute":{"outcomes":["approve"],"requireSignedRecord":["` + keyFromSeed(t, vectorSeed1).public + `"]}}`
	f := newConnectFixture(t, postgresBinding, ``)
	entry := `"warehouse":{"binding":"postgres@` + digestOf(postgresBinding) + `","credentials":{"history":{"file":"` + escapePath(f.credentials) + `"},"live":{"file":"` + escapePath(f.credentials) + `"},"write":{"file":"` + escapePath(f.credentials) + `"}},"user":"engine-warehouse","write":true,"decisionPolicy":` + policy + `}`
	text := strings.Replace(strings.Replace(f.fileText(t), `"engineVersion":"1"`, `"engineVersion":"5"`, 1), `"platforms":{}`, `"platforms":{`+entry+`}`, 1)
	if err := os.WriteFile(f.config, []byte(text), 0o640); err != nil {
		t.Fatal(err)
	}
	before, _, err := loadEngineConfig(f.config, stubAccounts(stubUsers))
	if err != nil {
		t.Fatal(err)
	}
	req := f.request()
	req.replace = true
	req.write = true
	req.credentials = map[string]string{"history": f.credentials, "live": f.credentials, "write": f.credentials}
	f.captured = `{"query":{"description":"Run a query","inputSchemaText":"{\"type\":\"object\"}"}}`
	if _, err := connect(context.Background(), req, f.host, f.check); err != nil {
		t.Fatal(err)
	}
	after, _, err := loadEngineConfig(f.config, stubAccounts(stubUsers))
	if err != nil {
		t.Fatal(err)
	}
	kept := after.platforms[0].policies["execute"]
	if after.version != "5" || kept == nil || kept.digest != before.platforms[0].policies["execute"].digest || len(kept.signers) != 1 {
		t.Fatalf("version %s, policy %+v: the policy kept as written, the version not lowered", after.version, kept)
	}
}
