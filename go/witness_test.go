package main

// The witness reader (SPEC.md §8), tested by trying to get past each of its
// refusals and findings with statements signed here under the corpus's test
// seed. The corpus holds the same rules as vectors (conformance_test.go);
// these hold the reader's own paths, each at least once, and the attacks
// each rule exists to stop.

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
)

// witnessContract is the process contract's `witness` command
// (corpus/README.md), answered by this reader: through it the test binary
// is an implementation `gateway conform --impl` can drive. It writes the
// answer, a verdict or a refusal, and exits 0; it exits 2 when it could not
// answer, and 64 for a command line out of form.
func witnessContract(args []string, stdout, stderr io.Writer) int {
	var trail, head string
	var keys, files []string
	for i := 0; i < len(args); i += 2 {
		if i+1 >= len(args) {
			fmt.Fprintln(stderr, "usage: witness --trail <hex> --witness-key <file>... [--witness <file>]... [--witness-head <file>]")
			return 64
		}
		switch args[i] {
		case "--trail":
			trail = args[i+1]
		case "--witness-key":
			keys = append(keys, args[i+1])
		case "--witness":
			files = append(files, args[i+1])
		case "--witness-head":
			head = args[i+1]
		default:
			fmt.Fprintln(stderr, "witness: unknown flag", args[i])
			return 64
		}
	}
	if trail == "" || len(keys) == 0 {
		fmt.Fprintln(stderr, "witness: --trail and at least one --witness-key are required")
		return 64
	}
	verdict, err := readWitnessFiles(trail, keys, files, head)
	if err != nil {
		fmt.Fprintln(stderr, "witness: no answer:", err)
		return 2
	}
	raw, err := verdict.marshal()
	if err != nil {
		fmt.Fprintln(stderr, "witness:", err)
		return 2
	}
	stdout.Write(raw)
	return 0
}

const testTrail = "3c5e1a7f9b2d4c6e8a0f1b3d5c7e9a2b"

// witnessSigner signs statements with the corpus's test seed.
type witnessSigner struct {
	seed    []byte
	private ed25519.PrivateKey
	public  []byte
}

func newWitnessSigner(t *testing.T) witnessSigner {
	t.Helper()
	seed := mustHex(t, strings.TrimSpace(readFile(t, corpusPath("TEST-SEED"))))
	private := ed25519.NewKeyFromSeed(seed)
	return witnessSigner{seed: seed, private: private, public: private.Public().(ed25519.PublicKey)}
}

// stmt is a statement's members, before it is signed; extra adds members
// the format does not define.
type stmt struct {
	kind     string
	sequence int64
	other    bool // another record at the sequence
	trail    string
	index    int64
	prev     string
	at       string
	version  string
	keyID    string
	cpExtra  map[string]value
	extra    map[string]value
	retires  *stmt // for a retirement, the checkpoint statement it repeats
}

func (s stmt) checkpoint() *vObject {
	if s.retires != nil {
		return s.retires.checkpoint()
	}
	trail := s.trail
	if trail == "" {
		trail = testTrail
	}
	label := "record"
	if s.other {
		label = "other record"
	}
	sum := sha512.Sum512_256([]byte(fmt.Sprintf("witness test %s at %d", label, s.sequence)))
	cp := newObject()
	cp.set("checkpointVersion", vString("1"))
	cp.set("recordDigest", vString("sha256:"+hex.EncodeToString(sum[:])))
	cp.set("sequence", vInt(s.sequence))
	cp.set("trail", vString(trail))
	for name, v := range s.cpExtra {
		cp.set(name, v)
	}
	return cp
}

// body is the statement without its signature.
func (w witnessSigner) body(s stmt) *vObject {
	o := newObject()
	o.set("checkpoint", s.checkpoint())
	o.set("index", vInt(s.index))
	keyID := s.keyID
	if keyID == "" {
		keyID = keyIDFor(w.public)
	}
	o.set("keyId", vString(keyID))
	kind := s.kind
	if kind == "" {
		kind = "checkpoint"
	}
	o.set("kind", vString(kind))
	if s.prev == "" {
		o.set("prevSignature", vNull{})
	} else {
		o.set("prevSignature", vString(s.prev))
	}
	version := s.version
	if version == "" {
		version = "1"
	}
	o.set("witnessVersion", vString(version))
	at := s.at
	if at == "" {
		at = fmt.Sprintf("2026-10-05T12:%02d:00Z", s.index%60)
	}
	o.set("witnessedAt", vString(at))
	for name, v := range s.extra {
		o.set(name, v)
	}
	return o
}

// line signs a statement and gives its line, without a newline, and its
// signature.
func (w witnessSigner) line(s stmt) (string, string) {
	body := w.body(s)
	signature := hex.EncodeToString(ed25519.Sign(w.private, append([]byte(witnessPrefix), canon(body)...)))
	return w.withSignature(body, signature), signature
}

func (w witnessSigner) withSignature(body *vObject, signature string) string {
	body.set("signature", vString(signature))
	return string(canon(body))
}

// chain signs a chain from index 0 of checkpoint statements at the
// sequences given, and gives its lines and signatures.
func (w witnessSigner) chain(sequences ...int64) ([]string, []string) {
	var lines, signatures []string
	prev := ""
	for i, sequence := range sequences {
		line, signature := w.line(stmt{sequence: sequence, index: int64(i), prev: prev})
		lines, signatures = append(lines, line), append(signatures, signature)
		prev = signature
	}
	return lines, signatures
}

func file(lines ...string) []byte {
	var b strings.Builder
	for _, line := range lines {
		b.WriteString(line + "\n")
	}
	return []byte(b.String())
}

func (w witnessSigner) reading(files [][]byte, head []byte) witnessReading {
	return witnessReading{trail: testTrail, keys: [][]byte{w.public}, files: files, head: head}
}

func wantFindings(t *testing.T, what string, v witnessVerdict, findings ...string) {
	t.Helper()
	if v.refused != "" || !slices.Equal(v.findings, findings) {
		t.Errorf("%s: refused %q, findings %v; want findings %v", what, v.refused, v.findings, findings)
	}
}

func wantRefused(t *testing.T, what string, v witnessVerdict, refusal string) {
	t.Helper()
	if v.refused != refusal || v.findings != nil {
		t.Errorf("%s: refused %q, findings %v; want refused %q", what, v.refused, v.findings, refusal)
	}
}

// A chain read from index 0 to a head the reader fetched is current, and
// says where it ends, its latest checkpoint and its conflicts; a conflict
// after a later checkpoint does not move coverage back.
func TestWitnessReadsAChainFromItsFirstStatement(t *testing.T) {
	w := newWitnessSigner(t)
	c0, s0 := w.line(stmt{sequence: 100, index: 0})
	c1, s1 := w.line(stmt{sequence: 200, index: 1, prev: s0})
	x2, s2 := w.line(stmt{kind: "conflict", sequence: 100, other: true, index: 2, prev: s1})
	v := readWitness(w.reading([][]byte{file(c0, c1, x2)}, file(x2)))
	raw, _ := v.marshal()
	want := `{"conflicts":[100],"findings":[],"headIndex":2,"highestIndex":2,"latestCheckpoint":{"index":1,"sequence":200,"witnessedAt":"2026-10-05T12:01:00Z"},"ok":true,"reading":"current","retired":false}`
	if string(raw) != want {
		t.Fatalf("got %s\nwant %s", raw, want)
	}
	// Retired, and read with no head: historical.
	r3, _ := w.line(stmt{kind: "retirement", index: 3, prev: s2, retires: &stmt{sequence: 200}})
	v = readWitness(w.reading([][]byte{file(c0, c1, x2, r3)}, nil))
	if v.findings != nil || v.reading != "historical" || v.head != nil || !v.retired || v.highest != 3 || v.latest.Sequence != 200 {
		t.Fatalf("a retired chain read with no head: %+v", v)
	}
}

// Every refusal is made before any statement is read, and none is a reading
// of part of what was supplied.
func TestWitnessRefusesBeforeAnyStatementIsRead(t *testing.T) {
	w := newWitnessSigner(t)
	lines, _ := w.chain(1)
	ok := file(lines...)

	keys := [][]byte{}
	for i := range 16 {
		seed := sha512.Sum512_256([]byte(fmt.Sprintf("witness test key %d", i)))
		keys = append(keys, ed25519.NewKeyFromSeed(seed[:]).Public().(ed25519.PublicKey))
	}
	keys[15] = w.public
	at := readWitness(witnessReading{trail: testTrail, keys: keys, files: [][]byte{ok}})
	if at.findings != nil || at.refused != "" {
		t.Fatalf("sixteen keys: %+v", at)
	}
	wantRefused(t, "seventeen keys", readWitness(witnessReading{trail: testTrail, keys: append(keys, w.public), files: [][]byte{ok}}), refusalKeysOverBound)

	// Each key the rule refuses, wherever it stands among the keys given.
	for _, c := range []struct{ key, refusal string }{
		{"edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f", refusalKeyNotCanonical}, // y = p
		{"eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f", refusalKeyNotCanonical}, // y = p + 1, the identity read leniently
		{"0100000000000000000000000000000000000000000000000000000000000080", refusalKeyNotCanonical}, // x = 0, sign set
		{"ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", refusalKeyNotCanonical}, // y = p - 1, x = 0, sign set
		{"0000000000000000000000000000000000000000000000000000000000000000", refusalKeySmallOrder},   // order 4, the all-zero key
		{"c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a", refusalKeySmallOrder},   // order 8
		{"0200000000000000000000000000000000000000000000000000000000000000", refusalKeyNotOnCurve},   // y = 2
	} {
		wantRefused(t, c.key, readWitness(witnessReading{trail: testTrail, keys: [][]byte{w.public, mustHex(t, c.key)}, files: [][]byte{ok}}), c.refusal)
	}

	// The byte bound is of the files and the head together; blank lines
	// count toward it and are no statements.
	pad := maxWitnessBytes - 2*len(ok)
	atBound := append(append([]byte{}, ok...), bytes.Repeat([]byte("\n"), pad)...)
	if v := readWitness(w.reading([][]byte{atBound}, ok)); v.findings != nil || v.refused != "" || v.reading != "current" {
		t.Fatalf("at the byte bound: %+v", v)
	}
	wantRefused(t, "a byte past the bound", readWitness(w.reading([][]byte{append(atBound, '\n')}, ok)), refusalBytesOverBound)

	// Statements are counted as supplied, before two copies are one, and
	// before any is read: lines that are no statements are refused by count,
	// not reported malformed.
	if v := readWitness(w.reading([][]byte{bytes.Repeat(ok, maxWitnessStatements-1)}, ok)); v.findings != nil || v.refused != "" {
		t.Fatalf("at the statement bound: %+v", v)
	}
	wantRefused(t, "a statement past the bound", readWitness(w.reading([][]byte{bytes.Repeat([]byte("not a statement\n"), maxWitnessStatements)}, ok)), refusalStatementsOverBound)
}

// Under a key of small order, or one a lenient decoder reads as one, a
// signature verifies that no private key made: R the identity and S zero.
// The standard library's verifier accepts it; the key rule is what stops it.
func TestWitnessKeyRuleStopsASignatureNoKeyMade(t *testing.T) {
	w := newWitnessSigner(t)
	for _, key := range []string{
		"0100000000000000000000000000000000000000000000000000000000000000",
		"eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
		"0100000000000000000000000000000000000000000000000000000000000080",
	} {
		raw := mustHex(t, key)
		body := w.body(stmt{sequence: 1, keyID: keyIDFor(raw)})
		forged := "01" + strings.Repeat("00", 63)
		if !ed25519.Verify(raw, append([]byte(witnessPrefix), canon(body)...), mustHex(t, forged)) {
			t.Fatalf("%s: the forgery does not verify under the standard library, so this test proves nothing", key)
		}
		line := w.withSignature(body, forged)
		v := readWitness(witnessReading{trail: testTrail, keys: [][]byte{raw}, files: [][]byte{file(line)}})
		if v.refused == "" {
			t.Errorf("%s: a statement no private key signed was read: %+v", key, v)
		}
	}
}

// The scalar arithmetic of a forger who holds the test seed: the secret
// scalar, the nonce of an honest signature, and a signature over a point
// the forger names.
var (
	groupOrder = func() *big.Int {
		l, _ := new(big.Int).SetString("27742317777372353535851937790883648493", 10)
		return l.Add(l, new(big.Int).Lsh(big.NewInt(1), 252))
	}()
)

func littleEndianInt(b []byte) *big.Int {
	reversed := slices.Clone(b)
	slices.Reverse(reversed)
	return new(big.Int).SetBytes(reversed)
}

func littleEndianBytes(n *big.Int) []byte {
	b := n.FillBytes(make([]byte, 32))
	slices.Reverse(b)
	return b
}

func (w witnessSigner) scalars(message []byte) (a, r *big.Int) {
	h := sha512.Sum512(w.seed)
	clamped := slices.Clone(h[:32])
	clamped[0] &= 248
	clamped[31] &= 127
	clamped[31] |= 64
	nonce := sha512.Sum512(append(slices.Clone(h[32:]), message...))
	return littleEndianInt(clamped), new(big.Int).Mod(littleEndianInt(nonce[:]), groupOrder)
}

// signNaming signs message as crypto/ed25519 would, under the encoding
// public, but naming the point named in place of the nonce's own.
func (w witnessSigner) signNaming(message, public, named []byte) []byte {
	a, r := w.scalars(message)
	h := sha512.Sum512(slices.Concat(named, public, message))
	s := new(big.Int).Mul(new(big.Int).Mod(littleEndianInt(h[:]), groupOrder), a)
	s.Add(s, r).Mod(s, groupOrder)
	return slices.Concat(named, littleEndianBytes(s))
}

// negate is the point plus the point of order 2, (0, -1): (x, y) to
// (-x, -y), by its encoding.
func negate(t *testing.T, encoded []byte) []byte {
	t.Helper()
	y := littleEndianInt(encoded)
	sign := y.Bit(255)
	y.SetBit(y, 255, 0)
	yy := new(big.Int).Mul(y, y)
	u := new(big.Int).Sub(yy, big.NewInt(1))
	v := new(big.Int).Mul(curveD, yy)
	v.Add(v, big.NewInt(1))
	xx := new(big.Int).ModInverse(v.Mod(v, curveP), curveP)
	xx.Mul(xx, u).Mod(xx, curveP)
	x, ok := squareRoot(xx)
	if !ok {
		t.Fatal("not a point")
	}
	if x.Bit(0) != sign {
		x.Sub(curveP, x)
	}
	nx, ny := new(big.Int).Sub(curveP, x), new(big.Int).Sub(curveP, y)
	nx.Mod(nx, curveP)
	out := littleEndianBytes(ny)
	out[31] |= byte(nx.Bit(0)) << 7
	return out
}

// Only the equation without the cofactor, over a canonical S, verifies: a
// signature whose point carries a part of small order, one under a key of
// mixed order that holds only up to that part, and one whose S is L more
// are each refused, though the cofactored check or a reduction of S
// accepts them.
func TestWitnessSignatureEquation(t *testing.T) {
	w := newWitnessSigner(t)
	body := w.body(stmt{sequence: 1})
	message := append([]byte(witnessPrefix), canon(body)...)
	honest := ed25519.Sign(w.private, message)
	if !slices.Equal(w.signNaming(message, w.public, honest[:32]), honest) {
		t.Fatal("the test's arithmetic does not sign as crypto/ed25519 does")
	}
	read := func(key []byte, body *vObject, signature []byte) witnessVerdict {
		return readWitness(witnessReading{trail: testTrail, keys: [][]byte{key}, files: [][]byte{file(w.withSignature(body, hex.EncodeToString(signature)))}})
	}
	if v := read(w.public, body, honest); v.findings != nil {
		t.Fatalf("the honest statement: %+v", v)
	}

	// The point of order 2 added to the signature's point.
	smallOrderPart := w.signNaming(message, w.public, negate(t, honest[:32]))
	wantFindings(t, "a point with a part of small order", read(w.public, body, smallOrderPart), findingWitnessSignatureInvalid)

	// S + L: the same [S]B, below 2^253.
	s := new(big.Int).Add(littleEndianInt(honest[32:]), groupOrder)
	wantFindings(t, "S + L", read(w.public, body, slices.Concat(honest[:32], littleEndianBytes(s))), findingWitnessSignatureInvalid)

	// A key of mixed order is accepted by the rule; a signature under it
	// verifies when h is even and is refused when h is odd.
	mixed := negate(t, w.public)
	if witnessKeyRefusal(mixed) != "" {
		t.Fatal("a key of mixed order is refused")
	}
	seen := map[bool]bool{}
	for second := 0; len(seen) < 2; second++ {
		body := w.body(stmt{sequence: 1, keyID: keyIDFor(mixed), at: fmt.Sprintf("2026-10-05T13:00:%02dZ", second)})
		message := append([]byte(witnessPrefix), canon(body)...)
		named := ed25519.Sign(w.private, message)[:32] // [r]B, the nonce's own point
		signature := w.signNaming(message, mixed, named)
		h := sha512.Sum512(slices.Concat(named, mixed, message))
		odd := new(big.Int).Mod(littleEndianInt(h[:]), groupOrder).Bit(0) == 1
		if seen[odd] {
			continue
		}
		seen[odd] = true
		v := read(mixed, body, signature)
		if odd {
			wantFindings(t, "mixed key, h odd", v, findingWitnessSignatureInvalid)
		} else if v.findings != nil || v.refused != "" {
			t.Errorf("mixed key, h even: %+v", v)
		}
	}

	// R the identity, a point of small order: the equation holds when S is
	// h times the secret scalar, and it is accepted.
	identity := mustHex(t, "01"+strings.Repeat("00", 31))
	a, _ := w.scalars(message)
	h := sha512.Sum512(slices.Concat(identity, w.public, message))
	sIdentity := new(big.Int).Mul(new(big.Int).Mod(littleEndianInt(h[:]), groupOrder), a)
	sIdentity.Mod(sIdentity, groupOrder)
	if v := read(w.public, body, slices.Concat(identity, littleEndianBytes(sIdentity))); v.findings != nil || v.refused != "" {
		t.Errorf("R the identity: %+v", v)
	}
}

// Each finding, by the statement or set that makes it, and only it: a set
// with any statement finding is not walked.
func TestWitnessFindings(t *testing.T) {
	w := newWitnessSigner(t)
	lines, sigs := w.chain(10, 20, 30, 40)
	other1, _ := w.line(stmt{sequence: 25, index: 1, prev: sigs[0]})
	foreign, _ := w.line(stmt{sequence: 5, trail: "d0c1b2a3948576a7b8c9d0e1f2031425"})
	extra, _ := w.line(stmt{sequence: 10, extra: map[string]value{"note": vString("x")}})
	version2, _ := w.line(stmt{sequence: 10, version: "2"})
	cpExtra, _ := w.line(stmt{sequence: 10, cpExtra: map[string]value{"note": vString("x")}})
	var altered map[string]any
	json.Unmarshal([]byte(lines[1]), &altered)
	altered["checkpoint"].(map[string]any)["sequence"] = 21
	alteredLine, _ := json.Marshal(altered)
	firstNamesPrev, _ := w.line(stmt{sequence: 10, prev: sigs[0]})
	skipsBack, _ := w.line(stmt{sequence: 30, index: 2, prev: sigs[0]})
	laterNamesNone, _ := w.line(stmt{sequence: 20, index: 1})
	notIncreasing, _ := w.line(stmt{sequence: 10, other: true, index: 1, prev: sigs[0]})
	conflictAbove, _ := w.line(stmt{kind: "conflict", sequence: 11, other: true, index: 1, prev: sigs[0]})
	conflictFirst, _ := w.line(stmt{kind: "conflict", sequence: 10, other: true})
	retired, retiredSig := w.line(stmt{kind: "retirement", index: 1, prev: sigs[0], retires: &stmt{sequence: 10}})
	afterRetirement, _ := w.line(stmt{sequence: 50, index: 2, prev: retiredSig})
	retiresEarlier, _ := w.line(stmt{kind: "retirement", index: 2, prev: sigs[1], retires: &stmt{sequence: 10}})
	retiresNothing, _ := w.line(stmt{kind: "retirement", retires: &stmt{sequence: 10}})

	for _, c := range []struct {
		what     string
		files    [][]byte
		head     []byte
		findings []string
	}{
		{"a member the format does not define", [][]byte{file(extra)}, nil, []string{findingWitnessMalformed}},
		{"another witnessVersion", [][]byte{file(version2)}, nil, []string{findingWitnessMalformed}},
		{"a fifth checkpoint member", [][]byte{file(cpExtra)}, nil, []string{findingWitnessMalformed}},
		{"index -0", [][]byte{file(strings.Replace(lines[0], `"index":0,`, `"index":-0,`, 1))}, nil, []string{findingWitnessMalformed}},
		{"index 0.0", [][]byte{file(strings.Replace(lines[0], `"index":0,`, `"index":0.0,`, 1))}, nil, []string{findingWitnessMalformed}},
		{"a signature in upper case", [][]byte{file(strings.Replace(lines[0], sigs[0], strings.ToUpper(sigs[0]), 1))}, nil, []string{findingWitnessMalformed}},
		{"a name given twice", [][]byte{file(strings.Replace(lines[0], `{"checkpoint"`, `{"index":0,"checkpoint"`, 1))}, nil, []string{findingWitnessMalformed}},
		{"not JSON", [][]byte{file("{")}, nil, []string{findingWitnessMalformed}},
		{"a head file of two statements", [][]byte{file(lines[:2]...)}, file(lines[0], lines[1]), []string{findingWitnessMalformed}},
		{"a keyId that names no key supplied", [][]byte{file(lines[0]), file(strings.Replace(lines[1], keyIDFor(w.public), strings.Repeat("0", 32), 1))}, nil, []string{findingWitnessSignatureInvalid}},
		{"a statement altered after signing", [][]byte{file(lines[0], string(alteredLine))}, nil, []string{findingWitnessSignatureInvalid}},
		{"a statement of another trail", [][]byte{file(lines[0]), file(foreign)}, nil, []string{findingWitnessTrailMismatch}},
		{"two statements at one index", [][]byte{file(lines[0], lines[1], other1)}, nil, []string{findingWitnessEquivocation}},
		{"a head that differs at an index held", [][]byte{file(lines...)}, file(other1), []string{findingWitnessEquivocation}},
		{"beginning late", [][]byte{file(lines[1:]...)}, nil, []string{findingWitnessChainBroken}},
		{"beginning late, to a head", [][]byte{file(lines[2:]...)}, file(lines[3]), []string{findingWitnessChainBroken}},
		{"nothing supplied", [][]byte{{}}, nil, []string{findingWitnessChainBroken}},
		{"a hole", [][]byte{file(lines[0], lines[1], lines[3])}, nil, []string{findingWitnessChainBroken}},
		{"a previous signature not the one before", [][]byte{file(lines[0], lines[1], skipsBack)}, nil, []string{findingWitnessChainBroken}},
		{"a previous signature changed after signing", [][]byte{file(lines[0], lines[1], strings.Replace(lines[2], sigs[1], sigs[0], 1))}, nil, []string{findingWitnessSignatureInvalid}},
		{"index 0 naming a previous", [][]byte{file(firstNamesPrev)}, nil, []string{findingWitnessChainBroken}},
		{"index 1 naming none", [][]byte{file(lines[0], laterNamesNone)}, nil, []string{findingWitnessChainBroken}},
		{"a sequence not increasing", [][]byte{file(lines[0], notIncreasing)}, nil, []string{findingWitnessChainBroken}},
		{"a conflict above the latest checkpoint", [][]byte{file(lines[0], conflictAbove)}, nil, []string{findingWitnessChainBroken}},
		{"a conflict first", [][]byte{file(conflictFirst)}, nil, []string{findingWitnessChainBroken}},
		{"a retirement not last", [][]byte{file(lines[0], retired, afterRetirement)}, nil, []string{findingWitnessChainBroken}},
		{"a retirement repeating an earlier checkpoint", [][]byte{file(lines[0], lines[1], retiresEarlier)}, nil, []string{findingWitnessChainBroken}},
		{"a retirement with no checkpoint before it", [][]byte{file(retiresNothing)}, nil, []string{findingWitnessChainBroken}},
		{"a head more than one past", [][]byte{file(lines[0], lines[1])}, file(lines[3]), []string{findingWitnessHeadUnreached}},
		{"a head alone, past index 0", nil, file(lines[2]), []string{findingWitnessChainBroken, findingWitnessHeadUnreached}},
		{"a head one past, not linked", [][]byte{file(lines[0])}, file(laterNamesNone), []string{findingWitnessChainBroken}},
	} {
		wantFindings(t, c.what, readWitness(w.reading(c.files, c.head)), c.findings...)
	}

	// What reads: one past, linked, joins; a chain past its head; a
	// statement respelled is the same statement.
	for _, c := range []struct {
		what        string
		files       [][]byte
		head        []byte
		reading     string
		head0, high int64
	}{
		{"a head one past, linked", [][]byte{file(lines[0], lines[1])}, file(lines[2]), "current", 2, 2},
		{"a chain past its head", [][]byte{file(lines...)}, file(lines[1]), "current", 1, 3},
		{"a head alone at index 0", nil, file(lines[0]), "current", 0, 0},
		{"a statement respelled", [][]byte{file(lines[0]), []byte(" \r\n" + strings.Replace(strings.Replace(lines[0], ",", " ,\t", -1), `"kind"`, `"kind"`, 1) + "\r\n")}, nil, "historical", -1, 0},
	} {
		v := readWitness(w.reading(c.files, c.head))
		if v.findings != nil || v.refused != "" || v.reading != c.reading || v.highest != c.high || (v.head == nil) != (c.head0 < 0) || (v.head != nil && *v.head != c.head0) {
			t.Errorf("%s: %+v", c.what, v)
		}
	}
}

// Every refusal and finding the reader can give is expected by at least one
// corpus vector, so none is a path the corpus does not hold.
func TestWitnessCorpusExpectsEveryAnswer(t *testing.T) {
	expected := map[string]bool{}
	paths, err := witnessVectorPaths(corpusDir)
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range paths {
		vector, err := readWitnessVector(path)
		if err != nil {
			t.Fatal(err)
		}
		if r, ok := vector.Expected["refused"].(string); ok {
			expected[r] = true
		}
		if findings, ok := vector.Expected["findings"].([]any); ok {
			for _, f := range findings {
				expected[f.(string)] = true
			}
		}
	}
	for _, answer := range []string{
		refusalKeysOverBound, refusalKeyNotCanonical, refusalKeySmallOrder, refusalKeyNotOnCurve, refusalBytesOverBound, refusalStatementsOverBound,
		findingWitnessMalformed, findingWitnessSignatureInvalid, findingWitnessTrailMismatch, findingWitnessEquivocation, findingWitnessChainBroken, findingWitnessHeadUnreached,
	} {
		if !expected[answer] {
			t.Errorf("no witness vector expects %s", answer)
		}
	}
}

// The process contract's witness command: an answer, a refusal among them,
// exits 0; an input it cannot read exits 2; a command line out of form 64.
func TestWitnessContract(t *testing.T) {
	w := newWitnessSigner(t)
	dir := t.TempDir()
	lines, _ := w.chain(1)
	write := func(name string, data []byte) string {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	key := write("key", []byte(hex.EncodeToString(w.public)+"\n"))
	statements := write("statements", file(lines...))
	run := func(args ...string) (int, string) {
		var out, errOut bytes.Buffer
		code := witnessContract(args, &out, &errOut)
		return code, out.String()
	}
	if code, out := run("--trail", testTrail, "--witness-key", key, "--witness", statements, "--witness-head", statements); code != 0 || !strings.Contains(out, `"reading":"current"`) {
		t.Errorf("a reading: %d %s", code, out)
	}
	small := write("small", []byte(strings.Repeat("0", 64)))
	if code, out := run("--trail", testTrail, "--witness-key", small, "--witness", statements); code != 0 || out != `{"refused":"key-small-order"}` {
		t.Errorf("a refusal: %d %s", code, out)
	}
	if code, _ := run("--trail", testTrail, "--witness-key", write("short", []byte("abc")), "--witness", statements); code != 2 {
		t.Errorf("a key file not of its form: %d", code)
	}
	if code, _ := run("--trail", testTrail, "--witness-key", key, "--witness", filepath.Join(dir, "absent")); code != 2 {
		t.Errorf("a statements file not there: %d", code)
	}
	if code, _ := run("--trail", testTrail, "--witness", statements); code != 64 {
		t.Errorf("no key: %d", code)
	}
}

// Statements are counted as the files are split, and the reading stops at
// the line past the bound: a file of many short lines, far under the byte
// bound, is refused having kept no more lines than the bound allows and
// parsed none, so it costs no more than 110000 statements would.
func TestWitnessStopsCountingAtTheBound(t *testing.T) {
	w := newWitnessSigner(t)
	short := bytes.Repeat([]byte("x\n"), 1<<22) // 8 MiB, 4194304 lines
	lines, headLines, counted, within := collectStatementLines([][]byte{short}, nil, maxWitnessStatements)
	if within || counted != maxWitnessStatements+1 || lines != nil || headLines != nil {
		t.Fatalf("4194304 short lines: within %v, counted %d, kept %d and %d; want a stop at line %d, keeping none",
			within, counted, len(lines), len(headLines), maxWitnessStatements+1)
	}

	// The head file is counted after the statements files.
	one, _ := w.chain(1)
	atBound := bytes.Repeat(file(one...), maxWitnessStatements)
	if _, _, counted, within := collectStatementLines([][]byte{atBound}, file(one...), maxWitnessStatements); within || counted != maxWitnessStatements+1 {
		t.Fatalf("the bound in the files and one statement in the head: within %v, counted %d", within, counted)
	}

	// What the refusal costs: the lines kept up to the bound, not every
	// line of the file. Reading every line first, as a reader that counts
	// after splitting does, allocates some 200 MB for this file.
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	v := readWitness(w.reading([][]byte{short}, nil))
	runtime.ReadMemStats(&after)
	wantRefused(t, "4194304 short lines", v, refusalStatementsOverBound)
	allocated := after.TotalAlloc - before.TotalAlloc
	if allocated > 32<<20 {
		t.Errorf("refusing 4194304 short lines allocated %d bytes", allocated)
	}
	t.Logf("refusing 4194304 short lines allocated %d bytes", allocated)
}

// A chain begins with a checkpoint statement: an empty set, and a set whose
// first statement is a conflict or a retirement, are witness-chain-broken,
// each by the reader's own check and not by a fault of building its answer.
func TestWitnessAChainBeginsWithACheckpoint(t *testing.T) {
	w := newWitnessSigner(t)
	conflict, _ := w.line(stmt{kind: "conflict", sequence: 10, other: true})
	retirement, _ := w.line(stmt{kind: "retirement", retires: &stmt{sequence: 10}})
	for _, c := range []struct {
		what  string
		files [][]byte
	}{
		{"no statements file", nil},
		{"an empty statements file", [][]byte{{}}},
		{"blank lines only", [][]byte{[]byte("\n \r\n\t\n")}},
		{"a conflict with no checkpoint before it", [][]byte{file(conflict)}},
		{"a retirement with no checkpoint before it", [][]byte{file(retirement)}},
	} {
		wantFindings(t, c.what, readWitness(w.reading(c.files, nil)), findingWitnessChainBroken)
	}
}
