package main

// gateway retain (ADR-0048, A1 and R1; retain.go): a sealed session removed
// under a signed acknowledgment once the window has passed, recorded as
// ADR-0034's session-removal record alone, and every refusal by name.

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// retentionAckKey is the external log's key the tests pin.
var retentionAckKey = ed25519.NewKeyFromSeed(bytes.Repeat([]byte{7}, 32))

// retainStore is scopeStore's store with p1, a sealed session of no scope
// identifier, besides, and an engine configuration of the retention
// version pinning retentionAckKey with a window of 30 days.
func retainStore(t *testing.T, extra ...[3]string) (*gatewayService, string) {
	t.Helper()
	g, seedPath := scopeStore(t, append([][3]string{{"p1", "plain", "only-p"}}, extra...)...)
	server := httptest.NewServer(g.handler())
	if code, out := post(t, server, "/seal", `{"session":"p1"}`); code != http.StatusOK {
		t.Fatalf("seal p1: %d %v", code, out)
	}
	server.Close()
	dir := t.TempDir()
	config := filepath.Join(dir, "engine.json")
	body := fmt.Sprintf(`{"engineVersion":%q,"authority":"gateway:test","seed":%q,"store":%q,"registry":%q,"decisionRecords":%q,"listen":"127.0.0.1:8787","catalog":%q,"platforms":{},"retention":{"window":30,"acknowledgedBy":[%q]}}`,
		retentionVersion, seedPath, g.storeRoot, g.regPath, filepath.Join(dir, "decisions"), filepath.Join(dir, "catalog"), hex.EncodeToString(retentionAckKey.Public().(ed25519.PublicKey)))
	if err := os.WriteFile(config, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return g, config
}

// sealOf is the seal the store's registry holds for the session.
func sealOf(t *testing.T, regPath string, pub ed25519.PublicKey, session string) seal {
	t.Helper()
	data, err := os.ReadFile(regPath)
	if err != nil {
		t.Fatal(err)
	}
	s, ok := walkRegistry(data, pub).seals[session]
	if !ok {
		t.Fatalf("no seal for %s", session)
	}
	return s
}

func sealTime(t *testing.T, s seal) time.Time {
	t.Helper()
	at, err := time.Parse(time.RFC3339, s.sealedAt)
	if err != nil {
		t.Fatal(err)
	}
	return at
}

func stampOf(at time.Time) string { return at.UTC().Format(time.RFC3339) }

func writeAcks(t *testing.T, lines ...[]byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "acks.jsonl")
	if err := os.WriteFile(path, bytes.Join(lines, nil), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func runRetain(config, acks string, now time.Time, rest ...string) (int, string, string) {
	var stdout, stderr bytes.Buffer
	args := append([]string{"--config", config, "--acknowledgments", acks, "--by", "operator-1"}, rest...)
	code := cmdRetainAt(args, &stdout, &stderr, fixedStamp(removalStamp), func() time.Time { return now })
	return code, stdout.String(), stderr.String()
}

// An acknowledged sealed session of a scope identifier, past the window,
// goes: its record first, alone, and then its files; the open session, the
// other scope's session and the session of no scope stay, and the store
// verifies with the session read as removed. A second run removes nothing.
func TestRetainRemovesAnAcknowledgedSessionPastTheWindow(t *testing.T) {
	g, config := retainStore(t)
	a1 := sealOf(t, g.regPath, g.publicKey, "a1")
	now := sealTime(t, a1).Add(31 * 24 * time.Hour)
	acks := writeAcks(t, retentionAckLine(retentionAckKey, "a1", a1.signature, a1.finalCount, stampOf(sealTime(t, a1).Add(time.Hour))))
	data, _ := os.ReadFile(acks)
	sum := sha256Hex(data)

	code, stdout, stderr := runRetain(config, acks, now)
	summary := "retain: " + retentionSummary(1, "sha256:"+sum, []string{keyIDFor(retentionAckKey.Public().(ed25519.PublicKey))}) + "\n"
	if code != 0 || !strings.Contains(stderr, "retain: removed 1 session(s), holding 2 receipt(s)") || !strings.HasSuffix(strings.TrimSuffix(stderr, retainUnlockedLine()), summary) {
		t.Fatalf("retain: %d %q %q", code, stdout, stderr)
	}
	if lines := strings.Split(strings.TrimSuffix(stdout, "\n"), "\n"); len(lines) != 1 || !strings.Contains(lines[0], `"kind":"session-removal"`) || !strings.Contains(lines[0], `"sessionId":"a1"`) {
		t.Fatalf("the records printed: %q", stdout)
	}
	if file := readFile(t, filepath.Join(g.storeRoot, removalsFile)); file != stdout || strings.Contains(file, "scope-removal") {
		t.Fatalf("the removal file: %q", file)
	}
	if _, err := os.Stat(filepath.Join(g.storeRoot, "receipts", "a1")); !os.IsNotExist(err) {
		t.Fatalf("a1 is still there: %v", err)
	}
	for _, kept := range []string{"a2", "b1", "p1"} {
		if _, err := os.Stat(filepath.Join(g.storeRoot, "receipts", kept)); err != nil {
			t.Fatalf("%s: %v", kept, err)
		}
	}
	// a2, open, is what the verdict finds of it before the call as after
	_, findings, observations := scopeVerdict(t, g)
	if strings.Join(findings, ",") != "a2 unregistered-session" || !strings.Contains(strings.Join(observations, ","), "a1 "+observationSessionRemoved) {
		t.Fatalf("the verdict: %v %v", findings, observations)
	}

	code, stdout, stderr = runRetain(config, acks, now)
	if code != 0 || stdout != "" || !strings.Contains(stderr, "retain: session a1 was recorded as removed already\n") {
		t.Fatalf("a second run: %d %q %q", code, stdout, stderr)
	}
}

// Each refusal names what refuses, before anything is written; a session no
// acknowledgment names, and one inside the window, stay, the call
// succeeding and removing nothing.
func TestRetainRefusesByNameAndKeepsWhatIsNotPastRetention(t *testing.T) {
	g, config := retainStore(t)
	a1 := sealOf(t, g.regPath, g.publicKey, "a1")
	p1 := sealOf(t, g.regPath, g.publicKey, "p1")
	sealed := sealTime(t, a1)
	now := sealed.Add(31 * 24 * time.Hour)
	other := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{9}, 32))
	cases := []struct {
		name  string
		lines [][]byte
		now   time.Time
		code  int
		want  string
	}{
		{"not acknowledged", nil, now, 0, "retain: no session is past retention under an acknowledgment; nothing was removed"},
		{"another key", [][]byte{retentionAckLine(other, "a1", a1.signature, a1.finalCount, stampOf(sealed))}, now, 1,
			"retain: acknowledgment line 1 names a key that retention.acknowledgedBy does not list"},
		{"a listed key's id over another key's signature", [][]byte{relabelledAck(t, retentionAckLine(other, "a1", a1.signature, a1.finalCount, stampOf(sealed)), other, retentionAckKey)}, now, 1,
			"retain: acknowledgment line 1 does not verify under retention.acknowledgedBy, key " + keyIDFor(retentionAckKey.Public().(ed25519.PublicKey))},
		{"before the seal", [][]byte{retentionAckLine(retentionAckKey, "a1", a1.signature, a1.finalCount, stampOf(sealed.Add(-time.Hour)))}, now, 1,
			"retain: acknowledgment line 1 names session a1 at a time earlier than its seal's"},
		{"after the clock", [][]byte{retentionAckLine(retentionAckKey, "a1", a1.signature, a1.finalCount, stampOf(now.Add(time.Hour)))}, now, 1,
			"retain: acknowledgment line 1 names session a1 at a time later than this command's clock"},
		{"inside the window", [][]byte{retentionAckLine(retentionAckKey, "a1", a1.signature, a1.finalCount, stampOf(sealed))}, sealed.Add(10 * 24 * time.Hour), 0,
			"retain: session a1 is within the retention window until " + stampOf(sealed.Add(30*24*time.Hour)) + "; it is kept"},
		{"an open session", [][]byte{retentionAckLine(retentionAckKey, "a2", a1.signature, a1.finalCount, stampOf(sealed))}, now, 1,
			"retain: acknowledgment line 1 names session a2, which is open; an open session is never removed"},
		{"another seal", [][]byte{retentionAckLine(retentionAckKey, "a1", p1.signature, a1.finalCount, stampOf(sealed))}, now, 1,
			"retain: acknowledgment line 1 names session a1 under another seal than the store holds"},
		{"no scope", [][]byte{retentionAckLine(retentionAckKey, "p1", p1.signature, p1.finalCount, stampOf(sealTime(t, p1)))}, sealTime(t, p1).Add(31 * 24 * time.Hour), 1,
			"retain: acknowledgment line 1 names session p1, which is of no scope identifier; it goes only with its whole store"},
	}
	keptSummary := map[string]string{
		"not acknowledged":  "retain: kept 3 sealed session(s): 3 named by no acknowledgment, 0 within the retention window",
		"inside the window": "retain: kept 3 sealed session(s): 2 named by no acknowledgment, 1 within the retention window",
	}
	for _, tc := range cases {
		code, stdout, stderr := runRetain(config, writeAcks(t, tc.lines...), tc.now)
		if code != tc.code || stdout != "" || !strings.Contains(stderr, tc.want+"\n") {
			t.Errorf("%s: %d %q %q", tc.name, code, stdout, stderr)
		}
		if kept := keptSummary[tc.name]; kept != "" && !strings.Contains(stderr, "retain: session b1 is named by no acknowledgment; it is kept\nretain: session p1 is named by no acknowledgment; it is kept\n"+kept+"\n") {
			t.Errorf("%s: the kept sessions are not named by reason and counted: %q", tc.name, stderr)
		}
		if tc.code == 1 && !strings.Contains(stderr, "retain: nothing was removed\n") {
			t.Errorf("%s: %q", tc.name, stderr)
		}
		if _, err := os.Stat(filepath.Join(g.storeRoot, removalsFile)); !os.IsNotExist(err) {
			t.Fatalf("%s: a removal file was written: %v", tc.name, err)
		}
		for _, kept := range []string{"a1", "a2", "b1", "p1"} {
			if _, err := os.Stat(filepath.Join(g.storeRoot, "receipts", kept)); err != nil {
				t.Fatalf("%s: %s: %v", tc.name, kept, err)
			}
		}
	}
}

// The retention member: a version of its own, refused by name under an
// earlier one; a window under 7 days refused; and none means nothing to
// retain by.
func TestEngineConfigRetentionMember(t *testing.T) {
	key := hex.EncodeToString(retentionAckKey.Public().(ed25519.PublicKey))
	var keys []string
	for i := byte(0); i < 5; i++ {
		keys = append(keys, hex.EncodeToString(ed25519.NewKeyFromSeed(bytes.Repeat([]byte{20 + i}, 32)).Public().(ed25519.PublicKey)))
	}
	root := t.TempDir()
	at := func(name string) string {
		text, err := json.Marshal(filepath.Join(root, name))
		if err != nil {
			t.Fatal(err)
		}
		return string(text)
	}
	base := func(version, retention string) string {
		return `{"engineVersion":"` + version + `","authority":"gateway:test","seed":` + at("s") + `,"store":` + at("st") + `,"registry":` + at("r") + `,"decisionRecords":` + at("d") + `,"listen":"127.0.0.1:8787","catalog":` + at("c") + `,"platforms":{}` + retention + `}`
	}
	cfg, err := parseEngineConfig([]byte(base(retentionVersion, `,"retention":{"window":7,"acknowledgedBy":["`+key+`"]}`)))
	if err != nil || cfg.retention == nil || cfg.retention.window != 7*24*time.Hour {
		t.Fatalf("a window of 7 days: %v %+v", err, cfg.retention)
	}
	for _, tc := range []struct{ text, want string }{
		{base("34", `,"retention":{"window":30,"acknowledgedBy":["`+key+`"]}`), "engine configuration: retention is a version-" + retentionVersion + " member; engineVersion 34 has no retention"},
		{base(retentionVersion, `,"retention":{"window":6,"acknowledgedBy":["`+key+`"]}`), "retention.window is a whole number of days from 7"},
		{base(retentionVersion, `,"retention":{"window":30,"acknowledgedBy":["`+strings.ToUpper(key)+`"]}`), "retention.acknowledgedBy[0] is an Ed25519 public key"},
		// the single-key string form is not read: the member is a list
		{base(retentionVersion, `,"retention":{"window":30,"acknowledgedBy":"`+key+`"}`), "retention.acknowledgedBy is a list of 1 to 4 Ed25519 public keys"},
		{base(retentionVersion, `,"retention":{"window":30,"acknowledgedBy":[]}`), "retention.acknowledgedBy is a list of 1 to 4 Ed25519 public keys"},
		{base(retentionVersion, `,"retention":{"window":30,"acknowledgedBy":["`+key+`","`+keys[1]+`","`+keys[2]+`","`+keys[3]+`","`+keys[4]+`"]}`), "retention.acknowledgedBy is a list of 1 to 4 Ed25519 public keys"},
		{base(retentionVersion, `,"retention":{"window":30,"acknowledgedBy":["`+keys[1]+`","`+key+`","`+key+`"]}`), "retention.acknowledgedBy[2] is listed twice"},
		{base(retentionVersion, `,"retention":{"window":30,"acknowledgedBy":["`+keys[1]+`",7]}`), "retention.acknowledgedBy[1] is an Ed25519 public key"},
		{base(retentionVersion, `,"retention":{"window":30}`), "retention"},
	} {
		if _, err := parseEngineConfig([]byte(tc.text)); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: %v", tc.text, err)
		}
	}
	if cfg, err := parseEngineConfig([]byte(base(retentionVersion, ""))); err != nil || cfg.retention != nil {
		t.Fatalf("no member: %v", err)
	}
}

func sha256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// relabelledAck is the line signed by signer with its keyId set to the id of
// named's key, so it names a listed key over another key's signature.
func relabelledAck(t *testing.T, line []byte, signer, named ed25519.PrivateKey) []byte {
	t.Helper()
	from := keyIDFor(signer.Public().(ed25519.PublicKey))
	to := keyIDFor(named.Public().(ed25519.PublicKey))
	if !bytes.Contains(line, []byte(from)) {
		t.Fatal("the line names no key id")
	}
	return bytes.Replace(line, []byte(from), []byte(to), 1)
}

// While the acknowledging log rotates its key, the configuration lists both:
// a line under either key verifies, and the call's summary names every key
// listed, in the configuration's order.
func TestRetainAcceptsALineUnderAnyListedKey(t *testing.T) {
	g, config := retainStore(t)
	newKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{8}, 32))
	oldHex := hex.EncodeToString(retentionAckKey.Public().(ed25519.PublicKey))
	newHex := hex.EncodeToString(newKey.Public().(ed25519.PublicKey))
	text := strings.Replace(readFile(t, config), `"acknowledgedBy":["`+oldHex+`"]`, `"acknowledgedBy":["`+oldHex+`","`+newHex+`"]`, 1)
	if err := os.WriteFile(config, []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
	a1 := sealOf(t, g.regPath, g.publicKey, "a1")
	b1 := sealOf(t, g.regPath, g.publicKey, "b1")
	now := sealTime(t, b1).Add(31 * 24 * time.Hour)
	acks := writeAcks(t,
		retentionAckLine(retentionAckKey, "a1", a1.signature, a1.finalCount, stampOf(sealTime(t, a1))),
		retentionAckLine(newKey, "b1", b1.signature, b1.finalCount, stampOf(sealTime(t, b1))))
	code, stdout, stderr := runRetain(config, acks, now)
	summary := "acknowledged by key(s) " + keyIDFor(retentionAckKey.Public().(ed25519.PublicKey)) + ", " + keyIDFor(newKey.Public().(ed25519.PublicKey)) + "\n"
	if code != 0 || strings.Count(stdout, `"kind":"session-removal"`) != 2 || !strings.Contains(stderr, summary) {
		t.Fatalf("retain under two keys: %d %q %q", code, stdout, stderr)
	}
}

// The worked example of docs/design/engine-config.md, under its synthetic
// key, verifies as the command reads a line, and the page carries it and its
// signing input byte for byte.
func TestTheDocumentedAcknowledgmentLineVerifies(t *testing.T) {
	const (
		public = "ea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421eea691446d22c"
		input  = `judgment-pack-gateway/retention-ack/1:{"acknowledgedAt":"2026-11-20T10:00:00Z","finalCount":3,"keyId":"fe812c12f3ab4ce6ac5db69ac352f906","kind":"retention-ack","sealSignature":"abababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababab","sessionId":"example-session-1"}`
		line   = `{"acknowledgedAt":"2026-11-20T10:00:00Z","finalCount":3,"keyId":"fe812c12f3ab4ce6ac5db69ac352f906","kind":"retention-ack","sealSignature":"abababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababab","sessionId":"example-session-1","signature":"828e0a5478f544ff5e6a083964b1e3b8dce742c8eadc44bb07bb2853b8508dce5b6678b17a0d348310313ccdba19bda520266e11affc462ec2d23191411b8204"}`
	)
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{7}, 32))
	if hex.EncodeToString(key.Public().(ed25519.PublicKey)) != public {
		t.Fatal("the synthetic key is not the documented one")
	}
	cfg, err := parseRetentionConfig(mustParse(t, `{"window":30,"acknowledgedBy":["`+public+`"]}`))
	if err != nil {
		t.Fatal(err)
	}
	ack, why := retentionAckOf([]byte(line), cfg)
	if why != "" || ack.sessionID != "example-session-1" || ack.finalCount != 3 {
		t.Fatalf("the documented line: %q %+v", why, ack)
	}
	obj := mustParse(t, line).(*vObject)
	if got := string(recordSigningInput(retentionAckContext, obj)); got != input {
		t.Fatalf("the signing input is not the documented one:\n%s", got)
	}
	if got := string(retentionAckLine(key, "example-session-1", strings.Repeat("ab", 64), 3, "2026-11-20T10:00:00Z")); got != line+"\n" {
		t.Fatalf("the line signed again differs:\n%s", got)
	}
	page := readFile(t, filepath.Join("..", "docs", "design", "engine-config.md"))
	for _, want := range []string{input, line, public, "fe812c12f3ab4ce6ac5db69ac352f906"} {
		if !strings.Contains(page, want) {
			t.Fatalf("docs/design/engine-config.md does not carry %q", want)
		}
	}
}

func mustParse(t *testing.T, text string) value {
	t.Helper()
	v, err := parseJSON([]byte(text))
	if err != nil {
		t.Fatal(err)
	}
	return v
}

// retainUnlockedLine is the note gateway retain gives on a platform that
// locks no registry, "" where it locks one.
func retainUnlockedLine() string {
	if registryLocked {
		return ""
	}
	return "retain: this platform locks no registry, so a gateway still running was not looked for; the gateway was to be stopped\n"
}
