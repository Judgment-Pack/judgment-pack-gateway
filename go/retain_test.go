package main

// gateway retain (ADR-0048, A1 and R1; retain.go): a sealed session removed
// under a signed acknowledgment once the window has passed, recorded as
// ADR-0034's session-removal record alone, and every refusal by name.

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
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
func retainStore(t *testing.T) (*gatewayService, string) {
	t.Helper()
	g, seedPath := scopeStore(t, [3]string{"p1", "plain", "only-p"})
	server := httptest.NewServer(g.handler())
	if code, out := post(t, server, "/seal", `{"session":"p1"}`); code != http.StatusOK {
		t.Fatalf("seal p1: %d %v", code, out)
	}
	server.Close()
	dir := t.TempDir()
	config := filepath.Join(dir, "engine.json")
	body := fmt.Sprintf(`{"engineVersion":%q,"authority":"gateway:test","seed":%q,"store":%q,"registry":%q,"decisionRecords":%q,"listen":"127.0.0.1:8787","catalog":%q,"platforms":{},"retention":{"window":30,"acknowledgedBy":%q}}`,
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
	summary := "retain: " + retentionSummary(1, "sha256:"+sum, keyIDFor(retentionAckKey.Public().(ed25519.PublicKey))) + "\n"
	if code != 0 || !strings.Contains(stderr, "retain: removed 1 session(s), holding 2 receipt(s)") || !strings.HasSuffix(strings.TrimSuffix(stderr, scopeUnlockedLine()), summary) {
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
	base := func(version, retention string) string {
		return `{"engineVersion":"` + version + `","authority":"gateway:test","seed":"/s","store":"/st","registry":"/r","decisionRecords":"/d","listen":"127.0.0.1:8787","catalog":"/c","platforms":{}` + retention + `}`
	}
	cfg, err := parseEngineConfig([]byte(base(retentionVersion, `,"retention":{"window":7,"acknowledgedBy":"`+key+`"}`)))
	if err != nil || cfg.retention == nil || cfg.retention.window != 7*24*time.Hour {
		t.Fatalf("a window of 7 days: %v %+v", err, cfg.retention)
	}
	for _, tc := range []struct{ text, want string }{
		{base("34", `,"retention":{"window":30,"acknowledgedBy":"`+key+`"}`), "engine configuration: retention is a version-" + retentionVersion + " member; engineVersion 34 has no retention"},
		{base(retentionVersion, `,"retention":{"window":6,"acknowledgedBy":"`+key+`"}`), "retention.window is a whole number of days from 7"},
		{base(retentionVersion, `,"retention":{"window":30,"acknowledgedBy":"`+strings.ToUpper(key)+`"}`), "retention.acknowledgedBy is an Ed25519 public key"},
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
