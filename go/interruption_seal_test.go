package main

// The seal made after an interruption (gateway #395; SPEC.md §3c): the
// registry line, how each reader loads it, and what verification says of
// the session it anchors -- sealed, observed so, and a finding only under
// --ordinary-seals-only.

import (
	"crypto/ed25519"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// interruptionSealLineBy is a seal made after an interruption written by
// hand from SPEC.md §3c's signed bytes, not by the code under test: the
// members in code-point order, then the signature, which sorts after them.
func interruptionSealLineBy(signer ed25519.PrivateKey, keyID, session string, count int64, head, at, via string) string {
	body := fmt.Sprintf(`{"finalCount":%d,"headSignature":"%s","keyId":"%s","kind":"seal-after-interruption","sealedAt":"%s","sealedVia":"%s","sessionId":"%s"}`,
		count, head, keyID, at, via, session)
	signature := ed25519.Sign(signer, []byte("judgment-pack-gateway/seal-after-interruption/1:"+body))
	return body[:len(body)-1] + fmt.Sprintf(`,"signature":"%x"}`, signature)
}

// ordinarySealLineBy is a seal of SPEC.md §3's form, written by hand.
func ordinarySealLineBy(signer ed25519.PrivateKey, session string, count int64, at string) string {
	keyID := keyIDFor(publicOf(signer))
	body := fmt.Sprintf(`{"finalCount":%d,"keyId":"%s","sealedAt":"%s","sessionId":"%s"}`, count, keyID, at, session)
	signature := ed25519.Sign(signer, []byte("judgment-pack-gateway/seal/2:"+body))
	return body[:len(body)-1] + fmt.Sprintf(`,"signature":"%x"}`, signature)
}

// receiptSignature is the signature member of a receipt file as written.
func receiptSignature(t *testing.T, storeRoot, session string, index int) string {
	t.Helper()
	signature, ok := topLevelSignature([]byte(readFile(t, filepath.Join(storeRoot, "receipts", session, fmt.Sprintf("%d.json", index)))))
	if !ok {
		t.Fatalf("receipt %s/%d has no signature", session, index)
	}
	return signature
}

// interruptedLines is a report's sealed-after-interruption observations,
// in the order given.
func interruptedLines(rep *report) []string {
	var lines []string
	for _, o := range rep.Observations {
		if o["observation"] == "sealed-after-interruption" {
			lines = append(lines, fmt.Sprintf("%v/%v/%v", o["sessionId"], o["callIndex"], o["observation"]))
		}
	}
	return lines
}

// leftOpenStore is a store an earlier gateway left: session "left" with two
// receipts and no seal, and session "closed" sealed with one. The registry
// holds only the ordinary seal.
func leftOpenStore(t *testing.T) *gatewayService {
	t.Helper()
	g, server := testService(t)
	for _, body := range []string{
		`{"session":"left","source":"screening","arguments":{"q":"x"}}`,
		`{"session":"left","source":"screening","arguments":{"q":"y"}}`,
		`{"session":"closed","source":"screening","arguments":{"q":"x"}}`,
	} {
		if code, out := post(t, server, "/acquire", body); code != http.StatusOK {
			t.Fatalf("acquire %s: %d %v", body, code, out)
		}
	}
	if code, out := post(t, server, "/seal", `{"session":"closed"}`); code != http.StatusOK {
		t.Fatalf("seal: %d %v", code, out)
	}
	server.Close()
	return g
}

func appendRegistry(t *testing.T, path string, lines ...string) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	for _, line := range lines {
		if _, err := f.WriteString(line + "\n"); err != nil {
			t.Fatal(err)
		}
	}
}

// A session left open and sealed after the interruption, over the two
// receipts the store holds, verifies: the store-wide verdict is ok again,
// and the session is observed sealed-after-interruption on its last
// receipt. Under --ordinary-seals-only the observation is a finding, and
// the verdict is not ok. Both verdicts are pinned byte for byte.
func TestASealAfterInterruptionAnchorsTheSessionItSeals(t *testing.T) {
	g := leftOpenStore(t)
	priv := ed25519.NewKeyFromSeed(testSeed)
	head := receiptSignature(t, g.storeRoot, "left", 1)
	appendRegistry(t, g.regPath, interruptionSealLineBy(priv, g.keyID, "left", 2, head, "2026-11-10T00:00:00Z", "command"))

	rep, err := verifyWithRegistry(g.storeRoot, g.regPath, "gateway:test", g.publicKey)
	if err != nil {
		t.Fatal(err)
	}
	out, _ := rep.marshal()
	const plain = `{"ok":true,"findings":[{"callIndex":0,"sessionId":"closed","status":"ok"},{"callIndex":0,"sessionId":"left","status":"ok"},{"callIndex":1,"sessionId":"left","status":"ok"}],"observations":[{"callIndex":1,"observation":"sealed-after-interruption","sessionId":"left"}]}`
	if string(out) != plain {
		t.Fatalf("verdict:\n got %s\nwant %s", out, plain)
	}

	strict, err := verifyOrdinarySealsOnly(g.storeRoot, g.regPath, "gateway:test", "", g.publicKey)
	if err != nil {
		t.Fatal(err)
	}
	out, _ = strict.marshal()
	const ordinaryOnly = `{"ok":false,"findings":[{"callIndex":0,"sessionId":"closed","status":"ok"},{"callIndex":0,"sessionId":"left","status":"ok"},{"callIndex":1,"sessionId":"left","status":"ok"},{"sessionId":"left","status":"sealed-after-interruption"}]}`
	if string(out) != ordinaryOnly {
		t.Fatalf("--ordinary-seals-only verdict:\n got %s\nwant %s", out, ordinaryOnly)
	}

	// the engine's own /verify is the plain verdict
	engine, err := verifyAsEngine(g.storeRoot, g.regPath, "gateway:test", "", g.publicKey)
	if err != nil {
		t.Fatal(err)
	}
	if out, _ := engine.marshal(); string(out) != plain {
		t.Fatalf("engine verdict: %s", out)
	}
}

// What a line must be to load as a seal made after an interruption, and
// what verification finds of the session it anchors when its count or its
// last receipt does not hold. Each row is one check a reader could drop.
func TestWhatASealAfterInterruptionMustBeAndWhatItIsHeldTo(t *testing.T) {
	g := leftOpenStore(t)
	priv := ed25519.NewKeyFromSeed(testSeed)
	other := rotationKey("not the gateway's")
	head := receiptSignature(t, g.storeRoot, "left", 1)
	first := receiptSignature(t, g.storeRoot, "left", 0)
	const at = "2026-11-10T00:00:00Z"
	line := func(session string, count int64, head, at, via string) string {
		return interruptionSealLineBy(priv, g.keyID, session, count, head, at, via)
	}
	good := line("left", 2, head, at, "command")
	// edit is a good line with one member's text replaced and signed again,
	// so only the form can refuse it
	resigned := func(from, to string) string {
		body := strings.Replace(good[:strings.Index(good, `,"signature":`)]+"}", from, to, 1)
		signature := ed25519.Sign(priv, []byte("judgment-pack-gateway/seal-after-interruption/1:"+canonOfText(t, body)))
		return body[:len(body)-1] + fmt.Sprintf(`,"signature":"%x"}`, signature)
	}
	unsealed := []string{"closed/0/ok", "left/0/ok", "left/1/ok", "left/<nil>/unregistered-session"}
	sealed := []string{"closed/0/ok", "left/0/ok", "left/1/ok"}
	observed := []string{"left/1/sealed-after-interruption"}
	open := []string{"left/1/session-open"}
	type row struct {
		name     string
		lines    []string
		findings []string
		open     []string
		observed []string
	}
	rows := []row{
		{"the seal, signed by the gateway's key", []string{good}, sealed, nil, observed},
		{"sealed by the gateway's start", []string{line("left", 2, head, at, "start")}, sealed, nil, observed},
		{"signed by another key", []string{interruptionSealLineBy(other, g.keyID, "left", 2, head, at, "command")}, unsealed, open, nil},
		{"naming another key's id", []string{interruptionSealLineBy(priv, keyIDFor(publicOf(other)), "left", 2, head, at, "command")}, unsealed, open, nil},
		{"signed under the ordinary seal's context", []string{strings.Replace(good, good[strings.Index(good, `"signature":"`)+13:len(good)-2], fmt.Sprintf("%x", ed25519.Sign(priv, sealSigningInput("left", 2, at, g.keyID))), 1)}, unsealed, open, nil},
		{"its signature altered", []string{good[:len(good)-3] + flipHex(good[len(good)-3:len(good)-2]) + `"}`}, unsealed, open, nil},
		{"a member more", []string{resigned(`"finalCount":2,`, `"extra":1,"finalCount":2,`)}, unsealed, open, nil},
		{"sealedVia missing", []string{resigned(`,"sealedVia":"command"`, ``)}, unsealed, open, nil},
		{"sealedVia of no kind", []string{resigned(`"sealedVia":"command"`, `"sealedVia":"operator"`)}, unsealed, open, nil},
		{"finalCount zero", []string{resigned(`"finalCount":2`, `"finalCount":0`)}, unsealed, open, nil},
		{"finalCount a string", []string{resigned(`"finalCount":2`, `"finalCount":"2"`)}, unsealed, open, nil},
		{"headSignature in uppercase", []string{resigned(head, strings.ToUpper(head))}, unsealed, open, nil},
		{"headSignature short", []string{resigned(head, head[:126])}, unsealed, open, nil},
		{"keyId in uppercase", []string{interruptionSealLineBy(priv, strings.ToUpper(g.keyID), "left", 2, head, at, "command")}, unsealed, open, nil},
		{"sealedAt of another form", []string{line("left", 2, head, "2026-11-10 00:00:00Z", "command")}, unsealed, open, nil},
		{"a session id §3a refuses", []string{line("left/..", 2, head, at, "command")}, unsealed, open, nil},
		{"its signature in uppercase", []string{good[:strings.Index(good, `"signature":"`)+13] + strings.ToUpper(good[strings.Index(good, `"signature":"`)+13:len(good)-2]) + `"}`}, unsealed, open, nil},
		{"counting a receipt fewer", []string{line("left", 1, first, at, "command")}, append(sealed, "left/<nil>/count-exceeds-seal"), nil, nil},
		{"counting a receipt more", []string{line("left", 3, head, at, "command")}, append(sealed, "left/<nil>/tail-rollback"), nil, nil},
		{"naming another receipt as the last", []string{line("left", 2, first, at, "command")}, append(sealed, "left/<nil>/seal-head-mismatch"), nil, nil},
		{"two seals made after an interruption", []string{good, line("left", 2, head, "2026-11-10T00:00:01Z", "start")}, append(sealed, "left/<nil>/seal-conflict"), nil, observed},
		{"an ordinary seal after it", []string{good, ordinarySealLineBy(priv, "left", 2, at)}, append(sealed, "left/<nil>/seal-conflict"), nil, observed},
		{"an ordinary seal before it", []string{ordinarySealLineBy(priv, "left", 2, at), good}, append(sealed, "left/<nil>/seal-conflict"), nil, nil},
		{"two ordinary seals, as ever", []string{ordinarySealLineBy(priv, "left", 2, at), ordinarySealLineBy(priv, "left", 2, "2026-11-10T00:00:01Z")}, sealed, nil, nil},
		{"a conflicting seal that does not load is none", []string{good, interruptionSealLineBy(other, g.keyID, "left", 2, head, at, "start")}, sealed, nil, observed},
		{"a session the store does not hold", []string{line("gone", 1, head, at, "command")}, append(append([]string{}, unsealed...), "gone/<nil>/sealed-session-missing"), open, nil},
		{"a session the store does not hold, sealed twice", []string{line("gone", 1, head, at, "command"), line("gone", 1, head, at, "start")}, append(append([]string{}, unsealed...), "gone/<nil>/sealed-session-missing", "gone/<nil>/seal-conflict"), open, nil},
	}
	before := readFile(t, g.regPath)
	for _, r := range rows {
		if err := os.WriteFile(g.regPath, []byte(before+strings.Join(r.lines, "\n")+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		rep, err := verifyWithRegistry(g.storeRoot, g.regPath, "gateway:test", g.publicKey)
		if err != nil {
			t.Fatalf("%s: no verdict: %v", r.name, err)
		}
		findings, gotOpen := verdictLines(t, rep)
		want := append([]string{}, r.findings...)
		sort.Strings(want)
		if strings.Join(findings, " ") != strings.Join(want, " ") ||
			strings.Join(gotOpen, " ") != strings.Join(r.open, " ") ||
			strings.Join(interruptedLines(rep), " ") != strings.Join(r.observed, " ") {
			t.Errorf("%s:\n got %v open %v observed %v\nwant %v open %v observed %v", r.name, findings, gotOpen, interruptedLines(rep), want, r.open, r.observed)
		}
		wantOK := len(want) == len(sealed) && strings.Join(want, " ") == strings.Join(sealed, " ")
		if rep.OK != wantOK {
			t.Errorf("%s: ok = %v, want %v", r.name, rep.OK, wantOK)
		}
	}
}

// canonOfText is the canonical text of a JSON object given as text.
func canonOfText(t *testing.T, text string) string {
	t.Helper()
	v, err := parseJSON([]byte(text))
	if err != nil {
		t.Fatalf("%s: %v", text, err)
	}
	return string(canon(v))
}

// flipHex is a hex digit other than the one given.
func flipHex(d string) string {
	if d == "0" {
		return "1"
	}
	return "0"
}

// A receipt added to the session after the seal, and the session's last
// receipt replaced, are found; a staging file an interrupted write left is
// no receipt and changes nothing.
func TestASealAfterInterruptionCatchesWhatChangesAfterIt(t *testing.T) {
	g := leftOpenStore(t)
	priv := ed25519.NewKeyFromSeed(testSeed)
	head := receiptSignature(t, g.storeRoot, "left", 1)
	appendRegistry(t, g.regPath, interruptionSealLineBy(priv, g.keyID, "left", 2, head, "2026-11-10T00:00:00Z", "command"))
	dir := filepath.Join(g.storeRoot, "receipts", "left")

	if err := os.WriteFile(filepath.Join(dir, "2.json.12.ab.tmp"), []byte(`{"torn`), 0o600); err != nil {
		t.Fatal(err)
	}
	rep, err := verifyWithRegistry(g.storeRoot, g.regPath, "gateway:test", g.publicKey)
	if err != nil {
		t.Fatal(err)
	}
	if !rep.OK || strings.Join(interruptedLines(rep), " ") != "left/1/sealed-after-interruption" {
		t.Fatalf("a staging file beside the session: ok=%v observed %v", rep.OK, interruptedLines(rep))
	}

	if err := os.WriteFile(filepath.Join(dir, "2.json"), []byte(readFile(t, filepath.Join(dir, "1.json"))), 0o600); err != nil {
		t.Fatal(err)
	}
	rep, err = verifyWithRegistry(g.storeRoot, g.regPath, "gateway:test", g.publicKey)
	if err != nil {
		t.Fatal(err)
	}
	findings, _ := verdictLines(t, rep)
	if rep.OK || !contains(findings, "left/<nil>/count-exceeds-seal") || len(interruptedLines(rep)) != 0 {
		t.Fatalf("a receipt added after the seal: ok=%v %v %v", rep.OK, findings, interruptedLines(rep))
	}
	os.Remove(filepath.Join(dir, "2.json"))

	// the last receipt replaced by the first one's bytes: the count holds,
	// the receipt does not, and neither does the seal's last receipt
	if err := os.WriteFile(filepath.Join(dir, "1.json"), []byte(readFile(t, filepath.Join(dir, "0.json"))), 0o600); err != nil {
		t.Fatal(err)
	}
	rep, err = verifyWithRegistry(g.storeRoot, g.regPath, "gateway:test", g.publicKey)
	if err != nil {
		t.Fatal(err)
	}
	findings, _ = verdictLines(t, rep)
	if rep.OK || !contains(findings, "left/<nil>/seal-head-mismatch") || len(interruptedLines(rep)) != 0 {
		t.Fatalf("the last receipt replaced: ok=%v %v %v", rep.OK, findings, interruptedLines(rep))
	}
}

// gateway verify --ordinary-seals-only: the option first, or not at all. The
// verdict it writes is the strict one, byte for byte; without it, the plain
// one. The option in a later place is a usage error, exit 2 with nothing on
// stdout -- never taken as the decision-record directory with the plain
// verdict run -- and a directory so spelled is given as
// ./--ordinary-seals-only.
func TestVerifyOrdinarySealsOnlyOnTheCommandLine(t *testing.T) {
	g := leftOpenStore(t)
	priv := ed25519.NewKeyFromSeed(testSeed)
	appendRegistry(t, g.regPath, interruptionSealLineBy(priv, g.keyID, "left", 2, receiptSignature(t, g.storeRoot, "left", 1), "2026-11-10T00:00:00Z", "command"))
	stderr := captureStderr(t)
	oldStdin, oldStdout := os.Stdin, os.Stdout
	t.Cleanup(func() { os.Stdin, os.Stdout = oldStdin, oldStdout })
	run := func(args ...string) (int, string) {
		t.Helper()
		dir := t.TempDir()
		in, err := os.Create(filepath.Join(dir, "key"))
		if err != nil {
			t.Fatal(err)
		}
		defer in.Close()
		if _, err := in.WriteString(mustPublic(t)); err != nil {
			t.Fatal(err)
		}
		in.Seek(0, 0)
		out, err := os.Create(filepath.Join(dir, "out"))
		if err != nil {
			t.Fatal(err)
		}
		defer out.Close()
		os.Stdin, os.Stdout = in, out
		code := cmdVerify(args)
		os.Stdin, os.Stdout = oldStdin, oldStdout
		return code, readFile(t, out.Name())
	}
	const strict = `{"ok":false,"findings":[{"callIndex":0,"sessionId":"closed","status":"ok"},{"callIndex":0,"sessionId":"left","status":"ok"},{"callIndex":1,"sessionId":"left","status":"ok"},{"sessionId":"left","status":"sealed-after-interruption"}]}` + "\n"
	const plain = `{"ok":true,"findings":[{"callIndex":0,"sessionId":"closed","status":"ok"},{"callIndex":0,"sessionId":"left","status":"ok"},{"callIndex":1,"sessionId":"left","status":"ok"}],"observations":[{"callIndex":1,"observation":"sealed-after-interruption","sessionId":"left"}]}` + "\n"
	if code, out := run("--ordinary-seals-only", g.storeRoot, g.regPath, "gateway:test"); code != 0 || out != strict {
		t.Fatalf("--ordinary-seals-only: %d %s", code, out)
	}
	if code, out := run(g.storeRoot, g.regPath, "gateway:test"); code != 0 || out != plain {
		t.Fatalf("plain: %d %s", code, out)
	}
	const notFirst = "gateway verify: --ordinary-seals-only goes first, before the store root; a directory so named is given as ./--ordinary-seals-only\n" +
		"usage: gateway verify [--ordinary-seals-only] <store-root> <registry-path> <authority> [--decision-records <dir> | <dir>]\n"
	for name, args := range map[string][]string{
		"a fourth argument":               {g.storeRoot, g.regPath, "gateway:test", "--ordinary-seals-only"},
		"the value of --decision-records": {g.storeRoot, g.regPath, "gateway:test", "--decision-records", "--ordinary-seals-only"},
		"second, after a store root":      {g.storeRoot, "--ordinary-seals-only", g.regPath, "gateway:test"},
		"first and again":                 {"--ordinary-seals-only", "--ordinary-seals-only", g.storeRoot, g.regPath, "gateway:test"},
		"first and as a fourth argument":  {"--ordinary-seals-only", g.storeRoot, g.regPath, "gateway:test", "--ordinary-seals-only"},
	} {
		before := stderr()
		code, out := run(args...)
		if got := strings.TrimPrefix(stderr(), before); code != 2 || out != "" || got != notFirst {
			t.Fatalf("--ordinary-seals-only as %s: %d %q %q", name, code, out, got)
		}
	}
	if code, out := run(g.storeRoot, g.regPath, "gateway:test", "./--ordinary-seals-only"); code != 0 || out != plain {
		t.Fatalf("a decision-record directory given as ./--ordinary-seals-only: %d %s", code, out)
	}
	if code, _ := run("--ordinary-seals-only", g.storeRoot, g.regPath); code != 2 {
		t.Fatalf("--ordinary-seals-only and two arguments: %d, want usage", code)
	}
}

// The verification rows shared with the TypeScript reader
// (testdata/interruption-seal/cases.json): a corpus vector, edited as the
// row says, verified plain or with --ordinary-seals-only, and its ok, its
// findings as sorted lines, and its session-open and
// sealed-after-interruption observations, in the order given. The corpus
// runner compares observations only where a vector states them (SPEC.md
// §7); these rows hold more of the same stores than a vector does.
func TestInterruptionSealSharedRows(t *testing.T) {
	publicKey := mustHex(t, strings.TrimSpace(readFile(t, corpusPath("TEST-PUBLIC-KEY"))))
	var rows []struct {
		Name              string   `json:"name"`
		Vector            string   `json:"vector"`
		Registry          *string  `json:"registry"`
		Remove            []string `json:"remove"`
		Tear              []string `json:"tear"`
		OrdinarySealsOnly bool     `json:"ordinarySealsOnly"`
		OK                bool     `json:"ok"`
		Findings          []string `json:"findings"`
		Observations      []string `json:"observations"`
	}
	readJSON(t, filepath.Join("..", "testdata", "interruption-seal", "cases.json"), &rows)
	if len(rows) == 0 {
		t.Fatal("no rows")
	}
	for _, row := range rows {
		var vec storeVector
		readJSON(t, corpusPath(filepath.FromSlash(row.Vector)), &vec)
		if row.Registry != nil {
			vec.Registry = *row.Registry
		}
		for _, file := range row.Remove {
			if _, there := vec.Files[file]; !there {
				t.Fatalf("%s: the vector holds no %s", row.Name, file)
			}
			delete(vec.Files, file)
		}
		for _, file := range row.Tear {
			text, there := vec.Files[file]
			if !there {
				t.Fatalf("%s: the vector holds no %s", row.Name, file)
			}
			vec.Files[file] = text[:len(text)/2]
		}
		tmp, root, registryPath, decisionRecords, err := materializeVector(vec)
		if err != nil {
			t.Fatal(err)
		}
		verify := verifyWithRegistryAndRecords
		if row.OrdinarySealsOnly {
			verify = verifyOrdinarySealsOnly
		}
		rep, err := verify(root, registryPath, vec.Authority, decisionRecords, publicKey)
		os.RemoveAll(tmp)
		if err != nil {
			t.Fatalf("%s: no verdict: %v", row.Name, err)
		}
		findings, _ := verdictLines(t, rep)
		var observations []string
		for _, o := range rep.Observations {
			if o["observation"] == "session-open" || o["observation"] == "sealed-after-interruption" {
				observations = append(observations, fmt.Sprintf("%v/%v/%v", o["sessionId"], o["callIndex"], o["observation"]))
			}
		}
		want := append([]string{}, row.Findings...)
		sort.Strings(want)
		if rep.OK != row.OK || strings.Join(findings, " ") != strings.Join(want, " ") || strings.Join(observations, " ") != strings.Join(row.Observations, " ") {
			t.Errorf("%s:\n got ok=%v %v %v\nwant ok=%v %v %v", row.Name, rep.OK, findings, observations, row.OK, want, row.Observations)
		}
	}
}
