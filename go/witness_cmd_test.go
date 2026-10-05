//go:build unix

package main

// The witness operator's acts (witness_cmd.go): `gateway witness register`,
// `retire` and `repair`, each against a stopped witness, where it acts, and
// a running one, which holds its files, where it refuses and changes
// nothing; and `serve --config` with a witness, refusing marks on the log's
// device, and opening the witness before the store is made.

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

// witnessEngineFile writes an engine configuration making the witness's
// files tw's, under the corpus's test seed, and returns its path.
func witnessEngineFile(t *testing.T, tw *testWitness, extra string) string {
	t.Helper()
	dir := tempDirAt(t, 0o700)
	seed := filepath.Join(dir, "gateway.seed")
	if err := os.WriteFile(seed, []byte(hex.EncodeToString(tw.signer.seed)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	text := `{"engineVersion":"6","authority":"gateway:witness","seed":"` + seed + `","store":"` + filepath.Join(dir, "store") + `",` +
		`"registry":"` + filepath.Join(dir, "registry.jsonl") + `","decisionRecords":"` + filepath.Join(dir, "decisions") + `","listen":"127.0.0.1:8787",` +
		`"catalog":"` + filepath.Join(dir, "catalog") + `",` +
		`"identity":{"issuer":"` + witnessIssuer + `","audience":"gateway:witness","keys":"` + filepath.Join(dir, "keys.json") + `"},` +
		`"witness":{"log":"` + tw.paths.log + `","marks":"` + tw.paths.marks + `"` + extra + `},"platforms":{}}`
	path := filepath.Join(dir, "engine.json")
	if err := os.WriteFile(path, []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// act runs `gateway witness` with args, and gives its exit code and what it
// wrote.
func act(args ...string) (int, string, string) {
	var stdout, stderr bytes.Buffer
	code := cmdWitness(args, &stdout, &stderr)
	return code, stdout.String(), stderr.String()
}

// files is the witness's files as they are, joined, to compare before and
// after an act.
func (tw *testWitness) files(t *testing.T) string {
	t.Helper()
	return tw.read(t, "log") + "|" + tw.read(t, "marks") + "|" + tw.read(t, "registrations") + "|" + tw.read(t, "setAside")
}

// Each act on a stopped witness: register appends the registration; retire
// signs the trail's retirement, made durable and marked, and prints it, and
// a second retire signs nothing; repair says what the rules allowed and
// whether the witness starts, and writes nothing where it may not.
func TestWitnessActsOnAStoppedWitness(t *testing.T) {
	tw := newTestWitness(t)
	config := witnessEngineFile(t, tw, "")
	if code, out, errText := act("register", "--config", config, "--trail", testTrail, "--issuer", witnessIssuer, "--subject", subjectOf(testTrail)); code != 0 || !strings.Contains(out, "registered trail "+testTrail) {
		t.Fatalf("register: %d %s %s", code, out, errText)
	}
	if got, want := tw.read(t, "registrations"), string(registrationLine(witnessRegistration{trail: testTrail, issuer: witnessIssuer, subject: subjectOf(testTrail)})); got != want {
		t.Fatalf("the registration: %s", firstDifference(want, got))
	}
	w := tw.open(t)
	mustSign(t, w, testTrail, 10)
	mustSign(t, w, testTrail, 20)
	w.close()

	code, out, errText := act("retire", "--config", config, "--trail", testTrail)
	if code != 0 || errText != "" {
		t.Fatalf("retire: %d %s", code, errText)
	}
	st := statementOf(t, []byte(strings.TrimSuffix(out, "\n")))
	if st.kind != "retirement" || st.index != 2 || st.sequence != 20 || !strings.HasSuffix(tw.read(t, "log"), out) {
		t.Fatalf("retire printed a %s at %d over %d, the log ending in it %v", st.kind, st.index, st.sequence, strings.HasSuffix(tw.read(t, "log"), out))
	}
	if outcome, findings := tw.judge(t); outcome != outcomeStart || len(findings) > 0 {
		t.Fatalf("after a retirement the checks find %s %v", outcome, findings)
	}
	before := tw.files(t)
	again, againOut, againErr := act("retire", "--config", config, "--trail", testTrail)
	if again != 0 || againOut != out || !strings.Contains(againErr, "retired already") || tw.files(t) != before {
		t.Fatalf("a second retire: %d, the same line %v, %s, wrote %v", again, againOut == out, againErr, tw.files(t) != before)
	}
	if code, _, errText := act("retire", "--config", config, "--trail", trailB); code != 1 || !strings.Contains(errText, "no checkpoint statement to retire") || tw.files(t) != before {
		t.Fatalf("retiring a trail with nothing: %d %s", code, errText)
	}

	repair := func() (int, witnessRepairReport, string) {
		code, out, errText := act("repair", "--config", config)
		var report witnessRepairReport
		if err := json.Unmarshal([]byte(out), &report); err != nil {
			t.Fatalf("repair printed no report: %d %.200q %s", code, out, errText)
		}
		return code, report, errText
	}
	if code, report, _ := repair(); code != 0 || report.Outcome != outcomeStart || report.Repaired || !report.Starts || len(report.Findings) != 0 || tw.files(t) != before {
		t.Fatalf("repair of a sound witness: %d %+v", code, report)
	}
	tw.write(t, "log", tw.read(t, "log")+`{"checkpoint":{"checkp`)
	if code, report, _ := repair(); code != 0 || report.Outcome != outcomeSetAside || !report.Repaired || !report.Starts || tw.read(t, "log") != strings.Split(before, "|")[0] || tw.read(t, "setAside") == "<absent>" {
		t.Fatalf("repair of torn last bytes: %d %+v", code, report)
	}
	if err := os.Remove(tw.paths.marks); err != nil {
		t.Fatal(err)
	}
	lost := tw.files(t)
	code, report, errText := repair()
	if code != 1 || report.Outcome != outcomeNewKey || report.Repaired || report.Starts || !strings.Contains(errText, "new key") || tw.files(t) != lost {
		t.Fatalf("repair of a witness that lost its marks: %d %+v %s, wrote %v", code, report, errText, tw.files(t) != lost)
	}
}

// Each act on a running witness: the witness holds its files, so the act
// says so and changes nothing; stopped, the same act goes through.
func TestWitnessActsOnARunningWitness(t *testing.T) {
	tw := newTestWitness(t, testTrail)
	config := witnessEngineFile(t, tw, "")
	w := tw.open(t)
	mustSign(t, w, testTrail, 10)
	before := tw.files(t)
	for _, args := range [][]string{
		{"register", "--config", config, "--trail", trailB, "--issuer", witnessIssuer, "--subject", subjectOf(trailB)},
		{"retire", "--config", config, "--trail", testTrail},
		{"repair", "--config", config},
	} {
		code, out, errText := act(args...)
		if code != 1 || out != "" || !strings.Contains(errText, "a running witness, or another act on it, holds the witness's files") || !strings.Contains(errText, "nothing was changed") {
			t.Fatalf("%s on a running witness: %d %q %s", args[0], code, out, errText)
		}
		if tw.files(t) != before {
			t.Fatalf("%s on a running witness changed its files", args[0])
		}
	}
	w.close()
	if code, _, errText := act("register", "--config", config, "--trail", trailB, "--issuer", witnessIssuer, "--subject", subjectOf(trailB)); code != 0 {
		t.Fatalf("register once the witness stopped: %d %s", code, errText)
	}
	if code, _, errText := act("retire", "--config", config, "--trail", testTrail); code != 0 {
		t.Fatalf("retire once the witness stopped: %d %s", code, errText)
	}
}

// What an act refuses before it touches anything: its usage; a
// registration no token could match -- another issuer, a subject the
// configuration does not allow; and a configuration with no witness.
func TestWitnessActRefusals(t *testing.T) {
	tw := newTestWitness(t)
	config := witnessEngineFile(t, tw, `,"submitters":[{"issuer":"`+witnessIssuer+`","subject":"deliverer-a"}]`)
	for _, args := range [][]string{
		nil,
		{"rotate", "--config", config},
		{"register", "--config", config, "--trail", testTrail, "--issuer", witnessIssuer},
		{"register", "--config", config, "--config", config, "--trail", testTrail, "--issuer", witnessIssuer, "--subject", "deliverer-a"},
		{"register", "--config", config, "--trail", testTrail, "--issuer", witnessIssuer, "--subject", "deliverer-a", "--marks", "x"},
		{"register", "--config", config, "--trail", strings.ToUpper(testTrail), "--issuer", witnessIssuer, "--subject", "deliverer-a"},
		{"retire", "--config", config, "--trail", testTrail[:31]},
		{"retire", "--config", config},
		{"repair", "--config", config, "--trail", testTrail},
		{"repair", "--config"},
		{"verify", "--config", config},
	} {
		if code, _, _ := act(args...); code != 2 {
			t.Fatalf("%v: exit %d, want 2", args, code)
		}
	}
	for _, c := range []struct {
		args []string
		want string
	}{
		{[]string{"register", "--config", config, "--trail", testTrail, "--issuer", "https://other.example", "--subject", "deliverer-a"}, "this engine takes tokens of identity.issuer"},
		{[]string{"register", "--config", config, "--trail", testTrail, "--issuer", witnessIssuer, "--subject", "deliverer-b"}, "is not among witness.submitters"},
		{[]string{"register", "--config", filepath.Join(t.TempDir(), "absent.json"), "--trail", testTrail, "--issuer", witnessIssuer, "--subject", "deliverer-a"}, "engine configuration"},
	} {
		if code, _, errText := act(c.args...); code != 1 || !strings.Contains(errText, c.want) {
			t.Fatalf("%v: %d %s", c.args, code, errText)
		}
	}
	if tw.files(t) != "<absent>|<absent>|<absent>|<absent>" {
		t.Fatal("a refused act wrote")
	}
	// a configuration with no witness member names no witness's files
	plain := filepath.Join(t.TempDir(), "engine.json")
	data, _ := os.ReadFile(config)
	text := string(data)
	text = text[:strings.Index(text, `"witness":`)] + `"platforms":{}}`
	if err := os.WriteFile(plain, []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
	if code, _, errText := act("repair", "--config", plain); code != 1 || !strings.Contains(errText, "has no witness member") {
		t.Fatalf("a configuration with no witness: %d %s", code, errText)
	}
}

// serve --config with a witness whose marks are on the log's own device is
// refused before anything is made, on the real host.
func TestServeConfigRefusesMarksOnTheLogsDevice(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("a root signer is refused first")
	}
	tw := newTestWitness(t)
	config := witnessEngineFile(t, tw, "")
	stderr := captureStderr(t)
	code := cmdServe([]string{"--config", config})
	out := stderr()
	if code != 1 || !strings.Contains(out, "is on the device of the log's directory") {
		t.Fatalf("exit %d: %.300s", code, out)
	}
	if _, err := os.Stat(filepath.Join(filepath.Dir(config), "store")); err == nil {
		t.Fatal("the store was made before the witness was refused")
	}
}

// serve --config opens the witness before it makes the store and the
// registry: a witness its start-up checks refuse leaves neither made. The
// marks are put on /dev/shm, a device apart from the temporary directory's,
// where the host has one.
func TestServeConfigOpensTheWitnessBeforeTheStore(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("a root signer is refused first")
	}
	shm, err := os.MkdirTemp("/dev/shm", "witness-marks-")
	if err != nil {
		t.Skipf("no /dev/shm to keep marks apart on: %v", err)
	}
	t.Cleanup(func() { os.RemoveAll(shm) })
	if err := os.Chmod(shm, 0o700); err != nil {
		t.Fatal(err)
	}
	tw := newTestWitness(t)
	var a, b syscall.Stat_t
	if syscall.Stat(shm, &a) != nil || syscall.Stat(filepath.Dir(tw.paths.log), &b) != nil || a.Dev == b.Dev {
		t.Skip("/dev/shm is on the temporary directory's device here")
	}
	// a log with a statement, and its marks lost: a new key, refused
	tw.paths.marks = filepath.Join(shm, "witness.marks")
	tw.register(t, testTrail)
	w := tw.open(t)
	mustSign(t, w, testTrail, 1)
	w.close()
	if err := os.Remove(tw.paths.marks); err != nil {
		t.Fatal(err)
	}
	config := witnessEngineFile(t, tw, "")
	issuer, _ := edIssuer(t)
	keys := []byte(`{"keys":[{"kty":"OKP","kid":"ed-1","crv":"Ed25519","x":"` + b64(issuer.edPub) + `"}]}`)
	if err := os.WriteFile(filepath.Join(filepath.Dir(config), "keys.json"), keys, 0o600); err != nil {
		t.Fatal(err)
	}
	stderr := captureStderr(t)
	code := cmdServe([]string{"--config", config})
	out := stderr()
	if code != 1 || !strings.Contains(out, "witness-marks-lost") {
		t.Fatalf("exit %d: %.400s", code, out)
	}
	for _, made := range []string{"store", "registry.jsonl"} {
		if _, err := os.Stat(filepath.Join(filepath.Dir(config), made)); err == nil {
			t.Fatalf("the %s was made before the witness was refused", made)
		}
	}
}
