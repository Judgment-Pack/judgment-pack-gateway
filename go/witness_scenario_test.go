//go:build unix

package main

// The acceptance scenario of ADR-0014 (determination 6): a verifier that
// starts from a decision record and its receipts alone finds the witness
// the record's trail is registered with, fetches its head and statements,
// and reads the countersigned coverage with the runtime's own reader.
//
// Every process is on 127.0.0.1. The witness W is this repository's binary,
// built at this commit, started with `serve --config` and a witness member;
// the operator's gateway G is an engine of this code built from an
// engine.json that names W for the trail in witnessedBy, its source and
// write tool the test's own programs; the records are written, chained and
// checkpointed by the runtime named by GATEWAY_SCENARIO_RUNTIME, a released
// binary at 0.28.0 or later; and the verifier runs this binary's `verify`
// and `witness fetch`, holding the record, the trail, G's store and
// registry and G's key, and nothing about W. Then the negatives: a key W
// does not hold, another origin than the statements came from, and W
// stopped.
//
// Without GATEWAY_SCENARIO_RUNTIME the scenario is skipped; CI's job names
// it (.github/workflows/ci.yml), and there nothing is skipped.

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

const (
	scenarioOperatorAudience = "gateway:operator"
	scenarioWitnessAudience  = "gateway:witness-w"
	scenarioSubmitAudience   = "witness:w"
	scenarioDeliverer        = "deliverer"
	scenarioWitnessOperator  = "witness-operator"
)

// scenario is what the test holds: the gateway binary, the runtime, the
// issuer every party trusts, and where the runtime's project is.
type scenario struct {
	gateway, runtime string
	issuer           *testIssuer
	keys             string // the issuer's key set, a file
	project          string
	trailFile        string
}

func TestReceiptNamesTheWitnessScenario(t *testing.T) {
	runtimePath := os.Getenv("GATEWAY_SCENARIO_RUNTIME")
	if runtimePath == "" {
		t.Skip("GATEWAY_SCENARIO_RUNTIME names no runtime; CI's scenario job names one")
	}
	if !filepath.IsAbs(runtimePath) {
		t.Fatal("GATEWAY_SCENARIO_RUNTIME is a path, absolute")
	}
	sc := &scenario{runtime: runtimePath, gateway: scenarioGateway(t)}
	sc.issuer, _ = edIssuer(t)
	sc.keys = filepath.Join(tempDirAt(t, 0o700), "keys.json")
	if err := os.WriteFile(sc.keys, []byte(`{"keys":[{"kty":"OKP","kid":"ed-1","crv":"Ed25519","x":"`+b64(sc.issuer.edPub)+`"}]}`), 0o600); err != nil {
		t.Fatal(err)
	}

	// 1. Witness W: its own seed, a witness member, registration by its
	// operator, the test issuer.
	w := sc.startWitness(t, "w")
	t.Logf("W at %s, key %s", w.origin, hex.EncodeToString(w.public)[:16])

	// 3, first: the runtime makes the trail, whose identity is fixed by its
	// first record, so the operator can name W for it.
	sc.project = sc.makeProject(t)
	sc.trailFile = filepath.Join(sc.project, "audit", "evaluations.jsonl")
	sc.evaluate(t, "")
	trail := sc.recordTrail(t, 1)
	t.Logf("trail %s", trail)

	// 2. The operator's gateway G, naming W for the trail.
	g := sc.operatorGateway(t, "g", map[string]string{trail: w.origin + "," + hex.EncodeToString(w.public)})

	// 3. An acquisition at G naming the trail; the runtime writes R at
	// sequence n citing it; the trail registered at W; the checkpoint
	// through n submitted: 200, a statement.
	acquired := g.acquire(t, sc, trail)
	signature := acquired["signature"].(string)
	sc.evaluate(t, `[{"sessionId":"scenario","callIndex":0,"signature":"`+signature+`"}]`)
	const n = 2
	recordLine := sc.recordLine(t, n)
	recordFile := filepath.Join(t.TempDir(), "record.jsonl")
	if err := os.WriteFile(recordFile, append(recordLine, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	w.register(t, sc, trail)
	checkpoint := sc.run(t, "audit", "checkpoint", "--trail", sc.trailFile)
	statement := w.submit(t, sc, checkpoint)
	kept := filepath.Join(t.TempDir(), "kept.jsonl")
	if err := os.WriteFile(kept, statement, 0o600); err != nil {
		t.Fatal(err)
	}

	// 4. The action at G on R, citing the acquisition; the session sealed.
	// Both receipts name W, for the trail, under W's key's identifier.
	var record struct {
		Pack struct {
			Digest string `json:"digest"`
		} `json:"pack"`
	}
	if err := json.Unmarshal(recordLine, &record); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(recordLine)
	acted := g.act(t, "sha256:"+hex.EncodeToString(sum[:]), record.Pack.Digest, signature)
	g.seal(t)
	want := map[string]any{"origin": w.origin, "keyId": keyIDFor(w.public), "trail": trail}
	for name, receipt := range map[string]map[string]any{"the acquisition": acquired, "the action": acted} {
		if fmt.Sprint(receipt["witness"]) != fmt.Sprint(want) {
			t.Fatalf("%s names %v, want %v", name, receipt["witness"], want)
		}
	}

	// 5. The verifier, holding R's line and the trail, G's store, registry
	// and pinned key, and nothing about W.
	verdict := sc.verify(t, g, sc.project+"/audit")
	if !verdict.OK || len(verdict.Witnesses) != 1 || verdict.Witnesses[0] != (witnessTriple{Trail: trail, Origin: w.origin, KeyID: keyIDFor(w.public)}) {
		t.Fatalf("gateway verify: ok %v, witnesses %+v", verdict.OK, verdict.Witnesses)
	}
	read := sc.fetch(t, g, recordFile, true, nil, nil, "--require-countersigned-through", fmt.Sprint(n))
	if read.Outcome != fetchRead || keyOf(read) != "served" || !read.Head || *read.Exit != 0 {
		t.Fatalf("the fetch: %s, key %s, head %v, exit %v\n%s", read.Outcome, keyOf(read), read.Head, read.Exit, read.Report)
	}
	countersigned(t, "the scenario", read.Report, n, "current")

	// A key W does not hold: G naming W's origin with another key. With no
	// pin, witness-key-not-named and nothing read; with the key named
	// pinned, W's statements under it are witness-signature-invalid.
	other, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	g2 := sc.operatorGateway(t, "g2", map[string]string{trail: w.origin + "," + hex.EncodeToString(other)})
	g2.acquire(t, sc, trail)
	g2.seal(t)
	if got := sc.fetch(t, g2, recordFile, false, nil, nil); got.Outcome != fetchKeyNotNamed || !noReport(got) {
		t.Fatalf("a key W does not hold, no pin: %s\n%s", got.Outcome, got.Report)
	}
	got := sc.fetch(t, g2, recordFile, false, []byte(other), nil)
	if got.Outcome != fetchRead || keyOf(got) != "pinned" || *got.Exit == 0 {
		t.Fatalf("a key W does not hold, pinned: %s, exit %v", got.Outcome, got.Exit)
	}
	notCredited(t, "a key W does not hold", got.Report, "witness-signature-invalid")

	// Another origin than the statements came from: G naming a second
	// witness W2, its own seed, holding nothing for the trail. W2 answers
	// 404 unknown-trail, and nothing is credited; W's statements under
	// W2's key are witness-signature-invalid.
	w2 := sc.startWitness(t, "w2")
	g3 := sc.operatorGateway(t, "g3", map[string]string{trail: w2.origin + "," + hex.EncodeToString(w2.public)})
	g3.acquire(t, sc, trail)
	g3.seal(t)
	got = sc.fetch(t, g3, recordFile, false, nil, nil)
	if got.Outcome != fetchRefused || got.Refusal == nil || got.Refusal.Reason != "unknown-trail" || !noReport(got) || keyOf(got) != "served" {
		t.Fatalf("another origin: %+v", got)
	}
	keyFile := filepath.Join(t.TempDir(), "w2.key")
	os.WriteFile(keyFile, []byte(hex.EncodeToString(w2.public)+"\n"), 0o600)
	report, _ := sc.runExit(t, "audit", "verify", "--format", "json", "--trail", sc.trailFile, "--witness-key", keyFile, "--witness", kept)
	notCredited(t, "W's statements under W2's key", report, "witness-signature-invalid")

	// W stopped after step 3: the fetch finds it unreachable; with no pin
	// nothing is read; with W's key pinned from before, the statement kept
	// reads historically, as far as supplied, countersigned through n.
	w.stop(t)
	if got := sc.fetch(t, g, recordFile, true, nil, nil); got.Outcome != fetchUnreachable || !noReport(got) {
		t.Fatalf("W stopped, no pin: %+v", got)
	}
	got = sc.fetch(t, g, recordFile, true, w.public, []string{kept})
	if got.Outcome != fetchUnreachable || keyOf(got) != "pinned" || got.Head || got.Exit == nil || *got.Exit != 0 {
		t.Fatalf("W stopped, pinned, kept: %+v\n%s", got, got.Report)
	}
	countersigned(t, "W stopped", got.Report, n, "historical")
}

// scenarioGateway is the gateway binary: the one CI built, or built here.
func scenarioGateway(t *testing.T) string {
	if path := os.Getenv("GATEWAY_SCENARIO_GATEWAY"); path != "" {
		return path
	}
	out := filepath.Join(t.TempDir(), "gateway")
	build := exec.Command("go", "build", "-buildvcs=false", "-o", out, ".")
	if text, err := build.CombinedOutput(); err != nil {
		t.Fatalf("go build: %v\n%s", err, text)
	}
	return out
}

// witnessProcess is a witness this repository's binary runs.
type witnessProcess struct {
	origin string
	public ed25519.PublicKey
	cmd    *exec.Cmd
	stderr *lockedBuffer
}

// startWitness starts a witness: an engine with a seed of its own, a
// witness member, no platform, on a free loopback port, its marks on
// /dev/shm, a device apart from the log's, as the engine requires.
func (sc *scenario) startWitness(t *testing.T, name string) *witnessProcess {
	t.Helper()
	dir := tempDirAt(t, 0o700)
	shm, err := os.MkdirTemp("/dev/shm", "witness-marks-")
	if err != nil {
		t.Fatalf("marks on a device apart from the log's: %v", err)
	}
	t.Cleanup(func() { os.RemoveAll(shm) })
	os.Chmod(shm, 0o700)
	var a, b syscall.Stat_t
	if syscall.Stat(shm, &a) != nil || syscall.Stat(dir, &b) != nil || a.Dev == b.Dev {
		t.Fatal("/dev/shm is on the temporary directory's device: the witness's marks need another")
	}
	seed := make([]byte, ed25519.SeedSize)
	rand.Read(seed)
	seedPath := filepath.Join(dir, "gateway.seed")
	if err := os.WriteFile(seedPath, []byte(hex.EncodeToString(seed)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, sub := range []string{"log", "decisions", "catalog"} {
		os.Mkdir(filepath.Join(dir, sub), 0o700)
	}
	port := freePort(t)
	config := `{"engineVersion":"6","authority":"gateway:` + name + `","seed":"` + seedPath + `","store":"` + filepath.Join(dir, "store") + `",` +
		`"registry":"` + filepath.Join(dir, "registry.jsonl") + `","decisionRecords":"` + filepath.Join(dir, "decisions") + `","listen":"127.0.0.1:` + port + `",` +
		`"catalog":"` + filepath.Join(dir, "catalog") + `","identity":{"issuer":"` + witnessIssuer + `","audience":"` + scenarioWitnessAudience + `","keys":"` + sc.keys + `"},` +
		`"witness":{"log":"` + filepath.Join(dir, "log", "witness.log") + `","marks":"` + filepath.Join(shm, "witness.marks") + `","audience":"` + scenarioSubmitAudience + `",` +
		`"submitters":[{"issuer":"` + witnessIssuer + `","subject":"` + scenarioDeliverer + `"}]},"platforms":{}}`
	configPath := filepath.Join(dir, "engine.json")
	if err := os.WriteFile(configPath, []byte(config), 0o600); err != nil {
		t.Fatal(err)
	}
	p := &witnessProcess{origin: "http://127.0.0.1:" + port, public: ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey), stderr: &lockedBuffer{}}
	p.cmd = exec.Command(sc.gateway, "serve", "--config", configPath)
	p.cmd.Stdout, p.cmd.Stderr = io.Discard, p.stderr
	if err := p.cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { p.stop(t) })
	deadline := time.Now().Add(30 * time.Second)
	for {
		resp, err := http.Get(p.origin + "/publickey")
		if err == nil {
			var doc struct {
				PublicKey string `json:"publicKey"`
			}
			json.NewDecoder(resp.Body).Decode(&doc)
			resp.Body.Close()
			if doc.PublicKey != hex.EncodeToString(p.public) {
				t.Fatalf("the witness serves key %s", doc.PublicKey)
			}
			return p
		}
		if time.Now().After(deadline) {
			t.Fatalf("the witness %s did not start: %s", name, p.stderr.String())
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func (p *witnessProcess) stop(t *testing.T) {
	if p.cmd.ProcessState != nil || p.cmd.Process == nil {
		return
	}
	p.cmd.Process.Signal(syscall.SIGTERM)
	done := make(chan struct{})
	go func() { p.cmd.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(20 * time.Second):
		p.cmd.Process.Kill()
		<-done
	}
}

// freePort is a loopback port nothing listens on now.
func freePort(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	_, port, _ := net.SplitHostPort(l.Addr().String())
	return port
}

// token is a token of the issuer's, for a subject and an audience.
func (sc *scenario) token(t *testing.T, subject, audience string) string {
	t.Helper()
	return sc.issuer.mint(t, "ed-1", nil, map[string]any{"iss": witnessIssuer, "sub": subject, "aud": audience, "exp": time.Now().Add(time.Hour).Unix()})
}

// register registers the trail at the witness, by its operator, at
// POST /witness/registrations.
func (p *witnessProcess) register(t *testing.T, sc *scenario, trail string) {
	t.Helper()
	body := `{"trail":"` + trail + `","issuer":"` + witnessIssuer + `","subject":"` + scenarioDeliverer + `"}`
	status, answer := send(t, http.MethodPost, p.origin+"/witness/registrations", "application/json", sc.token(t, scenarioWitnessOperator, scenarioWitnessAudience), []byte(body))
	if status != http.StatusOK {
		t.Fatalf("registration: %d %s", status, answer)
	}
}

// submit submits checkpoint lines, as the deliverer, and returns the
// statement the witness answers.
func (p *witnessProcess) submit(t *testing.T, sc *scenario, lines []byte) []byte {
	t.Helper()
	status, answer := send(t, http.MethodPost, p.origin+"/witness/checkpoints", "application/jsonl", sc.token(t, scenarioDeliverer, scenarioSubmitAudience), lines)
	if status != http.StatusOK || bytes.Count(answer, []byte{'\n'}) != 1 {
		t.Fatalf("submission: %d %s", status, answer)
	}
	return answer
}

func send(t *testing.T, method, url, contentType, token string, body []byte) (int, []byte) {
	t.Helper()
	req, err := http.NewRequest(method, url, bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", contentType)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	answer, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, answer
}

// makeProject is the runtime's project: the pack the image test uses, its
// audit directory, a facts and an evidence document.
func (sc *scenario) makeProject(t *testing.T) string {
	t.Helper()
	project := tempDirAt(t, 0o700)
	for _, dir := range []string{"packs", "audit"} {
		if err := os.Mkdir(filepath.Join(project, dir), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	pack, err := os.ReadFile(filepath.Join("..", ".github", "fixtures", "runtime", "data-request-intake-triage.json"))
	if err != nil {
		t.Fatal(err)
	}
	for name, text := range map[string][]byte{
		"packs/intake.json": pack,
		"jpack.json":        []byte(`{"configVersion":"3","audit":{"dir":"audit"},"packs":{"intake":{"path":"packs/intake.json"}}}`),
		"facts.json":        []byte(`{"request":{"type":"data-access","completeness":"complete","appropriateness":"hard-fail","embargoedInformationToUnauthorizedRecipients":false}}`),
		"evidence.json":     []byte(`{"intake-form":"present","sponsor-endorsement":"present"}`),
	} {
		if err := os.WriteFile(filepath.Join(project, name), text, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return project
}

// evaluate has the runtime evaluate the pack once, appending a chained
// record to the trail, citing what cites names, when it names anything.
func (sc *scenario) evaluate(t *testing.T, cites string) {
	t.Helper()
	args := []string{"experimental", "evaluate", "--pack-id", "intake", "--facts", "facts.json", "--evidence", "evidence.json", "--format", "json"}
	if cites != "" {
		if err := os.WriteFile(filepath.Join(sc.project, "cites.json"), []byte(cites), 0o600); err != nil {
			t.Fatal(err)
		}
		args = append(args, "--cites", "cites.json")
	}
	sc.run(t, args...)
}

// run runs the runtime in the project, and gives what it wrote; it must
// succeed.
func (sc *scenario) run(t *testing.T, args ...string) []byte {
	t.Helper()
	out, exit := sc.runExit(t, args...)
	if exit != 0 {
		t.Fatalf("jpack %s: exit %d\n%s", strings.Join(args, " "), exit, out)
	}
	return out
}

func (sc *scenario) runExit(t *testing.T, args ...string) ([]byte, int) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, sc.runtime, args...)
	cmd.Dir = sc.project
	cmd.Env = []string{"HOME=" + sc.project}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if exit, isExit := err.(*exec.ExitError); isExit {
		return append(out, stderr.Bytes()...), exit.ExitCode()
	}
	if err != nil {
		t.Fatalf("jpack %s: %v %s", strings.Join(args, " "), err, stderr.String())
	}
	return out, 0
}

// recordLine is the trail's line n, its exact bytes.
func (sc *scenario) recordLine(t *testing.T, n int) []byte {
	t.Helper()
	data, err := os.ReadFile(sc.trailFile)
	if err != nil {
		t.Fatal(err)
	}
	lines := bytes.Split(bytes.TrimSuffix(data, []byte{'\n'}), []byte{'\n'})
	if len(lines) < n {
		t.Fatalf("the trail holds %d lines", len(lines))
	}
	return lines[n-1]
}

func (sc *scenario) recordTrail(t *testing.T, n int) string {
	t.Helper()
	trail := recordTrail(sc.recordLine(t, n))
	if trail == "" {
		t.Fatal("the runtime's record names no trail")
	}
	return trail
}

// operatorGateway is the operator's gateway: an engine of this code from
// an engine.json naming the witnesses given in witnessedBy, its own seed,
// the test issuer, the project's audit directory for its decision records,
// a source and a write tool that are the test's own programs, served on a
// loopback listener.
type operatorGateway struct {
	service *gatewayService
	server  *httptest.Server
	token   string
	keyFile string
}

func (sc *scenario) operatorGateway(t *testing.T, name string, witnessedBy map[string]string) *operatorGateway {
	t.Helper()
	dir := tempDirAt(t, 0o700)
	var entries []string
	for trail, named := range witnessedBy {
		origin, key, _ := strings.Cut(named, ",")
		entries = append(entries, `"`+trail+`":{"origin":"`+origin+`","publicKey":"`+key+`"}`)
	}
	config := `{"engineVersion":"7","authority":"gateway:` + name + `","seed":"` + filepath.Join(dir, "gateway.seed") + `","store":"` + filepath.Join(dir, "store") + `",` +
		`"registry":"` + filepath.Join(dir, "registry.jsonl") + `","decisionRecords":"` + filepath.Join(sc.project, "audit") + `","listen":"127.0.0.1:8787",` +
		`"catalog":"` + filepath.Join(dir, "catalog") + `","identity":{"issuer":"` + witnessIssuer + `","audience":"` + scenarioOperatorAudience + `","keys":"` + sc.keys + `"},` +
		`"witnessedBy":{` + strings.Join(entries, ",") + `},"platforms":{}}`
	cfg, err := parseEngineConfig([]byte(config))
	if err != nil {
		t.Fatal(err)
	}
	identity, err := loadIdentity(cfg.identity)
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv(envSourceHelper, "1")
	env, _ := goodEnvelope()
	t.Setenv(envSourceEnvelope, envelopeText(t, env))
	sources := map[string]sourceSpec{
		"records":    {argv: []string{os.Args[0]}, env: helperEnv},
		"plat/write": {argv: []string{os.Args[0], "--tools=update"}, env: helperEnv, shape: "mcp", tools: []string{"update"}, endpoint: "https://mcp.example/"},
	}
	seed := make([]byte, ed25519.SeedSize)
	rand.Read(seed)
	service, err := buildService(cfg.store, seed, cfg.authority, cfg.registry, engineServeOptions(cfg, sources, identity))
	if err != nil {
		t.Fatal(err)
	}
	g := &operatorGateway{service: service, server: httptest.NewServer(service.handler())}
	t.Cleanup(g.server.Close)
	g.token = sc.token(t, "approver", scenarioOperatorAudience)
	g.keyFile = filepath.Join(dir, "gateway.pub")
	if err := os.WriteFile(g.keyFile, []byte(hex.EncodeToString(service.publicKey)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return g
}

func (g *operatorGateway) post(t *testing.T, path, body string) map[string]any {
	t.Helper()
	status, answer := send(t, http.MethodPost, g.server.URL+path, "application/json", g.token, []byte(body))
	var out map[string]any
	if json.Unmarshal(answer, &out) != nil || status != http.StatusOK {
		t.Fatalf("%s: %d %s", path, status, answer)
	}
	return out
}

func (g *operatorGateway) acquire(t *testing.T, sc *scenario, trail string) map[string]any {
	t.Helper()
	out := g.post(t, "/acquire", `{"session":"scenario","source":"records","arguments":{"q":"intake"},"trail":"`+trail+`"}`)
	return out["receipt"].(map[string]any)
}

func (g *operatorGateway) act(t *testing.T, recordDigest, packDigest, signature string) map[string]any {
	t.Helper()
	out := g.post(t, "/act", `{"session":"scenario","platform":"plat","tool":"update","arguments":{"id":"R-1"},`+
		`"decision":{"recordDigest":"`+recordDigest+`","packDigest":"`+packDigest+`"},`+
		`"cites":[{"sessionId":"scenario","callIndex":0,"signature":"`+signature+`"}]}`)
	return out["receipt"].(map[string]any)
}

func (g *operatorGateway) seal(t *testing.T) {
	t.Helper()
	g.post(t, "/seal", `{"session":"scenario"}`)
}

// verify is `gateway verify`, this binary's, under G's key on its standard
// input.
func (sc *scenario) verify(t *testing.T, g *operatorGateway, records string) report {
	t.Helper()
	key, _ := os.ReadFile(g.keyFile)
	cmd := exec.Command(sc.gateway, "verify", g.service.storeRoot, g.service.regPath, g.service.authority, "--decision-records", records)
	cmd.Stdin = bytes.NewReader(key)
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("gateway verify: %v", err)
	}
	var verdict report
	if err := json.Unmarshal(out, &verdict); err != nil {
		t.Fatalf("gateway verify: %v %s", err, out)
	}
	return verdict
}

// fetch is `gateway witness fetch`, this binary's, from the record, the
// trail and G's store, registry and key; the decision records with the
// action's store, which cites the record.
func (sc *scenario) fetch(t *testing.T, g *operatorGateway, record string, withRecords bool, pinned []byte, kept []string, extra ...string) witnessFetchReading {
	t.Helper()
	args := []string{"witness", "fetch", "--store", g.service.storeRoot, "--registry", g.service.regPath, "--authority", g.service.authority,
		"--public-key", g.keyFile, "--record", record, "--trail", sc.trailFile, "--runtime", sc.runtime,
		"--out", filepath.Join(t.TempDir(), "fetched"), "--allow-loopback"}
	if withRecords {
		args = append(args, "--decision-records", filepath.Join(sc.project, "audit"))
	}
	if pinned != nil {
		keyFile := filepath.Join(t.TempDir(), "pinned.key")
		os.WriteFile(keyFile, []byte(hex.EncodeToString(pinned)+"\n"), 0o600)
		args = append(args, "--witness-key", keyFile)
	}
	for _, file := range kept {
		args = append(args, "--statements", file)
	}
	args = append(args, extra...)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, sc.gateway, args...)
	cmd.Env = []string{"HOME=" + sc.project}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("gateway witness fetch: %v %s", err, stderr.String())
	}
	var fetched witnessFetchReport
	if err := json.Unmarshal(out, &fetched); err != nil || len(fetched.Witnesses) != 1 {
		t.Fatalf("gateway witness fetch printed %v: %s", err, out)
	}
	t.Logf("fetch: %s", out)
	return fetched.Witnesses[0]
}

// noReport is whether a reading ran no runtime: the command prints its
// report as null.
func noReport(r witnessFetchReading) bool {
	return r.Exit == nil && (len(r.Report) == 0 || string(r.Report) == "null")
}

// runtimeReading is what the scenario reads of the runtime's report.
type runtimeReading struct {
	Status   string `json:"status"`
	Coverage struct {
		Countersigned json.RawMessage `json:"countersigned"`
	} `json:"coverage"`
	Findings []json.RawMessage `json:"findings"`
	Witness  json.RawMessage   `json:"witness"`
}

// countersigned holds a report to coverage countersigned through n, its
// reading the one given, with no witness finding.
func countersigned(t *testing.T, what string, raw []byte, n int, reading string) {
	t.Helper()
	var r runtimeReading
	if err := json.Unmarshal(raw, &r); err != nil {
		t.Fatalf("%s: the runtime's report: %v %s", what, err, raw)
	}
	text := string(raw)
	if strings.Contains(text, `"witness-`) {
		t.Fatalf("%s: a witness finding: %s", what, raw)
	}
	var coverage struct {
		Status  string `json:"status"`
		Through int    `json:"through"`
	}
	json.Unmarshal(r.Coverage.Countersigned, &coverage)
	if coverage.Through != n || !strings.Contains(string(r.Witness), `"`+reading+`"`) {
		t.Fatalf("%s: countersigned %s, witness %s; want through %d, %s", what, r.Coverage.Countersigned, r.Witness, n, reading)
	}
}

// notCredited holds a report to the finding named and nothing
// countersigned.
func notCredited(t *testing.T, what string, raw []byte, finding string) {
	t.Helper()
	if !strings.Contains(string(raw), `"`+finding+`"`) {
		t.Fatalf("%s: no %s in %s", what, finding, raw)
	}
	var r runtimeReading
	json.Unmarshal(raw, &r)
	var coverage struct {
		Through int `json:"through"`
	}
	json.Unmarshal(r.Coverage.Countersigned, &coverage)
	if coverage.Through != 0 {
		t.Fatalf("%s: countersigned %s", what, r.Coverage.Countersigned)
	}
}
