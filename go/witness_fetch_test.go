//go:build unix

package main

// `gateway witness fetch` (witness_fetch.go; ADR-0014, determination 4)
// against a witness served over a real loopback listener, the runtime stood
// in by a function that records what it was handed: where the key comes
// from -- the reader's pin whose identifier the receipts name, or else the
// key the named origin serves, held to that identifier, and never the
// receipt -- and the three outcomes of question 9: a witness unreachable,
// read historically from what the reader holds under its pin; a witness
// refusing, its refusal given verbatim and nothing credited; a witness
// serving another key, nothing read. The whole reading against the real
// runtime is the scenario (witness_scenario_test.go).

import (
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
)

// fetchFixture is a witness served over a real listener, holding one
// statement for testTrail, and what a reader of an operator's receipts
// holds.
type fetchFixture struct {
	witness    *witnessFixture
	server     *httptest.Server
	publicKeys atomic.Int64 // GET /publickey answered
	recordFile string
	runs       [][]string // the runtime's argument lists, in order
	keysRun    []string   // the key file each run was handed
}

func newFetchFixture(t *testing.T) *fetchFixture {
	t.Helper()
	f := &fetchFixture{witness: newWitnessFixture(t, witnessSpec{}, testTrail)}
	if rec := f.witness.submit(t, testTrail, cpLine(testTrail, 1, "a")); rec.Code != http.StatusOK {
		t.Fatalf("submit: %d %s", rec.Code, rec.Body)
	}
	handler := f.witness.gateway.handler()
	f.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/publickey" {
			f.publicKeys.Add(1)
		}
		handler.ServeHTTP(w, r)
	}))
	t.Cleanup(f.server.Close)
	f.recordFile = filepath.Join(t.TempDir(), "record.jsonl")
	writeRecordOf(t, f.recordFile, testTrail)
	previous := witnessRuntime
	witnessRuntime = func(path string, args []string) ([]byte, int, error) {
		f.runs = append(f.runs, args)
		key := ""
		if i := slices.Index(args, "--witness-key"); i >= 0 {
			data, _ := os.ReadFile(args[i+1])
			key = strings.TrimSpace(string(data))
		}
		f.keysRun = append(f.keysRun, key)
		return []byte(`{"standIn":true,"keyFile":"` + key + `"}` + "\n"), 0, nil
	}
	t.Cleanup(func() { witnessRuntime = previous })
	return f
}

// writeRecordOf writes a runtime evaluation record of trail, one line.
func writeRecordOf(t *testing.T, path, trail string) {
	t.Helper()
	line := `{"recordVersion":"1","trail":"` + trail + `","sequence":1,"previous":"sha256:` + strings.Repeat("0", 64) + `","kind":"evaluation","pack":{"digest":"` + packA + `"}}` + "\n"
	if err := os.WriteFile(path, []byte(line), 0o600); err != nil {
		t.Fatal(err)
	}
}

// operatorStore is an operator's gateway naming, for trail, a witness at
// origin with key, an acquisition naming the trail, sealed; and the
// options a reader of it starts from.
func (f *fetchFixture) operatorStore(t *testing.T, trail, origin string, key []byte) witnessFetchOptions {
	t.Helper()
	service, server := testService(t)
	named, err := namedWitnessOf(trail, origin, hex.EncodeToString(key), "test")
	if err != nil {
		t.Fatal(err)
	}
	service.witnessedBy = map[string]namedWitness{trail: named}
	if code, out := post(t, server, "/acquire", `{"session":"op-1","source":"screening","arguments":{},"trail":"`+trail+`"}`); code != http.StatusOK {
		t.Fatalf("acquire: %d %v", code, out)
	}
	if code, out := post(t, server, "/seal", `{"session":"op-1"}`); code != http.StatusOK {
		t.Fatalf("seal: %d %v", code, out)
	}
	keyFile := filepath.Join(t.TempDir(), "gateway.pub")
	if err := os.WriteFile(keyFile, []byte(hex.EncodeToString(service.publicKey)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return witnessFetchOptions{
		store: service.storeRoot, registry: service.regPath, authority: service.authority, publicKey: keyFile,
		record: f.recordFile, trail: filepath.Join(t.TempDir(), "evaluations.jsonl"), runtime: "/stand-in/jpack",
		out: filepath.Join(t.TempDir(), "fetched"), allowLoopback: true,
	}
}

// pin writes a pinned key file.
func pin(t *testing.T, key []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "pinned.key")
	if err := os.WriteFile(path, []byte(hex.EncodeToString(key)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// fetchOne is the reading, which names one witness for the trail.
func fetchOne(t *testing.T, o witnessFetchOptions) witnessFetchReading {
	t.Helper()
	o.out = filepath.Join(t.TempDir(), "fetched")
	report, err := witnessFetch(o)
	if err != nil {
		t.Fatalf("fetch: %v", err)
	}
	if len(report.Witnesses) != 1 {
		t.Fatalf("fetch read %d witnesses: %+v", len(report.Witnesses), report)
	}
	return report.Witnesses[0]
}

func keyOf(r witnessFetchReading) string {
	if r.Key == nil {
		return "<none>"
	}
	return *r.Key
}

// The key: with no pin, the one the named origin serves, held to the
// identifier the receipts name, the report saying so; with a pin of that
// identifier, the pin, and /publickey is not asked; a pin of another key is
// not used for this witness.
func TestWitnessFetchTakesTheKeyFromAPinOrTheNamedOrigin(t *testing.T) {
	f := newFetchFixture(t)
	witness := f.witness.tw.signer.public
	o := f.operatorStore(t, testTrail, f.server.URL, witness)

	served := fetchOne(t, o)
	if served.Outcome != fetchRead || keyOf(served) != "served" || !served.Head || f.publicKeys.Load() != 1 || len(f.runs) != 1 {
		t.Fatalf("no pin: %s, key %s, head %v, /publickey %d, runs %d", served.Outcome, keyOf(served), served.Head, f.publicKeys.Load(), len(f.runs))
	}
	if f.keysRun[0] != hex.EncodeToString(witness) {
		t.Fatalf("the runtime was handed key %s", f.keysRun[0])
	}
	args := strings.Join(f.runs[0], " ")
	for _, want := range []string{"audit verify", "--format json", "--trail " + o.trail, "--witness ", "--witness-head "} {
		if !strings.Contains(args, want) {
			t.Fatalf("the runtime's arguments lack %q: %s", want, args)
		}
	}
	if !slices.Contains(served.Sentences, sentenceServedKey) || !strings.HasPrefix(served.Sentences[0], "The operator's gateway named this witness for this trail under its own key at "+served.NamedAt[0]) {
		t.Fatalf("the sentences: %q", served.Sentences)
	}
	var report map[string]any
	if err := json.Unmarshal(served.Report, &report); err != nil || report["standIn"] != true || *served.Exit != 0 {
		t.Fatalf("the runtime's report, verbatim: %s", served.Report)
	}
	// what was fetched is what was handed over: the head, and the chain
	// from index 0, as the witness served them
	head, _ := os.ReadFile(filepath.Join(f.runs[0][slices.Index(f.runs[0], "--witness-head")+1]))
	statements, _ := os.ReadFile(filepath.Join(f.runs[0][slices.Index(f.runs[0], "--witness")+1]))
	if len(head) == 0 || string(head) != string(statements) || strings.Count(string(statements), "\n") != 1 {
		t.Fatalf("the head %q and the statements %q", head, statements)
	}

	o.witnessKeys = []string{pin(t, witness)}
	pinned := fetchOne(t, o)
	if keyOf(pinned) != "pinned" || f.publicKeys.Load() != 1 || slices.Contains(pinned.Sentences, sentenceServedKey) || f.keysRun[1] != hex.EncodeToString(witness) {
		t.Fatalf("a pin of the key named: key %s, /publickey %d, sentences %q", keyOf(pinned), f.publicKeys.Load(), pinned.Sentences)
	}

	another := mustHex(t, witnessKey)
	o.witnessKeys = []string{pin(t, another)}
	notThatPin := fetchOne(t, o)
	if keyOf(notThatPin) != "served" || f.publicKeys.Load() != 2 || f.keysRun[2] != hex.EncodeToString(witness) {
		t.Fatalf("a pin of another key: key %s, handed %s", keyOf(notThatPin), f.keysRun[2])
	}
	o.witnessKeys = []string{pin(t, another), pin(t, witness)}
	if both := fetchOne(t, o); keyOf(both) != "pinned" || f.keysRun[3] != hex.EncodeToString(witness) {
		t.Fatalf("two pins: key %s, handed %s", keyOf(both), f.keysRun[3])
	}
}

// A witness that serves another key than the receipts name: with no pin,
// witness-key-not-named, and nothing from that origin is read; a reader
// that pinned the key named reads the chain under it, and the runtime, not
// this reader, finds what it finds.
func TestWitnessFetchReadsNothingFromAnOriginServingAnotherKey(t *testing.T) {
	f := newFetchFixture(t)
	named := mustHex(t, witnessKey)
	o := f.operatorStore(t, testTrail, f.server.URL, named)
	got := fetchOne(t, o)
	if got.Outcome != fetchKeyNotNamed || got.Key != nil || len(f.runs) != 0 || got.Report != nil || !slices.Contains(got.Sentences, sentenceKeyNotNamed) {
		t.Fatalf("another key served: %s, key %s, runs %d, report %s", got.Outcome, keyOf(got), len(f.runs), got.Report)
	}
	if _, err := os.Stat(filepath.Join(o.out, "1", "witness-key")); err == nil {
		t.Fatal("a key was written for a witness whose key is not the one named")
	}
	o.witnessKeys = []string{pin(t, named)}
	pinned := fetchOne(t, o)
	if pinned.Outcome != fetchRead || keyOf(pinned) != "pinned" || len(f.runs) != 1 || f.keysRun[0] != witnessKey {
		t.Fatalf("the key named, pinned: %s, key %s, handed %v", pinned.Outcome, keyOf(pinned), f.keysRun)
	}
}

// A witness that holds nothing for the trail: its 404 unknown-trail given
// verbatim, nothing credited, and the runtime not run.
func TestWitnessFetchGivesARefusalVerbatim(t *testing.T) {
	f := newFetchFixture(t)
	o := f.operatorStore(t, trailB, f.server.URL, f.witness.tw.signer.public)
	writeRecordOf(t, o.record, trailB)
	got := fetchOne(t, o)
	resp, err := http.Get(f.server.URL + "/witness/trails/" + trailB + "/head")
	if err != nil {
		t.Fatal(err)
	}
	var answer witnessFetchRefusal
	json.NewDecoder(resp.Body).Decode(&answer)
	resp.Body.Close()
	if got.Outcome != fetchRefused || got.Refusal == nil || got.Refusal.Status != 404 || got.Refusal.Reason != "unknown-trail" || got.Refusal.Error != answer.Error || answer.Error == "" ||
		len(f.runs) != 0 || got.Report != nil || !slices.Contains(got.Sentences, sentenceRefused) {
		t.Fatalf("a refusal: %+v, runs %d, the witness said %+v", got, len(f.runs), answer)
	}
}

// A witness that cannot be reached: with no pin there is no key, and
// nothing is read; with a pin, the statements the reader kept are read
// under it with no head, as far as supplied -- and with none kept, nothing.
func TestWitnessFetchReadsWhatIsHeldWhenTheWitnessIsUnreachable(t *testing.T) {
	f := newFetchFixture(t)
	witness := f.witness.tw.signer.public
	o := f.operatorStore(t, testTrail, f.server.URL, witness)
	kept := filepath.Join(t.TempDir(), "kept.jsonl")
	resp, err := http.Get(f.server.URL + "/witness/trails/" + testTrail + "/statements")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := readAllClose(resp)
	if err := os.WriteFile(kept, body, 0o600); err != nil {
		t.Fatal(err)
	}
	f.server.Close()

	got := fetchOne(t, o)
	if got.Outcome != fetchUnreachable || got.Key != nil || len(f.runs) != 0 || !slices.Contains(got.Sentences, sentenceUnreachable) || !slices.Contains(got.Sentences, sentenceNoPin) {
		t.Fatalf("unreachable, no pin: %+v", got)
	}
	o.witnessKeys = []string{pin(t, witness)}
	if got := fetchOne(t, o); got.Outcome != fetchUnreachable || len(f.runs) != 0 || !slices.Contains(got.Sentences, sentenceNoneHeld) {
		t.Fatalf("unreachable, pinned, nothing kept: %+v", got)
	}
	o.statements = []string{kept}
	got = fetchOne(t, o)
	args := strings.Join(f.runs[0], " ")
	if got.Outcome != fetchUnreachable || keyOf(got) != "pinned" || got.Head || len(f.runs) != 1 || strings.Contains(args, "--witness-head") || !strings.Contains(args, "--witness "+kept) || got.Report == nil {
		t.Fatalf("unreachable, pinned, kept: %+v, %s", got, args)
	}
}

func readAllClose(resp *http.Response) ([]byte, error) {
	defer resp.Body.Close()
	return io.ReadAll(resp.Body)
}

// What the reader refuses before it reads anything, and what it reads
// nothing from: an http origin it was not asked to read on loopback; a
// store that does not verify, since a witness is taken only from a verdict
// a reader acts on; a record of a trail no receipt names a witness for; a
// directory to write into that holds something; a runtime named by no
// path; a pinned key the key rule refuses.
func TestWitnessFetchRefusals(t *testing.T) {
	f := newFetchFixture(t)
	o := f.operatorStore(t, testTrail, f.server.URL, f.witness.tw.signer.public)

	o.allowLoopback = false
	if got := fetchOne(t, o); got.Outcome != fetchOriginRefused || f.publicKeys.Load() != 0 || len(f.runs) != 0 {
		t.Fatalf("http without --allow-loopback: %+v", got)
	}
	o.allowLoopback = true

	other := filepath.Join(t.TempDir(), "other.jsonl")
	writeRecordOf(t, other, trailB)
	none := o
	none.record, none.out = other, filepath.Join(t.TempDir(), "fetched")
	if report, err := witnessFetch(none); err != nil || len(report.Witnesses) != 0 || !slices.Contains(report.Sentences, sentenceNoWitness) {
		t.Fatalf("a trail no receipt names a witness for: %+v %v", report, err)
	}

	full := filepath.Join(t.TempDir(), "full")
	os.MkdirAll(filepath.Join(full, "x"), 0o700)
	busy := o
	busy.out = full
	if _, err := witnessFetch(busy); err == nil || !strings.Contains(err.Error(), "is not empty") {
		t.Fatalf("an out directory that holds something: %v", err)
	}

	smallOrder := filepath.Join(t.TempDir(), "small.key")
	os.WriteFile(smallOrder, []byte("0100000000000000000000000000000000000000000000000000000000000000\n"), 0o600)
	pinnedBad := o
	pinnedBad.witnessKeys, pinnedBad.out = []string{smallOrder}, filepath.Join(t.TempDir(), "fetched")
	if _, err := witnessFetch(pinnedBad); err == nil || !strings.Contains(err.Error(), "key-small-order") {
		t.Fatalf("a pinned key the rule refuses: %v", err)
	}

	var stdout, stderr strings.Builder
	if code := cmdWitness([]string{"fetch", "--store", o.store, "--registry", o.registry, "--authority", o.authority, "--public-key", o.publicKey,
		"--record", o.record, "--trail", o.trail, "--runtime", "jpack", "--out", filepath.Join(t.TempDir(), "o")}, &stdout, &stderr); code != 2 || !strings.Contains(stderr.String(), "by its path") {
		t.Fatalf("a runtime by name: %d %s", code, stderr.String())
	}

	// a receipt altered: the store does not verify, and nothing is read
	path := filepath.Join(o.store, "receipts", "op-1", "0.json")
	data, _ := os.ReadFile(path)
	os.WriteFile(path, []byte(strings.Replace(string(data), `"source":"screening"`, `"source":"screenin6"`, 1)), 0o600)
	o.out = filepath.Join(t.TempDir(), "fetched")
	if _, err := witnessFetch(o); err == nil || !strings.Contains(err.Error(), "do not verify") || len(f.runs) != 0 {
		t.Fatalf("a store that does not verify: %v, runs %d", err, len(f.runs))
	}
}

// The command's report is JSON on standard output, exit 0, the runtime's
// report in it as the runtime wrote it.
func TestWitnessFetchCommand(t *testing.T) {
	f := newFetchFixture(t)
	o := f.operatorStore(t, testTrail, f.server.URL, f.witness.tw.signer.public)
	var stdout, stderr strings.Builder
	code := cmdWitness([]string{"fetch", "--store", o.store, "--registry", o.registry, "--authority", o.authority, "--public-key", o.publicKey,
		"--record", o.record, "--trail", o.trail, "--runtime", o.runtime, "--out", o.out, "--allow-loopback", "--require-countersigned-through", "1"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("exit %d: %s", code, stderr.String())
	}
	var report struct {
		Trail     string `json:"trail"`
		Witnesses []struct {
			Outcome string          `json:"outcome"`
			Key     string          `json:"key"`
			Report  json.RawMessage `json:"report"`
		} `json:"witnesses"`
	}
	if err := json.Unmarshal([]byte(stdout.String()), &report); err != nil || report.Trail != testTrail || len(report.Witnesses) != 1 || report.Witnesses[0].Outcome != "read" ||
		!strings.Contains(stdout.String(), `"report":{"standIn":true,"keyFile":"`+hex.EncodeToString(f.witness.tw.signer.public)+`"}`) {
		t.Fatalf("the report: %v %s", err, stdout.String())
	}
	if !slices.Contains(f.runs[0], "--require-countersigned-through") {
		t.Fatalf("the runtime's arguments: %v", f.runs[0])
	}
}
