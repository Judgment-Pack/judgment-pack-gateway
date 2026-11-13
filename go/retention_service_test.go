package main

// A source that keeps no payload (engineVersion 22; SPEC.md §1.3a and §6,
// "Payloads a gateway does not keep"; ADR-0028): the platform member, the
// acquisition that returns the bytes and writes none, the receipt that says
// so, and connect --replace keeping it.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// unkeptService is a gateway with a source that keeps no payload and one
// that keeps every payload.
func unkeptService(t *testing.T, version string) (*gatewayService, *httptest.Server) {
	t.Helper()
	t.Setenv(envSourceHelper, "1")
	// the result is the arguments, so that two calls can return two results
	t.Setenv(envSourceEchoStdin, "1")
	root := t.TempDir()
	service, err := newGatewayService(
		filepath.Join(root, "store"), testSeed, "gateway:test",
		filepath.Join(root, "registry.jsonl"),
		map[string]sourceSpec{
			"unkept": {argv: []string{os.Args[0]}, env: helperEnv, notRetained: true},
			"kept":   {argv: []string{os.Args[0]}, env: helperEnv},
		})
	if err != nil {
		t.Fatal(err)
	}
	if version != "" {
		service.receiptVersion = version
	}
	server := httptest.NewServer(service.handler())
	t.Cleanup(server.Close)
	return service, server
}

// artifactsHeld is the names under the store's artifacts/.
func artifactsHeld(t *testing.T, storeRoot string) map[string]bool {
	t.Helper()
	entries, err := os.ReadDir(filepath.Join(storeRoot, "artifacts"))
	if err != nil {
		t.Fatal(err)
	}
	held := map[string]bool{}
	for _, e := range entries {
		held[e.Name()] = true
	}
	return held
}

// An acquisition of a source that keeps no payload answers the result, and
// a receipt whose resultDigest is its digest and that carries artifact
// "not-retained" under the signature; nothing is written under artifacts/.
// A source of the same gateway that keeps its payload writes it, and mints
// the receipt it minted before, without the member. The session verifies,
// the receipt that kept nothing ok with the observation artifact-not-retained,
// and the member taken out is a signature mismatch.
func TestASourceThatKeepsNoPayloadReturnsTheBytesAndWritesNone(t *testing.T) {
	service, server := unkeptService(t, "")
	code, unkept := post(t, server, "/acquire", `{"session":"nr-1","source":"unkept","arguments":{"q":"a"}}`)
	if code != http.StatusOK {
		t.Fatalf("an acquisition of the source that keeps nothing: %d %v", code, unkept)
	}
	receipt := unkept["receipt"].(map[string]any)
	if receipt["artifact"] != artifactNotRetained {
		t.Fatalf("the receipt carries no artifact member: %v", receipt)
	}
	result, present := unkept["result"]
	if !present {
		t.Fatalf("the answer holds no result: %v", unkept)
	}
	resultJSON, err := parseJSON(mustJSON(t, result))
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(canon(resultJSON))
	digest := hex.EncodeToString(sum[:])
	if receipt["resultDigest"] != "sha256:"+digest {
		t.Fatalf("resultDigest %v is not the digest of the result returned, sha256:%s", receipt["resultDigest"], digest)
	}
	if held := artifactsHeld(t, service.storeRoot); len(held) != 0 {
		t.Fatalf("the source that keeps nothing wrote %v", held)
	}
	code, kept := post(t, server, "/acquire", `{"session":"nr-1","source":"kept","arguments":{"q":"b"}}`)
	if code != http.StatusOK {
		t.Fatalf("an acquisition of the source that keeps: %d %v", code, kept)
	}
	keptReceipt := kept["receipt"].(map[string]any)
	// another result, so that no bytes the kept call wrote are the ones the
	// first receipt names (those would be re-digested, and no observation
	// said: SPEC.md §1.3a, step 1)
	if keptReceipt["resultDigest"] == receipt["resultDigest"] {
		t.Fatalf("the two calls returned one result: %v", keptReceipt["resultDigest"])
	}
	if _, present := keptReceipt["artifact"]; present || len(keptReceipt) != len(receipt)-1 {
		t.Fatalf("the receipt of a source that keeps is the one it was: %v", keptReceipt)
	}
	if held := artifactsHeld(t, service.storeRoot); len(held) != 1 || !held[strings.TrimPrefix(keptReceipt["resultDigest"].(string), "sha256:")] {
		t.Fatalf("the source that keeps wrote its payload: %v", held)
	}
	if code, out := post(t, server, "/seal", `{"session":"nr-1"}`); code != http.StatusOK {
		t.Fatalf("seal: %d %v", code, out)
	}
	rep, err := verifyWithRegistry(service.storeRoot, service.regPath, service.authority, service.publicKey)
	if err != nil {
		t.Fatal(err)
	}
	if !rep.OK || len(rep.Observations) != 1 || rep.Observations[0]["observation"] != observationNotRetained {
		t.Fatalf("the verdict: %+v", rep)
	}
	path := filepath.Join(service.storeRoot, "receipts", "nr-1", "0.json")
	minted, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	member := `"artifact":"not-retained",`
	if !strings.Contains(string(minted), member) {
		t.Fatalf("the receipt file holds no %s: %s", member, minted)
	}
	if err := os.WriteFile(path, []byte(strings.Replace(string(minted), member, "", 1)), 0o600); err != nil {
		t.Fatal(err)
	}
	rep, err = verifyWithRegistry(service.storeRoot, service.regPath, service.authority, service.publicKey)
	if err != nil {
		t.Fatal(err)
	}
	if rep.OK || rep.Findings[0]["status"] != "signature-mismatch" {
		t.Fatalf("the member taken out: %+v", rep.Findings)
	}
}

// Only a version 3 receipt can say its call kept nothing: a gateway minting
// version 2 refuses the acquisition, and writes no receipt and no payload.
func TestASourceThatKeepsNoPayloadRefusesAVersion2Receipt(t *testing.T) {
	service, server := unkeptService(t, receiptVersion)
	if code, out := post(t, server, "/acquire", `{"session":"nr-2","source":"unkept","arguments":{"q":"a"}}`); code == http.StatusOK {
		t.Fatalf("a version 2 acquisition of a source that keeps nothing: %d %v", code, out)
	}
	if held := artifactsHeld(t, service.storeRoot); len(held) != 0 {
		t.Fatalf("wrote %v", held)
	}
	if _, err := os.Stat(filepath.Join(service.storeRoot, "receipts", "nr-2", "0.json")); err == nil {
		t.Fatal("a receipt was written")
	}
}

// A platform's artifact (engineVersion 22): the one value "not-retained",
// fixed on the platform's history and live sources, on a platform that
// allows no write; refused by name before version 22. A refusal names the
// platform and quotes nothing of the value.
func TestThePlatformArtifactConfiguration(t *testing.T) {
	catalog := catalogWith(t, map[string]string{"postgres": postgresBinding})
	ref := "postgres@" + digestOf(postgresBinding)
	at := func(version, platformExtra string, ops ...string) string {
		if len(ops) == 0 {
			ops = []string{"history", "live"}
		}
		return strings.Replace(engineJSON(t, catalog, ``, platformJSONFor(t, "warehouse", ref, "engine-warehouse", platformExtra, ops...)), `"engineVersion":"1"`, `"engineVersion":"`+version+`"`, 1)
	}
	cfg, sources, err := load(t, at("22", `,"artifact":"not-retained"`))
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.platforms) != 1 || !cfg.platforms[0].notRetained || len(sources) != 2 ||
		!sources["warehouse/history"].notRetained || !sources["warehouse/live"].notRetained {
		t.Fatalf("the member on both sources: %+v %+v", cfg.platforms, sources)
	}
	// An http live operation's source keeps none either.
	records := catalogWith(t, map[string]string{"records": recordsBinding})
	text := strings.Replace(engineJSON(t, records, ``, platformJSONFor(t, "records", "records@"+digestOf(recordsBinding), "engine-docs", `,"artifact":"not-retained"`, "live")), `"engineVersion":"1"`, `"engineVersion":"22"`, 1)
	if _, sources, err := load(t, text); err != nil || len(sources) != 1 || sources["records/live"].shape != "http" || !sources["records/live"].notRetained {
		t.Fatalf("an http live source: %v %+v", err, sources)
	}
	// Beside a scope, which changes nothing of what is kept.
	if _, sources, err := load(t, at("22", `,"scope":"kappa-a","artifact":"not-retained"`)); err != nil || !sources["warehouse/live"].notRetained || sources["warehouse/live"].scope != "kappa-a" {
		t.Fatalf("beside a scope: %v %+v", err, sources)
	}
	// A version-22 file without the member keeps every payload.
	if _, sources, err := load(t, at("22", ``)); err != nil || sources["warehouse/history"].notRetained || sources["warehouse/live"].notRetained {
		t.Fatalf("version 22 without the member: %v %+v", err, sources)
	}
	const outOfForm = `platform warehouse: artifact must be the string "not-retained"`
	for _, tc := range []struct{ name, text, want, quoted string }{
		{"version 21", at("21", `,"artifact":"not-retained"`), "platform warehouse: artifact is a version-22 member; engineVersion 21 has no artifact", ""},
		{"another value", at("22", `,"artifact":"kept-elsewhere"`), outOfForm, "kept-elsewhere"},
		{"another case", at("22", `,"artifact":"Not-Retained"`), outOfForm, "Not-Retained"},
		{"empty", at("22", `,"artifact":""`), outOfForm, ""},
		{"null", at("22", `,"artifact":null`), outOfForm, ""},
		{"true", at("22", `,"artifact":true`), outOfForm, ""},
		{"an array", at("22", `,"artifact":["not-retained"]`), outOfForm, ""},
		{"beside write", at("22", `,"write":true,"artifact":"not-retained"`, "history", "live", "write"), "platform warehouse: artifact \"not-retained\" keeps no payload, and the platform sets write: true", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, _, err := load(t, tc.text)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("want %q, got %v", tc.want, err)
			}
			if tc.quoted != "" && strings.Contains(err.Error(), tc.quoted) {
				t.Fatalf("the refusal quotes the value: %v", err)
			}
		})
	}
}

// connect --replace keeps a platform's artifact, which connect has no flag
// for: an entry written without it would keep the payloads the operator
// chose not to hold. A replacement that sets --write is refused before
// anything is asked, and the file is left as it was.
func TestConnectReplaceKeepsTheArtifactMember(t *testing.T) {
	f := newConnectFixture(t, currentPolicyBinding, ``)
	entry := `"warehouse":{"binding":"postgres@` + digestOf(currentPolicyBinding) + `","credentials":{"history":{"file":"` + escapePath(f.credentials) + `"},"live":{"file":"` + escapePath(f.credentials) + `"}},"user":"engine-warehouse","operationDescriptors":{"live":"sha256:0000000000000000000000000000000000000000000000000000000000000000"},"artifact":"not-retained"}`
	text := strings.Replace(strings.Replace(f.fileText(t), `"engineVersion":"1"`, `"engineVersion":"22"`, 1), `"platforms":{}`, `"platforms":{`+entry+`}`, 1)
	if err := os.WriteFile(f.config, []byte(text), 0o640); err != nil {
		t.Fatal(err)
	}
	if _, _, err := loadEngineConfig(f.config, stubAccounts(stubUsers)); err != nil {
		t.Fatal(err)
	}
	req := f.request()
	req.replace = true
	req.write = true
	req.credentials = map[string]string{"history": f.credentials, "live": f.credentials, "write": f.credentials}
	if _, err := connect(context.Background(), req, f.host, f.check); err == nil || err.Error() != `platform warehouse keeps no payload (artifact "not-retained"), which --replace keeps, and a platform that keeps no payload allows no write; remove artifact from the file first, or replace the entry without --write` {
		t.Fatalf("a replacement with --write: %v", err)
	}
	if len(f.asked) != 0 || f.fileText(t) != text {
		t.Fatal("nothing is asked and nothing is written for a replacement the member would not fit")
	}
	req.write = false
	req.credentials = map[string]string{"history": f.credentials, "live": f.credentials}
	f.captured = `{"query":{"description":"Run a query","inputSchemaText":"{\"type\":\"object\"}"}}`
	if _, err := connect(context.Background(), req, f.host, f.check); err != nil {
		t.Fatal(err)
	}
	for _, spec := range f.asked {
		if !spec.notRetained {
			t.Fatalf("connect asked of a source without the member it keeps: %+v", spec)
		}
	}
	after, bindings, err := loadEngineConfig(f.config, stubAccounts(stubUsers))
	if err != nil {
		t.Fatal(err)
	}
	if sources := deriveSources(after, bindings); after.version != "22" || !after.platforms[0].notRetained || !sources["warehouse/live"].notRetained {
		t.Fatalf("version %s: the member kept as written", after.version)
	}
	if written := f.fileText(t); !strings.Contains(written, `"artifact": "not-retained"`) {
		t.Fatalf("the file as written: %s", written)
	}
}
