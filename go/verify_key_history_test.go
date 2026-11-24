package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// verifyKeyHistoryLine is the line the command writes for a vector, derived
// from the vector alone: the same derivation verify-ts's test makes, so that
// the two tools' outputs are held to one line, byte for byte. The version
// of an accepted history is the one its own keyHistoryVersion names.
func verifyKeyHistoryLine(t *testing.T, v keyHistoryVector) string {
	t.Helper()
	if v.Expected.Accepted == nil {
		return fmt.Sprintf(`{"accepted":false,"refused":%q}`, v.Expected.Refused) + "\n"
	}
	var doc struct {
		Version string `json:"keyHistoryVersion"`
	}
	if err := json.Unmarshal([]byte(v.History), &doc); err != nil {
		t.Fatalf("%s: %v", v.Name, err)
	}
	return fmt.Sprintf(`{"accepted":true,"version":%q,"keys":%d,"inForce":%q}`, doc.Version, v.Expected.Accepted.Keys, v.Expected.Accepted.InForce) + "\n"
}

// verifyKeyHistoryArgs is a vector's command line over a file: its pin as
// the command takes it, and its requireVersion.
func verifyKeyHistoryArgs(t *testing.T, v keyHistoryVector, file string) []string {
	t.Helper()
	pin, err := keyHistoryPinOf(corpusPath(), v.Pin)
	if err != nil {
		t.Fatalf("%s: %v", v.Name, err)
	}
	args := []string{"--public-key", hex.EncodeToString(pin.key)}
	if pin.alg == algES256 {
		args = append(args, "--public-key-alg", algES256)
	}
	if v.RequireVersion != "" {
		args = append(args, "--require-version", v.RequireVersion)
	}
	return append(args, file)
}

func runVerifyKeyHistory(args []string, stdin string) (int, string, string) {
	var out, errOut bytes.Buffer
	code := cmdVerifyKeyHistory(args, strings.NewReader(stdin), &out, &errOut)
	return code, out.String(), errOut.String()
}

func keyHistoryVectorByName(t *testing.T, name string) keyHistoryVector {
	t.Helper()
	v, err := readKeyHistoryVector(filepath.Join(corpusPath("key-history"), name+".json"))
	if err != nil {
		t.Fatal(err)
	}
	return v
}

// every key-history vector, through the command: the exit code, and the one
// line it writes, byte for byte.
func TestVerifyKeyHistoryEveryVector(t *testing.T) {
	paths, err := keyHistoryVectorPaths(corpusPath())
	if err != nil {
		t.Fatal(err)
	}
	if len(paths) != 29 {
		t.Fatalf("%d key-history vectors, 29 held", len(paths))
	}
	dir := t.TempDir()
	for _, path := range paths {
		v, err := readKeyHistoryVector(path)
		if err != nil {
			t.Fatal(err)
		}
		file := filepath.Join(dir, v.Name+".json")
		if err := os.WriteFile(file, []byte(v.History), 0o600); err != nil {
			t.Fatal(err)
		}
		code, out, errOut := runVerifyKeyHistory(verifyKeyHistoryArgs(t, v, file), "")
		want, wantCode := verifyKeyHistoryLine(t, v), 1
		if v.Expected.Accepted != nil {
			wantCode = 0
		}
		if code != wantCode || out != want {
			t.Errorf("%s: exit %d, %q; want exit %d, %q (%s)", v.Name, code, out, wantCode, want, errOut)
		}
	}
}

// standard input gives the line a file gives.
func TestVerifyKeyHistoryStandardInputIsTheFile(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{"kh-v2-across-store", "kh-v1-version-2-required", "kh-v2-p256-continuation"} {
		v := keyHistoryVectorByName(t, name)
		file := filepath.Join(dir, name+".json")
		if err := os.WriteFile(file, []byte(v.History), 0o600); err != nil {
			t.Fatal(err)
		}
		fileArgs := verifyKeyHistoryArgs(t, v, file)
		fromFileCode, fromFile, _ := runVerifyKeyHistory(fileArgs, "")
		stdinArgs := append(append([]string{}, fileArgs[:len(fileArgs)-1]...), "-")
		code, out, errOut := runVerifyKeyHistory(stdinArgs, v.History)
		if code != fromFileCode || out != fromFile || out != verifyKeyHistoryLine(t, v) {
			t.Errorf("%s: standard input exit %d, %q; file exit %d, %q (%s)", name, code, out, fromFileCode, fromFile, errOut)
		}
	}
}

// the pin is optional; where it is given, a first key that is not it is
// refused, and --require-version "2" refuses a history of version "1".
func TestVerifyKeyHistoryPinAndRequireVersion(t *testing.T) {
	dir := t.TempDir()
	v := keyHistoryVectorByName(t, "kh-v1-one-key")
	file := filepath.Join(dir, "one.json")
	if err := os.WriteFile(file, []byte(v.History), 0o600); err != nil {
		t.Fatal(err)
	}
	accepted := verifyKeyHistoryLine(t, v)
	if code, out, errOut := runVerifyKeyHistory([]string{file}, ""); code != 0 || out != accepted {
		t.Errorf("no pin: exit %d, %q (%s)", code, out, errOut)
	}
	p256, err := os.ReadFile(corpusPath("TEST-P256-PUBLIC-KEY"))
	if err != nil {
		t.Fatal(err)
	}
	if code, out, _ := runVerifyKeyHistory([]string{"--public-key", strings.TrimSpace(string(p256)), "--public-key-alg", "ES256", file}, ""); code != 1 || out != `{"accepted":false,"refused":"key"}`+"\n" {
		t.Errorf("another key pinned: exit %d, %q", code, out)
	}
	if code, out, _ := runVerifyKeyHistory([]string{"--require-version", "2", file}, ""); code != 1 || out != `{"accepted":false,"refused":"version"}`+"\n" {
		t.Errorf("version 2 required of version 1: exit %d, %q", code, out)
	}
}

func TestVerifyKeyHistoryUsageErrors(t *testing.T) {
	dir := t.TempDir()
	v := keyHistoryVectorByName(t, "kh-v1-one-key")
	file := filepath.Join(dir, "one.json")
	if err := os.WriteFile(file, []byte(v.History), 0o600); err != nil {
		t.Fatal(err)
	}
	key, err := os.ReadFile(corpusPath("TEST-PUBLIC-KEY"))
	if err != nil {
		t.Fatal(err)
	}
	edHex := strings.TrimSpace(string(key))
	for name, args := range map[string][]string{
		"a bad flag":                        {"--frobnicate", file},
		"a bad flag after the key":          {"--public-key", edHex, "--frobnicate", file},
		"no file":                           {},
		"no file after the options":         {"--public-key", edHex, "--require-version", "2"},
		"two files":                         {file, file},
		"a file and standard input":         {file, "-"},
		"--require-version 3":               {"--require-version", "3", file},
		"--require-version 1":               {"--require-version", "1", file},
		"--require-version without a value": {"--require-version"},
		"--public-key without a value":      {"--public-key"},
		"an uppercase key":                  {"--public-key", strings.ToUpper(edHex), file},
		"a key of 63 characters":            {"--public-key", edHex[1:], file},
		"an algorithm of another name":      {"--public-key", edHex, "--public-key-alg", "ES384", file},
		"an algorithm without a value":      {"--public-key", edHex, "--public-key-alg"},
		"an Ed25519 key under ES256":        {"--public-key", edHex, "--public-key-alg", "ES256", file},
		"an algorithm without a key":        {"--public-key-alg", "ES256", file},
		"the options in the other order":    {"--require-version", "2", "--public-key", edHex, file},
		"a file that is not there":          {filepath.Join(dir, "absent.json")},
		"a directory":                       {dir},
	} {
		code, out, errOut := runVerifyKeyHistory(args, "")
		if code != 2 || out != "" || errOut == "" {
			t.Errorf("%s: exit %d, stdout %q, stderr %q", name, code, out, errOut)
		}
	}
}

// an input of keyHistoryInputBound bytes is read, and one byte more is a
// usage-level refusal made before it is parsed.
func TestVerifyKeyHistoryInputBound(t *testing.T) {
	if keyHistoryInputBound != 16777216 {
		t.Fatalf("the bound is %d bytes; docs and verify-ts state 16777216", keyHistoryInputBound)
	}
	v := keyHistoryVectorByName(t, "kh-v1-one-key")
	dir := t.TempDir()
	padded := func(n int) string { return v.History + strings.Repeat(" ", n-len(v.History)) }
	at, over := padded(keyHistoryInputBound), padded(keyHistoryInputBound+1)
	atFile, overFile := filepath.Join(dir, "at.json"), filepath.Join(dir, "over.json")
	for file, text := range map[string]string{atFile: at, overFile: over} {
		if err := os.WriteFile(file, []byte(text), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	for name, run := range map[string]func(file, text string) (int, string, string){
		"a file": func(file, _ string) (int, string, string) {
			return runVerifyKeyHistory(verifyKeyHistoryArgs(t, v, file), "")
		},
		"standard input": func(_, text string) (int, string, string) {
			args := verifyKeyHistoryArgs(t, v, "-")
			return runVerifyKeyHistory(args, text)
		},
	} {
		// at the bound it is read: any verdict, and a line of it on standard output
		code, out, errOut := run(atFile, at)
		if (code != 0 && code != 1) || !strings.HasPrefix(out, `{"accepted":`) {
			t.Errorf("%s at the bound: exit %d, %q (%s)", name, code, out, errOut)
		}
		code, out, errOut = run(overFile, over)
		if code != 2 || out != "" || !strings.Contains(errOut, "larger than 16777216 bytes") {
			t.Errorf("%s one byte over the bound: exit %d, stdout %q, stderr %q", name, code, out, errOut)
		}
	}
}
