package main

import (
	"bytes"
	"encoding/hex"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
)

func TestParseServeOptions(t *testing.T) {
	tests := []struct {
		name        string
		args        []string
		wantOptions serveOptions
		wantErr     string
	}{
		{
			name:    "missing required arguments",
			args:    []string{},
			wantErr: "usage: gateway serve",
		},
		{
			name:    "unknown option",
			args:    []string{"store", "seed", "authority", "registry", "--bogus"},
			wantErr: `unknown option "--bogus"`,
		},
		{
			name:    "source without following value",
			args:    []string{"store", "seed", "authority", "registry", "--source"},
			wantErr: "--source requires",
		},
		{
			name:    "port without following value",
			args:    []string{"store", "seed", "authority", "registry", "--port"},
			wantErr: "--port requires",
		},
		{
			name:    "duplicate port option",
			args:    []string{"store", "seed", "authority", "registry", "--port", "8787", "--port", "9000"},
			wantErr: "duplicate --port option",
		},
		{
			name:    "port is a service name",
			args:    []string{"store", "seed", "authority", "registry", "--port", "http"},
			wantErr: "is not a number between 1 and 65535",
		},
		{
			name:    "port carries a host",
			args:    []string{"store", "seed", "authority", "registry", "--port", "localhost:9000"},
			wantErr: "is not a number between 1 and 65535",
		},
		{
			// "-1" is not "--"-prefixed, so it is consumed as the --port value
			// and rejected by validatePort rather than as an unknown option --
			// which gives the operator the message about the port, not about a
			// flag they did not write.
			name:    "port is negative",
			args:    []string{"store", "seed", "authority", "registry", "--port", "-1"},
			wantErr: "is not a number between 1 and 65535",
		},
		{
			name:    "port is above the range",
			args:    []string{"store", "seed", "authority", "registry", "--port", "65536"},
			wantErr: "is not a number between 1 and 65535",
		},
		{
			name:    "port zero asks the kernel to choose",
			args:    []string{"store", "seed", "authority", "registry", "--port", "0"},
			wantErr: "is not a number between 1 and 65535",
		},
		{
			name:    "port is empty",
			args:    []string{"store", "seed", "authority", "registry", "--port", ""},
			wantErr: "--port must not be empty",
		},
		{
			name:    "port has surrounding space",
			args:    []string{"store", "seed", "authority", "registry", "--port", " 8787"},
			wantErr: "is not a number between 1 and 65535",
		},
		{
			name:    "port has a sign",
			args:    []string{"store", "seed", "authority", "registry", "--port", "+8787"},
			wantErr: "is not a number between 1 and 65535",
		},
		{
			name: "port at the top of the range is accepted",
			args: []string{"store", "seed", "authority", "registry", "--port", "65535"},
			wantOptions: serveOptions{
				sources: map[string]sourceSpec{},
				port:    "65535",
			},
		},
		{
			name: "port at the bottom of the range is accepted",
			args: []string{"store", "seed", "authority", "registry", "--port", "1"},
			wantOptions: serveOptions{
				sources: map[string]sourceSpec{},
				port:    "1",
			},
		},
		{
			name:    "source value without equals",
			args:    []string{"store", "seed", "authority", "registry", "--source", "cmd"},
			wantErr: "--source expects NAME=CMD",
		},
		{
			name:    "source with empty name",
			args:    []string{"store", "seed", "authority", "registry", "--source", "=cmd"},
			wantErr: "--source name must not be empty",
		},
		{
			name:    "source with empty command",
			args:    []string{"store", "seed", "authority", "registry", "--source", "name="},
			wantErr: "--source command must not be empty",
		},
		{
			name: "duplicate source name",
			args: []string{
				"store", "seed", "authority", "registry",
				"--source", "screen=go version",
				"--source", "screen=go",
			},
			wantErr: `duplicate source "screen"`,
		},
		{
			name:    "unexpected positional argument",
			args:    []string{"store", "seed", "authority", "registry", "extra"},
			wantErr: `unexpected argument "extra"`,
		},
		{
			name: "required arguments only",
			args: []string{"store", "seed", "authority", "registry"},
			wantOptions: serveOptions{
				sources: map[string]sourceSpec{},
				port:    "8787",
			},
		},
		{
			name: "port only",
			args: []string{"store", "seed", "authority", "registry", "--port", "9000"},
			wantOptions: serveOptions{
				sources: map[string]sourceSpec{},
				port:    "9000",
			},
		},
		{
			name: "port before source",
			args: []string{
				"store", "seed", "authority", "registry",
				"--port", "9000",
				"--source", "screening=go version",
			},
			wantOptions: serveOptions{
				sources: map[string]sourceSpec{
					"screening": {argv: []string{"go", "version"}},
				},
				port: "9000",
			},
		},
		{
			name: "valid repeated sources and port",
			args: []string{
				"store", "seed", "authority", "registry",
				"--source", "screen=go",
				"--source", "quote=go version",
				"--port", "9000",
			},
			wantOptions: serveOptions{
				sources: map[string]sourceSpec{
					"screen": {argv: []string{"go"}},
					"quote":  {argv: []string{"go", "version"}},
				},
				port: "9000",
			},
		},
		{
			name: "source env sets a value",
			args: []string{
				"store", "seed", "authority", "registry",
				"--source", "screen=go",
				"--source-env", "screen=FOO=bar",
			},
			wantOptions: serveOptions{
				sources: map[string]sourceSpec{
					"screen": {argv: []string{"go"}, env: []string{"FOO=bar"}},
				},
				port: "8787",
			},
		},
		{
			name: "source env copies by name and may precede the source it names",
			args: []string{
				"store", "seed", "authority", "registry",
				"--source-env", "screen=FOO",
				"--source-env", "screen=BAR=x=y",
				"--source", "screen=go",
			},
			wantOptions: serveOptions{
				sources: map[string]sourceSpec{
					"screen": {argv: []string{"go"}, env: []string{"FOO", "BAR=x=y"}},
				},
				port: "8787",
			},
		},
		{
			name:    "source env for an undeclared source",
			args:    []string{"store", "seed", "authority", "registry", "--source-env", "nosuch=FOO"},
			wantErr: `--source-env names undeclared source "nosuch"`,
		},
		{
			name:    "source env without a key",
			args:    []string{"store", "seed", "authority", "registry", "--source", "screen=go", "--source-env", "screen="},
			wantErr: "--source-env expects NAME=KEY or NAME=KEY=VALUE",
		},
		{
			name:    "source env without equals",
			args:    []string{"store", "seed", "authority", "registry", "--source", "screen=go", "--source-env", "screen"},
			wantErr: "--source-env expects NAME=KEY or NAME=KEY=VALUE",
		},
		{
			name:    "source env missing value",
			args:    []string{"store", "seed", "authority", "registry", "--source-env"},
			wantErr: "--source-env requires",
		},
		{
			name: "source user",
			args: []string{
				"store", "seed", "authority", "registry",
				"--source", "screen=go",
				"--source-user", "screen=nobody",
			},
			wantOptions: serveOptions{
				sources: map[string]sourceSpec{
					"screen": {argv: []string{"go"}, user: "nobody"},
				},
				port: "8787",
			},
		},
		{
			name: "source user twice",
			args: []string{
				"store", "seed", "authority", "registry",
				"--source", "screen=go",
				"--source-user", "screen=nobody",
				"--source-user", "screen=daemon",
			},
			wantErr: `duplicate --source-user for "screen"`,
		},
		{
			name:    "source user for an undeclared source",
			args:    []string{"store", "seed", "authority", "registry", "--source-user", "nosuch=nobody"},
			wantErr: `--source-user names undeclared source "nosuch"`,
		},
		{
			name:    "source user without a user",
			args:    []string{"store", "seed", "authority", "registry", "--source", "screen=go", "--source-user", "screen="},
			wantErr: "--source-user expects NAME=USER",
		},
		{
			name: "source max output",
			args: []string{"store", "seed", "authority", "registry", "--source-max-output", "4096"},
			wantOptions: serveOptions{
				sources:         map[string]sourceSpec{},
				port:            "8787",
				maxSourceOutput: 4096,
			},
		},
		{
			name:    "source max output zero",
			args:    []string{"store", "seed", "authority", "registry", "--source-max-output", "0"},
			wantErr: `--source-max-output "0" is not a positive number of bytes`,
		},
		{
			name:    "source max output not a number",
			args:    []string{"store", "seed", "authority", "registry", "--source-max-output", "1MiB"},
			wantErr: `--source-max-output "1MiB" is not a positive number of bytes`,
		},
		{
			name: "duplicate source max output",
			args: []string{
				"store", "seed", "authority", "registry",
				"--source-max-output", "1",
				"--source-max-output", "2",
			},
			wantErr: "duplicate --source-max-output option",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, msg, ok := parseServeOptions(tt.args)
			if tt.wantErr != "" {
				if ok {
					t.Fatalf("parseServeOptions() accepted invalid args %v", tt.args)
				}
				if !strings.Contains(msg, tt.wantErr) {
					t.Fatalf("parseServeOptions() error = %q, want containing %q", msg, tt.wantErr)
				}
				return
			}
			if !ok {
				t.Fatalf("parseServeOptions() rejected valid args %v: %s", tt.args, msg)
			}
			if got.port != tt.wantOptions.port {
				t.Fatalf("port = %q, want %q", got.port, tt.wantOptions.port)
			}
			if !reflect.DeepEqual(got.sources, tt.wantOptions.sources) {
				t.Fatalf("sources = %v, want %v", got.sources, tt.wantOptions.sources)
			}
			wantMax := tt.wantOptions.maxSourceOutput
			if wantMax == 0 {
				wantMax = defaultMaxSourceOutput
			}
			if got.maxSourceOutput != wantMax {
				t.Fatalf("maxSourceOutput = %d, want %d", got.maxSourceOutput, wantMax)
			}
		})
	}
}

func TestCmdServeRejectsMalformedOptions(t *testing.T) {
	null, err := os.CreateTemp(t.TempDir(), "stderr")
	if err != nil {
		t.Fatal(err)
	}
	oldStderr := os.Stderr
	os.Stderr = null
	t.Cleanup(func() {
		os.Stderr = oldStderr
		null.Close()
	})

	for _, tt := range []struct {
		name string
		args []string
	}{
		{name: "unknown option", args: []string{"store", "seed", "authority", "registry", "--bogus"}},
		{name: "source missing value", args: []string{"store", "seed", "authority", "registry", "--source"}},
		{name: "port missing value", args: []string{"store", "seed", "authority", "registry", "--port"}},
		{name: "source no equals", args: []string{"store", "seed", "authority", "registry", "--source", "cmd"}},
		{name: "empty source name", args: []string{"store", "seed", "authority", "registry", "--source", "=cmd"}},
		{name: "empty source command", args: []string{"store", "seed", "authority", "registry", "--source", "name="}},
		{name: "source env for undeclared source", args: []string{"store", "seed", "authority", "registry", "--source-env", "nosuch=FOO"}},
		{name: "source max output zero", args: []string{"store", "seed", "authority", "registry", "--source-max-output", "0"}},
		{
			name: "duplicate source name",
			args: []string{
				"store", "seed", "authority", "registry",
				"--source", "screen=go version",
				"--source", "screen=go",
			},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if got := cmdServe(tt.args); got != 2 {
				t.Fatalf("cmdServe() = %d, want 2", got)
			}
		})
	}
}

func TestKeygenCreatesANewSeed(t *testing.T) {
	path := filepath.Join(t.TempDir(), "gateway.seed")
	if code := cmdKeygen([]string{path}); code != 0 {
		t.Fatalf("cmdKeygen() = %d, want 0", code)
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read seed: %v", err)
	}
	text, ok := strings.CutSuffix(string(raw), "\n")
	if !ok {
		t.Fatalf("seed file does not end in exactly one newline: %q", raw)
	}
	if len(text) != 64 {
		t.Fatalf("seed = %d characters, want 64", len(text))
	}
	if text != strings.ToLower(text) {
		t.Fatalf("seed is not lowercase hexadecimal: %q", text)
	}
	seed, err := hex.DecodeString(text)
	if err != nil {
		t.Fatalf("decode seed: %v", err)
	}
	if len(seed) != seedBytes {
		t.Fatalf("seed decodes to %d bytes, want %d", len(seed), seedBytes)
	}

	if runtime.GOOS != "windows" {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatalf("stat seed: %v", err)
		}
		if mode := info.Mode().Perm(); mode&0o077 != 0 {
			t.Fatalf("seed mode = %04o, want no group or world access", mode)
		}
	}
}

// The point of the issue: a rerun must not silently rotate the signing identity
// that every already-issued receipt and seal was produced under.
func TestKeygenRefusesToReplaceAnExistingPath(t *testing.T) {
	t.Run("regular file", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "gateway.seed")
		original := []byte("do not touch me\n")
		if err := os.WriteFile(path, original, 0o600); err != nil {
			t.Fatal(err)
		}
		if code := cmdKeygen([]string{path}); code == 0 {
			t.Fatal("cmdKeygen() = 0, want non-zero for an existing file")
		}
		after, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(after, original) {
			t.Fatalf("existing seed changed: %q -> %q", original, after)
		}
	})

	// Recorded from a mutation check: this subtest passes under the previous
	// os.WriteFile implementation too, because that already failed with EISDIR.
	// It is kept because the issue names it and because it pins the behaviour
	// against a future change that would create through a path, but it does not
	// on its own demonstrate the fix -- the regular-file and symlink subtests
	// are the two that fail without exclusive creation.
	t.Run("directory", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "gateway.seed")
		if err := os.Mkdir(path, 0o700); err != nil {
			t.Fatal(err)
		}
		if code := cmdKeygen([]string{path}); code == 0 {
			t.Fatal("cmdKeygen() = 0, want non-zero for an existing directory")
		}
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if !info.IsDir() {
			t.Fatal("the directory was replaced")
		}
	})

	t.Run("symlink is not followed", func(t *testing.T) {
		dir := t.TempDir()
		target := filepath.Join(dir, "real-secret")
		original := []byte("the operator's actual seed\n")
		if err := os.WriteFile(target, original, 0o600); err != nil {
			t.Fatal(err)
		}
		link := filepath.Join(dir, "gateway.seed")
		if err := os.Symlink(target, link); err != nil {
			t.Skipf("symlinks unavailable here: %v", err)
		}
		if code := cmdKeygen([]string{link}); code == 0 {
			t.Fatal("cmdKeygen() = 0, want non-zero for an existing symlink")
		}
		after, err := os.ReadFile(target)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(after, original) {
			t.Fatalf("the symlink was followed and its target overwritten: %q -> %q", original, after)
		}
		info, err := os.Lstat(link)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode()&os.ModeSymlink == 0 {
			t.Fatal("the symlink itself was replaced by a regular file")
		}
	})
}

func TestSourceCommandResolution(t *testing.T) {
	null, err := os.CreateTemp(t.TempDir(), "stderr")
	if err != nil {
		t.Fatal(err)
	}
	oldStderr := os.Stderr
	os.Stderr = null
	t.Cleanup(func() {
		os.Stderr = oldStderr
		null.Close()
	})

	tests := []struct {
		name string
		args []string
		want int
	}{
		{
			name: "resolves",
			args: []string{"store", "seed", "authority", "registry", "--source", "echo=go version"},
			want: 1, // fails later trying to read the seed file since "seed" does not exist
		},
		{
			name: "does not resolve",
			args: []string{"store", "seed", "authority", "registry", "--source", "missing=this-command-does-not-exist ok"},
			want: 2, // parseServeOptions fails, returning 2
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := cmdServe(tt.args); got != tt.want {
				t.Fatalf("cmdServe() = %d, want %d", got, tt.want)
			}
		})
	}
}

func TestCmdCanon(t *testing.T) {
	tests := []struct {
		name       string
		input      string
		wantCode   int
		wantStdout string
		checkRe    bool
	}{
		{
			name:       "valid object",
			input:      `{"b": 2, "a": 1}`,
			wantCode:   0,
			wantStdout: `{"a":1,"b":2}`,
		},
		{
			name:       "key ordering and escaping",
			input:      `{"z": "foo\nbar", "a": 1, "c": "\u003c"}`,
			wantCode:   0,
			wantStdout: `{"a":1,"c":"<","z":"foo\nbar"}`,
			checkRe:    true,
		},
		{
			name:       "malformed JSON",
			input:      `{bad}`,
			wantCode:   1,
			wantStdout: "",
		},
		{
			name:       "empty input",
			input:      "",
			wantCode:   1,
			wantStdout: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotCode, gotStdout := runCmdCanon(t, tt.input)
			if gotCode != tt.wantCode {
				t.Fatalf("cmdCanon() = %d, want %d", gotCode, tt.wantCode)
			}
			if gotStdout != tt.wantStdout {
				t.Fatalf("stdout = %q, want %q", gotStdout, tt.wantStdout)
			}
			if tt.wantCode == 0 && strings.HasSuffix(gotStdout, "\n") {
				t.Fatal("stdout has trailing newline")
			}
			if tt.checkRe {
				gotCode2, gotStdout2 := runCmdCanon(t, gotStdout)
				if gotCode2 != 0 {
					t.Fatalf("second cmdCanon() = %d, want 0", gotCode2)
				}
				if gotStdout2 != gotStdout {
					t.Fatalf("second run output %q does not match first run output %q", gotStdout2, gotStdout)
				}
			}
		})
	}
}

func runCmdCanon(t *testing.T, input string) (int, string) {
	t.Helper()

	inF, err := os.CreateTemp(t.TempDir(), "stdin")
	if err != nil {
		t.Fatal(err)
	}
	defer inF.Close()
	if _, err := inF.Write([]byte(input)); err != nil {
		t.Fatal(err)
	}
	if _, err := inF.Seek(0, 0); err != nil {
		t.Fatal(err)
	}

	outF, err := os.CreateTemp(t.TempDir(), "stdout")
	if err != nil {
		t.Fatal(err)
	}
	defer outF.Close()

	errF, err := os.CreateTemp(t.TempDir(), "stderr")
	if err != nil {
		t.Fatal(err)
	}
	defer errF.Close()

	oldStdin, oldStdout, oldStderr := os.Stdin, os.Stdout, os.Stderr
	defer func() {
		os.Stdin = oldStdin
		os.Stdout = oldStdout
		os.Stderr = oldStderr
	}()
	os.Stdin = inF
	os.Stdout = outF
	os.Stderr = errF

	code := cmdCanon()

	outBytes, err := os.ReadFile(outF.Name())
	if err != nil {
		t.Fatal(err)
	}

	return code, string(outBytes)
}

func TestReadPublicKey(t *testing.T) {
	reference, err := hex.DecodeString("fc9fa9b25640778d85953a5e1b4618cb8223565b6f566f739c73035079d7681b") // uses exact bytes
	if err != nil {
		t.Fatalf("decode reference key: %v", err)
	}
	lowerHex := hex.EncodeToString(reference)

	withLF := append([]byte{}, reference...)
	withLF[31] = '\n'

	tests := []struct {
		name    string
		raw     []byte
		want    []byte
		wantErr string
	}{
		{
			name: "32 raw bytes",
			raw:  reference,
			want: reference,
		},
		{
			name: "32 bytes with a trailing newline",
			raw:  append(append([]byte{}, reference...), '\n'),
			want: reference,
		},
		{
			name:    "32 bytes ending with LF plus trailing newline (TrimSpace eats LF)",
			raw:     append(append([]byte{}, withLF...), '\n'),
			wantErr: "expected 32 raw bytes, got 33",
		},
		{
			name: "64 lowercase hex characters",
			raw:  []byte(lowerHex),
			want: reference,
		},
		{
			// hex.DecodeString is case-insensitive; SPEC.md demands lowercase
			// wherever it governs hex, so this tolerance is readPublicKey's own
			name: "64 uppercase hex characters",
			raw:  []byte(strings.ToUpper(lowerHex)),
			want: reference,
		},
		{
			name: "corpus file shape: 64 hex characters and a newline",
			raw:  []byte(lowerHex + "\n"),
			want: reference,
		},
		{
			name:    "66 hex characters (even, decodes to 33 bytes)",
			raw:     []byte(lowerHex + "00"),
			wantErr: "expected 32 raw bytes, got 66",
		},
		{
			name:    "31 bytes",
			raw:     reference[:31],
			wantErr: "expected 32 raw bytes, got 31",
		},
		{
			name:    "33 bytes",
			raw:     append(append([]byte{}, reference...), 'x'),
			wantErr: "expected 32 raw bytes, got 33",
		},
		{
			name:    "63 hex characters",
			raw:     []byte(lowerHex[:63]),
			wantErr: "expected 32 raw bytes, got 63",
		},
		{
			name:    "65 hex characters",
			raw:     []byte(lowerHex + "0"),
			wantErr: "expected 32 raw bytes, got 65",
		},
		{
			name:    "64 characters that are not hex",
			raw:     bytes.Repeat([]byte("g"), 64),
			wantErr: "expected 32 raw bytes, got 64",
		},
		{
			name:    "empty input",
			raw:     []byte{},
			wantErr: "expected 32 raw bytes, got 0",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := readPublicKey(tt.raw)
			if tt.wantErr != "" {
				if err == nil {
					t.Fatalf("readPublicKey() accepted %d bytes, want error", len(tt.raw))
				}
				if !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("readPublicKey() error = %q, want containing %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("readPublicKey() error = %v, want none", err)
			}
			if !bytes.Equal(got, tt.want) {
				t.Fatalf("readPublicKey() = %x, want %x", got, tt.want)
			}
		})
	}
}

// captureStderr redirects os.Stderr for the rest of the test and returns a
// function that yields what was written so far.
func captureStderr(t *testing.T) func() string {
	t.Helper()
	file, err := os.CreateTemp(t.TempDir(), "stderr")
	if err != nil {
		t.Fatal(err)
	}
	oldStderr := os.Stderr
	os.Stderr = file
	t.Cleanup(func() {
		os.Stderr = oldStderr
		file.Close()
	})
	return func() string {
		raw, err := os.ReadFile(file.Name())
		if err != nil {
			t.Fatal(err)
		}
		return string(raw)
	}
}

// A seed anyone but its owner can read is refused before the gateway creates
// anything: keygen writes 0600, and a source running as another user on the
// same host is exactly the reader the mode bits exclude (ADR-0001).
func TestCmdServeRefusesAReadableSeed(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("mode bits are not the seed's protection on Windows")
	}
	stderr := captureStderr(t)
	dir := t.TempDir()
	seed := filepath.Join(dir, "gateway.seed")
	if code := cmdKeygen([]string{seed}); code != 0 {
		t.Fatalf("cmdKeygen() = %d", code)
	}
	if err := os.Chmod(seed, 0o644); err != nil {
		t.Fatal(err)
	}
	store := filepath.Join(dir, "store")
	args := []string{store, seed, "gateway:test", filepath.Join(dir, "registry.jsonl"), "--port", "1"}
	if got := cmdServe(args); got != 1 {
		t.Fatalf("cmdServe() = %d, want 1", got)
	}
	if out := stderr(); !strings.Contains(out, "chmod 0600") {
		t.Fatalf("the refusal must name the fix; stderr was %q", out)
	}
	if _, err := os.Stat(store); err == nil {
		t.Fatal("the store was created before the seed was refused")
	}
}

// A source user the gateway cannot switch to is refused at startup rather
// than run as the signer. Unprivileged on Unix, unsupported elsewhere; either
// way the refusal happens before anything is created.
func TestCmdServeRefusesASourceUserItCannotSwitchTo(t *testing.T) {
	if runtime.GOOS != "windows" && os.Geteuid() == 0 {
		t.Skip("running as root: the switch would be permitted")
	}
	stderr := captureStderr(t)
	dir := t.TempDir()
	seed := filepath.Join(dir, "gateway.seed")
	if code := cmdKeygen([]string{seed}); code != 0 {
		t.Fatalf("cmdKeygen() = %d", code)
	}
	store := filepath.Join(dir, "store")
	args := []string{
		store, seed, "gateway:test", filepath.Join(dir, "registry.jsonl"),
		"--source", "screening=go", "--source-user", "screening=nobody", "--port", "1",
	}
	if got := cmdServe(args); got != 1 {
		t.Fatalf("cmdServe() = %d, want 1", got)
	}
	if out := stderr(); !strings.Contains(out, "--source-user screening") {
		t.Fatalf("the refusal must name the option; stderr was %q", out)
	}
	if _, err := os.Stat(store); err == nil {
		t.Fatal("the store was created before the source user was refused")
	}
}

// The command line's output bound reaches the service, and the declared
// sources reach it as declared.
func TestBuildServiceAppliesTheCommandLine(t *testing.T) {
	dir := t.TempDir()
	seed := filepath.Join(dir, "gateway.seed")
	if code := cmdKeygen([]string{seed}); code != 0 {
		t.Fatalf("cmdKeygen() = %d", code)
	}
	args := []string{
		filepath.Join(dir, "store"), seed, "gateway:test", filepath.Join(dir, "registry.jsonl"),
		"--source", "screening=go", "--source-env", "screening=FOO=bar", "--source-max-output", "4096",
	}
	opts, msg, ok := parseServeOptions(args)
	if !ok {
		t.Fatal(msg)
	}
	loaded, err := loadSeed(seed)
	if err != nil {
		t.Fatal(err)
	}
	service, err := buildService(args[0], loaded, args[2], args[3], opts)
	if err != nil {
		t.Fatal(err)
	}
	if service.maxSourceOutput != 4096 {
		t.Fatalf("maxSourceOutput = %d, want 4096", service.maxSourceOutput)
	}
	spec := service.sources["screening"]
	if !reflect.DeepEqual(spec.argv, []string{"go"}) || !reflect.DeepEqual(spec.env, []string{"FOO=bar"}) {
		t.Fatalf("source not wired as declared: %+v", spec)
	}
}

// loadSeed reads what keygen wrote through the same descriptor it judged.
func TestLoadSeedReadsWhatKeygenWrote(t *testing.T) {
	dir := t.TempDir()
	seed := filepath.Join(dir, "gateway.seed")
	if code := cmdKeygen([]string{seed}); code != 0 {
		t.Fatalf("cmdKeygen() = %d", code)
	}
	loaded, err := loadSeed(seed)
	if err != nil {
		t.Fatal(err)
	}
	if len(loaded) != seedBytes {
		t.Fatalf("loaded %d bytes, want %d", len(loaded), seedBytes)
	}
	if _, err := loadSeed(filepath.Join(dir, "missing")); err == nil {
		t.Fatal("a missing seed must be an error")
	}
}

// Startup marks inherited descriptors before it opens anything: the call is
// made even when the seed is missing, which is the earliest refusal.
func TestStartupMarksInheritedDescriptors(t *testing.T) {
	stderr := captureStderr(t)
	_ = stderr
	called := false
	previous := closeInheritedDescriptors
	closeInheritedDescriptors = func() { called = true }
	t.Cleanup(func() { closeInheritedDescriptors = previous })
	dir := t.TempDir()
	args := []string{filepath.Join(dir, "store"), filepath.Join(dir, "missing.seed"), "gateway:test", filepath.Join(dir, "registry.jsonl")}
	if got := cmdServe(args); got != 1 {
		t.Fatalf("cmdServe() = %d, want 1", got)
	}
	if !called {
		t.Fatal("startup did not mark inherited descriptors before opening the seed")
	}
}

// loadSeed returns exactly the bytes the file encodes, and refuses a file
// that is not the size of a seed file however its first bytes read.
func TestLoadSeedIsExactAndBounded(t *testing.T) {
	dir := t.TempDir()
	want := bytes.Repeat([]byte{0xab}, seedBytes)
	path := filepath.Join(dir, "known.seed")
	if err := os.WriteFile(path, []byte(hex.EncodeToString(want)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := loadSeed(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("loaded %x, want %x", got, want)
	}
	oversized := filepath.Join(dir, "oversized.seed")
	body := append([]byte(hex.EncodeToString(want)), bytes.Repeat([]byte(" "), maxSeedFileBytes)...)
	body = append(body, []byte("trailing garbage")...)
	if err := os.WriteFile(oversized, body, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadSeed(oversized); err == nil || !strings.Contains(err.Error(), "larger than a seed file") {
		t.Fatalf("an oversized seed file must be refused by size: %v", err)
	}
}

// An inherited anchor marker makes an ordinary invocation refuse to run.
func TestStrayAnchorMarkerIsRefused(t *testing.T) {
	stderr := captureStderr(t)
	t.Setenv(envGroupAnchor, "1")
	if !refuseStrayAnchorMarker() {
		t.Fatal("the marker must be refused")
	}
	if out := stderr(); !strings.Contains(out, envGroupAnchor) {
		t.Fatalf("the refusal must name the marker; stderr was %q", out)
	}
	t.Setenv(envGroupAnchor, "")
	if refuseStrayAnchorMarker() {
		t.Fatal("an ordinary environment must not be refused")
	}
}

// verify takes the decision-record directory of SPEC.md §4 step 6 as a flag or
// as the process contract's fourth positional argument, and refuses a stray
// option, an empty flag value, or a fifth argument as usage.
func TestCmdVerifyArgumentForms(t *testing.T) {
	stderr := captureStderr(t)
	_ = stderr
	oldStdin := os.Stdin
	t.Cleanup(func() { os.Stdin = oldStdin })
	usage := func(args ...string) {
		t.Helper()
		if got := cmdVerify(args); got != 2 {
			t.Fatalf("cmdVerify(%v) = %d, want 2 (usage)", args, got)
		}
	}
	usage("store", "registry")
	usage("store", "registry", "authority", "--decision-records")
	usage("store", "registry", "authority", "")
	usage("store", "registry", "authority", "--decision-records", "")
	usage("store", "registry", "authority", "dir", "extra")
	usage("store", "registry", "authority", "--decision-records", "dir", "extra")

	// Both accepted forms reach verification: with a store that exists and an
	// absent registry they produce a verdict (exit 0), the decision-record
	// directory absent or present alike.
	dir := t.TempDir()
	store := filepath.Join(dir, "store")
	if err := os.MkdirAll(filepath.Join(store, "receipts"), 0o755); err != nil {
		t.Fatal(err)
	}
	public := mustPublic(t)
	for _, args := range [][]string{
		{store, filepath.Join(dir, "registry.jsonl"), "gateway:test"},
		{store, filepath.Join(dir, "registry.jsonl"), "gateway:test", filepath.Join(dir, "records")},
		{store, filepath.Join(dir, "registry.jsonl"), "gateway:test", "--decision-records", filepath.Join(dir, "records")},
		// A lone fourth argument is a directory whatever it is spelled.
		{store, filepath.Join(dir, "registry.jsonl"), "gateway:test", "--records"},
	} {
		in, err := os.CreateTemp(dir, "key")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := in.WriteString(public); err != nil {
			t.Fatal(err)
		}
		if _, err := in.Seek(0, 0); err != nil {
			t.Fatal(err)
		}
		os.Stdin = in
		if got := cmdVerify(args); got != 0 {
			t.Fatalf("cmdVerify(%v) = %d, want 0 (a verdict)", args, got)
		}
		in.Close()
	}
}
