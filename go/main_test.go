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
				sources: map[string][]string{},
				port:    "65535",
			},
		},
		{
			name: "port at the bottom of the range is accepted",
			args: []string{"store", "seed", "authority", "registry", "--port", "1"},
			wantOptions: serveOptions{
				sources: map[string][]string{},
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
				sources: map[string][]string{},
				port:    "8787",
			},
		},
		{
			name: "port only",
			args: []string{"store", "seed", "authority", "registry", "--port", "9000"},
			wantOptions: serveOptions{
				sources: map[string][]string{},
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
				sources: map[string][]string{
					"screening": {"go", "version"},
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
				sources: map[string][]string{
					"screen": {"go"},
					"quote":  {"go", "version"},
				},
				port: "9000",
			},
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
