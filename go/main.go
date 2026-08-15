package main

// A second, clean-room implementation of the judgment-pack gateway attestation
// format (receipt version 2), derived from SPEC.md and corpus/ alone.
//
// Subcommands:
//
//	gateway canon                                    < value.json
//	gateway verify <store-root> <registry> <auth>    < publickey.raw
//	gateway conform [--impl CMD] [--corpus DIR]
//	gateway serve <store> <seedfile> <authority> <registry> [--source NAME=CMD] [--port N]
//	gateway keygen [seedfile]

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strconv"
	"strings"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: gateway canon | verify | conform | serve | keygen")
		os.Exit(2)
	}
	switch os.Args[1] {
	case "canon":
		os.Exit(cmdCanon())
	case "verify":
		os.Exit(cmdVerify(os.Args[2:]))
	case "conform":
		os.Exit(cmdConform(os.Args[2:]))
	case "serve":
		os.Exit(cmdServe(os.Args[2:]))
	case "keygen":
		os.Exit(cmdKeygen(os.Args[2:]))
	default:
		fmt.Fprintf(os.Stderr, "unknown subcommand %q\n", os.Args[1])
		os.Exit(2)
	}
}

func cmdCanon() int {
	text, err := io.ReadAll(os.Stdin)
	if err != nil {
		fmt.Fprintln(os.Stderr, "read stdin:", err)
		return 1
	}
	out, err := canonText(text)
	if err != nil {
		fmt.Fprintln(os.Stderr, "refused:", err)
		return 1
	}
	// Exactly the canonical bytes, with no trailing newline.
	if _, err := os.Stdout.Write(out); err != nil {
		fmt.Fprintln(os.Stderr, "write stdout:", err)
		return 1
	}
	return 0
}

func cmdVerify(args []string) int {
	if len(args) != 3 {
		fmt.Fprintln(os.Stderr, "usage: gateway verify <store-root> <registry-path> <authority>")
		return 2
	}
	storeRoot, registryPath, authority := args[0], args[1], args[2]

	raw, err := io.ReadAll(os.Stdin)
	if err != nil {
		fmt.Fprintln(os.Stderr, "read public key from stdin:", err)
		return 1
	}
	publicKey, err := readPublicKey(raw)
	if err != nil {
		fmt.Fprintln(os.Stderr, "public key:", err)
		return 1
	}

	report, err := verifyWithRegistry(storeRoot, registryPath, authority, publicKey)
	if err != nil {
		// Could not produce a verdict at all.
		fmt.Fprintln(os.Stderr, "verify:", err)
		return 1
	}
	out, err := report.marshal()
	if err != nil {
		fmt.Fprintln(os.Stderr, "encode verdict:", err)
		return 1
	}
	os.Stdout.Write(out)
	os.Stdout.Write([]byte("\n"))
	return 0
}

// readPublicKey accepts the 32 raw bytes CONTRACT.md specifies. It also
// tolerates surrounding whitespace and a 64-character hex encoding, so that a
// key piped from a file such as corpus/TEST-PUBLIC-KEY still works: a stray
// trailing newline in a key file is a documented way this corpus has failed
// before, and it fails looking exactly like a format disagreement.
func readPublicKey(raw []byte) ([]byte, error) {
	if len(raw) == 32 {
		return raw, nil
	}
	trimmed := strings.TrimSpace(string(raw))
	if len(trimmed) == 32 {
		return []byte(trimmed), nil
	}
	if len(trimmed) == 64 {
		if b, err := hex.DecodeString(trimmed); err == nil {
			return b, nil
		}
	}
	return nil, fmt.Errorf("expected 32 raw bytes, got %d", len(raw))
}

// cmdKeygen writes a fresh 32-byte Ed25519 seed and reports the public key it
// implies, so an operator can pin that key out of band -- which SPEC.md §5 says
// is the only way the signature means anything.
func cmdKeygen(args []string) int {
	path := "gateway.seed"
	if len(args) > 0 {
		path = args[0]
	}
	seed := make([]byte, seedBytes)
	if _, err := rand.Read(seed); err != nil {
		fmt.Fprintln(os.Stderr, "generate seed:", err)
		return 1
	}
	if err := writeNewSeed(path, []byte(hex.EncodeToString(seed)+"\n")); err != nil {
		fmt.Fprintln(os.Stderr, "write seed:", err)
		return 1
	}
	// Derived from the bytes that were persisted, not from the bytes we meant
	// to persist. A short write or a filesystem that lied would otherwise print
	// a public key the operator pins out of band for a seed that is not there.
	persisted, err := readSeedFile(path)
	if err != nil {
		fmt.Fprintln(os.Stderr, "verify written seed:", err)
		return 1
	}
	public := ed25519.NewKeyFromSeed(persisted).Public().(ed25519.PublicKey)
	fmt.Printf("seed written to %s (keep it secret)\npublicKey %s\nkeyId     %s\n",
		path, hex.EncodeToString(public), keyIDFor(public))
	return 0
}

// writeNewSeed creates path exclusively. O_EXCL is the whole point and a
// check-then-write would not do: between a stat and a write, a rerun or a
// planted symlink decides which identity the gateway keeps. O_CREATE|O_EXCL
// also refuses a symlink outright rather than following it, so an existing
// path -- regular file, directory, or link -- is left untouched and the
// operator is told, instead of silently rotating the key every receipt and
// seal already produced was signed under.
func writeNewSeed(path string, encoded []byte) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if _, err := file.Write(encoded); err != nil {
		file.Close()
		os.Remove(path) // best effort: do not leave a partial seed behind
		return err
	}
	if err := file.Sync(); err != nil {
		file.Close()
		os.Remove(path)
		return err
	}
	if err := file.Close(); err != nil {
		os.Remove(path)
		return err
	}
	return nil
}

// readSeedFile reads back exactly what keygen persists: 64 lowercase hex
// characters and one newline, decoding to a 32-byte Ed25519 seed.
func readSeedFile(path string) ([]byte, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	text := strings.TrimSuffix(string(raw), "\n")
	if len(text) != hex.EncodedLen(seedBytes) {
		return nil, fmt.Errorf("expected %d hex characters, got %d",
			hex.EncodedLen(seedBytes), len(text))
	}
	if text != strings.ToLower(text) {
		return nil, errors.New("seed must be lowercase hexadecimal")
	}
	seed, err := hex.DecodeString(text)
	if err != nil {
		return nil, err
	}
	if len(seed) != seedBytes {
		return nil, fmt.Errorf("expected %d seed bytes, got %d", seedBytes, len(seed))
	}
	return seed, nil
}

type serveOptions struct {
	sources map[string][]string
	port    string
}

// validatePort accepts exactly what a TCP port may be on the command line: a
// decimal number in 1-65535. It deliberately does not accept a service name
// ("http"), a host:port pair, a leading "+", surrounding space, or 0 — 0 asks
// the kernel for an arbitrary free port, which makes the printed address wrong
// and is never what an operator naming a port meant.
func validatePort(value string) (string, bool) {
	if value == "" {
		return "--port must not be empty", false
	}
	for _, r := range value {
		if r < '0' || r > '9' {
			return fmt.Sprintf("--port %q is not a number between 1 and 65535", value), false
		}
	}
	number, err := strconv.Atoi(value)
	if err != nil || number < 1 || number > 65535 {
		return fmt.Sprintf("--port %q is not a number between 1 and 65535", value), false
	}
	return "", true
}

func parseServeOptions(args []string) (serveOptions, string, bool) {
	if len(args) < 4 {
		return serveOptions{}, "usage: gateway serve <store> <seedfile> <authority> <registry> " +
			"[--source NAME=CMD ...] [--port N]", false
	}

	opts := serveOptions{
		sources: map[string][]string{},
		port:    "8787",
	}
	rest := args[4:]
	portSeen := false
	for i := 0; i < len(rest); i++ {
		switch {
		case rest[i] == "--source":
			if i+1 >= len(rest) {
				return opts, "--source requires a following NAME=CMD value", false
			}
			name, command, found := strings.Cut(rest[i+1], "=")
			if !found {
				return opts, "--source expects NAME=CMD", false
			}
			if strings.TrimSpace(name) == "" {
				return opts, "--source name must not be empty", false
			}
			if _, exists := opts.sources[name]; exists {
				return opts, fmt.Sprintf("duplicate source %q", name), false
			}
			argv := strings.Fields(command)
			if len(argv) == 0 {
				return opts, "--source command must not be empty", false
			}
			if _, err := exec.LookPath(argv[0]); err != nil {
				return opts, fmt.Sprintf("--source %q command %q cannot be resolved", name, argv[0]), false
			}
			opts.sources[name] = argv
			i++
		case rest[i] == "--port":
			if i+1 >= len(rest) {
				return opts, "--port requires a following value", false
			}
			// `--port` is a singleton. Accepting it twice and keeping the last
			// value starts the gateway on a port the command line also names
			// somewhere else, which is exactly the ambiguity `--source` already
			// refuses a duplicate for.
			if portSeen {
				return opts, "duplicate --port option", false
			}
			// Validated here rather than at `net.Listen`, because by then
			// `cmdServe` has read the signing seed and `newGatewayService` may
			// have created store, receipt, artifact and registry directories. A
			// malformed command line must fail as usage, before any file or
			// network side effect.
			if msg, ok := validatePort(rest[i+1]); !ok {
				return opts, msg, false
			}
			opts.port = rest[i+1]
			portSeen = true
			i++
		case strings.HasPrefix(rest[i], "--"):
			return opts, fmt.Sprintf("unknown option %q", rest[i]), false
		default:
			return opts, fmt.Sprintf("unexpected argument %q", rest[i]), false
		}
	}
	return opts, "", true
}

func cmdServe(args []string) int {
	opts, msg, ok := parseServeOptions(args)
	if !ok {
		fmt.Fprintln(os.Stderr, msg)
		return 2
	}
	storeRoot, seedPath, authority, registryPath := args[0], args[1], args[2], args[3]
	raw, err := os.ReadFile(seedPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "read seed:", err)
		return 1
	}
	seed := []byte(strings.TrimSpace(string(raw)))
	if len(seed) == 2*seedBytes {
		if decoded, err := hex.DecodeString(string(seed)); err == nil {
			seed = decoded
		}
	}

	service, err := newGatewayService(storeRoot, seed, authority, registryPath, opts.sources)
	if err != nil {
		fmt.Fprintln(os.Stderr, "start:", err)
		return 1
	}
	if err := service.listenAndServe("127.0.0.1:" + opts.port); err != nil {
		fmt.Fprintln(os.Stderr, "serve:", err)
		return 1
	}
	return 0
}
