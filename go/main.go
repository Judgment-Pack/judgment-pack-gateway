package main

// A second, clean-room implementation of the judgment-pack gateway attestation
// format (receipt version 2), derived from SPEC.md and corpus/ alone.
//
// Two subcommands, per CONTRACT.md:
//
//	gateway canon                                    < value.json
//	gateway verify <store-root> <registry> <auth>    < publickey.raw

import (
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"strings"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: gateway canon | gateway verify <store-root> <registry-path> <authority>")
		os.Exit(2)
	}
	switch os.Args[1] {
	case "canon":
		os.Exit(cmdCanon())
	case "verify":
		os.Exit(cmdVerify(os.Args[2:]))
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
