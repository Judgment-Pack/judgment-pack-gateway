package main

// gateway verify-key-history: the consumer's check of a fetched key history
// (SPEC.md §3e; ADR-0055, amendment of 2026-11-24) as a command, so that a
// consumer that fetched /publickey/history can hold a gateway to version "2"
// without calling the library.

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
)

// keyHistoryInputBound is the most bytes of a key history the command reads,
// 16 MiB: far above the corpus's largest history (under 4 KiB) and over ten
// thousand keys, and verify-ts reads the same bound. An input past it is a
// usage-level refusal, made before anything is parsed.
const keyHistoryInputBound = 16 << 20

const verifyKeyHistoryUsage = "usage: gateway verify-key-history [--public-key <key> [--public-key-alg ES256]] [--require-version 2] <file|->"

// keyHistoryVerdict is the one line the command writes for a history that
// holds. The members and their order are verify-ts's, byte for byte.
type keyHistoryVerdict struct {
	Accepted bool   `json:"accepted"`
	Version  string `json:"version"`
	Keys     int    `json:"keys"`
	InForce  string `json:"inForce"`
}

// keyHistoryRefusedVerdict is the one line for a history that does not: the
// class of ADR-0055 §9's eight.
type keyHistoryRefusedVerdict struct {
	Accepted bool   `json:"accepted"`
	Refused  string `json:"refused"`
}

// cmdVerifyKeyHistory is gateway verify-key-history [--public-key <key>
// [--public-key-alg ES256]] [--require-version 2] <file|->: the check of
// checkKeyHistoryOf on the file's bytes, or on standard input for `-`, from
// the key pinned where one is given, and its verdict as one line of JSON on
// standard output. Exit 0 for a history that holds, 1 for one that is
// refused, naming the class, and 2 for a usage error, an input that cannot
// be read or is over keyHistoryInputBound, or a check that failed with no
// class: then nothing is written on standard output.
func cmdVerifyKeyHistory(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	usage := func(why string) int {
		fmt.Fprintln(stderr, "gateway verify-key-history: "+why)
		fmt.Fprintln(stderr, verifyKeyHistoryUsage)
		return 2
	}
	var pin *heldKey
	rest := args
	if len(rest) > 0 && rest[0] == "--public-key" {
		if len(rest) < 2 {
			return usage("--public-key takes a key")
		}
		alg, keyText := algEd25519, rest[1]
		rest = rest[2:]
		if len(rest) > 0 && rest[0] == "--public-key-alg" {
			if len(rest) < 2 || rest[1] != algES256 {
				return usage("--public-key-alg is ES256; without it the key is an Ed25519 key's 64 lowercase hexadecimal characters")
			}
			alg, rest = algES256, rest[2:]
		}
		key := decodeKeyHex(alg, keyText)
		if key == nil || !keySoundFor(alg, key) {
			return usage(fmt.Sprintf("--public-key is not a %s public key of its form", algName(alg)))
		}
		pin = &heldKey{alg: alg, key: key}
	}
	requireVersion := ""
	if len(rest) > 0 && rest[0] == "--require-version" {
		if len(rest) < 2 || rest[1] != keyHistoryVersion2 {
			return usage(`--require-version is "2"`)
		}
		requireVersion, rest = keyHistoryVersion2, rest[2:]
	}
	if len(rest) != 1 {
		return usage("exactly one file, or - for standard input")
	}
	if rest[0] != "-" && strings.HasPrefix(rest[0], "--") {
		return usage(fmt.Sprintf("unknown or misplaced option %s; a file so named is given as ./%s", rest[0], rest[0]))
	}
	var data []byte
	var err error
	if rest[0] == "-" {
		data, err = readBoundedFrom(stdin, "standard input", keyHistoryInputBound)
	} else {
		data, err = readBounded(rest[0], keyHistoryInputBound)
	}
	if err != nil {
		fmt.Fprintln(stderr, "gateway verify-key-history:", err)
		return 2
	}
	checked, err := checkKeyHistoryOf(data, pin, requireVersion)
	if err != nil {
		class := keyHistoryRefusalClass(err)
		if class == "" {
			fmt.Fprintln(stderr, "gateway verify-key-history: the check failed with no class:", err)
			return 2
		}
		out, merr := json.Marshal(keyHistoryRefusedVerdict{Accepted: false, Refused: class})
		if merr != nil {
			fmt.Fprintln(stderr, "gateway verify-key-history:", merr)
			return 2
		}
		fmt.Fprintf(stderr, "gateway verify-key-history: refused (%s): %v\n", class, err)
		fmt.Fprintln(stdout, string(out))
		return 1
	}
	out, err := json.Marshal(keyHistoryVerdict{Accepted: true, Version: checked.version, Keys: len(checked.entries), InForce: checked.entries[len(checked.entries)-1].keyID})
	if err != nil {
		fmt.Fprintln(stderr, "gateway verify-key-history:", err)
		return 2
	}
	fmt.Fprintln(stdout, string(out))
	return 0
}
