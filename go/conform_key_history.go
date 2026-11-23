package main

// The key-history vectors (ADR-0055 §9), corpus/key-history/*.json: each a
// key pinned, the answer's bytes as a string, an optional requireVersion,
// and the consumer's verdict: the keys accepted and the key in force, or
// the class of the refusal, which is part of the corpus contract. No
// verifier of the process contract reads a key history, so they are run in
// process, with no process-contract command; verify-ts runs them in its
// own corpus test.

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// keyHistoryClasses are the classes a refused vector names.
var keyHistoryClasses = map[string]bool{
	refusedVersion: true, refusedForm: true, refusedKey: true, refusedRotation: true,
	refusedOrdinal: true, refusedTime: true, refusedContinuation: true, refusedCarried: true,
}

type keyHistoryVector struct {
	Name string `json:"name"`
	Note string `json:"note"`
	// Pin is the name of a published Ed25519 key of the corpus, or
	// {"alg": "ES256", "key": <66 hexadecimal characters>}.
	Pin            json.RawMessage `json:"pin"`
	RequireVersion string          `json:"requireVersion"`
	History        string          `json:"history"`
	Expected       struct {
		Accepted *struct {
			Keys    int    `json:"keys"`
			InForce string `json:"inForce"`
		} `json:"accepted"`
		Refused string `json:"refused"`
	} `json:"expected"`
}

func keyHistoryVectorPaths(corpusDir string) ([]string, error) {
	found, err := filepath.Glob(filepath.Join(corpusDir, "key-history", "*.json"))
	if err != nil {
		return nil, err
	}
	sort.Strings(found)
	return found, nil
}

// readKeyHistoryVector reads one vector strictly: no member it does not
// name, none given twice, exactly one of the two answers, a refusal of one
// of the classes, and requireVersion "2" or absent.
func readKeyHistoryVector(path string) (keyHistoryVector, error) {
	var vector keyHistoryVector
	raw, err := os.ReadFile(path)
	if err != nil {
		return vector, err
	}
	if err := noMemberTwice(raw); err != nil {
		return vector, fmt.Errorf("%s: %v", path, err)
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&vector); err != nil {
		return vector, fmt.Errorf("%s: %v", path, err)
	}
	if dec.More() {
		return vector, fmt.Errorf("%s: more than one JSON value", path)
	}
	if vector.Name != strings.TrimSuffix(filepath.Base(path), ".json") {
		return vector, fmt.Errorf("%s: named %q", path, vector.Name)
	}
	if (vector.Expected.Accepted != nil) == (vector.Expected.Refused != "") {
		return vector, fmt.Errorf("%s: expected is exactly one of accepted and refused", path)
	}
	if vector.Expected.Refused != "" && !keyHistoryClasses[vector.Expected.Refused] {
		return vector, fmt.Errorf("%s: refused %q is not a class of ADR-0055 §9", path, vector.Expected.Refused)
	}
	if vector.RequireVersion != "" && vector.RequireVersion != keyHistoryVersion2 {
		return vector, fmt.Errorf("%s: requireVersion is \"2\", or absent", path)
	}
	return vector, nil
}

// keyHistoryPinOf is a vector's key pinned.
func keyHistoryPinOf(corpusDir string, raw json.RawMessage) (heldKey, error) {
	var name string
	if json.Unmarshal(raw, &name) == nil {
		if strings.ContainsAny(name, `/\`) || name == "" {
			return heldKey{}, fmt.Errorf("pin %q is not a key of the corpus", name)
		}
		text, err := os.ReadFile(filepath.Join(corpusDir, name))
		if err != nil {
			return heldKey{}, err
		}
		key, err := hex.DecodeString(strings.TrimSpace(string(text)))
		if err != nil || len(key) != 32 {
			return heldKey{}, fmt.Errorf("pin %s is not an Ed25519 public key", name)
		}
		return heldKey{alg: algEd25519, key: key}, nil
	}
	var pin struct {
		Alg string `json:"alg"`
		Key string `json:"key"`
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&pin); err != nil || pin.Alg != algES256 || !isLowerHexOfLen(pin.Key, 66) {
		return heldKey{}, fmt.Errorf("pin is the name of a key of the corpus, or {\"alg\": \"ES256\", \"key\": <66 hexadecimal characters>}")
	}
	key, _ := hex.DecodeString(pin.Key)
	return heldKey{alg: algES256, key: key}, nil
}

// runKeyHistoryVectors holds the consumer's check (checkKeyHistoryOf) to
// every key-history vector, on the verdict and on the class, and answers
// the disagreements and how many vectors it read.
func runKeyHistoryVectors(corpusDir string) ([]string, int, error) {
	paths, err := keyHistoryVectorPaths(corpusDir)
	if err != nil {
		return nil, 0, err
	}
	var failures []string
	for _, path := range paths {
		vector, err := readKeyHistoryVector(path)
		if err != nil {
			return nil, 0, err
		}
		pin, err := keyHistoryPinOf(corpusDir, vector.Pin)
		if err != nil {
			return nil, 0, fmt.Errorf("%s: %v", path, err)
		}
		checked, err := checkKeyHistoryOf([]byte(vector.History), &pin, vector.RequireVersion)
		switch accepted := vector.Expected.Accepted; {
		case accepted != nil && err != nil:
			failures = append(failures, fmt.Sprintf("key-history %s: expected accepted, refused %s: %v", vector.Name, keyHistoryRefusalClass(err), err))
		case accepted != nil && (len(checked.entries) != accepted.Keys || checked.entries[len(checked.entries)-1].keyID != accepted.InForce):
			failures = append(failures, fmt.Sprintf("key-history %s: expected %d keys, %s in force; accepted %d keys, %s in force", vector.Name, accepted.Keys, accepted.InForce, len(checked.entries), checked.entries[len(checked.entries)-1].keyID))
		case accepted == nil && err == nil:
			failures = append(failures, fmt.Sprintf("key-history %s: expected refused %s, accepted", vector.Name, vector.Expected.Refused))
		case accepted == nil && keyHistoryRefusalClass(err) != vector.Expected.Refused:
			failures = append(failures, fmt.Sprintf("key-history %s: expected refused %s, refused %s: %v", vector.Name, vector.Expected.Refused, keyHistoryRefusalClass(err), err))
		}
	}
	return failures, len(paths), nil
}
