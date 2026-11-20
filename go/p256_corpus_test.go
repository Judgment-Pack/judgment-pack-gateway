package main

// The P-256 corpus (ADR-0053 §11) and retention.acknowledgedBy's object form
// (§9). The vectors are verify-only: nothing here signs them again.

import (
	"math/big"
	"strings"
	"testing"
)

func TestP256SignatureVectors(t *testing.T) {
	var doc struct {
		Note    string `json:"note"`
		Vectors []struct {
			PublicKey string `json:"publicKey"`
			Message   string `json:"message"`
			Signature string `json:"signature"`
			HighS     string `json:"highS"`
		} `json:"vectors"`
	}
	readJSON(t, corpusPath("p256-vectors.json"), &doc)
	pinned := strings.TrimSpace(readFile(t, corpusPath("TEST-P256-PUBLIC-KEY")))
	if len(doc.Vectors) == 0 {
		t.Fatal("no vectors")
	}
	for i, v := range doc.Vectors {
		if v.PublicKey != pinned {
			t.Errorf("vector %d: key %s, not TEST-P256-PUBLIC-KEY", i, v.PublicKey)
		}
		key := heldKey{alg: algES256, key: mustHex(t, v.PublicKey)}
		msg, sig, high := mustHex(t, v.Message), mustHex(t, v.Signature), mustHex(t, v.HighS)
		if new(big.Int).SetBytes(sig[32:]).Cmp(p256HalfOrder) > 0 || new(big.Int).Add(new(big.Int).SetBytes(sig[32:]), new(big.Int).SetBytes(high[32:])).Cmp(p256Order) != 0 {
			t.Errorf("vector %d: signature and highS are not one signature's two forms", i)
		}
		if !verifyByAlgorithm(algES256, key, msg, sig) {
			t.Errorf("vector %d: the low-S signature does not verify", i)
		}
		if verifyByAlgorithm(algES256, key, msg, high) {
			t.Errorf("vector %d: the high-S twin verifies", i)
		}
		if verifyByAlgorithm(algEd25519, key, msg, sig) {
			t.Errorf("vector %d: verifies with alg absent", i)
		}
		sig[10] ^= 1
		if verifyByAlgorithm(algES256, key, msg, sig) {
			t.Errorf("vector %d: an altered signature verifies", i)
		}
	}
	if scalar := strings.TrimSpace(readFile(t, corpusPath("TEST-P256-SCALAR"))); scalar != strings.Repeat("01", 32) {
		t.Errorf("TEST-P256-SCALAR is %s", scalar)
	}
	if id := keyIDFor(mustHex(t, pinned)); id != "dbdb99c64b3d511f72c88fb6c054da73" {
		t.Errorf("the P-256 test key's id is %s", id)
	}
}

func TestRetentionAckVectorsInProcess(t *testing.T) {
	failures, n, err := runRetentionAckVectors(corpusPath())
	if err != nil {
		t.Fatal(err)
	}
	if n != 6 || len(failures) != 0 {
		t.Fatalf("%d vectors, failures: %v", n, failures)
	}
}
