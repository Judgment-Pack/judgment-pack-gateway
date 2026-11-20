package main

// retention.acknowledgedBy's object form for a P-256 key, from engine
// configuration version 40 (ADR-0053 §9).

import (
	"encoding/hex"
	"strings"
	"testing"
)

// TestAcknowledgedByForms is ADR-0053 §9's table, row by row.
func TestAcknowledgedByForms(t *testing.T) {
	ed := strings.TrimSpace(readFile(t, corpusPath("TEST-PUBLIC-KEY")))
	// the P-256 test key: the point of the scalar 01 repeated (ADR-0053 §11)
	const p = "026ff03b949241ce1dadd43519e6960e0a85b41a69a05c328103aa2bce1594ca16"
	// x = 1 has no point on P-256 (corpus/p256/stores/p256-rotation-next-off-curve.json)
	off := "02" + strings.Repeat("00", 31) + "01"
	const at = "engine configuration: retention.acknowledgedBy[0]"
	const edOnly = at + " is an Ed25519 public key, 64 lowercase hexadecimal characters"
	const both = at + ` is an Ed25519 public key of 64 lowercase hexadecimal characters, or {"alg": "ES256", "key": <66 lowercase hexadecimal characters>}`
	object := `{"alg":"ES256","key":"` + p + `"}`
	for _, c := range []struct {
		version, entry, alg, refused string
	}{
		{retentionVersion, `"` + ed + `"`, algEd25519, ""},
		{"39", `"` + ed + `"`, algEd25519, ""},
		{retentionVersion, object, "", edOnly},
		{"39", object, "", edOnly},
		{"39", `{"key":"` + ed + `"}`, "", edOnly},
		{p256SignerVersion, `"` + ed + `"`, algEd25519, ""},
		{p256SignerVersion, object, algES256, ""},
		{p256SignerVersion, `{"key":"` + p + `","alg":"ES256"}`, algES256, ""},
		{p256SignerVersion, `{"alg":"ES256","key":"` + off + `"}`, "", at + " is not a sound P-256 public key"},
		{p256SignerVersion, `{"key":"` + ed + `"}`, "", both},
		{p256SignerVersion, `{"alg":"EdDSA","key":"` + ed + `"}`, "", both},
		{p256SignerVersion, `{"alg":"ES384","key":"` + p + `"}`, "", both},
		{p256SignerVersion, `{"alg":"es256","key":"` + p + `"}`, "", both},
		{p256SignerVersion, `{"alg":"ES256","key":"` + p + `","x":1}`, "", both},
		{p256SignerVersion, `{"alg":"ES256","key":"` + strings.ToUpper(p) + `"}`, "", both},
		{p256SignerVersion, `{"alg":"ES256","key":"` + ed + `"}`, "", both},
		{p256SignerVersion, `"` + p + `"`, "", both},
		{p256SignerVersion, `"` + strings.ToUpper(ed) + `"`, "", both},
		{p256SignerVersion, `7`, "", both},
	} {
		cfg, err := parseRetentionConfig(mustParse(t, `{"window":30,"acknowledgedBy":[`+c.entry+`]}`), c.version)
		if c.refused != "" {
			if err == nil || err.Error() != c.refused {
				t.Errorf("version %s, %s: %v, want %q", c.version, c.entry, err, c.refused)
			}
			continue
		}
		if err != nil {
			t.Errorf("version %s, %s: %v", c.version, c.entry, err)
			continue
		}
		if got := cfg.acknowledgedBy[0]; got.alg != c.alg || c.alg == algES256 && hex.EncodeToString(got.key) != p {
			t.Errorf("version %s, %s: held as %q %x", c.version, c.entry, got.alg, got.key)
		}
	}
	// two listings of one key are one key listed twice, of either algorithm
	if _, err := parseRetentionConfig(mustParse(t, `{"window":30,"acknowledgedBy":["`+ed+`",`+object+`,`+object+`]}`), p256SignerVersion); err == nil || err.Error() != "engine configuration: retention.acknowledgedBy[2] is listed twice" {
		t.Errorf("a P-256 key listed twice: %v", err)
	}
}
