package main

import (
	"crypto/ed25519"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func delegationConfigText(key, url, credential string, extra string) string {
	return `{"hosts":[{"host":"desk","requester":"service:desk","keys":["` + key + `"],"admission":{"url":"` + url + `","credential":"` + credential + `"}}]` + extra + `}`
}

// The delegation member (SPEC.md §11.2): engine version 15, identity
// required, hosts held to their forms, keys to §8.4's rule, the admission read
// to HTTPS.
func TestDelegationConfigRefusals(t *testing.T) {
	pub := hex.EncodeToString(ed25519.NewKeyFromSeed(delegationHostSeed).Public().(ed25519.PublicKey))
	identity := &identitySpec{issuer: testIssuerURL, audience: "gateway:acme", keys: "/k"}
	// An absolute path on every platform, escaped for JSON.
	tokenPath := abs(t, t.TempDir(), "desk-token")
	good := delegationConfigText(pub, "https://desk.example/admission", tokenPath, `,"operators":["operator:on-call"],"bearerReadOnly":true`)
	parse := func(text, version string, id *identitySpec) (*delegationSpec, error) {
		v, err := parseJSON([]byte(text))
		if err != nil {
			t.Fatal(err)
		}
		return parseDelegationConfig(v, version, id)
	}
	spec, err := parse(good, "15", identity)
	if err != nil || len(spec.hosts) != 1 || !spec.bearerReadOnly || spec.operators[0] != "operator:on-call" || spec.hosts[0].keys[keyIDFor(mustHexBytes(t, pub))] == nil {
		t.Fatalf("good: %+v %v", spec, err)
	}
	smallOrder := "0100000000000000000000000000000000000000000000000000000000000000"
	for _, c := range []struct {
		name, text, version string
		id                  *identitySpec
		want                string
	}{
		{"a version-14 file", good, "14", identity, "delegation is a version-15 member"},
		{"no identity", good, "15", nil, "delegation needs identity"},
		{"no hosts", `{"hosts":[]}`, "15", identity, "at least one issuing host"},
		{"an unknown member", strings.Replace(good, `"bearerReadOnly"`, `"bearer"`, 1), "15", identity, `unknown member "bearer"`},
		{"a host twice", `{"hosts":[` + strings.TrimSuffix(strings.TrimPrefix(delegationConfigText(pub, "https://d.example/a", tokenPath, ""), `{"hosts":[`), `]}`) + `,` + strings.TrimSuffix(strings.TrimPrefix(delegationConfigText(pub, "https://d.example/a", tokenPath, ""), `{"hosts":[`), `]}`) + `]}`, "15", identity, "named twice"},
		{"a host not a flat token", strings.Replace(good, `"host":"desk"`, `"host":"de/sk"`, 1), "15", identity, "host must be a flat token"},
		{"an empty requester", strings.Replace(good, `"requester":"service:desk"`, `"requester":""`, 1), "15", identity, "requester must be"},
		{"a key of small order", delegationConfigText(smallOrder, "https://d.example/a", tokenPath, ""), "15", identity, "small order"},
		{"a key in upper case", delegationConfigText(strings.ToUpper(pub), "https://d.example/a", tokenPath, ""), "15", identity, "64 lowercase hexadecimal"},
		{"an http admission read", delegationConfigText(pub, "http://desk.example/admission", tokenPath, ""), "15", identity, "must be an https URL"},
		{"an admission read with a user", delegationConfigText(pub, "https://u@desk.example/admission", tokenPath, ""), "15", identity, "must be an https URL"},
		{"a relative credential", delegationConfigText(pub, "https://desk.example/admission", "token", ""), "15", identity, "must be an absolute path"},
		{"an operator who is a host", delegationConfigText(pub, "https://desk.example/admission", tokenPath, `,"operators":["service:desk"]`), "15", identity, "is an issuing host's requester"},
		{"bearerReadOnly not a boolean", delegationConfigText(pub, "https://desk.example/admission", tokenPath, `,"bearerReadOnly":"yes"`), "15", identity, "must be a boolean"},
	} {
		if _, err := parse(c.text, c.version, c.id); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Fatalf("%s: want %q, got %v", c.name, c.want, err)
		}
	}
	// The credential is read at start, one token.
	dir := t.TempDir()
	path := filepath.Join(dir, "token")
	if err := os.WriteFile(path, []byte("admission-credential\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	spec.hosts[0].credential = path
	d, err := loadDelegation(spec)
	if err != nil || d.hosts["desk"].bearer != "admission-credential" || !d.bearerReadOnly {
		t.Fatalf("load: %+v %v", d, err)
	}
	if err := os.WriteFile(path, []byte("two words\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadDelegation(spec); err == nil || !strings.Contains(err.Error(), "is not one token") {
		t.Fatalf("two words: %v", err)
	}
	if d, err := loadDelegation(nil); d != nil || err != nil {
		t.Fatal("no delegation loads nothing")
	}
}

func mustHexBytes(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// Posture: a gateway with a delegation reports the narrowing as the
// gateway's own and its sender constraint; one without reports neither.
func TestDelegationPostureLines(t *testing.T) {
	without := hostPosture(postureInput{})
	for _, l := range without.lines {
		if strings.HasPrefix(l.name, "delegation-") {
			t.Fatalf("a gateway without a delegation reports %s", l.name)
		}
	}
	for _, bearer := range []bool{false, true} {
		report := hostPosture(postureInput{delegation: &delegationPosture{bearerReadOnly: bearer}})
		lines := map[string]postureLine{}
		for _, l := range report.lines {
			lines[l.name] = l
		}
		narrowing := lines[protectionDelegationNarrowing]
		if narrowing.state != postureEnforced || !strings.Contains(narrowing.reason, "gateway-enforced, not platform-enforced") {
			t.Fatalf("narrowing: %+v", narrowing)
		}
		sender := lines[protectionDelegationSender]
		if (sender.state == postureEnforced) == bearer {
			t.Fatalf("sender constraint with bearerReadOnly %v: %+v", bearer, sender)
		}
		if !strings.Contains(string(report.canonical()), `"name":"delegation-narrowing"`) {
			t.Fatal("the canonical report omits the line")
		}
	}
}

// The engine configuration carries the member from version 15, and refuses it
// by name before.
func TestEngineConfigCarriesTheDelegation(t *testing.T) {
	catalog := catalogWith(t, map[string]string{"postgres": postgresBinding})
	ref := "postgres@" + digestOf(postgresBinding)
	good := platformJSON(t, "warehouse", ref, "engine-warehouse", ``)
	pub := hex.EncodeToString(ed25519.NewKeyFromSeed(delegationHostSeed).Public().(ed25519.PublicKey))
	extra := `,"identity":{"issuer":"https://login.example","audience":"gateway:acme","keys":"` + abs(t, t.TempDir(), "keys.json") + `"},"delegation":` + delegationConfigText(pub, "https://desk.example/admission", abs(t, t.TempDir(), "token"), "")
	text := strings.Replace(engineJSON(t, catalog, extra, good), `"engineVersion":"1"`, `"engineVersion":"15"`, 1)
	cfg, _, err := load(t, text)
	if err != nil || cfg.delegation == nil || cfg.delegation.hosts[0].host != "desk" {
		t.Fatalf("version 15: %+v %v", cfg.delegation, err)
	}
	if _, _, err := load(t, strings.Replace(text, `"engineVersion":"15"`, `"engineVersion":"14"`, 1)); err == nil || !strings.Contains(err.Error(), "delegation is a version-15 member") {
		t.Fatalf("version 14: %v", err)
	}
}
