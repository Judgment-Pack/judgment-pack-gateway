package main

import (
	"encoding/base64"
	"reflect"
	"slices"
	"strings"
	"testing"
)

// From assertionAlgorithmVersion a token step's assertionAlgorithm, "RS256"
// or "PS256", beside privateKey alone, is handed to adapter-http as
// --assertion-alg right after --assertion-key (ADR-0027, amendment #513).
// Under an earlier version it is refused by name; of any other value, or
// beside another kind of assertion, it is refused, and a refusal repeats no
// value. A step without it derives, at version 34, the source it derived at
// version 33.
func TestTokenStepAssertionAlgorithmIsAVersion34Member(t *testing.T) {
	catalog := catalogWith(t, map[string]string{"records": tokenBinding})
	ref := "records@" + digestOf(tokenBinding)
	adapters := `,"adapters":"` + abs(t, t.TempDir(), "bin") + `"`
	federated := abs(t, t.TempDir(), "federated.jwt")
	s256 := base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	step := func(members string) string {
		return tokenPlatformJSON(t, "records", ref, "engine-docs", `,"tokenStep":{`+members+`}`, ``)
	}
	head := `"endpoint":"https://login.example/token","clientId":"client-7"`
	keyed := head + `,"privateKey":"SIGNING_KEY","x5t#S256":"` + s256 + `"`

	if assertionAlgorithmVersion != "34" || !versionAtLeast(engineVersion, assertionAlgorithmVersion) {
		t.Fatalf("assertionAlgorithm is version 34's member: %q, engine %q", assertionAlgorithmVersion, engineVersion)
	}
	for _, algorithm := range []string{"RS256", "PS256"} {
		_, sources, err := load(t, atVersion(t, assertionAlgorithmVersion, catalog, adapters, step(keyed+`,"assertionAlgorithm":"`+algorithm+`"`)))
		if err != nil {
			t.Fatalf("%s: %v", algorithm, err)
		}
		argv := sources["records/live"].argv
		at := slices.Index(argv, "--assertion-key=SIGNING_KEY")
		if at < 0 || at+1 >= len(argv) || argv[at+1] != "--assertion-alg="+algorithm ||
			slices.ContainsFunc(argv, func(arg string) bool { return strings.HasPrefix(arg, "--bearer") }) {
			t.Fatalf("%s: --assertion-alg follows --assertion-key: %q", algorithm, argv)
		}
	}

	// A step without the member derives, at version 34, what it derived at
	// version 33, and carries no --assertion-alg.
	without := step(keyed)
	_, before, err := load(t, atVersion(t, delegatedTokenVersion, catalog, adapters, without))
	if err != nil {
		t.Fatal(err)
	}
	_, after, err := load(t, atVersion(t, assertionAlgorithmVersion, catalog, adapters, without))
	if err != nil || !reflect.DeepEqual(before["records/live"], after["records/live"]) {
		t.Fatalf("a step without assertionAlgorithm is derived as before: %v\n%+v\n%+v", err, before["records/live"], after["records/live"])
	}
	if slices.ContainsFunc(after["records/live"].argv, func(arg string) bool { return strings.HasPrefix(arg, "--assertion-alg") }) {
		t.Fatalf("no member, no --assertion-alg: %q", after["records/live"].argv)
	}

	signedBy := `"endpoint":"https://oauth.example/token","signedBy":{"kind":"credentials-api","serviceAccount":"` + testDelegatedAccount + `"},"subject":"admin@example.com","requestScope":"` + testDelegatedScopes + `"`
	for _, c := range []struct{ name, version, members, want, secret string }{
		{"below version 34", delegatedTokenVersion, keyed + `,"assertionAlgorithm":"PS256"`, `tokenStep.assertionAlgorithm is a version-34 member; engineVersion 33 has no assertionAlgorithm`, ""},
		{"below version 34, RS256", "21", keyed + `,"assertionAlgorithm":"RS256"`, `tokenStep.assertionAlgorithm is a version-34 member; engineVersion 21 has no assertionAlgorithm`, ""},
		{"ES256, which a P-256 key gives", assertionAlgorithmVersion, keyed + `,"assertionAlgorithm":"ES256"`, `tokenStep: assertionAlgorithm is "RS256" or "PS256"`, "ES256"},
		{"another case", assertionAlgorithmVersion, keyed + `,"assertionAlgorithm":"ps256"`, `tokenStep: assertionAlgorithm is "RS256" or "PS256"`, "ps256"},
		{"another hash", assertionAlgorithmVersion, keyed + `,"assertionAlgorithm":"PS384"`, `tokenStep: assertionAlgorithm is "RS256" or "PS256"`, "PS384"},
		{"none", assertionAlgorithmVersion, keyed + `,"assertionAlgorithm":"none-at-all"`, `tokenStep: assertionAlgorithm is "RS256" or "PS256"`, "none-at-all"},
		{"empty", assertionAlgorithmVersion, keyed + `,"assertionAlgorithm":""`, `tokenStep: assertionAlgorithm is "RS256" or "PS256"`, ""},
		{"a number", assertionAlgorithmVersion, keyed + `,"assertionAlgorithm":256`, `tokenStep: assertionAlgorithm is "RS256" or "PS256"`, ""},
		{"beside a federated token file", assertionAlgorithmVersion, head + `,"federatedTokenFile":"` + federated + `","assertionAlgorithm":"PS256"`, `tokenStep: assertionAlgorithm is the algorithm of an assertion the adapter signs, beside privateKey`, ""},
		{"beside the metadata server's token", assertionAlgorithmVersion, head + `,"federatedToken":{"kind":"metadata","audience":"api://records-reader"},"assertionAlgorithm":"PS256"`, `tokenStep: assertionAlgorithm is the algorithm of an assertion the adapter signs, beside privateKey`, ""},
		{"beside signedBy", assertionAlgorithmVersion, signedBy + `,"assertionAlgorithm":"PS256"`, `unknown member "assertionAlgorithm"`, ""},
	} {
		_, _, err := load(t, atVersion(t, c.version, catalog, adapters, step(c.members)))
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Fatalf("%s: want %q, got %v", c.name, c.want, err)
		}
		if c.secret != "" && strings.Contains(err.Error(), c.secret) {
			t.Fatalf("%s: the refusal repeats the value it was given: %v", c.name, err)
		}
	}
}
