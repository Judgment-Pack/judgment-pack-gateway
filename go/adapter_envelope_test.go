package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
	"unicode/utf8"
)

// The published envelope schema (schema/adapter-envelope.v1.json) and the
// signer's reading of an envelope are held together through the vectors
// beside the schema: schema/check_adapter_envelope.py runs a JSON Schema
// validator over them, and these tests run the signer's own reading -- the
// canonical parse of the output, then readEnvelope -- over the same files.
// A vector either side answers otherwise than its directory says fails the
// side that drifted.

var envelopeVectors = filepath.Join("..", "schema", "vectors", "adapter-envelope")

// envelopeRefusals is why the signer refuses each invalid vector: a part of
// the refusal's text, so a vector refused for another reason than the one it
// was written for fails as surely as one accepted.
var envelopeRefusals = map[string]string{
	"not-an-object":                       "not an object",
	"unknown-member":                      `unknown member "receipt"`,
	"missing-result":                      `missing member "result"`,
	"missing-acquisition":                 `missing member "acquisition"`,
	"acquisition-array":                   `member "acquisition" is not an object`,
	"page-false":                          `member "page" must be true when present`,
	"page-string":                         `member "page" must be true when present`,
	"page-result-object":                  "a page's result must be an array of items",
	"page-result-null":                    "a page's result must be an array of items",
	"acquisition-shape":                   `acquisition member "shape" is not one an adapter reports`,
	"acquisition-page-items":              `acquisition member "pageItems" is not one an adapter reports`,
	"acquisition-unknown-member":          `acquisition member "query" is not one an adapter reports`,
	"missing-adapter":                     `missing member "adapter"`,
	"missing-endpoint":                    `missing member "endpoint"`,
	"missing-statement":                   `missing member "statement"`,
	"missing-snapshot":                    `missing member "snapshot"`,
	"missing-peer-identity":               `missing member "peerIdentity"`,
	"missing-schema":                      `missing member "schema"`,
	"missing-upstream-token":              `missing member "upstreamToken"`,
	"missing-observed-at":                 `member "observedAt" is missing or not a string`,
	"adapter-string":                      `member "adapter" is not an object`,
	"adapter-missing-name":                `adapter: member "name" is missing or not a string`,
	"adapter-missing-version":             `adapter: member "version" is missing or not a string`,
	"adapter-missing-digest":              `adapter: member "digest" is missing or not a string`,
	"adapter-name-number":                 `adapter: member "name" is missing or not a string`,
	"adapter-version-null":                `adapter: member "version" is missing or not a string`,
	"adapter-unknown-member":              `adapter member "image" is not one an adapter reports`,
	"adapter-digest-uppercase":            `adapter: member "digest" is not a digest`,
	"adapter-digest-short":                `adapter: member "digest" is not a digest`,
	"adapter-digest-other-algorithm":      `adapter: member "digest" is not a digest`,
	"adapter-digest-line-feed":            `adapter: member "digest" is not a digest`,
	"endpoint-number":                     `member "endpoint" is neither null nor a string`,
	"statement-object":                    `member "statement" is neither null nor a string`,
	"snapshot-false":                      `member "snapshot" is neither null nor a string`,
	"peer-identity-array":                 `member "peerIdentity" is neither null nor a string`,
	"upstream-token-number":               `member "upstreamToken" is neither null nor a string`,
	"schema-text":                         `member "schema" is not of its stated form`,
	"schema-number":                       `member "schema" is neither null nor a string`,
	"observed-at-null":                    `member "observedAt" is missing or not a string`,
	"observed-at-milliseconds":            `member "observedAt" is not a stamp`,
	"observed-at-offset":                  `member "observedAt" is not a stamp`,
	"observed-at-lowercase":               `member "observedAt" is not a stamp`,
	"observed-at-space":                   `member "observedAt" is not a stamp`,
	"observed-at-date-only":               `member "observedAt" is not a stamp`,
	"observed-at-three-digit-year":        `member "observedAt" is not a stamp`,
	"observed-at-february-29-common-year": `member "observedAt" is not a stamp`,
	"observed-at-february-29-1900":        `member "observedAt" is not a stamp`,
	"observed-at-april-31":                `member "observedAt" is not a stamp`,
	"observed-at-month-13":                `member "observedAt" is not a stamp`,
	"observed-at-day-00":                  `member "observedAt" is not a stamp`,
	"observed-at-hour-24":                 `member "observedAt" is not a stamp`,
	"observed-at-minute-60":               `member "observedAt" is not a stamp`,
	"observed-at-second-60":               `member "observedAt" is not a stamp`,
	"observed-at-line-feed":               `member "observedAt" is not a stamp`,
	"transport-without-server":            "transport and server are present together or not at all",
	"server-without-transport":            "transport and server are present together or not at all",
	"transport-stdio":                     "transport is outside its enumeration",
	"server-string":                       `member "acquisition.server" is not an object`,
	"server-missing-name":                 `acquisition.server: member "name" is missing or not a string`,
	"server-missing-version":              `acquisition.server: member "version" is missing or not a string`,
	"server-version-number":               `acquisition.server: member "version" is missing or not a string`,
	"server-name-number":                  `acquisition.server: member "name" is missing or not a string`,
	"server-unknown-member":               `acquisition.server: unknown member "title"`,
	"remote-endpoint-null":                "a remote server's endpoint is not of its form",
	"remote-endpoint-null-without-peer":   "a remote server's endpoint is not of its form",
	"remote-endpoint-query":               "a remote server's endpoint is not of its form",
	"remote-endpoint-user":                "a remote server's endpoint is not of its form",
	"remote-endpoint-port-zero":           "a remote server's endpoint is not of its form",
	"remote-endpoint-percent":             "a remote server's endpoint is not of its form",
	"remote-endpoint-ipv6-zone":           "a remote server's endpoint is not of its form",
	"remote-endpoint-ipv6-groups":         "a remote server's endpoint is not of its form",
	"remote-endpoint-too-long":            "a remote server's endpoint is not of its form",
	"remote-endpoint-line-feed":           "a remote server's endpoint is not of its form",
	"remote-endpoint-http-name":           "a remote server's endpoint is not of its form",
	"remote-endpoint-http-localhost":      "a remote server's endpoint is not of its form",
	"remote-tls-peer-null":                "a remote server reached over TLS is named by tls:sha256:",
	"remote-tls-peer-uppercase":           "a remote server reached over TLS is named by tls:sha256:",
	"remote-tls-peer-line-feed":           "a remote server reached over TLS is named by tls:sha256:",
	"remote-loopback-peer":                "a remote server reached in the clear establishes no peer identity",
	"result-fraction":                     "non-integer number is outside the canonical domain",
	"result-item-fraction":                "non-integer number is outside the canonical domain",
	"result-past-safe-range":              "is outside the safe-integer range",
	"result-below-safe-range":             "is outside the safe-integer range",
}

// readEnvelopeText is the signer's reading of an adapter's output, as
// acquireForTrail makes it: the canonical parse, the envelope under the
// shape given, and the result as the response would carry it.
func readEnvelopeText(text []byte, shape string) error {
	output, err := parseJSON(text)
	if err != nil {
		return err
	}
	e, err := readEnvelope(output, shape)
	if err != nil {
		return err
	}
	_, err = returnableResult(e.result)
	return err
}

// vectorNames lists a directory's vectors by name, without ".json".
func vectorNames(t *testing.T, dir string) []string {
	t.Helper()
	paths, err := filepath.Glob(filepath.Join(dir, "*.json"))
	if err != nil {
		t.Fatal(err)
	}
	if len(paths) == 0 {
		t.Fatalf("no vectors in %s", dir)
	}
	var names []string
	for _, path := range paths {
		names = append(names, strings.TrimSuffix(filepath.Base(path), ".json"))
	}
	sort.Strings(names)
	return names
}

// The transport and server members are read here as from a source
// declared mcp, the one shape that may carry them; that another shape
// refuses them is TestReadEnvelopeHoldsTheRemoteMembersToTheDeclaredShape.
func TestAdapterEnvelopeVectors(t *testing.T) {
	for _, name := range vectorNames(t, filepath.Join(envelopeVectors, "valid")) {
		text, err := os.ReadFile(filepath.Join(envelopeVectors, "valid", name+".json"))
		if err != nil {
			t.Fatal(err)
		}
		if err := readEnvelopeText(text, "mcp"); err != nil {
			t.Errorf("valid/%s: refused: %v", name, err)
		}
	}
	seen := map[string]bool{}
	for _, name := range vectorNames(t, filepath.Join(envelopeVectors, "invalid")) {
		seen[name] = true
		want, stated := envelopeRefusals[name]
		if !stated {
			t.Errorf("invalid/%s: no refusal is stated for it in envelopeRefusals", name)
			continue
		}
		text, err := os.ReadFile(filepath.Join(envelopeVectors, "invalid", name+".json"))
		if err != nil {
			t.Fatal(err)
		}
		switch err := readEnvelopeText(text, "mcp"); {
		case err == nil:
			t.Errorf("invalid/%s: accepted", name)
		case !strings.Contains(err.Error(), want):
			t.Errorf("invalid/%s: refused for another reason: %v (want %q)", name, err, want)
		}
	}
	for name := range envelopeRefusals {
		if !seen[name] {
			t.Errorf("envelopeRefusals names %s, which is not a vector", name)
		}
	}
}

// The members the gateway takes from an adapter alone (ADR-0015) are
// refused from a source the operator declared with another shape, and the
// refusal is the envelope's.
func TestReadEnvelopeHoldsTheRemoteMembersToTheDeclaredShape(t *testing.T) {
	text, err := os.ReadFile(filepath.Join(envelopeVectors, "valid", "remote-over-tls.json"))
	if err != nil {
		t.Fatal(err)
	}
	for _, shape := range []string{"airbyte", "http"} {
		err := readEnvelopeText(text, shape)
		if err == nil || !strings.Contains(err.Error(), "the adapter's result is not an envelope: acquisition: transport and server are members of shape mcp alone") {
			t.Errorf("shape %s: %v", shape, err)
		}
	}
	plain, err := os.ReadFile(filepath.Join(envelopeVectors, "valid", "one-row.json"))
	if err != nil {
		t.Fatal(err)
	}
	for _, shape := range []string{"airbyte", "http", "mcp"} {
		if err := readEnvelopeText(plain, shape); err != nil {
			t.Errorf("shape %s refuses an envelope without the remote members: %v", shape, err)
		}
	}
}

// schemaDoc reads the published schema as plain JSON.
func schemaDoc(t *testing.T) map[string]any {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "schema", "adapter-envelope.v1.json"))
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatal(err)
	}
	return doc
}

// at is the member of the schema at a path of member names.
func at(t *testing.T, doc map[string]any, path ...string) any {
	t.Helper()
	var v any = doc
	for _, name := range path {
		obj, ok := v.(map[string]any)
		if !ok {
			t.Fatalf("schema: %s is not an object", strings.Join(path, "."))
		}
		if v, ok = obj[name]; !ok {
			t.Fatalf("schema: no %s", strings.Join(path, "."))
		}
	}
	return v
}

// names is a schema object's member names, or a schema array's strings,
// sorted.
func names(t *testing.T, v any) []string {
	t.Helper()
	var out []string
	switch v := v.(type) {
	case map[string]any:
		for name := range v {
			out = append(out, name)
		}
	case []any:
		for _, item := range v {
			out = append(out, fmt.Sprint(item))
		}
	default:
		t.Fatalf("schema: %v is neither an object nor an array", v)
	}
	sort.Strings(out)
	return out
}

func sorted(list ...string) []string {
	out := append([]string{}, list...)
	sort.Strings(out)
	return out
}

// The schema names the members the signer reads, by the signer's own list
// for the acquisition (envelopeMembers): a member added to one and not the
// other fails here, where no vector carrying it exists yet. Each level is
// closed, as the signer reads it.
func TestAdapterEnvelopeSchemaNamesTheMembersTheSignerReads(t *testing.T) {
	doc := schemaDoc(t)
	var acquisition []string
	for name := range envelopeMembers {
		acquisition = append(acquisition, name)
	}
	remote := []string{"server", "transport"}
	var reported []string
	for _, name := range acquisition {
		if name != "transport" && name != "server" {
			reported = append(reported, name)
		}
	}
	for _, c := range []struct {
		path []string
		want []string
	}{
		{[]string{"properties"}, sorted("acquisition", "result", "page")},
		{[]string{"required"}, sorted("acquisition", "result")},
		{[]string{"$defs", "acquisition", "properties"}, sorted(acquisition...)},
		{[]string{"$defs", "acquisition", "required"}, sorted(reported...)},
		{[]string{"$defs", "acquisition", "dependentRequired"}, remote},
		{[]string{"$defs", "acquisition", "properties", "adapter", "properties"}, sorted("name", "version", "digest")},
		{[]string{"$defs", "acquisition", "properties", "adapter", "required"}, sorted("name", "version", "digest")},
		{[]string{"$defs", "acquisition", "properties", "server", "properties"}, sorted("name", "version")},
		{[]string{"$defs", "acquisition", "properties", "server", "required"}, sorted("name", "version")},
	} {
		if got := names(t, at(t, doc, c.path...)); strings.Join(got, ",") != strings.Join(c.want, ",") {
			t.Errorf("schema %s: %v, the signer reads %v", strings.Join(c.path, "."), got, c.want)
		}
	}
	for _, path := range [][]string{
		{"additionalProperties"},
		{"$defs", "acquisition", "additionalProperties"},
		{"$defs", "acquisition", "properties", "adapter", "additionalProperties"},
		{"$defs", "acquisition", "properties", "server", "additionalProperties"},
	} {
		if open, isBool := at(t, doc, path...).(bool); !isBool || open {
			t.Errorf("schema %s admits a member the signer refuses", strings.Join(path, "."))
		}
	}
}

// schemaPattern is a pattern of the schema compiled as Go reads one. The
// schema's patterns use what ECMA-262, Python's re and Go's regexp read
// alike: classes, counted repetition, groups that capture nothing, anchors.
func schemaPattern(t *testing.T, v any) *regexp.Regexp {
	t.Helper()
	text, ok := v.(string)
	if !ok {
		t.Fatalf("schema: a pattern that is not a string: %v", v)
	}
	return regexp.MustCompile(text)
}

// The forms the schema writes as patterns are the signer's forms, read with
// Go's regexp: the stamp over the days of years whose Februaries differ
// and over the edges of each field, and the endpoint of a remote server over
// the table's cases and every one-character change of them. A pattern and
// the signer's rule answering one string differently fail here, before a
// validator is run.
func TestAdapterEnvelopeSchemaFormsAreTheSignersForms(t *testing.T) {
	doc := schemaDoc(t)
	stamp := schemaPattern(t, at(t, doc, "$defs", "stamp", "pattern"))
	stampLength := int(at(t, doc, "$defs", "stamp", "maxLength").(float64))
	stamps := 0
	for _, year := range []string{"0000", "0004", "0100", "1900", "2000", "2023", "2024", "2026", "2100", "9999"} {
		for month := 0; month <= 13; month++ {
			for day := 0; day <= 32; day++ {
				for _, clock := range []string{"00:00:00", "23:59:59", "24:00:00", "12:60:00", "12:00:60", "9:00:00"} {
					s := fmt.Sprintf("%s-%02d-%02dT%sZ", year, month, day, clock)
					for _, text := range []string{s, s + "\n", strings.TrimSuffix(s, "Z")} {
						schema := stamp.MatchString(text) && utf8.RuneCountInString(text) <= stampLength
						if schema != isStamp(text) {
							t.Errorf("stamp %q: the schema says %v, the signer %v", text, schema, isStamp(text))
						}
						stamps++
					}
				}
			}
		}
	}

	endpoint := at(t, doc, "$defs", "remoteEndpoint").(map[string]any)
	form := schemaPattern(t, endpoint["pattern"])
	never := schemaPattern(t, at(t, doc, "$defs", "remoteEndpoint", "not", "pattern"))
	length := int(endpoint["maxLength"].(float64))
	type rule struct{ when, then *regexp.Regexp }
	var rules []rule
	for _, item := range endpoint["allOf"].([]any) {
		item := item.(map[string]any)
		rules = append(rules, rule{
			schemaPattern(t, item["if"].(map[string]any)["pattern"]),
			schemaPattern(t, item["then"].(map[string]any)["pattern"]),
		})
	}
	schemaEndpoint := func(s string) bool {
		if utf8.RuneCountInString(s) > length || never.MatchString(s) || !form.MatchString(s) {
			return false
		}
		for _, r := range rules {
			if r.when.MatchString(s) && !r.then.MatchString(s) {
				return false
			}
		}
		return true
	}
	accepted, refused := endpointCases(t)
	endpoints := 0
	check := func(s string) {
		if schemaEndpoint(s) != isRemoteEndpoint(s) {
			t.Errorf("endpoint %q: the schema says %v, the signer %v", s, schemaEndpoint(s), isRemoteEndpoint(s))
		}
		endpoints++
	}
	for _, c := range append(append([]endpointCase{}, accepted...), refused...) {
		s := c.text()
		check(s)
		check(s + "\n")
		if len(s) > 64 {
			continue
		}
		for i := 0; i <= len(s); i++ {
			for _, b := range "[]:%/.@?#1aF0g -" {
				check(s[:i] + string(b) + s[i:])
				if i < len(s) {
					check(s[:i] + string(b) + s[i+1:])
				}
			}
			if i < len(s) {
				check(s[:i] + s[i+1:])
			}
		}
	}
	t.Logf("%d stamps and %d endpoints read alike by the schema's patterns and the signer", stamps, endpoints)
}
