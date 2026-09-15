// Package metaschema holds every schema the shared vectors and fixtures
// say schema grammar 1 accepts to the JSON Schema meta-schemas of both
// dialects the grammar admits, 2020-12 and draft-07: a schema served as
// written in either dialect is a schema in both
// (docs/design/tool-descriptors.md). The validator carries both
// meta-schemas and fetches nothing. It is a module of its own, apart from
// the gateway's two, so neither takes the dependency.
package metaschema

import (
	"bytes"
	"encoding/json"
	"os"
	"testing"

	"github.com/santhosh-tekuri/jsonschema/v6"
)

type candidate struct {
	Name    string          `json:"name"`
	Text    string          `json:"text"`
	PadTo   int             `json:"padTo"`
	Refusal json.RawMessage `json:"refusal"`
}

// accepted is every candidate a file says the grammar accepts.
func accepted(t *testing.T, file, member string) []candidate {
	t.Helper()
	data, err := os.ReadFile("../" + file)
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]json.RawMessage
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatal(err)
	}
	var all []candidate
	if err := json.Unmarshal(doc[member], &all); err != nil {
		t.Fatal(err)
	}
	var out []candidate
	for _, c := range all {
		if string(c.Refusal) == "null" {
			out = append(out, c)
		}
	}
	if len(out) == 0 {
		t.Fatalf("%s: no accepted schema", file)
	}
	return out
}

func TestEveryAcceptedSchemaIsValidInBothDialects(t *testing.T) {
	dialects := map[string]*jsonschema.Schema{}
	for _, url := range []string{"https://json-schema.org/draft/2020-12/schema", "http://json-schema.org/draft-07/schema#"} {
		meta, err := jsonschema.NewCompiler().Compile(url)
		if err != nil {
			t.Fatal(err)
		}
		dialects[url] = meta
	}
	var all []candidate
	all = append(all, accepted(t, "vectors.json", "schemas")...)
	all = append(all, accepted(t, "pydantic.json", "fixtures")...)
	all = append(all, accepted(t, "zod.json", "fixtures")...)
	for _, c := range all {
		text := []byte(c.Text)
		if c.PadTo > len(text) {
			text = append(append(append([]byte{}, text[:len(text)-1]...), bytes.Repeat([]byte(" "), c.PadTo-len(text))...), text[len(text)-1])
		}
		for url, meta := range dialects {
			instance, err := jsonschema.UnmarshalJSON(bytes.NewReader(text))
			if err != nil {
				t.Fatalf("%s: %v", c.Name, err)
			}
			if err := meta.Validate(instance); err != nil {
				t.Errorf("%s is not a schema under %s: %v", c.Name, url, err)
			}
		}
	}
	t.Logf("%d accepted schemas, each valid under both meta-schemas", len(all))
}

// The check has teeth: a schema the grammar refuses for its value, a
// negative length, is found invalid by both meta-schemas.
func TestTheMetaSchemasRefuseWhatTheyShould(t *testing.T) {
	for _, url := range []string{"https://json-schema.org/draft/2020-12/schema", "http://json-schema.org/draft-07/schema#"} {
		meta, err := jsonschema.NewCompiler().Compile(url)
		if err != nil {
			t.Fatal(err)
		}
		instance, _ := jsonschema.UnmarshalJSON(bytes.NewReader([]byte(`{"type":"object","properties":{"x":{"minLength":-1}}}`)))
		if meta.Validate(instance) == nil {
			t.Errorf("%s admits a negative minLength", url)
		}
	}
}
