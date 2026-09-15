package mcp

import (
	"bytes"
	"encoding/json"
	"os"
	"strconv"
	"strings"
	"testing"
)

// sharedVectors are the vectors the adapter and the frontend both answer
// to (testdata/tool-descriptors/vectors.json), read from disk: the
// frontend's implementation is its own, and neither links the other's.
type sharedVectors struct {
	About         []string `json:"about"`
	DisplayPolicy struct {
		Unicode string `json:"unicode"`
		Refused []struct {
			CodePoint string `json:"codePoint"`
			Class     string `json:"class"`
		} `json:"refused"`
		Admitted []struct {
			CodePoint string `json:"codePoint"`
			Note      string `json:"note"`
		} `json:"admitted"`
	} `json:"displayPolicy"`
	Descriptions []struct {
		Name    string  `json:"name"`
		Value   string  `json:"value"`
		Refusal *string `json:"refusal"`
	} `json:"descriptions"`
	Identities []struct {
		Name   string         `json:"name"`
		Server serverIdentity `json:"server"`
		// Refusal is the code, or null.
		Refusal *string `json:"refusal"`
	} `json:"identities"`
	Schemas []schemaVector `json:"schemas"`
}

type schemaVector struct {
	Name    string `json:"name"`
	Text    string `json:"text"`
	PadTo   int    `json:"padTo"`
	Refusal *struct {
		Code    string  `json:"code"`
		Pointer *string `json:"pointer"`
	} `json:"refusal"`
}

// bytes is the vector's text as a candidate's original bytes, padded with
// spaces before its last byte when it says so.
func (v schemaVector) bytes() []byte {
	text := []byte(v.Text)
	if v.PadTo > len(text) {
		padded := append(append(append([]byte{}, text[:len(text)-1]...), bytes.Repeat([]byte(" "), v.PadTo-len(text))...), text[len(text)-1])
		return padded
	}
	return text
}

func loadVectors(t *testing.T) sharedVectors {
	t.Helper()
	data, err := os.ReadFile("../../testdata/tool-descriptors/vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var v sharedVectors
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&v); err != nil {
		t.Fatal(err)
	}
	if len(v.Schemas) == 0 || len(v.DisplayPolicy.Refused) == 0 || len(v.Descriptions) == 0 || len(v.Identities) == 0 {
		t.Fatal("the vectors file is missing a section")
	}
	return v
}

func codePoint(t *testing.T, s string) rune {
	t.Helper()
	n, err := strconv.ParseUint(strings.TrimPrefix(s, "U+"), 16, 32)
	if err != nil {
		t.Fatalf("code point %q: %v", s, err)
	}
	return rune(n)
}

func TestDisplayPolicyAnswersToTheSharedVectors(t *testing.T) {
	v := loadVectors(t)
	if v.DisplayPolicy.Unicode != "15.0.0" {
		t.Fatalf("the vectors are for Unicode %s", v.DisplayPolicy.Unicode)
	}
	classes := map[string]bool{}
	for _, c := range v.DisplayPolicy.Refused {
		classes[c.Class] = true
		r := codePoint(t, c.CodePoint)
		if !displayRefuses(r) {
			t.Errorf("%s (%s) is admitted; policy 1 refuses it", c.CodePoint, c.Class)
		}
		// Refused wherever it stands in a string, and named.
		if got, refused := displayRefusal("ok " + string(r) + " ok"); !refused || got != r {
			t.Errorf("%s inside a string: refused=%v, named U+%04X", c.CodePoint, refused, got)
		}
	}
	for _, class := range []string{"Cc", "Bidi_Control", "Default_Ignorable_Code_Point", "Co", "Cn", "Noncharacter_Code_Point"} {
		if !classes[class] {
			t.Errorf("no vector for class %s", class)
		}
	}
	for _, c := range v.DisplayPolicy.Admitted {
		if displayRefuses(codePoint(t, c.CodePoint)) {
			t.Errorf("%s is refused; policy 1 admits it", c.CodePoint)
		}
	}
}

func TestTheGrammarAnswersToTheSharedVectors(t *testing.T) {
	v := loadVectors(t)
	accepted := 0
	for _, vector := range v.Schemas {
		t.Run(vector.Name, func(t *testing.T) {
			got := checkSchema(vector.bytes(), nil)
			switch {
			case vector.Refusal == nil && got != nil:
				t.Fatalf("refused (%s at %q): %s", got.code, got.pointer, got.reason())
			case vector.Refusal == nil:
				accepted++
			case got == nil:
				t.Fatalf("accepted; want %s", vector.Refusal.Code)
			case got.code != vector.Refusal.Code:
				t.Fatalf("refused as %s (%s); want %s", got.code, got.reason(), vector.Refusal.Code)
			case vector.Refusal.Pointer == nil && !got.whole:
				t.Fatalf("refused at %q; want the candidate refused whole", got.pointer)
			case vector.Refusal.Pointer != nil && (got.whole || got.pointer != *vector.Refusal.Pointer):
				t.Fatalf("refused at %q (whole %v); want %q", got.pointer, got.whole, *vector.Refusal.Pointer)
			}
		})
	}
	if accepted == 0 {
		t.Fatal("no vector was accepted")
	}
}

func TestDescriptionsAndIdentitiesAnswerToTheSharedVectors(t *testing.T) {
	v := loadVectors(t)
	for _, d := range v.Descriptions {
		raw, _ := json.Marshal(d.Value)
		got, r := checkDescription(raw, nil)
		switch {
		case d.Refusal == nil && r != nil:
			t.Errorf("description %q refused: %s", d.Name, r.reason())
		case d.Refusal == nil && got != d.Value:
			t.Errorf("description %q captured as %q", d.Name, got)
		case d.Refusal != nil && (r == nil || r.code != *d.Refusal):
			t.Errorf("description %q: got %v, want %s", d.Name, r, *d.Refusal)
		}
	}
	for _, id := range v.Identities {
		r := checkIdentity(id.Server.Name, id.Server.Version, nil)
		switch {
		case id.Refusal == nil && r != nil:
			t.Errorf("identity %q refused: %s", id.Name, r.reason())
		case id.Refusal != nil && (r == nil || r.code != *id.Refusal):
			t.Errorf("identity %q: got %v, want %s", id.Name, r, *id.Refusal)
		}
	}
}

// What Pydantic and zod-to-json-schema emit for a tool's arguments, as the
// two MCP SDKs send it: a flat model or object is accepted, and what the
// scope leaves out -- references, format, pattern, the array form of
// items -- is refused where the fixture says.
func TestLibraryOutputAnswersAsTheFixturesSay(t *testing.T) {
	for _, file := range []string{"pydantic.json", "zod.json"} {
		data, err := os.ReadFile("../../testdata/tool-descriptors/" + file)
		if err != nil {
			t.Fatal(err)
		}
		var fixtures struct {
			About     []string       `json:"about"`
			Generator string         `json:"generator"`
			Fixtures  []schemaVector `json:"fixtures"`
		}
		dec := json.NewDecoder(bytes.NewReader(data))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&fixtures); err != nil {
			t.Fatalf("%s: %v", file, err)
		}
		accepted, refused := 0, 0
		for _, f := range fixtures.Fixtures {
			got := checkSchema(f.bytes(), nil)
			switch {
			case f.Refusal == nil && got != nil:
				t.Errorf("%s %s: refused (%s): %s", file, f.Name, got.code, got.reason())
			case f.Refusal == nil:
				accepted++
			case got == nil || got.code != f.Refusal.Code || f.Refusal.Pointer == nil || got.pointer != *f.Refusal.Pointer:
				t.Errorf("%s %s: got %+v, want %s at %v", file, f.Name, got, f.Refusal.Code, f.Refusal.Pointer)
			default:
				refused++
			}
		}
		if accepted == 0 || refused == 0 {
			t.Errorf("%s: %d accepted, %d refused", file, accepted, refused)
		}
	}
}
