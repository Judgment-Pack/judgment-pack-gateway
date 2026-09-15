package main

import (
	"bytes"
	"encoding/json"
	"os"
	"strconv"
	"strings"
	"testing"
	"unicode"
)

// The frontend's own policy and grammar answer to the vectors the adapter
// answers to (testdata/tool-descriptors), read from disk: neither links the
// other's code.

type descriptorVector struct {
	Name    string `json:"name"`
	Text    string `json:"text"`
	PadTo   int    `json:"padTo"`
	Refusal *struct {
		Code    string  `json:"code"`
		Pointer *string `json:"pointer"`
	} `json:"refusal"`
}

func (v descriptorVector) text() string {
	if v.PadTo > len(v.Text) {
		return v.Text[:len(v.Text)-1] + strings.Repeat(" ", v.PadTo-len(v.Text)) + v.Text[len(v.Text)-1:]
	}
	return v.Text
}

type descriptorVectors struct {
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
		Name   string `json:"name"`
		Server struct {
			Name    string `json:"name"`
			Version string `json:"version"`
		} `json:"server"`
		Refusal *string `json:"refusal"`
	} `json:"identities"`
	Schemas []descriptorVector `json:"schemas"`
}

func readDescriptorVectors(t *testing.T, name string, into any) {
	t.Helper()
	data, err := os.ReadFile("../testdata/tool-descriptors/" + name)
	if err != nil {
		t.Fatal(err)
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(into); err != nil {
		t.Fatalf("%s: %v", name, err)
	}
}

func TestTheFrontendsPolicyAnswersToTheSharedVectors(t *testing.T) {
	var v descriptorVectors
	readDescriptorVectors(t, "vectors.json", &v)
	point := func(s string) rune {
		n, err := strconv.ParseUint(strings.TrimPrefix(s, "U+"), 16, 32)
		if err != nil {
			t.Fatal(err)
		}
		return rune(n)
	}
	for _, c := range v.DisplayPolicy.Refused {
		if !policyRefuses(point(c.CodePoint)) {
			t.Errorf("%s (%s) admitted", c.CodePoint, c.Class)
		}
	}
	for _, c := range v.DisplayPolicy.Admitted {
		if policyRefuses(point(c.CodePoint)) {
			t.Errorf("%s refused", c.CodePoint)
		}
	}
	for _, d := range v.Descriptions {
		r := judgeText(d.Value, descriptionBound, "a description")
		if (r == nil) != (d.Refusal == nil) || (r != nil && r.code != *d.Refusal) {
			t.Errorf("description %q: %v, want %v", d.Name, r, d.Refusal)
		}
	}
	for _, id := range v.Identities {
		r := judgeText(id.Server.Name, identityBound, "the server's name")
		if r == nil {
			r = judgeText(id.Server.Version, identityBound, "the server's version")
		}
		if (r == nil) != (id.Refusal == nil) || (r != nil && r.code != *id.Refusal) {
			t.Errorf("identity %q: %v, want %v", id.Name, r, id.Refusal)
		}
	}
}

func TestTheFrontendsGrammarAnswersToTheSharedVectors(t *testing.T) {
	var v descriptorVectors
	readDescriptorVectors(t, "vectors.json", &v)
	var fixtures []descriptorVector
	for _, name := range []string{"pydantic.json", "zod.json"} {
		var f struct {
			About     []string           `json:"about"`
			Generator string             `json:"generator"`
			Fixtures  []descriptorVector `json:"fixtures"`
		}
		readDescriptorVectors(t, name, &f)
		fixtures = append(fixtures, f.Fixtures...)
	}
	for _, vector := range append(v.Schemas, fixtures...) {
		got := judgeSchemaText(vector.text())
		switch {
		case vector.Refusal == nil && got != nil:
			t.Errorf("%s: refused %s at %q: %v", vector.Name, got.code, got.pointer, got)
		case vector.Refusal == nil:
		case got == nil:
			t.Errorf("%s: accepted; want %s", vector.Name, vector.Refusal.Code)
		case got.code != vector.Refusal.Code:
			t.Errorf("%s: refused as %s (%v); want %s", vector.Name, got.code, got, vector.Refusal.Code)
		case vector.Refusal.Pointer == nil && !got.whole:
			t.Errorf("%s: refused at %q; want whole", vector.Name, got.pointer)
		case vector.Refusal.Pointer != nil && (got.whole || got.pointer != *vector.Refusal.Pointer):
			t.Errorf("%s: refused at %q (whole %v); want %q", vector.Name, got.pointer, got.whole, *vector.Refusal.Pointer)
		}
	}
}

// The table the frontend reads is the policy over every code point, as
// Go's own Unicode 15.0.0 tables derive it; the frontend's lookup is a bit
// per code point, built from the table.
func TestTheFrontendsTableIsUnicode15Policy(t *testing.T) {
	if unicode.Version != "15.0.0" {
		t.Skipf("Go's tables are Unicode %s; the cross-check needs 15.0.0", unicode.Version)
	}
	assignedIn := []*unicode.RangeTable{unicode.L, unicode.M, unicode.N, unicode.P, unicode.S, unicode.Z, unicode.Cc, unicode.Cf, unicode.Co, unicode.Cs}
	bad := 0
	for r := rune(0); r <= unicode.MaxRune; r++ {
		assigned := false
		for _, table := range assignedIn {
			if unicode.Is(table, r) {
				assigned = true
				break
			}
		}
		ignorable := (unicode.Is(unicode.Other_Default_Ignorable_Code_Point, r) || unicode.Is(unicode.Cf, r) || unicode.Is(unicode.Variation_Selector, r)) &&
			!unicode.Is(unicode.White_Space, r) && !(r >= 0xFFF9 && r <= 0xFFFB) && !(r >= 0x13430 && r <= 0x13440) && !unicode.Is(unicode.Prepended_Concatenation_Mark, r)
		want := r != '\t' && r != '\n' && (unicode.Is(unicode.Cc, r) || unicode.Is(unicode.Bidi_Control, r) || ignorable ||
			unicode.Is(unicode.Co, r) || !assigned || unicode.Is(unicode.Noncharacter_Code_Point, r))
		if policyRefuses(r) != want {
			if bad++; bad <= 10 {
				t.Errorf("U+%04X: refused %v, want %v", r, policyRefuses(r), want)
			}
		}
	}
	if bad > 0 {
		t.Fatalf("%d code points disagree", bad)
	}
}
