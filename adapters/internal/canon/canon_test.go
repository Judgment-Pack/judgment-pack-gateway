package canon

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

// The adapter's canonicalizer answers to the same frozen vectors as the
// core's (corpus/canon.json), read from disk and never linked: every
// accepted vector renders byte-for-byte, every rejected one is refused.
func TestCanonicalizeAnswersToTheFrozenCorpus(t *testing.T) {
	data, err := os.ReadFile("../../../corpus/canon.json")
	if err != nil {
		t.Fatal(err)
	}
	var corpus struct {
		Vectors []struct {
			Note         string `json:"note"`
			InputJSON    string `json:"inputJson"`
			ExpectedHex  string `json:"expectedHex"`
			ExpectedUTF8 string `json:"expectedUtf8"`
			Reject       bool   `json:"reject"`
		} `json:"vectors"`
	}
	if err := json.Unmarshal(data, &corpus); err != nil {
		t.Fatal(err)
	}
	if len(corpus.Vectors) < 30 {
		t.Fatalf("expected the whole corpus, read %d vectors", len(corpus.Vectors))
	}
	for _, v := range corpus.Vectors {
		got, err := Canonicalize([]byte(v.InputJSON), RefuseNumbers)
		if v.Reject {
			if err == nil {
				t.Errorf("%s: %q must be refused, produced %q", v.Note, v.InputJSON, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("%s: %q refused: %v", v.Note, v.InputJSON, err)
			continue
		}
		if string(got) != v.ExpectedUTF8 || hex.EncodeToString(got) != v.ExpectedHex {
			t.Errorf("%s: %q produced %q, want %q", v.Note, v.InputJSON, got, v.ExpectedUTF8)
		}
	}
}

// Under the carrying policy a number outside the domain becomes a string
// holding its literal exactly; everything the corpus refuses for another
// reason is still refused.
func TestCanonicalizeCarriesNumbersAsText(t *testing.T) {
	cases := map[string]string{
		`{"n":1.5}`:                    `{"n":"1.5"}`,
		`{"n":1.0}`:                    `{"n":"1.0"}`,
		`{"n":1e2}`:                    `{"n":"1e2"}`,
		`{"n":9007199254740992}`:       `{"n":"9007199254740992"}`,
		`{"n":-9007199254740992}`:      `{"n":"-9007199254740992"}`,
		`{"n":9007199254740991}`:       `{"n":9007199254740991}`,
		`{"b":[0.5,2],"a":{"x":-0.0}}`: `{"a":{"x":"-0.0"},"b":["0.5",2]}`,
	}
	for in, want := range cases {
		got, err := Canonicalize([]byte(in), CarryNumbersAsText)
		if err != nil || string(got) != want {
			t.Errorf("%s: got %q (%v), want %q", in, got, err, want)
		}
	}
	for _, in := range []string{`{"a":1,"a":2}`, `{"k":"\ud800"}`, "{\"k\":\"\xff\"}", `{"a":1}{"b":2}`, `[1,`} {
		if _, err := Canonicalize([]byte(in), CarryNumbersAsText); err == nil {
			t.Errorf("%q must be refused under either policy", in)
		}
	}
}

// -0 is an integer in the domain and is emitted as 0 (§1.1), under either
// policy; a literal JSON forbids is refused.
func TestCanonicalizeNormalizesNegativeZero(t *testing.T) {
	for _, policy := range []NumberPolicy{RefuseNumbers, CarryNumbersAsText} {
		got, err := Canonicalize([]byte(`{"n":-0,"m":[-0,0,-1]}`), policy)
		if err != nil || string(got) != `{"m":[0,0,-1],"n":0}` {
			t.Fatalf("policy %d: %q %v", policy, got, err)
		}
	}
	for _, in := range []string{`{"n":01}`, `{"n":-}`, `{"n":+1}`} {
		if _, err := Canonicalize([]byte(in), CarryNumbersAsText); err == nil {
			t.Errorf("%s must be refused", in)
		}
	}
}

func TestNestingIsBoundedAsADecoderReads(t *testing.T) {
	deep := func(n int) []byte { return []byte(strings.Repeat("[", n) + strings.Repeat("]", n)) }
	if _, err := Canonicalize(deep(10000), RefuseNumbers); err != nil {
		t.Fatalf("10000 levels are read: %v", err)
	}
	if _, err := Canonicalize(deep(10001), RefuseNumbers); err == nil || !strings.Contains(err.Error(), "nesting deeper than 10000 levels") {
		t.Fatalf("10001 levels are refused: %v", err)
	}
	var v any
	if json.Unmarshal(deep(10000), &v) != nil || json.Unmarshal(deep(10001), &v) == nil {
		t.Fatal("the bound is the decoder's")
	}
}
