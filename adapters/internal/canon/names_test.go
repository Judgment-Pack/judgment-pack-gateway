package canon

import (
	"encoding/json"
	"strings"
	"testing"
)

type namedInner struct {
	Text string `json:"text"`
	Bold bool   `json:"bold,omitempty"`
}

// Hidden has the name of a field of the struct that embeds this one, which
// is nearer and so is the one the name means. It is a struct so that the
// two can be told apart: a text holds its value to nothing.
type namedEmbedded struct {
	Shared string     `json:"shared"`
	Hidden namedInner `json:"query"`
}

// namedLoop embeds a pointer to itself.
type namedLoop struct {
	*namedLoop
	Name string `json:"name"`
}

type namedSelf struct{ given bool }

func (n *namedSelf) UnmarshalJSON([]byte) error { n.given = true; return nil }

// NamedLabel is embedded below and is no struct: it is a member of its own
// name, and has no members to give.
type NamedLabel string

type namedRequest struct {
	namedEmbedded
	NamedLabel
	Query    string                `json:"query"`
	Max      int                   `json:"maxResults"`
	Untagged string                //nolint
	Skipped  string                `json:"-"`
	Inner    namedInner            `json:"inner"`
	Pointer  *namedInner           `json:"pointer"`
	List     []namedInner          `json:"list"`
	Pair     [2]namedInner         `json:"pair"`
	ByName   map[string]namedInner `json:"byName"`
	Any      any                   `json:"any"`
	Raw      json.RawMessage       `json:"raw"`
	Self     namedSelf             `json:"self"`
	Bytes    []byte                `json:"bytes"`
	hidden   string
}

// Every case is first decoded as the readers decode, refusing a member the
// type does not know, so that a case this check refuses is one the decoder
// alone would have taken: that is what the check is for.
func TestExactNamesRefusesWhatTheDecoderFolds(t *testing.T) {
	_ = namedRequest{}.hidden
	for name, raw := range map[string]string{
		"a name in capitals":                      `{"QUERY":"a"}`,
		"a name with one capital":                 `{"Query":"a"}`,
		"a name in capitals beside the name":      `{"query":"a","QUERY":"b"}`,
		"a name with a long s":                    `{"maxReſults":1}`,
		"a name with a Kelvin sign":               `{"inner":{"teKt":"a"}}`,
		"a name given twice":                      `{"query":"a","query":"b"}`,
		"a field's own name for its tag's":        `{"Max":1}`,
		"an untagged field's name in small":       `{"untagged":"a"}`,
		"within a struct":                         `{"inner":{"TEXT":"a"}}`,
		"within a struct behind a pointer":        `{"pointer":{"Text":"a"}}`,
		"within an element of a list":             `{"list":[{"text":"a"},{"BOLD":true}]}`,
		"within an element of an array":           `{"pair":[{"text":"a"},{"Text":"b"}]}`,
		"within a value of a map":                 `{"byName":{"ANY NAME":{"TEXT":"a"}}}`,
		"twice within a struct":                   `{"inner":{"text":"a","text":"b"}}`,
		"of an embedded struct, in capitals":      `{"SHARED":"a"}`,
		"a name nothing has":                      `{"other":"a"}`,
		"a name a field gives up with a dash":     `{"Skipped":"a"}`,
		"a dash, which names no field":            `{"-":"a"}`,
		"an embedded text's name in small":        `{"namedlabel":"a"}`,
		"an unexported field's name":              `{"hidden":"a"}`,
		"a value after the value":                 `{"query":"a"} {"query":"b"}`,
		"a value cut short":                       `{"query":"a"`,
		"a value cut short within a struct":       `{"inner":{"text":"a"`,
		"nothing":                                 ``,
		"a name of an embedded struct's, twice":   `{"shared":"a","shared":"b"}`,
		"the name of a list's member in capitals": `{"LIST":[]}`,
	} {
		if err := ExactNames([]byte(raw), &namedRequest{}); err != ErrName {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestExactNamesTakesWhatIsNamedAsWritten(t *testing.T) {
	for name, raw := range map[string]string{
		"every member by its name":               `{"query":"a","maxResults":1,"Untagged":"b","inner":{"text":"c","bold":true},"pointer":{"text":"d"},"list":[{"text":"e"},{}],"pair":[{},{"bold":false}],"byName":{"ANY NAME":{"text":"f"},"any name":{"text":"g"}},"shared":"h"}`,
		"no member":                              `{}`,
		"a struct that is null":                  `{"inner":null,"pointer":null,"list":null,"byName":null}`,
		"an interface's value, held to nothing":  `{"any":{"QUERY":"a","query":"b","query":"c"}}`,
		"a raw value, held to nothing":           `{"raw":{"TEXT":[{"Text":1,"Text":2}]}}`,
		"a value that decodes itself":            `{"self":{"GIVEN":true,"given":false}}`,
		"bytes, which are a string":              `{"bytes":"AAAA"}`,
		"a map's keys, which are not names":      `{"byName":{"TEXT":{},"text":{}}}`,
		"white space about the value":            " \n{\"query\" : \"a\"}\n ",
		"a name a nearer field hides, once":      `{"query":"a"}`,
		"an embedded text, by its type's name":   `{"NamedLabel":"a"}`,
		"a name a nearer field hides, its value": `{"query":{"TEXT":"held to nothing, as a text's value is"}}`,
		"a value of another kind than the field": `{"inner":"text","list":{"text":"a"},"query":{"QUERY":1}}`,
	} {
		if err := ExactNames([]byte(raw), &namedRequest{}); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// What the check is for: each of these the decoder takes, a member it does
// not know being refused, and reads the member that comes last.
func TestTheDecoderAloneTakesANameInAnotherCase(t *testing.T) {
	for _, raw := range []string{`{"query":"first","QUERY":"second"}`, `{"query":"first","Query":"second"}`} {
		var into struct {
			Query string `json:"query"`
		}
		dec := json.NewDecoder(strings.NewReader(raw))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&into); err != nil || into.Query != "second" {
			t.Fatalf("the decoder no longer folds a name: %v, %q; ExactNames may have nothing left to hold", err, into.Query)
		}
		if ExactNames([]byte(raw), &into) != ErrName {
			t.Fatal("taken")
		}
	}
}

func TestExactNamesOfAValueThatIsNoStruct(t *testing.T) {
	var list []namedInner
	if err := ExactNames([]byte(`[{"text":"a"},{"TEXT":"b"}]`), &list); err != ErrName {
		t.Fatal(err)
	}
	if err := ExactNames([]byte(`[{"text":"a"},{"bold":true}]`), &list); err != nil {
		t.Fatal(err)
	}
	var text string
	if err := ExactNames([]byte(`"a"`), &text); err != nil {
		t.Fatal(err)
	}
	var nothing struct{}
	if err := ExactNames([]byte(`{}`), &nothing); err != nil {
		t.Fatal(err)
	}
	if err := ExactNames([]byte(`{"extra":1}`), &nothing); err != ErrName {
		t.Fatal(err)
	}
	if err := ExactNames([]byte(`{"QUERY":"a"}`), nil); err != nil {
		t.Fatal("a value held to no type was refused", err)
	}
}

func TestExactNamesOfAStructThatEmbedsItselfComesToAnEnd(t *testing.T) {
	if err := ExactNames([]byte(`{"name":"a"}`), &namedLoop{}); err != nil {
		t.Fatal(err)
	}
	if err := ExactNames([]byte(`{"NAME":"a"}`), &namedLoop{}); err != ErrName {
		t.Fatal(err)
	}
}

func TestExactNamesRefusesAValueNestedPastTheBound(t *testing.T) {
	var into any
	deep := strings.Repeat("[", maxNesting+2) + strings.Repeat("]", maxNesting+2)
	if err := ExactNames([]byte(deep), &into); err != ErrName {
		t.Fatal(err)
	}
}

// What the check takes, the decoder takes too, a member it does not know
// being refused: the check is not looser than the decoder about a name.
func TestWhatExactNamesTakesTheDecoderTakes(t *testing.T) {
	for _, raw := range []string{
		`{"query":"a","maxResults":1,"Untagged":"b","inner":{"text":"c","bold":true},"pointer":{"text":"d"},"list":[{"text":"e"},{}],"pair":[{},{"bold":false}],"byName":{"x":{"text":"f"}},"shared":"h","NamedLabel":"i","bytes":"AAAA","any":{"a":1},"raw":[1],"self":2}`,
		`{}`,
	} {
		if err := ExactNames([]byte(raw), &namedRequest{}); err != nil {
			t.Fatal(err)
		}
		var into namedRequest
		dec := json.NewDecoder(strings.NewReader(raw))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&into); err != nil {
			t.Fatalf("the check takes a name the decoder refuses: %v", err)
		}
	}
}
