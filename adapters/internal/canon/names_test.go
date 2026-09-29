package canon

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

type namedInner struct {
	Text  string `json:"text"`
	Bold  bool   `json:"bold,omitempty"`
	Token string `json:"token,omitempty"`
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

// strictly decodes raw as the readers do: into the type, refusing a member
// the type does not know and anything after the value.
func strictly(raw string, into any) error {
	dec := json.NewDecoder(strings.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(into); err != nil {
		return err
	}
	if dec.More() {
		return ErrName
	}
	return nil
}

// What the check is for: each of these the decoder takes, a member the type
// does not know being refused, and the check refuses.
func TestExactNamesRefusesWhatTheDecoderFolds(t *testing.T) {
	_ = namedRequest{}.hidden
	for name, raw := range map[string]string{
		"a name in capitals":                      `{"QUERY":"a"}`,
		"a name with one capital":                 `{"Query":"a"}`,
		"a name in capitals beside the name":      `{"query":"a","QUERY":"b"}`,
		"a name with a long s":                    `{"maxRe\u017fults":1}`,
		"a name with a Kelvin sign":               `{"inner":{"to\u212aen":"a"}}`,
		"a name given twice":                      `{"query":"a","query":"b"}`,
		"an untagged field's name in small":       `{"untagged":"a"}`,
		"within a struct":                         `{"inner":{"TEXT":"a"}}`,
		"within a struct behind a pointer":        `{"pointer":{"Text":"a"}}`,
		"within an element of a list":             `{"list":[{"text":"a"},{"BOLD":true}]}`,
		"within an element of an array":           `{"pair":[{"text":"a"},{"Text":"b"}]}`,
		"within a value of a map":                 `{"byName":{"ANY NAME":{"TEXT":"a"}}}`,
		"twice within a struct":                   `{"inner":{"text":"a","text":"b"}}`,
		"of an embedded struct, in capitals":      `{"SHARED":"a"}`,
		"an embedded text's name in small":        `{"namedlabel":"a"}`,
		"a name of an embedded struct's, twice":   `{"shared":"a","shared":"b"}`,
		"the name of a list's member in capitals": `{"LIST":[]}`,
	} {
		if err := strictly(raw, &namedRequest{}); err != nil {
			t.Errorf("%s: the decoder refuses it, so the case holds nothing of the check: %v", name, err)
		}
		if err := ExactNames([]byte(raw), &namedRequest{}); err != ErrName {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// What the decoder refuses itself, the check refuses too: it is not the
// looser of the two.
func TestExactNamesRefusesWhatTheDecoderRefuses(t *testing.T) {
	for name, raw := range map[string]string{
		"a name nothing has":                  `{"other":"a"}`,
		"a name nothing has, within a struct": `{"inner":{"teKt":"a"}}`,
		"a tag's name's field's own name":     `{"Max":1}`,
		"the same in capitals":                `{"MAX":1}`,
		"a name a field gives up with a dash": `{"Skipped":"a"}`,
		"a dash, which names no field":        `{"-":"a"}`,
		"an unexported field's name":          `{"hidden":"a"}`,
		"a value after the value":             `{"query":"a"} {"query":"b"}`,
		"a value cut short":                   `{"query":"a"`,
		"a value cut short within a struct":   `{"inner":{"text":"a"`,
		"nothing":                             ``,
	} {
		if err := strictly(raw, &namedRequest{}); err == nil {
			t.Errorf("%s: the decoder takes it", name)
		}
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

// The types below are made to meet each rule by which the decoder chooses a
// field, among them the ones a review of this check found it had wrong.

type chosenDeep struct {
	X any `json:"x"`
}
type chosenLeft struct{ chosenDeep }
type chosenRight struct {
	X namedInner `json:"x"`
}

// chosenNearest has x at two depths: the nearer is meant.
type chosenNearest struct {
	chosenLeft
	chosenRight
}

// chosenTagged has X by a field's own name and by a tag: the tag's is meant.
type chosenTagged struct {
	X      any
	Chosen namedInner `json:"X"`
}

// chosenOfNone has x twice at one depth, both by a tag: neither is meant,
// and the decoder takes x for the field named X. It is made as the program
// runs: written out, it is a struct the vet tool refuses, for the tag that
// two of its fields share.
var chosenOfNone = reflect.StructOf([]reflect.StructField{
	{Name: "A", Type: reflect.TypeOf(""), Tag: `json:"x"`},
	{Name: "B", Type: reflect.TypeOf(""), Tag: `json:"x"`},
	{Name: "Upper", Type: reflect.TypeOf(""), Tag: `json:"X"`},
})

// chosenTwice embeds one struct at two places of one depth: none of its
// names is meant.
type chosenA struct{ chosenDeep }
type chosenB struct{ chosenDeep }
type chosenTwice struct {
	chosenA
	chosenB
	Kept string `json:"kept"`
}

type chosenPrivate struct {
	Text string `json:"text"`
}

// chosenHeld embeds a struct that is not exported, under a name: it is a
// member of that name. chosenGiven embeds it under none: it gives its names.
type chosenHeld struct {
	chosenPrivate `json:"inner"`
}
type chosenGiven struct {
	chosenPrivate
}

// chosenBadTag has a tag whose name the package does not take, for the
// backslash in it: the field is named by itself.
type chosenBadTag struct {
	Field string `json:"bad\\name"`
	Comma string `json:",omitempty"`
	Dash  string `json:"-,"`
	Space string `json:"two words"`
}

// chosenLower is embedded below, is not exported and is no struct: it has
// no name. Plain is a struct that is not embedded and has no tag: it is a
// member of its own name, and gives none of its own.
type chosenLower string
type chosenQuiet struct {
	chosenLower
	Plain namedInner
	Kept  string `json:"kept"`
}

type chosenD0 struct {
	Value string `json:"value"`
}
type chosenD1 struct{ chosenD0 }
type chosenD2 struct{ chosenD1 }
type chosenD3 struct{ chosenD2 }
type chosenD4 struct{ chosenD3 }
type chosenD5 struct{ chosenD4 }
type chosenD6 struct{ chosenD5 }
type chosenD7 struct{ chosenD6 }
type chosenD8 struct{ chosenD7 }

// chosenD9 has its one name nine structs in.
type chosenD9 struct{ chosenD8 }

// The check is held to the decoder itself. A name is a field's name as
// written where the decoder takes a member of that name and, writing out
// what it read, writes the member under the same name: what it folded, it
// writes under the field's name and not the member's. For every type and
// every name a type has, in the case it has and in others, the check takes
// the name where that is so and refuses it where it is not.
func TestExactNamesChoosesAFieldAsTheDecoderDoes(t *testing.T) {
	values := []string{`"v"`, `1`, `true`, `{"text":"v"}`, `[{"text":"v"}]`, `{"k":{"text":"v"}}`, `"AAAA"`}
	names := []string{"x", "X", "a", "A", "b", "B", "upper", "Upper", "UPPER", "kept", "Kept", "KEPT", "chosen", "Chosen", "text", "Text", "TEXT", "inner", "Inner",
		"field", "Field", "FIELD", "bad\\name", "comma", "Comma", "dash", "Dash", "-", "two words", "Two Words", "space", "Space", "value", "Value", "VALUE",
		"chosenPrivate", "chosenDeep", "chosenD8", "chosenLower", "chosenlower", "Plain", "plain", "query", "Query", "maxResults", "maxresults", "Max", "Untagged", "untagged", "shared", "Shared", "NamedLabel", "namedLabel",
		"bold", "token", "to\u212aen", "Token", "list", "pair", "byName", "any", "raw", "self", "bytes", "Bytes", "pointer", "Skipped", "hidden"}
	taken, refused := 0, 0
	for _, kind := range []reflect.Type{reflect.TypeOf(chosenNearest{}), reflect.TypeOf(chosenTagged{}), chosenOfNone, reflect.TypeOf(chosenTwice{}), reflect.TypeOf(chosenHeld{}), reflect.TypeOf(chosenGiven{}),
		reflect.TypeOf(chosenBadTag{}), reflect.TypeOf(chosenD9{}), reflect.TypeOf(chosenQuiet{}), reflect.TypeOf(namedRequest{}), reflect.TypeOf(namedInner{}), reflect.TypeOf(namedLoop{})} {
		for _, name := range names {
			asWritten := false
			raw := ""
			for _, value := range values {
				raw = `{"` + name + `":` + value + `}`
				fresh := reflect.New(kind).Interface()
				if strictly(raw, fresh) != nil {
					continue
				}
				written, err := json.Marshal(fresh)
				if err != nil {
					t.Fatal(err)
				}
				var members map[string]json.RawMessage
				if err = json.Unmarshal(written, &members); err != nil {
					t.Fatal(err)
				}
				var member string
				json.Unmarshal([]byte(`"`+name+`"`), &member)
				_, asWritten = members[member]
				break
			}
			err := ExactNames([]byte(raw), reflect.New(kind).Interface())
			if asWritten && err != nil {
				t.Errorf("%s: %s is refused, and the decoder reads and writes it under that name", kind, raw)
			}
			if !asWritten && err == nil {
				t.Errorf("%s: %s is taken, and the decoder refuses it or writes it under another name", kind, raw)
			}
			if asWritten {
				taken++
			} else {
				refused++
			}
		}
	}
	// Both answers are asked for many times over, or the comparison holds
	// the check to one of them only.
	if taken < 25 || refused < 200 {
		t.Fatalf("%d names taken and %d refused", taken, refused)
	}
	t.Logf("%d names taken and %d refused, as the decoder has them", taken, refused)
}

// The cases of the review, by name: what each type takes and refuses.
func TestExactNamesOfFieldsThatAreChosenAmongSeveral(t *testing.T) {
	for name, test := range map[string]struct {
		into  any
		raw   string
		taken bool
	}{
		"the nearer of two depths, its members held":        {&chosenNearest{}, `{"x":{"TEXT":"a"}}`, false},
		"the nearer of two depths, as written":              {&chosenNearest{}, `{"x":{"text":"a"}}`, true},
		"the one a tag names, its members held":             {&chosenTagged{}, `{"X":{"TEXT":"a"}}`, false},
		"the one a tag names, as written":                   {&chosenTagged{}, `{"X":{"text":"a"}}`, true},
		"a name two tags give, which means neither":         {reflect.New(chosenOfNone).Interface(), `{"x":"a"}`, false},
		"beside them, the name one tag gives":               {reflect.New(chosenOfNone).Interface(), `{"X":"a"}`, true},
		"a name of a struct embedded at two places":         {&chosenTwice{}, `{"x":"a"}`, false},
		"beside it, a name of the struct's own":             {&chosenTwice{}, `{"kept":"a"}`, true},
		"a struct not exported, embedded under a name":      {&chosenHeld{}, `{"inner":{"text":"a"}}`, true},
		"the same, its members held":                        {&chosenHeld{}, `{"inner":{"TEXT":"a"}}`, false},
		"the same, by a name it does not give":              {&chosenHeld{}, `{"text":"a"}`, false},
		"a struct not exported, embedded under no name":     {&chosenGiven{}, `{"text":"a"}`, true},
		"a tag's name the package does not take":            {&chosenBadTag{}, `{"bad\\name":"a"}`, false},
		"the field of that tag, by its own name":            {&chosenBadTag{}, `{"Field":"a"}`, true},
		"a tag that names nothing before its comma":         {&chosenBadTag{}, `{"Comma":"a"}`, true},
		"a tag that names a dash":                           {&chosenBadTag{}, `{"-":"a"}`, true},
		"a tag that names two words":                        {&chosenBadTag{}, `{"two words":"a"}`, true},
		"an embedded text that is not exported":             {&chosenQuiet{}, `{"chosenLower":"a"}`, false},
		"a struct that is a member, by its own name":        {&chosenQuiet{}, `{"Plain":{"text":"a"}}`, true},
		"the same, by a name of its own members":            {&chosenQuiet{}, `{"text":"a"}`, false},
		"a name nine structs in":                            {&chosenD9{}, `{"value":"a"}`, true},
		"the same in capitals":                              {&chosenD9{}, `{"VALUE":"a"}`, false},
		"a struct that embeds itself, a name of its own":    {&namedLoop{}, `{"name":"a"}`, true},
		"a struct that embeds itself, the name in capitals": {&namedLoop{}, `{"NAME":"a"}`, false},
	} {
		err := ExactNames([]byte(test.raw), test.into)
		if test.taken && err != nil || !test.taken && err != ErrName {
			t.Errorf("%s: %v", name, err)
		}
	}
}
