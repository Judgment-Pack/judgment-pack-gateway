package canon

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"reflect"
	"strings"
	"unicode"
)

// ErrName is what ExactNames refuses with. It names no member: a member's
// name is the caller's text, and a refusal repeats none of it.
var ErrName = errors.New("a member is not named as the contract names it, or is named twice")

var unmarshaler = reflect.TypeOf((*json.Unmarshaler)(nil)).Elem()

// ExactNames holds the member names of raw to the names a value of into's
// type is decoded by, and refuses raw where they differ.
//
// encoding/json decodes an object into a struct by matching each member's
// name to a field's without regard to case, and by a folding that takes the
// long s and the Kelvin sign for the letters they resemble. So "QUERY" is
// read as query, and an object that holds both is read as holding the one
// that comes last. A reader that refuses an unknown member does not refuse
// either: to the decoder both are known. ExactNames refuses a member of an
// object decoded into a struct unless its name is a field's name as written,
// and refuses a name given twice in such an object.
//
// It chooses a member's field as the decoder does (fieldNames), and follows
// the type: into a struct's fields, the elements of a slice or an array and
// the values of a map. Where the type says nothing of a value's
// members -- an interface, a json.RawMessage, a type that decodes itself --
// it holds that value to nothing, and whoever reads the value later holds it
// to what they read. It decodes nothing and changes nothing: a caller
// decodes as before, and calls this beside it.
//
// raw must be one JSON value with nothing after it.
func ExactNames(raw []byte, into any) error {
	t := reflect.TypeOf(into)
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	if err := walkNames(dec, t, 0); err != nil {
		return err
	}
	if _, err := dec.Token(); err != io.EOF {
		return ErrName
	}
	return nil
}

// named is one field a member's name could mean: the name it is decoded
// by, how many structs in it lies, and whether a tag gave it the name.
type named struct {
	name   string
	of     reflect.Type
	depth  int
	tagged bool
}

// fieldNames is the names a struct is decoded by, each with its field's
// type, by the rules encoding/json states for choosing a field:
//
//   - a field is named by its tag where the tag has a name the package takes
//     (letters, digits and the punctuation it lists), and by its own name
//     otherwise; a tag of "-" alone gives the field up;
//   - a field that is not exported has no name, unless it is an embedded
//     struct;
//   - an embedded struct with no name in its tag gives its fields' names as
//     if they were the outer struct's, a struct embedded in it likewise, and
//     one with a name in its tag is a member of that name;
//   - of several fields of one name the least deep is meant; of several at
//     that depth, the one a tag named, if it is the only one so named; and
//     where that leaves more than one, none of them is meant.
//
// A struct embedded at two places of one depth gives each of its names
// twice, so that none of them is meant. A struct is followed once: one that
// embeds itself comes to an end.
func fieldNames(t reflect.Type) map[string]reflect.Type {
	var found []named
	visited := map[reflect.Type]bool{}
	level, times := []reflect.Type{t}, map[reflect.Type]int{t: 1}
	for depth := 0; len(level) > 0; depth++ {
		var next []reflect.Type
		nextTimes := map[reflect.Type]int{}
		for _, in := range level {
			if visited[in] {
				continue
			}
			visited[in] = true
			for i := 0; i < in.NumField(); i++ {
				f := in.Field(i)
				inner := f.Type
				if inner.Kind() == reflect.Pointer {
					inner = inner.Elem()
				}
				if f.Anonymous {
					if !f.IsExported() && inner.Kind() != reflect.Struct {
						continue
					}
				} else if !f.IsExported() {
					continue
				}
				tag := f.Tag.Get("json")
				if tag == "-" {
					continue
				}
				name, _, _ := strings.Cut(tag, ",")
				if !tagName(name) {
					name = ""
				}
				if name == "" && f.Anonymous && inner.Kind() == reflect.Struct {
					if nextTimes[inner]++; nextTimes[inner] == 1 {
						next = append(next, inner)
					}
					continue
				}
				one := named{name, f.Type, depth, name != ""}
				if name == "" {
					one.name = f.Name
				}
				found = append(found, one)
				if times[in] > 1 {
					found = append(found, one)
				}
			}
		}
		level, times = next, nextTimes
	}
	byName := map[string][]named{}
	for _, one := range found {
		byName[one.name] = append(byName[one.name], one)
	}
	names := map[string]reflect.Type{}
	for name, all := range byName {
		// The structs were gone through a depth at a time, so the first
		// field found of a name is of the least depth it is found at.
		least := all[0].depth
		var nearest, tagged []named
		for _, one := range all {
			if one.depth == least {
				nearest = append(nearest, one)
				if one.tagged {
					tagged = append(tagged, one)
				}
			}
		}
		if len(tagged) > 0 {
			nearest = tagged
		}
		if len(nearest) == 1 {
			names[name] = nearest[0].of
		}
	}
	return names
}

// tagName reports whether the package takes name, from a tag, for a name.
func tagName(name string) bool {
	if name == "" {
		return false
	}
	for _, c := range name {
		switch {
		case strings.ContainsRune("!#$%&()*+-./:;<=>?@[]^_{|}~ ", c):
		case !unicode.IsLetter(c) && !unicode.IsDigit(c):
			return false
		}
	}
	return true
}

func selfDecoding(t reflect.Type) bool {
	return t.Implements(unmarshaler) || reflect.PointerTo(t).Implements(unmarshaler)
}

// walkNames reads one value from dec, holding it to t. A nil t holds it to
// nothing.
func walkNames(dec *json.Decoder, t reflect.Type, depth int) error {
	if depth > maxNesting {
		return ErrName
	}
	for t != nil && t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	// An interface needs no word here: it is no struct, no map and no list,
	// and so holds what it is given to nothing.
	if t != nil && selfDecoding(t) {
		t = nil
	}
	tok, err := dec.Token()
	if err != nil {
		return ErrName
	}
	delim, opens := tok.(json.Delim)
	if !opens {
		return nil
	}
	switch delim {
	case '{':
		var names map[string]reflect.Type
		var values reflect.Type
		if t != nil && t.Kind() == reflect.Struct {
			names = fieldNames(t)
		} else if t != nil && t.Kind() == reflect.Map {
			values = t.Elem()
		}
		seen := map[string]bool{}
		for dec.More() {
			key, err := dec.Token()
			name, isName := key.(string)
			if err != nil || !isName {
				return ErrName
			}
			inner := values
			if names != nil {
				field, named := names[name]
				if !named || seen[name] {
					return ErrName
				}
				seen[name] = true
				inner = field
			}
			if err := walkNames(dec, inner, depth+1); err != nil {
				return err
			}
		}
	case '[':
		var element reflect.Type
		if t != nil && (t.Kind() == reflect.Slice || t.Kind() == reflect.Array) {
			element = t.Elem()
		}
		for dec.More() {
			if err := walkNames(dec, element, depth+1); err != nil {
				return err
			}
		}
	default:
		return ErrName
	}
	if _, err := dec.Token(); err != nil {
		return ErrName
	}
	return nil
}
