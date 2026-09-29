package canon

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"reflect"
	"strings"
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
// It follows the type: into a struct's fields, the elements of a slice or an
// array and the values of a map. Where the type says nothing of a value's
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

// fieldNames is the names a struct is decoded by, each with its field's
// type: the name of the tag where there is one, the field's own where there
// is none, and the names of an embedded struct's fields as if they were the
// struct's own, where a nearer field of the same name does not hide them.
func fieldNames(t reflect.Type, into map[string]reflect.Type, depth int) {
	var embedded []reflect.Type
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		tag, tagged := f.Tag.Lookup("json")
		name, _, _ := strings.Cut(tag, ",")
		if tagged && tag == "-" {
			continue
		}
		if f.Anonymous && name == "" {
			inner := f.Type
			for inner.Kind() == reflect.Pointer {
				inner = inner.Elem()
			}
			if inner.Kind() == reflect.Struct {
				embedded = append(embedded, inner)
				continue
			}
		}
		if !f.IsExported() {
			continue
		}
		if name == "" {
			name = f.Name
		}
		if _, nearer := into[name]; !nearer {
			into[name] = f.Type
		}
	}
	// A struct may embed a pointer to itself, and would be followed without
	// end. No request is a struct within a struct eight times over.
	if depth < 8 {
		for _, inner := range embedded {
			fieldNames(inner, into, depth+1)
		}
	}
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
			names = map[string]reflect.Type{}
			fieldNames(t, names, 0)
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
