package main

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
)

func TestActionReceiptSharedMutations(t *testing.T) {
	raw, err := os.ReadFile("../testdata/action-reconciliation/mutations.json")
	if err != nil {
		t.Fatal(err)
	}
	var rows []struct {
		Kind, Member  string
		Value         json.RawMessage
		Remove, Valid bool
	}
	if err = json.Unmarshal(raw, &rows); err != nil {
		t.Fatal(err)
	}
	for _, row := range rows {
		t.Run(row.Kind+"/"+row.Member, func(t *testing.T) {
			text := `{"key":"` + strings.Repeat("a", 64) + `","contract":"sha256:` + strings.Repeat("b", 64) + `","outcome":"uncertain"}`
			if row.Kind != "delivery" {
				text = `{"key":"` + strings.Repeat("a", 64) + `","contract":"sha256:` + strings.Repeat("b", 64) + `","outcome":"committed","action":{"sessionId":"act","callIndex":0,"signature":"` + testSig3 + `"}}`
			}
			v, _ := parseJSON([]byte(text))
			o := v.(*vObject)
			target := o
			if row.Kind == "citation" {
				v, _ := o.get("action")
				target = v.(*vObject)
			}
			if row.Remove {
				replacement := newObject()
				for _, name := range target.names {
					if name != row.Member {
						v, _ := target.get(name)
						replacement.set(name, v)
					}
				}
				if row.Kind == "citation" {
					o.set("action", replacement)
				} else {
					o = replacement
				}
			} else {
				v, err := parseJSON(row.Value)
				if err != nil {
					t.Fatal(err)
				}
				target.set(row.Member, v)
			}
			kind := "action"
			if row.Kind != "delivery" {
				kind = "acquisition"
			}
			obj, r := receipt3(kind, func(receipt *vObject) {
				detail, _ := receipt.get(kind)
				name := "delivery"
				if kind == "acquisition" {
					name = "reconciliation"
				}
				detail.(*vObject).set(name, o)
			})
			err := validateVersion3(obj, r)
			if (err == nil) != row.Valid {
				t.Fatalf("valid=%v: %v", row.Valid, err)
			}
		})
	}
}
