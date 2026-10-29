package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestV2SharedSourceIdentityVectors(t *testing.T) {
	sharedSourceIdentityVectors(t, "v2.json", false)
}
func TestV3SharedSourceIdentityVectors(t *testing.T) { sharedSourceIdentityVectors(t, "v3.json", true) }

// V4 is a customer command's: V3 with the command's executable identity.
func TestV4SharedSourceIdentityVectors(t *testing.T) { sharedSourceIdentityVectors(t, "v4.json", true) }
func sharedSourceIdentityVectors(t *testing.T, filename string, customer bool) {
	var v struct {
		Binding, Platform, Operation, Endpoint, SnapshotText, SnapshotDigest, OwnerDeclarationText, OwnerDeclarationDigest string
		Groups                                                                                                             []struct {
			Name       string
			Tools      map[string]ToolTaxonomy
			Taxonomy   ToolTaxonomy
			Operations []string
		}
		Tools         map[string]ToolTaxonomy
		FrontendNames map[string]string
		Command       []string
		Refusals      []struct{ Name, Find, Replace string }
	}
	raw, err := os.ReadFile(filepath.Join("..", "testdata", "tool-taxonomy", filename))
	if err != nil || json.Unmarshal(raw, &v) != nil {
		t.Fatal(err)
	}
	if digestOf(v.SnapshotText) != v.SnapshotDigest || digestOf(v.OwnerDeclarationText) != v.OwnerDeclarationDigest {
		t.Fatal("fixture digest")
	}
	op := operation{customer: customer, name: v.Operation, taxonomies: v.Tools, url: v.Endpoint, command: v.Command}
	accept := func(text string) bool {
		s, err := parseSnapshot([]byte(text))
		return err == nil && snapshotOwners(s, &op) == nil && s.platform == v.Platform && s.binding == v.Binding && snapshotEndpointProblem(s, &op) == nil
	}
	if !accept(v.SnapshotText) {
		t.Fatal("canonical source-identity vector refused")
	}
	for raw, name := range v.FrontendNames {
		if name != v.Platform+"."+raw {
			t.Fatal("explicit name mapping")
		}
	}
	for _, g := range v.Groups {
		summary, profile, err := SummarizeTaxonomies(g.Tools)
		if err != nil || summary != g.Taxonomy || profile.Effect != g.Taxonomy.Effect || !reflect.DeepEqual(profile.Operations, g.Operations) {
			t.Fatalf("group %s: %+v %+v %v", g.Name, summary, profile, err)
		}
	}
	for _, r := range v.Refusals {
		t.Run(r.Name, func(t *testing.T) {
			if strings.Count(v.SnapshotText, r.Find) != 1 {
				t.Fatal("fixture edit")
			}
			changed := strings.Replace(v.SnapshotText, r.Find, r.Replace, 1)
			if accept(changed) {
				t.Fatal("unapproved source identity accepted")
			}
			if digestOf(changed) == v.SnapshotDigest {
				t.Fatal("metadata changed without digest change")
			}
		})
	}
}
