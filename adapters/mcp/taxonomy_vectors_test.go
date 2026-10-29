package mcp

import (
	"crypto/sha256"
	"encoding/hex"
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
func sharedSourceIdentityVectors(t *testing.T, filename string, customer bool) {
	var v struct {
		Binding, Platform, Operation, Endpoint, SnapshotText, SnapshotDigest, OwnerDeclarationText, OwnerDeclarationDigest string
		Groups                                                                                                             []struct {
			Name       string
			Tools      map[string]ToolTaxonomy
			Taxonomy   ToolTaxonomy
			Operations []string
		}
		Tools    map[string]ToolTaxonomy
		Refusals []struct{ Name, Find, Replace string }
	}
	raw, err := os.ReadFile(filepath.Join("..", "..", "testdata", "tool-taxonomy", filename))
	if err != nil || json.Unmarshal(raw, &v) != nil {
		t.Fatal(err)
	}
	cfg := Config{Customer: customer, URL: v.Endpoint, ToolTaxonomies: v.Tools, Tools: []string{"search", "write"}, ApprovedPlatform: v.Platform, ApprovedBinding: v.Binding, ApprovedOperation: v.Operation, DescriptorSnapshot: filepath.Join(t.TempDir(), "snapshot.json")}
	writeApproval(t, &cfg, []byte(v.SnapshotText))
	if cfg.DescriptorPin != v.SnapshotDigest {
		t.Fatal("fixture digest")
	}
	if _, _, err := approvedSnapshot(cfg); err != nil {
		t.Fatal(err)
	}
	ownerCfg := cfg
	ownerCfg.ToolTaxonomies = nil
	ownerCfg.OwnerDeclarationFile = filepath.Join(t.TempDir(), "owner.json")
	writeOwnerFile(t, &ownerCfg, []byte(v.OwnerDeclarationText))
	if ownerCfg.OwnerDeclarationPin != v.OwnerDeclarationDigest {
		t.Fatal("declaration digest")
	}
	if _, err := ownerCfg.withOwnerDeclaration(); err != nil {
		t.Fatal(err)
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
			changed := []byte(strings.Replace(v.SnapshotText, r.Find, r.Replace, 1))
			writeApproval(t, &cfg, changed)
			if _, _, err := approvedSnapshot(cfg); err == nil {
				t.Fatal("unapproved source identity accepted")
			}
			sum := sha256.Sum256(changed)
			if "sha256:"+hex.EncodeToString(sum[:]) == v.SnapshotDigest {
				t.Fatal("metadata digest unchanged")
			}
		})
	}
}
