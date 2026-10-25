package connections

import (
	"adapters/mcp"
	"encoding/json"
	"os"
	"reflect"
	"testing"
)

func TestV5CatalogCoversExactCapabilitiesOperationsAndDispatchers(t *testing.T) {
	out := ConnectionCatalogV5()
	if out.Version != 5 || len(out.Providers) != 8 || len(out.Sources) != 3 {
		t.Fatal("catalog shape")
	}
	for _, p := range out.Providers {
		if len(p.OperationTaxonomies) != len(p.Operations) {
			t.Fatal("missing operation taxonomy")
		}
		for _, method := range p.Operations {
			owner, ok := p.OperationTaxonomies[method]
			if !ok || !owner.Valid() {
				t.Fatalf("undeclared %s/%s", p.ID, method)
			}
		}
		constituents := map[string]mcp.ToolTaxonomy{}
		if len(p.OperationDeclarations) != len(p.Operations) {
			t.Fatal("operation declaration coverage")
		}
		for _, method := range p.Operations {
			d := p.OperationDeclarations[method]
			if CheckOperationDeclarationV5(d) != nil || d.Taxonomy != p.OperationTaxonomies[method] || d.Profile.Effect != "act" {
				t.Fatal("actual entry lost policy effect")
			}
			for role, owner := range d.Components {
				constituents[method+"/"+role] = owner
			}
		}
		summary, profile, err := mcp.SummarizeTaxonomies(constituents)
		if err != nil || summary != p.Taxonomy || !reflect.DeepEqual(profile, p.Profile) {
			t.Fatal("provider constituent profile understated")
		}

		if len(p.Source.CapabilityTaxonomies) != len(p.Source.Capabilities) {
			t.Fatal("capability mismatch")
		}
	}
	want := map[string]map[string]string{
		"web": {"page": "read"}, "web-discovery": {"discover": "discover"}, "web-search": {"answer": "answer", "search": "discover"},
		"drive": {"read": "read"}, "gmail": {"read": "read"}, "notion": {"read": "read"}, "obsidian": {"read": "read"}, "aws-s3": {"read": "read"},
		"databricks":   {"statement": "act", "catalog": "discover", "mcp": "run"},
		"azure-devops": {"workitems.query": "discover", "workitems.query-and-get": "discover", "workitems.get": "read", "repos.list": "discover", "repos.items": "read", "repos.commits": "discover", "pullrequests.list": "discover", "pipelines.list": "discover", "pipelines.runs": "discover", "pipelines.run": "read", "mcp": "run"},
	}
	for id, selectors := range want {
		declared := sourceOwners[id]
		if len(declared) != len(selectors) {
			t.Fatalf("dispatcher %s incomplete", id)
		}
		for selector, operation := range selectors {
			owner, ok := declared[selector]
			if !ok || owner.Operation != operation || !owner.Valid() {
				t.Fatalf("%s/%s missing", id, selector)
			}
			if owner.Operation == "run" && owner.Effect != "act" {
				t.Fatal("generic MCP understated")
			}
		}
	}
	for _, p := range out.Providers {
		if p.ID == "databricks" || p.ID == "azure-devops" {
			if p.Source.Taxonomy.Operation != "run" || p.Source.Profile.Effect != "act" {
				t.Fatal("source dispatcher understated")
			}
		}
	}
	for _, s := range out.Sources {
		for name, owner := range s.CapabilityTaxonomies {
			operation := map[string]string{"answer": "answer", "search": "discover", "page": "read"}[name]
			if operation == "" || owner.Operation != operation || owner.Effect != "read-external" {
				t.Fatal("capability owner")
			}
		}
	}
}

func TestV5CatalogValuesAreDetachedAndHistoricalCatalogsUnchanged(t *testing.T) {
	before := []any{ConnectionCatalog(), ConnectionCatalogV3(), ConnectionCatalogV4()}
	raw, _ := json.Marshal(before)
	catalog := ConnectionCatalogV5()
	catalog.Providers[0].OperationTaxonomies["status"] = mcp.ToolTaxonomy{}
	catalog.Providers[0].Operations[0] = "corrupt"
	catalog.Providers[0].Source.DispatchTaxonomies["read"] = mcp.ToolTaxonomy{}
	catalog.Providers[0].Profile.Operations[0] = "corrupt"
	next := ConnectionCatalogV5()
	if next.Providers[0].Operations[0] == "corrupt" || !next.Providers[0].OperationTaxonomies["status"].Valid() || !next.Providers[0].Source.DispatchTaxonomies["read"].Valid() {
		t.Fatal("caller changed declaration")
	}
	after, _ := json.Marshal([]any{ConnectionCatalog(), ConnectionCatalogV3(), ConnectionCatalogV4()})
	if string(raw) != string(after) {
		t.Fatal("historical catalog encoding changed")
	}
}
func TestV5MissingOwnerDeclarationRefusesCatalogAndActualRequestValidation(t *testing.T) {
	held := sourceOwners["databricks"]["catalog"]
	delete(sourceOwners["databricks"], "catalog")
	defer func() { sourceOwners["databricks"]["catalog"] = held }()
	if _, err := (DatabricksRequest{Read: "catalog", List: "catalogs"}).check(DatabricksConnection{}); err == nil {
		t.Fatal("undeclared source dispatcher admitted")
	}
	// Removing a known leaf cannot become a weaker valid catalog profile.
	func() {
		defer func() {
			if recover() == nil {
				t.Fatal("incomplete dispatcher published")
			}
		}()
		ConnectionCatalogV5()
	}()
}
func TestV5MissingCapabilityOrControlDeclarationRefusesCatalog(t *testing.T) {
	for _, kind := range []string{"capability", "control"} {
		t.Run(kind, func(t *testing.T) {
			registry, key := capabilityOwners, CapabilityAnswer
			if kind == "control" {
				registry, key = controlMethodOwners, "files-commit"
			}
			held := registry[key]
			delete(registry, key)
			defer func() { registry[key] = held }()
			defer func() {
				if recover() == nil {
					t.Fatal("incomplete declaration published")
				}
			}()
			ConnectionCatalogV5()
		})
	}
}

func TestV5ActualBrokerEntryCannotHidePolicyOrPersistentCustodyEffects(t *testing.T) {
	catalog := ConnectionCatalogV5()
	if catalog.DiscoveryTaxonomy != (mcp.ToolTaxonomy{Operation: "discover", Effect: "pure"}) {
		t.Fatal("pure discovery scope")
	}
	for _, p := range catalog.Providers {
		for method, d := range p.OperationDeclarations {
			if d.Taxonomy.Effect != "act" || d.Components["operator-policy"] != operatorPolicyOwner || d.Components["operation"].Operation == "own-state" {
				t.Fatalf("weaker actual entry %s/%s", p.ID, method)
			}
		}
	}
	for _, method := range []string{"configure", "disconnect", "source-bind", "source-revoke", "select"} {
		if controlMethodOwners[method].Effect != "act" {
			t.Fatal("persisted custody mislabelled in-run bookkeeping")
		}
	}
	for _, method := range []string{"poll", "cancel"} {
		if controlMethodOwners[method] != (mcp.ToolTaxonomy{Operation: "run", Effect: "act"}) {
			t.Fatal("authorization cancellation understated")
		}
	}
	original, ok := controlDeclaration("google-drive", "status")
	if !ok || original.Taxonomy != (mcp.ToolTaxonomy{Operation: "run", Effect: "act"}) {
		t.Fatal("status actual-entry profile")
	}
	for _, change := range []string{"missing-policy", "extra", "forged-summary", "forged-profile", "missing-operation"} {
		t.Run(change, func(t *testing.T) {
			d := original
			d.Components = copyOwners(original.Components)
			switch change {
			case "missing-policy":
				delete(d.Components, "operator-policy")
			case "extra":
				d.Components["extra"] = operatorPolicyOwner
			case "forged-summary":
				d.Taxonomy = externalOwner("read")
			case "forged-profile":
				d.Profile = mcp.CapabilityProfile{Effect: "read", Operations: []string{"read"}}
			case "missing-operation":
				delete(d.Components, "operation")
			}
			// An attacker may recompute a consistent weaker/extra profile; exact
			// constituent closure must still refuse it.
			if change == "missing-policy" || change == "extra" || change == "missing-operation" {
				d.Taxonomy, d.Profile, _ = mcp.SummarizeTaxonomies(d.Components)
			}
			if CheckOperationDeclarationV5(d) == nil {
				t.Fatal("contradictory actual-entry declaration accepted")
			}
		})
	}
}

func TestV5HandwrittenConstituentAndAcquisitionVectors(t *testing.T) {
	raw, err := os.ReadFile("../../testdata/tool-taxonomy/catalog-v5.json")
	if err != nil {
		t.Fatal(err)
	}
	var vector struct {
		DiscoveryTaxonomy mcp.ToolTaxonomy                       `json:"discoveryTaxonomy"`
		Status            OperationDeclarationV5                 `json:"status"`
		SourceDispatch    map[string]map[string]mcp.ToolTaxonomy `json:"sourceDispatch"`
	}
	if err := json.Unmarshal(raw, &vector); err != nil {
		t.Fatal(err)
	}
	catalog := ConnectionCatalogV5()
	if catalog.DiscoveryTaxonomy != vector.DiscoveryTaxonomy {
		t.Fatal("discovery vector")
	}
	actual, ok := controlDeclaration("google-drive", "status")
	if !ok || !reflect.DeepEqual(actual, vector.Status) || CheckOperationDeclarationV5(vector.Status) != nil {
		t.Fatal("actual-entry constituent vector")
	}
	for provider, selectors := range vector.SourceDispatch {
		for selector, expected := range selectors {
			actual, ok := sourceOwner(provider, selector)
			if !ok || actual != expected {
				t.Fatalf("source protocol bookkeeping/mutation vector %s/%s", provider, selector)
			}
		}
	}
	for _, provider := range []string{"drive", "gmail", "notion", "obsidian", "aws-s3"} {
		if owner, ok := sourceOwner(provider, "read"); !ok || owner != externalOwner("read") {
			t.Fatal("bounded acquisition lost read-external")
		}
	}
	if owner, _ := sourceOwner("databricks", "statement"); owner.Effect != "act" {
		t.Fatal("SQL mutation hidden as bookkeeping")
	}
}
