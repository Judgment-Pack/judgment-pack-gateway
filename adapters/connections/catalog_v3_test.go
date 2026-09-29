package connections

import (
	"adapters/attachment"
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

func TestV3CatalogIsCompleteLocalizedAndMatchesLocalPlan(t *testing.T) {
	catalog := ConnectionCatalogV3()
	if catalog.Version != 3 || len(catalog.Providers) != 6 {
		t.Fatal("wrong catalog")
	}
	plan := ConnectionLocalPlan()
	for _, descriptor := range catalog.Providers {
		if (descriptor.Protocol != "connection-v1" && descriptor.Protocol != "web-search-v1") || descriptor.Presentation.Name == "" {
			t.Fatal(descriptor.ID)
		}
		for _, locale := range []string{"en", "fr", "es", "de", "it", "pt-PT", "pt-BR", "ko", "ja", "zh-Hans", "zh-Hant", "yue-Hant"} {
			if descriptor.Presentation.Description[locale] == "" || descriptor.Presentation.Instructions[locale] == "" {
				t.Fatal("missing translation", descriptor.ID, locale)
			}
		}
		found := false
		for _, source := range plan.Sources {
			found = found || source.ID == descriptor.Source.ID && source.Shape == descriptor.Source.Shape
		}
		if !found {
			t.Fatal("catalog offers unconfigured source", descriptor.ID)
		}
	}
	raw, err := json.Marshal(catalog)
	if err != nil || len(raw) > 128<<10 {
		t.Fatal("catalog exceeds budget", len(raw), err)
	}
	catalog.Providers[0].Presentation.Description["en"] = "changed"
	if ConnectionCatalogV3().Providers[0].Presentation.Description["en"] == "changed" {
		t.Fatal("shared descriptor state")
	}
}

// A desk refuses a plan that names a source twice, and reaches the rendering
// adapter by the one entry named render: a bare source that holds no
// connection.
func TestTheLocalPlanNamesEachSourceOnceAndTheRenderingAdapter(t *testing.T) {
	plan := ConnectionLocalPlan()
	seen := map[string]int{}
	for _, source := range plan.Sources {
		seen[source.ID]++
	}
	for id, times := range seen {
		if times != 1 {
			t.Errorf("the plan names %q %d times", id, times)
		}
	}
	if plan.Version != 1 || len(plan.Sources) != 10 {
		t.Fatalf("version %d, %d sources", plan.Version, len(plan.Sources))
	}
	for _, source := range plan.Sources {
		if source.ID != "render" {
			continue
		}
		// The arguments are these and no others, so that every bound the
		// plan does not name is the adapter's default.
		if source.Executable != "adapter-render" || strings.Join(source.Args, " ") != "--max-output 6291456" || len(source.Args) != 2 ||
			source.Shape != "command" || source.Connections || source.Timeout != 30 {
			t.Fatalf("render = %+v", source)
		}
		return
	}
	t.Fatal("the plan names no source render")
}

func TestResourceProducerSupportsUnknownProviderAndBindsRetainedBytes(t *testing.T) {
	for _, provider := range []string{"fixture-files", "fixture-objects"} {
		raw, err := ResourceDocument(context.Background(), provider, "bucket/policy.txt", "Policy.txt", "text/plain", "https://example.com/policy", []byte("Fixture policy.\n"))
		if err != nil {
			t.Fatal(err)
		}
		if attachment.Check(raw) != nil {
			t.Fatal("invalid producer output")
		}
		var value map[string]any
		if json.Unmarshal(raw, &value) != nil {
			t.Fatal("not JSON")
		}
		source := value["provenance"].(map[string]any)["source"].(map[string]any)
		if source["provider"] != provider || source["resourceId"] != "bucket/policy.txt" {
			t.Fatal("wrong resource")
		}
		source["version"] = digest([]byte("changed"))
		changed, _ := json.Marshal(value)
		if attachment.Check(changed) == nil {
			t.Fatal("changed resource accepted")
		}
		if path := os.Getenv("JPACK_TEST_RESOURCE_RECORD"); path != "" && provider == "fixture-files" {
			if err := os.WriteFile(path, raw, 0600); err != nil {
				t.Fatal(err)
			}
		}
	}
}

func TestResourceProducerRejectsInvalidIdentityAndCapabilityURLs(t *testing.T) {
	for _, sourceURL := range []string{"https://example.com/policy?token=secret", "https://user:password@example.com/policy", "file:///private", "javascript:alert(1)"} {
		if _, err := ResourceDocument(context.Background(), "fixture-files", "policy", "policy.txt", "text/plain", sourceURL, []byte("Policy")); err == nil {
			t.Fatal("unsafe citation URL accepted")
		}
	}
	for _, provider := range []string{"../provider", "a b", "UPPER", ""} {
		if _, err := ResourceDocument(context.Background(), provider, "policy", "policy.txt", "text/plain", "", []byte("Policy")); err == nil {
			t.Fatal("unsafe provider accepted")
		}
	}
}
