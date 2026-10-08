package main

import (
	"adapters/connections"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"strings"
	"testing"
)

func TestCatalogCLIHelper(t *testing.T) {
	if os.Getenv("GATEWAY_CATALOG_HELPER") != "1" {
		return
	}
	// Discovery must also work without reading publisher registration.
	publisherRegistration = []byte(`invalid`)
	os.Args = append([]string{"gateway-connections"}, os.Args[3:]...)
	os.Exit(run())
}

func TestCatalogCLIHasNoAccountOrFilesystemPrerequisite(t *testing.T) {
	for _, flags := range [][]string{{"--catalog"}, {"--catalog", "--state-dir", "private"}, {"--catalog", "--provider", "gmail"}, {"--catalog", "--disabled"}, {"--catalog", "--principal", "owner"}, {"--catalog", "extra"}} {
		cmd := exec.Command(os.Args[0], append([]string{"-test.run=^TestCatalogCLIHelper$", "--"}, flags...)...)
		cmd.Env = append(os.Environ(), "GATEWAY_CATALOG_HELPER=1")
		cmd.Dir = t.TempDir()
		raw, err := cmd.Output()
		if len(flags) == 1 {
			var catalog connections.Catalog
			if err != nil || json.Unmarshal(raw, &catalog) != nil || catalog.Version != 2 || len(catalog.Sources) != 2 || len(catalog.Providers) != 4 {
				t.Fatalf("catalog command failed: %s %v", raw, err)
			}
		} else if err == nil || len(raw) != 0 {
			t.Fatalf("mixed discovery mode accepted: %v", flags)
		}
		entries, err := os.ReadDir(cmd.Dir)
		if err != nil || len(entries) != 0 {
			t.Fatal("catalog created account state")
		}
	}
}

func TestExtendedDiscoveryModesHaveNoAccountPrerequisite(t *testing.T) {
	for _, mode := range []string{"--catalog-v3", "--local-plan"} {
		for _, extra := range [][]string{nil, {"--catalog"}, {"--provider", "gmail"}, {"--state-dir", "private"}, {"--disabled"}, {"extra"}} {
			flags := append([]string{mode}, extra...)
			cmd := exec.Command(os.Args[0], append([]string{"-test.run=^TestCatalogCLIHelper$", "--"}, flags...)...)
			cmd.Env = append(os.Environ(), "GATEWAY_CATALOG_HELPER=1")
			cmd.Dir = t.TempDir()
			raw, err := cmd.Output()
			if len(extra) == 0 {
				var result struct {
					Version int `json:"version"`
				}
				want := 1
				if mode == "--catalog-v3" {
					want = 3
				}
				if err != nil || json.Unmarshal(raw, &result) != nil || result.Version != want {
					t.Fatalf("%s: %s %v", mode, raw, err)
				}
			} else if err == nil || len(raw) != 0 {
				t.Fatalf("mixed mode accepted: %v", flags)
			}
			entries, err := os.ReadDir(cmd.Dir)
			if err != nil || len(entries) != 0 {
				t.Fatal("discovery created state")
			}
		}
	}
}

// The local plan follows the document-processing settings as they stand when
// it is asked, and writes nothing: with none, or with none configured, it is
// main's plan byte for byte, whatever the environment.
func TestTheLocalPlanFollowsTheProcessingSettings(t *testing.T) {
	plan := func(dir string, set bool) []byte {
		t.Helper()
		cmd := exec.Command(os.Args[0], "-test.run=^TestCatalogCLIHelper$", "--", "--local-plan")
		cmd.Env = []string{"GATEWAY_CATALOG_HELPER=1"}
		for _, kv := range os.Environ() {
			if !strings.HasPrefix(kv, "JPACK_CONNECTIONS_DIR=") {
				cmd.Env = append(cmd.Env, kv)
			}
		}
		if set {
			cmd.Env = append(cmd.Env, "JPACK_CONNECTIONS_DIR="+dir)
		}
		cmd.Dir = t.TempDir()
		raw, err := cmd.Output()
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	want, err := json.Marshal(connections.ConnectionLocalPlanWith(false))
	if err != nil {
		t.Fatal(err)
	}
	want = append(want, '\n')
	dir := t.TempDir()
	os.Chmod(dir, 0700)
	for _, set := range []bool{false, true} {
		if got := plan(dir, set); string(got) != string(want) {
			t.Fatalf("without settings the plan is not main's: %s", got)
		}
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 0 {
		t.Fatal("the plan created custody")
	}
	s, err := connections.OpenProcessingStore(dir, "desk-local")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	b := connections.NewProcessing(s, false)
	status, err := b.Handle(context.Background(), "status", []byte(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	current := status.(connections.ProcessingStatus)
	config := current.ProcessingConfig
	config.Connections = []connections.OCRConnection{{ID: "local", Name: "Local", Kind: "tesseract", Enabled: true}}
	config.Mode, config.Connection = "auto", "local"
	raw, _ := json.Marshal(map[string]any{"ifMatch": current.SHA256, "config": config})
	if _, err = b.Handle(context.Background(), "configure", raw); err != nil {
		t.Fatal(err)
	}
	if got := plan(dir, false); string(got) != string(want) {
		t.Fatal("the plan read settings it was not pointed at")
	}
	var served connections.LocalPlan
	if json.Unmarshal(plan(dir, true), &served) != nil {
		t.Fatal("bad plan")
	}
	long := 0
	for _, source := range served.Sources {
		if source.Timeout == 150 {
			long++
			if !source.Connections || source.Args[len(source.Args)-1] != "--document-processing" {
				t.Fatalf("%+v", source)
			}
		}
	}
	if long != 4 {
		t.Fatalf("%d sources have the processing envelope", long)
	}
}

// A search connection whose timeout the ordinary envelope does not carry gives
// web-search the long one in the plan, and nothing else changes.
func TestTheLocalPlanFollowsTheSearchTimeouts(t *testing.T) {
	dir := t.TempDir()
	os.Chmod(dir, 0700)
	plan := func() connections.LocalPlan {
		t.Helper()
		cmd := exec.Command(os.Args[0], "-test.run=^TestCatalogCLIHelper$", "--", "--local-plan")
		cmd.Env = append(os.Environ(), "GATEWAY_CATALOG_HELPER=1", "JPACK_CONNECTIONS_DIR="+dir)
		cmd.Dir = t.TempDir()
		raw, err := cmd.Output()
		var served connections.LocalPlan
		if err != nil || json.Unmarshal(raw, &served) != nil {
			t.Fatal(err)
		}
		return served
	}
	s, err := connections.OpenSearchStore(dir, "desk-local")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	b := connections.NewSearch(s, false)
	defer b.Close()
	raw, _ := json.Marshal(connections.SearchConnection{ID: "demo", Name: "Demo", Provider: "tavily", DailyLimit: 10, Credential: "tvly-test-private-key", TimeoutSeconds: 90})
	if _, err = b.Handle(context.Background(), "configure", raw); err != nil {
		t.Fatal(err)
	}
	want, _ := json.Marshal(connections.ConnectionLocalPlanFor(false, true))
	got, _ := json.Marshal(plan())
	if string(got) != string(want) {
		t.Fatalf("a 90-second search connection: %s", got)
	}
}
