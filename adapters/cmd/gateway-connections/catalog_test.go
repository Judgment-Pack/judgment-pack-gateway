package main

import (
	"adapters/connections"
	"encoding/json"
	"os"
	"os/exec"
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
			if err != nil || json.Unmarshal(raw, &catalog) != nil || catalog.Version != 1 || len(catalog.Providers) != 4 {
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
