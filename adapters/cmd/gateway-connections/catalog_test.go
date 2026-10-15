package main

import (
	"adapters/connections"
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
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
	for _, mode := range []string{"--catalog-v3", "--catalog-v4", "--local-plan", "--source-capabilities"} {
		for _, extra := range [][]string{nil, {"--catalog"}, {"--catalog-v3"}, {"--provider", "gmail"}, {"--state-dir", "private"}, {"--disabled"}, {"extra"}} {
			if mode == "--catalog-v3" && len(extra) == 1 && extra[0] == "--catalog-v3" {
				continue
			}
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
				if mode == "--catalog-v4" {
					want = 4
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

// Each request is given its deadline: 50 seconds, a document-processing test
// 140, a search connection's test 125.
func TestEachRequestGetsItsDeadline(t *testing.T) {
	for _, c := range []struct {
		provider, method string
		want             time.Duration
	}{{"web-search", "test", 125 * time.Second}, {"web-search", "status", 50 * time.Second}, {"web-search", "configure", 50 * time.Second}, {"document-processing", "test", 140 * time.Second}, {"document-processing", "status", 50 * time.Second}, {"google-drive", "test", 50 * time.Second}} {
		ctx, cancel := requestContext(c.provider, c.method)
		deadline, ok := ctx.Deadline()
		cancel()
		if left := time.Until(deadline); !ok || left > c.want || left < c.want-time.Second {
			t.Errorf("%s %s: %v left, want %v", c.provider, c.method, left, c.want)
		}
	}
}

// The plan and the capability report read the operator's web redirect
// policies from the same variable: absent or empty, the plan is main's and
// nothing is enabled; google-grounding, the web source is launched with it
// and the report says so; an unknown name refuses both with one sentence and
// no output.
func TestTheOperatorsRedirectPoliciesReachThePlanAndTheReport(t *testing.T) {
	ask := func(mode string, env ...string) ([]byte, string, error) {
		t.Helper()
		cmd := exec.Command(os.Args[0], "-test.run=^TestCatalogCLIHelper$", "--", mode)
		cmd.Env = []string{"GATEWAY_CATALOG_HELPER=1"}
		for _, kv := range os.Environ() {
			if !strings.HasPrefix(kv, "JPACK_CONNECTIONS_DIR=") && !strings.HasPrefix(kv, connections.WebRedirectPoliciesEnv+"=") {
				cmd.Env = append(cmd.Env, kv)
			}
		}
		cmd.Env = append(cmd.Env, env...)
		cmd.Dir = t.TempDir()
		var stderr strings.Builder
		cmd.Stderr = &stderr
		raw, err := cmd.Output()
		return raw, stderr.String(), err
	}
	main, _ := json.Marshal(connections.ConnectionLocalPlanWith(false))
	none, _ := json.Marshal(connections.ConnectionSourceCapabilities(nil))
	enabled, _ := json.Marshal(connections.ConnectionSourceCapabilities([]string{"google-grounding"}))
	withPolicy, _ := json.Marshal(connections.ConnectionLocalPlanWith(false).WithWebRedirectPolicies([]string{"google-grounding"}))
	for _, c := range []struct {
		env          []string
		plan, report string
	}{
		{nil, string(main), string(none)},
		{[]string{"JPACK_WEB_REDIRECT_POLICIES="}, string(main), string(none)},
		{[]string{"JPACK_WEB_REDIRECT_POLICIES=google-grounding"}, string(withPolicy), string(enabled)},
	} {
		if raw, _, err := ask("--local-plan", c.env...); err != nil || string(raw) != c.plan+"\n" {
			t.Errorf("%v plan: %s %v", c.env, raw, err)
		}
		if raw, _, err := ask("--source-capabilities", c.env...); err != nil || string(raw) != c.report+"\n" {
			t.Errorf("%v report: %s %v", c.env, raw, err)
		}
	}
	for _, mode := range []string{"--local-plan", "--source-capabilities"} {
		raw, said, err := ask(mode, "JPACK_WEB_REDIRECT_POLICIES=any-origin")
		var exit *exec.ExitError
		if !errors.As(err, &exit) || exit.ExitCode() != 2 || len(raw) != 0 || said != connections.WebRedirectPolicyRefusal+"\n" {
			t.Errorf("%s with an unknown policy: %q %q %v", mode, raw, said, err)
		}
	}
	// The catalogs do not read it.
	for _, mode := range []string{"--catalog-v3", "--catalog-v4"} {
		if raw, _, err := ask(mode, "JPACK_WEB_REDIRECT_POLICIES=any-origin"); err != nil || len(raw) == 0 {
			t.Error("the catalog read the redirect policies", mode, err)
		}
	}
}

// --catalog-v4 writes version 4 as the package makes it, and the earlier
// flags write their versions without the research capabilities.
func TestTheCatalogFlagsWriteTheirVersions(t *testing.T) {
	for _, c := range []struct {
		flag string
		want any
	}{{"--catalog", connections.ConnectionCatalog()}, {"--catalog-v3", connections.ConnectionCatalogV3()}, {"--catalog-v4", connections.ConnectionCatalogV4()}} {
		cmd := exec.Command(os.Args[0], "-test.run=^TestCatalogCLIHelper$", "--", c.flag)
		cmd.Env = append(os.Environ(), "GATEWAY_CATALOG_HELPER=1")
		cmd.Dir = t.TempDir()
		raw, err := cmd.Output()
		want, _ := json.Marshal(c.want)
		if err != nil || string(raw) != string(want)+"\n" {
			t.Errorf("%s: %v", c.flag, err)
		}
		if has := strings.Contains(string(raw), `"capabilities"`); has != (c.flag == "--catalog-v4") {
			t.Errorf("%s: capabilities written: %v", c.flag, has)
		}
	}
}
