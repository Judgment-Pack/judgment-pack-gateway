package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// Publisher trust for customer MCP servers (#357): the declaration, the
// liveness read, the name-lookalike flag, and the operator's policy.

var publisherT0 = time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC)

// publisherStandIn answers the registry, repository and RDAP reads from a
// table of path to status and body.
func publisherStandIn(t *testing.T, answers map[string][2]string) publisherChecker {
	t.Helper()
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		a, ok := answers[r.URL.EscapedPath()]
		if !ok {
			http.NotFound(w, r)
			return
		}
		switch a[0] {
		case "200":
			w.Write([]byte(a[1]))
		case "404":
			http.NotFound(w, r)
		default:
			http.Error(w, "unavailable", 503)
		}
	}))
	t.Cleanup(server.Close)
	return publisherChecker{client: server.Client(), npm: server.URL + "/npm/", github: server.URL + "/gh/", rdap: server.URL + "/rdap/", now: func() time.Time { return publisherT0 }}
}

func TestPublisherDeclarationForm(t *testing.T) {
	for _, ok := range []string{
		`{"kind":"registry","name":"npm:@acme/tickets-mcp"}`, `{"kind":"registry","name":"npm:tickets"}`,
		`{"kind":"repository","name":"github.com/acme/tickets-mcp"}`, `{"kind":"domain","name":"tickets.acme.example"}`,
	} {
		v, _ := parseJSON([]byte(ok))
		if _, err := parsePublisher(v); err != nil {
			t.Errorf("%s: %v", ok, err)
		}
	}
	for _, bad := range []string{
		`{"kind":"registry","name":"pypi:tickets"}`, `{"kind":"registry","name":"npm:Tickets"}`,
		`{"kind":"repository","name":"gitlab.com/acme/x"}`, `{"kind":"repository","name":"github.com/acme/.."}`,
		`{"kind":"domain","name":"Acme.example"}`, `{"kind":"domain","name":"localhost"}`,
		`{"kind":"person","name":"x"}`, `{"kind":"domain"}`, `{"kind":"domain","name":"a.example","extra":1}`, `"acme"`,
	} {
		v, _ := parseJSON([]byte(bad))
		if _, err := parsePublisher(v); err == nil {
			t.Errorf("%s was taken", bad)
		}
	}
	customer := `{"bindingVersion":"2","customer":true,"publisher":{"kind":"domain","name":"acme.example"},"platform":"tickets","operations":{"live":{"shape":"mcp","server":{"url":"https://tickets.acme.example/mcp","bearer":"token"},"tools":["query"],"toolTaxonomies":{"query":{"operation":"read","effect":"read-external"}},"licence":"fixture"}}}`
	b, err := parseBinding([]byte(customer))
	if err != nil || b.publisher == nil || b.publisher.name != "acme.example" {
		t.Fatalf("a customer binding's publisher: %+v %v", b.publisher, err)
	}
	if _, err := parseBinding([]byte(strings.Replace(customer, `"customer":true,`, "", 1))); err == nil {
		t.Fatal("a publisher was taken on a binding that is not a customer's")
	}
}

// A lapsed or archived publisher is unmaintained; a live one maintained;
// one whose liveness cannot be read unknown.
func TestPublisherLiveness(t *testing.T) {
	c := publisherStandIn(t, map[string][2]string{
		"/npm/live-pkg":            {"200", `{"dist-tags":{"latest":"2.0.0"},"versions":{"1.0.0":{"deprecated":"old"},"2.0.0":{}}}`},
		"/npm/@acme%2fold":         {"200", `{"dist-tags":{"latest":"1.0.0"},"versions":{"1.0.0":{"deprecated":"no longer maintained"}}}`},
		"/npm/garbled":             {"200", `{"dist-tags":{},"versions":{}}`},
		"/npm/flagged":             {"200", `{"dist-tags":{"latest":"3.0.0"},"versions":{"3.0.0":{"deprecated":true}}}`},
		"/rdap/redeemed.example":   {"200", `{"ldhName":"redeemed.example","status":["active","Redemption Period"],"events":[]}`},
		"/gh/acme/live":            {"200", `{"archived":false,"disabled":false}`},
		"/gh/acme/archived":        {"200", `{"archived":true,"disabled":false}`},
		"/gh/acme/silent":          {"200", `{"disabled":false}`},
		"/gh/acme/down":            {"503", ""},
		"/rdap/acme.example":       {"200", `{"ldhName":"acme.example","status":["active"],"events":[{"eventAction":"expiration","eventDate":"2027-01-01T00:00:00Z"}]}`},
		"/rdap/lapsed.example":     {"200", `{"ldhName":"lapsed.example","status":["active"],"events":[{"eventAction":"expiration","eventDate":"2026-10-30T12:00:00Z"}]}`},
		"/rdap/pending.example":    {"200", `{"ldhName":"pending.example","status":["pending delete"],"events":[]}`},
		"/rdap/other-name.example": {"200", `{"ldhName":"another.example","status":["active"],"events":[]}`},
	})
	for _, k := range []struct {
		kind, name, state string
	}{
		{"registry", "npm:live-pkg", publisherMaintained},
		{"registry", "npm:@acme/old", publisherUnmaintained},
		{"registry", "npm:gone", publisherUnverifiable},
		{"registry", "npm:flagged", publisherUnmaintained},
		{"registry", "npm:garbled", publisherUnknown},
		{"repository", "github.com/acme/live", publisherMaintained},
		{"repository", "github.com/acme/archived", publisherUnmaintained},
		{"repository", "github.com/acme/missing", publisherUnverifiable},
		{"repository", "github.com/acme/silent", publisherUnknown},
		{"repository", "github.com/acme/down", publisherUnknown},
		{"domain", "acme.example", publisherMaintained},
		{"domain", "lapsed.example", publisherUnmaintained},
		{"domain", "pending.example", publisherUnmaintained},
		{"domain", "unregistered.example", publisherUnverifiable},
		{"domain", "tickets.acme.example", publisherMaintained},
		{"domain", "deep.tickets.lapsed.example", publisherUnmaintained},
		{"domain", "redeemed.example", publisherUnmaintained},
		{"domain", "other-name.example", publisherUnknown},
	} {
		if state, reason := c.check(context.Background(), &publisherDecl{k.kind, k.name}); state != k.state || reason == "" {
			t.Errorf("%s %s: %s (%s), not %s", k.kind, k.name, state, reason, k.state)
		}
	}
	if state, _ := c.check(context.Background(), nil); state != publisherUndeclared {
		t.Fatalf("no publisher: %s", state)
	}
}

// A name that closely matches a shipped integration's under another
// publisher is flagged; under that integration's own publisher it is not.
func TestNameLookalike(t *testing.T) {
	stranger := &publisherDecl{"domain", "tools.stranger.example"}
	for _, name := range []string{"databricks", "databrick", "databricsk", "Data-Bricks", "databricks-mcp", "n0tion", "n0t1on", "azure-dev0ps", "gmai1",
		"n\u043eti\u043en", "\uff4e\uff4f\uff54\uff49\uff4f\uff4e", "gm\u0430\u0456l", "d\u0430t\u0430br\u0456\u0441ks", "\u043ebsidi\u0430n", "p\u043estgr\u0435s", "\u039d\u039f\u03a4\u0399\u039f\u039d"} {
		if got := lookalike([]string{name}, stranger); got == "" {
			t.Errorf("%s was not flagged", name)
		}
		if got := lookalike([]string{name}, nil); got == "" {
			t.Errorf("%s with no publisher was not flagged", name)
		}
	}
	for _, name := range []string{"tickets", "weather", "notes", "gml", "posture"} {
		if got := lookalike([]string{name}, stranger); got != "" {
			t.Errorf("%s was flagged as %s", name, got)
		}
	}
	for _, own := range []*publisherDecl{{"domain", "databricks.com"}, {"domain", "mcp.databricks.com"}, {"repository", "github.com/databricks/mcp"}, {"registry", "npm:@databricks/mcp"}} {
		if got := lookalike([]string{"databricks-mcp"}, own); got != "" {
			t.Errorf("databricks' own publisher %+v was flagged", own)
		}
	}
	if got := lookalike([]string{"databricks"}, &publisherDecl{"domain", "databricks.com.stranger.example"}); got == "" {
		t.Fatal("a domain ending in another's name was taken for it")
	}
}

// The publisher of a customer registration is read before anything runs,
// shown with the approval and recorded; under the refuse policy an
// unmaintained publisher refuses the registration, its acquisitions and
// its actions, and a scheduled re-check reads it again.
func TestCustomerRegistrationRecordsPublisherAndPolicyRefuses(t *testing.T) {
	bin, _ := buildMCPStandIns(t, t.TempDir())
	target := newWriteStandIn(t, customerTools)
	answers := map[string][2]string{"/gh/acme/tickets-mcp": {"200", `{"archived":false,"disabled":false}`}}
	checker := publisherStandIn(t, answers)
	binding := strings.Replace(customerBinding(target.URL, ""), `"bindingVersion":"2"`, `"bindingVersion":"2","customer":true,"publisher":{"kind":"repository","name":"github.com/acme/tickets-mcp"}`, 1)
	f, req, check, adapt := customerFixture(t, bin, binding, false)
	// The record takes the configuration's own mode and owner (M5).
	if err := os.Chmod(f.config, 0o640); err != nil {
		t.Fatal(err)
	}
	// Where this user is in a group besides its own, the configuration is
	// given that group, which a record made by this process would not have
	// unless it keeps the configuration's owner.
	if groups, err := os.Getgroups(); err == nil && runtime.GOOS != "windows" {
		for _, g := range groups {
			if g != os.Getgid() && os.Chown(f.config, -1, g) == nil {
				break
			}
		}
	}
	out, err := connectPublisher(context.Background(), req, f.host, check, checker)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(strings.Join(out.statements, "\n"), req.platform+": publisher repository github.com/acme/tickets-mcp: maintained at 2026-10-30T12:00:00.000Z") {
		t.Fatalf("the approval does not show the publisher: %q", out.statements)
	}
	path := publishersPath(f.config)
	record, err := readPublishers(path)
	if err != nil || record.Publishers[req.platform].State != publisherMaintained || !strings.HasPrefix(record.Publishers[req.platform].Binding, "tickets@sha256:") {
		t.Fatalf("%+v %v", record, err)
	}
	// Windows has no Unix modes or owners to keep.
	info, err := os.Stat(path)
	configInfo, _ := os.Stat(f.config)
	if err != nil || runtime.GOOS != "windows" && (info.Mode().Perm() != 0o640 || ownerIDsOf(info) != ownerIDsOf(configInfo)) {
		t.Fatalf("the record's mode and owner are not the configuration's: %v %v", info, err)
	}

	cfg, bindings, err := loadEngineConfig(f.config, stubAccounts(stubUsers))
	if err != nil {
		t.Fatal(err)
	}
	service, server := connectedTestService(t, cfg)
	name := req.platform + "/live"
	service.sources[name] = adapt(deriveSources(cfg, bindings)[name])
	if service.sources[name].publishers != path {
		t.Fatalf("the source is not held to the record: %q", service.sources[name].publishers)
	}
	acquire := func(session string) (int, map[string]any) {
		return post(t, server, "/acquire", `{"session":"`+session+`","source":"`+name+`","arguments":{"tool":"query","arguments":{}}}`)
	}
	if code, result := acquire("maintained"); code != http.StatusOK {
		t.Fatalf("a maintained publisher: %d %v", code, result)
	}

	// The repository is archived: the scheduled re-check reads it, and the
	// report policy reports it and refuses nothing.
	answers["/gh/acme/tickets-mcp"] = [2]string{"200", `{"archived":true,"disabled":false}`}
	var stdout, stderr bytes.Buffer
	if code := runPublishers(context.Background(), []string{"--config", f.config, "--check"}, &stdout, &stderr, checker); code != 0 {
		t.Fatalf("re-check: %d %s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), req.platform+": publisher-unmaintained: "+reasonRepoArchived) || !strings.Contains(stdout.String(), "policy: report") {
		t.Fatalf("%s", stdout.String())
	}
	before := targetCalls(target)
	if code, result := acquire("reported"); code != http.StatusOK {
		t.Fatalf("an unmaintained publisher under the report policy: %d %v", code, result)
	}

	// Under the refuse policy it refuses, before the source is started.
	stdout.Reset()
	if code := runPublishers(context.Background(), []string{"--config", f.config, "--policy", "refuse"}, &stdout, &stderr, checker); code != 0 || !strings.Contains(stdout.String(), "policy: refuse") {
		t.Fatalf("policy: %d %s %s", code, stdout.String(), stderr.String())
	}
	calls := targetCalls(target)
	if code, result := acquire("refused"); code == http.StatusOK || !strings.Contains(strings.ToLower(result["error"].(string)), "publisher-unmaintained") {
		t.Fatalf("an unmaintained publisher under the refuse policy: %d %v", code, result)
	}
	if targetCalls(target) != calls || calls <= before {
		t.Fatal("the refused acquisition reached the server")
	}

	// And a registration again (a recapture) is refused before anything
	// is run, the configuration unchanged.
	configured, _ := os.ReadFile(f.config)
	req.replace = true
	out, err = connectPublisher(context.Background(), req, f.host, check, checker)
	if err == nil || !strings.Contains(err.Error(), "publisher-unmaintained") || !strings.Contains(strings.Join(out.statements, "\n"), "publisher-unmaintained") {
		t.Fatalf("a recapture under the refuse policy: %v %q", err, out.statements)
	}
	if now, _ := os.ReadFile(f.config); !bytes.Equal(now, configured) {
		t.Fatal("the refused recapture changed the configuration")
	}
}

// The refusal is of the record's own binding, under the refuse policy,
// and a record that cannot be read refuses rather than admits.
func TestPublisherRefusalReadsTheRecord(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "engine.json"+publishersSuffix)
	if err := publisherRefusal(path, "tickets", "tickets@sha256:aa"); err != nil {
		t.Fatalf("no record: %v", err)
	}
	f := publisherFile{Version: 1, Policy: publisherPolicyRefuse, Publishers: map[string]publisherRecord{"tickets": {Binding: "tickets@sha256:aa", State: publisherUnmaintained}}}
	if err := writeRecord(t, path, f); err != nil {
		t.Fatal(err)
	}
	if err := publisherRefusal(path, "tickets", "tickets@sha256:aa"); err == nil {
		t.Fatal("an unmaintained publisher under the refuse policy was admitted")
	}
	if err := publisherRefusal(path, "tickets", "tickets@sha256:bb"); err != nil {
		t.Fatalf("another binding's record: %v", err)
	}
	f.Publishers["tickets"] = publisherRecord{Binding: "tickets@sha256:aa", State: publisherUnknown}
	writeRecord(t, path, f)
	if err := publisherRefusal(path, "tickets", "tickets@sha256:aa"); err != nil {
		t.Fatalf("an unknown publisher: %v", err)
	}
	f.Policy = publisherPolicyReport
	f.Publishers["tickets"] = publisherRecord{Binding: "tickets@sha256:aa", State: publisherUnmaintained}
	writeRecord(t, path, f)
	if err := publisherRefusal(path, "tickets", "tickets@sha256:aa"); err != nil {
		t.Fatalf("the report policy: %v", err)
	}
	os.WriteFile(path, []byte(`{"version":1,"policy":"refuse","publishers":{},"extra":true}`), 0o600)
	if err := publisherRefusal(path, "tickets", "tickets@sha256:aa"); err == nil || !strings.Contains(err.Error(), "publisher-record-unreadable") {
		t.Fatalf("an unreadable record: %v", err)
	}
	var stdout, stderr bytes.Buffer
	for _, args := range [][]string{{}, {"--config"}, {"--config", "a", "--policy", "deny"}, {"--config", "a", "--config", "b"}, {"--check", "--check", "--config", "a"}} {
		if code := runPublishers(context.Background(), args, &stdout, &stderr, publisherChecker{}); code != 2 {
			t.Errorf("%v: %d", args, code)
		}
	}
}

// An action through a customer platform whose publisher the record says is
// unmaintained is refused under the refuse policy before an executor runs.
func TestActionRefusedForUnmaintainedPublisher(t *testing.T) {
	service, _ := testService(t)
	service.receiptVersion = receiptVersion3
	path := filepath.Join(t.TempDir(), "engine.json"+publishersSuffix)
	ref := "tickets@sha256:" + strings.Repeat("a", 64)
	if err := writeRecord(t, path, publisherFile{Version: 1, Policy: publisherPolicyRefuse, Publishers: map[string]publisherRecord{"tickets": {Binding: ref, State: publisherUnmaintained}}}); err != nil {
		t.Fatal(err)
	}
	service.sources["tickets/write"] = sourceSpec{shape: "mcp", tools: []string{"update"}, binding: ref, publishers: path, argv: []string{"executor-that-is-not-there"}}
	who := &caller{issuer: "https://issuer.example", subject: "operator"}
	_, err := service.act([]byte(`"publisher-session"`), []byte(`"tickets"`), []byte(`"update"`), nil, nil, nil, who)
	refusal, ok := err.(actRefusal)
	if !ok || refusal.step != "platform" || !strings.Contains(refusal.reason, "publisher-unmaintained") {
		t.Fatalf("an action under the refuse policy: %v", err)
	}
}

// writeRecord puts a publisher record in place as a test sets it.
func writeRecord(t *testing.T, path string, f publisherFile) error {
	t.Helper()
	data, err := json.Marshal(f)
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o600)
}

// M3: under the refuse policy, a publisher the public source does not show
// is reported, and refuses nothing; only evidence of a lapse refuses.
func TestUnverifiablePublisherIsNeverRefused(t *testing.T) {
	path := filepath.Join(t.TempDir(), "engine.json"+publishersSuffix)
	ref := "tickets@sha256:" + strings.Repeat("a", 64)
	writeRecord(t, path, publisherFile{Version: 1, Policy: publisherPolicyRefuse, Publishers: map[string]publisherRecord{"tickets": {Binding: ref, State: publisherUnverifiable, Reason: reasonRepoMissing}}})
	if err := publisherRefusal(path, "tickets", ref); err != nil {
		t.Fatalf("an unverifiable publisher under the refuse policy: %v", err)
	}
	if lines := publisherLines("tickets", publisherRecord{Kind: "repository", Name: "github.com/acme/private", State: publisherUnverifiable, Reason: reasonRepoMissing}); len(lines) != 2 || !strings.Contains(lines[1], "publisher-unverifiable") {
		t.Fatalf("%q", lines)
	}
}

// M4: a refusal answered to /acquire or /act names no path.
func TestUnreadableRecordRefusalNamesNoPath(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "engine.json"+publishersSuffix)
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatal(err)
	}
	err := publisherRefusal(path, "tickets", "tickets@sha256:aa")
	if err == nil || strings.Contains(err.Error(), dir) || strings.Contains(err.Error(), "engine.json") || strings.Contains(err.Error(), string(filepath.Separator)) {
		t.Fatalf("the refusal: %v", err)
	}
}

// H3: a policy set while a scheduled re-check reads the publishers is not
// lost when the re-check writes what it read.
func TestPolicySetDuringRecheckIsKept(t *testing.T) {
	bin, _ := buildMCPStandIns(t, t.TempDir())
	target := newWriteStandIn(t, customerTools)
	answers := map[string][2]string{"/gh/acme/tickets-mcp": {"200", `{"archived":false,"disabled":false}`}}
	checker := publisherStandIn(t, answers)
	binding := strings.Replace(customerBinding(target.URL, ""), `"bindingVersion":"2"`, `"bindingVersion":"2","customer":true,"publisher":{"kind":"repository","name":"github.com/acme/tickets-mcp"}`, 1)
	f, req, check, _ := customerFixture(t, bin, binding, false)
	if _, err := connectPublisher(context.Background(), req, f.host, check, checker); err != nil {
		t.Fatal(err)
	}
	// The re-check's read is held until the policy has been set.
	entered, release := make(chan struct{}), make(chan struct{})
	slow := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(entered)
		<-release
		w.Write([]byte(`{"archived":true,"disabled":false}`))
	}))
	defer slow.Close()
	held := publisherChecker{client: slow.Client(), github: slow.URL + "/gh/", now: func() time.Time { return publisherT0 }}
	done := make(chan int)
	go func() {
		var stdout, stderr bytes.Buffer
		done <- runPublishers(context.Background(), []string{"--config", f.config, "--check"}, &stdout, &stderr, held)
	}()
	<-entered
	var stdout, stderr bytes.Buffer
	if code := runPublishers(context.Background(), []string{"--config", f.config, "--policy", "refuse"}, &stdout, &stderr, checker); code != 0 {
		t.Fatalf("the policy: %d %s", code, stderr.String())
	}
	close(release)
	if code := <-done; code != 0 {
		t.Fatal("the re-check failed")
	}
	record, err := readPublishers(publishersPath(f.config))
	if err != nil || record.Policy != publisherPolicyRefuse || record.Publishers[req.platform].State != publisherUnmaintained {
		t.Fatalf("the policy set during the re-check was lost: %+v %v", record, err)
	}
	if err := publisherRefusal(publishersPath(f.config), req.platform, record.Publishers[req.platform].Binding); err == nil {
		t.Fatal("the unmaintained publisher was admitted")
	}
}
