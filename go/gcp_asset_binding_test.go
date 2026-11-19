package main

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"
)

// inventoryBinding is a catalog entry whose one operation is live by the
// gcp-asset shape (ADR-0039, Amendment A1). Every name in it is synthetic.
const inventoryBinding = `{
  "bindingVersion": "1",
  "platform": "inventory",
  "operations": {
    "live": {"shape": "gcp-asset", "licence": "Apache-2.0", "parents": ["projects/example-project-1", "projects/example-project-2"],
      "assetTypes": ["compute.googleapis.com/Instance", "storage.googleapis.com/Bucket"], "contentTypes": ["RESOURCE"]}
  }
}`

// gcpLive is a binding of one gcp-asset live operation with the members
// given, and the shape and licence every operation carries.
func gcpLive(members string) string {
	return `{"bindingVersion":"1","platform":"p","operations":{"live":{"shape":"gcp-asset","licence":"MIT"` + members + `}}}`
}

// A gcp-asset live operation is held to its shape before the engine
// starts: exactly its members, projects only (a folder refused by name),
// asset types of the platform's form and no pattern, RESOURCE and
// IAM_POLICY, no repeat, members "count-users" or absent, and no other
// operation beside it. A refusal names the member by its place and
// repeats no value.
func TestGCPAssetOperationRefusals(t *testing.T) {
	const types = `,"assetTypes":["compute.googleapis.com/Instance"],"contentTypes":["RESOURCE"]`
	const ok = `,"parents":["projects/example-project-1"]` + types
	live := `"live":{"shape":"gcp-asset","licence":"MIT"` + ok + `}`
	history := `"history":{"shape":"airbyte","image":"x@` + testImageDigest + `","licence":"MIT"}`
	for _, c := range []struct{ name, text, want string }{
		{"an endpoint", gcpLive(ok + `,"endpoint":"https://inventory.example"`), `unknown member "endpoint"`},
		{"a write member", gcpLive(ok + `,"write":true`), `unknown member "write"`},
		{"no parents", gcpLive(types), `missing member "parents"`},
		{"a folder", gcpLive(`,"parents":["folders/987654321"]` + types), "parents[0] is a folder, and this version reads projects only"},
		{"a project number", gcpLive(`,"parents":["projects/987654321"]` + types), "parents[0] is not projects/<project-id>"},
		{"an organization", gcpLive(`,"parents":["organizations/987654321"]` + types), "parents[0] is not projects/<project-id>"},
		{"a parent twice", gcpLive(`,"parents":["projects/example-project-1","projects/example-project-1"]` + types), "parents[1] repeats an earlier parent"},
		{"an asset type pattern", gcpLive(`,"parents":["projects/example-project-1"],"assetTypes":["compute.googleapis.com/*"],"contentTypes":["RESOURCE"]`), "assetTypes[0] is not an asset type"},
		{"an asset type twice", gcpLive(`,"parents":["projects/example-project-1"],"assetTypes":["compute.googleapis.com/Instance","compute.googleapis.com/Instance"],"contentTypes":["RESOURCE"]`), "assetTypes[1] repeats an earlier asset type"},
		{"a content type of another kind", gcpLive(`,"parents":["projects/example-project-1"],"assetTypes":["compute.googleapis.com/Instance"],"contentTypes":["ORG_POLICY"]`), "contentTypes[0] is neither RESOURCE nor IAM_POLICY"},
		{"a content type twice", gcpLive(`,"parents":["projects/example-project-1"],"assetTypes":["compute.googleapis.com/Instance"],"contentTypes":["RESOURCE","RESOURCE"]`), "contentTypes[1] repeats an earlier content type"},
		{"members of another value", gcpLive(ok + `,"members":"hash-every-member"`), `members, when present, is "count-users"`},
		{"members null", gcpLive(ok + `,"members":null`), `members, when present, is "count-users"`},
		{"history beside it", `{"bindingVersion":"1","platform":"p","operations":{` + history + `,` + live + `}}`, "operation live of the gcp-asset shape is its binding's only operation"},
		{"a write by the shape", `{"bindingVersion":"1","platform":"p","operations":{"write":{"shape":"gcp-asset","licence":"MIT"` + ok + `}}}`, `operation write is served by the mcp shape, not "gcp-asset"`},
		{"an owner-declared binding", `{"bindingVersion":"2","platform":"p","operations":{"live":{"shape":"gcp-asset","licence":"MIT"` + ok + `,"toolTaxonomies":{}}}}`, "the gcp-asset shape is a bindingVersion 1 operation"},
		{"no licence", `{"bindingVersion":"1","platform":"p","operations":{"live":{"shape":"gcp-asset"` + ok + `}}}`, "licence"},
	} {
		_, err := parseBinding([]byte(c.text))
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: want %q, got %v", c.name, c.want, err)
			continue
		}
		if strings.Contains(err.Error(), "987654321") || strings.Contains(err.Error(), "hash-every-member") {
			t.Errorf("%s: the refusal repeats a value: %v", c.name, err)
		}
	}
}

// A gcp-asset operation parses to what adapter-gcp-asset is started with,
// names no MCP operation and no tool to describe, and its command line
// carries each flag and its value as one word, the member reduction only
// where the binding asks for it.
func TestGCPAssetOperationParses(t *testing.T) {
	b, err := parseBinding([]byte(inventoryBinding))
	if err != nil {
		t.Fatal(err)
	}
	want := &gcpAssetOperation{parents: []string{"projects/example-project-1", "projects/example-project-2"},
		assetTypes: []string{"compute.googleapis.com/Instance", "storage.googleapis.com/Bucket"}, contentTypes: []string{"RESOURCE"}}
	if b.live == nil || b.live.shape != gcpAssetShape || !reflect.DeepEqual(b.live.gcpAsset, want) || b.live.http != nil || b.history != nil || b.write != nil {
		t.Fatalf("the operation: %+v", b.live)
	}
	if ops := enabledMCPOperations(platformConfig{}, b); len(ops) != 0 || describedOperation(b, false) != nil {
		t.Fatalf("a gcp-asset operation is no MCP operation: %v", ops)
	}
	argv := gcpAssetSourceArgv("adapter-gcp-asset", *want, "/c.json", "metadata")
	if !reflect.DeepEqual(argv, []string{"adapter-gcp-asset", "--parents=projects/example-project-1,projects/example-project-2",
		"--asset-types=compute.googleapis.com/Instance,storage.googleapis.com/Bucket", "--content-types=RESOURCE", "--credentials=/c.json", "--token-source=metadata"}) {
		t.Fatalf("argv: %q", argv)
	}
	b, err = parseBinding([]byte(gcpLive(`,"parents":["projects/example-project-1"],"assetTypes":["iam.googleapis.com/ServiceAccount"],"contentTypes":["RESOURCE","IAM_POLICY"],"members":"count-users"`)))
	if err != nil {
		t.Fatal(err)
	}
	if !b.live.gcpAsset.countUsers || !contains(gcpAssetSourceArgv("a", *b.live.gcpAsset, "c", "key"), "--members=count-users") {
		t.Fatalf("count-users: %+v", b.live.gcpAsset)
	}
}

// gcpPlatformJSON is a platform entry for the inventory binding: its live
// credentials file with the token source given, when given.
func gcpPlatformJSON(t *testing.T, ref, tokenSource, extra string) string {
	t.Helper()
	ts := ""
	if tokenSource != "" {
		ts = `,"tokenSource":` + tokenSource
	}
	return `"inventory":{"binding":"` + ref + `","credentials":{"live":{"file":"` + abs(t, t.TempDir(), "inventory-live.json") + `"` + ts + `}},"user":"engine-docs"` + extra + `}`
}

func engineAt(t *testing.T, version, catalog, platforms string) string {
	t.Helper()
	return strings.Replace(engineJSON(t, catalog, ``, platforms), `"engineVersion":"1"`, `"engineVersion":"`+version+`"`, 1)
}

// The engine derives `<platform>/live` of a gcp-asset binding as
// adapter-gcp-asset, as the platform's user with its live credentials file
// and token source, shape http, under the source sandbox, keeping no
// payload unless the operator set artifact "retained".
func TestEngineDerivesAGCPAssetSource(t *testing.T) {
	catalog := catalogWith(t, map[string]string{"inventory": inventoryBinding})
	ref := "inventory@" + digestOf(inventoryBinding)
	cfg, sources, err := load(t, engineAt(t, "29", catalog, gcpPlatformJSON(t, ref, `{"kind":"metadata"}`, ``)))
	if err != nil {
		t.Fatal(err)
	}
	live, ok := sources["inventory/live"]
	if !ok || len(sources) != 1 {
		t.Fatalf("sources: %+v", sources)
	}
	wantArgv := []string{"adapter-gcp-asset", "--parents=projects/example-project-1,projects/example-project-2",
		"--asset-types=compute.googleapis.com/Instance,storage.googleapis.com/Bucket", "--content-types=RESOURCE",
		"--credentials=" + cfg.platforms[0].credentials["live"], "--token-source=metadata"}
	if !reflect.DeepEqual(live.argv, wantArgv) || live.shape != "http" || live.user != "engine-docs" || live.binding != ref || !live.notRetained ||
		live.gcpAsset == nil || live.gcpAsset.tokenSource != "metadata" || live.gcpAsset.retained || live.tokenStep {
		t.Fatalf("the source: %+v", live)
	}
	if live.sandbox == nil || live.sandbox.source != "inventory/live" {
		t.Fatalf("the source sandbox wraps the gcp-asset source: %+v", live.sandbox)
	}
	_, sources, err = load(t, engineAt(t, "29", catalog, gcpPlatformJSON(t, ref, `{"kind":"key"}`, `,"artifact":"retained"`)))
	if err != nil {
		t.Fatal(err)
	}
	if live := sources["inventory/live"]; live.notRetained || !live.gcpAsset.retained || live.gcpAsset.tokenSource != "key" {
		t.Fatalf("artifact retained, by key: %+v", live)
	}
	_, sources, err = load(t, engineAt(t, "29", catalog, gcpPlatformJSON(t, ref, `{"kind":"metadata"}`, `,"artifact":"not-retained"`)))
	if err != nil || !sources["inventory/live"].notRetained {
		t.Fatalf("artifact not-retained, as written: %v", err)
	}
}

// What a gcp-asset platform may not carry, and what only it may: the
// shape before version 29; write: true; no token source, or one of
// another kind, form or place; a token step, a grant, an endpoint; the
// sealed token's variable in its environment; and, on another shape's
// platform, a token source or artifact "retained".
func TestEngineRefusesWhatAGCPAssetPlatformWouldNotUse(t *testing.T) {
	catalog := catalogWith(t, map[string]string{"inventory": inventoryBinding, "records": recordsBinding})
	ref := "inventory@" + digestOf(inventoryBinding)
	records := "records@" + digestOf(recordsBinding)
	stateDir := abs(t, t.TempDir(), "custody")
	metadata := `{"kind":"metadata"}`
	recordsWith := func(credentials, extra string) string {
		return `"records":{"binding":"` + records + `","credentials":{` + credentials + `},"user":"engine-docs"` + extra + `}`
	}
	liveFile := `"file":"` + abs(t, t.TempDir(), "live.json") + `"`
	for _, c := range []struct{ name, text, want string }{
		{"the shape at version 28", engineAt(t, "28", catalog, gcpPlatformJSON(t, ref, "", ``)), "a version-29 shape; engineVersion 28 has none"},
		{"a token source at version 28", engineAt(t, "28", catalog, gcpPlatformJSON(t, ref, metadata, ``)), "tokenSource is a version-29 member"},
		{"write: true", engineAt(t, "29", catalog, gcpPlatformJSON(t, ref, metadata, `,"write":true`)), "write: true"},
		{"no token source", engineAt(t, "29", catalog, gcpPlatformJSON(t, ref, "", ``)), "credentials.live names no tokenSource"},
		{"federation", engineAt(t, "29", catalog, gcpPlatformJSON(t, ref, `{"kind":"federation"}`, ``)), `kind is "metadata"`},
		{"a token source with another member", engineAt(t, "29", catalog, gcpPlatformJSON(t, ref, `{"kind":"key","scopes":["x"]}`, ``)), `unknown member "scopes"`},
		{"a token source a string", engineAt(t, "29", catalog, gcpPlatformJSON(t, ref, `"metadata"`, ``)), "tokenSource"},
		{"a grant", engineAt(t, "29", catalog, gcpPlatformJSON(t, ref, metadata, `,"grant":{"provider":"notion","connection":"inventory","stateDir":"`+stateDir+`","principal":"operator","user":"engine-desk"}`)), "grant"},
		{"an endpoint", engineAt(t, "29", catalog, gcpPlatformJSON(t, ref, metadata, `,"endpoint":"inventory.internal"`)), "names an endpoint"},
		{"the sealed token's variable", engineAt(t, "29", catalog, gcpPlatformJSON(t, ref, metadata, `,"environment":{"ADAPTER_GCP_ASSET_SEALED_TOKEN":"x"}`)), "environment may not set ADAPTER_GCP_ASSET_SEALED_TOKEN"},
		{"artifact retained at version 28", engineAt(t, "28", catalog, recordsWith(`"live":{`+liveFile+`}`, `,"artifact":"retained"`)), `artifact must be the string "not-retained", the one value it has`},
		{"artifact retained on an http platform", engineAt(t, "29", catalog, recordsWith(`"live":{`+liveFile+`}`, `,"artifact":"retained"`)), `artifact "retained" keeps the payloads`},
		{"a token source on an http platform", engineAt(t, "29", catalog, recordsWith(`"live":{`+liveFile+`,"tokenSource":{"kind":"key"}}`, ``)), "is not of the gcp-asset shape, which alone takes one"},
		{"a token source for history", engineAt(t, "29", catalog, recordsWith(`"history":{`+liveFile+`,"tokenSource":{"kind":"key"}}`, ``)), "a token source is a live operation's of the gcp-asset shape alone"},
	} {
		if _, _, err := load(t, c.text); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: want %q, got %v", c.name, c.want, err)
		}
	}
}

// A request is held to the source's form and configuration before any
// token is obtained for it, the parent first: a parent not configured is
// refused by name, quoted, whatever else the request gets wrong.
func TestGCPAssetAdmits(t *testing.T) {
	op := gcpAssetOperation{parents: []string{"projects/example-project-1", "projects/example-project-2"},
		assetTypes: []string{"compute.googleapis.com/Instance", "storage.googleapis.com/Bucket"}, contentTypes: []string{"RESOURCE"}}
	const good = `"parent":"projects/example-project-2","contentType":"RESOURCE","assetTypes":["storage.googleapis.com/Bucket"]`
	for _, ok := range []string{`{` + good + `}`, `{` + good + `,"pageToken":"Cg5wYWdlLXRva2VuLTE","pageSize":1000,"readTime":"2026-11-16T10:00:00Z"}`, `{` + good + `,"pageToken":null}`} {
		if err := gcpAssetAdmits("inventory/live", op, []byte(ok)); err != nil {
			t.Errorf("%s: %v", ok, err)
		}
	}
	for _, c := range []struct{ name, text, want string }{
		{"a parent not configured", `{"parent":"projects/other-project-9","contentType":"RESOURCE","assetTypes":["storage.googleapis.com/Bucket"]}`, `parent-not-configured: "projects/other-project-9" is not a parent this source serves; no token was requested`},
		{"a parent not configured, before the rest", `{"parent":"folders/123","contentType":"IAM_POLICY","assetTypes":[]}`, `parent-not-configured: "folders/123"`},
		{"not JSON", `{`, "not one JSON value"},
		{"not an object", `[]`, "not an object"},
		{"an unknown member", `{` + good + `,"filter":"x"}`, `unknown member "filter"`},
		{"no parent", `{"contentType":"RESOURCE","assetTypes":["storage.googleapis.com/Bucket"]}`, `missing member "parent"`},
		{"a content type not served", `{"parent":"projects/example-project-1","contentType":"IAM_POLICY","assetTypes":["storage.googleapis.com/Bucket"]}`, "contentType is not one this source serves"},
		{"no asset type", `{"parent":"projects/example-project-1","contentType":"RESOURCE","assetTypes":[]}`, "assetTypes must be an array of 1 to 32 strings"},
		{"an asset type not served", `{"parent":"projects/example-project-1","contentType":"RESOURCE","assetTypes":["sqladmin.googleapis.com/Instance"]}`, "assetTypes[0] is not one this source serves"},
		{"an asset type twice", `{"parent":"projects/example-project-1","contentType":"RESOURCE","assetTypes":["storage.googleapis.com/Bucket","storage.googleapis.com/Bucket"]}`, "assetTypes[1] repeats"},
		{"a page token with a space", `{` + good + `,"pageToken":"a b"}`, "pageToken must be null or a string"},
		{"a page token past its bound", `{` + good + `,"pageToken":"` + strings.Repeat("a", maxGCPAssetPageToken+1) + `"}`, "pageToken must be null or a string"},
		{"a page size of none", `{` + good + `,"pageSize":0}`, "pageSize must be an integer from 1 to 1000"},
		{"a page size past its bound", `{` + good + `,"pageSize":1001}`, "pageSize must be an integer from 1 to 1000"},
		{"a read time of another form", `{` + good + `,"readTime":"yesterday"}`, "readTime must be an RFC 3339 timestamp"},
	} {
		err := gcpAssetAdmits("inventory/live", op, []byte(c.text))
		if err == nil || !strings.Contains(err.Error(), c.want) || !strings.Contains(err.Error(), "no token was requested") {
			t.Errorf("%s: want %q, got %v", c.name, c.want, err)
		}
	}
}

// The report beside status 9 is read strictly, and anything out of its
// form -- empty, missing a member, past its bound, padded, of another
// reason -- is a refusal all the same, of no stated reason, never a pass.
func TestReadOnlyRefusalReport(t *testing.T) {
	for _, c := range []struct {
		text string
		want readOnlyRefusal
	}{
		{`{"refused":{"reason":"credential-can-write","subject":"compute.instances.delete"}}`, readOnlyRefusal{reason: refusalCredentialCanWrite, subject: "compute.instances.delete"}},
		{`{"refused":{"reason":"credential-can-write","subject":null}}`, readOnlyRefusal{reason: refusalCredentialCanWrite}},
		{`{"refused":{"reason":"credential-scope-unknown","subject":null}}`, readOnlyRefusal{reason: refusalCredentialScope}},
		{`{"refused":{"reason":"credential-bound-at-resource","subject":"//storage.googleapis.com/example-bucket"}}`, readOnlyRefusal{reason: refusalCredentialBoundAtRsrc, subject: "//storage.googleapis.com/example-bucket"}},
	} {
		if got := readOnlyRefusalReport([]byte(c.text)); got != c.want {
			t.Errorf("%s: got %+v", c.text, got)
		}
	}
	for name, text := range map[string]string{
		"empty":                    ``,
		"not JSON":                 `{"refused":`,
		"no refused member":        `{}`,
		"an empty refusal":         `{"refused":{}}`,
		"no subject":               `{"refused":{"reason":"credential-can-write"}}`,
		"another member":           `{"refused":{"reason":"credential-can-write","subject":null,"token":"x"}}`,
		"a member beside refused":  `{"refused":{"reason":"credential-can-write","subject":null},"ok":true}`,
		"another reason":           `{"refused":{"reason":"credential-fine","subject":null}}`,
		"a reason not a string":    `{"refused":{"reason":9,"subject":null}}`,
		"an empty subject":         `{"refused":{"reason":"credential-can-write","subject":""}}`,
		"a subject not ASCII":      `{"refused":{"reason":"credential-can-write","subject":"é"}}`,
		"a subject past its bound": `{"refused":{"reason":"credential-can-write","subject":"` + strings.Repeat("a", maxRefusalSubject+1) + `"}}`,
		"a report past its bound":  `{"refused":{"reason":"credential-can-write","subject":null}}` + strings.Repeat(" ", maxRefusalReport),
		"padded":                   ` {"refused":{"reason":"credential-can-write","subject":null}}`,
		"a trailing newline":       `{"refused":{"reason":"credential-can-write","subject":null}}` + "\n",
	} {
		got := readOnlyRefusalReport([]byte(text))
		if got.reason != "" || !strings.Contains(got.sentence(), "out of its form") {
			t.Errorf("%s: a report out of its form reads as %+v", name, got)
		}
	}
}

// TestGCPAssetStandIn stands in for adapter-gcp-asset in the service
// tests: a --token-only run, then a page run, each answering its own
// stdout and status, and recording which it was and whether it was handed
// a sealed token.
func TestGCPAssetStandIn(t *testing.T) {
	dir := os.Getenv("GCP_ASSET_STAND_IN_DIR")
	if dir == "" {
		return
	}
	run := "PAGE"
	if contains(os.Args, "--token-only") {
		run = "TOKEN"
	}
	io.ReadAll(os.Stdin)
	f, _ := os.OpenFile(filepath.Join(dir, "runs"), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	fmt.Fprintf(f, "%s:%t\n", run, os.Getenv(gcpAssetSealedTokenVariable) != "")
	f.Close()
	os.Stdout.WriteString(os.Getenv("GCP_ASSET_STAND_IN_" + run + "_OUT"))
	n, _ := strconv.Atoi(os.Getenv("GCP_ASSET_STAND_IN_" + run + "_EXIT"))
	os.Exit(n)
}

// gcpStandInSealed is the stand-in's sealed token: never kept, so every
// acquisition obtains one, which is the refresh's check.
const gcpStandInSealed = "c3RhbmQtaW4tc2VhbGVkLXRva2Vu"

// gcpStandIn is a gcp-asset source the stand-in answers for, recording in
// dir: its token run's and its page run's answers.
func gcpStandIn(dir string, op gcpAssetOperation, tokenOut string, tokenExit int, pageOut string, pageExit int) sourceSpec {
	return sourceSpec{argv: []string{os.Args[0], "-test.run=^TestGCPAssetStandIn$", "--"}, shape: "http", notRetained: true,
		gcpAsset: newGCPAssetSource(op, gcpAssetTokenMetadata, false),
		env: []string{"GCP_ASSET_STAND_IN_DIR=" + dir, "GCP_ASSET_STAND_IN_TOKEN_OUT=" + tokenOut, "GCP_ASSET_STAND_IN_TOKEN_EXIT=" + strconv.Itoa(tokenExit),
			"GCP_ASSET_STAND_IN_PAGE_OUT=" + pageOut, "GCP_ASSET_STAND_IN_PAGE_EXIT=" + strconv.Itoa(pageExit)}}
}

func gcpStandInRuns(dir string) []string { return standInLines(dir, "runs") }

const (
	gcpStandInToken     = `{"sealed":"` + gcpStandInSealed + `","expiresIn":null}`
	gcpStandInCanWrite  = `{"refused":{"reason":"credential-can-write","subject":"compute.instances.delete"}}`
	gcpStandInRequest   = `{"session":"drift-1","source":"inventory/live","arguments":{"parent":"projects/example-project-1","contentType":"RESOURCE","assetTypes":["compute.googleapis.com/Instance"]}}`
	gcpStandInElsewhere = `{"session":"drift-1","source":"inventory/live","arguments":{"parent":"projects/other-project-9","contentType":"RESOURCE","assetTypes":["compute.googleapis.com/Instance"]}}`
)

var gcpStandInOp = gcpAssetOperation{parents: []string{"projects/example-project-1", "projects/example-project-2"},
	assetTypes: []string{"compute.googleapis.com/Instance"}, contentTypes: []string{"RESOURCE"}}

// The read-only check and its closure, through the service: the start
// obtains a sealed token, which the adapter answers only after its check,
// and says the source's lines; a parent not configured is refused before
// any run; a refusal on a refresh closes the source, said once on the
// engine's stderr, and a closed source runs nothing after; a refusal on a
// page whose report is out of its form closes it all the same; and the
// sealed token is named nowhere.
func TestAGCPAssetRefusalClosesTheSource(t *testing.T) {
	service, server := testService(t)
	log := &tokenLog{}
	service.reportsOut = log
	dir := t.TempDir()
	service.sources = map[string]sourceSpec{"inventory/live": gcpStandIn(dir, gcpStandInOp, gcpStandInToken, 0, `{"refused":`, sourceExitRefused)}
	var said bytes.Buffer
	if err := service.gcpAssetStart(&said); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"start: source inventory/live: token source metadata", "write check passed on the 2 configured projects",
		`artifact "not-retained", the shape's default`, "resource-bindings: unchecked"} {
		if !strings.Contains(said.String(), want) {
			t.Errorf("the start does not say %q:\n%s", want, said.String())
		}
	}
	if runs := gcpStandInRuns(dir); !reflect.DeepEqual(runs, []string{"TOKEN:false"}) {
		t.Fatalf("the start's runs: %v", runs)
	}
	if lines := readOnlyCredentialsLines(service.sources); len(lines) != 1 || lines[0].state != posturePartial {
		t.Fatalf("the posture line: %+v", lines)
	}
	if p := readOnlySourcePostures(service.sources); len(p) != 1 || p[0].state != "serving" || p[0].writeCheck != "passed" || p[0].refusal != nil {
		t.Fatalf("serving: %+v", p)
	}
	if p := hostPosture(postureInput{configured: true, sources: service.sources, reach: &scopeReach{}}).readOnly; len(p) != 0 {
		t.Fatalf("a reach that takes no unscoped source lists it: %+v", p)
	}

	// A parent not configured: no token run and no page run.
	got := postRaw(t, server.URL, "/acquire", gcpStandInElsewhere)
	if got.code == http.StatusOK || !strings.Contains(got.body, "parent-not-configured") {
		t.Fatalf("a parent not configured: %d %s", got.code, got.body)
	}
	if runs := gcpStandInRuns(dir); len(runs) != 1 {
		t.Fatalf("a parent not configured ran the source: %v", runs)
	}

	// A page refused with a report out of its form closes the source.
	got = postRaw(t, server.URL, "/acquire", gcpStandInRequest)
	if got.code == http.StatusOK || !strings.Contains(got.body, "is closed") || !strings.Contains(got.body, "out of its form") {
		t.Fatalf("a page refused: %d %s", got.code, got.body)
	}
	if runs := gcpStandInRuns(dir); !reflect.DeepEqual(runs, []string{"TOKEN:false", "TOKEN:false", "PAGE:true"}) {
		t.Fatalf("the refresh and the page: %v", runs)
	}
	got = postRaw(t, server.URL, "/acquire", gcpStandInRequest)
	if got.code == http.StatusOK || !strings.Contains(got.body, "is closed") {
		t.Fatalf("a closed source served: %d %s", got.code, got.body)
	}
	if runs := gcpStandInRuns(dir); len(runs) != 3 {
		t.Fatalf("a closed source ran: %v", runs)
	}
	requireNothingKept(t, service, "drift-1")
	service.reports.flush(5 * time.Second)
	if !strings.Contains(log.String(), "serve: source inventory/live closed on a page") || strings.Count(log.String(), "closed on a") != 1 {
		t.Fatalf("the closure is not said once:\n%s", log.String())
	}
	p := readOnlySourcePostures(service.sources)
	if len(p) != 1 || p[0].state != "closed" || p[0].refusal == nil || p[0].refusal.reason != "" || p[0].refusal.on != "page" ||
		!strings.Contains(p[0].text(), "refusal=unstated on page") {
		t.Fatalf("closed on a page: %+v", p)
	}
	if lines := readOnlyCredentialsLines(service.sources); !strings.HasSuffix(lines[0].reason, "; 1 of them closed") {
		t.Fatalf("the posture line counts no closure: %+v", lines)
	}
	for _, text := range []string{said.String(), got.body, log.String(), p[0].text()} {
		if strings.Contains(text, gcpStandInSealed) {
			t.Fatalf("the sealed token is named: %s", text)
		}
	}

	// A refusal on a refresh: the write check found a write permission on
	// the token obtained after the start's, and the page never runs.
	dir = t.TempDir()
	service.sources = map[string]sourceSpec{"inventory/live": gcpStandIn(dir, gcpStandInOp, gcpStandInToken, 0, `{}`, 0)}
	if err := service.gcpAssetStart(io.Discard); err != nil {
		t.Fatal(err)
	}
	spec := service.sources["inventory/live"]
	spec.env = gcpStandIn(dir, gcpStandInOp, gcpStandInCanWrite, sourceExitRefused, `{}`, 0).env
	service.sources["inventory/live"] = spec
	got = postRaw(t, server.URL, "/acquire", gcpStandInRequest)
	if got.code == http.StatusOK || !strings.Contains(got.body, `credential-can-write: the credential holds \"compute.instances.delete\"`) {
		t.Fatalf("a refusal on a refresh: %d %s", got.code, got.body)
	}
	if runs := gcpStandInRuns(dir); !reflect.DeepEqual(runs, []string{"TOKEN:false", "TOKEN:false"}) {
		t.Fatalf("a refusal on a refresh ran the page: %v", runs)
	}
	service.reports.flush(5 * time.Second)
	if !strings.Contains(log.String(), "serve: source inventory/live closed on a refresh: credential-can-write") {
		t.Fatalf("the refresh's closure is not said:\n%s", log.String())
	}
	if p := readOnlySourcePostures(service.sources); p[0].state != "closed" || p[0].writeCheck != "refused" || p[0].refusal.on != "refresh" {
		t.Fatalf("closed on a refresh: %+v", p)
	}
}

// The start refuses to serve a source whose check refused, or did not
// complete; a refusal closes it, a check that did not complete leaves it
// not started.
func TestTheStartRefusesAGCPAssetSourceNotShownReadOnly(t *testing.T) {
	service, _ := testService(t)
	dir := t.TempDir()
	service.sources = map[string]sourceSpec{"inventory/live": gcpStandIn(dir, gcpStandInOp, `{"refused":{"reason":"credential-scope-unknown","subject":null}}`, sourceExitRefused, ``, 0)}
	err := service.gcpAssetStart(io.Discard)
	if err == nil || !strings.Contains(err.Error(), "credential-scope-unknown") || !strings.Contains(err.Error(), "does not start") {
		t.Fatalf("a scope refused at the start: %v", err)
	}
	if p := readOnlySourcePostures(service.sources); p[0].state != "closed" || p[0].refusal.on != "start" || p[0].writeCheck != "refused" {
		t.Fatalf("closed at the start: %+v", p)
	}
	service.sources = map[string]sourceSpec{"inventory/live": gcpStandIn(dir, gcpStandInOp, `{"sealed":`, 1, ``, 0)}
	err = service.gcpAssetStart(io.Discard)
	if err == nil || !strings.Contains(err.Error(), "the read-only check did not complete") {
		t.Fatalf("a check that did not complete: %v", err)
	}
	if p := readOnlySourcePostures(service.sources); p[0].state != "not-started" || p[0].refusal != nil {
		t.Fatalf("not started: %+v", p)
	}
}

// handedTimeout is the --timeout= word's value on argv, wherever it is:
// the stand-in's command line carries the adapter's flags after "--".
func handedTimeout(argv []string) string {
	for _, arg := range argv {
		if value, ok := strings.CutPrefix(arg, "--timeout="); ok {
			return value
		}
	}
	return ""
}

// The adapter is handed the time left on the acquisition, less a margin
// for its start and its report, as --timeout: on its token run and on its
// page run. A check that time ended before it completed is the adapter's
// status 1, not 9: it fails that refresh and the acquisition, closes
// nothing, and the next acquisition obtains a token, and checks, again.
func TestAGCPAssetCheckTheTimeEndedClosesNothing(t *testing.T) {
	service, server := testService(t)
	dir := t.TempDir()
	service.sources = map[string]sourceSpec{"inventory/live": gcpStandIn(dir, gcpStandInOp, gcpStandInToken, 0, `{}`, 0)}
	if err := service.gcpAssetStart(io.Discard); err != nil {
		t.Fatal(err)
	}
	handed := func(run string) time.Duration {
		t.Helper()
		argv := service.startedWith.Load()
		if argv == nil || contains(*argv, "--token-only") != (run == "token") {
			t.Fatalf("the %s run's command line: %v", run, argv)
		}
		d, err := time.ParseDuration(handedTimeout(*argv))
		if err != nil {
			t.Fatalf("the %s run is handed no --timeout: %q", run, *argv)
		}
		return d
	}
	if d := handed("token"); d <= defaultSourceTimeout-gcpAssetRunMargin-2*time.Second || d > defaultSourceTimeout-gcpAssetRunMargin {
		t.Fatalf("the start's token run is handed %v of the %v source timeout", d, defaultSourceTimeout)
	}

	// The token run reports a check it could not complete: status 1.
	spec := service.sources["inventory/live"]
	spec.env = gcpStandIn(dir, gcpStandInOp, ``, 1, `{}`, 0).env
	service.sources["inventory/live"] = spec
	got := postRaw(t, server.URL, "/acquire", gcpStandInRequest)
	if got.code == http.StatusOK || strings.Contains(got.body, "is closed") || strings.Contains(got.body, refusalCredentialCanWrite) {
		t.Fatalf("a refresh whose check did not complete: %d %s", got.code, got.body)
	}
	if runs := gcpStandInRuns(dir); !reflect.DeepEqual(runs, []string{"TOKEN:false", "TOKEN:false"}) {
		t.Fatalf("the page ran on a token that was not obtained: %v", runs)
	}
	if p := readOnlySourcePostures(service.sources); p[0].state != "serving" || p[0].refusal != nil {
		t.Fatalf("a check that did not complete closed the source: %+v", p)
	}

	// The next acquisition asks for a token again, and its page runs.
	spec.env = gcpStandIn(dir, gcpStandInOp, gcpStandInToken, 0, `{}`, 0).env
	service.sources["inventory/live"] = spec
	postRaw(t, server.URL, "/acquire", gcpStandInRequest)
	if runs := gcpStandInRuns(dir); !reflect.DeepEqual(runs, []string{"TOKEN:false", "TOKEN:false", "TOKEN:false", "PAGE:true"}) {
		t.Fatalf("the source served nothing after a check that did not complete: %v", runs)
	}
	if d := handed("page"); d <= 0 || d > defaultSourceTimeout-gcpAssetRunMargin {
		t.Fatalf("the page run is handed %v", d)
	}
}

// gcpAssetTimed hands the adapter what is left of the acquisition's time,
// less the margin, or half of what is left where that is less.
func TestGCPAssetTimed(t *testing.T) {
	spec := sourceSpec{argv: []string{"adapter-gcp-asset", "--parents=projects/example-project-1"}}
	timed := gcpAssetTimed(context.Background(), 30*time.Second, spec)
	if !reflect.DeepEqual(timed.argv, []string{"adapter-gcp-asset", "--parents=projects/example-project-1", "--timeout=25s"}) || len(spec.argv) != 2 {
		t.Fatalf("no deadline: %q, the spec's own: %q", timed.argv, spec.argv)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	d, err := time.ParseDuration(handedTimeout(gcpAssetTimed(ctx, 30*time.Second, spec).argv))
	if err != nil || d > 2*time.Second || d < time.Second {
		t.Fatalf("four seconds left: %v %v", d, err)
	}
}

// postureLinesOf are the lines of the protection in the report served to a
// caller of the reach, nil the installation's, as hostPosture judges it.
func postureLinesOf(sources map[string]sourceSpec, reach *scopeReach, protection string) []postureLine {
	var lines []postureLine
	for _, l := range hostPosture(postureInput{configured: true, sources: sources, reach: reach}).lines {
		if l.name == protection {
			lines = append(lines, l)
		}
	}
	return lines
}

// The posture line is of the sources the caller reaches (ADR-0041): its
// state and every count, the closed among them, so a source of a scope the
// caller does not reach, closed or held less, changes none of it; a caller
// reaching no read-only source is given no line; and what "checked" covers
// is said with it.
func TestReadOnlyCredentialsCountsTheClosedTheCallerReaches(t *testing.T) {
	iamOp := gcpStandInOp
	iamOp.contentTypes = []string{"RESOURCE", "IAM_POLICY"}
	closed := newGCPAssetSource(iamOp, gcpAssetTokenMetadata, false)
	closed.closed = &readOnlyRefusal{reason: refusalCredentialCanWrite, on: "refresh"}
	sources := map[string]sourceSpec{
		"a/live":  {shape: "http", scope: "scope-a", gcpAsset: closed},
		"b/live":  {shape: "http", scope: "scope-b", gcpAsset: newGCPAssetSource(gcpStandInOp, gcpAssetTokenMetadata, false)},
		"b/iam":   {shape: "http", scope: "scope-b", gcpAsset: newGCPAssetSource(iamOp, gcpAssetTokenMetadata, false)},
		"b/other": {shape: "http", scope: "scope-b", gcpAsset: newGCPAssetSource(gcpStandInOp, gcpAssetTokenMetadata, false)},
	}
	for _, c := range []struct {
		name  string
		reach *scopeReach
		state string
		want  string
	}{
		{"every source", nil, posturePartial, "2 of the 4 read-only sources this caller reaches serve IAM_POLICY"},
		{"scope A's caller", &scopeReach{ids: map[string]bool{"scope-a": true}}, postureEnforced, "1 of the 1 read-only sources this caller reaches serve IAM_POLICY"},
		{"scope B's caller", &scopeReach{ids: map[string]bool{"scope-b": true}}, posturePartial, "1 of the 3 read-only sources this caller reaches serve IAM_POLICY"},
	} {
		closedWant := "; 0 of them closed"
		if c.reach == nil || c.reach.ids["scope-a"] {
			closedWant = "; 1 of them closed"
		}
		lines := postureLinesOf(sources, c.reach, protectionReadOnlyCredentials)
		if len(lines) != 1 || lines[0].state != c.state || !strings.Contains(lines[0].reason, c.want) ||
			!strings.HasSuffix(lines[0].reason, closedWant) || !strings.Contains(lines[0].reason, "not a grant through a group") {
			t.Errorf("%s: %+v", c.name, lines)
		}
	}
	if lines := postureLinesOf(sources, &scopeReach{ids: map[string]bool{"scope-c": true}}, protectionReadOnlyCredentials); lines != nil {
		t.Errorf("a caller reaching no read-only source: %+v", lines)
	}
	if s := (readOnlyRefusal{reason: refusalCredentialBoundAtRsrc, subject: "//storage.googleapis.com/b"}).sentence(); !strings.Contains(s, "or allUsers or allAuthenticatedUsers") {
		t.Fatalf("the refusal's sentence: %s", s)
	}
}
