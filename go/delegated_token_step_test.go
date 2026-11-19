package main

import (
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
)

// Every name and address here is invented (ADR-0045).
const (
	testDelegatedAccount = "directory-reader@example-project.iam.gserviceaccount.com"
	testDelegatedScopes  = "https://www.googleapis.com/auth/admin.directory.user.readonly https://www.googleapis.com/auth/admin.reports.audit.readonly"
)

// From delegatedTokenVersion a token step's assertion may be signed by the
// credentials API: signedBy, {"kind": "credentials-api", "serviceAccount":
// …}, with a fixed subject and requestScope, no clientId and no other
// credential, handed to adapter-http as those alone. Under an earlier
// version it is refused by name; out of form, beside another credential
// or a clientId, or asking a scope off the read-only list, it is refused,
// and a refusal repeats no value. A step of another form derives the
// source it derived before.
func TestTokenStepSignedByTheCredentialsAPI(t *testing.T) {
	catalog := catalogWith(t, map[string]string{"records": tokenBinding})
	ref := "records@" + digestOf(tokenBinding)
	adapters := `,"adapters":"` + abs(t, t.TempDir(), "bin") + `"`
	step := func(members string) string {
		return tokenPlatformJSON(t, "records", ref, "engine-docs", `,"tokenStep":{`+members+`}`, ``)
	}
	head := `"endpoint":"https://oauth.example/token"`
	signedBy := `"signedBy":{"kind":"credentials-api","serviceAccount":"` + testDelegatedAccount + `"}`
	subject := `"subject":"admin@example.com"`
	scope := `"requestScope":"` + testDelegatedScopes + `"`
	good := head + `,` + signedBy + `,` + subject + `,` + scope
	_, sources, err := load(t, atVersion(t, delegatedTokenVersion, catalog, adapters, step(good)))
	if err != nil {
		t.Fatal(err)
	}
	live := sources["records/live"]
	want := []string{"--token-endpoint=https://oauth.example/token", "--signed-by-service-account=" + testDelegatedAccount, "--token-subject=admin@example.com", "--token-scope=" + testDelegatedScopes}
	at := slices.Index(live.argv, want[0])
	if !live.tokenStep || at < 0 || at+4 > len(live.argv) || !reflect.DeepEqual(live.argv[at:at+4], want) || slices.ContainsFunc(live.argv, func(arg string) bool {
		return strings.HasPrefix(arg, "--client-id") || strings.HasPrefix(arg, "--assertion-") || strings.HasPrefix(arg, "--federated-token") || strings.HasPrefix(arg, "--bearer")
	}) {
		t.Fatalf("a credentials API token step: %q", live.argv)
	}
	keyed := step(`"endpoint":"https://login.example/token","clientId":"client-7","privateKey":"SIGNING_KEY"`)
	_, before, err := load(t, atVersion(t, metadataTokenVersion, catalog, adapters, keyed))
	if err != nil {
		t.Fatal(err)
	}
	_, after, err := load(t, atVersion(t, delegatedTokenVersion, catalog, adapters, keyed))
	if err != nil || !reflect.DeepEqual(before["records/live"], after["records/live"]) {
		t.Fatalf("a key step is derived as before: %v", err)
	}
	federated := abs(t, t.TempDir(), "federated.jwt")
	exactlyOne := "exactly one of privateKey, federatedTokenFile, federatedToken and signedBy is the assertion's credential"
	accountForm := "signedBy: serviceAccount is NAME@PROJECT.iam.gserviceaccount.com"
	subjectForm := "tokenStep: subject is an address of at most 254 bytes"
	scopeForm := "tokenStep: requestScope is one or more of the Admin SDK's read-only scopes ADR-0045 lists, each once"
	withAccount := func(account string) string {
		return step(head + `,"signedBy":{"kind":"credentials-api","serviceAccount":"` + account + `"},` + subject + `,` + scope)
	}
	withSubject := func(s string) string { return step(head + `,` + signedBy + `,"subject":"` + s + `",` + scope) }
	withScope := func(s string) string {
		return step(head + `,` + signedBy + `,` + subject + `,"requestScope":"` + s + `"`)
	}
	for _, c := range []struct{ name, version, platform, want string }{
		{"under the version before", metadataTokenVersion, step(good), "credentials.live.tokenStep.signedBy is a version-" + delegatedTokenVersion + " member; engineVersion " + metadataTokenVersion + " has no signedBy"},
		{"a subject under the version before", metadataTokenVersion, step(`"endpoint":"https://login.example/token","clientId":"client-7","privateKey":"K",` + subject), `tokenStep: unknown member "subject"`},
		{"none of the four", delegatedTokenVersion, step(`"endpoint":"https://login.example/token","clientId":"client-7"`), exactlyOne},
		{"beside privateKey", delegatedTokenVersion, step(good + `,"privateKey":"SIGNING_KEY"`), exactlyOne},
		{"beside federatedTokenFile", delegatedTokenVersion, step(good + `,"federatedTokenFile":"` + federated + `"`), exactlyOne},
		{"beside federatedToken", delegatedTokenVersion, step(good + `,"federatedToken":{"kind":"metadata","audience":"api://x"}`), exactlyOne},
		{"a clientId", delegatedTokenVersion, step(good + `,"clientId":"client-7"`), "tokenStep: clientId is not given beside signedBy"},
		{"a thumbprint", delegatedTokenVersion, step(good + `,"x5t":"AAAAAAAAAAAAAAAAAAAAAAAAAAA"`), `tokenStep: unknown member "x5t"`},
		{"a subject beside another form", delegatedTokenVersion, step(`"endpoint":"https://login.example/token","clientId":"client-7","privateKey":"K",` + subject), `tokenStep: unknown member "subject"`},
		{"no subject", delegatedTokenVersion, step(head + `,` + signedBy + `,` + scope), `tokenStep: missing member "subject"`},
		{"no requestScope", delegatedTokenVersion, step(head + `,` + signedBy + `,` + subject), `tokenStep: missing member "requestScope"`},
		{"an endpoint placeholder", delegatedTokenVersion, step(`"endpoint":"https://oauth.example/{realm}",` + signedBy + `,` + subject + `,` + scope), "tokenStep: endpoint must be"},
		{"another kind", delegatedTokenVersion, step(head + `,"signedBy":{"kind":"key","serviceAccount":"` + testDelegatedAccount + `"},` + subject + `,` + scope), `signedBy: kind is "credentials-api"`},
		{"an address beside the kind", delegatedTokenVersion, step(head + `,"signedBy":{"kind":"credentials-api","serviceAccount":"` + testDelegatedAccount + `","url":"https://10.0.0.1"},` + subject + `,` + scope), `signedBy: unknown member "url"`},
		{"an account with a slash", delegatedTokenVersion, withAccount("directory-reader/x@example-project.iam.gserviceaccount.com"), accountForm},
		{"an account with a colon", delegatedTokenVersion, withAccount("directory-reader@example.com:example-project.iam.gserviceaccount.com"), accountForm},
		{"an account percent-encoded", delegatedTokenVersion, withAccount("directory-reader%2F@example-project.iam.gserviceaccount.com"), accountForm},
		{"an account of another domain", delegatedTokenVersion, withAccount("directory-reader@example-project.iam.example.com"), accountForm},
		{"an uppercase account", delegatedTokenVersion, withAccount("Directory-reader@example-project.iam.gserviceaccount.com"), accountForm},
		{"a subject without @", delegatedTokenVersion, withSubject("admin.example.com"), subjectForm},
		{"a subject with a space", delegatedTokenVersion, withSubject("ad min@example.com"), subjectForm},
		{"a subject with a quote", delegatedTokenVersion, withSubject(`ad\"min@example.com`), subjectForm},
		{"a subject of 255 bytes", delegatedTokenVersion, withSubject("admin@" + strings.Repeat("a.", 124) + "com"), subjectForm},
		{"the security scope", delegatedTokenVersion, withScope("https://www.googleapis.com/auth/admin.directory.user.security"), scopeForm},
		{"a write scope", delegatedTokenVersion, withScope("https://www.googleapis.com/auth/admin.directory.group"), scopeForm},
		{"the platform scope", delegatedTokenVersion, withScope("https://www.googleapis.com/auth/cloud-platform"), scopeForm},
		{"a scope twice", delegatedTokenVersion, withScope("https://www.googleapis.com/auth/admin.reports.audit.readonly https://www.googleapis.com/auth/admin.reports.audit.readonly"), scopeForm},
		{"an empty scope", delegatedTokenVersion, withScope(""), scopeForm},
		{"two spaces", delegatedTokenVersion, withScope(strings.Replace(testDelegatedScopes, " ", "  ", 1)), scopeForm},
	} {
		_, _, err := load(t, atVersion(t, c.version, catalog, ``, c.platform))
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Fatalf("%s: want %q, got %v", c.name, c.want, err)
		}
		for _, value := range []string{"directory-reader", "admin@", "ad min", "admin.example", "cloud-platform", ".security", "10.0.0.1", `"key"`} {
			if strings.Contains(err.Error(), value) {
				t.Fatalf("%s: the refusal repeats %q: %v", c.name, value, err)
			}
		}
	}
}

// numericIDBinding is an http binding one of whose paths carries
// {numericId}.
const numericIDBinding = `{"bindingVersion":"1","platform":"postgres","operations":{"live":{"shape":"http","endpoint":"https://records.example","paths":["/users","/users/{numericId}"],"methods":["GET"],"bearer":"token","checkPath":"/users","licence":"MIT"}}}`

// A binding whose http paths carry {numericId} or {alnumId} is read from
// engine version 33: under an earlier version, 31 and 32 included, where
// {id} is read, it is refused at start by name.
func TestHTTPNumericAndAlnumPlaceholdersAreAVersion33Member(t *testing.T) {
	for _, binding := range []string{numericIDBinding, strings.Replace(numericIDBinding, "{numericId}", "{alnumId}", 1)} {
		ref := "postgres@" + digestOf(binding)
		name := "{numericId}"
		if strings.Contains(binding, "{alnumId}") {
			name = "{alnumId}"
		}
		catalog := catalogWith(t, map[string]string{"postgres": binding})
		platform := platformJSONFor(t, "directory", ref, "engine-docs", ``, "live")
		for _, version := range []string{"30", metadataTokenVersion} {
			want := "platform directory: binding " + ref + "'s live operation names a path template of " + name + ", paths[1], a version-33 member; engineVersion " + version + " has none"
			if _, _, err := load(t, atVersion(t, version, catalog, ``, platform)); err == nil || !strings.Contains(err.Error(), want) {
				t.Fatalf("%s under version %s: %v", name, version, err)
			}
		}
		if _, _, err := load(t, atVersion(t, delegatedTokenVersion, catalog, ``, platform)); err != nil {
			t.Fatal(err)
		}
	}
}

// The shipped Workspace bindings admit their read paths by GET alone, and
// a Workspace id only of its form: no address, no GUID in a numeric slot,
// no application off the list, no other method.
func TestWorkspaceBindingsAdmitOnlyTheirReadPaths(t *testing.T) {
	spec := func(name string) sourceSpec {
		data, err := os.ReadFile(filepath.Join("..", "catalog", name+".json"))
		if err != nil {
			t.Fatal(err)
		}
		b, err := parseBinding(data)
		if err != nil {
			t.Fatal(err)
		}
		return sourceSpec{requestEndpoint: b.live.http.endpoint, requestPaths: b.live.http.paths, requestMethods: b.live.http.methods}
	}
	directory, reports := spec("google-workspace-directory"), spec("google-workspace-reports")
	refused := fmt.Sprintf(errTokenRequestNotAdmitted, "workspace/live")
	for _, c := range []struct {
		spec    sourceSpec
		request string
		admit   bool
	}{
		{directory, `{"path":"/admin/directory/v1/users","query":{"customer":"my_customer","query":"email:alice@example.com"},"method":"GET"}`, true},
		{directory, `{"path":"/admin/directory/v1/users/115813357217846539498","method":"GET"}`, true},
		{directory, `{"path":"/admin/directory/v1/groups/03x8tuzt3kzz0ym/members","method":"GET"}`, true},
		{directory, `{"path":"/admin/directory/v1/groups","query":{"userKey":"alice@example.com"},"method":"GET"}`, true},
		{directory, `{"path":"/admin/directory/v1/customer/my_customer/roleassignments/9170516996784129","method":"GET"}`, true},
		{directory, `{"link":"https://admin.googleapis.com/admin/directory/v1/users?customer=my_customer&pageToken=p-2","method":"GET"}`, true},
		{directory, `{"path":"/admin/directory/v1/users/alice@example.com","method":"GET"}`, false},
		{directory, `{"path":"/admin/directory/v1/users/115813357217846539498","method":"POST"}`, false},
		{directory, `{"path":"/admin/directory/v1/users/115813357217846539498"}`, false},
		{directory, `{"path":"/admin/directory/v1/users/115813357217846539498","method":"DELETE"}`, false},
		{directory, `{"path":"/admin/directory/v1/users/115813357217846539498/tokens","method":"GET"}`, false},
		{directory, `{"path":"/admin/directory/v1/users/6a1f0c2e-4b7d-4e9a-8c3f-2d5e7b9a1c40","method":"GET"}`, false},
		{directory, `{"path":"/admin/directory/v1/groups/team@example.com/members","method":"GET"}`, false},
		{directory, `{"path":"/admin/directory/v1/groups/03X8tuzt3kzz0ym/members","method":"GET"}`, false},
		{directory, `{"path":"/admin/directory/v1/customer/my_customer/roles/ALL/privileges","method":"GET"}`, false},
		{directory, `{"path":"/admin/directory/v1/customers/my_customer","method":"GET"}`, false},
		{directory, `{"link":"https://admin.googleapis.com/admin/directory/v1/users/alice%40example.com","method":"GET"}`, false},
		{reports, `{"path":"/admin/reports/v1/activity/users/all/applications/login","query":{"startTime":"2026-11-01T00:00:00Z"},"method":"GET"}`, true},
		{reports, `{"path":"/admin/reports/v1/activity/users/all/applications/chat","method":"GET"}`, false},
		{reports, `{"path":"/admin/reports/v1/activity/users/alice@example.com/applications/login","method":"GET"}`, false},
		{reports, `{"path":"/admin/reports/v1/activity/users/all/applications/login/watch","method":"POST"}`, false},
		{reports, `{"path":"/admin/directory/v1/users","method":"GET"}`, false},
	} {
		err := tokenStepAdmits("workspace/live", c.spec, []byte(c.request))
		if c.admit && err != nil || !c.admit && (err == nil || err.Error() != refused) {
			t.Fatalf("%s: %v", c.request, err)
		}
	}
}
