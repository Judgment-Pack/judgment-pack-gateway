package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// httpRequestCase is one request of the table the engine and adapter-http
// answer to (testdata/http-requests/cases.json).
type httpRequestCase struct {
	Rule      string          `json:"rule"`
	Request   json.RawMessage `json:"request"`
	Endpoint  string          `json:"endpoint"`
	Paths     []string        `json:"paths"`
	Methods   []string        `json:"methods"`
	PadLinkTo int             `json:"padLinkTo"`
	Path      *string         `json:"path"`
	RawQuery  *string         `json:"rawQuery"`
}

type httpRequestTable struct {
	About     []string          `json:"about"`
	Endpoint  string            `json:"endpoint"`
	Paths     []string          `json:"paths"`
	Methods   []string          `json:"methods"`
	Rules     []string          `json:"rules"`
	Accepted  []httpRequestCase `json:"accepted"`
	Refused   []httpRequestCase `json:"refused"`
	Templates struct {
		Accepted []string `json:"accepted"`
		Refused  []struct {
			Rule string `json:"rule"`
			Path string `json:"path"`
		} `json:"refused"`
	} `json:"templates"`
}

// spec is the token step's source the case is read under, and its
// request, the link extended to padLinkTo.
func (c httpRequestCase) spec(t *testing.T, table httpRequestTable) (sourceSpec, []byte) {
	t.Helper()
	spec := sourceSpec{requestEndpoint: table.Endpoint, requestPaths: table.Paths, requestMethods: table.Methods}
	if c.Endpoint != "" {
		spec.requestEndpoint = c.Endpoint
	}
	if c.Paths != nil {
		spec.requestPaths = c.Paths
	}
	if c.Methods != nil {
		spec.requestMethods = c.Methods
	}
	request := []byte(c.Request)
	if c.PadLinkTo > 0 {
		var members map[string]any
		if err := json.Unmarshal(c.Request, &members); err != nil {
			t.Fatal(err)
		}
		link := members["link"].(string)
		members["link"] = link + strings.Repeat("a", c.PadLinkTo-len(link))
		var err error
		if request, err = json.Marshal(members); err != nil {
			t.Fatal(err)
		}
	}
	return spec, request
}

// The table's requests, as a token step's source holds them before a
// token is obtained: an accepted one passes, a refused one is refused by
// the one fixed sentence; and the table's templates, as a binding's paths
// are held when the binding is loaded. adapter-http's own test reads the
// same table, so the two agree on every request in it.
func TestHTTPRequestsAreAdmittedAsTheTableSays(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "testdata", "http-requests", "cases.json"))
	if err != nil {
		t.Fatal(err)
	}
	var table httpRequestTable
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&table); err != nil {
		t.Fatal(err)
	}
	if len(table.Accepted) == 0 || len(table.Refused) == 0 || len(table.Templates.Accepted) == 0 || len(table.Templates.Refused) == 0 {
		t.Fatal("the table holds a case on each side")
	}
	refused := fmt.Sprintf(errTokenRequestNotAdmitted, "directory/live")
	for i, c := range table.Accepted {
		spec, request := c.spec(t, table)
		if err := tokenStepAdmits("directory/live", spec, request); err != nil {
			t.Errorf("accepted %d (%s): %s: %v", i, c.Rule, request, err)
		}
	}
	for i, c := range table.Refused {
		spec, request := c.spec(t, table)
		if err := tokenStepAdmits("directory/live", spec, request); err == nil || err.Error() != refused {
			t.Errorf("refused %d (%s): %s: %v", i, c.Rule, request, err)
		}
	}
	for _, path := range table.Templates.Accepted {
		if err := httpPathProblem(path); err != nil {
			t.Errorf("template %s: %v", path, err)
		}
	}
	for _, c := range table.Templates.Refused {
		if err := httpPathProblem(c.Path); err == nil {
			t.Errorf("template %s (%s) accepted", c.Path, c.Rule)
		}
	}
}

// templatedBinding is an http binding one of whose paths is a template.
const templatedBinding = `{"bindingVersion":"1","platform":"postgres","operations":{"live":{"shape":"http","endpoint":"https://records.example","paths":["/groups","/groups/{id}/members"],"methods":["GET"],"bearer":"token","checkPath":"/groups","licence":"MIT"}}}`

// A binding whose http paths carry a template is read from engine version
// 31: under an earlier version it is refused at start, by name, and
// connect writes no entry for it, since raising a file's version is the
// operator's change to make; a binding without one loads as before.
func TestHTTPPathTemplatesAreAVersion31Member(t *testing.T) {
	ref := "postgres@" + digestOf(templatedBinding)
	catalog := catalogWith(t, map[string]string{"postgres": templatedBinding})
	platform := platformJSONFor(t, "directory", ref, "engine-docs", ``, "live")
	if _, _, err := load(t, atVersion(t, "30", catalog, ``, platform)); err == nil ||
		!strings.Contains(err.Error(), "platform directory: binding "+ref+"'s live operation names a path template, paths[1], a version-31 member; engineVersion 30 has none") {
		t.Fatalf("a template under version 30: %v", err)
	}
	_, sources, err := load(t, atVersion(t, "31", catalog, ``, platform))
	if err != nil {
		t.Fatal(err)
	}
	if live := sources["directory/live"]; argumentValue(live.argv, "--paths=") != "/groups,/groups/{id}/members" || !reflect.DeepEqual(live.check, []string{"--check-path=/groups"}) {
		t.Fatalf("the template is handed to adapter-http as written: %+v", live)
	}
	fixed := strings.Replace(templatedBinding, `,"/groups/{id}/members"`, ``, 1)
	if _, _, err := load(t, atVersion(t, "30", catalogWith(t, map[string]string{"postgres": fixed}), ``, platformJSONFor(t, "directory", "postgres@"+digestOf(fixed), "engine-docs", ``, "live"))); err != nil {
		t.Fatalf("a binding with no template under version 30: %v", err)
	}

	f := newConnectFixture(t, templatedBinding, ``)
	f.reports["http"] = `{"check":{"status":"succeeded","adapter":{"name":"adapter-http","version":"0.31.0","digest":"` + testImageDigest + `"},"endpoint":"https://records.example","peerIdentity":"tls:sha256:ab","probe":{"path":"/groups","status":200}}}`
	req := f.request()
	req.credentials = map[string]string{"live": f.credentials}
	req.endpoint = ""
	before := f.fileText(t)
	if _, err := connect(context.Background(), req, f.host, f.check); err == nil || !strings.Contains(err.Error(), "a version-31 member; engineVersion 1 has none; raise engineVersion to \"31\" first") || len(f.asked) != 0 {
		t.Fatalf("connect of a template under version 1: %v, asked %d", err, len(f.asked))
	}
	if f.fileText(t) != before {
		t.Fatal("a refused connect wrote the file")
	}
	// A {numericId} template names its own version, 33, not {id}'s.
	numeric := strings.Replace(templatedBinding, `"/groups/{id}/members"`, `"/groups/{numericId}/members"`, 1)
	g := newConnectFixture(t, numeric, ``)
	g.reports["http"] = f.reports["http"]
	req = g.request()
	req.credentials = map[string]string{"live": g.credentials}
	req.endpoint = ""
	if _, err := connect(context.Background(), req, g.host, g.check); err == nil || !strings.Contains(err.Error(), "a path template of {numericId}, paths[1], a version-33 member; engineVersion 1 has none; raise engineVersion to \"33\" first") || len(g.asked) != 0 {
		t.Fatalf("connect of a {numericId} template under version 1: %v, asked %d", err, len(g.asked))
	}
}
