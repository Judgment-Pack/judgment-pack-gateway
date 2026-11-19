package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
)

// fixtureHost is the host the fixtures' links name; the test serves them
// under its own loopback endpoint.
const fixtureHost = "https://graph.example.com"

// The synthetic answers of testdata/microsoft-graph-streams, served by the
// stand-in directory of graph_binding_e2e_test.go and read through the
// shipped catalog binding unchanged and the real adapter-http: each stream
// is read to its second page by the next link its first page names, and the
// bytes of each page are the file's; a delta round ends in its delta link;
// and the four cases the files carry are answered as the gateway answers
// them today.
func TestGraphStreamsFixturesAreReadThroughTheShippedBinding(t *testing.T) {
	read := func(name string) []byte {
		t.Helper()
		b, err := os.ReadFile(filepath.Join("..", "testdata", "microsoft-graph-streams", name))
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	streams := []struct {
		name, path string
		top        bool
	}{
		{"users-delta", "/v1.0/users/delta", false},
		{"groups-delta", "/v1.0/groups/delta", false},
		{"group-members", "/v1.0/groups/00000000-0000-4000-8000-0000000000aa/members", true},
		{"role-assignments", "/v1.0/roleManagement/directory/roleAssignments", true},
		{"role-definitions", "/v1.0/roleManagement/directory/roleDefinitions", true},
		{"oauth2-permission-grants", "/v1.0/oauth2PermissionGrants", true},
		{"service-principals", "/v1.0/servicePrincipals", true},
		{"sign-ins", "/v1.0/auditLogs/signIns", true},
		{"directory-audits", "/v1.0/auditLogs/directoryAudits", true},
		{"risk-detections", "/v1.0/identityProtection/riskDetections", true},
		{"risky-users", "/v1.0/identityProtection/riskyUsers", true},
		{"user-registration-details", "/v1.0/reports/authenticationMethods/userRegistrationDetails", true},
		{"devices", "/v1.0/devices", true},
		{"organization", "/v1.0/organization", false},
	}
	// routes: request URI as the directory receives it -> the file it answers
	// with; a file's status and headers, when it has them, are in its .status.
	routes := map[string]string{}
	for _, s := range streams {
		uri := s.path
		if s.top {
			uri += "?$top=2"
		}
		var page struct {
			Next string `json:"@odata.nextLink"`
		}
		if err := json.Unmarshal(read(s.name+".1.json"), &page); err != nil || !strings.HasPrefix(page.Next, fixtureHost+s.path) {
			t.Fatalf("%s: first page's next link %q: %v", s.name, page.Next, err)
		}
		routes[uri], routes[strings.TrimPrefix(page.Next, fixtureHost)] = s.name+".1.json", s.name+".2.json"
	}
	const expiredURI = "/v1.0/users/delta?$deltatoken=users-delta-expired"
	const throttledURI = "/v1.0/auditLogs/signIns?$top=2&$skiptoken=sign-ins-page-3"
	routes[expiredURI], routes[throttledURI] = "delta-expired.json", "throttled.json"
	routes["/v1.0/identityProtection/riskDetections?$top=1"] = "unlicensed.json"
	routes["/v1.0/oauth2PermissionGrants?$top=1"] = "oauth2-permission-grants.empty.json"

	api := &graphAPI{serve: func(w http.ResponseWriter, r *http.Request, origin string) {
		file, ok := routes[r.RequestURI]
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		status := http.StatusOK
		if st, err := os.ReadFile(filepath.Join("..", "testdata", "microsoft-graph-streams", strings.TrimSuffix(file, ".json")+".status")); err == nil {
			lines := strings.Split(strings.TrimSpace(string(st)), "\n")
			status, _ = strconv.Atoi(lines[0])
			for _, l := range lines[1:] {
				k, v, _ := strings.Cut(l, ": ")
				w.Header().Set(k, v)
			}
		}
		w.WriteHeader(status)
		w.Write([]byte(strings.ReplaceAll(string(read(file)), fixtureHost, origin)))
	}}
	server, graph, _, _ := graphGateway(t, api)

	// want is the file as served: the fixture host replaced by the endpoint.
	want := func(file string) any {
		var v any
		if err := json.Unmarshal([]byte(strings.ReplaceAll(string(read(file)), fixtureHost, graph.URL)), &v); err != nil {
			t.Fatal(err)
		}
		return v
	}
	acquire := func(session, arguments string) map[string]any {
		t.Helper()
		code, out := post(t, server, "/acquire", `{"session":"`+session+`","source":"directory/live","arguments":`+arguments+`}`)
		if code != http.StatusOK {
			t.Fatalf("%s: %d %v", arguments, code, out)
		}
		return out
	}
	body := func(out map[string]any) map[string]any {
		return out["result"].(map[string]any)["body"].(map[string]any)
	}

	for _, s := range streams {
		args := fmt.Sprintf(`{"path":%q,"method":"GET"}`, s.path)
		if s.top {
			args = fmt.Sprintf(`{"path":%q,"method":"GET","query":{"$top":"2"}}`, s.path)
		}
		first := body(acquire("gs-"+s.name, args))
		if !reflect.DeepEqual(first, want(s.name+".1.json")) {
			t.Fatalf("%s page 1: %v", s.name, first)
		}
		second := body(acquire("gs-"+s.name, fmt.Sprintf(`{"link":%q,"method":"GET"}`, first["@odata.nextLink"])))
		if !reflect.DeepEqual(second, want(s.name+".2.json")) {
			t.Fatalf("%s page 2: %v", s.name, second)
		}
		delta, hasDelta := second["@odata.deltaLink"].(string)
		if _, hasNext := second["@odata.nextLink"]; hasNext || hasDelta != strings.HasSuffix(s.name, "-delta") ||
			hasDelta && !strings.HasPrefix(delta, graph.URL+s.path+"?$deltatoken=") {
			t.Fatalf("%s page 2 ends the stream: next %v, delta %q", s.name, hasNext, delta)
		}
	}

	// 410: the expired delta token is the class, the sentence and the code of
	// source_reference_expired; nothing of the endpoint's answer.
	expired := postRaw(t, server.URL, "/acquire", fmt.Sprintf(`{"session":"gs-410","source":"directory/live","arguments":{"link":%q,"method":"GET"}}`, graph.URL+expiredURI))
	if expired.code != http.StatusGone || !strings.Contains(expired.body, `"code":"`+sourceReferenceExpiredCode+`"`) ||
		strings.Contains(expired.body, "syncStateNotFound") || strings.Contains(expired.body, "users-delta-expired") {
		t.Fatalf("an expired delta token: %d %s", expired.code, expired.body)
	}
	// 429: the throttled class (ADR-0029): the gateway's sentence, and the
	// wait the endpoint named written from the number.
	throttled := postRaw(t, server.URL, "/acquire", fmt.Sprintf(`{"session":"gs-429","source":"directory/live","arguments":{"link":%q,"method":"GET"}}`, graph.URL+throttledURI))
	if throttled.code != http.StatusTooManyRequests || throttled.header.Get("Retry-After") != "7" || !strings.Contains(throttled.body, (&sourceThrottled{status: 429}).Error()) ||
		strings.Contains(throttled.body, "TooManyRequests") {
		t.Fatalf("a throttled read: %d %v %s", throttled.code, throttled.header, throttled.body)
	}
	// 403: as the code does today -- not a passed-through answer and not
	// receipted: any status but 2xx is a failed source (400, one sentence,
	// no receipt), and that sentence carries the endpoint's own excerpt.
	unlicensed := postRaw(t, server.URL, "/acquire", `{"session":"gs-403","source":"directory/live","arguments":{"path":"/v1.0/identityProtection/riskDetections","method":"GET","query":{"$top":"1"}}}`)
	if unlicensed.code != http.StatusBadRequest || !strings.Contains(unlicensed.body, "the endpoint answered 403 Forbidden") ||
		!strings.Contains(unlicensed.body, "does not hold a licence") || strings.Contains(unlicensed.body, `"receipt"`) {
		t.Fatalf("an unlicensed read: %d %s", unlicensed.code, unlicensed.body)
	}
	// A present-but-empty stream is an answer: 200, an empty value, receipted.
	empty := acquire("gs-empty", `{"path":"/v1.0/oauth2PermissionGrants","method":"GET","query":{"$top":"1"}}`)
	result, receipt := empty["result"].(map[string]any), empty["receipt"].(map[string]any)
	if v, ok := body(empty)["value"].([]any); !ok || len(v) != 0 || result["status"] != float64(200) || receipt["kind"] != "acquisition" ||
		receipt["sessionId"] != "gs-empty" || receipt["resultDigest"] == nil || receipt["signature"] == nil {
		t.Fatalf("an empty stream: %v", empty)
	}
}
