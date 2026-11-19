package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"
)

// testErrorCodes is a declaration of the form the microsoft-graph binding
// makes (ADR-0047), synthetic in its pairs: the code at error.code, two
// pairs of 400, and one access code.
var testErrorCodes = &httpErrorCodes{at: []string{"error", "code"},
	expired: []httpExpiredPair{{400, "syncStateNotFound"}, {400, "resyncRequired"}},
	access:  []string{"Authorization_RequestDenied"}}

// The report beside an access refusal's status is read strictly, and its
// code is answered only when the source's binding lists it: a code the
// adapter reported that the gateway does not hold is "unlisted". A 401 is
// not read from a source with a token step, whose 401 is the token refused.
func TestAccessRefusedReportIsReadStrictly(t *testing.T) {
	for _, c := range []struct {
		report    string
		codes     *httpErrorCodes
		tokenStep bool
		status    int
		code      string
	}{
		{`{"accessRefused":{"code":"Authorization_RequestDenied","status":403}}`, testErrorCodes, false, 403, "Authorization_RequestDenied"},
		{`{"accessRefused":{"code":"Authorization_RequestDenied","status":401}}`, testErrorCodes, false, 401, "Authorization_RequestDenied"},
		{`{ "accessRefused": { "status": 403, "code": "unlisted" } }`, testErrorCodes, false, 403, "unlisted"},
		{`{"accessRefused":{"code":"codeNotDeclared","status":403}}`, testErrorCodes, false, 403, "unlisted"},
		{`{"accessRefused":{"code":"Authorization_RequestDenied","status":403}}`, nil, false, 403, "unlisted"},
		{`{"accessRefused":{"code":"Authorization_RequestDenied","status":403}}`, testErrorCodes, true, 403, "Authorization_RequestDenied"},
		{`{"accessRefused":{"code":"unlisted","status":401}}`, testErrorCodes, true, 0, ""},
		{`{"accessRefused":{"code":"unlisted","status":404}}`, testErrorCodes, false, 0, ""},
		{`{"accessRefused":{"code":"unlisted","status":"403"}}`, testErrorCodes, false, 0, ""},
		{`{"accessRefused":{"code":"unlisted","status":-403}}`, testErrorCodes, false, 0, ""},
		{`{"accessRefused":{"code":403,"status":403}}`, testErrorCodes, false, 0, ""},
		{`{"accessRefused":{"code":"the endpoint's own words","status":403}}`, testErrorCodes, false, 0, ""},
		{`{"accessRefused":{"code":"` + strings.Repeat("a", 65) + `","status":403}}`, testErrorCodes, false, 0, ""},
		{`{"accessRefused":{"status":403}}`, testErrorCodes, false, 0, ""},
		{`{"accessRefused":{"code":"unlisted","status":403,"body":"x"}}`, testErrorCodes, false, 0, ""},
		{`{"accessRefused":{"code":"unlisted","status":403},"error":"x"}`, testErrorCodes, false, 0, ""},
		{`{"accessRefused":{"code":"unlisted","status":403}}` + "\n", testErrorCodes, false, 0, ""},
		{`{"referenceExpired":{"status":410}}`, testErrorCodes, false, 0, ""},
		{``, testErrorCodes, false, 0, ""},
	} {
		got, ok := accessRefusedReport([]byte(c.report), c.codes, c.tokenStep)
		if ok != (c.status != 0) || ok && (got.status != c.status || got.code != c.code) {
			t.Errorf("%q (token step %v): %+v %v", c.report, c.tokenStep, got, ok)
		}
	}
	if class := sourceRefusalClass((&sourceAccessRefused{status: 403}).Error()); class != refusalSourceFailed {
		t.Errorf("an access refusal is classed %s", class)
	}
}

// /acquire answers an http adapter's access report 403, whatever the
// endpoint's status, with the code, the endpoint's status and the listed
// code or "unlisted", mints and keeps nothing, and leaves the session open.
// A report out of its form, the report beside another status, and the
// status from a source of another shape are a failed source, as before. A
// declared pair is answered 410 as an expired reference; an undeclared one
// is a failed source.
func TestAnAccessRefusalIsAnsweredWithItsCode(t *testing.T) {
	const failed = `{"error":"source failed: adapter-http: the endpoint answered 429 Too Many Requests: slow down, key k-7f2c"}`
	refused := func(status int, code string) string {
		return fmt.Sprintf(`{"code":"source_access_refused","endpointCode":%q,"endpointStatus":%d,"error":"source failed: the source's endpoint answered %d %s: it refused this read to the source's credential; nothing was retained or minted"}`, code, status, status, http.StatusText(status))
	}
	const pair = `{"code":"source_reference_expired","error":"source failed: the source's endpoint answered 400 Bad Request with an error code its binding declares an expired reference: the reference the request sent has expired; nothing was retained or minted"}`
	for _, c := range []struct {
		name, shape, out string
		codes            *httpErrorCodes
		exit, code       int
		body             string
	}{
		{"a listed code", "http", `{"accessRefused":{"code":"Authorization_RequestDenied","status":403}}`, testErrorCodes, 10, 403, refused(403, "Authorization_RequestDenied")},
		{"a 401", "http", `{"accessRefused":{"code":"Authorization_RequestDenied","status":401}}`, testErrorCodes, 10, 403, refused(401, "Authorization_RequestDenied")},
		{"a code the gateway does not hold", "http", `{"accessRefused":{"code":"codeNotDeclared","status":403}}`, testErrorCodes, 10, 403, refused(403, "unlisted")},
		{"no list", "http", `{"accessRefused":{"code":"Authorization_RequestDenied","status":403}}`, nil, 10, 403, refused(403, "unlisted")},
		{"another form", "http", `{"accessRefused":{"code":"unlisted","status":404}}`, testErrorCodes, 10, 400, failed},
		{"another status", "http", `{"accessRefused":{"code":"unlisted","status":403}}`, testErrorCodes, 1, 400, failed},
		{"another shape", "mcp", `{"accessRefused":{"code":"unlisted","status":403}}`, testErrorCodes, 10, 400, failed},
		{"a declared pair", "http", `{"referenceExpired":{"code":"resyncRequired","status":400}}`, testErrorCodes, 8, 410, pair},
		{"an undeclared pair", "http", `{"referenceExpired":{"code":"resyncRequired","status":404}}`, testErrorCodes, 8, 400, failed},
		{"a pair with no list", "http", `{"referenceExpired":{"code":"resyncRequired","status":400}}`, nil, 8, 400, failed},
	} {
		t.Run(c.name, func(t *testing.T) {
			service, server := testService(t)
			service.sources["refused"] = sourceSpec{argv: []string{os.Args[0], "-test.run=^TestThrottleStandIn$"}, shape: c.shape, errorCodes: c.codes,
				env: []string{"THROTTLE_STAND_IN=1", "THROTTLE_STAND_IN_OUT=" + c.out, fmt.Sprintf("THROTTLE_STAND_IN_EXIT=%d", c.exit)}}
			got := postRaw(t, server.URL, "/acquire", `{"session":"refused-1","source":"refused","arguments":{"path":"/r"}}`)
			if got.code != c.code || got.header.Get("Retry-After") != "" || got.body != c.body {
				t.Fatalf("%d Retry-After %q: %s", got.code, got.header.Values("Retry-After"), got.body)
			}
			requireNothingKept(t, service, "refused-1")
			service.sources["refused"] = sourceSpec{argv: []string{os.Args[0]}, env: helperEnv}
			if code, body := post(t, server, "/acquire", `{"session":"refused-1","source":"refused","arguments":{}}`); code != http.StatusOK || body["receipt"].(map[string]any)["callIndex"] != float64(0) {
				t.Fatalf("the read again: %d %v", code, body)
			}
		})
	}
}

// The report beside a token request's status is not read: a token request
// is not the source's read, and the run is a failed source as any other.
func TestAnAccessReportBesideATokenRequestIsNotRead(t *testing.T) {
	service, _ := testService(t)
	spec := standInSpec(t.TempDir(), `{"accessRefused":{"code":"unlisted","status":403}}`, sourceExitAccessRefused, "ok")
	if _, _, err := service.obtainToken(context.Background(), time.Minute, "records/live", spec); err == nil || err.Error() != "source failed: stand-in-stderr-4e1a" {
		t.Fatalf("the report beside a token request: %v", err)
	}
}

// errorCodes is held to its shape and bounds where the binding is parsed,
// each refusal naming the member by its place and repeating no value, and
// the engine hands it to adapter-http as one word per flag.
func TestHTTPErrorCodesAreHeldToTheirBounds(t *testing.T) {
	parse := func(text string) (*httpErrorCodes, error) {
		v, err := (&parser{data: []byte(text)}).document()
		if err != nil {
			t.Fatalf("%s: %v", text, err)
		}
		return parseHTTPErrorCodes(v, "live")
	}
	got, err := parse(`{"at":["error","code"],"referenceExpired":[{"status":400,"code":"syncStateNotFound"},{"status":400,"code":"resyncRequired"}],"accessRefused":["Authorization_RequestDenied"]}`)
	if err != nil || !reflect.DeepEqual(got, testErrorCodes) {
		t.Fatalf("the declaration: %+v %v", got, err)
	}
	if words := got.argv(); !reflect.DeepEqual(words, []string{"--error-code-at=error.code", "--expired-codes=400:syncStateNotFound,400:resyncRequired", "--access-codes=Authorization_RequestDenied"}) {
		t.Fatalf("the words: %q", words)
	}
	if words := (&httpErrorCodes{at: []string{"code"}, access: []string{"a"}}).argv(); !reflect.DeepEqual(words, []string{"--error-code-at=code", "--access-codes=a"}) {
		t.Fatalf("the words of one list: %q", words)
	}
	long := strings.Repeat("a", 65)
	many := func(n int, item string) string {
		items := make([]string, n)
		for i := range items {
			items[i] = fmt.Sprintf(item, i)
		}
		return strings.Join(items, ",")
	}
	for _, c := range []struct{ text, refusal string }{
		{`["error"]`, "errorCodes must be an object"},
		{`{"accessRefused":["a"]}`, "at"},
		{`{"at":[],"accessRefused":["a"]}`, "errorCodes.at must be"},
		{`{"at":["a","b","c","d","e"],"accessRefused":["a"]}`, "errorCodes.at must be"},
		{`{"at":["error.code"],"accessRefused":["a"]}`, "errorCodes.at[0]"},
		{`{"at":["` + long + `"],"accessRefused":["a"]}`, "errorCodes.at[0]"},
		{`{"at":["code"]}`, "names referenceExpired, accessRefused or both"},
		{`{"at":["code"],"accessRefused":["a"],"message":"x"}`, "message"},
		{`{"at":["code"],"accessRefused":[]}`, "errorCodes.accessRefused must be"},
		{`{"at":["code"],"accessRefused":[` + many(17, `"c%d"`) + `]}`, "errorCodes.accessRefused must be"},
		{`{"at":["code"],"accessRefused":["` + long + `"]}`, "errorCodes.accessRefused[0]"},
		{`{"at":["code"],"accessRefused":["a b"]}`, "errorCodes.accessRefused[0]"},
		{`{"at":["code"],"accessRefused":["a,b"]}`, "errorCodes.accessRefused[0]"},
		{`{"at":["code"],"accessRefused":["unlisted"]}`, "errorCodes.accessRefused[0]"},
		{`{"at":["code"],"accessRefused":["a","a"]}`, "errorCodes.accessRefused[1]"},
		{`{"at":["code"],"accessRefused":[7]}`, "errorCodes.accessRefused[0]"},
		{`{"at":["code"],"referenceExpired":[]}`, "errorCodes.referenceExpired must be"},
		{`{"at":["code"],"referenceExpired":[` + many(9, `{"status":400,"code":"c%d"}`) + `]}`, "errorCodes.referenceExpired must be"},
		{`{"at":["code"],"referenceExpired":[{"status":400}]}`, "errorCodes.referenceExpired[0] must be"},
		{`{"at":["code"],"referenceExpired":[{"status":400,"code":"a","body":"x"}]}`, "errorCodes.referenceExpired[0] must be"},
		{`{"at":["code"],"referenceExpired":[{"status":401,"code":"a"}]}`, "errorCodes.referenceExpired[0].status"},
		{`{"at":["code"],"referenceExpired":[{"status":403,"code":"a"}]}`, "errorCodes.referenceExpired[0].status"},
		{`{"at":["code"],"referenceExpired":[{"status":410,"code":"a"}]}`, "errorCodes.referenceExpired[0].status"},
		{`{"at":["code"],"referenceExpired":[{"status":429,"code":"a"}]}`, "errorCodes.referenceExpired[0].status"},
		{`{"at":["code"],"referenceExpired":[{"status":500,"code":"a"}]}`, "errorCodes.referenceExpired[0].status"},
		{`{"at":["code"],"referenceExpired":[{"status":399,"code":"a"}]}`, "errorCodes.referenceExpired[0].status"},
		{`{"at":["code"],"referenceExpired":[{"status":400,"code":"unlisted"}]}`, "errorCodes.referenceExpired[0].code"},
		{`{"at":["code"],"referenceExpired":[{"status":400,"code":"a:b"}]}`, "errorCodes.referenceExpired[0].code"},
		{`{"at":["code"],"referenceExpired":[{"status":400,"code":"a"},{"status":400,"code":"a"}]}`, "errorCodes.referenceExpired[1] repeats"},
	} {
		if _, err := parse(c.text); err == nil || !strings.Contains(err.Error(), c.refusal) || strings.Contains(err.Error(), long) {
			t.Errorf("%s: %v", c.text, err)
		}
	}
}
