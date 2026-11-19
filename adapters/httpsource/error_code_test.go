package httpsource

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strconv"
	"strings"
	"testing"
)

// testCodes is a declaration of the form the microsoft-graph binding makes
// (ADR-0047): the code at error.code, two pairs of 400, one access code.
var testCodes = &ErrorCodes{At: []string{"error", "code"},
	Expired: []ExpiredPair{{400, "syncStateNotFound"}, {400, "resyncRequired"}},
	Access:  []string{"Authorization_RequestDenied"}}

// errorBody is an endpoint's error object of the code given, padded with
// a message to n bytes when n is larger than it.
func errorBody(code string, n int) string {
	body := `{"error":{"code":"` + code + `","message":"secret-token-value refused"}}`
	if n > len(body) {
		body = `{"error":{"code":"` + code + `","message":"secret-token-value refused` + strings.Repeat(" ", n-len(body)) + `"}}`
	}
	return body
}

// An answer of 401 or 403 from the source's endpoint is an AccessRefused
// answer of its status, carrying the endpoint's code only when the binding
// lists it, and "unlisted" for every other body: a code not listed, a body
// past the bound, one not JSON, without the code, with a code of another
// type or form, repeating the member, or with nothing declared. The
// diagnostic is the one any refusing answer has, redacted; the report
// carries nothing of the body.
func TestAnAccessRefusalCarriesOnlyAListedCode(t *testing.T) {
	var status int
	var body string
	e := newEndpoint(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		io.WriteString(w, body)
	})
	for _, c := range []struct {
		name   string
		status int
		body   string
		codes  *ErrorCodes
		want   string
	}{
		{"a listed code", 403, errorBody("Authorization_RequestDenied", 0), testCodes, "Authorization_RequestDenied"},
		{"a 401", 401, errorBody("Authorization_RequestDenied", 0), testCodes, "Authorization_RequestDenied"},
		{"at the bound", 403, errorBody("Authorization_RequestDenied", MaxErrorBody), testCodes, "Authorization_RequestDenied"},
		{"past the bound", 403, errorBody("Authorization_RequestDenied", MaxErrorBody+1), testCodes, UnlistedCode},
		{"an unlisted code", 403, errorBody("codeNotDeclared", 0), testCodes, UnlistedCode},
		{"not JSON", 403, `Authorization_RequestDenied`, testCodes, UnlistedCode},
		{"no code", 403, `{"error":{"message":"Authorization_RequestDenied"}}`, testCodes, UnlistedCode},
		{"no error object", 403, `{"code":"Authorization_RequestDenied"}`, testCodes, UnlistedCode},
		{"a number", 403, `{"error":{"code":403}}`, testCodes, UnlistedCode},
		{"an object", 403, `{"error":{"code":{"value":"Authorization_RequestDenied"}}}`, testCodes, UnlistedCode},
		{"a code of another form", 403, `{"error":{"code":"Authorization RequestDenied"}}`, testCodes, UnlistedCode},
		{"a repeated member", 403, `{"error":{"code":"codeNotDeclared","code":"Authorization_RequestDenied"}}`, testCodes, UnlistedCode},
		{"a repeated member written with an escape", 403, `{"error":{"code":"codeNotDeclared","\u0063ode":"Authorization_RequestDenied"}}`, testCodes, UnlistedCode},
		{"a value after it", 403, errorBody("Authorization_RequestDenied", 0) + `{}`, testCodes, UnlistedCode},
		{"nothing declared", 403, errorBody("Authorization_RequestDenied", 0), nil, UnlistedCode},
		{"no access list", 403, errorBody("Authorization_RequestDenied", 0), &ErrorCodes{At: testCodes.At, Expired: testCodes.Expired}, UnlistedCode},
	} {
		status, body = c.status, c.body
		cfg := e.config(t)
		cfg.ErrorCodes = c.codes
		_, err := Acquire(context.Background(), cfg, parseRequest(t, `{"path":"/search","body":{}}`))
		var refused *AccessRefused
		if !errors.As(err, &refused) || refused.Status != c.status || refused.Code != c.want {
			t.Fatalf("%s: %#v", c.name, err)
		}
		if !strings.Contains(err.Error(), "the endpoint answered") || strings.Contains(err.Error(), "secret-token") {
			t.Fatalf("%s: the diagnostic: %v", c.name, err)
		}
		report := string(refused.Report())
		if report != `{"accessRefused":{"code":"`+c.want+`","status":`+strconv.Itoa(c.status)+`}}` || strings.Contains(report, "secret") {
			t.Fatalf("%s: the report: %s", c.name, report)
		}
	}
	// Every other refusing answer is what it was.
	for _, other := range []int{400, 404, 409, 500} {
		status, body = other, errorBody("Authorization_RequestDenied", 0)
		cfg := e.config(t)
		cfg.ErrorCodes = testCodes
		_, err := Acquire(context.Background(), cfg, parseRequest(t, `{"path":"/search","body":{}}`))
		var refused *AccessRefused
		var expired *ReferenceExpired
		if err == nil || errors.As(err, &refused) || errors.As(err, &expired) {
			t.Fatalf("%d: %#v", other, err)
		}
	}
}

// A status and code pair the binding declares is an expired reference,
// reported with the pair; the same code beside an undeclared status, an
// undeclared code, and a body past the bound or not JSON are a refusing
// answer as before.
func TestADeclaredPairIsAnExpiredReference(t *testing.T) {
	var status int
	var body string
	e := newEndpoint(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(status)
		io.WriteString(w, body)
	})
	for _, c := range []struct {
		name    string
		status  int
		body    string
		codes   *ErrorCodes
		expired string
	}{
		{"a declared pair", 400, errorBody("syncStateNotFound", 0), testCodes, "syncStateNotFound"},
		{"the other declared pair", 400, errorBody("resyncRequired", 0), testCodes, "resyncRequired"},
		{"an undeclared status", 404, errorBody("syncStateNotFound", 0), testCodes, ""},
		{"an undeclared code", 400, errorBody("codeNotDeclared", 0), testCodes, ""},
		{"past the bound", 400, errorBody("syncStateNotFound", MaxErrorBody+1), testCodes, ""},
		{"not JSON", 400, `syncStateNotFound`, testCodes, ""},
		{"a code of another type", 400, `{"error":{"code":["syncStateNotFound"]}}`, testCodes, ""},
		{"nothing declared", 400, errorBody("syncStateNotFound", 0), nil, ""},
	} {
		status, body = c.status, c.body
		cfg := e.config(t)
		cfg.ErrorCodes = c.codes
		_, err := Acquire(context.Background(), cfg, parseRequest(t, `{"path":"/search","body":{}}`))
		var expired *ReferenceExpired
		if err == nil || errors.As(err, &expired) != (c.expired != "") || strings.Contains(err.Error(), "secret-token") {
			t.Fatalf("%s: %#v", c.name, err)
		}
		if c.expired != "" && (expired.Status != c.status || expired.Code != c.expired ||
			string(expired.Report()) != `{"referenceExpired":{"code":"`+c.expired+`","status":400}}`) {
			t.Fatalf("%s: %+v %s", c.name, expired, expired.Report())
		}
	}
}

// Under a token step, the endpoint's 401 is the token refused, whatever
// its body, and its 403 an access refusal with the token kept; the token
// endpoint's own 401 is a refused token request. None reads a code.
func TestATokenStepKeepsItsOwnRefusals(t *testing.T) {
	_, ecKey := testKeys(t)
	s := newTokenStub(t, &ecKey.PublicKey)
	var status int
	source := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(status)
		io.WriteString(w, errorBody("Authorization_RequestDenied", 0))
	}))
	defer source.Close()
	cfg := s.tokenConfig(t, pkcs8PEM(t, ecKey))
	cfg.Endpoint, cfg.ErrorCodes = source.URL, testCodes
	request := parseRequest(t, `{"path":"/read","method":"GET"}`)
	status = http.StatusUnauthorized
	_, err := Acquire(context.Background(), cfg, request)
	var refused *AccessRefused
	if failureKind(err) != TokenRejectedBySource || errors.As(err, &refused) {
		t.Fatalf("the endpoint's 401 under a token step: %#v", err)
	}
	status = http.StatusForbidden
	if _, err := Acquire(context.Background(), cfg, request); !errors.As(err, &refused) || refused.Code != "Authorization_RequestDenied" {
		t.Fatalf("the endpoint's 403 under a token step: %#v", err)
	}
	s.answer = func(w http.ResponseWriter) {
		w.WriteHeader(http.StatusUnauthorized)
		io.WriteString(w, errorBody("Authorization_RequestDenied", 0))
	}
	if _, err := ObtainSealed(context.Background(), cfg); failureKind(err) != TokenRefused || errors.As(err, &refused) {
		t.Fatalf("the token endpoint's 401: %#v", err)
	}
}

// The flags are held to the lists' bounds and forms before any request,
// and a refusal repeats no value.
func TestParseErrorCodesHoldsTheListsToTheirBounds(t *testing.T) {
	got, err := ParseErrorCodes("error.code", "400:syncStateNotFound,400:resyncRequired", "Authorization_RequestDenied")
	if err != nil || !reflect.DeepEqual(got, testCodes) {
		t.Fatalf("the declaration: %+v %v", got, err)
	}
	if got, err := ParseErrorCodes("", "", ""); got != nil || err != nil {
		t.Fatalf("no declaration: %+v %v", got, err)
	}
	long := strings.Repeat("a", MaxErrorCode+1)
	list := func(n int, item string) string { return strings.TrimSuffix(strings.Repeat(item+",", n), ",") }
	for _, c := range [][3]string{
		{"error.code", "", ""},
		{"", "", "a"},
		{"", "400:a", ""},
		{"a.b.c.d.e", "", "x"},
		{"error..code", "", "x"},
		{long, "", "x"},
		{"error.code", "", list(MaxAccessCodes+1, "x")},
		{"error.code", "", "x,x"},
		{"error.code", "", "unlisted"},
		{"error.code", "", long},
		{"error.code", "", "a b"},
		{"error.code", "", "a:b"},
		{"error.code", "", "x,"},
		{"error.code", list(MaxExpiredPairs+1, "400:a"), ""},
		{"error.code", "400:a,400:a", ""},
		{"error.code", "401:a", ""},
		{"error.code", "403:a", ""},
		{"error.code", "410:a", ""},
		{"error.code", "429:a", ""},
		{"error.code", "500:a", ""},
		{"error.code", "+400:a", ""},
		{"error.code", "0400:a", ""},
		{"error.code", "400:", ""},
		{"error.code", "400", ""},
		{"error.code", "400:unlisted", ""},
		{"error.code", "400:" + long, ""},
	} {
		if got, err := ParseErrorCodes(c[0], c[1], c[2]); err == nil || got != nil || strings.Contains(err.Error(), long) {
			t.Errorf("%q: %+v %v", c, got, err)
		}
	}
}

// A refusing answer past the output bound is still said by its status, not
// by the bound: a 403 is an access refusal with no code read from its cut
// bytes, a 410 an expired reference. A success past the bound is refused.
func TestARefusalPastTheOutputBoundKeepsItsClass(t *testing.T) {
	var status int
	e := newEndpoint(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		// Cut at the bound, the first bytes are one JSON value naming a
		// listed code; whole, a second value follows it. No code is read.
		io.WriteString(w, `{"error":{"code":"Authorization_RequestDenied"}}`+strings.Repeat(" ", 3000)+`{}`)
	})
	cfg := e.config(t)
	cfg.MaxOutput = 2048
	cfg.ErrorCodes = testCodes
	status = 403
	_, err := Acquire(context.Background(), cfg, parseRequest(t, `{"path":"/search","body":{}}`))
	var refused *AccessRefused
	if !errors.As(err, &refused) || refused.Status != 403 || refused.Code != UnlistedCode || strings.Contains(err.Error(), "output bound") {
		t.Fatalf("a 403 past the bound: %#v", err)
	}
	status = 410
	_, err = Acquire(context.Background(), cfg, parseRequest(t, `{"path":"/search","body":{}}`))
	var expired *ReferenceExpired
	if !errors.As(err, &expired) {
		t.Fatalf("a 410 past the bound: %#v", err)
	}
	status = 200
	_, err = Acquire(context.Background(), cfg, parseRequest(t, `{"path":"/search","body":{}}`))
	if err == nil || !strings.Contains(err.Error(), "exceeds the output bound of 2048 bytes") {
		t.Fatalf("a success past the bound: %v", err)
	}
}

// Every success past the output bound is refused for its size, never cut
// and minted: 200 and every other 2xx.
func TestEverySuccessPastTheOutputBoundIsRefused(t *testing.T) {
	var status int
	e := newEndpoint(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		io.WriteString(w, `{"a":1}`+strings.Repeat(" ", 3000)+`{}`)
	})
	cfg := e.config(t)
	cfg.MaxOutput = 2048
	for _, status = range []int{200, 201, 203, 206, 299} {
		out, err := Acquire(context.Background(), cfg, parseRequest(t, `{"path":"/search","body":{}}`))
		if err == nil || !strings.Contains(err.Error(), "exceeds the output bound") {
			t.Errorf("status %d past the bound: minted %d bytes, err=%v", status, len(out), err)
		}
	}
}

// A declared expired pair is not read from bytes the output bound cut: the
// answer stays a refusing answer of its status, not an expired reference.
func TestNoExpiredPairIsReadFromCutBytes(t *testing.T) {
	e := newEndpoint(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(testCodes.Expired[0].Status)
		io.WriteString(w, `{"error":{"code":"`+testCodes.Expired[0].Code+`"}}`+strings.Repeat(" ", 3000)+`{}`)
	})
	cfg := e.config(t)
	cfg.MaxOutput = 2048
	cfg.ErrorCodes = testCodes
	_, err := Acquire(context.Background(), cfg, parseRequest(t, `{"path":"/search","body":{}}`))
	var expired *ReferenceExpired
	if err == nil || errors.As(err, &expired) {
		t.Fatalf("a declared pair read from the cut bytes: %#v", err)
	}
}

// A refusing answer cut at a small output bound is said as cut, and no part
// of a credential at the cut reaches the diagnostic.
func TestACutRefusalKeepsAPartialCredentialOut(t *testing.T) {
	e := newEndpoint(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(403)
		io.WriteString(w, strings.Repeat("a", 100-12)+"secret-token-value"+strings.Repeat("b", 100))
	})
	cfg := e.config(t)
	cfg.MaxOutput = 100
	_, err := Acquire(context.Background(), cfg, parseRequest(t, `{"path":"/search","body":{}}`))
	if err == nil {
		t.Fatal("a refusing answer past the bound was taken")
	}
	if msg := err.Error(); strings.Contains(msg, "secret-tok") {
		t.Fatalf("a partial credential at the cut reaches the diagnostic: %q", msg)
	}
}
