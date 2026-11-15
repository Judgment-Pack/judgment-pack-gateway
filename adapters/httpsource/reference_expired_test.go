package httpsource

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"testing"
)

// An answer of 410 from the source's endpoint fails the acquisition as a
// ReferenceExpired answer, with the diagnostic any refusing answer has,
// redacted; a 404, a 400 and every other refusing answer are what they
// were. A token endpoint's 410 is a refused token request, as before.
func TestAcquireSaysAnExpiredReferenceByItsKind(t *testing.T) {
	var status int
	e := newEndpoint(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(status)
		io.WriteString(w, "cursor gone, secret-token-value")
	})
	for _, c := range []struct {
		status  int
		expired bool
	}{{410, true}, {404, false}, {400, false}, {409, false}, {412, false}} {
		status = c.status
		_, err := Acquire(context.Background(), e.config(t), parseRequest(t, `{"path":"/search","body":{}}`))
		var expired *ReferenceExpired
		want := "the endpoint answered " + strconv.Itoa(c.status) + " " + http.StatusText(c.status)
		if err == nil || !strings.Contains(err.Error(), want) || !strings.Contains(err.Error(), "[redacted]") || strings.Contains(err.Error(), "secret-token") {
			t.Fatalf("%d: the diagnostic: %v", c.status, err)
		}
		if errors.As(err, &expired) != c.expired {
			t.Fatalf("%d: said as an expired reference %v: %#v", c.status, !c.expired, err)
		}
	}
	if report := (&ReferenceExpired{}).Report(); string(report) != `{"referenceExpired":{"status":410}}` {
		t.Fatalf("the report: %s", report)
	}

	_, ecKey := testKeys(t)
	s := newTokenStub(t, &ecKey.PublicKey)
	s.answer = func(w http.ResponseWriter) {
		w.WriteHeader(http.StatusGone)
		io.WriteString(w, `{"error":"invalid_grant"}`)
	}
	_, err := ObtainSealed(context.Background(), s.tokenConfig(t, pkcs8PEM(t, ecKey)))
	var expired *ReferenceExpired
	if err == nil || errors.As(err, &expired) || failureKind(err) != TokenRefused {
		t.Fatalf("a token endpoint's 410: %#v", err)
	}
}
