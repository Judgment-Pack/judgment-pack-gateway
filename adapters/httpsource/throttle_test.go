package httpsource

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"
)

// Retry-After is taken as delta-seconds or an HTTP-date, in whole seconds
// from now, at most an hour; anything else, and a date not after now, is no
// wait.
func TestRetryAfterIsReadIntoBoundedSeconds(t *testing.T) {
	now := time.Date(2026, 11, 13, 12, 0, 0, 0, time.UTC)
	for _, c := range []struct {
		values []string
		want   int // -1 for nil
	}{
		{nil, -1},
		{[]string{"30"}, 30},
		{[]string{"0"}, 0},
		{[]string{"0030"}, 30},
		{[]string{" 30 "}, 30},
		{[]string{"3600"}, 3600},
		{[]string{"3601"}, 3600},
		{[]string{strings.Repeat("9", 400)}, 3600},
		{[]string{"-5"}, -1},
		{[]string{"+5"}, -1},
		{[]string{"1.5"}, -1},
		{[]string{"1e3"}, -1},
		{[]string{"soon"}, -1},
		{[]string{""}, -1},
		{[]string{"10, 20"}, -1},
		{[]string{"30", "30"}, -1},
		{[]string{"30", "40"}, -1},
		{[]string{"Fri, 13 Nov 2026 12:01:30 GMT"}, 90},
		{[]string{"Friday, 13-Nov-26 12:01:30 GMT"}, 90},
		{[]string{"Fri Nov 13 12:01:30 2026"}, 90},
		{[]string{"Fri, 13 Nov 2026 14:00:00 GMT"}, 3600},
		{[]string{"Fri, 13 Nov 2026 12:00:00 GMT"}, -1},
		{[]string{"Fri, 13 Nov 2026 11:59:59 GMT"}, -1},
		{[]string{"Fri, 13 Nov 2026 12:01:30 +0000"}, -1},
	} {
		got := RetryAfter(c.values, now)
		if (got == nil) != (c.want == -1) || (got != nil && *got != c.want) {
			t.Errorf("%q: %v, want %d", c.values, got, c.want)
		}
	}
	// A date is counted up to the next whole second.
	if got := RetryAfter([]string{"Fri, 13 Nov 2026 12:00:10 GMT"}, now.Add(500*time.Millisecond)); got == nil || *got != 10 {
		t.Errorf("a date 9.5 seconds away: %v", got)
	}
}

// An answer of 429 or 503 fails the acquisition as a Throttled answer of
// that class, with the wait it asked for and the diagnostic any refusing
// answer has, redacted; every other refusing answer is what it was.
func TestAcquireSaysAThrottledAnswerByItsKind(t *testing.T) {
	var status int
	var retryAfter string
	e := newEndpoint(t, func(w http.ResponseWriter, r *http.Request) {
		if retryAfter != "" {
			w.Header().Set("Retry-After", retryAfter)
		}
		w.WriteHeader(status)
		io.WriteString(w, "slow down, secret-token-value")
	})
	for _, c := range []struct {
		status     int
		retryAfter string
		wait       int // -1 for none, 0 for not throttled
	}{
		{429, "17", 17},
		{429, "", -1},
		{503, "4000", 3600},
		{503, "later", -1},
		{500, "17", 0},
		{502, "17", 0},
		{504, "17", 0},
		{401, "17", 0},
	} {
		status, retryAfter = c.status, c.retryAfter
		_, err := Acquire(context.Background(), e.config(t), parseRequest(t, `{"path":"/search","body":{}}`))
		var throttled *Throttled
		isThrottled := errors.As(err, &throttled)
		want := "the endpoint answered " + strconv.Itoa(c.status) + " " + http.StatusText(c.status)
		if err == nil || !strings.Contains(err.Error(), want) || !strings.Contains(err.Error(), "[redacted]") || strings.Contains(err.Error(), "secret-token") {
			t.Fatalf("%d: the diagnostic: %v", c.status, err)
		}
		switch {
		case c.wait == 0 && isThrottled:
			t.Fatalf("%d is said as throttled", c.status)
		case c.wait == 0:
		case !isThrottled || throttled.Status != c.status:
			t.Fatalf("%d: not said as throttled: %#v", c.status, err)
		case c.wait == -1 && throttled.RetryAfter != nil, c.wait > 0 && (throttled.RetryAfter == nil || *throttled.RetryAfter != c.wait):
			t.Fatalf("%d %q: wait %v", c.status, c.retryAfter, throttled.RetryAfter)
		}
	}
	seventeen := 17
	report := (&Throttled{Status: 429, RetryAfter: &seventeen}).Report()
	if string(report) != `{"throttled":{"retryAfter":17,"status":429}}` {
		t.Fatalf("the report: %s", report)
	}
	if report := (&Throttled{Status: 503}).Report(); string(report) != `{"throttled":{"retryAfter":null,"status":503}}` {
		t.Fatalf("the report with no wait: %s", report)
	}
}

// A token endpoint that answers 429 or 503 is a Throttled answer too, with
// the diagnostic the refused token request has; any other refusal is
// TokenRefused, as before.
func TestTokenStepSaysAThrottledTokenRequestByItsKind(t *testing.T) {
	_, ecKey := testKeys(t)
	key := pkcs8PEM(t, ecKey)
	for _, c := range []struct {
		status int
		wait   int // -1 for none, 0 for not throttled
	}{{429, 20}, {503, -1}, {500, 0}, {400, 0}} {
		s := newTokenStub(t, &ecKey.PublicKey)
		s.answer = func(w http.ResponseWriter) {
			if c.wait > 0 {
				w.Header().Set("Retry-After", "20")
			}
			w.WriteHeader(c.status)
			io.WriteString(w, `{"error":"temporarily_unavailable"}`)
		}
		_, err := ObtainSealed(context.Background(), s.tokenConfig(t, key))
		var throttled *Throttled
		if err == nil || !strings.Contains(err.Error(), "the token endpoint refused the token request (") || strings.Contains(err.Error(), "temporarily_unavailable") {
			t.Fatalf("%d: the diagnostic: %v", c.status, err)
		}
		switch {
		case c.wait == 0 && (errors.As(err, &throttled) || failureKind(err) != TokenRefused):
			t.Fatalf("%d: %#v", c.status, err)
		case c.wait != 0 && (!errors.As(err, &throttled) || throttled.Status != c.status || (c.wait == -1) != (throttled.RetryAfter == nil)):
			t.Fatalf("%d: %#v", c.status, err)
		}
	}
}
