package main

import (
	"adapters/connections"
	"errors"
	"strings"
	"testing"
)

// unread fails the test if the adapter reads its request: a start that is
// refused is refused before stdin.
type unread struct{ t *testing.T }

func (u unread) Read([]byte) (int, error) {
	u.t.Error("stdin was read")
	return 0, errors.New("stdin was read")
}

// The redirect policies are the command line's, read at start: an unknown or
// repeated one, or one given to discovery, refuses the start before the
// request is read; none, empty, or google-grounding go on to the request,
// which here names no URL and is refused without a network request.
func TestTheRedirectPoliciesAreReadAtStart(t *testing.T) {
	for _, value := range []string{"any-origin", "google-grounding,google-grounding", "google-grounding,"} {
		var stdout, stderr strings.Builder
		if code := run([]string{"--redirect-policies=" + value}, unread{t}, &stdout, &stderr); code != 2 || stdout.Len() != 0 || stderr.String() != connections.WebRedirectPolicyRefusal+"\n" {
			t.Errorf("%q: %d %q", value, code, stderr.String())
		}
	}
	for _, args := range [][]string{
		{"--redirect-policies=google-grounding", "--redirect-policies=google-grounding"},
		{"--discover", "--redirect-policies=google-grounding"},
		{"--discover", "--redirect-policies="},
		{"--redirect-policies"},
		{"--redirect-policy=google-grounding"},
		{"--discover", "--document-processing"},
	} {
		var stdout, stderr strings.Builder
		if code := run(args, unread{t}, &stdout, &stderr); code != 2 || stdout.Len() != 0 {
			t.Errorf("%v: %d", args, code)
		}
	}
	for _, args := range [][]string{nil, {"--redirect-policies="}, {"--redirect-policies=google-grounding"}, {"--document-processing", "--redirect-policies=google-grounding"}} {
		var stdout, stderr strings.Builder
		if code := run(args, strings.NewReader(`{}`), &stdout, &stderr); code != 1 || stderr.String() != "web-invalid-request\n" {
			t.Errorf("%v: %d %q", args, code, stderr.String())
		}
	}
}
