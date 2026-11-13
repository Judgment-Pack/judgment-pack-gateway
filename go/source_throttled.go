package main

// A throttled source (gateway #425, SPEC.md §6, "Adapter sources"): an
// adapter of the http shape whose endpoint -- the source's, or its token
// step's -- answered 429 or 503 exits with sourceExitThrottled and reports,
// on stdout beside the status, the class and the wait the endpoint asked
// for, in whole seconds and bounded. /acquire answers its caller with that
// class, the gateway's own sentence and, when a wait was reported, a
// Retry-After the gateway writes from the number: nothing else of the
// endpoint's answer, and nothing of the adapter's stderr, reaches the
// caller. Any other exit, of this status or another, and a report out of
// its form, are a failed source as before.

import (
	"fmt"
	"net/http"
)

// sourceExitThrottled is the exit status a throttled answer is reported by
// (adapters/httpsource, ThrottledStatus).
const sourceExitThrottled = 7

// maxRetryAfter is the longest wait, in seconds, a report may carry
// (adapters/httpsource, MaxRetryAfter).
const maxRetryAfter = 3600

// sourceThrottled is an acquisition whose source reported a throttled
// answer: status 429 or 503, and the wait in seconds, -1 when none.
type sourceThrottled struct {
	status     int
	retryAfter int
}

// Error is the one sentence for the class: it begins as every failure of a
// source's own does ("source failed: "), and names nothing the source said.
func (e *sourceThrottled) Error() string {
	return fmt.Sprintf("source failed: the source's endpoint answered %d %s; nothing was retained or minted", e.status, http.StatusText(e.status))
}

// throttleReport reads an http adapter's stdout beside sourceExitThrottled:
// exactly {"throttled": {"status": 429 | 503, "retryAfter": 0 to 3600 |
// null}}, each member once. Anything else is not a report, and false.
func throttleReport(stdout []byte) (*sourceThrottled, bool) {
	v, err := parseJSON(stdout)
	if err != nil {
		return nil, false
	}
	outer, ok := v.(*vObject)
	if !ok || exactlyMembers(outer, map[string]bool{"throttled": true}, "throttle report") != nil {
		return nil, false
	}
	raw, _ := outer.get("throttled")
	report, ok := raw.(*vObject)
	if !ok || exactlyMembers(report, map[string]bool{"status": true, "retryAfter": true}, "throttle report") != nil {
		return nil, false
	}
	rawStatus, _ := report.get("status")
	status, ok := rawStatus.(vInt)
	if !ok || (status != http.StatusTooManyRequests && status != http.StatusServiceUnavailable) {
		return nil, false
	}
	out := &sourceThrottled{status: int(status), retryAfter: -1}
	rawWait, _ := report.get("retryAfter")
	switch wait := rawWait.(type) {
	case vNull:
	case vInt:
		if wait < 0 || wait > maxRetryAfter {
			return nil, false
		}
		out.retryAfter = int(wait)
	default:
		return nil, false
	}
	return out, true
}
