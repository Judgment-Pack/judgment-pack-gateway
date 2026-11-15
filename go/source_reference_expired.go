package main

// An expired reference (gateway #461, SPEC.md §6, "Adapter sources"): an
// adapter of the http shape whose source's endpoint answered 410 -- the
// cursor, change token or other reference the request sent is no longer
// held -- exits with sourceExitReferenceExpired and reports, on stdout
// beside the status, that class and nothing else. /acquire answers its
// caller 410 with the code sourceReferenceExpiredCode and the gateway's own
// sentence: nothing of the endpoint's answer, and nothing of the adapter's
// stderr, reaches the caller. It follows the throttled answer
// (source_throttled.go, ADR-0029) in every other respect: any other exit,
// a report out of its form, and the report from a source of another shape
// or from a token step's token request, are a failed source as before.

import (
	"net/http"
)

// sourceExitReferenceExpired is the exit status an expired reference is
// reported by (adapters/httpsource, ReferenceExpiredStatus).
const sourceExitReferenceExpired = 8

// sourceReferenceExpiredCode is the code /acquire's answer carries beside
// its sentence, which a caller acts on by reading again from its first
// value rather than from the reference it kept.
const sourceReferenceExpiredCode = "source_reference_expired"

// sourceReferenceExpired is an acquisition whose source reported that its
// endpoint answered 410. failed is the failure the same run is said as
// where the report is not read (a token step's token request).
type sourceReferenceExpired struct {
	failed error
}

// Error is the one sentence for the class: it begins as every failure of a
// source's own does ("source failed: "), and names nothing the source said.
func (e *sourceReferenceExpired) Error() string {
	return "source failed: the source's endpoint answered 410 Gone: the reference the request sent has expired; nothing was retained or minted"
}

// referenceExpiredReport reads an http adapter's stdout beside
// sourceExitReferenceExpired: exactly {"referenceExpired": {"status":
// 410}}, each member once, its integer spelled in digits alone (no sign),
// and nothing before or after the value, whitespace included. Anything
// else is not a report, and false.
func referenceExpiredReport(stdout []byte) bool {
	if len(stdout) == 0 || isJSONSpace(stdout[0]) || isJSONSpace(stdout[len(stdout)-1]) {
		return false
	}
	v, err := (&parser{data: stdout, unsigned: true}).document()
	if err != nil {
		return false
	}
	outer, ok := v.(*vObject)
	if !ok || exactlyMembers(outer, map[string]bool{"referenceExpired": true}, "reference report") != nil {
		return false
	}
	raw, _ := outer.get("referenceExpired")
	report, ok := raw.(*vObject)
	if !ok || exactlyMembers(report, map[string]bool{"status": true}, "reference report") != nil {
		return false
	}
	rawStatus, _ := report.get("status")
	status, ok := rawStatus.(vInt)
	return ok && status == http.StatusGone
}
