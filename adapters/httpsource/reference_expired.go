package httpsource

// An expired reference (gateway #461, SPEC.md §6, "Adapter sources"): the
// source's endpoint answered 410, the reference the request sent -- a
// cursor, a change token -- no longer held there. The command exits with
// ReferenceExpiredStatus and writes Report on stdout beside it: the class,
// and nothing else of the answer. Its stderr diagnostic is the one it wrote
// for that answer before the status existed, so a gateway that does not
// read the status reports the failure as it always did. A token endpoint's
// 410 is not one: a token request sends no reference, and it stays a
// refused token request. An answer of another 4xx is one when its status
// and its error code are a pair the binding declares (ADR-0047,
// error_code.go): the report then names the pair, both the binding's own.

import (
	"net/http"

	"adapters/internal/canon"
)

// ReferenceExpiredStatus is the exit status an expired reference is
// reported by.
const ReferenceExpiredStatus = 8

// ReferenceExpired is an answer of 410 from the source's endpoint, or of
// a declared pair: Code is then the pair's code and Status its status, and
// both are empty for a 410.
type ReferenceExpired struct {
	Status int
	Code   string
	text   string
}

func (e *ReferenceExpired) Error() string { return e.text }

// Report is what the command writes on stdout beside
// ReferenceExpiredStatus: {"referenceExpired": {"status": 410}}, or for a
// declared pair {"referenceExpired": {"code": CODE, "status": STATUS}}.
func (e *ReferenceExpired) Report() []byte {
	if e.Code == "" {
		return []byte(`{"referenceExpired":{"status":410}}`)
	}
	out, _ := canon.EncodeJSON(map[string]any{"referenceExpired": map[string]any{"status": e.Status, "code": e.Code}})
	return out
}

// expires is whether a source's answer of status is an expired reference.
func expires(status int) bool {
	return status == http.StatusGone
}
