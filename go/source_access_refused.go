package main

// An access refusal and the binding's error codes (gateway #514 and #524,
// docs/adr/0047-an-endpoints-error-code-from-a-closed-list.md, SPEC.md §6):
// an http binding's live operation may declare, under errorCodes, where its
// endpoint's error object holds the error code, the status and code pairs
// that also mean an expired reference, and the codes passed on with an
// access refusal. The engine hands them to adapter-http, which alone reads
// the endpoint's body; the gateway holds every report to the same lists, so
// what reaches a caller is a value the pinned binding states, never the
// endpoint's text. An endpoint's 401 or 403 -- a 401 only where no token
// step obtained the token sent -- exits with sourceExitAccessRefused and
// reports the status and the listed code, or "unlisted"; /acquire answers
// 403 with sourceAccessRefusedCode and the gateway's own sentence,
// unreceipted, as the 410 and 429 classes are.

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"
)

// sourceExitAccessRefused is the exit status an access refusal is reported
// by (adapters/httpsource, AccessRefusedStatus).
const sourceExitAccessRefused = 10

// sourceAccessRefusedCode is the code /acquire's answer carries beside its
// sentence; unlistedErrorCode is endpointCode's value when the endpoint's
// code is not on the binding's access list or could not be read.
const (
	sourceAccessRefusedCode = "source_access_refused"
	unlistedErrorCode       = "unlisted"
)

// The bounds of an errorCodes member (adapters/httpsource, error_code.go).
const (
	maxErrorCode      = 64
	maxErrorCodePlace = 4
	maxExpiredPairs   = 8
	maxAccessCodes    = 16
)

// httpErrorCodes is an http operation's errorCodes: at, the member names
// from the error object's top to the code; expired, the declared pairs;
// access, the codes an access refusal passes on.
type httpErrorCodes struct {
	at      []string
	expired []httpExpiredPair
	access  []string
}

type httpExpiredPair struct {
	status int
	code   string
}

var httpErrorCodesMembers = map[string]bool{"at": true, "referenceExpired": false, "accessRefused": false}

// errorCodeForm is whether s is a code a list may hold: 1 to maxErrorCode
// bytes of ASCII letters, digits, "_", "." and "-"; a member name of at is
// of the same form without ".", which joins the names on the command line.
func errorCodeForm(s string, dot bool) bool {
	if s == "" || len(s) > maxErrorCode {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '-' || dot && c == '.') {
			return false
		}
	}
	return true
}

// expiredPairStatus is whether a status may be declared beside a code as
// an expired reference: a 4xx no other class answers, so not 401, 403, 410
// or 429.
func expiredPairStatus(status int64) bool {
	return status >= 400 && status <= 499 && status != http.StatusUnauthorized && status != http.StatusForbidden &&
		status != http.StatusGone && status != http.StatusTooManyRequests
}

// parseHTTPErrorCodes holds an operation's errorCodes to its shape: exactly
// at and at least one of referenceExpired and accessRefused; at 1 to 4
// member names; referenceExpired 1 to 8 objects of exactly status and code;
// accessRefused 1 to 16 codes; every code of the code form, once in its
// list, and not "unlisted". A refusal names the member by its place and
// repeats no value.
func parseHTTPErrorCodes(raw value, name string) (*httpErrorCodes, error) {
	obj, ok := raw.(*vObject)
	if !ok {
		return nil, fmt.Errorf("operation %s: errorCodes must be an object", name)
	}
	if err := exactlyMembers(obj, httpErrorCodesMembers, "operation "+name+": errorCodes"); err != nil {
		return nil, err
	}
	c := &httpErrorCodes{}
	place, ok := obj.byName["at"].(vArray)
	if !ok || len(place) == 0 || len(place) > maxErrorCodePlace {
		return nil, fmt.Errorf("operation %s: errorCodes.at must be an array of 1 to %d member names", name, maxErrorCodePlace)
	}
	for i, item := range place {
		s, ok := item.(vString)
		if !ok || !errorCodeForm(string(s), false) {
			return nil, fmt.Errorf("operation %s: errorCodes.at[%d] must be 1 to %d ASCII letters, digits, \"_\" and \"-\"", name, i, maxErrorCode)
		}
		c.at = append(c.at, string(s))
	}
	_, hasExpired := obj.get("referenceExpired")
	_, hasAccess := obj.get("accessRefused")
	if !hasExpired && !hasAccess {
		return nil, fmt.Errorf("operation %s: errorCodes names referenceExpired, accessRefused or both", name)
	}
	if hasExpired {
		pairs, ok := obj.byName["referenceExpired"].(vArray)
		if !ok || len(pairs) == 0 || len(pairs) > maxExpiredPairs {
			return nil, fmt.Errorf("operation %s: errorCodes.referenceExpired must be an array of 1 to %d pairs", name, maxExpiredPairs)
		}
		for i, item := range pairs {
			pair, ok := item.(*vObject)
			if !ok || exactlyMembers(pair, map[string]bool{"status": true, "code": true}, "pair") != nil {
				return nil, fmt.Errorf("operation %s: errorCodes.referenceExpired[%d] must be an object of exactly status and code", name, i)
			}
			status, ok := pair.byName["status"].(vInt)
			if !ok || !expiredPairStatus(int64(status)) {
				return nil, fmt.Errorf("operation %s: errorCodes.referenceExpired[%d].status must be a 4xx other than 401, 403, 410 and 429", name, i)
			}
			code, ok := pair.byName["code"].(vString)
			if !ok || !errorCodeForm(string(code), true) || code == unlistedErrorCode {
				return nil, fmt.Errorf("operation %s: errorCodes.referenceExpired[%d].code must be 1 to %d ASCII letters, digits, \"_\", \".\" and \"-\", and not \"unlisted\"", name, i, maxErrorCode)
			}
			p := httpExpiredPair{status: int(status), code: string(code)}
			for _, earlier := range c.expired {
				if earlier == p {
					return nil, fmt.Errorf("operation %s: errorCodes.referenceExpired[%d] repeats an earlier pair", name, i)
				}
			}
			c.expired = append(c.expired, p)
		}
	}
	if hasAccess {
		codes, ok := obj.byName["accessRefused"].(vArray)
		if !ok || len(codes) == 0 || len(codes) > maxAccessCodes {
			return nil, fmt.Errorf("operation %s: errorCodes.accessRefused must be an array of 1 to %d codes", name, maxAccessCodes)
		}
		for i, item := range codes {
			code, ok := item.(vString)
			if !ok || !errorCodeForm(string(code), true) || code == unlistedErrorCode || contains(c.access, string(code)) {
				return nil, fmt.Errorf("operation %s: errorCodes.accessRefused[%d] must be 1 to %d ASCII letters, digits, \"_\", \".\" and \"-\", once, and not \"unlisted\"", name, i, maxErrorCode)
			}
			c.access = append(c.access, string(code))
		}
	}
	return c, nil
}

// argv is adapter-http's words for the declaration, each flag and its
// value one word.
func (c *httpErrorCodes) argv() []string {
	if c == nil {
		return nil
	}
	out := []string{"--error-code-at=" + strings.Join(c.at, ".")}
	if len(c.expired) > 0 {
		pairs := make([]string, 0, len(c.expired))
		for _, p := range c.expired {
			pairs = append(pairs, strconv.Itoa(p.status)+":"+p.code)
		}
		out = append(out, "--expired-codes="+strings.Join(pairs, ","))
	}
	if len(c.access) > 0 {
		out = append(out, "--access-codes="+strings.Join(c.access, ","))
	}
	return out
}

// declaresExpired is whether status and code are one of the declared
// pairs; nil declares none.
func (c *httpErrorCodes) declaresExpired(status int, code string) bool {
	if c == nil {
		return false
	}
	for _, p := range c.expired {
		if p.status == status && p.code == code {
			return true
		}
	}
	return false
}

// listedAccessCode is code when it is on the access list, and
// unlistedErrorCode otherwise: the gateway passes on no code its binding
// does not state, whatever the adapter reported.
func (c *httpErrorCodes) listedAccessCode(code string) string {
	if c != nil {
		for _, listed := range c.access {
			if listed == code {
				return listed
			}
		}
	}
	return unlistedErrorCode
}

// sourceAccessRefused is an acquisition whose source reported that its
// endpoint answered 401 or 403: the status, and the code the answer passes
// on, from the binding's list or unlistedErrorCode. failed is the failure
// the same run is said as where the report is not read (a token request).
type sourceAccessRefused struct {
	status int
	code   string
	failed error
}

// Error is the one sentence for the class: it begins as every failure of a
// source's own does ("source failed: "), and names nothing the source said.
func (e *sourceAccessRefused) Error() string {
	return fmt.Sprintf("source failed: the source's endpoint answered %d %s: it refused this read to the source's credential; nothing was retained or minted", e.status, http.StatusText(e.status))
}

// accessRefusedReport reads an http adapter's stdout beside
// sourceExitAccessRefused: exactly {"accessRefused": {"status": 401 | 403,
// "code": CODE}}, each member once, the integer in digits alone, the code
// "unlisted" or of the code form, and nothing before or after the value,
// whitespace included; a 401 is not read from a source with a token step,
// whose 401 is the token refused. The code is answered only when codes
// lists it, and as unlistedErrorCode otherwise. Anything else is not a
// report, and false.
func accessRefusedReport(stdout []byte, codes *httpErrorCodes, tokenStep bool) (*sourceAccessRefused, bool) {
	if len(stdout) == 0 || isJSONSpace(stdout[0]) || isJSONSpace(stdout[len(stdout)-1]) {
		return nil, false
	}
	v, err := (&parser{data: stdout, unsigned: true}).document()
	if err != nil {
		return nil, false
	}
	outer, ok := v.(*vObject)
	if !ok || exactlyMembers(outer, map[string]bool{"accessRefused": true}, "access report") != nil {
		return nil, false
	}
	report, ok := outer.byName["accessRefused"].(*vObject)
	if !ok || exactlyMembers(report, map[string]bool{"status": true, "code": true}, "access report") != nil {
		return nil, false
	}
	status, ok := report.byName["status"].(vInt)
	if !ok || status != http.StatusForbidden && (status != http.StatusUnauthorized || tokenStep) {
		return nil, false
	}
	code, ok := report.byName["code"].(vString)
	if !ok || code != unlistedErrorCode && !errorCodeForm(string(code), true) {
		return nil, false
	}
	return &sourceAccessRefused{status: int(status), code: codes.listedAccessCode(string(code))}, true
}
