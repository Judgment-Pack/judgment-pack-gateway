package httpsource

// An endpoint's error code (gateway #514 and #524, ADR-0047, SPEC.md §6,
// "Adapter sources"): the one place this adapter reads anything of a
// refusing answer's body as data. ErrorCodes is what the binding declares,
// handed in by --error-code-at, --expired-codes and --access-codes: where
// the code sits in the endpoint's error object, the status and code pairs
// that also mean an expired reference, and the codes passed on with an
// access refusal. errorCodeOf reads the code from a bounded body; it is
// answered only when it is on one of those closed lists, so what crosses
// to stdout is a value the binding states, never the endpoint's text.

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"

	"adapters/internal/canon"
)

// AccessRefusedStatus is the exit status an access refusal is reported by.
const AccessRefusedStatus = 10

// UnlistedCode is the code an access refusal is reported with when the
// endpoint's code is not on the binding's access list, or could not be
// read: a body over MaxErrorBody, not JSON, without the code, or with a
// code that is not a string of the code form.
const UnlistedCode = "unlisted"

// The bounds of an endpoint's error code and of the binding's lists.
const (
	// MaxErrorBody is the most of a refusing answer's body the code is
	// read from: a body longer than this is read for no code at all.
	MaxErrorBody = 4 << 10
	// MaxErrorCode is the longest code, and the longest member name of
	// the code's place, a list may hold.
	MaxErrorCode = 64
	// MaxErrorCodePlace is the most member names the code's place has.
	MaxErrorCodePlace = 4
	// MaxExpiredPairs and MaxAccessCodes bound the two lists.
	MaxExpiredPairs = 8
	MaxAccessCodes  = 16
)

// ErrorCodes is the binding's declaration: At, the member names from the
// body's top object to the code; Expired, the pairs that mean an expired
// reference; Access, the codes an access refusal passes on. A nil
// ErrorCodes declares nothing: no pair is an expired reference and every
// access refusal is UnlistedCode.
type ErrorCodes struct {
	At      []string
	Expired []ExpiredPair
	Access  []string
}

// ExpiredPair is a status and the endpoint's code that, answered together,
// mean the reference the request sent is no longer held.
type ExpiredPair struct {
	Status int
	Code   string
}

// errorCodeForm is whether s is a code a list may hold, and so one a body
// is answered with: 1 to MaxErrorCode bytes of ASCII letters, digits, "_",
// "." and "-". A name of the code's place is of the same form without ".",
// which joins the names on the command line.
func errorCodeForm(s string, dot bool) bool {
	if s == "" || len(s) > MaxErrorCode {
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

// ExpiredStatus is whether status may be declared beside a code as an
// expired reference: a 4xx that no other class already answers -- not 401
// or 403 (an access refusal), 410 (an expired reference whatever its
// code) or 429 (throttled).
func ExpiredStatus(status int) bool {
	return status >= 400 && status <= 499 && status != http.StatusUnauthorized && status != http.StatusForbidden &&
		status != http.StatusGone && status != http.StatusTooManyRequests
}

// ParseErrorCodes reads the three flags' values: at, the member names
// joined by "."; expired, STATUS:CODE pairs joined by ","; access, codes
// joined by ",". All empty is no declaration (nil). Otherwise at is given,
// and at least one list, each within its bound, each item of its form and
// once, no code UnlistedCode. A refusal repeats no value.
func ParseErrorCodes(at, expired, access string) (*ErrorCodes, error) {
	if at == "" && expired == "" && access == "" {
		return nil, nil
	}
	if at == "" || expired == "" && access == "" {
		return nil, errors.New("--error-code-at is given with --expired-codes, --access-codes or both, and neither list without it")
	}
	c := &ErrorCodes{At: strings.Split(at, ".")}
	if len(c.At) > MaxErrorCodePlace {
		return nil, fmt.Errorf("--error-code-at names at most %d members", MaxErrorCodePlace)
	}
	for _, name := range c.At {
		if !errorCodeForm(name, false) {
			return nil, fmt.Errorf("--error-code-at names members of 1 to %d ASCII letters, digits, \"_\" and \"-\", joined by \".\"", MaxErrorCode)
		}
	}
	if expired != "" {
		items := strings.Split(expired, ",")
		if len(items) > MaxExpiredPairs {
			return nil, fmt.Errorf("--expired-codes holds at most %d pairs", MaxExpiredPairs)
		}
		for _, item := range items {
			text, code, ok := strings.Cut(item, ":")
			status, err := strconv.Atoi(text)
			if !ok || err != nil || len(text) != 3 || !ExpiredStatus(status) || !errorCodeForm(code, true) || code == UnlistedCode {
				return nil, errors.New("--expired-codes holds STATUS:CODE pairs, a 4xx status other than 401, 403, 410 and 429 and a code of the code form")
			}
			pair := ExpiredPair{Status: status, Code: code}
			for _, earlier := range c.Expired {
				if earlier == pair {
					return nil, errors.New("--expired-codes repeats a pair")
				}
			}
			c.Expired = append(c.Expired, pair)
		}
	}
	if access != "" {
		c.Access = strings.Split(access, ",")
		if len(c.Access) > MaxAccessCodes {
			return nil, fmt.Errorf("--access-codes holds at most %d codes", MaxAccessCodes)
		}
		for i, code := range c.Access {
			if !errorCodeForm(code, true) || code == UnlistedCode || contains(c.Access[:i], code) {
				return nil, errors.New("--access-codes holds codes of the code form, each once, and not \"unlisted\"")
			}
		}
	}
	return c, nil
}

// errorCodeOf is the one reading of a refusing answer's body: at most
// MaxErrorBody bytes, exactly one JSON value with no member name repeated
// in any object, the members at in turn each an object's, and the last a
// string of the code form. Anything else is no code, and false. The code
// is not yet held to a list.
func errorCodeOf(body []byte, at []string) (string, bool) {
	if len(body) > MaxErrorBody || len(at) == 0 {
		return "", false
	}
	dec := json.NewDecoder(bytes.NewReader(body))
	v, err := strictValue(dec)
	if err != nil {
		return "", false
	}
	if _, err := dec.Token(); err != io.EOF {
		return "", false
	}
	for _, name := range at {
		obj, ok := v.(map[string]any)
		if !ok {
			return "", false
		}
		if v, ok = obj[name]; !ok {
			return "", false
		}
	}
	code, ok := v.(string)
	if !ok || !errorCodeForm(code, true) {
		return "", false
	}
	return code, true
}

var errRepeatedName = errors.New("a member name is repeated")

// strictValue decodes one JSON value from dec, refusing an object that
// repeats a member name, since which of two codes is the endpoint's would
// otherwise be the decoder's choice.
func strictValue(dec *json.Decoder) (any, error) {
	tok, err := dec.Token()
	if err != nil {
		return nil, err
	}
	delim, ok := tok.(json.Delim)
	if !ok {
		return tok, nil
	}
	switch delim {
	case '{':
		obj := map[string]any{}
		for dec.More() {
			name, err := dec.Token()
			if err != nil {
				return nil, err
			}
			key, _ := name.(string)
			if _, repeated := obj[key]; repeated {
				return nil, errRepeatedName
			}
			if obj[key], err = strictValue(dec); err != nil {
				return nil, err
			}
		}
		_, err := dec.Token()
		return obj, err
	case '[':
		var list []any
		for dec.More() {
			item, err := strictValue(dec)
			if err != nil {
				return nil, err
			}
			list = append(list, item)
		}
		_, err := dec.Token()
		return list, err
	}
	return nil, errors.New("not a JSON value")
}

// expiredPair is the declared code of an answer of status whose body's
// code, with status, is one of the binding's expired pairs; false when it
// is not, or nothing is declared.
func (c *ErrorCodes) expiredPair(status int, body []byte) (string, bool) {
	if c == nil || len(c.Expired) == 0 {
		return "", false
	}
	code, ok := errorCodeOf(body, c.At)
	if !ok {
		return "", false
	}
	for _, pair := range c.Expired {
		if pair.Status == status && pair.Code == code {
			return pair.Code, true
		}
	}
	return "", false
}

// accessCode is the code an access refusal whose answer is body passes
// on: the body's code when it is on the binding's access list, the list's
// own copy of it, and UnlistedCode otherwise.
func (c *ErrorCodes) accessCode(body []byte) string {
	if c == nil || len(c.Access) == 0 {
		return UnlistedCode
	}
	code, ok := errorCodeOf(body, c.At)
	if !ok {
		return UnlistedCode
	}
	for _, listed := range c.Access {
		if listed == code {
			return listed
		}
	}
	return UnlistedCode
}

// refusesAccess is whether a source's answer of status is an access
// refusal: 403, and 401 to a request that carried no token the step
// obtained (that one is TokenRejectedBySource, said before this is asked).
func refusesAccess(status int) bool {
	return status == http.StatusUnauthorized || status == http.StatusForbidden
}

// AccessRefused is an answer of 401 or 403 from the source's endpoint:
// the status, and the code from the binding's access list or UnlistedCode.
type AccessRefused struct {
	Status int
	Code   string
	text   string
}

func (e *AccessRefused) Error() string { return e.text }

// Report is what the command writes on stdout beside AccessRefusedStatus:
// {"accessRefused": {"code": CODE, "status": 401 | 403}}.
func (e *AccessRefused) Report() []byte {
	out, _ := canon.EncodeJSON(map[string]any{"accessRefused": map[string]any{"status": e.Status, "code": e.Code}})
	return out
}
