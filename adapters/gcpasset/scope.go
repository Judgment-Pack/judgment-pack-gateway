package gcpasset

// The scope check (Amendment A2, A3) and the read-only refusals. Each token
// is held to the scopes it was actually granted, read from the token
// answer's scope member or, where the answer has none, from the
// token-information endpoint. The check fails closed: an answer that is
// absent, unreadable or holds no scopes is refused, and so is any scope
// beyond the one requested but for a closed list of identity scopes that
// grant no API access.

import (
	"context"
	"encoding/json"
	"mime"
	"net/http"
	"net/url"
	"strings"

	"adapters/internal/canon"
)

// The read-only refusals, by the names the decision gives them.
const (
	ReasonScopeUnknown    = "credential-scope-unknown"
	ReasonCanWrite        = "credential-can-write"
	ReasonBoundAtResource = "credential-bound-at-resource"
)

// identityScopes are the scopes a token source may add to what it grants:
// they grant no API access. The list is closed.
var identityScopes = map[string]bool{
	"openid": true,
	"https://www.googleapis.com/auth/userinfo.email": true,
	"email": true,
}

// maxSubject bounds a refusal's subject.
const maxSubject = 1024

// Refused is a read-only refusal: the command exits with RefusedStatus and
// writes Report beside it. Subject is the permission found, or the asset
// whose binding was found; nil where there is none to name, as for
// credential-scope-unknown. Nothing else is carried: never a token, its
// digest or any part of it.
type Refused struct {
	Reason  string
	Subject *string
}

func (r *Refused) Error() string {
	switch {
	case r.Subject == nil && r.Reason == ReasonCanWrite:
		return r.Reason + ": the write check did not complete, and a credential not shown to be read-only is refused"
	case r.Subject == nil && r.Reason == ReasonScopeUnknown:
		return r.Reason + ": the scopes the token was granted could not be shown to be the one requested alone"
	case r.Subject == nil:
		return r.Reason
	}
	return r.Reason + ": " + *r.Subject
}

// Report is {"refused": {"reason": R, "subject": S | null}}.
func (r *Refused) Report() []byte {
	out, _ := canon.EncodeJSON(map[string]any{"refused": map[string]any{"reason": r.Reason, "subject": r.Subject}})
	return out
}

// refused is a refusal naming subject, when it is printable ASCII within
// maxSubject bytes; a subject of another form is named by none.
func refused(reason, subject string) *Refused {
	r := &Refused{Reason: reason}
	if subject != "" && len(subject) <= maxSubject && printable(subject) {
		r.Subject = &subject
	}
	return r
}

func printable(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < 0x20 || s[i] > 0x7e {
			return false
		}
	}
	return true
}

// holdScope holds a token to the one scope it was requested with.
func (s *source) holdScope(ctx context.Context, tok obtained, requested string) error {
	unknown := &Refused{Reason: ReasonScopeUnknown}
	if tok.scopeUnreadable {
		return unknown
	}
	granted := ""
	if tok.scope != nil {
		granted = *tok.scope
	} else {
		var ok bool
		if granted, ok = s.tokenInfoScope(ctx, tok.value); !ok {
			return unknown
		}
	}
	if !scopesHeld(granted, requested) {
		return unknown
	}
	return nil
}

// scopesHeld is whether granted, space-separated, names the requested scope
// and nothing beyond it but identity scopes. An empty grant holds nothing.
func scopesHeld(granted, requested string) bool {
	fields := strings.Fields(granted)
	if len(fields) == 0 {
		return false
	}
	held := false
	for _, scope := range fields {
		switch {
		case scope == requested:
			held = true
		case identityScopes[scope]:
		default:
			return false
		}
	}
	return held
}

// tokenInfoScope asks the token-information endpoint what the token was
// granted, sending the token in a form body rather than a URL: the answer
// must be 200, JSON in the canonical domain within 64 KiB, with a scope
// member that is a string. Anything else is false.
func (s *source) tokenInfoScope(ctx context.Context, token string) (string, bool) {
	raw, contentType, status, err := s.post(ctx, endpoints.TokenInfo, url.Values{"access_token": {token}})
	if err != nil || status != http.StatusOK {
		return "", false
	}
	if mediaType, _, _ := mime.ParseMediaType(contentType); mediaType != "application/json" {
		return "", false
	}
	if _, err := canon.Canonicalize(raw, canon.CarryNumbersAsText); err != nil {
		return "", false
	}
	var members map[string]json.RawMessage
	if json.Unmarshal(raw, &members) != nil {
		return "", false
	}
	var scope string
	if !stringMember(members["scope"], &scope) {
		return "", false
	}
	return scope, true
}
