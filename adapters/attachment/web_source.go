package attachment

import (
	"net/url"
	"regexp"
	"strings"
	"unicode/utf8"
)

// WebURL checks a source identity's spelling, not DNS or reachability. The web
// adapter separately admits every resolved address immediately before dialing.
func WebURL(raw string) (*url.URL, bool) {
	if raw == "" || len(raw) > 4096 || !utf8.ValidString(raw) || strings.ContainsAny(raw, "\\\x00\r\n\t ") {
		return nil, false
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Opaque != "" || u.User != nil || u.Hostname() == "" || u.Fragment != "" || strings.Contains(raw, "#") || u.Port() != "" && u.Port() != "443" || u.String() != raw {
		return nil, false
	}
	return u, true
}

func ValidWebSource(s Source) bool {
	_, a := WebURL(s.RequestedURL)
	_, b := WebURL(s.URL)
	if !a || !b || !regexp.MustCompile(`^sha256:[a-f0-9]{64}$`).MatchString(s.Version) || !regexp.MustCompile(`^sha256:[a-f0-9]{64}$`).MatchString(s.ResponseDigest) {
		return false
	}
	if s.RedirectPolicy != "" && !followedPolicyHop(s) {
		return false
	}
	return s.Format == "static-text-v1" && s.MediaType == "text/html" || s.Format == "original-v1" && (s.MediaType == "text/plain" || s.MediaType == "application/pdf")
}

// RedirectPolicyGoogleGrounding is the one redirect policy a web source may
// name: a hop from a Google grounding search result's redirect endpoint
// (GroundingRedirectEndpoint) to the publisher.
const (
	RedirectPolicyGoogleGrounding = "google-grounding"
	GroundingRedirectHost         = "vertexaisearch.cloud.google.com"
	groundingRedirectPrefix       = "/grounding-api-redirect/"
)

// GroundingRedirectEndpoint reports whether u is the one endpoint the
// google-grounding policy follows a redirect from: https, exactly the host
// GroundingRedirectHost as spelled (lowercase), port 443 implicit or
// explicit, no userinfo, a path of the prefix and one non-empty token segment
// with nothing percent-encoded in it and not "." or "..", and no query, an
// empty one ("?") included. The web adapter decides the hop by it, and the
// check holds a record naming the policy to it, so the two cannot disagree.
func GroundingRedirectEndpoint(u *url.URL) bool {
	if u == nil || u.Scheme != "https" || u.User != nil || u.Hostname() != GroundingRedirectHost || u.Port() != "" && u.Port() != "443" || u.RawQuery != "" || u.ForceQuery {
		return false
	}
	escaped := u.EscapedPath()
	if !strings.HasPrefix(escaped, groundingRedirectPrefix) {
		return false
	}
	token := escaped[len(groundingRedirectPrefix):]
	return token != "" && token != "." && token != ".." && !strings.ContainsAny(token, "/%")
}

// followedPolicyHop holds a source that names a redirect policy to what the
// policy can have done: requested at the grounding endpoint exactly, and read
// at another host. A record without the member is not held to it.
func followedPolicyHop(s Source) bool {
	requested, errRequested := url.Parse(s.RequestedURL)
	final, errFinal := url.Parse(s.URL)
	return s.RedirectPolicy == RedirectPolicyGoogleGrounding && errRequested == nil && errFinal == nil && GroundingRedirectEndpoint(requested) && !strings.EqualFold(final.Hostname(), requested.Hostname())
}
