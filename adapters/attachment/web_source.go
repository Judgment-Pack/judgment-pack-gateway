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
	return s.Format == "static-text-v1" && s.MediaType == "text/html" || s.Format == "original-v1" && (s.MediaType == "text/plain" || s.MediaType == "application/pdf")
}
