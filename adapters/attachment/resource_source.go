package attachment

import (
	"net/url"
	"regexp"
	"unicode/utf8"
)

// Resource identity is opaque to the consumer. A selected grant and receipt
// bind this identity and provider; a URL is optional display metadata, never
// an authorization endpoint or a credential-bearing download URL.
func ValidResourceSource(s Source) bool {
	if !regexp.MustCompile(`^[a-z][a-z0-9-]{0,47}$`).MatchString(s.Provider) || len(s.ResourceID) == 0 || len(s.ResourceID) > 4096 || !utf8.ValidString(s.ResourceID) || s.Format != "retained-file-v1" || !ValidDigest(s.Version) {
		return false
	}
	for _, r := range s.ResourceID {
		if r < 32 || r == 127 {
			return false
		}
	}
	if s.URL == "" {
		return true
	}
	if _, ok := WebURL(s.URL); !ok {
		return false
	}
	u, err := url.Parse(s.URL)
	return err == nil && u.RawQuery == "" && !u.ForceQuery
}
