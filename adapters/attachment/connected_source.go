package attachment

import (
	"net/url"
	"path"
	"regexp"
	"strings"
	"unicode/utf8"
)

// ValidConnectedSource validates only reviewed identities. It does not establish
// that the publisher fetched this resource, that the text is complete, or true.
func ValidConnectedSource(s Source) bool {
	if s.Format != "text-snapshot-v1" || !regexp.MustCompile(`^sha256:[a-f0-9]{64}$`).MatchString(s.Version) || len(s.URL) > 4096 {
		return false
	}
	u, err := url.Parse(s.URL)
	if err != nil || u.User != nil || u.Fragment != "" {
		return false
	}
	switch s.Provider {
	case "notion":
		if !regexp.MustCompile(`^(?:[a-f0-9]{32}|[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})$`).MatchString(s.ResourceID) || u.Scheme != "https" || u.Port() != "" {
			return false
		}
		host := u.Hostname()
		if host != "notion.so" && host != "www.notion.so" && host != "notion.com" && host != "www.notion.com" {
			return false
		}
		return strings.HasSuffix(strings.ReplaceAll(u.Path, "-", ""), strings.ReplaceAll(s.ResourceID, "-", ""))
	case "obsidian":
		id := s.ResourceID
		if id == "" || len(id) > 1024 || !utf8.ValidString(id) || path.Clean(id) != id || strings.HasPrefix(id, "/") || strings.ContainsAny(id, "\\\x00\r\n:") || !strings.HasSuffix(strings.ToLower(id), ".md") {
			return false
		}
		for _, c := range id {
			if c < 32 || c == 127 {
				return false
			}
		}
		for _, part := range strings.Split(id, "/") {
			if strings.HasPrefix(part, ".") {
				return false
			}
		}
		q, err := url.ParseQuery(u.RawQuery)
		return err == nil && u.Scheme == "obsidian" && u.Host == "open" && u.Path == "" && len(q) == 2 && len(q["vault"]) == 1 && q.Get("vault") != "" && len(q["file"]) == 1 && q.Get("file") == strings.TrimSuffix(id, path.Ext(id))
	default:
		return false
	}
}
