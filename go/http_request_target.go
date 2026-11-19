package main

// What an acquisition of an http source may name (docs/adr/0040-path-templates-and-links-on-an-http-source.md):
// a binding's path is fixed, or a template whose one placeholder, {id}, is
// a whole segment a GUID fills and nothing else, from engine version 31,
// or, from engine version 33, {numericId}, 1 to 32 ASCII digits, or
// {alnumId}, 1 to 64 lowercase ASCII letters and digits
// (docs/adr/0045-a-delegated-subject-token-signed-by-the-credentials-api.md, decision 9);
// and a request names a path among them with a query object, or a link --
// an absolute URL the endpoint handed out, a next page's or a delta's --
// under the binding's endpoint. adapter-http is what holds a request to
// these rules before it connects (adapters/httpsource/target.go); the
// engine holds a token step's request to the same rules before a token is
// obtained for it (tokenStepAdmits), and holds a binding's paths to them
// when it loads the binding (httpPathProblem). testdata/http-requests/cases.json
// is the table both are tested against.

import (
	"fmt"
	"strconv"
	"strings"
)

const (
	// httpIDPlaceholder is the one placeholder an http path may carry, at
	// most once, as a whole segment. It is not a platform parameter: a
	// parameter fills a remote MCP operation's URL when the engine starts
	// (binding_template.go), and {id} is filled by each request.
	httpIDPlaceholder = "{id}"
	// httpTemplateCheckID stands in for {id} when a template is held to
	// the rules of a path, since every path it admits differs from it only
	// in that segment's hex digits.
	httpTemplateCheckID = "00000000-0000-0000-0000-000000000000"
	// maxHTTPLinkBytes is adapter-http's bound on a link.
	maxHTTPLinkBytes = 16 << 10
	// httpTemplatesVersion is the engine version from which an http path
	// may be a template.
	httpTemplatesVersion = "31"
)

// httpPlaceholder is a placeholder an http path may carry as a whole
// segment: the form of what fills it, a value of that form a template is
// held to a path's rules with, and the engine version a binding may carry
// it from. {id} is ADR-0040's, unchanged; {numericId} and {alnumId} are
// ADR-0045's, narrow forms of their own beside it, not a widening of it.
type httpPlaceholder struct {
	name, check, version string
	admits               func(string) bool
}

var httpPlaceholders = []httpPlaceholder{
	{httpIDPlaceholder, httpTemplateCheckID, httpTemplatesVersion, isGUID},
	{"{numericId}", "0", delegatedTokenVersion, isNumericID},
	{"{alnumId}", "0", delegatedTokenVersion, isAlnumID},
}

// isNumericID is whether s is 1 to 32 ASCII digits and nothing else.
func isNumericID(s string) bool {
	if s == "" || len(s) > 32 {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

// isAlnumID is whether s is 1 to 64 lowercase ASCII letters and digits and
// nothing else.
func isAlnumID(s string) bool {
	if s == "" || len(s) > 64 {
		return false
	}
	for i := 0; i < len(s); i++ {
		if !('0' <= s[i] && s[i] <= '9' || 'a' <= s[i] && s[i] <= 'z') {
			return false
		}
	}
	return true
}

// httpPlaceholderOf is the placeholder a path carries, nil when none.
func httpPlaceholderOf(path string) *httpPlaceholder {
	for i := range httpPlaceholders {
		if strings.Contains(path, httpPlaceholders[i].name) {
			return &httpPlaceholders[i]
		}
	}
	return nil
}

// httpTemplateProblem holds a binding path's placeholder to its rule: at
// most one placeholder of any kind, a whole segment, and no other brace.
// It returns the path with a value of the placeholder's form in its place,
// which the rest of a path's rules then hold.
func httpTemplateProblem(path string) (string, error) {
	count := 0
	for _, p := range httpPlaceholders {
		count += strings.Count(path, p.name)
	}
	p := httpPlaceholderOf(path)
	switch {
	case count == 0:
		if strings.ContainsAny(path, "{}") {
			return "", fmt.Errorf("carries a brace that is not the %s placeholder", httpIDPlaceholder)
		}
		return path, nil
	case count > 1 && strings.Count(path, httpIDPlaceholder) > 1:
		return "", fmt.Errorf("carries more than one %s placeholder", httpIDPlaceholder)
	case count > 1:
		return "", fmt.Errorf("carries more than one placeholder")
	}
	for _, segment := range strings.Split(path, "/") {
		if strings.Contains(segment, p.name) && segment != p.name {
			return "", fmt.Errorf("carries %s within a segment; the placeholder is a whole segment", p.name)
		}
	}
	filled := strings.Replace(path, p.name, p.check, 1)
	if strings.ContainsAny(filled, "{}") {
		return "", fmt.Errorf("carries a brace that is not the %s placeholder", p.name)
	}
	return filled, nil
}

// httpTemplated is whether a binding path is a template.
func httpTemplated(path string) bool {
	return httpPlaceholderOf(path) != nil
}

// isGUID is whether s is a GUID in its 8-4-4-4-12 form: 36 characters,
// hyphens at the four places the form puts them, hex digits of either case
// everywhere else, and nothing more.
func isGUID(s string) bool {
	if len(s) != 36 {
		return false
	}
	for i := 0; i < len(s); i++ {
		switch i {
		case 8, 13, 18, 23:
			if s[i] != '-' {
				return false
			}
		default:
			if !isHexDigit(s[i]) {
				return false
			}
		}
	}
	return true
}

// httpPathAdmitted is whether a request's path is one of a binding's
// paths: equal to a fixed one, or to a template in every segment but the
// {id} one, which is a GUID. A path so admitted is as well formed as the
// binding's own, which httpPathProblem held.
func httpPathAdmitted(paths []string, path string) bool {
	for _, configured := range paths {
		if httpTemplateMatches(configured, path) {
			return true
		}
	}
	return false
}

func httpTemplateMatches(template, path string) bool {
	if !httpTemplated(template) {
		return template == path
	}
	p := httpPlaceholderOf(template)
	want, got := strings.Split(template, "/"), strings.Split(path, "/")
	if len(want) != len(got) {
		return false
	}
	for i := range want {
		if want[i] == p.name {
			if !p.admits(got[i]) {
				return false
			}
		} else if want[i] != got[i] {
			return false
		}
	}
	return true
}

// httpLinkAdmitted is whether a link names a path under the endpoint that
// the paths admit, as adapter-http admits one: a bound and visible ASCII;
// no fragment and no backslash; the endpoint's scheme and host, compared
// without regard to case; the endpoint's port, the scheme's default
// standing for an absent one; no user; a query, when there is one, of the
// characters RFC 3986 gives a query, a percent sign only before two hex
// digits; and a path with no percent sign that is the endpoint's path
// followed by an admitted one. endpoint is of the endpoint form, which
// parseHTTPOperation held.
func httpLinkAdmitted(endpoint string, paths []string, link string) bool {
	if link == "" || len(link) > maxHTTPLinkBytes || !visibleASCII(link) || strings.ContainsAny(link, `#\`) {
		return false
	}
	scheme, endpointRest, _ := strings.Cut(endpoint, "://")
	prefix := scheme + "://"
	if len(link) < len(prefix) || !strings.EqualFold(link[:len(prefix)], prefix) {
		return false
	}
	rest := link[len(prefix):]
	authority, tail := rest, ""
	if end := strings.IndexAny(rest, "/?"); end >= 0 {
		authority, tail = rest[:end], rest[end:]
	}
	if strings.Contains(authority, "@") {
		return false
	}
	host, port, hasPort, ok := endpointAuthority(authority)
	if !ok || host == "" || hasPort && !isEndpointPort(port) {
		return false
	}
	endpointAuth, endpointPath, _ := strings.Cut(endpointRest, "/")
	endpointHost, endpointPort, _, _ := endpointAuthority(endpointAuth)
	if !strings.EqualFold(host, endpointHost) || httpEffectivePort(scheme, port) != httpEffectivePort(scheme, endpointPort) {
		return false
	}
	rawPath, query, hasQuery := strings.Cut(tail, "?")
	if hasQuery && !httpQueryAsWritten(query) {
		return false
	}
	if strings.Contains(rawPath, "%") {
		return false
	}
	under := strings.TrimSuffix("/"+endpointPath, "/")
	if !strings.HasPrefix(rawPath, under+"/") {
		return false
	}
	return httpPathAdmitted(paths, rawPath[len(under):])
}

// httpEffectivePort is the port a URL of the scheme reaches: the one
// written, or the scheme's default when none is.
func httpEffectivePort(scheme, port string) int {
	if port == "" {
		if scheme == "http" {
			return 80
		}
		return 443
	}
	n, err := strconv.Atoi(port)
	if err != nil {
		return -1
	}
	return n
}

// httpQueryAsWritten is whether a link's query is one a request line
// carries byte for byte: not empty, and of unreserved characters,
// sub-delims, ":", "@", "/" and "?" alone, with a percent sign only as the
// start of an escape of two hex digits.
func httpQueryAsWritten(query string) bool {
	if query == "" {
		return false
	}
	for i := 0; i < len(query); i++ {
		c := query[i]
		switch {
		case 'a' <= c && c <= 'z', 'A' <= c && c <= 'Z', '0' <= c && c <= '9':
		case strings.IndexByte("-._~!$&'()*+,;=:@/?", c) >= 0:
		case c == '%':
			if i+2 >= len(query) || !isHexDigit(query[i+1]) || !isHexDigit(query[i+2]) {
				return false
			}
			i += 2
		default:
			return false
		}
	}
	return true
}

// httpQueryObject is whether a request's query, when it has one, is what
// adapter-http takes: an object of strings with non-empty names.
func httpQueryObject(request *vObject) bool {
	raw, present := request.get("query")
	if !present {
		return true
	}
	query, ok := raw.(*vObject)
	if !ok {
		return false
	}
	for _, name := range query.names {
		if _, ok := query.byName[name].(vString); !ok || name == "" {
			return false
		}
	}
	return true
}

// httpTemplatesMatch refuses a binding whose http paths carry a template
// under a configuration of an engine version before the placeholder's:
// {id} before httpTemplatesVersion, {numericId} and {alnumId} before
// delegatedTokenVersion. The version a file states is the reading of it its
// author reviewed, and a path that admits every value of a form is not a
// path an earlier reading admitted. It answers, beside the refusal, the
// version the refused placeholder needs, which connect names.
func httpTemplatesMatch(b binding, ref, version string) (string, error) {
	if b.live == nil || b.live.http == nil {
		return "", nil
	}
	for i, path := range b.live.http.paths {
		p := httpPlaceholderOf(path)
		switch {
		case p == nil || versionAtLeast(version, p.version):
		case p.name == httpIDPlaceholder:
			return p.version, fmt.Errorf("binding %s's live operation names a path template, paths[%d], a version-%s member; engineVersion %s has none", ref, i, httpTemplatesVersion, version)
		default:
			return p.version, fmt.Errorf("binding %s's live operation names a path template of %s, paths[%d], a version-%s member; engineVersion %s has none", ref, p.name, i, p.version, version)
		}
	}
	return "", nil
}
