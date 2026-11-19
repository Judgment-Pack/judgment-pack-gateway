package httpsource

// A request's target (docs/adr/0040-path-templates-and-links-on-an-http-source.md):
// a configured path is fixed, or a template whose one placeholder, {id},
// is a whole segment matched by a GUID and nothing else; and a request
// names its target by a path under the endpoint and a query object, or by
// a link -- an absolute URL the endpoint itself handed out, a next page's
// or a delta's -- which is admitted only when it names this endpoint, a
// path the configuration admits, and nothing a request line would send as
// other bytes than it carries. The core module holds an acquisition to the
// same rules before a token is obtained for it (go/http_request_target.go);
// testdata/http-requests/cases.json is the table both are tested against.

import (
	"errors"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
)

const (
	// idPlaceholder is the one placeholder a configured path may carry, at
	// most once, as a whole segment.
	idPlaceholder = "{id}"
	// templateCheckID stands in for {id} when a template is held to the
	// rules of a path, since every path it admits differs from it only in
	// that segment's hex digits.
	templateCheckID = "00000000-0000-0000-0000-000000000000"
	// maxLinkBytes bounds a link: a next page's or a delta's link carries
	// an opaque token, and one past this is not one an endpoint handed out
	// to be followed.
	maxLinkBytes = 16 << 10
)

// The refusals of a link, each one fixed sentence naming the rule and
// nothing of the link: a link carries the endpoint's paging or change
// token, which a diagnostic returned to whoever called has no need of.
var (
	errLinkScheme   = errors.New(`request: "link" is not an absolute URL of the endpoint's scheme`)
	errLinkUser     = errors.New(`request: "link" carries a user`)
	errLinkHost     = errors.New(`request: "link" names another host than the endpoint`)
	errLinkPort     = errors.New(`request: "link" names another port than the endpoint`)
	errLinkFragment = errors.New(`request: "link" carries a fragment`)
	errLinkPercent  = errors.New(`request: "link"'s path carries a percent sign; a link is followed only when its path is sent as written`)
	errLinkUnder    = errors.New(`request: "link"'s path is not under the endpoint's path`)
	errLinkPathForm = errors.New(`request: "link"'s path carries a dot segment, an empty segment, a backslash or a character that would not be sent as written`)
	errLinkPath     = errors.New(`request: "link"'s path is not one this source may request`)
	errLinkQuery    = errors.New(`request: "link"'s query is empty, or carries a character a query does not`)
	errLinkForm     = errors.New(`request: "link" must be a URL of at most 16384 bytes of visible ASCII`)
)

// isGUID is whether s is a GUID in its 8-4-4-4-12 form: 36 characters,
// hyphens at the four places the form puts them, hex digits of either case
// everywhere else, and nothing more -- no brace, no slash, no percent
// sign, no dot.
func isGUID(s string) bool {
	if len(s) != 36 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch i {
		case 8, 13, 18, 23:
			if c != '-' {
				return false
			}
		default:
			if !('0' <= c && c <= '9' || 'a' <= c && c <= 'f' || 'A' <= c && c <= 'F') {
				return false
			}
		}
	}
	return true
}

// configuredPathProblem is why a configured path, one of --paths, is not
// one to admit, or nil: a fixed path pathProblem holds, or a template --
// one {id}, a whole segment, and no other brace -- which, with a GUID in
// place of {id}, pathProblem holds.
func configuredPathProblem(path string) error {
	switch strings.Count(path, idPlaceholder) {
	case 0:
	case 1:
		for _, segment := range strings.Split(path, "/") {
			if strings.Contains(segment, idPlaceholder) && segment != idPlaceholder {
				return errors.New(`"path" carries {id} within a segment; the placeholder is a whole segment`)
			}
		}
	default:
		return errors.New(`"path" carries more than one {id} placeholder`)
	}
	filled := strings.Replace(path, idPlaceholder, templateCheckID, 1)
	if strings.ContainsAny(filled, "{}") {
		return errors.New(`"path" carries a brace that is not the {id} placeholder`)
	}
	return pathProblem(filled)
}

// pathAdmitted is whether a request's path, one pathProblem holds, is one
// of the configured paths: equal to a fixed one, or to a template in every
// segment but the {id} one, which is a GUID.
func pathAdmitted(paths []string, path string) bool {
	for _, configured := range paths {
		if templateMatches(configured, path) {
			return true
		}
	}
	return false
}

func templateMatches(template, path string) bool {
	if !strings.Contains(template, idPlaceholder) {
		return template == path
	}
	want, got := strings.Split(template, "/"), strings.Split(path, "/")
	if len(want) != len(got) {
		return false
	}
	for i := range want {
		if want[i] == idPlaceholder {
			if !isGUID(got[i]) {
				return false
			}
		} else if want[i] != got[i] {
			return false
		}
	}
	return true
}

// linkFormProblem holds a link to what ParseRequest can hold it to without
// the configuration: a bound, and visible ASCII alone, so nothing in it is
// sent as other bytes than it carries or reads as the end of a request
// line.
func linkFormProblem(link string) error {
	if link == "" || len(link) > maxLinkBytes {
		return errLinkForm
	}
	for i := 0; i < len(link); i++ {
		if link[i] < 0x21 || link[i] > 0x7e {
			return errLinkForm
		}
	}
	return nil
}

// linkTarget is the path under the endpoint and the query a link names,
// or why it is refused. It is admitted only when its scheme and host are
// the endpoint's, compared without regard to case, its port is the
// endpoint's, the scheme's default standing for an absent one, it carries
// no user and no fragment, and its path, as written, is the endpoint's
// path followed by a path pathProblem holds and the configuration admits,
// with no percent sign in it, so the path sent is the link's byte for
// byte; its query, when it has one, is sent byte for byte too, and is held
// to the characters RFC 3986 gives a query. Nothing is decoded, resolved
// or normalized but the scheme's and the host's case and the default port.
func linkTarget(base *url.URL, paths []string, link string) (path, rawQuery string, err error) {
	if err := linkFormProblem(link); err != nil {
		return "", "", err
	}
	if strings.Contains(link, "#") {
		return "", "", errLinkFragment
	}
	if strings.Contains(link, `\`) {
		return "", "", errLinkPathForm
	}
	prefix := base.Scheme + "://"
	if len(link) < len(prefix) || !strings.EqualFold(link[:len(prefix)], prefix) {
		return "", "", errLinkScheme
	}
	rest := link[len(prefix):]
	authority, tail := rest, ""
	if end := strings.IndexAny(rest, "/?"); end >= 0 {
		authority, tail = rest[:end], rest[end:]
	}
	if strings.Contains(authority, "@") {
		return "", "", errLinkUser
	}
	host, port, err := splitAuthority(authority)
	if err != nil {
		return "", "", err
	}
	if !strings.EqualFold(host, authorityHost(base)) {
		return "", "", errLinkHost
	}
	if effectivePort(base.Scheme, port) != effectivePort(base.Scheme, base.Port()) {
		return "", "", errLinkPort
	}
	rawPath, query, hasQuery := strings.Cut(tail, "?")
	if hasQuery && !queryAsWritten(query) {
		return "", "", errLinkQuery
	}
	if strings.Contains(rawPath, "%") {
		return "", "", errLinkPercent
	}
	under := strings.TrimSuffix(base.EscapedPath(), "/")
	if !strings.HasPrefix(rawPath, under+"/") {
		return "", "", errLinkUnder
	}
	path = rawPath[len(under):]
	if pathProblem(path) != nil {
		return "", "", errLinkPathForm
	}
	if !pathAdmitted(paths, path) {
		return "", "", errLinkPath
	}
	return path, query, nil
}

// authorityHost is the endpoint's host as an authority writes it: an IPv6
// literal in its brackets, any other host as it is.
func authorityHost(base *url.URL) string {
	if strings.HasPrefix(base.Host, "[") {
		return "[" + base.Hostname() + "]"
	}
	return base.Hostname()
}

// splitAuthority is a link's host and port, the host as the authority
// writes it -- an IPv6 literal with its brackets, which authorityHost
// gives the endpoint's too, so a bracketed name never compares equal to
// the endpoint's bare one -- or the refusal of an authority that is no
// host and port: an empty or unclosed host, brackets around anything but
// an IPv6 address with no zone, or a port that is empty, not decimal,
// zero-led or past 65535. The core module compares the bracketed text as
// this does (go/http_request_target.go, httpLinkAdmitted).
func splitAuthority(authority string) (host, port string, err error) {
	rest := ""
	if strings.HasPrefix(authority, "[") {
		end := strings.IndexByte(authority, ']')
		if end < 0 {
			return "", "", errLinkHost
		}
		if addr, err := netip.ParseAddr(authority[1:end]); err != nil || !addr.Is6() || addr.Zone() != "" {
			return "", "", errLinkHost
		}
		host, rest = authority[:end+1], authority[end+1:]
		if rest != "" && rest[0] != ':' {
			return "", "", errLinkHost
		}
	} else if i := strings.IndexByte(authority, ':'); i >= 0 {
		host, rest = authority[:i], authority[i:]
	} else {
		host = authority
	}
	if host == "" {
		return "", "", errLinkHost
	}
	if rest != "" {
		port = rest[1:]
		if !validPort(port) {
			return "", "", errLinkPort
		}
	}
	return host, port, nil
}

func validPort(port string) bool {
	if port == "" || len(port) > 5 || port[0] == '0' {
		return false
	}
	for i := 0; i < len(port); i++ {
		if port[i] < '0' || port[i] > '9' {
			return false
		}
	}
	n, _ := strconv.Atoi(port)
	return n <= 65535
}

// effectivePort is the port a URL of the scheme reaches: the one written,
// or the scheme's default when none is.
func effectivePort(scheme, port string) int {
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

// queryAsWritten is whether a link's query is one the request line carries
// byte for byte: not empty, and of the characters RFC 3986 gives a query
// alone -- unreserved, sub-delims, ":", "@", "/" and "?" -- with a percent
// sign only as the start of an escape of two hex digits.
func queryAsWritten(query string) bool {
	if query == "" {
		return false
	}
	for i := 0; i < len(query); i++ {
		c := query[i]
		switch {
		case 'a' <= c && c <= 'z', 'A' <= c && c <= 'Z', '0' <= c && c <= '9':
		case strings.IndexByte("-._~!$&'()*+,;=:@/?", c) >= 0:
		case c == '%':
			if i+2 >= len(query) || !isHex(query[i+1]) || !isHex(query[i+2]) {
				return false
			}
			i += 2
		default:
			return false
		}
	}
	return true
}

func isHex(c byte) bool {
	return '0' <= c && c <= '9' || 'a' <= c && c <= 'f' || 'A' <= c && c <= 'F'
}

// formQuery is the query of a request's query object as sent: sorted by
// name and form-encoded as url.Values encodes it, but for "$", which is
// left as written -- an OData endpoint names its system options $top,
// $select, $filter, and RFC 3986 gives "$" a query unescaped. Every "%24"
// of the encoding is a "$": a percent sign written in the object is sent
// as "%25".
func formQuery(query map[string]string) string {
	values := url.Values{}
	for name, value := range query {
		values.Set(name, value)
	}
	return strings.ReplaceAll(values.Encode(), "%24", "$")
}
