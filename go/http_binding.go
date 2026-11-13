package main

// A binding's live operation of the http shape (docs/adr/0024-an-http-source-in-the-engine.md,
// gateway #384): the engine derives `<platform>/live` as adapter-http, the
// adapter `serve --source-shape NAME=http` runs, started as every engine
// source is -- as the platform's OS user, under the source sandbox from
// engine version 13, with the platform's credentials file for live -- and
// receipted exactly as the plain form receipts it, since the signer reads
// the same envelope from the same program. The binding fixes the endpoint,
// the paths, the methods and the headers; an acquisition chooses a path
// and a method among them and gives the query and, by POST, the body, and
// names no other URL, header or credential.

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
)

// httpOperation is what adapter-http is started with for an http live
// operation, as the binding fixes it. Nothing here is a secret: the
// credential is a member of the platform's credentials file, which only the
// adapter reads.
type httpOperation struct {
	// endpoint is the base URL every request goes under, of the endpoint
	// form (SPEC.md §1.2a): https, or http to a loopback address written
	// as one.
	endpoint string
	// paths are the only request paths an acquisition may name, each
	// exactly as it is sent under the endpoint.
	paths []string
	// methods are the methods an acquisition may name, GET and POST; POST
	// alone when the binding names none, as the adapter's own default.
	methods []string
	// headers are NAME=VALUE pairs sent on every request, never a
	// credential's.
	headers []string
	// bearer is the credentials member sent as "Authorization: Bearer";
	// credentialHeader, NAME=MEMBER, the header that member is sent under
	// instead. Exactly one is set.
	bearer, credentialHeader string
	// checkPath is the path a check of the source GETs, or "": one of
	// paths, with GET among methods, so a check asks for nothing an
	// acquisition could not.
	checkPath string
}

// The bounds of an http operation, so a binding cannot grow the command
// line the engine builds without limit. maxHTTPPathsWord bounds the one
// word the paths are passed in, "--paths=" and the paths comma-joined:
// Linux with 4 KiB pages refuses to start a program given a word of 128
// KiB or more, its terminator counted, which 128 paths of 1024 bytes
// would pass, and a binding that loads would then never start.
const (
	maxHTTPPaths     = 128
	maxHTTPHeaders   = 32
	maxHTTPItem      = 1024 // bytes, of a path or a header
	maxHTTPPathsWord = 128<<10 - 1
)

// httpCredentialHeaders are the request headers adapter-http refuses as a
// fixed header, a value there being a credential; httpAdapterHeaders are
// those it writes itself. A binding naming one is refused before the engine
// starts rather than at every run.
var (
	httpCredentialHeaders = map[string]bool{"authorization": true, "proxy-authorization": true, "cookie": true}
	httpAdapterHeaders    = map[string]bool{"content-type": true, "content-length": true, "user-agent": true,
		"accept-encoding": true, "host": true, "transfer-encoding": true, "connection": true}
)

var httpOperationMembers = map[string]bool{
	"shape": true, "licence": true, "endpoint": true, "paths": true,
	"methods": false, "headers": false, "bearer": false, "credentialHeader": false, "checkPath": false,
}

// parseHTTPOperation holds an http operation to its shape: exactly the
// members above; an endpoint of the endpoint form, with no placeholder,
// since no platform parameter fills one here, and a path the adapter sends
// as written; paths each as adapter-http accepts a path and none with a
// comma, which would split into two on the adapter's command line, or a
// percent sign or any other character it would send escaped, and all of
// them within the
// one word of that command line they are passed in; methods GET and POST;
// headers an operator may fix; exactly one of bearer and credentialHeader,
// since the platform's credentials file for live is required and is read
// for that member alone; and a check path among the paths, by GET. A
// refusal names the member by its place and repeats no value.
func parseHTTPOperation(op *vObject, name string, o *operation) error {
	if err := exactlyMembers(op, httpOperationMembers, "operation "+name); err != nil {
		return err
	}
	h := &httpOperation{}
	var err error
	if h.endpoint, err = requireString(op, "endpoint"); err != nil || strings.ContainsAny(h.endpoint, "{}") || !isRemoteEndpoint(h.endpoint) {
		return fmt.Errorf("operation %s: endpoint must be %s, and names no placeholder", name, remoteEndpointForm)
	}
	if err := httpEndpointPathProblem(h.endpoint); err != nil {
		return fmt.Errorf("operation %s: endpoint's path %v", name, err)
	}
	if h.paths, err = httpStrings(op, "paths", name, maxHTTPPaths); err != nil {
		return err
	}
	for i, path := range h.paths {
		if err := httpPathProblem(path); err != nil {
			return fmt.Errorf("operation %s: paths[%d] %v", name, i, err)
		}
		for _, earlier := range h.paths[:i] {
			if earlier == path {
				return fmt.Errorf("operation %s: paths[%d] repeats an earlier path", name, i)
			}
		}
	}
	if len(httpPathsWord(h.paths)) > maxHTTPPathsWord {
		return fmt.Errorf("operation %s: paths must join, with commas, into one argument of adapter-http's command line under 128 KiB", name)
	}
	h.methods = []string{"POST"}
	if _, present := op.get("methods"); present {
		if h.methods, err = httpStrings(op, "methods", name, 2); err != nil {
			return err
		}
		for i, method := range h.methods {
			if method != "GET" && method != "POST" {
				return fmt.Errorf("operation %s: methods[%d] is neither GET nor POST", name, i)
			}
			if contains(h.methods[:i], method) {
				return fmt.Errorf("operation %s: methods[%d] repeats an earlier method", name, i)
			}
		}
	}
	_, hasBearer := op.get("bearer")
	_, hasHeader := op.get("credentialHeader")
	switch {
	case hasBearer == hasHeader:
		return fmt.Errorf("operation %s: exactly one of bearer and credentialHeader names the credentials member sent", name)
	case hasBearer:
		if h.bearer, err = requireString(op, "bearer"); err != nil || h.bearer == "" || !visibleASCII(h.bearer) {
			return fmt.Errorf("operation %s: bearer names the credentials member sent as the bearer, in printable ASCII without spaces", name)
		}
	default:
		value, err := requireString(op, "credentialHeader")
		header, member, isPair := strings.Cut(value, "=")
		if err != nil || !isPair || !remoteHeaderName.MatchString(header) || member == "" || !visibleASCII(member) {
			return fmt.Errorf("operation %s: credentialHeader is NAME=MEMBER, a header name and the credentials member sent under it", name)
		}
		// Proxy-Authorization is read by a proxy, not the endpoint: a
		// credential sent under it is sent to another host than the one
		// the binding fixes.
		if lower := strings.ToLower(header); httpAdapterHeaders[lower] || lower == "proxy-authorization" {
			return fmt.Errorf("operation %s: credentialHeader names %s, which is not a header the endpoint reads a credential from", name, header)
		}
		h.credentialHeader = value
	}
	if _, present := op.get("headers"); present {
		if h.headers, err = httpStrings(op, "headers", name, maxHTTPHeaders); err != nil {
			return err
		}
		seen := map[string]bool{}
		if h.credentialHeader != "" {
			header, _, _ := strings.Cut(h.credentialHeader, "=")
			seen[strings.ToLower(header)] = true
		}
		for i, pair := range h.headers {
			header, value, isPair := strings.Cut(pair, "=")
			if !isPair || !remoteHeaderName.MatchString(header) || value == "" || strings.TrimSpace(value) != value || !printableASCII(value) {
				return fmt.Errorf("operation %s: headers[%d] must be NAME=VALUE, a header name and a value of printable ASCII", name, i)
			}
			lower := strings.ToLower(header)
			if httpCredentialHeaders[lower] {
				return fmt.Errorf("operation %s: headers[%d] names %s, a credential's header; a credential's place is the credentials file", name, i, header)
			}
			if httpAdapterHeaders[lower] {
				return fmt.Errorf("operation %s: headers[%d] names %s, which adapter-http writes itself", name, i, header)
			}
			if seen[lower] {
				return fmt.Errorf("operation %s: headers[%d] names a header already named", name, i)
			}
			seen[lower] = true
		}
	}
	if _, present := op.get("checkPath"); present {
		if h.checkPath, err = requireString(op, "checkPath"); err != nil || !contains(h.paths, h.checkPath) {
			return fmt.Errorf("operation %s: checkPath, when present, is one of the operation's paths", name)
		}
		if !contains(h.methods, "GET") {
			return fmt.Errorf("operation %s: checkPath is requested by GET, which methods does not name", name)
		}
	}
	o.http = h
	return nil
}

// httpStrings is the member as a non-empty array of at most limit
// non-empty strings, each at most maxHTTPItem bytes.
func httpStrings(op *vObject, member, name string, limit int) ([]string, error) {
	raw, _ := op.get(member)
	items, ok := raw.(vArray)
	if !ok || len(items) == 0 || len(items) > limit {
		return nil, fmt.Errorf("operation %s: %s must be an array of 1 to %d strings", name, member, limit)
	}
	out := make([]string, 0, len(items))
	for i, item := range items {
		s, ok := item.(vString)
		if !ok || s == "" || len(s) > maxHTTPItem {
			return nil, fmt.Errorf("operation %s: %s[%d] must be a non-empty string of at most %d bytes", name, member, i, maxHTTPItem)
		}
		out = append(out, string(s))
	}
	return out, nil
}

// httpPathProblem holds a path to what adapter-http accepts as one -- it
// begins with "/", carries no query, fragment, backslash, dot segment or
// empty segment -- and to what the engine's command line carries as one:
// printable ASCII without a space, a comma or a percent sign, and no
// brace, which reads as a placeholder no parameter fills; and to what the
// adapter sends as written: no character its URL escaping would send
// percent-escaped (httpSentAsWritten). httpStrings has held it to be
// non-empty and bounded.
func httpPathProblem(path string) error {
	switch {
	case path[0] != '/':
		return errors.New(`must begin with "/"`)
	case !visibleASCII(path):
		return errors.New("must be printable ASCII without spaces")
	case strings.ContainsAny(path, `?#\`):
		return errors.New("carries a query, a fragment or a backslash")
	case strings.ContainsAny(path, ",%{}"):
		return errors.New("carries a comma, a percent sign or a brace")
	case !httpSentAsWritten(path):
		return errors.New(errHTTPEscapedPath)
	}
	for _, segment := range strings.Split(path[1:], "/") {
		if segment == "." || segment == ".." {
			return errors.New("carries a dot segment")
		}
		if segment == "" && path != "/" {
			return errors.New("carries an empty segment")
		}
	}
	return nil
}

// httpEndpointPathProblem holds the path of an endpoint of the endpoint
// form to what adapter-http sends as written: the adapter sends the path
// decoded and escaped again, so a percent sign is refused, as in paths,
// and so is any other character that escaping would send percent-escaped;
// and a dot segment or an empty segment, which a server or a proxy may
// resolve or merge, is refused but for the one "/" that may end the
// endpoint, which the adapter drops before the request's path.
func httpEndpointPathProblem(endpoint string) error {
	_, rest, _ := strings.Cut(endpoint, "://")
	_, path, _ := strings.Cut(rest, "/")
	if strings.Contains(path, "%") {
		return errors.New("carries a percent sign")
	}
	if !httpSentAsWritten("/" + path) {
		return errors.New(errHTTPEscapedPath)
	}
	segments := strings.Split(path, "/")
	for i, segment := range segments {
		if segment == "." || segment == ".." {
			return errors.New("carries a dot segment")
		}
		if segment == "" && i < len(segments)-1 {
			return errors.New("carries an empty segment")
		}
	}
	return nil
}

// errHTTPEscapedPath is the refusal of a path, or an endpoint's path, that
// httpSentAsWritten does not hold.
const errHTTPEscapedPath = "carries a character adapter-http would send percent-escaped, not as written"

// httpSentAsWritten is whether adapter-http sends path as written. The
// adapter sets a request's path, the endpoint's decoded path followed by
// the request's, and leaves its escaping to the URL package, which sends
// some printable characters percent-escaped: a path holding one is sent as
// other bytes than the binding states and the operator reviewed. The set
// is the URL package's, read here from the same escaping the adapter's
// request is formed with, not written out a second time.
func httpSentAsWritten(path string) bool {
	return (&url.URL{Path: path}).EscapedPath() == path
}

// visibleASCII is whether s is of U+0021 to U+007E alone; printableASCII
// admits the space too.
func visibleASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < 0x21 || s[i] > 0x7e {
			return false
		}
	}
	return true
}

func printableASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < 0x20 || s[i] > 0x7e {
			return false
		}
	}
	return true
}

// httpSourceArgv is adapter-http's command line for an http operation, each
// flag and its value one word: the endpoint, the paths and the methods the
// binding fixes, the platform's credentials file for live, the member sent
// and how -- or, with a token step, the step that obtains the token sent as
// the bearer -- and the fixed headers. The adapter's own bounds -- a 1 MiB
// envelope, a 20 second request -- lie inside the engine's on every source.
func httpSourceArgv(adapter string, op httpOperation, credentials string, token *tokenStepConfig) []string {
	argv := []string{adapter, "--endpoint=" + op.endpoint, httpPathsWord(op.paths), "--methods=" + strings.Join(op.methods, ","), "--credentials=" + credentials}
	if token != nil {
		// The token the step obtains is the bearer, in place of the member
		// the binding names (tokenStepMatch holds the binding to bearer).
		argv = append(argv, tokenStepArgv(token)...)
	} else if op.bearer != "" {
		argv = append(argv, "--bearer="+op.bearer)
	} else {
		argv = append(argv, "--credential-header="+op.credentialHeader)
	}
	for _, h := range op.headers {
		argv = append(argv, "--header="+h)
	}
	return argv
}

// httpPathsWord is the word of adapter-http's command line that carries
// the paths.
func httpPathsWord(paths []string) string {
	return "--paths=" + strings.Join(paths, ",")
}

// httpPlatformMatch refuses what a platform names that its http binding
// would leave unused, and so read as in force: a grant, since an http
// acquisition names no tool, so a delegation's scope admits none (SPEC.md
// §11.5, reason tool) and the grant would admit nothing; and an endpoint,
// since the binding fixes the endpoint and the receipt names the URL the
// adapter sent to. write: true, a decisionPolicy, writeRequesters,
// descriptors and parameters are refused where every binding without a
// write operation, a live MCP operation or a placeholder refuses them.
func httpPlatformMatch(p platformConfig, b binding) error {
	if b.live == nil || b.live.http == nil {
		return nil
	}
	if p.grant != nil {
		return fmt.Errorf("names a grant, and binding %s serves live by the http shape, whose acquisitions name no tool, so a delegation's scope admits none and the grant would admit nothing; remove grant", p.binding)
	}
	if p.endpoint != "" {
		return fmt.Errorf("names an endpoint, and binding %s serves live by the http shape, whose endpoint the binding fixes and the receipt names as the adapter sent to it; remove endpoint", p.binding)
	}
	return nil
}

// argumentValue is the value of the first flag=value word of argv that
// begins with prefix, up to any "--"; "" when there is none.
func argumentValue(argv []string, prefix string) string {
	for _, arg := range argv {
		if arg == "--" {
			break
		}
		if value, ok := strings.CutPrefix(arg, prefix); ok {
			return value
		}
	}
	return ""
}

// describeSourceCheck says what a derived source's check reported, in one
// line: an http source's by describeHTTPCheck, against the endpoint and
// the check path its command line was given; every other shape's by
// describeCheck.
func describeSourceCheck(spec sourceSpec, report []byte) (string, error) {
	if spec.shape == "http" {
		return describeHTTPCheck(report, argumentValue(spec.argv, "--endpoint="), argumentValue(spec.check, "--check-path="))
	}
	return describeCheck(spec.shape, report, remoteURL(spec.argv))
}

// describeHTTPCheck reads adapter-http's check report: the endpoint it
// names must be the one the source was given, a probe must be reported
// exactly when a check path was given, of that path and answered 2xx, and
// the line names the endpoint, the peer's identity when TLS gave one, and
// what the check path answered. A refusal names what it compares by role
// and repeats neither side.
func describeHTTPCheck(report []byte, endpoint, checkPath string) (string, error) {
	who, raw, err := checkedAdapter(report)
	if err != nil {
		return "", err
	}
	var check struct {
		Endpoint     string `json:"endpoint"`
		PeerIdentity string `json:"peerIdentity"`
		Probe        *struct {
			Path   string `json:"path"`
			Status int    `json:"status"`
		} `json:"probe"`
	}
	if err := json.Unmarshal(raw, &check); err != nil {
		return "", errors.New("the adapter's report is not a check report")
	}
	if endpoint == "" || check.Endpoint != endpoint {
		return "", errors.New("the endpoint the adapter reports is not the one the source was given")
	}
	line := who + ": endpoint " + endpoint
	if check.PeerIdentity != "" {
		line += ", peer " + requestText(check.PeerIdentity)
	}
	switch {
	case checkPath == "" && check.Probe != nil:
		return "", errors.New("the adapter reports a check path the source was not given")
	case checkPath == "":
		return line + "; reached", nil
	case check.Probe == nil || check.Probe.Path != checkPath:
		return "", errors.New("the adapter does not report the check path the source was given")
	case check.Probe.Status < 200 || check.Probe.Status > 299:
		return "", fmt.Errorf("the check path answered %d", check.Probe.Status)
	}
	return fmt.Sprintf("%s; GET %s answered %d", line, checkPath, check.Probe.Status), nil
}
