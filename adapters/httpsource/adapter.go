// Package httpsource is the gateway's HTTP-shaped adapter: one bounded
// request over TLS to an endpoint the operator fixed -- a search
// provider's JSON API, a reader service that renders a page or a PDF as
// text, any resource a URL names -- with a credential this adapter holds,
// answering the envelope SPEC.md §6 states on stdout: the response as the
// result, and the acquisition as this adapter recorded it. It holds the
// endpoint's credentials and never the signing seed, and it imports
// nothing of the core module.
//
// What the receipt then records is byte lineage from the endpoint's
// answer: which endpoint, over which TLS identity, answered what, when. It
// says nothing about whether the answer is true, current, or the page
// its author meant: a reader service that rendered a page is the source
// of the bytes, and the page's own origin is what that service reports.
package httpsource

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"adapters/internal/canon"
	"adapters/internal/redact"
)

// Version is what the adapter reports of itself in the receipt's adapter
// member, beside the digest of its own executable, which is what pins it.
var Version = "0"

// Config is the operator's configuration of one adapter invocation, from
// the command line the gateway spawned it with.
type Config struct {
	// Endpoint is the base URL every request is sent under: https, or
	// http on a loopback host only. It carries no user, no query and no
	// fragment; a base path is allowed and the request's path follows it.
	Endpoint string
	// Credentials is the path of a JSON object of strings; empty for an
	// endpoint that needs none.
	Credentials string
	// Bearer names the credentials member sent as "Authorization: Bearer".
	Bearer string
	// CredentialHeader is NAME=MEMBER: the header NAME sent with the
	// credentials member MEMBER as its value, for an endpoint that takes
	// its key under its own header name.
	CredentialHeader string
	// Headers are NAME=VALUE pairs sent on every request as written: an
	// Accept, a format selector. A credential is not one of them.
	Headers []string
	// Paths are the only request paths this source may be asked for,
	// each exactly as it will be sent under the endpoint.
	Paths []string
	// Methods are the methods a request may name; POST alone when empty.
	Methods []string
	// MaxOutput bounds the envelope in bytes, and so the response body.
	MaxOutput int64
	// CAFile, when given, is a PEM file whose certificates are the only
	// roots trusted for the endpoint, instead of the system's.
	CAFile string
	// CheckPath, when given, is a path a check requests with GET; without
	// one a check establishes the endpoint's TLS identity and nothing more.
	CheckPath string
}

// Request is the canonical arguments the gateway hands the adapter on
// stdin: which path, by which method, with what query and body.
type Request struct {
	Path   string
	Method string
	Query  map[string]string
	Body   json.RawMessage
}

const (
	adapterName = "adapter-http"
	stampLayout = "2006-01-02T15:04:05Z"
	// maxRequestBytes bounds what is read from stdin, as the gateway
	// bounds what it sends.
	maxRequestBytes = 1 << 20
	// maxHeaderBytes bounds the endpoint's response header.
	maxHeaderBytes = 64 << 10
	// diagnosticBodyBytes is how much of a refusing answer's body is read
	// for the diagnostic that names it.
	diagnosticBodyBytes = 4 << 10
)

var (
	requestMembers = map[string]bool{"path": true, "method": true, "query": true, "body": true}
	// carriedHeaders are the response headers the result carries, by
	// their lowercase names: what says how the answer is encoded and
	// what the endpoint said about its currency, and nothing that could
	// carry a credential or a session back.
	carriedHeaders = []string{"cache-control", "content-length", "content-type", "date", "etag", "expires", "last-modified"}
	headerName     = regexp.MustCompile(`^[A-Za-z0-9!#$%&'*+.^_` + "`" + `|~-]+$`)
	// credentialHeaders are the request headers a fixed --header may not
	// set: a value there is a credential, and a credential's place is the
	// credentials file, not a command line a process listing shows.
	credentialHeaders = map[string]bool{"authorization": true, "proxy-authorization": true, "cookie": true}
	allowedMethods    = map[string]bool{"GET": true, "POST": true}
)

// ParseRequest reads the request strictly: one JSON object in the
// canonical domain, its members among path, method, query and body by
// their exact names, a path that begins at the endpoint, a method among
// GET and POST, a query of strings, and a body only where a POST carries
// one.
func ParseRequest(r io.Reader) (Request, error) {
	raw, err := io.ReadAll(io.LimitReader(r, maxRequestBytes+1))
	if err != nil {
		return Request{}, fmt.Errorf("request: %w", err)
	}
	if len(raw) > maxRequestBytes {
		return Request{}, fmt.Errorf("request exceeds %d bytes", maxRequestBytes)
	}
	// Held to the canonical domain first -- duplicate member names, a
	// number with a fraction, trailing content -- so that what is read
	// below is read once and the same way the gateway read it.
	canonical, err := canon.Canonicalize(raw, canon.RefuseNumbers)
	if err != nil {
		return Request{}, fmt.Errorf("request: %v", err)
	}
	// What is read from here on is the canonical text, so the body sent
	// and the statement committed to are one spelling whoever wrote the
	// request.
	members, err := exactMembers(canonical)
	if err != nil {
		return Request{}, errors.New("request: not a JSON object")
	}
	for name := range members {
		if !requestMembers[name] {
			return Request{}, fmt.Errorf("request: unknown member %q", name)
		}
	}
	var req Request
	pathRaw, ok := members["path"]
	if !ok {
		return Request{}, errors.New(`request: "path" is required`)
	}
	if err := json.Unmarshal(pathRaw, &req.Path); err != nil || !json.Valid(pathRaw) || pathRaw[0] != '"' {
		return Request{}, errors.New(`request: "path" must be a string`)
	}
	if err := pathProblem(req.Path); err != nil {
		return Request{}, fmt.Errorf("request: %v", err)
	}
	req.Method = http.MethodPost
	if methodRaw, ok := members["method"]; ok {
		if err := json.Unmarshal(methodRaw, &req.Method); err != nil || methodRaw[0] != '"' {
			return Request{}, errors.New(`request: "method" must be a string`)
		}
		if !allowedMethods[req.Method] {
			return Request{}, fmt.Errorf(`request: "method" must be GET or POST, spelled so; got %q`, req.Method)
		}
	}
	if queryRaw, ok := members["query"]; ok {
		pairs, err := exactMembers(queryRaw)
		if err != nil {
			return Request{}, errors.New(`request: "query" must be an object of strings`)
		}
		req.Query = map[string]string{}
		for name, value := range pairs {
			var s string
			if name == "" || len(value) == 0 || value[0] != '"' || json.Unmarshal(value, &s) != nil {
				return Request{}, errors.New(`request: "query" must be an object of strings with non-empty names`)
			}
			req.Query[name] = s
		}
	}
	if bodyRaw, ok := members["body"]; ok {
		if req.Method == http.MethodGet {
			return Request{}, errors.New("request: a GET carries no body")
		}
		req.Body = bodyRaw
	}
	return req, nil
}

// pathProblem is why a request path is not one to send, or nil: it names
// a resource under the endpoint and nothing else -- no query, no fragment,
// no dot segment, no empty segment, nothing a header line could carry.
func pathProblem(path string) error {
	switch {
	case path == "" || path[0] != '/':
		return errors.New(`"path" must begin with "/"`)
	case strings.ContainsAny(path, "?#\\"):
		return errors.New(`"path" carries a query, a fragment or a backslash`)
	case strings.ContainsAny(path, " \t\r\n\x00"):
		return errors.New(`"path" carries whitespace or a control character`)
	}
	for _, segment := range strings.Split(path[1:], "/") {
		if segment == "." || segment == ".." {
			return errors.New(`"path" carries a dot segment`)
		}
		if segment == "" && path != "/" {
			return errors.New(`"path" carries an empty segment`)
		}
	}
	for _, r := range path {
		if r < 0x20 || r == 0x7f {
			return errors.New(`"path" carries a control character`)
		}
	}
	return nil
}

// exactMembers reads an object by its members' exact names, refusing a
// name that appears twice: a decoder into a struct would let PATH stand in
// for path, and a second member overwrite the first.
func exactMembers(raw json.RawMessage) (map[string]json.RawMessage, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	tok, err := dec.Token()
	if err != nil {
		return nil, err
	}
	if delim, ok := tok.(json.Delim); !ok || delim != '{' {
		return nil, errors.New("not an object")
	}
	members := map[string]json.RawMessage{}
	for dec.More() {
		nameTok, err := dec.Token()
		if err != nil {
			return nil, err
		}
		name, ok := nameTok.(string)
		if !ok {
			return nil, errors.New("member name is not a string")
		}
		if _, dup := members[name]; dup {
			return nil, fmt.Errorf("member %q appears twice", name)
		}
		var value json.RawMessage
		if err := dec.Decode(&value); err != nil {
			return nil, err
		}
		members[name] = value
	}
	if _, err := dec.Token(); err != nil {
		return nil, err
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, errors.New("trailing content after the object")
	}
	return members, nil
}

// endpointOf parses and holds the endpoint: https, or http on a loopback
// host; no user, no query, no fragment.
func endpointOf(raw string) (*url.URL, error) {
	if raw == "" {
		return nil, errors.New("an endpoint is required")
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || u.Hostname() == "" {
		return nil, errors.New("the endpoint is not an absolute URL")
	}
	switch u.Scheme {
	case "https":
	case "http":
		if !isLoopback(u.Hostname()) {
			return nil, errors.New("the endpoint must be https; http is accepted on a loopback host only, since a credential sent in the clear is a credential given away")
		}
	default:
		return nil, errors.New("the endpoint must be an https URL")
	}
	if u.User != nil {
		return nil, errors.New("the endpoint carries a user: a credential's place is the credentials file")
	}
	if u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.RawFragment != "" {
		return nil, errors.New("the endpoint carries a query or a fragment; the request names those")
	}
	return u, nil
}

func isLoopback(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// fixedHeaders parses the operator's NAME=VALUE headers.
func fixedHeaders(pairs []string) (http.Header, error) {
	h := http.Header{}
	for _, pair := range pairs {
		name, value, ok := strings.Cut(pair, "=")
		if !ok || !headerName.MatchString(name) {
			return nil, fmt.Errorf("header %q is not NAME=VALUE with a header name", pair)
		}
		if credentialHeaders[strings.ToLower(name)] {
			return nil, fmt.Errorf("header %s is a credential's; it goes in the credentials file", name)
		}
		if strings.ContainsAny(value, "\r\n\x00") {
			return nil, fmt.Errorf("header %s carries a value a header line cannot", name)
		}
		h.Add(name, value)
	}
	return h, nil
}

// credentialsOf reads the credentials file as a JSON object of strings and
// returns the one member the configuration sends, with every value for
// redaction. Nothing here names a member in a refusal: a member's name may
// be another member's value.
func credentialsOf(cfg Config) (header, value string, secrets []string, err error) {
	member := cfg.Bearer
	header = "Authorization"
	if cfg.CredentialHeader != "" {
		if cfg.Bearer != "" {
			return "", "", nil, errors.New("one of --bearer and --credential-header names the credential, not both")
		}
		name, m, ok := strings.Cut(cfg.CredentialHeader, "=")
		if !ok || !headerName.MatchString(name) || m == "" {
			return "", "", nil, errors.New("--credential-header is NAME=MEMBER with a header name")
		}
		header, member = name, m
	}
	if member == "" {
		if cfg.Credentials != "" {
			return "", "", nil, errors.New("a credentials file is given but neither --bearer nor --credential-header names the member to send")
		}
		return "", "", nil, nil
	}
	if cfg.Credentials == "" {
		return "", "", nil, errors.New("a credential member is named but no --credentials file is given")
	}
	data, err := redact.ReadCredentials(cfg.Credentials)
	if err != nil {
		return "", "", nil, err
	}
	if _, err := canon.Canonicalize(data, canon.CarryNumbersAsText); err != nil {
		return "", "", nil, redact.MalformedCredentials(err)
	}
	members, err := exactMembers(data)
	if err != nil {
		return "", "", nil, errors.New("credentials file is not a JSON object of strings")
	}
	for _, raw := range members {
		if trimmed := bytes.TrimSpace(raw); len(trimmed) == 0 || trimmed[0] != '"' {
			return "", "", nil, errors.New("a credentials member is not a string")
		}
	}
	raw, ok := members[member]
	if !ok {
		return "", "", nil, errors.New("the credentials file does not carry the member the configuration sends")
	}
	if err := json.Unmarshal(raw, &value); err != nil {
		return "", "", nil, errors.New("a credentials member is not a string")
	}
	if value == "" || strings.ContainsAny(value, "\r\n\x00") {
		return "", "", nil, errors.New("the credential member has a value a header cannot carry")
	}
	if cfg.Bearer != "" {
		value = "Bearer " + value
	}
	return header, value, redact.SecretsOf(data), nil
}

// prepared is a configuration held to its rules, ready to send under.
type prepared struct {
	base      *url.URL
	headers   http.Header
	credName  string
	credValue string
	secrets   []string
	client    *http.Client
	identity  adapterIdentity
	loopback  bool
	transport *http.Transport
}

// prepare holds the configuration to its rules and reads the credentials,
// before any request is read or any connection made.
func prepare(cfg Config) (*prepared, error) {
	base, err := endpointOf(cfg.Endpoint)
	if err != nil {
		return nil, err
	}
	if len(cfg.Paths) == 0 {
		return nil, errors.New("--paths must name at least one path this source may request")
	}
	for _, p := range cfg.Paths {
		if err := pathProblem(p); err != nil {
			return nil, fmt.Errorf("--paths %q: %v", p, err)
		}
	}
	for _, m := range cfg.Methods {
		if !allowedMethods[m] {
			return nil, fmt.Errorf("--methods names %q; GET and POST are the methods", m)
		}
	}
	if cfg.MaxOutput < 1 {
		return nil, errors.New("max-output must be positive")
	}
	headers, err := fixedHeaders(cfg.Headers)
	if err != nil {
		return nil, err
	}
	credName, credValue, secrets, err := credentialsOf(cfg)
	if err != nil {
		return nil, err
	}
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12}
	if cfg.CAFile != "" {
		pem, err := os.ReadFile(cfg.CAFile)
		if err != nil {
			return nil, fmt.Errorf("--ca-file could not be read: %v", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, errors.New("--ca-file carries no certificate")
		}
		tlsConfig.RootCAs = pool
	}
	transport := &http.Transport{
		Proxy:                  http.ProxyFromEnvironment,
		TLSClientConfig:        tlsConfig,
		ForceAttemptHTTP2:      true,
		DisableKeepAlives:      true,
		MaxResponseHeaderBytes: maxHeaderBytes,
		TLSHandshakeTimeout:    10 * time.Second,
	}
	client := &http.Client{
		Transport: transport,
		// A redirect is an answer from another resource than the one the
		// operator fixed, and following one would carry the credential
		// there: it is reported, never followed.
		CheckRedirect: func(*http.Request, []*http.Request) error { return errRedirect },
	}
	identity, err := ownIdentity()
	if err != nil {
		return nil, err
	}
	return &prepared{base: base, headers: headers, credName: credName, credValue: credValue, secrets: secrets,
		client: client, identity: identity, loopback: base.Scheme == "http", transport: transport}, nil
}

var errRedirect = errors.New("the endpoint answered with a redirect, which is not followed")

// ownIdentity is this adapter as the receipt names the program that
// fetched: its name, its version, and the digest of its own executable.
func ownIdentity() (adapterIdentity, error) {
	exe, err := os.Executable()
	if err == nil {
		exe, err = filepath.EvalSymlinks(exe)
	}
	if err != nil {
		return adapterIdentity{}, fmt.Errorf("the adapter's own executable could not be located for its digest: %v", err)
	}
	file, err := os.Open(exe)
	if err != nil {
		return adapterIdentity{}, fmt.Errorf("the adapter's own executable could not be read for its digest: %v", err)
	}
	defer file.Close()
	h := sha256.New()
	if _, err := io.Copy(h, file); err != nil {
		return adapterIdentity{}, fmt.Errorf("the adapter's own executable could not be read for its digest: %v", err)
	}
	return adapterIdentity{Name: adapterName, Version: Version, Digest: "sha256:" + hex.EncodeToString(h.Sum(nil))}, nil
}

// build is the request as it will be sent: the path under the endpoint,
// the query sorted, the fixed headers, a JSON body, and the credential
// last.
func (p *prepared) build(ctx context.Context, cfg Config, req Request) (*http.Request, error) {
	if !contains(cfg.Paths, req.Path) {
		return nil, fmt.Errorf("path %q is not one this source may request: %v", req.Path, cfg.Paths)
	}
	methods := cfg.Methods
	if len(methods) == 0 {
		methods = []string{http.MethodPost}
	}
	if !contains(methods, req.Method) {
		return nil, fmt.Errorf("method %s is not one this source may use: %v", req.Method, methods)
	}
	target := *p.base
	target.Path = strings.TrimSuffix(p.base.Path, "/") + req.Path
	target.RawPath = ""
	if len(req.Query) > 0 {
		values := url.Values{}
		for name, value := range req.Query {
			values.Set(name, value)
		}
		target.RawQuery = values.Encode()
	}
	var body io.Reader
	if req.Body != nil {
		body = bytes.NewReader(req.Body)
	}
	out, err := http.NewRequestWithContext(ctx, req.Method, target.String(), body)
	if err != nil {
		return nil, fmt.Errorf("the request could not be formed: %v", err)
	}
	for name, values := range p.headers {
		out.Header[name] = append([]string(nil), values...)
	}
	if out.Header.Get("Accept") == "" {
		out.Header.Set("Accept", "application/json")
	}
	if req.Body != nil {
		out.Header.Set("Content-Type", "application/json")
		out.ContentLength = int64(len(req.Body))
	}
	out.Header.Set("User-Agent", "judgment-pack-adapter-http/"+Version)
	if p.credName != "" {
		out.Header.Set(p.credName, p.credValue)
	}
	return out, nil
}

// answer is what the endpoint returned, read whole and bounded.
type answer struct {
	status       int
	header       http.Header
	body         []byte
	peerIdentity *string
	observedAt   string
}

// send performs the request and reads the answer within the bound; the
// error it returns is not yet redacted.
func (p *prepared) send(ctx context.Context, cfg Config, req *http.Request) (*answer, error) {
	resp, err := p.client.Do(req)
	if err != nil {
		if ctx.Err() != nil {
			return nil, fmt.Errorf("the endpoint did not answer in time: %v", ctx.Err())
		}
		if errors.Is(err, errRedirect) {
			location := ""
			var uerr *url.Error
			if errors.As(err, &uerr) && uerr.URL != "" {
				location = " to " + uerr.URL
			}
			return nil, fmt.Errorf("%v%s", errRedirect, location)
		}
		return nil, fmt.Errorf("the endpoint could not be reached: %v", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, cfg.MaxOutput+1))
	if err != nil {
		if ctx.Err() != nil {
			return nil, fmt.Errorf("the endpoint did not answer in time: %v", ctx.Err())
		}
		return nil, fmt.Errorf("the answer could not be read whole: %v", err)
	}
	observedAt := time.Now().UTC().Truncate(time.Second).Format(stampLayout)
	if int64(len(body)) > cfg.MaxOutput {
		return nil, fmt.Errorf("the answer exceeds the output bound of %d bytes", cfg.MaxOutput)
	}
	a := &answer{status: resp.StatusCode, header: resp.Header, body: body, observedAt: observedAt}
	if resp.TLS != nil && len(resp.TLS.PeerCertificates) > 0 {
		sum := sha256.Sum256(resp.TLS.PeerCertificates[0].Raw)
		a.peerIdentity = ptr("tls:sha256:" + hex.EncodeToString(sum[:]))
	}
	return a, nil
}

// Acquire sends the one request and returns the envelope.
func Acquire(ctx context.Context, cfg Config, req Request) ([]byte, error) {
	p, err := prepare(cfg)
	if err != nil {
		return nil, err
	}
	// Every exit passes here: a diagnostic is redacted once and bounded
	// before it crosses the source boundary, where the gateway returns
	// it to whoever called /acquire.
	finish := func(out []byte, err error) ([]byte, error) {
		if err != nil {
			return nil, errors.New(redact.Diagnostic(err.Error(), false, p.secrets))
		}
		return out, nil
	}
	httpReq, err := p.build(ctx, cfg, req)
	if err != nil {
		return finish(nil, err)
	}
	a, err := p.send(ctx, cfg, httpReq)
	if err != nil {
		return finish(nil, err)
	}
	if a.status < 200 || a.status > 299 {
		// A refusal is a read that did not happen: nothing is minted for
		// it, and its first bytes say why, redacted, since an endpoint
		// may quote the credential it refused.
		head := a.body
		truncated := false
		if len(head) > diagnosticBodyBytes {
			head, truncated = head[:diagnosticBodyBytes], true
		}
		return nil, errors.New(redact.Diagnostic(fmt.Sprintf("the endpoint answered %d %s: %s", a.status, http.StatusText(a.status), strings.TrimSpace(string(head))), truncated, p.secrets))
	}
	result, err := resultOf(a)
	if err != nil {
		return finish(nil, err)
	}
	return finish(buildEnvelope(cfg, p, httpReq, req, a, result))
}

// resultOf carries the answer into the canon domain: its status, the
// headers the result carries, and its body -- as a JSON value when the
// endpoint said it sent JSON, held to the domain with any non-integer
// number carried as its literal text, and otherwise as base64, so a PDF
// or a page is carried byte for byte.
func resultOf(a *answer) ([]byte, error) {
	headers := map[string]string{}
	for _, name := range carriedHeaders {
		if values := a.header.Values(name); len(values) > 0 {
			headers[name] = strings.Join(values, ", ")
		}
	}
	mediaType, _, _ := mime.ParseMediaType(a.header.Get("Content-Type"))
	encoding := "base64"
	var body json.RawMessage
	if mediaType == "application/json" || mediaType == "text/json" || strings.HasSuffix(mediaType, "+json") {
		canonical, err := canon.Canonicalize(a.body, canon.CarryNumbersAsText)
		if err != nil {
			return nil, fmt.Errorf("the endpoint said it sent JSON, and the answer is not JSON in the canonical domain: %v", err)
		}
		encoding, body = "json", canonical
	} else {
		encoded, err := json.Marshal(base64.StdEncoding.EncodeToString(a.body))
		if err != nil {
			return nil, err
		}
		body = encoded
	}
	return canon.EncodeJSON(result{Status: a.status, Headers: headers, BodyEncoding: encoding, Body: body})
}

type result struct {
	Status       int               `json:"status"`
	Headers      map[string]string `json:"headers"`
	BodyEncoding string            `json:"bodyEncoding"`
	Body         json.RawMessage   `json:"body"`
}

type adapterIdentity struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Digest  string `json:"digest"`
}

type acquisition struct {
	Adapter       adapterIdentity `json:"adapter"`
	Endpoint      *string         `json:"endpoint"`
	Statement     *string         `json:"statement"`
	Snapshot      *string         `json:"snapshot"`
	PeerIdentity  *string         `json:"peerIdentity"`
	Schema        *string         `json:"schema"`
	UpstreamToken *string         `json:"upstreamToken"`
	ObservedAt    string          `json:"observedAt"`
}

type envelope struct {
	Acquisition acquisition     `json:"acquisition"`
	Result      json.RawMessage `json:"result"`
}

// statement is the request as the receipt commits to it: method, path,
// the query and the body as sent. It is the one member of the acquisition
// the gateway commits under a salt, so a search query or a page URL in
// it is in the receipt only as a commitment.
type statement struct {
	Method string            `json:"method"`
	Path   string            `json:"path"`
	Query  map[string]string `json:"query,omitempty"`
	Body   json.RawMessage   `json:"body,omitempty"`
}

// buildEnvelope is the envelope of SPEC.md §6 for one request: the answer
// as the result, and the acquisition as this adapter recorded it -- itself
// as the adapter, the URL it sent to (without the query, which the
// statement carries) as the endpoint, the request as the statement, the
// answer's ETag or, failing that, its Last-Modified as the snapshot, the
// TLS peer's certificate as the peer identity, and null for what an HTTP
// answer does not carry: a schema, an integrity token of the upstream's.
func buildEnvelope(cfg Config, p *prepared, sent *http.Request, req Request, a *answer, result []byte) ([]byte, error) {
	encoded, err := canon.EncodeJSON(statement{Method: req.Method, Path: req.Path, Query: req.Query, Body: req.Body})
	if err != nil {
		return nil, err
	}
	text, err := canon.Canonicalize(encoded, canon.RefuseNumbers)
	if err != nil {
		return nil, err
	}
	endpoint := *sent.URL
	endpoint.RawQuery, endpoint.ForceQuery = "", false
	acq := acquisition{
		Adapter:      p.identity,
		Endpoint:     ptr(endpoint.String()),
		Statement:    ptr(string(text)),
		PeerIdentity: a.peerIdentity,
		ObservedAt:   a.observedAt,
	}
	if etag := a.header.Get("ETag"); etag != "" {
		acq.Snapshot = ptr(etag)
	} else if modified := a.header.Get("Last-Modified"); modified != "" {
		acq.Snapshot = ptr(modified)
	}
	out, err := canon.EncodeJSON(envelope{Acquisition: acq, Result: json.RawMessage(result)})
	if err != nil {
		return nil, err
	}
	if int64(len(out)) > cfg.MaxOutput {
		return nil, fmt.Errorf("the envelope exceeds the output bound of %d bytes", cfg.MaxOutput)
	}
	return out, nil
}

// checkReport is what Check writes: the endpoint as the operator fixed it
// and the identity its TLS peer presented, and, where a check path was
// given, what that path answered. It is for the operator connecting a
// platform, and it is not an envelope: nothing is minted from it.
type checkReport struct {
	Status       string          `json:"status"`
	Adapter      adapterIdentity `json:"adapter"`
	Endpoint     string          `json:"endpoint"`
	PeerIdentity *string         `json:"peerIdentity"`
	Probe        *probeReport    `json:"probe,omitempty"`
}

type probeReport struct {
	Path   string `json:"path"`
	Status int    `json:"status"`
}

// FailedCheck is the report of a check that did not succeed, for stdout
// beside the exit status: the same member the success carries, so a
// caller reads one shape, and the reason as the adapter reported it,
// already redacted.
func FailedCheck(reason string) []byte {
	out, _ := canon.EncodeJSON(map[string]any{"check": map[string]string{"status": "failed", "message": reason}})
	return out
}

// Check holds the configuration and the credentials to their rules, then
// reaches the endpoint: with a check path, one GET of it, which must
// answer 2xx; without one, the TLS handshake alone, which establishes the
// peer's identity and nothing about the credential.
func Check(ctx context.Context, cfg Config) ([]byte, error) {
	p, err := prepare(cfg)
	if err != nil {
		return nil, err
	}
	report := checkReport{Status: "succeeded", Adapter: p.identity, Endpoint: p.base.String()}
	finish := func(err error) ([]byte, error) {
		return nil, errors.New(redact.Diagnostic(err.Error(), false, p.secrets))
	}
	if cfg.CheckPath != "" {
		if err := pathProblem(cfg.CheckPath); err != nil {
			return finish(fmt.Errorf("--check-path: %v", err))
		}
		probe := Config{Paths: []string{cfg.CheckPath}, Methods: []string{http.MethodGet}, MaxOutput: cfg.MaxOutput}
		req, err := p.build(ctx, probe, Request{Path: cfg.CheckPath, Method: http.MethodGet})
		if err != nil {
			return finish(err)
		}
		a, err := p.send(ctx, cfg, req)
		if err != nil {
			return finish(err)
		}
		if a.status < 200 || a.status > 299 {
			return finish(fmt.Errorf("the check path answered %d %s", a.status, http.StatusText(a.status)))
		}
		report.PeerIdentity = a.peerIdentity
		report.Probe = &probeReport{Path: cfg.CheckPath, Status: a.status}
	} else if !p.loopback {
		dialer := &tls.Dialer{NetDialer: &net.Dialer{}, Config: p.transport.TLSClientConfig.Clone()}
		host := p.base.Host
		if p.base.Port() == "" {
			host = net.JoinHostPort(p.base.Hostname(), "443")
		}
		conn, err := dialer.DialContext(ctx, "tcp", host)
		if err != nil {
			return finish(fmt.Errorf("the endpoint could not be reached: %v", err))
		}
		state := conn.(*tls.Conn).ConnectionState()
		conn.Close()
		if len(state.PeerCertificates) > 0 {
			sum := sha256.Sum256(state.PeerCertificates[0].Raw)
			report.PeerIdentity = ptr("tls:sha256:" + hex.EncodeToString(sum[:]))
		}
	}
	out, err := canon.EncodeJSON(map[string]any{"check": report})
	if err != nil {
		return nil, err
	}
	return out, nil
}

func contains(list []string, s string) bool {
	for _, item := range list {
		if item == s {
			return true
		}
	}
	return false
}

func ptr(s string) *string { return &s }
