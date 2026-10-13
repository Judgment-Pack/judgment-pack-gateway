package mcp

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"adapters/internal/canon"
	"adapters/internal/redact"
	"adapters/mcphttp"
)

// Version is what the adapter reports of itself in the receipt's adapter
// member when it reaches a remote server, beside the digest of its own
// executable, which is what pins it.
var Version = "0"

const (
	adapterName = "adapter-mcp"
	// maxOutputCeiling is the largest output bound the remote form takes:
	// past it the bounded read's sentinel byte would overflow, and a bound
	// that large is not a bound.
	maxOutputCeiling = 1 << 40
	// callOverhead is what a tool call's answer may hold beyond the result
	// the output bound holds: the JSON-RPC envelope, the framing of an event
	// stream (up to 64 events), and a server's comments and notifications
	// ahead of the response. The answer's whole body is read no further than
	// --max-output and this, and a result is then held to --max-output alone.
	callOverhead = 64 << 10
	// initializeLimit bounds the whole answer to initialize, which
	// --max-output does not bound: a name, a version, capabilities and the
	// server's instructions.
	initializeLimit = 1 << 20
	// listLimit bounds the whole answer to one page of tools/list, which
	// --max-output does not bound either; the pages together stay within
	// maxToolPages of it.
	listLimit = mcphttp.MaxResponse
	// maxBearer is the longest credential the client sends.
	maxBearer = 8192
)

// token68 is RFC 6750's form of a bearer token (§2.1, the b64token of
// RFC 7235's token68): letters, digits and "-._~+/", then "=" padding.
// Held to it, a credential holds no quote, backslash or control character,
// so the form a server could echo it in is the form it was sent in, and
// the client's refusal of an answer that repeats it finds it there.
var token68 = regexp.MustCompile(`^[A-Za-z0-9._~+/-]+=*$`)

var (
	headerName = regexp.MustCompile(`^[A-Za-z0-9!#$%&'*+.^_` + "`" + `|~-]+$`)
	// reservedHeaders are the request headers a fixed --header may not set:
	// a credential's (its place is the credentials file, not a command line
	// a process listing shows), the protocol's own, which the client keeps,
	// and the ones the client or the transport writes, which a fixed value
	// would silently lose to or fight with.
	reservedHeaders = map[string]string{
		"authorization": "a credential's", "proxy-authorization": "a credential's", "cookie": "a credential's",
		"mcp-session-id": "the protocol's", "mcp-protocol-version": "the protocol's", "last-event-id": "the protocol's",
		"content-type": "the client's", "accept": "the client's", "content-length": "the transport's", "host": "the transport's",
		"transfer-encoding": "the transport's", "connection": "the transport's", "accept-encoding": "the transport's",
	}
)

// remoteRefusal is why a configuration with a URL does not name one remote
// server to reach, or nil: the URL alone names the server, held as
// mcphttp.EndpointProblem holds it; a credentials file only with the member
// it sends; fixed headers only of names a header of the operator's may
// carry. Nothing is read here.
func (cfg Config) remoteRefusal() error {
	if cfg.Image != "" {
		return errors.New("--url and --image each name a server; exactly one of --image, --url and a server command after -- names it")
	}
	if len(cfg.Command) > 0 || len(cfg.Args) > 0 {
		return errors.New("a remote server given by --url takes no command and no arguments after --")
	}
	if cfg.Endpoint != "" {
		return errors.New("--endpoint names the host a server the adapter runs reaches; a remote server's endpoint is its --url, which the receipt records")
	}
	if err := mcphttp.EndpointProblem(cfg.URL); err != nil {
		return fmt.Errorf("--url: %v", err)
	}
	switch {
	case cfg.Credentials != "" && cfg.Bearer == "":
		return errors.New("a credentials file is given but --bearer names no member of it to send; a credentials file with no use is a mistake")
	case cfg.Bearer != "" && cfg.Credentials == "":
		return errors.New("--bearer names a member but no --credentials file is given")
	}
	if _, err := fixedHeaders(cfg.Headers); err != nil {
		return err
	}
	if cfg.MaxOutput > maxOutputCeiling {
		return fmt.Errorf("max-output is at most %d bytes", int64(maxOutputCeiling))
	}
	return nil
}

// stdioRefusal is why a configuration without a URL carries what only a
// remote server takes, or nil.
func (cfg Config) stdioRefusal() error {
	if cfg.Bearer != "" || len(cfg.Headers) > 0 || cfg.CAFile != "" {
		return errors.New("--bearer, --header and --ca-file are for a remote server, given by --url")
	}
	return nil
}

// fixedHeaders reads the operator's NAME=VALUE headers.
func fixedHeaders(pairs []string) (http.Header, error) {
	h := http.Header{}
	for _, pair := range pairs {
		name, value, ok := strings.Cut(pair, "=")
		if !ok || !headerName.MatchString(name) {
			return nil, fmt.Errorf("--header %q is not NAME=VALUE with a header name", pair)
		}
		if whose, reserved := reservedHeaders[strings.ToLower(name)]; reserved {
			return nil, fmt.Errorf("--header %s is %s and cannot be fixed", name, whose)
		}
		if strings.ContainsAny(value, "\r\n\x00") {
			return nil, fmt.Errorf("--header %s carries a value a header line cannot", name)
		}
		h.Add(name, value)
	}
	return h, nil
}

// bearerOf reads the credentials file as a JSON object of strings and
// returns the member --bearer names, with every value for redaction. No
// refusal names a member: a member's name may be another member's value.
func bearerOf(cfg Config) (token string, secrets []string, err error) {
	if cfg.Credentials == "" {
		return "", nil, nil
	}
	data, err := redact.ReadCredentials(cfg.Credentials)
	if err != nil {
		return "", nil, err
	}
	if _, err := canon.Canonicalize(data, canon.CarryNumbersAsText); err != nil {
		return "", nil, malformedCredentials(err)
	}
	members, err := exactMembers(data)
	if err != nil {
		return "", nil, errors.New("credentials file is not a JSON object of strings")
	}
	for _, raw := range members {
		if trimmed := bytes.TrimSpace(raw); len(trimmed) == 0 || trimmed[0] != '"' {
			return "", nil, errors.New("a credentials member is not a string")
		}
	}
	raw, ok := members[cfg.Bearer]
	if !ok {
		return "", nil, errors.New("the credentials file does not carry the member --bearer names")
	}
	if err := json.Unmarshal(raw, &token); err != nil {
		return "", nil, errors.New("a credentials member is not a string")
	}
	if len(token) > maxBearer || !token68.MatchString(token) {
		return "", nil, fmt.Errorf("the member --bearer names is not a bearer token of RFC 6750's form (token68: letters, digits and -._~+/, at least one, then = padding; at most %d bytes), so nothing is sent", maxBearer)
	}
	return token, redact.SecretsOf(data), nil
}

// ownIdentity is this adapter as the receipt names the program that
// fetched from a remote server: its name, its version, and the digest of
// its own executable.
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

// openRemote reads the credential and the roots, and opens the client a
// remote conversation goes through: nothing is sent yet. Each answer is
// read no further than its own limit, before any of it is parsed: a tool
// call's, the output bound and callOverhead; initialize's, initializeLimit;
// a page of the tool list's, listLimit, so a tool list longer than a small
// output bound is still read. The tool's result is held to the output bound
// after, as the stdio form holds it.
func openRemote(cfg Config) (*server, []string, error) {
	headers, err := fixedHeaders(cfg.Headers)
	if err != nil {
		return nil, nil, err
	}
	token, secrets, err := bearerOf(cfg)
	if err != nil {
		return nil, nil, err
	}
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12}
	if cfg.CAFile != "" {
		pem, err := os.ReadFile(cfg.CAFile)
		if err != nil {
			return nil, secrets, fmt.Errorf("--ca-file could not be read: %v", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, secrets, errors.New("--ca-file carries no certificate")
		}
		tlsConfig.RootCAs = pool
	}
	transport := &http.Transport{
		Proxy:                  http.ProxyFromEnvironment,
		TLSClientConfig:        tlsConfig,
		ForceAttemptHTTP2:      true,
		MaxResponseHeaderBytes: 64 << 10,
		TLSHandshakeTimeout:    10 * time.Second,
		DialContext:            (&net.Dialer{Timeout: 10 * time.Second}).DialContext,
	}
	identity, err := ownIdentity()
	if err != nil {
		return nil, secrets, err
	}
	client, err := mcphttp.Open(cfg.URL, mcphttp.Options{Token: token, Headers: headers, MaxResponse: cfg.MaxOutput + callOverhead,
		InitializeLimit: initializeLimit, ListLimit: listLimit, CallLimit: cfg.MaxOutput + callOverhead, Tools: cfg.Tools}, &http.Client{Transport: transport})
	if err != nil {
		return nil, secrets, err
	}
	closed := false
	stop := func() error {
		// The session ends with the conversation; a server that does not
		// answer the end of it is not waited on past a few seconds.
		if !closed {
			closed = true
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			client.Close(ctx)
			transport.CloseIdleConnections()
		}
		return nil
	}
	return &server{rpc: remoteConversation{client}, stop: stop, firstLine: func() string { return "" }, identity: identity, remote: client}, secrets, nil
}

// sessionSecret is secrets with a remote server's session id among them,
// once the server has issued one; secrets as they are otherwise.
func (s *server) sessionSecret(secrets []string) []string {
	if s.remote != nil {
		if session := s.remote.SessionID(); session != "" {
			return append(secrets, session)
		}
	}
	return secrets
}

// remoteConversation is the conversation over Streamable HTTP: the
// session id is the client's, sent on every request after initialize and
// recorded nowhere else; a tool call goes through the client's allowlist.
type remoteConversation struct{ client *mcphttp.Client }

func (r remoteConversation) call(ctx context.Context, method string, params any) (json.RawMessage, error) {
	if method == "tools/call" {
		call, _ := params.(map[string]any)
		name, _ := call["name"].(string)
		return r.client.CallTool(ctx, name, call["arguments"])
	}
	return r.client.Request(ctx, method, params)
}

func (r remoteConversation) initialized(ctx context.Context, protocol string) error {
	return r.client.Negotiated(ctx, protocol)
}
