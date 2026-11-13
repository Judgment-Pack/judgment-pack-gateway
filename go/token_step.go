package main

// A platform's token step (engineVersion 21, gateway #421,
// docs/adr/0027-an-http-source-obtains-its-token-by-a-client-assertion.md):
// an http live source whose credential is an access token adapter-http
// obtains from a token endpoint fixed here, by a client assertion it signs
// with a key held as a member of the platform's live credentials file, or
// by a federated identity token it reads from a file fixed here. The signer
// reads neither, nor the access token: it holds, per source, the token as
// adapter-http sealed it under a key only the platform's credential
// derives, hands it to the next acquisition, and drops it when the source
// refuses it.

import (
	"encoding/base64"
	"errors"
	"fmt"
	"os/exec"
	"regexp"
	"strings"
	"sync"
	"time"
)

// tokenStepConfig is credentials.live.tokenStep as written: nothing here is
// a secret. Exactly one of privateKey, the member of the live credentials
// file holding the key, and federatedTokenFile is set; x5t and x5tS256, at
// most one, only beside privateKey.
type tokenStepConfig struct {
	endpoint, clientID, privateKey, federatedTokenFile, x5t, x5tS256, requestScope string
}

var tokenStepMembers = map[string]bool{
	"endpoint": true, "clientId": true,
	"privateKey": false, "federatedTokenFile": false, "x5t": false, "x5t#S256": false, "requestScope": false,
}

var (
	// scopeTokenForm is RFC 6749 section 3.3's scope-token.
	scopeTokenForm = regexp.MustCompile(`^[\x21\x23-\x5b\x5d-\x7e]+$`)
	// base64urlForm is unpadded base64url, the form of a JOSE thumbprint.
	base64urlForm = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)
)

// parseTokenStep reads credentials.<op>.tokenStep: a version-21 member of
// the live operation's credentials alone, since the token is the credential
// an http live source sends and no other operation is served by the http
// shape; an endpoint of the endpoint form (https, or http at a loopback
// address written as one) with no placeholder; a client identifier of 1 to
// 256 printable ASCII characters without spaces; exactly one of privateKey,
// a credentials member's name, and federatedTokenFile, an absolute path; at
// most one of x5t (a SHA-1 thumbprint, base64url) and x5t#S256 (a SHA-256
// one), beside privateKey only; and requestScope, scope tokens separated by
// single spaces. A refusal names the member and repeats no value.
func parseTokenStep(v value, name, op, version string) (*tokenStepConfig, error) {
	where := "engine configuration: platform " + name + ": credentials." + op + ".tokenStep"
	if !versionAtLeast(version, "21") {
		return nil, fmt.Errorf("%s is a version-21 member; engineVersion %s has no tokenStep", where, version)
	}
	if op != "live" {
		return nil, fmt.Errorf("%s: a token step is taken by a live operation of the http shape alone; the %s operation's credentials are sent as its file holds them", where, op)
	}
	obj, err := requireObject(v, "tokenStep")
	if err != nil {
		return nil, fmt.Errorf("%s: %v", where, err)
	}
	if err := exactlyMembers(obj, tokenStepMembers, "platform "+name+" credentials."+op+".tokenStep"); err != nil {
		return nil, err
	}
	t := &tokenStepConfig{}
	if t.endpoint, err = requireString(obj, "endpoint"); err != nil || strings.ContainsAny(t.endpoint, "{}") || !isRemoteEndpoint(t.endpoint) {
		return nil, fmt.Errorf("%s: endpoint must be %s, and names no placeholder", where, remoteEndpointForm)
	}
	if t.clientID, err = requireString(obj, "clientId"); err != nil || len(t.clientID) > 256 || !visibleASCII(t.clientID) || t.clientID == "" {
		return nil, fmt.Errorf("%s: clientId is 1 to 256 printable ASCII characters without spaces", where)
	}
	_, hasKey := obj.get("privateKey")
	_, hasFederated := obj.get("federatedTokenFile")
	switch {
	case hasKey == hasFederated:
		return nil, fmt.Errorf("%s: exactly one of privateKey and federatedTokenFile is the assertion's credential", where)
	case hasKey:
		if t.privateKey, err = requireString(obj, "privateKey"); err != nil || t.privateKey == "" || !visibleASCII(t.privateKey) {
			return nil, fmt.Errorf("%s: privateKey names the live credentials member holding the key, in printable ASCII without spaces", where)
		}
	default:
		if t.federatedTokenFile, err = requireAbsolutePath(obj, "federatedTokenFile"); err != nil {
			return nil, fmt.Errorf("%s.%v", where, err)
		}
	}
	for _, thumb := range []struct {
		member string
		size   int
		into   *string
	}{{"x5t", 20, &t.x5t}, {"x5t#S256", 32, &t.x5tS256}} {
		if _, present := obj.get(thumb.member); !present {
			continue
		}
		if !hasKey {
			return nil, fmt.Errorf("%s: %s is a thumbprint for an assertion the adapter signs, beside privateKey", where, thumb.member)
		}
		s, err := requireString(obj, thumb.member)
		raw, decodeErr := base64.RawURLEncoding.DecodeString(s)
		if err != nil || !base64urlForm.MatchString(s) || decodeErr != nil || len(raw) != thumb.size {
			return nil, fmt.Errorf("%s: %s is the base64url, unpadded, of a %d-byte thumbprint", where, thumb.member, thumb.size)
		}
		*thumb.into = s
	}
	if t.x5t != "" && t.x5tS256 != "" {
		return nil, fmt.Errorf("%s: one of x5t and x5t#S256, not both", where)
	}
	if _, present := obj.get("requestScope"); present {
		t.requestScope, err = requireString(obj, "requestScope")
		valid := err == nil && t.requestScope != "" && len(t.requestScope) <= 1024
		for _, token := range strings.Split(t.requestScope, " ") {
			valid = valid && scopeTokenForm.MatchString(token)
		}
		if !valid {
			return nil, fmt.Errorf("%s: requestScope is at most 1024 bytes of scope tokens separated by single spaces (RFC 6749 section 3.3)", where)
		}
	}
	return t, nil
}

// tokenStepMatch holds a platform's token step to its binding: the binding's
// live operation is of the http shape, and sends its credential as the
// bearer, which is how an access token is sent; credentialHeader names a
// static credential's header, and a token sent under it would be sent as
// the binding does not state.
func tokenStepMatch(p platformConfig, b binding) error {
	if p.tokenStep == nil {
		return nil
	}
	if b.live == nil || b.live.http == nil {
		return fmt.Errorf("credentials.live names a tokenStep, and binding %s's live operation is not of the http shape, which alone takes one", p.binding)
	}
	if b.live.http.bearer == "" {
		return fmt.Errorf("credentials.live names a tokenStep, whose access token is sent as the bearer, and binding %s sends its credential under credentialHeader", p.binding)
	}
	return nil
}

// tokenStepArgv is adapter-http's command line for the token step, each
// flag and its value one word, in place of the binding's --bearer: the
// token is the bearer.
func tokenStepArgv(t *tokenStepConfig) []string {
	argv := []string{"--token-endpoint=" + t.endpoint, "--client-id=" + t.clientID}
	if t.privateKey != "" {
		argv = append(argv, "--assertion-key="+t.privateKey)
	} else {
		argv = append(argv, "--federated-token-file="+t.federatedTokenFile)
	}
	if t.x5t != "" {
		argv = append(argv, "--assertion-x5t="+t.x5t)
	}
	if t.x5tS256 != "" {
		argv = append(argv, "--assertion-x5t-s256="+t.x5tS256)
	}
	if t.requestScope != "" {
		argv = append(argv, "--token-scope="+t.requestScope)
	}
	return argv
}

// sealedTokenVariable is the environment variable adapter-http is handed a
// sealed token in (adapters/httpsource, SealedTokenVariable). A platform
// with a token step may not set it in its environment.
const sealedTokenVariable = "ADAPTER_HTTP_SEALED_TOKEN"

// The exit statuses adapter-http reports a token step's failure by
// (adapters/httpsource, TokenFailureKind).
const (
	tokenExitNoCredential     = 3
	tokenExitRefused          = 4
	tokenExitRejectedBySource = 5
	tokenExitSealUnusable     = 6
)

// The results of a token step that failed, each one fixed sentence naming
// the source and nothing the adapter wrote: no endpoint's answer, no
// token, no assertion, no key.
const (
	errTokenNoCredential = "source %s: the token step has no credential: the key or the federated token its configuration names is not there, or is not one it can authenticate with; no token was requested"
	errTokenRefused      = "source %s: the token endpoint refused the token request, or answered with no token the gateway takes"
	errTokenRejected     = "source %s: the source refused the access token the token step obtained; the token is dropped, and the request was not sent again"
	errTokenAnswer       = "source %s: the token step did not answer with a sealed token"
)

// tokenRefreshMargin is how long before its stated expiry a sealed token is
// obtained again; a token stating no longer lifetime than this, or none, is
// used for the one acquisition it was obtained for and not kept.
// adapter-http opens one until thirty seconds before its expiry, so the
// signer never hands in one the adapter would refuse for its time.
const tokenRefreshMargin = 60 * time.Second

// maxSealedToken bounds a sealed token as the adapter answers it.
const maxSealedToken = 64 << 10

// tokenKey is what a sealed token is kept under: the source, and the scope
// identifier its platform is fixed to. A token obtained for one source is
// never handed to another's.
type tokenKey struct{ source, scope string }

// tokenCache is the sealed tokens the signer holds, in memory and nowhere
// else, one per source. Its zero value is ready to use.
type tokenCache struct {
	mu      sync.Mutex
	entries map[tokenKey]*tokenEntry
	// now is the clock, for a test; nil is time.Now.
	now func() time.Time
}

// tokenEntry is one source's sealed token. flight is held while it is
// obtained, so concurrent acquisitions wait for one token request and do
// not each send their own.
type tokenEntry struct {
	flight    sync.Mutex
	sealed    string
	refreshAt time.Time
}

func (c *tokenCache) clock() time.Time {
	if c.now != nil {
		return c.now()
	}
	return time.Now()
}

func (c *tokenCache) entry(key tokenKey) *tokenEntry {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.entries == nil {
		c.entries = map[tokenKey]*tokenEntry{}
	}
	e := c.entries[key]
	if e == nil {
		e = &tokenEntry{}
		c.entries[key] = e
	}
	return e
}

// obtain is the source's sealed token: the one held, until the margin
// before its expiry, or else one fetch obtains, held when its lifetime is
// longer than the margin. One fetch runs at a time per source; whoever
// waited on it takes what it held.
func (c *tokenCache) obtain(key tokenKey, fetch func() (string, int, error)) (string, error) {
	e := c.entry(key)
	e.flight.Lock()
	defer e.flight.Unlock()
	if e.sealed != "" && c.clock().Before(e.refreshAt) {
		return e.sealed, nil
	}
	e.sealed = ""
	sealed, expiresIn, err := fetch()
	if err != nil {
		return "", err
	}
	if lifetime := time.Duration(expiresIn) * time.Second; lifetime > tokenRefreshMargin {
		e.sealed, e.refreshAt = sealed, c.clock().Add(lifetime-tokenRefreshMargin)
	}
	return sealed, nil
}

// drop forgets the source's sealed token when it is still the one given,
// so a token obtained since by another acquisition is kept.
func (c *tokenCache) drop(key tokenKey, sealed string) {
	e := c.entry(key)
	e.flight.Lock()
	defer e.flight.Unlock()
	if e.sealed == sealed {
		e.sealed = ""
	}
}

// sourceExited is a source that ran and exited with a status other than
// zero; its text is what runSource has always said of one.
type sourceExited struct {
	code int
	text string
}

func (e *sourceExited) Error() string { return e.text }

// exitCodeOf is the status a source exited with, or 0 when err is not of a
// source that exited.
func exitCodeOf(err error) int {
	var exited *sourceExited
	if errors.As(err, &exited) {
		return exited.code
	}
	return 0
}

// exitStatus is the status of a source's wait error, 0 when it carries
// none.
func exitStatus(waitErr error) int {
	var exit *exec.ExitError
	if errors.As(waitErr, &exit) && exit.ExitCode() > 0 {
		return exit.ExitCode()
	}
	return 0
}

// runAcquisitionSource runs an acquisition's source: as runSource for a
// source with no token step. With one, the source's sealed token is taken
// from the cache, or obtained by adapter-http --token-only as the
// platform's user, and handed to the acquisition. A token the source
// refused is dropped and the acquisition fails: sending the request again
// would be a second read of the source under one receipt. A sealed token
// the adapter could not open -- its credential renewed since -- is dropped
// and obtained once more, and the acquisition run once more; no request was
// sent the first time.
func (g *gatewayService) runAcquisitionSource(source string, spec sourceSpec, stdin []byte) (value, string, string, error) {
	if !spec.tokenStep {
		return g.runSource(source, spec, stdin)
	}
	key := tokenKey{source: source, scope: spec.scope}
	for attempt := 0; ; attempt++ {
		sealed, err := g.tokens.obtain(key, func() (string, int, error) { return g.obtainToken(source, spec) })
		if err != nil {
			return nil, "", "", err
		}
		run := spec
		run.env = append(append([]string(nil), spec.env...), sealedTokenVariable+"="+sealed)
		result, digest, observedAt, err := g.runSource(source, run, stdin)
		switch exitCodeOf(err) {
		case tokenExitRejectedBySource:
			g.tokens.drop(key, sealed)
			return nil, "", "", fmt.Errorf(errTokenRejected, source)
		case tokenExitSealUnusable:
			g.tokens.drop(key, sealed)
			if attempt == 0 {
				continue
			}
			return nil, "", "", fmt.Errorf(errTokenRefused, source)
		case tokenExitNoCredential:
			g.tokens.drop(key, sealed)
			return nil, "", "", fmt.Errorf(errTokenNoCredential, source)
		case tokenExitRefused:
			g.tokens.drop(key, sealed)
			return nil, "", "", fmt.Errorf(errTokenRefused, source)
		}
		return result, digest, observedAt, err
	}
}

// obtainToken runs adapter-http --token-only for the source, as the source
// is run, and reads its answer: exactly a sealed token and the lifetime the
// endpoint stated, null or 1 to 86400 seconds. A failure of the step is one
// of the fixed results; a source that could not start or did not finish is
// said as runSource says it.
func (g *gatewayService) obtainToken(source string, spec sourceSpec) (string, int, error) {
	run := spec
	run.argv = append(append([]string(nil), spec.argv...), "--token-only")
	result, _, _, err := g.runSource(source, run, nil)
	switch exitCodeOf(err) {
	case tokenExitNoCredential:
		return "", 0, fmt.Errorf(errTokenNoCredential, source)
	case tokenExitRefused, tokenExitRejectedBySource, tokenExitSealUnusable:
		return "", 0, fmt.Errorf(errTokenRefused, source)
	}
	if err != nil {
		return "", 0, err
	}
	answer, ok := result.(*vObject)
	if !ok || exactlyMembers(answer, map[string]bool{"sealed": true, "expiresIn": true}, "token step") != nil {
		return "", 0, fmt.Errorf(errTokenAnswer, source)
	}
	sealed, ok := memberString(answer, "sealed")
	if !ok || sealed == "" || len(sealed) > maxSealedToken || !base64urlForm.MatchString(sealed) {
		return "", 0, fmt.Errorf(errTokenAnswer, source)
	}
	expiresIn := 0
	raw, _ := answer.get("expiresIn")
	if _, isNull := raw.(vNull); !isNull {
		n, ok := raw.(vInt)
		if !ok || n < 1 || n > 86400 {
			return "", 0, fmt.Errorf(errTokenAnswer, source)
		}
		expiresIn = int(n)
	}
	return sealed, expiresIn, nil
}
