package main

// A platform's token step (engineVersion 21, gateway #421,
// docs/adr/0027-an-http-source-obtains-its-token-by-a-client-assertion.md):
// an http live source whose credential is an access token adapter-http
// obtains from a token endpoint fixed here, by a client assertion it signs
// with a key held as a member of the platform's live credentials file, or
// by a federated identity token it reads from a file fixed here, or, from
// metadataTokenVersion, asks of the platform's metadata server for an
// audience fixed here (ADR-0043), or, from delegatedTokenVersion, by a
// JWT-bearer assertion naming a delegated subject fixed here, which the
// service account credentials API signs (ADR-0045). The signer
// reads neither, nor the access token: it holds, per source, the token as
// adapter-http sealed it under a key only the platform's credential
// derives, hands it to the next acquisition, and drops it when the source
// refuses it.

import (
	"context"
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
// file holding the key, federatedTokenFile, and metadataAudience, the
// audience of federatedToken {"kind": "metadata"}, is set; x5t and x5tS256,
// at most one, only beside privateKey.
type tokenStepConfig struct {
	endpoint, clientID, privateKey, federatedTokenFile, metadataAudience, x5t, x5tS256, requestScope string
	// serviceAccount and subject are signedBy's service account and the
	// assertion's subject (ADR-0045); set together, and with no clientId,
	// no other credential and no thumbprint beside them.
	serviceAccount, subject string
	// federatedTokenDir is not written: it is the directory federatedTokenFile
	// is named in, as engineRefusals resolved it, which the adapter finds
	// the file again under at each token request.
	federatedTokenDir string
	// assertionAlgorithm is "RS256" or "PS256", beside privateKey alone,
	// from assertionAlgorithmVersion (ADR-0027, amendment #513); empty, the
	// algorithm is the key's, as before.
	assertionAlgorithm string
}

var tokenStepMembers = map[string]bool{
	"endpoint": true, "clientId": true,
	"privateKey": false, "federatedTokenFile": false, "federatedToken": false, "x5t": false, "x5t#S256": false, "requestScope": false,
	"assertionAlgorithm": false,
}

// metadataTokenVersion is the engine configuration version that admits
// tokenStep.federatedToken (ADR-0043): 32, the version after the
// path-template change (31, ADR-0040). engine.go lists it in
// engineVersions, so a merge that keeps both changes' versions without
// renumbering it does not compile (a duplicate key in that map).
const metadataTokenVersion = "32"

// delegatedTokenVersion is the engine configuration version that admits
// tokenStep.signedBy and tokenStep.subject (ADR-0045), and a binding path's
// {numericId} and {alnumId} placeholders: 33, the version after the
// metadata token (32, ADR-0043). engine.go lists it in engineVersions.
const delegatedTokenVersion = "33"

// assertionAlgorithmVersion is the engine configuration version that admits
// tokenStep.assertionAlgorithm (ADR-0027, amendment #513): 34, the version
// after the delegated subject (33, ADR-0045). engine.go reads this constant
// as the newest version.
const assertionAlgorithmVersion = "34"

// assertionAlgorithms are tokenStep.assertionAlgorithm's values: the two an
// RSA key signs. ES256 is not one: a P-256 key gives it, and nothing else
// may.
var assertionAlgorithms = map[string]bool{"RS256": true, "PS256": true}

// signedByCredentialsAPI is signedBy's one kind: the service account
// credentials API, at the address adapter-http has built in.
const signedByCredentialsAPI = "credentials-api"

var (
	// serviceAccountForm is a service account's address under a project's
	// iam.gserviceaccount.com domain: a name and a project of 6 to 30 lowercase letters, digits and hyphens,
	// each starting with a letter and not ending with a hyphen. It refuses
	// the default compute and App Engine accounts, whose addresses are of
	// other forms. It enters the credentials API's path, and admits no
	// / % ? # or :.
	serviceAccountForm = regexp.MustCompile(`^[a-z][a-z0-9-]{4,28}[a-z0-9]@[a-z][a-z0-9-]{4,28}[a-z0-9]\.iam\.gserviceaccount\.com$`)
	// subjectForm is the delegated subject's address: a local part of 1 to
	// 64 letters, digits and . _ + -, and a domain of dot-separated labels
	// of letters, digits and hyphens; at most 254 bytes in all.
	subjectForm = regexp.MustCompile(`^[A-Za-z0-9._+-]{1,64}@[A-Za-z0-9-]{1,63}(\.[A-Za-z0-9-]{1,63})+$`)
)

// delegatedScopes are the scopes a token step signed by the credentials API
// may ask for: the Admin SDK's read-only scopes the catalog's Workspace
// bindings read under, and no other. admin.directory.user.security is not
// among them: it also deletes a user's tokens and signs a user out.
var delegatedScopes = map[string]bool{
	"https://www.googleapis.com/auth/admin.directory.user.readonly":           true,
	"https://www.googleapis.com/auth/admin.directory.group.readonly":          true,
	"https://www.googleapis.com/auth/admin.directory.group.member.readonly":   true,
	"https://www.googleapis.com/auth/admin.directory.rolemanagement.readonly": true,
	"https://www.googleapis.com/auth/admin.reports.audit.readonly":            true,
}

// delegatedTokenStepMembers are a signedBy step's members, every one
// required: no clientId, since the JWT-bearer grant authenticates no client
// and the assertion's iss is the service account, and no thumbprint, since
// the adapter signs nothing.
var delegatedTokenStepMembers = map[string]bool{"endpoint": true, "signedBy": true, "subject": true, "requestScope": true}

// federatedTokenMetadata is federatedToken's one kind: the platform's
// metadata server, at the address adapter-http has built in.
const federatedTokenMetadata = "metadata"

// audienceForm is a metadata identity token's audience: 1 to 256 ASCII
// letters, digits and . _ ~ : / @ -, as adapter-http holds it, so it can
// add no query member to the request it is sent in.
var audienceForm = regexp.MustCompile(`^[A-Za-z0-9._~:/@-]{1,256}$`)

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
// a credentials member's name, federatedTokenFile, an absolute path, and,
// from metadataTokenVersion, federatedToken (parseFederatedToken); at
// most one of x5t (a SHA-1 thumbprint, base64url) and x5t#S256 (a SHA-256
// one), beside privateKey only; from assertionAlgorithmVersion,
// assertionAlgorithm, "RS256" or "PS256", beside privateKey only; and
// requestScope, scope tokens separated by single spaces. A refusal names the
// member and repeats no value.
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
	if _, delegated := obj.get("signedBy"); delegated {
		if !versionAtLeast(version, delegatedTokenVersion) {
			return nil, fmt.Errorf("%s.signedBy is a version-%s member; engineVersion %s has no signedBy", where, delegatedTokenVersion, version)
		}
		return parseDelegatedTokenStep(obj, where, "platform "+name+" credentials."+op+".tokenStep")
	}
	if err := exactlyMembers(obj, tokenStepMembers, "platform "+name+" credentials."+op+".tokenStep"); err != nil {
		return nil, err
	}
	_, hasAlgorithm := obj.get("assertionAlgorithm")
	if hasAlgorithm && !versionAtLeast(version, assertionAlgorithmVersion) {
		return nil, fmt.Errorf("%s.assertionAlgorithm is a version-%s member; engineVersion %s has no assertionAlgorithm", where, assertionAlgorithmVersion, version)
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
	metadata, hasMetadata := obj.get("federatedToken")
	if hasMetadata && !versionAtLeast(version, metadataTokenVersion) {
		return nil, fmt.Errorf("%s.federatedToken is a version-%s member; engineVersion %s has no federatedToken", where, metadataTokenVersion, version)
	}
	switch {
	case !hasMetadata && !hasKey && !hasFederated && versionAtLeast(version, delegatedTokenVersion):
		return nil, fmt.Errorf("%s: exactly one of privateKey, federatedTokenFile, federatedToken and signedBy is the assertion's credential", where)
	case hasMetadata && (hasKey || hasFederated), !hasMetadata && !hasKey && !hasFederated && versionAtLeast(version, metadataTokenVersion):
		return nil, fmt.Errorf("%s: exactly one of privateKey, federatedTokenFile and federatedToken is the assertion's credential", where)
	case hasMetadata:
		if t.metadataAudience, err = parseFederatedToken(metadata, where); err != nil {
			return nil, err
		}
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
	if hasAlgorithm {
		if !hasKey {
			return nil, fmt.Errorf("%s: assertionAlgorithm is the algorithm of an assertion the adapter signs, beside privateKey", where)
		}
		s, err := requireString(obj, "assertionAlgorithm")
		if err != nil || !assertionAlgorithms[s] {
			return nil, fmt.Errorf("%s: assertionAlgorithm is \"RS256\" or \"PS256\"", where)
		}
		t.assertionAlgorithm = s
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

// parseFederatedToken reads tokenStep.federatedToken: an object of exactly
// kind, "metadata" alone, and audience, in audienceForm. No member names an
// address: adapter-http has the metadata server's built in. A refusal
// names the member and repeats no value.
func parseFederatedToken(v value, where string) (string, error) {
	where += ".federatedToken"
	obj, err := requireObject(v, "federatedToken")
	if err != nil {
		return "", fmt.Errorf("%s: %v", where, err)
	}
	if err := exactlyMembers(obj, map[string]bool{"kind": true, "audience": true}, where); err != nil {
		return "", err
	}
	if kind, ok := memberString(obj, "kind"); !ok || kind != federatedTokenMetadata {
		return "", fmt.Errorf("%s: kind is %q, the platform's metadata server, at the address adapter-http has built in", where, federatedTokenMetadata)
	}
	if audience, ok := memberString(obj, "audience"); ok && audienceForm.MatchString(audience) {
		return audience, nil
	}
	return "", fmt.Errorf("%s: audience is 1 to 256 ASCII letters, digits and the characters . _ ~ : / @ -", where)
}

// parseDelegatedTokenStep reads a token step of the signedBy form
// (ADR-0045): exactly endpoint, of the endpoint form with no placeholder;
// signedBy, an object of exactly kind, "credentials-api" alone, and
// serviceAccount, in serviceAccountForm; subject, in subjectForm; and
// requestScope, one or more of delegatedScopes, each once, separated by
// single spaces. No other credential, no clientId and no thumbprint stands
// beside it. A refusal names the member and repeats no value.
func parseDelegatedTokenStep(obj *vObject, where, what string) (*tokenStepConfig, error) {
	for _, other := range []string{"privateKey", "federatedTokenFile", "federatedToken"} {
		if _, present := obj.get(other); present {
			return nil, fmt.Errorf("%s: exactly one of privateKey, federatedTokenFile, federatedToken and signedBy is the assertion's credential", where)
		}
	}
	if _, present := obj.get("clientId"); present {
		return nil, fmt.Errorf("%s: clientId is not given beside signedBy: the JWT-bearer grant authenticates no client, and the assertion's iss is the service account", where)
	}
	if err := exactlyMembers(obj, delegatedTokenStepMembers, what); err != nil {
		return nil, err
	}
	t := &tokenStepConfig{}
	var err error
	if t.endpoint, err = requireString(obj, "endpoint"); err != nil || strings.ContainsAny(t.endpoint, "{}") || !isRemoteEndpoint(t.endpoint) {
		return nil, fmt.Errorf("%s: endpoint must be %s, and names no placeholder", where, remoteEndpointForm)
	}
	signedBy, _ := obj.get("signedBy")
	signer, err := requireObject(signedBy, "signedBy")
	if err != nil {
		return nil, fmt.Errorf("%s.signedBy: %v", where, err)
	}
	if err := exactlyMembers(signer, map[string]bool{"kind": true, "serviceAccount": true}, where+".signedBy"); err != nil {
		return nil, err
	}
	if kind, ok := memberString(signer, "kind"); !ok || kind != signedByCredentialsAPI {
		return nil, fmt.Errorf("%s.signedBy: kind is %q, the service account credentials API, at the address adapter-http has built in", where, signedByCredentialsAPI)
	}
	if account, ok := memberString(signer, "serviceAccount"); ok && serviceAccountForm.MatchString(account) {
		t.serviceAccount = account
	} else {
		return nil, fmt.Errorf("%s.signedBy: serviceAccount is NAME@PROJECT.iam.gserviceaccount.com, NAME and PROJECT each 6 to 30 lowercase letters, digits and hyphens, starting with a letter and not ending with a hyphen", where)
	}
	if subject, ok := memberString(obj, "subject"); ok && len(subject) <= 254 && subjectForm.MatchString(subject) {
		t.subject = subject
	} else {
		return nil, fmt.Errorf("%s: subject is an address of at most 254 bytes: 1 to 64 letters, digits and . _ + -, an @, and a domain of dot-separated labels of letters, digits and hyphens", where)
	}
	scope, ok := memberString(obj, "requestScope")
	seen := map[string]bool{}
	for _, token := range strings.Split(scope, " ") {
		ok = ok && delegatedScopes[token] && !seen[token]
		seen[token] = true
	}
	if !ok {
		return nil, fmt.Errorf("%s: requestScope is one or more of the Admin SDK's read-only scopes ADR-0045 lists, each once, separated by single spaces", where)
	}
	t.requestScope = scope
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
	if t.serviceAccount != "" {
		return []string{"--token-endpoint=" + t.endpoint, "--signed-by-service-account=" + t.serviceAccount, "--token-subject=" + t.subject, "--token-scope=" + t.requestScope}
	}
	argv := []string{"--token-endpoint=" + t.endpoint, "--client-id=" + t.clientID}
	if t.privateKey != "" {
		argv = append(argv, "--assertion-key="+t.privateKey)
		if t.assertionAlgorithm != "" {
			argv = append(argv, "--assertion-alg="+t.assertionAlgorithm)
		}
	} else if t.metadataAudience != "" {
		argv = append(argv, "--federated-token-metadata-audience="+t.metadataAudience)
	} else {
		argv = append(argv, "--federated-token-file="+t.federatedTokenFile)
		if t.federatedTokenDir != "" {
			argv = append(argv, "--federated-token-dir="+t.federatedTokenDir)
		}
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
	// errTokenRequestNotAdmitted is a request naming a path, a link or a
	// method the source's operation does not allow, refused before a token
	// is obtained for it. It names nothing of the request.
	errTokenRequestNotAdmitted = "source %s: the request does not name a path and a method the source's operation allows; no token was requested"
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
	// mu guards entries and every entry's members.
	mu      sync.Mutex
	entries map[tokenKey]*tokenEntry
	// now is the clock, for a test; nil is time.Now.
	now func() time.Time
}

// tokenEntry is one source's sealed token, and the token request in
// progress for it, nil when none is: concurrent acquisitions wait for that
// one request and do not each send their own.
type tokenEntry struct {
	sealed    string
	refreshAt time.Time
	flight    *tokenFlight
}

// tokenFlight is one token request. done is closed when it has ended; err
// is then why it failed, nil when it obtained a token.
type tokenFlight struct {
	done chan struct{}
	err  error
}

// errTokenFlightEnded is what the acquisitions waiting on a token request
// are told when the request ended without a result, its fetch having
// panicked.
var errTokenFlightEnded = errors.New("the token step ended without a result")

func (c *tokenCache) clock() time.Time {
	if c.now != nil {
		return c.now()
	}
	return time.Now()
}

// entryLocked is the key's entry, made when there is none; c.mu is held.
func (c *tokenCache) entryLocked(key tokenKey) *tokenEntry {
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
// longer than the margin. One fetch runs at a time per source. Whoever
// waited on it takes the token it held; when it failed, each of them is
// told its failure and none fetches again, so a token endpoint that hangs
// or refuses costs the acquisitions waiting one token request, not one
// each in turn. A later acquisition, which did not wait on that one, tries
// again. Waiting ends with ctx, whose error is then returned.
func (c *tokenCache) obtain(ctx context.Context, key tokenKey, fetch func() (string, int, error)) (string, error) {
	for {
		c.mu.Lock()
		e := c.entryLocked(key)
		if e.sealed != "" && c.clock().Before(e.refreshAt) {
			sealed := e.sealed
			c.mu.Unlock()
			return sealed, nil
		}
		if f := e.flight; f != nil {
			c.mu.Unlock()
			select {
			case <-f.done:
			case <-ctx.Done():
				return "", ctx.Err()
			}
			if f.err != nil {
				return "", f.err
			}
			// It obtained a token: held, or, one not kept, of the one use
			// it was obtained for. Look again.
			continue
		}
		f := &tokenFlight{done: make(chan struct{})}
		e.sealed, e.flight = "", f
		c.mu.Unlock()
		return c.fly(e, f, fetch)
	}
}

// fly runs the fetch of the flight f for the entry e, and ends the flight
// with its result, whatever the fetch does.
func (c *tokenCache) fly(e *tokenEntry, f *tokenFlight, fetch func() (string, int, error)) (sealed string, err error) {
	expiresIn := 0
	err = errTokenFlightEnded
	defer func() {
		c.mu.Lock()
		e.flight, f.err = nil, err
		if lifetime := time.Duration(expiresIn) * time.Second; err == nil && lifetime > tokenRefreshMargin {
			e.sealed, e.refreshAt = sealed, c.clock().Add(lifetime-tokenRefreshMargin)
		}
		c.mu.Unlock()
		close(f.done)
	}()
	sealed, expiresIn, err = fetch()
	if err != nil {
		return "", err
	}
	return sealed, nil
}

// drop forgets the source's sealed token when it is still the one given,
// so a token obtained since by another acquisition is kept.
func (c *tokenCache) drop(key tokenKey, sealed string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if e := c.entryLocked(key); e.sealed == sealed {
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
//
// A request naming a path or a method the source's operation does not
// allow is refused before anything runs, as the adapter would refuse it,
// so it costs the token endpoint nothing. The source's one timeout bounds
// the whole acquisition -- the wait for a token request, the token
// request, the source, and the run once more -- as it bounds one run of a
// source with no token step, so what /acquire and the MCP side's forward
// bound (mcpForwardTimeout) are sized for holds here too.
func (g *gatewayService) runAcquisitionSource(source string, spec sourceSpec, stdin []byte) (value, string, string, error) {
	// A gcp-asset source's adapter obtains its own tokens, and the signer
	// holds the list token as for a token step (gcp_asset_binding.go).
	if spec.gcpAsset != nil {
		return g.runGCPAssetSource(source, spec, stdin)
	}
	if !spec.tokenStep {
		return g.runSource(source, spec, stdin)
	}
	if err := tokenStepAdmits(source, spec, stdin); err != nil {
		return nil, "", "", err
	}
	ctx, timeout, cancel := g.sourceRunContext(source, spec)
	defer cancel()
	key := tokenKey{source: source, scope: spec.scope}
	for attempt := 0; ; attempt++ {
		sealed, err := g.tokens.obtain(ctx, key, func() (string, int, error) { return g.obtainToken(ctx, timeout, source, spec) })
		if err != nil {
			if ctx.Err() != nil && errors.Is(err, ctx.Err()) {
				// The deadline passed while it waited on another's token
				// request.
				err = acquisitionEnded(ctx, timeout)
			}
			return nil, "", "", err
		}
		run := spec
		run.env = append(append([]string(nil), spec.env...), sealedTokenVariable+"="+sealed)
		result, digest, observedAt, err := g.runOnce(ctx, timeout, source, run, stdin)
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

// acquisitionEnded is the failure of an acquisition whose context ended
// before a run of it began, nil while it has not: past its deadline, said
// as a source that did not finish within its timeout is; otherwise, the
// gateway stopping, as a source that could not be started.
func acquisitionEnded(ctx context.Context, timeout time.Duration) error {
	switch err := ctx.Err(); {
	case err == nil:
		return nil
	case errors.Is(err, context.DeadlineExceeded):
		return sourceTimeoutError(timeout)
	default:
		return &sourceNotStarted{fmt.Errorf("source could not be started: %v", err)}
	}
}

// runOnce is one run of a token step's acquisition under the acquisition's
// context, ended by an overflow of its output alone.
func (g *gatewayService) runOnce(ctx context.Context, timeout time.Duration, source string, spec sourceSpec, stdin []byte) (value, string, string, error) {
	if err := acquisitionEnded(ctx, timeout); err != nil {
		return nil, "", "", err
	}
	run, cancel := context.WithCancel(ctx)
	defer cancel()
	return g.runSourceUnder(run, cancel, timeout, source, spec, stdin)
}

// tokenStepAdmits holds a token step's request to its operation's
// endpoint, paths and methods, as adapter-http holds it
// (http_request_target.go): an object naming exactly one of a path, a
// string the paths admit -- one of them, or a template's with a GUID for
// its {id} -- with a query, when it gives one, of strings, and a link, a
// string under the endpoint whose path the paths admit, with no query
// beside it; and a method, POST when it names none, among the methods.
// Anything else is refused by one fixed sentence, before a token is
// obtained for it.
func tokenStepAdmits(source string, spec sourceSpec, stdin []byte) error {
	refused := fmt.Errorf(errTokenRequestNotAdmitted, source)
	args, err := parseJSON(stdin)
	if err != nil {
		return refused
	}
	request, ok := args.(*vObject)
	if !ok {
		return refused
	}
	_, hasPath := request.get("path")
	_, hasLink := request.get("link")
	switch {
	case hasPath == hasLink:
		return refused
	case hasLink:
		link, ok := memberString(request, "link")
		_, hasQuery := request.get("query")
		if !ok || hasQuery || !httpLinkAdmitted(spec.requestEndpoint, spec.requestPaths, link) {
			return refused
		}
	default:
		path, ok := memberString(request, "path")
		if !ok || !httpPathAdmitted(spec.requestPaths, path) || !httpQueryObject(request) {
			return refused
		}
	}
	method := "POST"
	if _, present := request.get("method"); present {
		if method, ok = memberString(request, "method"); !ok {
			return refused
		}
	}
	if !contains(spec.requestMethods, method) {
		return refused
	}
	return nil
}

// obtainToken runs adapter-http --token-only for the source, as the source
// is run, under the acquisition's context, and reads its answer: exactly a
// sealed token and the lifetime the endpoint stated, null or 1 to 86400
// seconds. A failure of the step is one of the fixed results; a source that
// could not start or did not finish is said as runSource says it.
func (g *gatewayService) obtainToken(ctx context.Context, timeout time.Duration, source string, spec sourceSpec) (string, int, error) {
	run := spec
	run.argv = append(append([]string(nil), spec.argv...), "--token-only")
	result, _, _, err := g.runOnce(ctx, timeout, source, run, nil)
	// An expired reference is the source's endpoint's answer to a request's
	// reference; a token request sends none, so the report beside a token
	// request's status is not read, and the run is a failed source as any.
	var expired *sourceReferenceExpired
	if errors.As(err, &expired) {
		err = expired.failed
	}
	// So is an access refusal: a token request is not the source's read.
	var refused *sourceAccessRefused
	if errors.As(err, &refused) {
		err = refused.failed
	}
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
