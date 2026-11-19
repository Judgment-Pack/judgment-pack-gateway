package gcpasset

// The token sources (Amendment A3) and the sealed list token. This version
// takes two of the three the amendment names:
//
//  1. the metadata server of the platform's own compute, each token's
//     scope requested as it is minted, no key on disk;
//  3. a service-account key, by the jwt-bearer grant, the scope in the
//     assertion, the key read from the platform's live credentials file.
//
// Federation (2) is not built: its service-account impersonation step,
// generateAccessToken, accepts only the cloud-platform scope, which the
// amendment never requests. The adapter's README says so.
//
// A token-only run (ObtainSealed) obtains the list token and the check
// token, holds each to its scope, runs the write check with the check
// token, drops it, and answers the list token sealed under a key only the
// platform's credential derives. So a sealed token exists only for a
// credential that was checked when that token was obtained: the check runs
// at every refresh, before the new token is used. Where groups are
// resolved (groups.go), a third token, of GroupsScope, is obtained after
// the write check passed, held to its scope as the others are, and sealed
// beside the list token; one that could not be obtained is no failure of
// the run, and every group is then unresolved, no-token.

import (
	"bytes"
	"context"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"adapters/internal/canon"
	"adapters/internal/metadataclient"
	"adapters/internal/redact"
)

// endpoints are the platform's endpoints. They are fixed: a key file's own
// token_uri is not read, so a key cannot carry its assertion elsewhere. The
// metadata server is the link-local IP literal the adapters share
// (adapters/internal/metadataclient, gateway #510), so no resolver is asked
// where it is. A test of this package sets them, and no build of the
// command can change them.
var endpoints = struct {
	Asset, ResourceManager, Identity, Metadata, OAuthToken, TokenInfo string
}{
	Asset:           "https://cloudasset.googleapis.com",
	ResourceManager: "https://cloudresourcemanager.googleapis.com",
	Identity:        "https://cloudidentity.googleapis.com",
	Metadata:        metadataclient.Address,
	OAuthToken:      "https://oauth2.googleapis.com/token",
	TokenInfo:       "https://oauth2.googleapis.com/tokeninfo",
}

// testRoots, when not nil, are the only roots trusted, for a test's
// servers; nil is the system's.
var testRoots *x509.CertPool

const (
	// maxTokenAnswer bounds a token endpoint's, the metadata server's and
	// the token-information endpoint's answer.
	maxTokenAnswer = 64 << 10
	maxAccessToken = 16 << 10
	maxExpiresIn   = 86400
	// assertionLifetime is a jwt-bearer assertion's.
	assertionLifetime = 10 * time.Minute
	// oneUseLifetime is how long a token whose answer stated no lifetime is
	// held, sealed, for the one acquisition it was obtained for;
	// expiryMargin is how long before its stated expiry a sealed token is
	// no longer opened.
	oneUseLifetime = 60 * time.Second
	expiryMargin   = 30 * time.Second
	maxSealed      = 64 << 10
	sealInfo       = "adapter-gcp-asset sealed token 1"
	// minSealKey is the shortest sealKey a metadata platform's credentials
	// file may hold.
	minSealKey = 32
)

var (
	// b64token is RFC 6750 section 2.1's form of a bearer token.
	b64token  = regexp.MustCompile(`^[A-Za-z0-9\-._~+/]+=*$`)
	digits    = regexp.MustCompile(`^[0-9]+$`)
	emailForm = regexp.MustCompile(`^[A-Za-z0-9._%+-]{1,128}@[A-Za-z0-9.-]{1,253}$`)
)

// TokenFailure is a token source's failure, said by its kind: the exit
// status the gateway reads.
type TokenFailure struct {
	Kind int
	text string
}

func (f *TokenFailure) Error() string { return f.text }

func tokenFailure(kind int, format string, args ...any) error {
	return &TokenFailure{Kind: kind, text: fmt.Sprintf(format, args...)}
}

// errRedirect is a redirect, which is never followed: it would carry a
// token or an assertion elsewhere.
var errRedirect = errors.New("an endpoint answered with a redirect, which is not followed")

// noAnswer is a request that brought back no answer to read: no status,
// because the run's time or the request's ended or the connection failed,
// or a 200 whose body one of those ended. A status, a redirect among them,
// is an answer.
type noAnswer struct{ text string }

func (e *noAnswer) Error() string { return e.text }

func unanswered(err error) bool {
	var n *noAnswer
	return errors.As(err, &n)
}

// source is a configuration with its credential read.
type source struct {
	cfg Config
	// material is what the seal's key is derived from: the key's PEM text,
	// or the metadata platform's sealKey.
	material []byte
	// key and keyID are the service account's, for TokenSourceKey; email is
	// its address there, and the metadata server's answer otherwise, read
	// when a token is obtained.
	key   *rsa.PrivateKey
	keyID string
	email string
	// secrets are every value kept out of a diagnostic: the credentials
	// file's scalars, and each token and assertion once made.
	secrets []string
	// api is the client for every endpoint but the metadata server's, which
	// metadataGet asks with the adapters' shared metadata client.
	api *http.Client
}

func httpClient() *http.Client {
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: testRoots}
	transport := &http.Transport{
		TLSClientConfig:        tlsConfig,
		DisableKeepAlives:      true,
		MaxResponseHeaderBytes: maxHeaderBytes,
		TLSHandshakeTimeout:    requestTimeout,
		DisableCompression:     true,
		Proxy:                  http.ProxyFromEnvironment,
	}
	return &http.Client{
		Timeout:       requestTimeout,
		Transport:     transport,
		CheckRedirect: func(*http.Request, []*http.Request) error { return errRedirect },
	}
}

// newSource reads the platform's credentials file under the configuration:
// the service account's key for TokenSourceKey, an object of strings
// holding a sealKey for TokenSourceMetadata. The file's owner and mode are
// held by the gateway at start (the secret-file rules every credentials
// file is held to).
func newSource(cfg Config) (*source, error) {
	data, err := redact.ReadCredentials(cfg.Credentials)
	if err != nil {
		return nil, tokenFailure(StatusNoCredential, "%v", err)
	}
	if _, err := canon.Canonicalize(data, canon.CarryNumbersAsText); err != nil {
		return nil, tokenFailure(StatusNoCredential, "%v", redact.MalformedCredentials(err))
	}
	s := &source{cfg: cfg, secrets: redact.SecretsOf(data), api: httpClient()}
	var members map[string]json.RawMessage
	if json.Unmarshal(data, &members) != nil || members == nil {
		return nil, tokenFailure(StatusNoCredential, "the credentials file is not a JSON object")
	}
	member := func(name string) (string, bool) {
		var v string
		raw, present := members[name]
		return v, present && stringMember(raw, &v)
	}
	switch cfg.TokenSource {
	case TokenSourceMetadata:
		key, ok := member("sealKey")
		if !ok || len(key) < minSealKey {
			return nil, tokenFailure(StatusNoCredential, "the credentials file of a metadata token source holds sealKey, a string of at least %d bytes the sealed token's key is derived from", minSealKey)
		}
		s.material = []byte(key)
	case TokenSourceKey:
		kind, _ := member("type")
		email, emailOK := member("client_email")
		pemText, keyOK := member("private_key")
		keyID, _ := member("private_key_id")
		if kind != "service_account" || !emailOK || !emailForm.MatchString(email) || !keyOK {
			return nil, tokenFailure(StatusNoCredential, "the credentials file is not a service account's key: type service_account, client_email and private_key")
		}
		block, _ := pem.Decode([]byte(pemText))
		if block == nil || block.Type != "PRIVATE KEY" {
			return nil, tokenFailure(StatusNoCredential, "the service account's private_key is not a PKCS #8 PEM key")
		}
		parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		key, isRSA := parsed.(*rsa.PrivateKey)
		if err != nil || !isRSA || key.N.BitLen() < 2048 {
			return nil, tokenFailure(StatusNoCredential, "the service account's private_key is not an RSA key of 2048 bits or more")
		}
		s.key, s.keyID, s.email, s.material = key, keyID, email, []byte(pemText)
	}
	return s, nil
}

// redacted is err with every secret of s replaced in its text, its kind
// kept.
func (s *source) redacted(err error) error {
	var failure *TokenFailure
	if errors.As(err, &failure) {
		return &TokenFailure{Kind: failure.Kind, text: redact.Diagnostic(failure.text, false, s.secrets)}
	}
	var refused *Refused
	if errors.As(err, &refused) {
		return refused
	}
	var expired *ReferenceExpired
	if errors.As(err, &expired) {
		return expired
	}
	var unresolved *GroupUnresolved
	if errors.As(err, &unresolved) {
		return unresolved
	}
	var notConfigured *ParentNotConfigured
	if errors.As(err, &notConfigured) {
		return notConfigured
	}
	if errors.Is(err, errCheckIncomplete) {
		return errCheckIncomplete
	}
	return errors.New(redact.Diagnostic(err.Error(), false, s.secrets))
}

// obtained is a token as its source answered it: the value, the lifetime
// stated (0 when none), and the scope member when the answer had one;
// scopeUnreadable is a scope member that is not a string.
type obtained struct {
	value           string
	expiresIn       int
	scope           *string
	scopeUnreadable bool
}

// mint obtains one token of the one scope from the configured source.
func (s *source) mint(ctx context.Context, scope string) (obtained, error) {
	var tok obtained
	var err error
	switch s.cfg.TokenSource {
	case TokenSourceMetadata:
		tok, err = s.metadataToken(ctx, scope)
	default:
		tok, err = s.keyToken(ctx, scope)
	}
	if err != nil {
		return obtained{}, err
	}
	s.secrets = append(s.secrets, tok.value)
	return tok, nil
}

// metadataGet is one request to the metadata server, with the adapters'
// shared metadata client (adapters/internal/metadataclient): no proxy, a
// connection to endpoints.Metadata's address alone, no redirect followed.
// The Metadata-Flavor header is sent, and answered back once, so an answer
// from something else on that address is not taken.
func (s *source) metadataGet(ctx context.Context, path string) ([]byte, string, error) {
	unreached := tokenFailure(StatusNoCredential, "the metadata server could not be reached: no token was obtained")
	client, err := metadataclient.New(endpoints.Metadata, requestTimeout)
	if err != nil {
		return nil, "", unreached
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoints.Metadata+path, nil)
	if err != nil {
		return nil, "", tokenFailure(StatusTokenRefused, "the metadata request could not be formed")
	}
	req.Header.Set("Metadata-Flavor", "Google")
	resp, err := client.Do(req)
	if err != nil {
		return nil, "", unreached
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxTokenAnswer+1))
	if err != nil || len(raw) > maxTokenAnswer {
		return nil, "", tokenFailure(StatusTokenRefused, "the metadata server's answer could not be read whole within 64 KiB")
	}
	if !metadataclient.Flavored(resp.Header) {
		return nil, "", tokenFailure(StatusTokenRefused, "the metadata server's answer does not carry Metadata-Flavor: Google")
	}
	if resp.StatusCode != http.StatusOK {
		return nil, "", tokenFailure(StatusTokenRefused, "the metadata server refused the request (%d)", resp.StatusCode)
	}
	return raw, resp.Header.Get("Content-Type"), nil
}

func (s *source) metadataToken(ctx context.Context, scope string) (obtained, error) {
	if s.email == "" {
		raw, _, err := s.metadataGet(ctx, "/computeMetadata/v1/instance/service-accounts/default/email")
		if err != nil {
			return obtained{}, err
		}
		email := strings.TrimSpace(string(raw))
		if !emailForm.MatchString(email) {
			return obtained{}, tokenFailure(StatusTokenRefused, "the metadata server named no service account this adapter takes")
		}
		s.email = email
	}
	raw, contentType, err := s.metadataGet(ctx, "/computeMetadata/v1/instance/service-accounts/default/token?scopes="+url.QueryEscape(scope))
	if err != nil {
		return obtained{}, err
	}
	if mediaType, _, _ := mime.ParseMediaType(contentType); mediaType != "application/json" {
		return obtained{}, tokenFailure(StatusTokenRefused, "the metadata server's token answer is not application/json")
	}
	return parseTokenAnswer(raw)
}

func (s *source) keyToken(ctx context.Context, scope string) (obtained, error) {
	assertion, err := s.assertion(scope, time.Now())
	if err != nil {
		return obtained{}, tokenFailure(StatusNoCredential, "the assertion could not be signed")
	}
	s.secrets = append(s.secrets, assertion)
	form := url.Values{}
	form.Set("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer")
	form.Set("assertion", assertion)
	raw, contentType, status, err := s.post(ctx, endpoints.OAuthToken, form)
	if err != nil {
		return obtained{}, tokenFailure(StatusTokenRefused, "%v", err)
	}
	if status != http.StatusOK {
		return obtained{}, tokenFailure(StatusTokenRefused, "the token endpoint refused the token request (%d)", status)
	}
	if mediaType, _, _ := mime.ParseMediaType(contentType); mediaType != "application/json" {
		return obtained{}, tokenFailure(StatusTokenRefused, "the token endpoint's answer is not application/json")
	}
	return parseTokenAnswer(raw)
}

// post sends one form-encoded POST and reads the answer within 64 KiB. A
// request that brought back no answer is a noAnswer; a status other than
// 200 is returned whether or not its body could be read, since no caller
// reads that body.
func (s *source) post(ctx context.Context, target string, form url.Values) ([]byte, string, int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, target, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, "", 0, errors.New("the request could not be formed")
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "judgment-pack-"+adapterName+"/"+Version)
	resp, err := s.api.Do(req)
	if err != nil {
		if errors.Is(err, errRedirect) {
			return nil, "", 0, errRedirect
		}
		return nil, "", 0, &noAnswer{"the endpoint could not be reached in time"}
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxTokenAnswer+1))
	switch {
	case err != nil && resp.StatusCode != http.StatusOK:
		return nil, resp.Header.Get("Content-Type"), resp.StatusCode, nil
	case err != nil:
		return nil, "", 0, &noAnswer{"the endpoint's answer could not be read whole in time"}
	case len(raw) > maxTokenAnswer:
		return nil, "", 0, errors.New("the endpoint's answer could not be read whole within 64 KiB")
	}
	return raw, resp.Header.Get("Content-Type"), resp.StatusCode, nil
}

// assertion is the jwt-bearer assertion for one scope: RS256, the key's
// identifier as kid, the service account as iss, the scope, the token
// endpoint as aud. It names no subject, for any scope: the groups token
// too is the service account's own, never a user's by domain-wide
// delegation, and nothing a configuration holds can supply one.
func (s *source) assertion(scope string, now time.Time) (string, error) {
	header := map[string]string{"alg": "RS256", "typ": "JWT"}
	if s.keyID != "" {
		header["kid"] = s.keyID
	}
	claims := map[string]any{"iss": s.email, "scope": scope, "aud": endpoints.OAuthToken,
		"iat": now.Unix(), "exp": now.Add(assertionLifetime).Unix()}
	h, err := json.Marshal(header)
	if err != nil {
		return "", err
	}
	c, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	signing := base64.RawURLEncoding.EncodeToString(h) + "." + base64.RawURLEncoding.EncodeToString(c)
	digest := sha256.Sum256([]byte(signing))
	sig, err := rsa.SignPKCS1v15(rand.Reader, s.key, crypto.SHA256, digest[:])
	if err != nil {
		return "", err
	}
	return signing + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}

// parseTokenAnswer reads a token answer strictly: JSON in the canonical
// domain, no member named twice; access_token of RFC 6750's form within
// 16 KiB; token_type Bearer in any case; expires_in, when present, 1 to
// 86400, as a number or a string of its digits; scope, when present, kept
// for the scope check, which refuses one that is not a string.
func parseTokenAnswer(raw []byte) (obtained, error) {
	malformed := tokenFailure(StatusTokenRefused, "the token source answered with no token this adapter takes")
	if _, err := canon.Canonicalize(raw, canon.CarryNumbersAsText); err != nil {
		return obtained{}, malformed
	}
	var members map[string]json.RawMessage
	if json.Unmarshal(raw, &members) != nil || members == nil {
		return obtained{}, malformed
	}
	var out obtained
	var tokenType string
	if !stringMember(members["access_token"], &out.value) || out.value == "" || len(out.value) > maxAccessToken || !b64token.MatchString(out.value) {
		return obtained{}, malformed
	}
	if !stringMember(members["token_type"], &tokenType) || !strings.EqualFold(tokenType, "Bearer") {
		return obtained{}, malformed
	}
	if expires, present := members["expires_in"]; present {
		text := string(bytes.TrimSpace(expires))
		if quoted, ok := strings.CutPrefix(text, `"`); ok {
			if text, ok = strings.CutSuffix(quoted, `"`); !ok || !digits.MatchString(text) {
				return obtained{}, malformed
			}
		}
		n, err := strconv.Atoi(text)
		if err != nil || n < 1 || n > maxExpiresIn {
			return obtained{}, malformed
		}
		out.expiresIn = n
	}
	if scope, present := members["scope"]; present {
		// Present and not a string is an unreadable answer, which the
		// scope check refuses rather than asks again elsewhere.
		var s string
		out.scopeUnreadable = !stringMember(scope, &s)
		out.scope = &s
	}
	return out, nil
}

// checked obtains one token of the one scope and holds what it was granted
// to that scope (scope.go).
func (s *source) checked(ctx context.Context, scope string) (obtained, error) {
	tok, err := s.mint(ctx, scope)
	if err != nil {
		return obtained{}, err
	}
	if err := s.holdScope(ctx, tok, scope); err != nil {
		return obtained{}, err
	}
	return tok, nil
}

// obtainChecked is the whole of a token's obtaining: the list token and the
// check token, each held to its scope, and the write check on every
// configured project with the check token, which is then dropped; and,
// where groups are resolved, the groups token, held to its scope. It
// returns the list token, and the groups token or nil. A groups token
// whose granted scopes refuse refuses the whole, as the others' do; one
// that could not be obtained, or whose scope check could not finish, is
// nil, and every group is then unresolved (no-token).
func (s *source) obtainChecked(ctx context.Context) (obtained, *obtained, error) {
	list, err := s.checked(ctx, AssetScope)
	if err != nil {
		return obtained{}, nil, err
	}
	check, err := s.checked(ctx, CheckScope)
	if err != nil {
		return obtained{}, nil, err
	}
	if err := s.writeCheck(ctx, check.value, writeList); err != nil {
		return obtained{}, nil, err
	}
	if !s.cfg.resolvesGroups() {
		return list, nil, nil
	}
	groups, err := s.checked(ctx, GroupsScope)
	var refusal *Refused
	switch {
	case errors.As(err, &refusal):
		return obtained{}, nil, err
	case err != nil:
		return list, nil, nil
	}
	return list, &groups, nil
}

// sealed is what a sealed token holds: the list token, the time after
// which it is not opened, the principal it was minted for, which the
// resource-binding check matches, and, where groups are resolved, the
// groups token, "" where none could be obtained.
type sealed struct {
	Token       string `json:"token"`
	NotAfter    int64  `json:"notAfter"`
	Principal   string `json:"principal"`
	GroupsToken string `json:"groupsToken,omitempty"`
}

// sealAAD binds a sealed token to the configuration it was obtained and
// checked under: the token source, the credentials file, the parents and
// the scope; and, where groups are resolved, the groups token's scope, so
// a token sealed without one is not opened where groups are resolved, nor
// one sealed with it where they are not.
func sealAAD(cfg Config) []byte {
	words := append([]string{sealInfo, cfg.TokenSource, cfg.Credentials, AssetScope}, cfg.Parents...)
	if cfg.resolvesGroups() {
		words = append(words, GroupsScope)
	}
	out, _ := json.Marshal(words)
	return out
}

func sealCipher(material []byte) (cipher.AEAD, error) {
	key, err := hkdf.Key(sha256.New, material, nil, sealInfo, 32)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func (s *source) seal(token, groupsToken string, notAfter time.Time) (string, error) {
	aead, err := sealCipher(s.material)
	if err != nil {
		return "", err
	}
	plain, err := json.Marshal(sealed{Token: token, NotAfter: notAfter.Unix(), Principal: s.email, GroupsToken: groupsToken})
	if err != nil {
		return "", err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(aead.Seal(nonce, nonce, plain, sealAAD(s.cfg))), nil
}

// open opens a sealed token under this configuration and credential, or
// refuses it as unusable: not sealed under them, past its time, or not a
// token.
func (s *source) open(text string, now time.Time) (sealed, error) {
	unusable := tokenFailure(StatusSealUnusable, "the sealed token handed in is not one this configuration and credential open, or is past its time")
	if len(text) > maxSealed {
		return sealed{}, unusable
	}
	raw, err := base64.RawURLEncoding.DecodeString(text)
	if err != nil {
		return sealed{}, unusable
	}
	aead, err := sealCipher(s.material)
	if err != nil || len(raw) < aead.NonceSize() {
		return sealed{}, unusable
	}
	plain, err := aead.Open(nil, raw[:aead.NonceSize()], raw[aead.NonceSize():], sealAAD(s.cfg))
	if err != nil {
		return sealed{}, unusable
	}
	var out sealed
	if json.Unmarshal(plain, &out) != nil || !now.Before(time.Unix(out.NotAfter, 0)) || out.Token == "" || !b64token.MatchString(out.Token) || !emailForm.MatchString(out.Principal) ||
		(out.GroupsToken != "" && (!s.cfg.resolvesGroups() || !b64token.MatchString(out.GroupsToken))) {
		return sealed{}, unusable
	}
	s.secrets = append(s.secrets, out.Token)
	if out.GroupsToken != "" {
		s.secrets = append(s.secrets, out.GroupsToken)
	}
	return out, nil
}

// acquisitionTokens are what an acquisition lists with: the list token,
// the principal it was minted for, and the groups token, "" where groups
// are not resolved or none could be obtained.
type acquisitionTokens struct {
	list, principal, groups string
}

// listToken is the tokens an acquisition uses: the sealed ones handed in,
// opened, or else ones obtained and checked now for this one use.
func (s *source) listToken(ctx context.Context) (acquisitionTokens, error) {
	if s.cfg.SealedToken != "" {
		opened, err := s.open(s.cfg.SealedToken, time.Now())
		if err != nil {
			return acquisitionTokens{}, err
		}
		return acquisitionTokens{list: opened.Token, principal: opened.Principal, groups: opened.GroupsToken}, nil
	}
	tok, groups, err := s.obtainChecked(ctx)
	if err != nil {
		return acquisitionTokens{}, err
	}
	out := acquisitionTokens{list: tok.value, principal: s.email}
	if groups != nil {
		out.groups = groups.value
	}
	return out, nil
}

// sealLifetime is how long a token is held sealed: the lifetime its
// source stated, less expiryMargin where that leaves enough, or
// oneUseLifetime where none was stated.
func sealLifetime(tok obtained) time.Duration {
	if tok.expiresIn <= 0 {
		return oneUseLifetime
	}
	lifetime := time.Duration(tok.expiresIn) * time.Second
	if lifetime > 2*expiryMargin {
		lifetime -= expiryMargin
	}
	return lifetime
}

// ObtainSealed is the token-only run: both tokens obtained and held to
// their scopes, the write check run with the check token, and the list
// token answered sealed, with the lifetime its source stated or null.
func ObtainSealed(ctx context.Context, cfg Config) ([]byte, error) {
	if err := prepareConfig(cfg); err != nil {
		return nil, err
	}
	s, err := newSource(cfg)
	if err != nil {
		return nil, err
	}
	tok, groups, err := s.obtainChecked(ctx)
	if err != nil {
		return nil, s.redacted(err)
	}
	// Held sealed no longer than either token lives: where the groups
	// token stated no lifetime, the seal is for one use, as one of the
	// list token's would be.
	now := time.Now()
	notAfter := now.Add(sealLifetime(tok))
	var expiresIn *int
	if tok.expiresIn > 0 {
		expiresIn = &tok.expiresIn
	}
	groupsToken := ""
	if groups != nil {
		groupsToken = groups.value
		if lifetime := sealLifetime(*groups); now.Add(lifetime).Before(notAfter) {
			notAfter = now.Add(lifetime)
		}
		switch {
		case groups.expiresIn <= 0:
			expiresIn = nil
		case expiresIn != nil && groups.expiresIn < *expiresIn:
			expiresIn = &groups.expiresIn
		}
	}
	text, err := s.seal(tok.value, groupsToken, notAfter)
	if err != nil {
		return nil, s.redacted(err)
	}
	return canon.EncodeJSON(struct {
		Sealed    string `json:"sealed"`
		ExpiresIn *int   `json:"expiresIn"`
	}{Sealed: text, ExpiresIn: expiresIn})
}
