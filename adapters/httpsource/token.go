package httpsource

// The token step (gateway #421, docs/adr/0027-an-http-source-obtains-its-token-by-a-client-assertion.md):
// instead of sending a static member of its credentials file, the adapter
// obtains an access token from a token endpoint the operator fixed, by the
// OAuth 2.0 client-credentials grant with a client assertion (RFC 7523
// section 2.2, RFC 7521 section 4.2), and sends that token as the bearer.
// The assertion is either a JWT this adapter signs with a private key held
// as a member of its credentials file, or a federated identity token read
// from a file at each token request. The key, the federated token, the
// assertion and the access token are this process's alone: none is written
// on stdout but sealed, and none appears in a diagnostic.

import (
	"bytes"
	"context"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"adapters/internal/canon"
)

// TokenStep is how the adapter obtains the access token it sends: a token
// endpoint and a client identifier, and exactly one of KeyMember, the
// credentials member holding a PKCS#8 private key the adapter signs the
// assertion with, and FederatedTokenFile, a file whose content is the
// assertion. X5T and X5TS256 are a fixed certificate thumbprint for the
// assertion's header, at most one, beside KeyMember only. Scope, when
// given, is sent as the request's scope.
type TokenStep struct {
	Endpoint           string
	ClientID           string
	KeyMember          string
	FederatedTokenFile string
	X5T                string
	X5TS256            string
	Scope              string
}

// TokenFailure is a token step that did not produce, or could not use, an
// access token, by kind. Its text names no response body, token, assertion
// or key; the command exits with the kind's status, which is how the
// gateway tells the kinds apart without reading the text.
type TokenFailure struct {
	Kind TokenFailureKind
	text string
}

func (f *TokenFailure) Error() string { return f.text }

// TokenFailureKind is the exit status the command reports a TokenFailure by.
type TokenFailureKind int

const (
	// TokenNoCredential: the key member or the federated token is not
	// there, or is not one the step can authenticate with. No token
	// request was sent.
	TokenNoCredential TokenFailureKind = 3
	// TokenRefused: the token endpoint was not reached, refused the
	// request, or answered with no token this adapter takes.
	TokenRefused TokenFailureKind = 4
	// TokenRejectedBySource: the endpoint answered 401 to a request that
	// carried the token. The request was sent once and is not retried.
	TokenRejectedBySource TokenFailureKind = 5
	// TokenSealUnusable: the sealed token handed in could not be opened
	// under this configuration and credential, or is past its time. No
	// request was sent.
	TokenSealUnusable TokenFailureKind = 6
)

func tokenFailure(kind TokenFailureKind, format string, args ...any) error {
	return &TokenFailure{Kind: kind, text: fmt.Sprintf(format, args...)}
}

// SealedTokenVariable is the environment variable a sealed token is handed
// to an acquisition in. An environment is the adapter's own user's to read;
// what is in it is sealed under a key only that user's credential derives.
const SealedTokenVariable = "ADAPTER_HTTP_SEALED_TOKEN"

const (
	// assertionLifetime is how long a signed assertion is valid for: long
	// enough to cross to the endpoint, short enough that a captured one is
	// soon of no use.
	assertionLifetime = 5 * time.Minute
	// tokenRequestTimeout bounds the token request, inside the acquisition's
	// own time.
	tokenRequestTimeout = 10 * time.Second
	// maxTokenResponse bounds the token endpoint's answer.
	maxTokenResponse = 64 << 10
	// maxAccessToken bounds the access token taken from it.
	maxAccessToken = 16 << 10
	// maxExpiresIn is the longest lifetime a token is taken with; an answer
	// stating a longer one is refused as malformed.
	maxExpiresIn = 86400
	// maxFederatedToken bounds the federated token file.
	maxFederatedToken = 16 << 10
	// oneUseLifetime is how long a token whose answer stated no lifetime is
	// held, sealed, for the one acquisition it was obtained for.
	oneUseLifetime = 60 * time.Second
	// expiryMargin is how long before its stated expiry a sealed token is
	// no longer opened, so a request does not reach the source with a token
	// about to lapse.
	expiryMargin = 30 * time.Second
	// maxSealed bounds a sealed token handed in.
	maxSealed = 64 << 10
	sealInfo  = "adapter-http sealed token 1"
)

var (
	// b64token is RFC 6750 section 2.1's form of a bearer token.
	b64token = regexp.MustCompile(`^[A-Za-z0-9\-._~+/]+=*$`)
	// scopeToken is RFC 6749 section 3.3's scope-token.
	scopeToken = regexp.MustCompile(`^[\x21\x23-\x5b\x5d-\x7e]+$`)
	// base64urlText is unpadded base64url, the form of a JOSE thumbprint.
	base64urlText = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)
)

// holdTokenStep holds the step's configuration to its rules, before any
// credential is read: the endpoint https or loopback http, as the source's
// endpoint is held, and exactly one kind of assertion.
func holdTokenStep(t *TokenStep) (*url.URL, error) {
	endpoint, err := endpointOf(t.Endpoint)
	if err != nil {
		return nil, fmt.Errorf("--token-endpoint: %v", err)
	}
	if t.ClientID == "" || len(t.ClientID) > 256 || !visible(t.ClientID) {
		return nil, errors.New("--client-id is 1 to 256 printable ASCII characters without spaces")
	}
	switch {
	case (t.KeyMember == "") == (t.FederatedTokenFile == ""):
		return nil, errors.New("a token step takes exactly one of --assertion-key and --federated-token-file")
	case t.KeyMember == "" && (t.X5T != "" || t.X5TS256 != ""):
		return nil, errors.New("a certificate thumbprint is for an assertion this adapter signs, with --assertion-key")
	case t.X5T != "" && t.X5TS256 != "":
		return nil, errors.New("one of --assertion-x5t and --assertion-x5t-s256, not both")
	case t.X5T != "" && !thumbprintOf(t.X5T, sha1Size):
		return nil, errors.New("--assertion-x5t is the base64url, unpadded, of a 20-byte SHA-1 thumbprint")
	case t.X5TS256 != "" && !thumbprintOf(t.X5TS256, sha256.Size):
		return nil, errors.New("--assertion-x5t-s256 is the base64url, unpadded, of a 32-byte SHA-256 thumbprint")
	}
	if t.KeyMember != "" && !visible(t.KeyMember) {
		return nil, errors.New("--assertion-key names a credentials member in printable ASCII without spaces")
	}
	if t.Scope != "" {
		for _, token := range strings.Split(t.Scope, " ") {
			if !scopeToken.MatchString(token) {
				return nil, errors.New("--token-scope is scope tokens separated by single spaces (RFC 6749 section 3.3)")
			}
		}
	}
	return endpoint, nil
}

const sha1Size = 20

func thumbprintOf(s string, size int) bool {
	if !base64urlText.MatchString(s) {
		return false
	}
	raw, err := base64.RawURLEncoding.DecodeString(s)
	return err == nil && len(raw) == size
}

func visible(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < 0x21 || s[i] > 0x7e {
			return false
		}
	}
	return s != ""
}

// tokenSigner is the step's credential, read: the key and the algorithm
// its type gives, or the federated token; and the material the seal's key
// is derived from.
type tokenSigner struct {
	key       crypto.Signer
	alg       string
	federated string
	material  []byte
}

// readTokenCredential reads the step's credential: the PKCS#8 key under
// the credentials member, an RSA key of at least 2048 bits (RS256) or a
// P-256 key (ES256); or the federated token, the file's content without
// the white space around it, of at most 16 KiB of printable ASCII. A
// credential that is not there, or is not one of these, is
// TokenNoCredential, and the refusal quotes nothing of it.
func readTokenCredential(t *TokenStep, members map[string]string) (*tokenSigner, error) {
	if t.FederatedTokenFile != "" {
		file, err := os.Open(t.FederatedTokenFile)
		if err != nil {
			return nil, tokenFailure(TokenNoCredential, "the token step's federated token file could not be read")
		}
		defer file.Close()
		raw, err := io.ReadAll(io.LimitReader(file, maxFederatedToken+1))
		if err != nil {
			return nil, tokenFailure(TokenNoCredential, "the token step's federated token file could not be read")
		}
		if len(raw) > maxFederatedToken {
			return nil, tokenFailure(TokenNoCredential, "the token step's federated token file exceeds 16 KiB")
		}
		text := strings.TrimSpace(string(raw))
		if text == "" || !visible(text) {
			return nil, tokenFailure(TokenNoCredential, "the token step's federated token file holds no token")
		}
		return &tokenSigner{federated: text, material: []byte(text)}, nil
	}
	value, ok := members[t.KeyMember]
	if !ok || value == "" {
		return nil, tokenFailure(TokenNoCredential, "the credentials file does not carry the token step's key")
	}
	block, rest := pem.Decode([]byte(value))
	if block == nil || block.Type != "PRIVATE KEY" || len(bytes.TrimSpace(rest)) != 0 {
		return nil, tokenFailure(TokenNoCredential, "the token step's key is not one PEM block of type PRIVATE KEY (PKCS #8)")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, tokenFailure(TokenNoCredential, "the token step's key is not a PKCS #8 private key")
	}
	signer := &tokenSigner{material: []byte(value)}
	switch key := parsed.(type) {
	case *rsa.PrivateKey:
		if key.N.BitLen() < 2048 {
			return nil, tokenFailure(TokenNoCredential, "the token step's RSA key is shorter than 2048 bits")
		}
		signer.key, signer.alg = key, "RS256"
	case *ecdsa.PrivateKey:
		if key.Curve != elliptic.P256() {
			return nil, tokenFailure(TokenNoCredential, "the token step's EC key is not on P-256")
		}
		signer.key, signer.alg = key, "ES256"
	default:
		return nil, tokenFailure(TokenNoCredential, "the token step's key is neither RSA nor EC P-256")
	}
	return signer, nil
}

// assertion is the client assertion: the federated token as read, or a
// JWT this adapter signs -- iss and sub the client identifier, aud the
// token endpoint as configured, a fresh jti, and iat, nbf and exp five
// minutes apart; its header names the algorithm the key's type gives,
// typ JWT, and the configured thumbprint.
func (s *tokenSigner) assertion(t *TokenStep, now time.Time) (string, error) {
	if s.federated != "" {
		return s.federated, nil
	}
	header := struct {
		Alg     string `json:"alg"`
		Typ     string `json:"typ"`
		X5T     string `json:"x5t,omitempty"`
		X5TS256 string `json:"x5t#S256,omitempty"`
	}{Alg: s.alg, Typ: "JWT", X5T: t.X5T, X5TS256: t.X5TS256}
	jti := make([]byte, 16)
	if _, err := rand.Read(jti); err != nil {
		return "", err
	}
	claims := struct {
		Iss string `json:"iss"`
		Sub string `json:"sub"`
		Aud string `json:"aud"`
		Jti string `json:"jti"`
		Iat int64  `json:"iat"`
		Nbf int64  `json:"nbf"`
		Exp int64  `json:"exp"`
	}{Iss: t.ClientID, Sub: t.ClientID, Aud: t.Endpoint, Jti: hex.EncodeToString(jti), Iat: now.Unix(), Nbf: now.Unix(), Exp: now.Add(assertionLifetime).Unix()}
	h, err := json.Marshal(header)
	if err != nil {
		return "", err
	}
	c, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	input := base64.RawURLEncoding.EncodeToString(h) + "." + base64.RawURLEncoding.EncodeToString(c)
	digest := sha256.Sum256([]byte(input))
	var signature []byte
	switch key := s.key.(type) {
	case *rsa.PrivateKey:
		if signature, err = rsa.SignPKCS1v15(nil, key, crypto.SHA256, digest[:]); err != nil {
			return "", err
		}
	case *ecdsa.PrivateKey:
		// JWS (RFC 7518 section 3.4): r and s, each 32 bytes big-endian.
		r, sv, err := ecdsa.Sign(rand.Reader, key, digest[:])
		if err != nil {
			return "", err
		}
		signature = make([]byte, 64)
		r.FillBytes(signature[:32])
		sv.FillBytes(signature[32:])
	}
	return input + "." + base64.RawURLEncoding.EncodeToString(signature), nil
}

// obtainedToken is an access token the endpoint answered with, and the
// lifetime it stated in seconds, or 0 when it stated none.
type obtainedToken struct {
	value     string
	expiresIn int
}

// tokenClient is the client a token request is made with: TLS 1.2 or
// later to the system's roots, no redirect followed -- a redirect would
// carry the assertion elsewhere -- and the request bounded in time.
func tokenClient() *http.Client {
	return &http.Client{
		Timeout: tokenRequestTimeout,
		Transport: &http.Transport{
			Proxy:                  http.ProxyFromEnvironment,
			TLSClientConfig:        &tls.Config{MinVersion: tls.VersionTLS12},
			DisableKeepAlives:      true,
			MaxResponseHeaderBytes: maxHeaderBytes,
			TLSHandshakeTimeout:    tokenRequestTimeout,
			DisableCompression:     true,
		},
		CheckRedirect: func(*http.Request, []*http.Request) error { return errRedirect },
	}
}

// requestToken sends the one token request and reads the answer strictly:
// status 200, at most 64 KiB, JSON, no member named twice; access_token a
// string of RFC 6750's token form of at most 16 KiB; token_type Bearer, in
// any case; expires_in, when present, an integer from 1 to 86400. Any
// other answer is TokenRefused, and the refusal names the status at most,
// never the body.
func requestToken(ctx context.Context, client *http.Client, t *TokenStep, assertion string) (obtainedToken, error) {
	form := url.Values{}
	form.Set("grant_type", "client_credentials")
	form.Set("client_id", t.ClientID)
	form.Set("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer")
	form.Set("client_assertion", assertion)
	if t.Scope != "" {
		form.Set("scope", t.Scope)
	}
	body := form.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, t.Endpoint, strings.NewReader(body))
	if err != nil {
		return obtainedToken{}, tokenFailure(TokenRefused, "the token request could not be formed")
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "judgment-pack-adapter-http/"+Version)
	resp, err := client.Do(req)
	if err != nil {
		if errors.Is(err, errRedirect) {
			return obtainedToken{}, tokenFailure(TokenRefused, "the token endpoint answered with a redirect, which is not followed")
		}
		return obtainedToken{}, tokenFailure(TokenRefused, "the token endpoint could not be reached in time")
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxTokenResponse+1))
	if err != nil {
		return obtainedToken{}, tokenFailure(TokenRefused, "the token endpoint's answer could not be read whole")
	}
	if resp.StatusCode != http.StatusOK {
		return obtainedToken{}, tokenFailure(TokenRefused, "the token endpoint refused the token request (%d)", resp.StatusCode)
	}
	if len(raw) > maxTokenResponse {
		return obtainedToken{}, tokenFailure(TokenRefused, "the token endpoint's answer exceeds 64 KiB")
	}
	if mediaType, _, _ := mime.ParseMediaType(resp.Header.Get("Content-Type")); mediaType != "application/json" {
		return obtainedToken{}, tokenFailure(TokenRefused, "the token endpoint's answer is not application/json")
	}
	return parseTokenAnswer(raw)
}

// parseTokenAnswer reads a token endpoint's 200 answer as requestToken
// states.
func parseTokenAnswer(raw []byte) (obtainedToken, error) {
	malformed := tokenFailure(TokenRefused, "the token endpoint answered with no token this adapter takes")
	if _, err := canon.Canonicalize(raw, canon.CarryNumbersAsText); err != nil {
		return obtainedToken{}, malformed
	}
	members, err := exactMembers(raw)
	if err != nil {
		return obtainedToken{}, malformed
	}
	var out obtainedToken
	var tokenType string
	if json.Unmarshal(members["access_token"], &out.value) != nil || !strings.HasPrefix(string(bytes.TrimSpace(members["access_token"])), `"`) {
		return obtainedToken{}, malformed
	}
	if out.value == "" || len(out.value) > maxAccessToken || !b64token.MatchString(out.value) {
		return obtainedToken{}, malformed
	}
	if json.Unmarshal(members["token_type"], &tokenType) != nil || !strings.EqualFold(tokenType, "Bearer") {
		return obtainedToken{}, malformed
	}
	if expires, present := members["expires_in"]; present {
		n, err := strconv.Atoi(string(bytes.TrimSpace(expires)))
		if err != nil || n < 1 || n > maxExpiresIn {
			return obtainedToken{}, malformed
		}
		out.expiresIn = n
	}
	return out, nil
}

// sealed is what a sealed token holds: the token, and the time after which
// it is not opened.
type sealed struct {
	Token    string `json:"token"`
	NotAfter int64  `json:"notAfter"`
}

// sealAAD binds a sealed token to the configuration it was obtained under:
// the source's endpoint, the token endpoint, the client, the kind of
// assertion and the scope asked for. A token sealed for one is not opened
// under another, whatever hands it in.
func sealAAD(cfg Config) []byte {
	t := cfg.Token
	out, _ := json.Marshal([]string{sealInfo, cfg.Endpoint, t.Endpoint, t.ClientID, t.KeyMember, t.FederatedTokenFile, t.X5T, t.X5TS256, t.Scope})
	return out
}

// sealCipher is AES-256-GCM under a key derived by HKDF-SHA256 from the
// step's credential, the key's PEM text or the federated token: only the
// adapter's own user, which reads that credential, derives it. A
// credential that changes -- a federated token renewed, a key replaced --
// derives another key, and what was sealed before is no longer opened.
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

func sealToken(cfg Config, material []byte, token string, notAfter time.Time) (string, error) {
	aead, err := sealCipher(material)
	if err != nil {
		return "", err
	}
	plain, err := json.Marshal(sealed{Token: token, NotAfter: notAfter.Unix()})
	if err != nil {
		return "", err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(aead.Seal(nonce, nonce, plain, sealAAD(cfg))), nil
}

// openToken opens a sealed token under this configuration and credential,
// or refuses it as TokenSealUnusable: not sealed under them, past its time,
// or not a token.
func openToken(cfg Config, material []byte, text string, now time.Time) (string, error) {
	unusable := tokenFailure(TokenSealUnusable, "the sealed token handed in is not one this configuration and credential open, or is past its time")
	if len(text) > maxSealed {
		return "", unusable
	}
	raw, err := base64.RawURLEncoding.DecodeString(text)
	if err != nil {
		return "", unusable
	}
	aead, err := sealCipher(material)
	if err != nil || len(raw) < aead.NonceSize() {
		return "", unusable
	}
	plain, err := aead.Open(nil, raw[:aead.NonceSize()], raw[aead.NonceSize():], sealAAD(cfg))
	if err != nil {
		return "", unusable
	}
	var s sealed
	if json.Unmarshal(plain, &s) != nil || !now.Before(time.Unix(s.NotAfter, 0)) || s.Token == "" || !b64token.MatchString(s.Token) {
		return "", unusable
	}
	return s.Token, nil
}

// tokenFor is the access token an acquisition or a check sends: the sealed
// one handed in, opened, or else one obtained now for this one use. secrets
// gains the assertion and the token for every diagnostic after.
func tokenFor(ctx context.Context, cfg Config, signer *tokenSigner, secrets *[]string) (string, error) {
	if signer.federated != "" {
		*secrets = append(*secrets, signer.federated)
	}
	if cfg.SealedToken != "" {
		token, err := openToken(cfg, signer.material, cfg.SealedToken, time.Now())
		if err != nil {
			return "", err
		}
		*secrets = append(*secrets, token)
		return token, nil
	}
	obtained, err := obtain(ctx, cfg, signer, secrets)
	if err != nil {
		return "", err
	}
	return obtained.value, nil
}

// obtain makes the assertion and the token request.
func obtain(ctx context.Context, cfg Config, signer *tokenSigner, secrets *[]string) (obtainedToken, error) {
	assertion, err := signer.assertion(cfg.Token, time.Now())
	if err != nil {
		return obtainedToken{}, tokenFailure(TokenNoCredential, "the token step's assertion could not be signed")
	}
	*secrets = append(*secrets, assertion)
	obtained, err := requestToken(ctx, tokenClient(), cfg.Token, assertion)
	if err != nil {
		return obtainedToken{}, err
	}
	*secrets = append(*secrets, obtained.value)
	return obtained, nil
}

// ObtainSealed is the token step alone, for a caller that holds the token
// between acquisitions without being able to read it: it obtains a token
// and answers it sealed (sealToken), with the lifetime the endpoint
// stated, or null when it stated none; such a token is sealed for one
// acquisition, a minute.
func ObtainSealed(ctx context.Context, cfg Config) ([]byte, error) {
	if cfg.Token == nil {
		return nil, errors.New("--token-only is for a token step")
	}
	p, err := prepare(cfg)
	if err != nil {
		return nil, err
	}
	finish := func(err error) ([]byte, error) { return nil, p.redacted(err) }
	obtained, err := obtain(ctx, cfg, p.signer, &p.secrets)
	if err != nil {
		return finish(err)
	}
	now := time.Now()
	notAfter := now.Add(oneUseLifetime)
	var expiresIn *int
	if obtained.expiresIn > 0 {
		// Opened until the margin before the stated expiry, or, for a
		// lifetime too short to keep a margin, until the expiry itself.
		lifetime := time.Duration(obtained.expiresIn) * time.Second
		if lifetime > 2*expiryMargin {
			lifetime -= expiryMargin
		}
		notAfter = now.Add(lifetime)
		expiresIn = &obtained.expiresIn
	}
	text, err := sealToken(cfg, p.signer.material, obtained.value, notAfter)
	if err != nil {
		return finish(err)
	}
	return canon.EncodeJSON(struct {
		Sealed    string `json:"sealed"`
		ExpiresIn *int   `json:"expiresIn"`
	}{Sealed: text, ExpiresIn: expiresIn})
}
