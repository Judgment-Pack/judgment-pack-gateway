package main

// The key-service signer (docs/adr/0050-an-external-signer-in-a-key-service.md):
// an Ed25519 key version (EC_SIGN_ED25519) in Cloud KMS signs for the
// gateway, asked with asymmetricSign at the built-in API host and
// authenticated by the gateway's own access token from the platform's
// metadata server (ADR-0043, ADR-0045). The private key never leaves the
// service; the gateway reads the public key once, at start, checks it and
// derives its keyId from it, and holds every signature to it before
// anything is written with it (signingKey.signVerified).

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"sync"
	"time"
)

// keyServiceBase is the key service's API: built in, https, named by no
// configuration member, flag or environment variable. Only a test of this
// package points it at a stand-in.
var keyServiceBase = "https://cloudkms.googleapis.com"

// keyServiceMetadataBase is the platform's metadata server at its fixed
// link-local address, an IP literal (ADR-0043). Only a test of this
// package points it at a stand-in.
var keyServiceMetadataBase = "http://169.254.169.254"

// keyServiceRoots are the roots the API's certificate is held to: nil, the
// system's. Only a test of this package names its stand-in's.
var keyServiceRoots *x509.CertPool

const (
	// keyServiceDeadline bounds one signing, the access token included, and
	// the start's read of the public key.
	keyServiceDeadline = 5 * time.Second
	// keyServiceAnswerLimit bounds every answer's body read.
	keyServiceAnswerLimit = 64 << 10
	// keyServiceTokenMargin is how long before its expiry an access token
	// is asked for again.
	keyServiceTokenMargin = 60 * time.Second
	keyServiceAlgorithm   = "EC_SIGN_ED25519"
	metadataAccessPath    = "/computeMetadata/v1/instance/service-accounts/default/token"
	// keyServiceLatch is how long after a signing that failed every signing
	// fails at once with the same sentence, asking nothing: a service that
	// is down costs one deadline, not one for each acquisition waiting on
	// the service's lock, and a stop is not starved behind them.
	keyServiceLatch = 2 * time.Second
	// keyServiceTokenLimit bounds the access token taken; keyServiceTokenLife
	// bounds the life its answer may claim, in seconds.
	keyServiceTokenLimit = 16 << 10
	keyServiceTokenLife  = 86400
)

// accessTokenForm is an access token's form (RFC 6750 b64token).
var accessTokenForm = regexp.MustCompile(`^[A-Za-z0-9._~+/-]+=*$`)

// signingPublicKeyForm is signingPublicKey's form: the key version's Ed25519
// public key, 64 lowercase hexadecimal characters.
var signingPublicKeyForm = regexp.MustCompile(`^[0-9a-f]{64}$`)

// keyVersionForm is signingKeyVersion's closed form: one key version's
// resource name, every segment of the service's own alphabet.
var keyVersionForm = regexp.MustCompile(`^projects/[a-z][a-z0-9-]{4,28}[a-z0-9]/locations/[a-z0-9-]{1,63}/keyRings/[A-Za-z0-9_-]{1,63}/cryptoKeys/[A-Za-z0-9_-]{1,63}/cryptoKeyVersions/[1-9][0-9]{0,9}$`)

const keyVersionFormText = "projects/<project>/locations/<location>/keyRings/<ring>/cryptoKeys/<key>/cryptoKeyVersions/<n>"

// The fixed sentences of a signing that did not happen. None repeats a
// value the service answered.
var (
	errKeyServiceUnreachable    = errors.New("the key service could not be reached in time; nothing was signed")
	errKeyServiceRefused        = errors.New("the key service refused to sign; nothing was signed")
	errKeyServiceAnswer         = errors.New("the key service answered with no signature the gateway takes; nothing was signed")
	errKeyServiceToken          = errors.New("the gateway's access token could not be had from the metadata server; nothing was signed")
	errKeyServicePublicKey      = errors.New("the key service answered no Ed25519 public key of the key version configured; the gateway does not start")
	errSigningPublicKeyRequired = errors.New("engine configuration: signingKeyVersion is not given without signingPublicKey, the key version's Ed25519 public key that pins it (ADR-0050)")
	errKeyServiceNotExpected    = errors.New("the key service's key version answers a public key other than the one signingPublicKey names; nothing is signed with it")
)

var castagnoli = crc32.MakeTable(crc32.Castagnoli)

func crc32c(data []byte) string {
	return strconv.FormatUint(uint64(crc32.Checksum(data, castagnoli)), 10)
}

// keyServiceSigner signs with one key version in the key service.
type keyServiceSigner struct {
	version  string
	public   ed25519.PublicKey
	api      *http.Client
	metadata *http.Client
	now      func() time.Time

	mu      sync.Mutex
	token   string
	expires time.Time

	// fault guards life, the context every signing derives from (the
	// service's lifetime once bound, so a stop cancels a signing that
	// waits), and the latch: the failure of the last signing, repeated at
	// once until latchedUntil.
	fault        sync.Mutex
	life         context.Context
	latched      error
	latchedUntil time.Time
}

// bindLife makes every signing from now on derive from ctx: once ctx ends,
// a signing that waits on the service ends with it.
func (k *keyServiceSigner) bindLife(ctx context.Context) {
	k.fault.Lock()
	defer k.fault.Unlock()
	k.life = ctx
}

// lifeBinder is a signer whose signings derive from a lifetime.
type lifeBinder interface{ bindLife(context.Context) }

// newKeyServiceSignerPinned is newKeyServiceSigner held to expected, where
// it is named (signingPublicKey, ADR-0050): a key version whose public key
// is another signs nothing. The refusal names neither key.
func newKeyServiceSignerPinned(version, expected string) (*keyServiceSigner, string, error) {
	k, line, err := newKeyServiceSigner(version)
	if err != nil {
		return nil, "", err
	}
	if expected != "" && hex.EncodeToString(k.public) != expected {
		return nil, "", errKeyServiceNotExpected
	}
	return k, line, nil
}

// pinnedClient is a client that dials base's address alone, through no
// proxy, following no redirect, its header bounded, every request bounded
// by keyServiceDeadline: the metadata client's rules (adapters/internal/
// metadataclient), which this module holds as its own since it imports no
// other module's packages.
func pinnedClient(base string, roots *x509.CertPool) (*http.Client, error) {
	parsed, err := url.Parse(base)
	if err != nil || parsed.Host == "" || parsed.Path != "" || parsed.RawQuery != "" || parsed.User != nil {
		return nil, errors.New("not a base address")
	}
	port := parsed.Port()
	switch {
	case parsed.Scheme == "http" && net.ParseIP(parsed.Hostname()) != nil:
		if port == "" {
			port = "80"
		}
	case parsed.Scheme == "https":
		if port == "" {
			port = "443"
		}
	default:
		return nil, errors.New("not a base address")
	}
	pinned := net.JoinHostPort(parsed.Hostname(), port)
	dialer := &net.Dialer{Timeout: keyServiceDeadline}
	transport := &http.Transport{
		Proxy: nil,
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			if address != pinned {
				return nil, errors.New("a connection to an address other than the one built in is not made")
			}
			return dialer.DialContext(ctx, network, address)
		},
		DisableKeepAlives:      false,
		MaxResponseHeaderBytes: keyServiceAnswerLimit,
		DisableCompression:     true,
	}
	if parsed.Scheme == "https" {
		transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots, ServerName: parsed.Hostname()}
		transport.ForceAttemptHTTP2 = true
	}
	return &http.Client{
		Timeout:       keyServiceDeadline,
		Transport:     transport,
		CheckRedirect: func(*http.Request, []*http.Request) error { return errRedirectRefused },
	}, nil
}

var errRedirectRefused = errors.New("a redirect is not followed")

// newKeyServiceSigner is the signer of the key version named, its public
// key read once from the service and checked: the answer names the version
// asked, EC_SIGN_ED25519, a PEM whose CRC32C is the one answered, holding
// one Ed25519 public key. Anything else is errKeyServicePublicKey, and the
// gateway does not start. The key's place in the registry is held by the
// registry's walk, which must end at it (newRegistryWriterOnWith).
func newKeyServiceSigner(version string) (*keyServiceSigner, string, error) {
	if !keyVersionForm.MatchString(version) {
		return nil, "", fmt.Errorf("signingKeyVersion is not of the form %s", keyVersionFormText)
	}
	api, err := pinnedClient(keyServiceBase, keyServiceRoots)
	if err != nil {
		return nil, "", err
	}
	metadata, err := pinnedClient(keyServiceMetadataBase, nil)
	if err != nil || !bytes.HasPrefix([]byte(keyServiceMetadataBase), []byte("http://")) {
		return nil, "", errors.New("the metadata server is asked over http at an IP literal")
	}
	k := &keyServiceSigner{version: version, api: api, metadata: metadata, now: time.Now}
	ctx, cancel := context.WithTimeout(context.Background(), keyServiceDeadline)
	defer cancel()
	var answer struct {
		Name            string `json:"name"`
		Pem             string `json:"pem"`
		Algorithm       string `json:"algorithm"`
		PemCrc32c       string `json:"pemCrc32c"`
		ProtectionLevel string `json:"protectionLevel"`
	}
	if err := k.call(ctx, http.MethodGet, "/v1/"+version+"/publicKey", nil, &answer); err != nil {
		return nil, "", fmt.Errorf("signingKeyVersion: %w", err)
	}
	if answer.Name != version || answer.Algorithm != keyServiceAlgorithm || answer.PemCrc32c != crc32c([]byte(answer.Pem)) {
		return nil, "", errKeyServicePublicKey
	}
	block, rest := pem.Decode([]byte(answer.Pem))
	if block == nil || block.Type != "PUBLIC KEY" || len(bytes.TrimSpace(rest)) != 0 {
		return nil, "", errKeyServicePublicKey
	}
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	public, ok := parsed.(ed25519.PublicKey)
	if err != nil || !ok || len(public) != ed25519.PublicKeySize {
		return nil, "", errKeyServicePublicKey
	}
	k.public = public
	level := answer.ProtectionLevel
	if level != "SOFTWARE" && level != "HSM" && level != "EXTERNAL" && level != "EXTERNAL_VPC" {
		level = "unstated"
	}
	return k, fmt.Sprintf("the signer is the key service's key version %s (Ed25519, protection level %s), keyId %s; the gateway holds no private key", version, level, keyIDFor(public)), nil
}

func (k *keyServiceSigner) publicKey() ed25519.PublicKey { return k.public }

// sign asks the service for the signature of message by the key version
// configured, within keyServiceDeadline: the answer must name that version,
// say the data's CRC32C was verified, and carry a signature of 64 bytes
// whose CRC32C is the one answered. The caller holds it to the public key
// (signingKey.signVerified).
func (k *keyServiceSigner) sign(message []byte) ([]byte, error) {
	k.fault.Lock()
	life, latched, until := k.life, k.latched, k.latchedUntil
	k.fault.Unlock()
	if latched != nil && k.now().Before(until) {
		return nil, latched
	}
	if life == nil {
		life = context.Background()
	}
	signature, err := k.ask(life, message)
	k.fault.Lock()
	if err != nil {
		k.latched, k.latchedUntil = err, k.now().Add(keyServiceLatch)
	} else {
		k.latched = nil
	}
	k.fault.Unlock()
	return signature, err
}

// ask is one asymmetricSign call within keyServiceDeadline of life.
func (k *keyServiceSigner) ask(life context.Context, message []byte) ([]byte, error) {
	ctx, cancel := context.WithTimeout(life, keyServiceDeadline)
	defer cancel()
	request, _ := json.Marshal(map[string]string{
		"data":       base64.StdEncoding.EncodeToString(message),
		"dataCrc32c": crc32c(message),
	})
	var answer struct {
		Name               string `json:"name"`
		Signature          string `json:"signature"`
		SignatureCrc32c    string `json:"signatureCrc32c"`
		VerifiedDataCrc32c bool   `json:"verifiedDataCrc32c"`
	}
	if err := k.call(ctx, http.MethodPost, "/v1/"+k.version+":asymmetricSign", request, &answer); err != nil {
		return nil, err
	}
	signature, err := base64.StdEncoding.DecodeString(answer.Signature)
	if err != nil || answer.Name != k.version || !answer.VerifiedDataCrc32c ||
		len(signature) != ed25519.SignatureSize || answer.SignatureCrc32c != crc32c(signature) {
		return nil, errKeyServiceAnswer
	}
	return signature, nil
}

// call makes one request of the API, authenticated by the access token,
// and reads its answer, status 200 and at most keyServiceAnswerLimit of
// JSON, into out. Any other status is errKeyServiceRefused -- a 429 or a
// 503 among them: the key service is the gateway's own, not a source, so
// it is no source's throttled answer (ADR-0029) -- and an answer that
// cannot be had is errKeyServiceUnreachable.
func (k *keyServiceSigner) call(ctx context.Context, method, path string, body []byte, out any) error {
	token, err := k.accessToken(ctx)
	if err != nil {
		return err
	}
	var reader io.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, keyServiceBase+path, reader)
	if err != nil {
		return errKeyServiceUnreachable
	}
	req.Header.Set("Authorization", "Bearer "+token)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := k.api.Do(req)
	if err != nil {
		if errors.Is(err, errRedirectRefused) {
			return errKeyServiceRefused
		}
		return errKeyServiceUnreachable
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return errKeyServiceRefused
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, keyServiceAnswerLimit+1))
	if err != nil {
		return errKeyServiceUnreachable
	}
	if len(raw) > keyServiceAnswerLimit || json.Unmarshal(raw, out) != nil {
		return errKeyServiceAnswer
	}
	return nil
}

// accessToken is the gateway's own access token, from the metadata server
// (GET, Metadata-Flavor: Google, the answer taken only with that header
// once), kept until keyServiceTokenMargin before it expires.
func (k *keyServiceSigner) accessToken(ctx context.Context) (string, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.token != "" && k.now().Before(k.expires) {
		return k.token, nil
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, keyServiceMetadataBase+metadataAccessPath, nil)
	if err != nil {
		return "", errKeyServiceToken
	}
	req.Header.Set("Metadata-Flavor", "Google")
	resp, err := k.metadata.Do(req)
	if err != nil {
		return "", errKeyServiceToken
	}
	defer resp.Body.Close()
	if flavor := resp.Header.Values("Metadata-Flavor"); len(flavor) != 1 || flavor[0] != "Google" || resp.StatusCode != http.StatusOK {
		return "", errKeyServiceToken
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, keyServiceAnswerLimit+1))
	var answer struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int64  `json:"expires_in"`
		TokenType   string `json:"token_type"`
	}
	if err != nil || len(raw) > keyServiceAnswerLimit || json.Unmarshal(raw, &answer) != nil ||
		len(answer.AccessToken) > keyServiceTokenLimit || !accessTokenForm.MatchString(answer.AccessToken) ||
		answer.TokenType != "Bearer" || answer.ExpiresIn <= 0 || answer.ExpiresIn > keyServiceTokenLife {
		return "", errKeyServiceToken
	}
	k.token = answer.AccessToken
	k.expires = k.now().Add(time.Duration(answer.ExpiresIn)*time.Second - keyServiceTokenMargin)
	return k.token, nil
}

// commandSigner is what an operator command run with the gateway stopped
// signs through (ADR-0050): the key service's key version the configuration
// names, held to signingPublicKey where it is named, or else the seed's key.
func commandSigner(version, expected string, seed []byte) (signer, error) {
	if version == "" {
		return newSeedSigner(seed), nil
	}
	k, _, err := newKeyServiceSignerPinned(version, expected)
	if err != nil {
		return nil, err
	}
	return k, nil
}

// heldUnderAnotherKey refuses a registry, and the store beside it, holding
// history under a key id the registry's walk did not reach (ADR-0050): a
// record of the registry other than a rotation, or the first receipt of
// any of the store's series, under a key no rotation leads from to own,
// whether own is a key service's or the seed's. A gateway moved from
// its seed to a key service, or to another key version, signs once a
// rotation to its key is recorded, and not before. receipts may be nil.
func heldUnderAnotherKey(registry []byte, keys []reachedKey, own ed25519.PublicKey, receipts indexedSpace) error {
	reached := func(keyID string) bool {
		for _, k := range keys {
			if k.keyID == keyID {
				return true
			}
		}
		return false
	}
	refuse := func(what, keyID string) error {
		return fmt.Errorf("the %s is under key id %s, and no rotation in the registry leads from it to this gateway's key %s: a gateway moved to a key service, or to another key version, starts once a rotation to its key is recorded (ADR-0050)", what, keyID, keyIDFor(own))
	}
	for _, line := range bytes.Split(registry, []byte("\n")) {
		if kind, _ := rotationKindOf(string(line)); kind != "" || len(bytes.TrimSpace(line)) == 0 {
			continue
		}
		v, err := parseJSON(line)
		obj, ok := v.(*vObject)
		if err != nil || !ok {
			continue
		}
		if keyID, _ := memberString(obj, "keyId"); keyID != "" && !reached(keyID) {
			return refuse("registry holds a record that", keyID)
		}
	}
	if receipts == nil {
		return nil
	}
	series, err := receipts.listSeries()
	if err != nil {
		return err
	}
	// the first receipt of every series that holds one: a series left
	// empty is passed over, and the next is read, so no series is skipped
	// because an earlier one holds nothing
	for _, s := range series {
		entries, err := receipts.listEntries(s)
		if err != nil {
			return err
		}
		if len(entries) == 0 {
			continue
		}
		data, err := receipts.getEntry(s, entries[0])
		if err != nil {
			return err
		}
		v, err := parseJSON(data)
		if obj, ok := v.(*vObject); err == nil && ok {
			if keyID, _ := memberString(obj, "keyId"); keyID != "" && !reached(keyID) {
				return refuse("store holds a receipt that", keyID)
			}
		}
	}
	return nil
}
