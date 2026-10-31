package main

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"time"
)

// The credential a delegation is exercised through (RFC 0030 §2, "The
// credential"; SPEC.md §11.3, §11.4): bound by this gateway at the issuing
// host's authenticated request to one leaf, the chain's digests, the run's
// software and the run's proof-of-possession key, living at most five
// minutes and never past the leaf's expiry, revocable on its own. It is
// opaque and kept in memory: a restart ends every credential.

const (
	credentialPrefix    = "jpd1_"
	credentialLifetime  = 5 * time.Minute
	maxLiveCredentials  = 4096
	maxProofsRemembered = 65536
	// proofWindow is how far a DPoP proof's iat may be from the gateway's
	// time either way, and how long its jti is remembered after that.
	proofWindow  = 60 * time.Second
	maxProofJTI  = 256
	maxProofSize = 8192
)

// boundCredential is one live credential: never the token, which is not
// kept, but its digest and what it is bound to.
type boundCredential struct {
	digest   string
	host     string
	chain    *delegationChain
	software []byte // canon of the bound software identity
	jkt      string // the RFC 7638 thumbprint of the run's key; "" for a bearer credential
	expires  time.Time
}

// delegationService is the gateway as an enforcing host: the issuing hosts it
// admits delegated calls for, their pinned keys, the live credentials, and
// the DPoP proofs seen within the window.
type delegationService struct {
	// audience is the gateway's authority: the name of the gateway audience
	// a scope entry admits calls here under.
	audience       string
	hosts          map[string]*delegationHost
	keys           delegationKeys
	operators      map[string]bool
	bearerReadOnly bool

	mu          sync.Mutex
	credentials map[string]*boundCredential // by the digest of the token
	proofs      map[string]time.Time        // a jti, and when it may be forgotten

	// client makes the admission and standing reads; now is the gateway's
	// time. Both are test seams.
	client *http.Client
	now    func() time.Time
}

func newDelegationService(hosts map[string]*delegationHost, operators []string, bearerReadOnly bool) *delegationService {
	d := &delegationService{
		hosts: hosts, keys: delegationKeys{}, operators: map[string]bool{}, bearerReadOnly: bearerReadOnly,
		credentials: map[string]*boundCredential{}, proofs: map[string]time.Time{},
		client: admissionClient(nil), now: time.Now,
	}
	for name, h := range hosts {
		d.keys[name] = h.keys
	}
	for _, o := range operators {
		d.operators[o] = true
	}
	return d
}

// hostOf is the issuing host a verified token authenticates as, or nil.
func (d *delegationService) hostOf(who *caller) *delegationHost {
	if who == nil || who.delegated != nil {
		return nil
	}
	for _, h := range d.hosts {
		if h.requester == who.subject {
			return h
		}
	}
	return nil
}

// tokenDigestOf is a token's digest as a receipt names it.
func tokenDigestOf(token string) string {
	sum := sha256.Sum256([]byte(token))
	return "sha256:" + hex.EncodeToString(sum[:])
}

// bind is POST /delegation/credential (SPEC.md §11.3).
func (d *delegationService) bind(host *delegationHost, body map[string]json.RawMessage) (map[string]any, error) {
	chainRaw, present := body["chain"]
	if !present {
		return nil, refuse(refusalMalformed, "the request names no chain")
	}
	chainV, err := parseJSONWithin(chainRaw, maxArgumentValues)
	if err != nil {
		return nil, refuse(refusalMalformed, "the chain is not JSON this gateway reads")
	}
	chain, refusal := verifyDelegationChain(chainV, d.keys)
	if refusal != nil {
		return nil, refusal
	}
	if chain.root().host != host.host {
		return nil, refuse("host-unauthenticated", "the chain was issued by another host than the one asking")
	}
	softwareRaw, present := body["software"]
	softwareV, err := parseJSONWithin(softwareRaw, 64)
	if !present || err != nil || !validSoftware(softwareV) {
		return nil, refuse(refusalMalformed, "software is not a software identity")
	}
	keyRaw, present := body["key"]
	if !present {
		return nil, refuse(refusalMalformed, "the request names no key; a bearer credential is asked for with key null")
	}
	jkt := ""
	if string(keyRaw) != "null" {
		keyV, err := parseJSONWithin(keyRaw, 64)
		if err != nil {
			return nil, refuse(refusalMalformed, "key is not a JSON Web Key")
		}
		_, jkt, err = proofKey(keyV)
		if err != nil {
			return nil, refuse(refusalMalformed, "key: %v", err)
		}
	}
	t := d.now().UTC().Truncate(time.Millisecond)
	if r := chain.timeRefusal(t); r != nil {
		return nil, r
	}
	if string(canon(chain.leaf().software)) != string(canon(softwareV)) {
		return nil, refuse("software-mismatch", "the leaf's software is not the run's")
	}
	if r := d.admissionRead(host, chain, nil, t); r != nil {
		return nil, r
	}
	if jkt == "" && !(d.bearerReadOnly && chain.readOnly()) {
		return nil, refuse("sender-constraint-required", "a credential for this chain is bound to a proof-of-possession key")
	}
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return nil, err
	}
	token := credentialPrefix + base64.RawURLEncoding.EncodeToString(raw)
	expires := t.Add(credentialLifetime)
	if leaf := chain.leaf().expiresAt; leaf.Before(expires) {
		expires = leaf
	}
	bound := &boundCredential{digest: tokenDigestOf(token), host: host.host, chain: chain, software: canon(softwareV), jkt: jkt, expires: expires}
	d.mu.Lock()
	d.pruneLocked(t)
	if len(d.credentials) >= maxLiveCredentials {
		d.mu.Unlock()
		return nil, unavailable{errors.New("the gateway holds as many live delegation credentials as it binds; bind again when one has expired")}
	}
	d.credentials[bound.digest] = bound
	d.mu.Unlock()
	tokenType := "DPoP"
	if jkt == "" {
		tokenType = "Bearer"
	}
	chainOut := []any{}
	for _, digest := range chain.digests() {
		chainOut = append(chainOut, string(digest.(vString)))
	}
	return map[string]any{
		"credential": token,
		"tokenType":  tokenType,
		"expiresAt":  delegationTime(expires),
		"binding":    map[string]any{"id": chain.leaf().id, "chain": chainOut},
	}, nil
}

// pruneLocked forgets expired credentials and proofs.
func (d *delegationService) pruneLocked(t time.Time) {
	for digest, c := range d.credentials {
		if !t.Before(c.expires) {
			delete(d.credentials, digest)
		}
	}
	for jti, until := range d.proofs {
		if t.After(until) {
			delete(d.proofs, jti)
		}
	}
}

// revoke is POST /delegation/revoke (SPEC.md §11.6): it ends the live
// credentials the body names, within the host's own chains alone.
func (d *delegationService) revoke(host *delegationHost, body map[string]json.RawMessage) (map[string]any, error) {
	if len(body) != 1 {
		return nil, refuse(refusalMalformed, "a revocation names exactly one of credential, delegation and agent")
	}
	var which, name string
	for k, raw := range body {
		which = k
		if err := json.Unmarshal(raw, &name); err != nil {
			return nil, refuse(refusalMalformed, "%s is not a string", k)
		}
	}
	match := func(c *boundCredential) bool { return false }
	switch which {
	case "credential":
		if !isDigest(name) {
			return nil, refuse(refusalMalformed, "credential is the digest of a credential")
		}
		match = func(c *boundCredential) bool { return c.digest == name }
	case "delegation", "agent":
		if !isOpaqueID(name) {
			return nil, refuse(refusalMalformed, "%s is an opaque identifier", which)
		}
		match = func(c *boundCredential) bool {
			for _, l := range c.chain.links {
				if (which == "delegation" && l.id == name) || (which == "agent" && l.agent == name) {
					return true
				}
			}
			return false
		}
	default:
		return nil, refuse(refusalMalformed, "a revocation names credential, delegation or agent")
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	n := 0
	for digest, c := range d.credentials {
		if c.host == host.host && match(c) {
			delete(d.credentials, digest)
			n++
		}
	}
	return map[string]any{"revoked": n}, nil
}

// credentialOf reads a request's Authorization header as a delegation
// credential: ok is false when it presents no delegation credential at all,
// and the request is then authenticated as before.
func credentialOf(r *http.Request) (token, scheme string, ok bool) {
	scheme, token, found := strings.Cut(r.Header.Get("Authorization"), " ")
	if !found {
		return "", "", false
	}
	token = strings.TrimSpace(token)
	switch {
	case strings.EqualFold(scheme, "DPoP"):
		return token, "DPoP", true
	case strings.EqualFold(scheme, "Bearer") && strings.HasPrefix(token, credentialPrefix):
		return token, "Bearer", true
	}
	return "", "", false
}

// present is step 0 for a request presenting a delegation credential: the
// credential live at this gateway, unexpired, and, where bound to a key, a
// DPoP proof of that key for this request. It answers the bound credential
// and the caller it proves: the chain's subject, with the credential's
// digest (SPEC.md §11.7).
func (d *delegationService) present(r *http.Request, token, scheme string) (*caller, *delegationRefusal) {
	mismatch := func(why string) (*caller, *delegationRefusal) {
		return nil, refuse(refusalCredentialMismatch, "%s", why)
	}
	if !strings.HasPrefix(token, credentialPrefix) || len(token) > 128 {
		return mismatch("the token is not a delegation credential this gateway bound")
	}
	t := d.now().UTC()
	digest := tokenDigestOf(token)
	d.mu.Lock()
	c := d.credentials[digest]
	d.mu.Unlock()
	if c == nil {
		return mismatch("the credential is not live at this gateway")
	}
	if !t.Before(c.expires) {
		return mismatch("the credential has expired")
	}
	switch {
	case c.jkt == "" && scheme != "Bearer":
		return mismatch("a bearer credential is presented as Bearer")
	case c.jkt != "" && scheme != "DPoP":
		return mismatch("the credential is bound to a key and is presented as DPoP with a proof")
	case c.jkt != "":
		if err := d.verifyProof(r, token, c.jkt, t); err != nil {
			return mismatch("the proof of possession does not hold: " + err.Error())
		}
	}
	leaf, root := c.chain.leaf(), c.chain.root()
	return &caller{
		issuer: leaf.sub.issuer, subject: leaf.sub.subject, tokenDigest: digest,
		delegated: &delegatedSender{
			kind: "actor", issuer: c.host, subject: leaf.agent,
			scope:      reservationScope{sub: leaf.sub, rootActor: root.agent, host: c.host},
			credential: c,
		},
	}, nil
}

// live reports whether a credential is still bound and unexpired at t: the
// second barrier behind the admission read, checked again at admission, after
// any wait since step 0.
func (d *delegationService) live(c *boundCredential, t time.Time) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.credentials[c.digest] == c && t.Before(c.expires)
}

// proofKey reads a DPoP public key, an RFC 7517 JWK of Ed25519 or P-256 with
// no private member, and its RFC 7638 thumbprint.
func proofKey(v value) (publicKey, string, error) {
	obj, ok := v.(*vObject)
	if !ok {
		return publicKey{}, "", errors.New("not an object")
	}
	if _, private := obj.get("d"); private {
		return publicKey{}, "", errors.New("a private key member is present")
	}
	kty, _ := memberString(obj, "kty")
	crv, _ := memberString(obj, "crv")
	decode := func(name string, size int) ([]byte, error) {
		s, ok := memberString(obj, name)
		b, err := base64.RawURLEncoding.Strict().DecodeString(s)
		if !ok || err != nil || base64.RawURLEncoding.EncodeToString(b) != s || len(b) != size {
			return nil, fmt.Errorf("%s is not %d bytes of base64url", name, size)
		}
		return b, nil
	}
	thumb := newObject()
	var pk publicKey
	switch {
	case kty == "OKP" && crv == "Ed25519":
		x, err := decode("x", ed25519.PublicKeySize)
		if err != nil {
			return publicKey{}, "", err
		}
		if why := unusableSigningKey(x); why != "" {
			return publicKey{}, "", errors.New("the key " + why)
		}
		pk = publicKey{alg: "EdDSA", key: ed25519.PublicKey(x)}
		for _, m := range []string{"crv", "kty", "x"} {
			s, _ := memberString(obj, m)
			thumb.set(m, vString(s))
		}
	case kty == "EC" && crv == "P-256":
		x, err := decode("x", 32)
		if err != nil {
			return publicKey{}, "", err
		}
		y, err := decode("y", 32)
		if err != nil {
			return publicKey{}, "", err
		}
		point := &ecdsa.PublicKey{Curve: elliptic.P256(), X: new(big.Int).SetBytes(x), Y: new(big.Int).SetBytes(y)}
		if !point.Curve.IsOnCurve(point.X, point.Y) {
			return publicKey{}, "", errors.New("the key is not a point on P-256")
		}
		pk = publicKey{alg: "ES256", key: point}
		for _, m := range []string{"crv", "kty", "x", "y"} {
			s, _ := memberString(obj, m)
			thumb.set(m, vString(s))
		}
	default:
		return publicKey{}, "", errors.New("the key is neither an Ed25519 nor a P-256 key")
	}
	sum := sha256.Sum256(canon(thumb))
	return pk, base64.RawURLEncoding.EncodeToString(sum[:]), nil
}

// verifyProof holds a request's DPoP header to RFC 9449 §4.3 for the
// credential bound to jkt (SPEC.md §11.4).
func (d *delegationService) verifyProof(r *http.Request, token, jkt string, t time.Time) error {
	headers := r.Header.Values("DPoP")
	if len(headers) != 1 {
		return errors.New("the request carries no single DPoP header")
	}
	proof := headers[0]
	if len(proof) > maxProofSize {
		return errors.New("the proof is too long")
	}
	parts := strings.Split(proof, ".")
	if len(parts) != 3 {
		return errors.New("the proof is not a compact JWS")
	}
	headerBytes, err := segment("header", parts[0])
	if err != nil {
		return err
	}
	header, err := objectOf(headerBytes, "proof header")
	if err != nil {
		return err
	}
	if typ, _ := memberString(header, "typ"); typ != "dpop+jwt" {
		return errors.New("the proof's typ is not dpop+jwt")
	}
	jwkV, present := header.get("jwk")
	if !present {
		return errors.New("the proof names no key")
	}
	key, thumbprint, err := proofKey(jwkV)
	if err != nil {
		return err
	}
	if alg, _ := memberString(header, "alg"); alg != key.alg {
		return errors.New("the proof's alg is not its key's")
	}
	if thumbprint != jkt {
		return errors.New("the proof's key is not the credential's")
	}
	signature, err := segment("signature", parts[2])
	if err != nil {
		return err
	}
	if err := verifySignature(key, []byte(parts[0]+"."+parts[1]), signature); err != nil {
		return errors.New("the proof's signature does not verify")
	}
	payload, err := segment("payload", parts[1])
	if err != nil {
		return err
	}
	claims, err := objectOf(payload, "proof claims")
	if err != nil {
		return err
	}
	jti, _ := memberString(claims, "jti")
	if jti == "" || len(jti) > maxProofJTI {
		return errors.New("the proof's jti is not a string of 1 to 256 characters")
	}
	if htm, _ := memberString(claims, "htm"); htm != r.Method {
		return errors.New("the proof's htm is not the request's method")
	}
	htu, _ := memberString(claims, "htu")
	if htu != "http://"+r.Host+r.URL.Path && htu != "https://"+r.Host+r.URL.Path {
		return errors.New("the proof's htu is not the request's URI")
	}
	iat, present, err := integerMember(claims, "iat")
	if err != nil || !present {
		return errors.New("the proof's iat is not an integer")
	}
	at := time.Unix(iat, 0)
	if at.Before(t.Add(-proofWindow)) || at.After(t.Add(proofWindow)) {
		return errors.New("the proof's iat is outside the window")
	}
	sum := sha256.Sum256([]byte(token))
	if ath, _ := memberString(claims, "ath"); ath != base64.RawURLEncoding.EncodeToString(sum[:]) {
		return errors.New("the proof's ath is not the credential's")
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	d.pruneLocked(t)
	if _, seen := d.proofs[jti]; seen {
		return errors.New("the proof's jti was presented before")
	}
	if len(d.proofs) >= maxProofsRemembered {
		return errors.New("the gateway remembers as many proofs as it can; present one later")
	}
	d.proofs[jti] = at.Add(proofWindow)
	return nil
}
