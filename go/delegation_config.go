package main

import (
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"sort"
	"strings"
)

// The engine configuration's delegation member (engineVersion 15, SPEC.md
// §11.2): the issuing hosts this gateway admits delegated calls for, the
// keys each signs with, where each is read, and the gateway's operators.

// delegationP256Version is the engine configuration version from which an
// issuing host's keys may pin a P-256 key, the object {"alg": "ES256", "key":
// <66 lowercase hexadecimal characters>}, beside Ed25519 keys as strings
// (spec RFC 0030, amendment of 2026-11-22; SPEC.md §11.2). engine.go lists
// it in engineVersions.
const delegationP256Version = "41"

// admissionReadV2Version is the engine configuration version from which an
// issuing host's admission may carry readVersion, "1" or "2" (ADR-0058; spec
// RFC 0030 §2a), and from which the MCP server's tools/list names each
// platform tool's descriptorDigest and versionLabel in _meta. The number is
// a placeholder: it reads "46", the next on main, and takes its number in
// merge order (47 expected, after the scope binding's 46). engine.go lists it
// in engineVersions.
const admissionReadV2Version = "46"

// delegationHostSpec is one issuing host as configured.
type delegationHostSpec struct {
	host      string
	requester string // the subject of the host's own token from the configured issuer
	// keys are by key identifier, each with the algorithm it is pinned with.
	keys       map[string]heldKey
	admission  string // an https URL
	credential string // an absolute path to the admission credential
	// readVersion is the version of every read sent to the host, "1" or
	// "2", from admissionReadV2Version; "" below it, which is "1".
	readVersion string
}

// sentVersion is the readVersion every read to the host carries: never
// negotiated, never retried at another (RFC 0030 §2a).
func (h delegationHostSpec) sentVersion() string {
	if h.readVersion == "2" {
		return "2"
	}
	return "1"
}

// delegationSpec is the member as written.
type delegationSpec struct {
	hosts          []delegationHostSpec // in host order
	operators      []string
	bearerReadOnly bool
}

// maxAdmissionCredentialBytes bounds the credential file the gateway presents
// to an issuing host.
const maxAdmissionCredentialBytes = 8192

func parseDelegationConfig(v value, version string, identity *identitySpec) (*delegationSpec, error) {
	if !versionAtLeast(version, "15") {
		return nil, fmt.Errorf("delegation is a version-15 member; engineVersion %s has no delegation", version)
	}
	if identity == nil {
		return nil, errors.New("delegation needs identity: an issuing host authenticates by a bearer token from the configured issuer")
	}
	obj, err := requireObject(v, "delegation")
	if err != nil {
		return nil, err
	}
	if err := exactlyMembers(obj, map[string]bool{"hosts": true, "operators": false, "bearerReadOnly": false}, "delegation"); err != nil {
		return nil, err
	}
	spec := &delegationSpec{}
	hostsV, _ := obj.get("hosts")
	hosts, ok := hostsV.(vArray)
	if !ok || len(hosts) == 0 {
		return nil, errors.New("delegation.hosts must be an array of at least one issuing host")
	}
	seen := map[string]bool{}
	requesters := map[string]bool{}
	for i, hv := range hosts {
		h, err := parseDelegationHost(hv, version)
		if err != nil {
			return nil, fmt.Errorf("delegation.hosts[%d]: %v", i, err)
		}
		if seen[h.host] {
			return nil, fmt.Errorf("delegation.hosts[%d]: host %q is named twice", i, h.host)
		}
		if requesters[h.requester] {
			return nil, fmt.Errorf("delegation.hosts[%d]: requester %q is another host's", i, h.requester)
		}
		seen[h.host], requesters[h.requester] = true, true
		spec.hosts = append(spec.hosts, h)
	}
	sort.Slice(spec.hosts, func(i, j int) bool { return spec.hosts[i].host < spec.hosts[j].host })
	if opsV, present := obj.get("operators"); present {
		arr, ok := opsV.(vArray)
		if !ok {
			return nil, errors.New("delegation.operators must be an array of subjects")
		}
		for _, item := range arr {
			s, ok := stringOf(item)
			if !ok || s == "" {
				return nil, errors.New("delegation.operators must be an array of non-empty subjects")
			}
			if requesters[s] {
				return nil, fmt.Errorf("delegation.operators: %q is an issuing host's requester", s)
			}
			spec.operators = append(spec.operators, s)
		}
	}
	if bv, present := obj.get("bearerReadOnly"); present {
		b, ok := bv.(vBool)
		if !ok {
			return nil, errors.New("delegation.bearerReadOnly must be a boolean")
		}
		spec.bearerReadOnly = bool(b)
	}
	return spec, nil
}

func parseDelegationHost(v value, version string) (delegationHostSpec, error) {
	obj, err := requireObject(v, "host")
	if err != nil {
		return delegationHostSpec{}, err
	}
	if err := exactlyMembers(obj, map[string]bool{"host": true, "requester": true, "keys": true, "admission": true}, "host"); err != nil {
		return delegationHostSpec{}, err
	}
	h := delegationHostSpec{keys: map[string]heldKey{}}
	if h.host, _ = memberString(obj, "host"); !isFlatTokenString(h.host) {
		return delegationHostSpec{}, errors.New("host must be a flat token")
	}
	if h.requester, _ = memberString(obj, "requester"); h.requester == "" {
		return delegationHostSpec{}, errors.New("requester must be the subject of the host's token")
	}
	keysV, _ := obj.get("keys")
	keys, ok := keysV.(vArray)
	if !ok || len(keys) == 0 {
		if versionAtLeast(version, delegationP256Version) {
			return delegationHostSpec{}, errors.New(`keys must be an array of at least one public key: an Ed25519 key in hex, or {"alg": "ES256", "key": <66 lowercase hexadecimal characters>}`)
		}
		return delegationHostSpec{}, errors.New("keys must be an array of at least one Ed25519 public key in hex")
	}
	for i, kv := range keys {
		key, err := delegationHostKey(i, kv, version)
		if err != nil {
			return delegationHostSpec{}, err
		}
		h.keys[key.keyID()] = key
	}
	admissionV, _ := obj.get("admission")
	admission, err := requireObject(admissionV, "admission")
	if err != nil {
		return delegationHostSpec{}, err
	}
	readV2 := versionAtLeast(version, admissionReadV2Version)
	if _, present := admission.get("readVersion"); present && !readV2 {
		return delegationHostSpec{}, fmt.Errorf(`admission.readVersion is a version-%s member; engineVersion %s sends version "1" reads alone`, admissionReadV2Version, version)
	}
	if err := exactlyMembers(admission, map[string]bool{"url": true, "credential": true, "readVersion": false}, "admission"); err != nil {
		return delegationHostSpec{}, err
	}
	h.admission, _ = memberString(admission, "url")
	if err := validAdmissionURL(h.admission); err != nil {
		return delegationHostSpec{}, err
	}
	if h.credential, err = requireAbsolutePath(admission, "credential"); err != nil {
		return delegationHostSpec{}, fmt.Errorf("admission.%v", err)
	}
	if readV2 {
		h.readVersion = "1"
		if rv, present := admission.get("readVersion"); present {
			s, ok := rv.(vString)
			if !ok || (s != "1" && s != "2") {
				return delegationHostSpec{}, fmt.Errorf(`host %s: admission.readVersion is %s; it is "1" or "2"`, h.host, canon(rv))
			}
			h.readVersion = string(s)
		}
	}
	return h, nil
}

// delegationHostKey is the key keys[i] pins, with its algorithm, read as
// retention.acknowledgedBy reads one (acknowledgingKey; ADR-0053 §9): a
// string of 64 lowercase hexadecimal characters is an Ed25519 key held to
// §8.4's key rule, at every version, as before; from delegationP256Version
// the object {"alg": "ES256", "key": <66 lowercase hexadecimal characters>},
// nothing else, is a P-256 key held to its key rule (p256PublicKey). Before
// that version an object is refused by name, and every other entry with the
// Ed25519 sentence; from it, every other entry is refused with the sentence
// naming both forms -- a bare string of 66 characters among them, since
// taking it would choose the algorithm from the key's length.
func delegationHostKey(i int, each value, version string) (heldKey, error) {
	if s, ok := each.(vString); ok && isLowerHexOfLen(string(s), 64) {
		raw, _ := hex.DecodeString(string(s))
		if why := unusableSigningKey(raw); why != "" {
			return heldKey{}, fmt.Errorf("keys[%d] %s", i, why)
		}
		return edKey(raw), nil
	}
	obj, isObject := each.(*vObject)
	if !versionAtLeast(version, delegationP256Version) {
		if isObject {
			return heldKey{}, fmt.Errorf(`keys[%d]: a P-256 key, {"alg": "ES256", "key": ...}, is a version-%s form; engineVersion %s pins Ed25519 keys alone`, i, delegationP256Version, version)
		}
		return heldKey{}, fmt.Errorf("keys[%d] is not 64 lowercase hexadecimal characters", i)
	}
	bothForms := fmt.Errorf(`keys[%d] is an Ed25519 public key of 64 lowercase hexadecimal characters, or {"alg": "ES256", "key": <66 lowercase hexadecimal characters>}`, i)
	if !isObject || len(obj.byName) != 2 {
		return heldKey{}, bothForms
	}
	alg, okAlg := memberString(obj, "alg")
	keyHex, okKey := memberString(obj, "key")
	if !okAlg || alg != algES256 || !okKey {
		return heldKey{}, bothForms
	}
	key := decodeKeyHex(algES256, keyHex)
	if key == nil {
		return heldKey{}, bothForms
	}
	if !keySoundFor(algES256, key) {
		return heldKey{}, fmt.Errorf("keys[%d] is not a sound P-256 public key", i)
	}
	return heldKey{alg: algES256, key: key}, nil
}

// validAdmissionURL holds an admission read's address to HTTPS: the read
// carries the gateway's credential and decides admission, so it never
// travels in the clear (SPEC.md §11.5).
func validAdmissionURL(s string) error {
	u, err := url.Parse(s)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.Fragment != "" || strings.ContainsAny(s, " \t\r\n") {
		return errors.New("admission.url must be an https URL with a host and no user or fragment")
	}
	return nil
}

// delegationHost is one issuing host as the service holds it: the spec and
// the credential read from its file.
type delegationHost struct {
	delegationHostSpec
	bearer string
}

// loadDelegation reads each host's admission credential and returns the
// service the gateway admits delegated calls with; nil when the
// configuration names no delegation.
func loadDelegation(spec *delegationSpec) (*delegationService, error) {
	if spec == nil {
		return nil, nil
	}
	hosts := map[string]*delegationHost{}
	for _, h := range spec.hosts {
		data, err := readBounded(h.credential, maxAdmissionCredentialBytes)
		if err != nil {
			return nil, fmt.Errorf("delegation host %s: admission.credential: %v", h.host, err)
		}
		bearer := strings.TrimRight(string(data), "\r\n")
		if bearer == "" || strings.ContainsAny(bearer, " \t\r\n") || !isVisibleASCII(bearer) {
			return nil, fmt.Errorf("delegation host %s: admission.credential is not one token", h.host)
		}
		hosts[h.host] = &delegationHost{delegationHostSpec: h, bearer: bearer}
	}
	return newDelegationService(hosts, spec.operators, spec.bearerReadOnly), nil
}

func isVisibleASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < 0x21 || s[i] > 0x7e {
			return false
		}
	}
	return true
}
