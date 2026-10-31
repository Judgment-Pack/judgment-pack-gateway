package main

import (
	"crypto/ed25519"
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

// delegationHostSpec is one issuing host as configured.
type delegationHostSpec struct {
	host       string
	requester  string // the subject of the host's own token from the configured issuer
	keys       map[string]ed25519.PublicKey
	admission  string // an https URL
	credential string // an absolute path to the admission credential
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
		h, err := parseDelegationHost(hv)
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

func parseDelegationHost(v value) (delegationHostSpec, error) {
	obj, err := requireObject(v, "host")
	if err != nil {
		return delegationHostSpec{}, err
	}
	if err := exactlyMembers(obj, map[string]bool{"host": true, "requester": true, "keys": true, "admission": true}, "host"); err != nil {
		return delegationHostSpec{}, err
	}
	h := delegationHostSpec{keys: map[string]ed25519.PublicKey{}}
	if h.host, _ = memberString(obj, "host"); !isFlatTokenString(h.host) {
		return delegationHostSpec{}, errors.New("host must be a flat token")
	}
	if h.requester, _ = memberString(obj, "requester"); h.requester == "" {
		return delegationHostSpec{}, errors.New("requester must be the subject of the host's token")
	}
	keysV, _ := obj.get("keys")
	keys, ok := keysV.(vArray)
	if !ok || len(keys) == 0 {
		return delegationHostSpec{}, errors.New("keys must be an array of at least one Ed25519 public key in hex")
	}
	for i, kv := range keys {
		s, ok := stringOf(kv)
		raw, err := hex.DecodeString(s)
		if !ok || err != nil || !isLowerHexOfLen(s, 64) {
			return delegationHostSpec{}, fmt.Errorf("keys[%d] is not 64 lowercase hexadecimal characters", i)
		}
		if why := unusableSigningKey(raw); why != "" {
			return delegationHostSpec{}, fmt.Errorf("keys[%d] %s", i, why)
		}
		h.keys[keyIDFor(raw)] = ed25519.PublicKey(raw)
	}
	admissionV, _ := obj.get("admission")
	admission, err := requireObject(admissionV, "admission")
	if err != nil {
		return delegationHostSpec{}, err
	}
	if err := exactlyMembers(admission, map[string]bool{"url": true, "credential": true}, "admission"); err != nil {
		return delegationHostSpec{}, err
	}
	h.admission, _ = memberString(admission, "url")
	if err := validAdmissionURL(h.admission); err != nil {
		return delegationHostSpec{}, err
	}
	if h.credential, err = requireAbsolutePath(admission, "credential"); err != nil {
		return delegationHostSpec{}, fmt.Errorf("admission.%v", err)
	}
	return h, nil
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
