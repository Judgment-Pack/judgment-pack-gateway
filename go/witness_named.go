package main

// A receipt names the witness its trail is registered with
// (docs/adr/0014-a-receipt-names-the-witness.md; SPEC.md §1.2a, §4): an
// optional signed member of version 3, `witness: {origin, keyId, trail}`,
// set from the operator's configuration as a receipt is minted -- on an
// action, the trail of the record /act found; on an acquisition, the trail
// its request names -- and never on a seal. The member is the operator's
// gateway's word that it named this witness for this trail at the receipt's
// servedAt: nothing of the witness, the chain or the operator. This file
// holds its form, which the verifier holds a receipt to; the configuration
// that names a witness for a trail (`witnessedBy`, `--witnessed-by`); and
// the member as a receipt carries it.

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// maxWitnessOrigin bounds an origin's length (ADR-0014 §1).
const maxWitnessOrigin = 2048

// witnessNaming is the member as a receipt carries it.
type witnessNaming struct {
	origin string
	keyID  string
	trail  string
}

// witnessTriple is one distinct naming, as the verifier's report gives it
// (SPEC.md §4, `witnesses`).
type witnessTriple struct {
	Trail  string `json:"trail"`
	Origin string `json:"origin"`
	KeyID  string `json:"keyId"`
}

var (
	originName = regexp.MustCompile(`^[a-z0-9-]+(\.[a-z0-9-]+)*$`)
	originIPv6 = regexp.MustCompile(`^\[[0-9a-f:]+\]$`)
	originPort = regexp.MustCompile(`^[1-9][0-9]{0,4}$`)
	originIPv4 = regexp.MustCompile(`^(0|[1-9][0-9]{0,2})\.(0|[1-9][0-9]{0,2})\.(0|[1-9][0-9]{0,2})\.(0|[1-9][0-9]{0,2})$`)
)

// isWitnessOrigin is the form of a witness's origin (ADR-0014 §1; SPEC.md
// §1.2a): "https://" or "http://", a host in lowercase, ":" and a port in
// decimal with no leading zero, from 1 to 65535, and nothing after; "http"
// only with a loopback address written as one -- an IPv4 address of
// 127.0.0.0/8 in dotted decimal, or [::1] -- and at most 2048 characters. A
// host is a name of lowercase letters, digits and hyphens in labels joined
// by single dots (an IPv4 address among them), or an IPv6 address of
// lowercase hexadecimal and colons in brackets.
func isWitnessOrigin(s string) bool {
	if len(s) > maxWitnessOrigin {
		return false
	}
	rest, secure := strings.CutPrefix(s, "https://")
	if !secure {
		var plain bool
		if rest, plain = strings.CutPrefix(s, "http://"); !plain {
			return false
		}
	}
	colon := strings.LastIndexByte(rest, ':')
	if colon < 0 {
		return false
	}
	host, port := rest[:colon], rest[colon+1:]
	if !originPort.MatchString(port) {
		return false
	}
	if n, err := strconv.Atoi(port); err != nil || n > 65535 {
		return false
	}
	if !secure {
		return isLoopbackHost(host)
	}
	if originName.MatchString(host) {
		return true
	}
	return originIPv6.MatchString(host) && isIPv6Literal(host[1:len(host)-1])
}

// isLoopbackHost is a loopback address written as one: [::1], or an IPv4
// address of 127.0.0.0/8 in dotted decimal, each part from 0 to 255 with no
// leading zero.
func isLoopbackHost(host string) bool {
	if host == "[::1]" {
		return true
	}
	parts := originIPv4.FindStringSubmatch(host)
	if parts == nil || parts[1] != "127" {
		return false
	}
	for _, part := range parts[2:] {
		if n, _ := strconv.Atoi(part); n > 255 {
			return false
		}
	}
	return true
}

// isIPv6Literal is an IPv6 address, of hexadecimal and colons alone.
func isIPv6Literal(s string) bool {
	ip := net.ParseIP(s)
	return ip != nil && strings.Contains(s, ":")
}

// witnessMemberOf holds a receipt's witness member to its form (§1.4 order
// 1): an object whose origin is of the form above, whose keyId and trail
// are each 32 lowercase hexadecimal characters. A member it does not name
// is tolerated, as everywhere in a receipt.
func witnessMemberOf(v value) (*witnessNaming, error) {
	obj, err := requireObject(v, "witness")
	if err != nil {
		return nil, err
	}
	origin, err := requireString(obj, "origin")
	if err != nil {
		return nil, fmt.Errorf("witness: %w", err)
	}
	if !isWitnessOrigin(origin) {
		return nil, errors.New("witness: origin is not of its form")
	}
	keyID, err := requireString(obj, "keyId")
	if err != nil {
		return nil, fmt.Errorf("witness: %w", err)
	}
	if !isLowerHexOfLen(keyID, 32) {
		return nil, errors.New("witness: keyId is not 32 lowercase hex characters")
	}
	trail, err := requireString(obj, "trail")
	if err != nil {
		return nil, fmt.Errorf("witness: %w", err)
	}
	if !isLowerHexOfLen(trail, 32) {
		return nil, errors.New("witness: trail is not 32 lowercase hex characters")
	}
	return &witnessNaming{origin: origin, keyID: keyID, trail: trail}, nil
}

// --- the operator's configuration ------------------------------------------

// namedWitness is the witness the operator's configuration names for a
// trail: where it serves SPEC.md §6's paths, and its key, pinned from the
// witness's operator, by which its keyId is derived.
type namedWitness struct {
	origin    string
	publicKey []byte
	keyID     string
}

// namedWitnessOf holds one entry of witnessedBy to its form: an origin of
// the form above, and a public key of 64 lowercase hexadecimal characters
// the key rule (SPEC.md §8.4) takes. where names the entry in a refusal.
func namedWitnessOf(trail, origin, publicKey, where string) (namedWitness, error) {
	if !isLowerHexOfLen(trail, 32) {
		return namedWitness{}, fmt.Errorf("%s names a trail that is not 32 lowercase hexadecimal characters", where)
	}
	if !isWitnessOrigin(origin) {
		return namedWitness{}, fmt.Errorf("%s: origin is not https://<host>:<port>, or http://<a loopback address>:<port>, with a lowercase host, an explicit port and nothing after it", where)
	}
	if !isLowerHexOfLen(publicKey, 64) {
		return namedWitness{}, fmt.Errorf("%s: publicKey is not a key of 64 lowercase hexadecimal characters", where)
	}
	raw, _ := hex.DecodeString(publicKey)
	if reason := unusableSigningKey(raw); reason != "" {
		return namedWitness{}, fmt.Errorf("%s: publicKey names a key that %s", where, reason)
	}
	return namedWitness{origin: origin, publicKey: raw, keyID: keyIDFor(raw)}, nil
}

var witnessedByMembers = map[string]bool{"origin": true, "publicKey": true}

// parseWitnessedBy reads the configuration's witnessedBy member, a
// version-7 member: an object keyed by trail identity whose values are
// {origin, publicKey}. A trail given twice is a name given twice, which the
// parser has refused already.
func parseWitnessedBy(v value, version string) (map[string]namedWitness, error) {
	if !versionAtLeast(version, "7") {
		return nil, fmt.Errorf("witnessedBy is a version-7 member; engineVersion %s has no witnessedBy", version)
	}
	obj, err := requireObject(v, "witnessedBy")
	if err != nil {
		return nil, errors.New("witnessedBy must be an object keyed by trail identity")
	}
	named := map[string]namedWitness{}
	for _, trail := range obj.names {
		where := "witnessedBy." + requestText(trail)
		entryV, _ := obj.get(trail)
		entry, err := requireObject(entryV, where)
		if err != nil {
			return nil, fmt.Errorf("%s must be an object of origin and publicKey", where)
		}
		if err := exactlyMembers(entry, witnessedByMembers, where); err != nil {
			return nil, err
		}
		origin, _ := memberString(entry, "origin")
		publicKey, _ := memberString(entry, "publicKey")
		w, err := namedWitnessOf(trail, origin, publicKey, where)
		if err != nil {
			return nil, err
		}
		named[trail] = w
	}
	return named, nil
}

// parseWitnessedByFlag reads one --witnessed-by TRAIL=ORIGIN,PUBLICKEY.
func parseWitnessedByFlag(arg string) (string, namedWitness, error) {
	trail, rest, found := strings.Cut(arg, "=")
	origin, publicKey, comma := strings.Cut(rest, ",")
	if !found || !comma {
		return "", namedWitness{}, errors.New("--witnessed-by expects TRAIL=ORIGIN,PUBLICKEY")
	}
	w, err := namedWitnessOf(trail, origin, publicKey, "--witnessed-by "+requestText(trail))
	return trail, w, err
}

// holdWitnessedBy is why a gateway may not start naming these witnesses, or
// nil: a witness named with the gateway's own key -- compared by the key's
// bytes, whatever spelled it -- is no witness against the operator, who can
// use that key (ADR-0013 §1); and the member is a version 3 member.
func holdWitnessedBy(named map[string]namedWitness, ownPublicKey []byte, receiptVersion string) error {
	if len(named) == 0 {
		return nil
	}
	if receiptVersion != receiptVersion3 {
		return errors.New("a witness named for a trail needs receipt version 3: the member that names it is a version 3 member")
	}
	trails := make([]string, 0, len(named))
	for trail := range named {
		trails = append(trails, trail)
	}
	sort.Strings(trails)
	for _, trail := range trails {
		if bytes.Equal(named[trail].publicKey, ownPublicKey) {
			return fmt.Errorf("the witness named for trail %s has this gateway's own key; a gateway whose key the operator can use is no witness against the operator", trail)
		}
	}
	return nil
}

// witnessMember is the member a receipt minted for trail carries, or nil
// when the configuration names no witness for it -- and then the receipt
// is the receipt it was before the member existed.
func (g *gatewayService) witnessMember(trail string) *vObject {
	w, named := g.witnessedBy[trail]
	if trail == "" || !named {
		return nil
	}
	member := newObject()
	member.set("origin", vString(w.origin))
	member.set("keyId", vString(w.keyID))
	member.set("trail", vString(trail))
	return member
}

// recordTrail is the trail of a record /act found, read from the bytes whose
// digest matched: a runtime evaluation record's trail when it is 32
// lowercase hexadecimal characters, and "" for any other record.
func recordTrail(data []byte) string {
	record, _ := readRuntimeRecord(data)
	if record == nil {
		return ""
	}
	trail, _ := memberString(record.obj, "trail")
	if !isLowerHexOfLen(trail, 32) {
		return ""
	}
	return trail
}
