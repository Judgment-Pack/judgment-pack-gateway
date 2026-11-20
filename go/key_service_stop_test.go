package main

// The last review round of ADR-0050 (#431): every series's first receipt
// held to the history at a seed's start and a key service's, signingPublicKey
// required beside signingKeyVersion, a SIGHUP rotation whose append failed
// stopping the gateway, and SIGHUP refused on a witness.

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
)

// seriesStandIn is an indexedSpace of series held in order, each a list of
// receipts; only the reads heldUnderAnotherKey makes are answered.
type seriesStandIn struct {
	indexedSpace
	names   []string
	entries map[string][][]byte
}

func (s seriesStandIn) listSeries() ([]string, error) { return s.names, nil }
func (s seriesStandIn) listEntries(series string) ([]string, error) {
	var names []string
	for i := range s.entries[series] {
		names = append(names, string(rune('a'+i)))
	}
	return names, nil
}
func (s seriesStandIn) getEntry(series, entry string) ([]byte, error) {
	return s.entries[series][entry[0]-'a'], nil
}

// A series holding no receipt is passed over, and the next one's first
// receipt is read: one under a key no rotation leads from refuses.
func TestAnEmptyFirstSeriesDoesNotHideASeriesUnderAnotherKey(t *testing.T) {
	own := ed25519.NewKeyFromSeed(testSeed).Public().(ed25519.PublicKey)
	other := ksKey("one").Public().(ed25519.PublicKey)
	keys := []reachedKey{{keyID: keyIDFor(own), key: own}}
	receipt := func(key ed25519.PublicKey) []byte { return []byte(`{"keyId":"` + keyIDFor(key) + `"}`) }
	space := seriesStandIn{names: []string{"a-empty", "b-other"}, entries: map[string][][]byte{"b-other": {receipt(other)}}}
	if err := heldUnderAnotherKey(nil, keys, own, space); err == nil || !strings.Contains(err.Error(), "the store holds a receipt that is under key id "+keyIDFor(other)) {
		t.Fatalf("an empty first series hid a series under another key: %v", err)
	}
	space.entries["b-other"] = [][]byte{receipt(own)}
	if err := heldUnderAnotherKey(nil, keys, own, space); err != nil {
		t.Fatalf("an empty first series and one under the gateway's key: %v", err)
	}
}

// A history under the key service's key B, then a start under seed A: the
// seed's start is held to the history as a key service's is, so the store
// is never left mixed without a rotation, and B starts again over it.
func TestASeedDoesNotStartOverAKeyServicesHistory(t *testing.T) {
	standInKeyService(t)
	b := mustKeyServiceSigner(t, ksVersion1)
	served, store, registry := ksService(t, b)
	mustAcquire(t, served, "under-b")
	if _, err := newGatewayServiceSigned(store, testSeed, nil, "gateway:test", registry, ksSources()); err == nil || !strings.Contains(err.Error(), "the store holds a receipt that is under key id "+keyIDFor(ksKey("one").Public().(ed25519.PublicKey))) {
		t.Fatalf("seed A started over B's receipts: %v", err)
	}
	mustSeal(t, served, "under-b")
	if _, err := newGatewayServiceSigned(store, testSeed, nil, "gateway:test", registry, ksSources()); err == nil || !strings.Contains(err.Error(), "the registry holds a record that is under key id "+keyIDFor(ksKey("one").Public().(ed25519.PublicKey))) {
		t.Fatalf("seed A started over B's registry: %v", err)
	}
	if _, err := newGatewayServiceSigned(store, testSeed, b, "gateway:test", registry, ksSources()); err != nil {
		t.Fatalf("B again, over its own history alone: %v", err)
	}
}

// failingAppend is the registry's log with its appends failing, written
// bytes of the record answered as n.
type failingAppend struct {
	appendLog
	n int
}

func (l failingAppend) appendRecord([]byte) (int, error) {
	return l.n, errors.New("synthetic append failure")
}

// A SIGHUP rotation whose append failed, a byte of it written or none,
// switches nothing and stops the gateway; a refusal before the append
// does not stop it.
func TestASIGHUPRotationWhoseAppendFailedStopsTheGateway(t *testing.T) {
	standInKeyService(t)
	seedKeyID := keyIDFor(ed25519.NewKeyFromSeed(testSeed).Public().(ed25519.PublicKey))
	one := hex.EncodeToString(ksKey("one").Public().(ed25519.PublicKey))
	for _, n := range []int{0, 7} {
		g, _, _ := ksService(t, nil)
		reread := engineConfig{signingKeyVersion: ksVersion1, signingPublicKey: hex.EncodeToString(ksKey("two").Public().(ed25519.PublicKey))}
		g.rereadConfig = func() (engineConfig, error) { return reread, nil }
		var stopped error
		stop := func(err error) { stopped = err }
		var said bytes.Buffer
		if g.answerHangup(ksStamper, &said, stop) || stopped != nil {
			t.Fatalf("a refusal before the append stopped the gateway: %v", stopped)
		}
		reread.signingPublicKey = one
		g.registry.log = failingAppend{appendLog: g.registry.log, n: n}
		var written rotationMayBeWritten
		if !g.answerHangup(ksStamper, &said, stop) || !errors.As(stopped, &written) || !strings.Contains(stopped.Error(), "and stops") {
			t.Fatalf("written %d: a failed rotation append did not stop the gateway: %v", n, stopped)
		}
		if g.ownKeyID() != seedKeyID || !strings.Contains(said.String(), "synthetic append failure") {
			t.Fatalf("written %d: the gateway switched, or said nothing: %s %q", n, g.ownKeyID(), said.String())
		}
	}
}

// A gateway serving as a witness refuses a SIGHUP rotation, though the
// configuration read again names no witness.
func TestASIGHUPRotationIsRefusedOnAWitness(t *testing.T) {
	standInKeyService(t)
	g, _, _ := ksService(t, nil)
	g.witness = &witnessService{}
	g.rereadConfig = func() (engineConfig, error) {
		return engineConfig{signingKeyVersion: ksVersion1, signingPublicKey: hex.EncodeToString(ksKey("one").Public().(ed25519.PublicKey))}, nil
	}
	if _, err := g.rotateOnHangup(ksStamper); !errors.Is(err, errRotationBesideWitness) || g.ownKeyID() != keyIDFor(ed25519.NewKeyFromSeed(testSeed).Public().(ed25519.PublicKey)) {
		t.Fatalf("a witness rotated to the key service: %v", err)
	}
}
