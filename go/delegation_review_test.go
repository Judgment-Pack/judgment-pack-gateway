package main

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// The review of record on #363 (M1 to M4): the probes that pin what the
// earlier tests left free.

// signedProof is a DPoP proof with the header and claims given, signed by
// sign over its signing input.
func signedProof(header, claims map[string]any, sign func([]byte) []byte) string {
	hb, _ := json.Marshal(header)
	cb, _ := json.Marshal(claims)
	input := b64(hb) + "." + b64(cb)
	return input + "." + b64(sign([]byte(input)))
}

func (h *delegationHarness) claimsFor(path, credential string, iat time.Time) map[string]any {
	jti := make([]byte, 12)
	_, _ = rand.Read(jti)
	sum := sha256.Sum256([]byte(credential))
	return map[string]any{"jti": b64(jti), "htm": "POST", "htu": h.server.URL + path, "iat": iat.Unix(), "ath": b64(sum[:])}
}

// M1: a proof is typed dpop+jwt; a jti is refused for the whole window it
// could be accepted in, as the clock moves; a proof dated ahead of the
// window is refused; and ES256 binds and presents.
func TestDelegationProofIsPinned(t *testing.T) {
	h := newDelegationHarness(t, false)
	cred := h.credential(t, statement(t, nil))
	body := h.acquireBody("s1", "query")
	ed := func(b []byte) []byte { return ed25519.Sign(h.runKey, b) }
	header := func(typ string) map[string]any {
		return map[string]any{"typ": typ, "alg": "EdDSA", "jwk": h.runJWK}
	}
	present := func(proof string) (int, map[string]any) {
		return h.post(t, "/acquire", body, map[string]string{"Authorization": "DPoP " + cred, "DPoP": proof})
	}
	// K5: another typ.
	if status, out := present(signedProof(header("JWT"), h.claimsFor("/acquire", cred, h.now), ed)); status != http.StatusUnauthorized || refusalOf(out) != refusalCredentialMismatch {
		t.Fatalf("typ JWT: %d %v", status, out)
	}
	// K6: the same proof, accepted once, is refused 1.5 s later and 59 s
	// later, while its iat is still inside the window.
	proof := signedProof(header("dpop+jwt"), h.claimsFor("/acquire", cred, h.now), ed)
	if status, out := present(proof); status != http.StatusOK {
		t.Fatalf("first use: %d %v", status, out)
	}
	start := h.now
	for _, later := range []time.Duration{1500 * time.Millisecond, 59 * time.Second} {
		h.setNow(start.Add(later))
		if status, out := present(proof); status != http.StatusUnauthorized || refusalOf(out) != refusalCredentialMismatch {
			t.Fatalf("a replay %v later: %d %v", later, status, out)
		}
	}
	h.setNow(start)
	// K7: a proof dated ahead of the window, and one at its edge.
	if status, out := present(signedProof(header("dpop+jwt"), h.claimsFor("/acquire", cred, start.Add(10*time.Minute)), ed)); status != http.StatusUnauthorized || refusalOf(out) != refusalCredentialMismatch {
		t.Fatalf("a proof dated ten minutes ahead: %d %v", status, out)
	}
	if status, out := present(signedProof(header("dpop+jwt"), h.claimsFor("/acquire", cred, start.Add(61*time.Second)), ed)); status != http.StatusUnauthorized {
		t.Fatalf("a proof dated past the window: %d %v", status, out)
	}
	if status, out := present(signedProof(header("dpop+jwt"), h.claimsFor("/acquire", cred, start.Add(60*time.Second)), ed)); status != http.StatusOK {
		t.Fatalf("a proof at the window's edge: %d %v", status, out)
	}
}

// M1: a P-256 key binds, and an ES256 proof of it presents; the same key
// under alg EdDSA does not.
func TestDelegationProofES256(t *testing.T) {
	h := newDelegationHarness(t, false)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	jwk := map[string]any{"kty": "EC", "crv": "P-256", "x": b64(key.X.FillBytes(make([]byte, 32))), "y": b64(key.Y.FillBytes(make([]byte, 32)))}
	status, out := h.bind(t, []map[string]any{statement(t, nil)}, jwk)
	if status != http.StatusOK || out["tokenType"] != "DPoP" {
		t.Fatalf("bind a P-256 key: %d %v", status, out)
	}
	cred := out["credential"].(string)
	es := func(b []byte) []byte {
		digest := sha256.Sum256(b)
		r, s, _ := ecdsa.Sign(rand.Reader, key, digest[:])
		return append(r.FillBytes(make([]byte, 32)), s.FillBytes(make([]byte, 32))...)
	}
	present := func(alg string) (int, map[string]any) {
		proof := signedProof(map[string]any{"typ": "dpop+jwt", "alg": alg, "jwk": jwk}, h.claimsFor("/acquire", cred, h.now), es)
		return h.post(t, "/acquire", h.acquireBody("s1", "query"), map[string]string{"Authorization": "DPoP " + cred, "DPoP": proof})
	}
	if status, out := present("ES256"); status != http.StatusOK {
		t.Fatalf("an ES256 proof: %d %v", status, out)
	}
	if status, _ := present("EdDSA"); status != http.StatusUnauthorized {
		t.Fatalf("a P-256 key under EdDSA: %d", status)
	}
}

// withSecondHost configures a second issuing host, desk2, pinning the same
// key, as a gateway serving two hosts would.
func (h *delegationHarness) withSecondHost() {
	desk := h.d.hosts["desk"]
	h.d.hosts["desk2"] = &delegationHost{delegationHostSpec: delegationHostSpec{host: "desk2", requester: "service:desk2", keys: desk.keys, admission: desk.admission}, bearer: desk.bearer}
	h.d.keys["desk2"] = desk.keys
}

// M2: one issuing host neither ends another's credentials nor reaches its
// reservations.
func TestDelegationHostsAreIsolated(t *testing.T) {
	h := newDelegationHarness(t, false)
	h.withSecondHost()
	actionKeysMode(t, h.root, "write", "drop")
	cred := h.credential(t, statement(t, nil))
	other := h.token(t, "service:desk2")
	// K1: desk2 revoking desk's agent and delegation ends nothing.
	for _, body := range []string{`{"agent":"` + rootAgent + `"}`, `{"delegation":"` + strings.Repeat("11", 16) + `"}`, `{"credential":"` + tokenDigestOf(cred) + `"}`} {
		status, out := h.post(t, "/delegation/revoke", body, map[string]string{"Authorization": "Bearer " + other})
		if status != http.StatusOK || out["revoked"] != float64(0) {
			t.Fatalf("another host revokes %s: %d %v", body, status, out)
		}
	}
	key := delegationKey(8)
	if status, out := h.present(t, "/act", h.actBody("s1", key, ""), cred); status != http.StatusOK {
		t.Fatalf("desk's credential after desk2's revocations: %d %v", status, out)
	}
	// K2: desk2's token naming desk's reservation is refused; desk's is not.
	reservation := h.reservationOf(testSub(), rootAgent)
	status, out := h.post(t, "/act", h.actBody("s2", key, reservation), map[string]string{"Authorization": "Bearer " + other})
	if status != http.StatusForbidden || refusalOf(out) != refusalKeyUnauthenticated {
		t.Fatalf("another host's token on this host's reservation: %d %v", status, out)
	}
	if status, out := h.post(t, "/act", h.actBody("s3", key, reservation), map[string]string{"Authorization": "Bearer " + h.token(t, hostRequester)}); status != http.StatusOK {
		t.Fatalf("the reservation's own host: %d %v", status, out)
	}
	if h.sent(key) != 1 {
		t.Fatalf("sent %d", h.sent(key))
	}
}

// M3: an unreadable subject record refuses, rather than giving another root
// actor a reservation of its own; and the admission and standing reads take
// 200 alone.
func TestDelegationFailsClosedOnRecordsAndStatuses(t *testing.T) {
	h := newDelegationHarness(t, false)
	actionKeysMode(t, h.root, "write", "drop")
	key := delegationKey(9)
	cred := h.credential(t, statement(t, nil))
	if status, out := h.present(t, "/act", h.actBody("s1", key, ""), cred); status != http.StatusOK {
		t.Fatalf("dispatch: %d %v", status, out)
	}
	sender := &delegatedSender{scope: reservationScope{sub: principalRef{"person", testIssuerURL, testSubjectSub}, rootActor: rootAgent, host: "desk"}}
	record := filepath.Join(h.g.storeRoot, "actions", h.g.actionSubjectNamespace(sender, key), "scope.json")
	if err := os.Remove(record); err != nil {
		t.Fatal(err)
	}
	// K3: another root actor of the subject, with the record unreadable.
	other := h.credential(t, statement(t, map[string]any{"id": strings.Repeat("66", 16), "act": map[string]any{"agent": otherAgent, "software": testSoftware}}))
	status, out := h.present(t, "/act", h.actBody("s2", key, ""), other)
	if status != http.StatusBadRequest || !strings.Contains(out["error"].(string), "action-journal-invalid") || h.sent(key) != 1 {
		t.Fatalf("an unreadable subject record: %d %v, sent %d", status, out, h.sent(key))
	}
	// K4: a 2xx that is not 200 is no answer, for either read.
	for _, code := range []int{http.StatusCreated, http.StatusAccepted} {
		code := code
		h.host.setAnswer(func(b map[string]any) (int, string) {
			if _, standing := b["standing"]; standing {
				return code, `{"standing":"current"}`
			}
			return code, `{"admission":"admit"}`
		})
		if status, out := h.present(t, "/acquire", h.acquireBody("s3", "query"), cred); status != http.StatusForbidden || refusalOf(out) != refusalAdmissionUnknown {
			t.Fatalf("admission answered %d: %d %v", code, status, out)
		}
		status, out := h.post(t, "/act", h.actBody("s4", key, h.reservationOf(testSub(), rootAgent)), map[string]string{"Authorization": "Bearer " + h.token(t, testSubjectSub)})
		if status != http.StatusForbidden || refusalOf(out) != refusalStandingUnknown {
			t.Fatalf("standing answered %d: %d %v", code, status, out)
		}
	}
}

// M4: a receipt minted for a dispatch marker found without its answer is the
// dispatch's: its tokenDigest is the credential that dispatched, whoever
// found the marker, and the finder is named by the read-back's reconciler.
func TestDelegatedMarkerReceiptNamesTheDispatchingCredential(t *testing.T) {
	h := newDelegationHarness(t, false)
	actionKeysMode(t, h.root, "write", "drop")
	cred := h.credential(t, statement(t, nil))
	sender := &caller{delegated: &delegatedSender{scope: reservationScope{sub: principalRef{"person", testIssuerURL, testSubjectSub}, rootActor: rootAgent, host: "desk"}}}
	crash := func(key string) {
		t.Helper()
		if err := os.Remove(filepath.Join(h.g.storeRoot, "actions", h.g.actionNamespace(sender, key), "action.json")); err != nil {
			t.Fatal(err)
		}
	}
	check := func(out map[string]any, finderKind, finderDigest string) {
		t.Helper()
		action := out["action"].(map[string]any)["receipt"].(map[string]any)
		requester := action["action"].(map[string]any)["requester"].(map[string]any)
		callerOf := action["caller"].(map[string]any)
		if requester["tokenDigest"] != tokenDigestOf(cred) || callerOf["tokenDigest"] != tokenDigestOf(cred) || action["delegation"].(map[string]any)["id"] != strings.Repeat("11", 16) {
			t.Fatalf("the action receipt is not the dispatch's: %v %v %v", requester, callerOf, action["delegation"])
		}
		read, rec := reconciledBy(t, out)
		if rec["kind"] != finderKind || read["caller"].(map[string]any)["tokenDigest"] != finderDigest {
			t.Fatalf("the read-back names %v, caller %v", rec, read["caller"])
		}
	}
	// The issuing host finds the marker.
	key := delegationKey(10)
	if status, out := h.present(t, "/act", h.actBody("s1", key, ""), cred); status != http.StatusOK {
		t.Fatalf("dispatch: %d %v", status, out)
	}
	crash(key)
	hostToken := h.token(t, hostRequester)
	status, out := h.post(t, "/act", h.actBody("s2", key, h.reservationOf(testSub(), rootAgent)), map[string]string{"Authorization": "Bearer " + hostToken})
	if status != http.StatusOK {
		t.Fatalf("the host finds the marker: %d %v", status, out)
	}
	check(out, "host", tokenDigestOf(hostToken))
	// A takeover under a re-issued delegation finds it.
	key = delegationKey(11)
	if status, out := h.present(t, "/act", h.actBody("s3", key, ""), cred); status != http.StatusOK {
		t.Fatalf("dispatch: %d %v", status, out)
	}
	crash(key)
	takeover := h.credential(t, statement(t, map[string]any{"id": strings.Repeat("55", 16), "issuedAt": "2026-10-30T00:30:00.000Z"}))
	status, out = h.present(t, "/act", h.actBody("s4", key, ""), takeover)
	if status != http.StatusOK || h.sent(key) != 1 {
		t.Fatalf("the takeover finds the marker: %d %v, sent %d", status, out, h.sent(key))
	}
	check(out, "actor", tokenDigestOf(takeover))
	// A marker that records the admission but not the credential refuses.
	key = delegationKey(12)
	if status, out := h.present(t, "/act", h.actBody("s5", key, ""), cred); status != http.StatusOK {
		t.Fatalf("dispatch: %d %v", status, out)
	}
	crash(key)
	marker := filepath.Join(h.g.storeRoot, "actions", h.g.actionNamespace(sender, key), "dispatch-1.json")
	raw, err := os.ReadFile(marker)
	if err != nil {
		t.Fatal(err)
	}
	var recorded map[string]any
	if err := json.Unmarshal(raw, &recorded); err != nil || recorded["tokenDigest"] != tokenDigestOf(cred) {
		t.Fatalf("the marker: %s %v", raw, err)
	}
	delete(recorded, "tokenDigest")
	rewritten, _ := json.Marshal(recorded)
	if err := os.WriteFile(marker, rewritten, 0o600); err != nil {
		t.Fatal(err)
	}
	if status, out := h.present(t, "/act", h.actBody("s6", key, ""), cred); status != http.StatusBadRequest || !strings.Contains(out["error"].(string), "action-journal-invalid") {
		t.Fatalf("a marker recording no credential: %d %v", status, out)
	}
}
