package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// The harness for delegated calls (SPEC.md §11): a gateway serving the
// action-keys fixture sources under an identity and a delegation, an issuing
// host answering its admission and standing reads over TLS, and a run holding
// a proof-of-possession key.

var delegationHostSeed = []byte("judgment-pack-delegation-host-01")

const (
	testIssuerURL  = "https://login.example"
	hostRequester  = "service:desk"
	testOperator   = "operator:on-call"
	testSubjectSub = "approver-7"
	rootAgent      = "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1"
	childAgent     = "a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2"
	otherAgent     = "a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9"
)

var testSoftware = map[string]any{"package": "judgment-pack-agent", "version": "0.13.0"}

func testSub() map[string]any {
	return map[string]any{"kind": "person", "issuer": testIssuerURL, "subject": testSubjectSub}
}

// issuingHost stands in for the issuing host's admission endpoint.
type issuingHost struct {
	server *httptest.Server
	bearer string
	mu     sync.Mutex
	reads  []map[string]any
	// answer is what the host says to a read; nil admits every call and
	// answers every subject current.
	answer func(body map[string]any) (int, string)
}

func newIssuingHost(t *testing.T) *issuingHost {
	t.Helper()
	h := &issuingHost{bearer: "admission-credential-1"}
	h.server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+h.bearer || r.Method != http.MethodPost {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		// Where a redirect would lead: an answer that admits everything.
		if r.URL.Path == "/elsewhere" {
			_, _ = io.WriteString(w, `{"admission":"admit"}`)
			return
		}
		raw, _ := io.ReadAll(r.Body)
		var body map[string]any
		if err := json.Unmarshal(raw, &body); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		h.mu.Lock()
		h.reads = append(h.reads, body)
		answer := h.answer
		h.mu.Unlock()
		status, text := http.StatusOK, `{"admission":"admit"}`
		if _, standing := body["standing"]; standing {
			text = `{"standing":"current"}`
		}
		if answer != nil {
			status, text = answer(body)
		}
		if status >= 300 && status < 400 {
			w.Header().Set("Location", h.server.URL+"/elsewhere")
		}
		w.WriteHeader(status)
		_, _ = io.WriteString(w, text)
	}))
	t.Cleanup(h.server.Close)
	return h
}

// counted is how many reads asked the host to count a dispatch.
func (h *issuingHost) counted() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	n := 0
	for _, r := range h.reads {
		if call, ok := r["call"].(map[string]any); ok && call["count"] == true {
			n++
		}
	}
	return n
}

func (h *issuingHost) readCount() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return len(h.reads)
}

func (h *issuingHost) setAnswer(f func(body map[string]any) (int, string)) {
	h.mu.Lock()
	h.answer = f
	h.mu.Unlock()
}

type delegationHarness struct {
	root   string
	g      *gatewayService
	d      *delegationService
	server *httptest.Server
	issuer *testIssuer
	host   *issuingHost
	runKey ed25519.PrivateKey
	runJWK map[string]any
	call   actionKeysCall
	mu     sync.Mutex
	now    time.Time
}

func newDelegationHarness(t *testing.T, bearerReadOnly bool) *delegationHarness {
	t.Helper()
	if !actionJournalSupported {
		t.Skip("keyed dispatch fails closed on this host")
	}
	t.Setenv(envSourceHelper, "1")
	root := t.TempDir()
	actionKeysMode(t, root, "write", "respond")
	actionKeysMode(t, root, "live", "read")
	sources := actionKeysSources(t, root, os.Args[0])
	live, write := sources["tickets/live"], sources["tickets/write"]
	live.effects = map[string]string{"query": "read-external"}
	write.effects = map[string]string{"query": "act"}
	sources["tickets/live"], sources["tickets/write"] = live, write
	g := actionKeysService(t, root, sources)
	issuer := newIssuer(t)
	id := identityFor(t, issuer)
	g.identity = &id
	call := actionKeysPrepare(t, g, root)
	host := newIssuingHost(t)
	pub := ed25519.NewKeyFromSeed(delegationHostSeed).Public().(ed25519.PublicKey)
	d := newDelegationService(map[string]*delegationHost{"desk": {
		delegationHostSpec: delegationHostSpec{host: "desk", requester: hostRequester, keys: map[string]ed25519.PublicKey{keyIDFor(pub): pub}, admission: host.server.URL},
		bearer:             host.bearer,
	}}, []string{testOperator}, bearerReadOnly)
	pool := x509.NewCertPool()
	pool.AddCert(host.server.Certificate())
	d.client = admissionClient(pool)
	h := &delegationHarness{root: root, g: g, d: d, issuer: issuer, host: host, call: call, now: time.Date(2026, 10, 30, 1, 0, 0, 0, time.UTC)}
	d.now = func() time.Time { h.mu.Lock(); defer h.mu.Unlock(); return h.now }
	g.attachDelegation(d)
	runPub, runKey, _ := ed25519.GenerateKey(rand.Reader)
	h.runKey = runKey
	h.runJWK = map[string]any{"kty": "OKP", "crv": "Ed25519", "x": b64(runPub)}
	h.server = httptest.NewServer(g.handler())
	t.Cleanup(h.server.Close)
	return h
}

func (h *delegationHarness) setNow(t time.Time) { h.mu.Lock(); h.now = t; h.mu.Unlock() }

// token is a token of the configured issuer for subject.
func (h *delegationHarness) token(t *testing.T, subject string) string {
	t.Helper()
	now := time.Now()
	return h.issuer.mint(t, "ed-1", nil, map[string]any{"iss": testIssuerURL, "sub": subject, "aud": "gateway:acme", "exp": now.Add(time.Hour).Unix(), "iat": now.Unix()})
}

// statement signs a link under the issuing host's key: the defaults are a
// root of rootAgent with read-external on tickets/live and act on
// tickets/write, valid from midnight to eight; fields replace members, and
// a nil field removes one.
func statement(t *testing.T, fields map[string]any) map[string]any {
	t.Helper()
	priv := ed25519.NewKeyFromSeed(delegationHostSeed)
	s := map[string]any{
		"delegationVersion": "1", "id": strings.Repeat("11", 16), "host": "desk",
		"keyId": keyIDFor(priv.Public().(ed25519.PublicKey)), "sub": testSub(),
		"act": map[string]any{"agent": rootAgent, "software": testSoftware},
		"scope": map[string]any{"sources": []any{
			scopeOf("tickets/live", []any{"query"}, []any{"read-external"}, map[string]any{"calls": 10}),
			scopeOf("tickets/write", []any{"query"}, []any{"act"}, map[string]any{}),
		}},
		"mayDelegate": true, "issuedAt": "2026-10-30T00:00:00.000Z", "expiresAt": "2026-10-30T08:00:00.000Z",
		"parent": nil, "depth": 0,
	}
	for k, v := range fields {
		if v == nil && k != "parent" {
			delete(s, k)
			continue
		}
		s[k] = v
	}
	delete(s, "signature")
	signed := ed25519.Sign(priv, append([]byte(delegationContext), statementCanon(t, s)...))
	s["signature"] = hex.EncodeToString(signed)
	return s
}

func scopeOf(source string, tools, effects []any, limits map[string]any) map[string]any {
	return map[string]any{"audience": map[string]any{"kind": "gateway", "name": "gateway:test"}, "source": source, "tools": tools, "effects": effects, "limits": limits}
}

func statementCanon(t *testing.T, v any) []byte {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := parseJSON(raw)
	if err != nil {
		t.Fatal(err)
	}
	return canon(parsed)
}

func statementDigest(t *testing.T, s map[string]any) string {
	sum := sha256.Sum256(statementCanon(t, s))
	return "sha256:" + hex.EncodeToString(sum[:])
}

// childOf is a link below parent, for childAgent, with read-external on
// tickets/live alone unless fields say otherwise.
func childOf(t *testing.T, parent map[string]any, fields map[string]any) map[string]any {
	t.Helper()
	f := map[string]any{
		"id": strings.Repeat("22", 16), "act": map[string]any{"agent": childAgent, "software": testSoftware},
		"scope":  map[string]any{"sources": []any{scopeOf("tickets/live", []any{"query"}, []any{"read-external"}, map[string]any{"calls": 5})}},
		"parent": map[string]any{"id": parent["id"], "digest": statementDigest(t, parent)},
		"depth":  parent["depth"].(int) + 1, "expiresAt": "2026-10-30T04:00:00.000Z",
	}
	for k, v := range fields {
		f[k] = v
	}
	return statement(t, f)
}

// post sends body to path with the headers given and decodes the answer.
func (h *delegationHarness) post(t *testing.T, path, body string, headers map[string]string) (int, map[string]any) {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, h.server.URL+path, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	var out map[string]any
	_ = json.Unmarshal(raw, &out)
	return resp.StatusCode, out
}

// bind asks for a credential as the issuing host, with the run's key, or
// with key as given when it is not nil ("null" for a bearer credential).
func (h *delegationHarness) bind(t *testing.T, chain []map[string]any, key any) (int, map[string]any) {
	t.Helper()
	if key == nil {
		key = h.runJWK
	}
	body, _ := json.Marshal(map[string]any{"chain": chain, "software": testSoftware, "key": key})
	if key == "null" {
		body = []byte(strings.Replace(string(body), `"key":"null"`, `"key":null`, 1))
	}
	return h.post(t, "/delegation/credential", string(body), map[string]string{"Authorization": "Bearer " + h.token(t, hostRequester)})
}

func (h *delegationHarness) credential(t *testing.T, chain ...map[string]any) string {
	t.Helper()
	status, out := h.bind(t, chain, nil)
	if status != http.StatusOK {
		t.Fatalf("bind: %d %v", status, out)
	}
	return out["credential"].(string)
}

// proof is a DPoP proof of the run's key for path, signed by key (the run's
// when nil), with claims replaced by those given.
func (h *delegationHarness) proof(t *testing.T, path, credential string, key ed25519.PrivateKey, claims map[string]any) string {
	t.Helper()
	jwk := h.runJWK
	if key == nil {
		key = h.runKey
	} else {
		jwk = map[string]any{"kty": "OKP", "crv": "Ed25519", "x": b64(key.Public().(ed25519.PublicKey))}
	}
	jti := make([]byte, 12)
	_, _ = rand.Read(jti)
	sum := sha256.Sum256([]byte(credential))
	h.mu.Lock()
	iat := h.now.Unix()
	h.mu.Unlock()
	c := map[string]any{"jti": b64(jti), "htm": "POST", "htu": h.server.URL + path, "iat": iat, "ath": b64(sum[:])}
	for k, v := range claims {
		c[k] = v
	}
	hb, _ := json.Marshal(map[string]any{"typ": "dpop+jwt", "alg": "EdDSA", "jwk": jwk})
	cb, _ := json.Marshal(c)
	signed := b64(hb) + "." + b64(cb)
	return signed + "." + b64(ed25519.Sign(key, []byte(signed)))
}

// present calls path with a credential and a fresh proof.
func (h *delegationHarness) present(t *testing.T, path, body, credential string) (int, map[string]any) {
	t.Helper()
	return h.post(t, path, body, map[string]string{"Authorization": "DPoP " + credential, "DPoP": h.proof(t, path, credential, nil, nil)})
}

func (h *delegationHarness) acquireBody(session, tool string) string {
	return `{"session":"` + session + `","source":"tickets/live","arguments":{"tool":"` + tool + `","arguments":{"key":"k"}}}`
}

func (h *delegationHarness) actBody(session, key string, extra string) string {
	return `{"session":"` + session + `","platform":"tickets","tool":"query","arguments":{"ticket":"T-1"},"decision":` + string(h.call.Decision) + `,"cites":` + string(h.call.Cites) + `,"actionKey":"` + key + `"` + extra + `}`
}

func (h *delegationHarness) sent(key string) int { return actionKeysSent(h.root, key) }

func (h *delegationHarness) reservationOf(sub map[string]any, rootActor string) string {
	raw, _ := json.Marshal(map[string]any{"sub": sub, "rootActor": rootActor, "host": "desk"})
	return `,"reservation":` + string(raw)
}

func refusalOf(out map[string]any) string {
	s, _ := out["refusal"].(string)
	return s
}

func delegationKey(n int) string { return strings.Repeat(string("0123456789abcdef"[n%16]), 64) }

var _ = filepath.Join
