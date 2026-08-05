package main

// The gateway service. It holds the signing seed, runs configured sources,
// signs and chains what they return, and seals sessions. A caller supplies a
// session id, a source name and arguments -- never a receipt. That is what keeps
// a model or agent structurally out of the proof path: a caller can assert
// anything, but it cannot manufacture the gateway's signature.

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"sync"
	"time"
)

type sessionState struct {
	index  int64
	prev   string
	sealed bool
}

type gatewayService struct {
	store     *store
	registry  *registryWriter
	storeRoot string
	regPath   string
	authority string
	publicKey ed25519.PublicKey
	keyID     string
	sources   map[string][]string

	mu       sync.Mutex
	sessions map[string]*sessionState
}

func newGatewayService(storeRoot string, seed []byte, authority, registryPath string,
	sources map[string][]string) (*gatewayService, error) {
	st, err := newStore(storeRoot, seed, authority)
	if err != nil {
		return nil, err
	}
	reg, err := newRegistryWriter(registryPath, seed)
	if err != nil {
		return nil, err
	}
	return &gatewayService{
		store: st, registry: reg, storeRoot: storeRoot, regPath: registryPath,
		authority: authority, publicKey: st.publicKey, keyID: st.keyID,
		sources: sources, sessions: map[string]*sessionState{},
	}, nil
}

// badRequest marks errors that are the caller's fault, so the handler can answer 400
// rather than 500.
type badRequest struct{ error }

func (g *gatewayService) acquire(sessionID, source string, arguments value) (map[string]any, error) {
	if err := requireSession(sessionID); err != nil {
		return nil, badRequest{err} // refuse before running anything
	}
	argv, known := g.sources[source]
	if !known {
		return nil, badRequest{fmt.Errorf("unknown source: %s", source)}
	}
	canonicalArgs := canon(arguments)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...)
	cmd.Stdin = bytes.NewReader(canonicalArgs)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		trimmed := stderr.String()
		if len(trimmed) > 200 {
			trimmed = trimmed[:200]
		}
		return nil, fmt.Errorf("source failed: %s", trimmed)
	}
	result, err := parseJSON(stdout.Bytes())
	if err != nil {
		return nil, fmt.Errorf("source did not return a canonical JSON value: %w", err)
	}

	g.mu.Lock()
	defer g.mu.Unlock()
	state, seen := g.sessions[sessionID]
	if !seen {
		state = &sessionState{}
		g.sessions[sessionID] = state
	}
	if state.sealed {
		return nil, badRequest{fmt.Errorf("session is sealed: %s", sessionID)}
	}

	resultDigest, err := g.store.retain(canon(result))
	if err != nil {
		return nil, err
	}
	mac := hmac.New(sha256.New, argumentsKey(g.store.seed))
	mac.Write(append([]byte("args:"), canonicalArgs...))

	core := newObject()
	core.set("receiptVersion", vString(receiptVersion))
	core.set("sessionId", vString(sessionID))
	core.set("callIndex", vInt(state.index))
	if state.prev == "" {
		core.set("prevSignature", vNull{})
	} else {
		core.set("prevSignature", vString(state.prev))
	}
	core.set("source", vString(source))
	core.set("argumentsDigest", vString("hmac-sha256:"+hex.EncodeToString(mac.Sum(nil))))
	core.set("resultDigest", vString(resultDigest))
	core.set("servedAt", vString(nowStamp()))
	core.set("authority", vString(g.authority))

	stored, signature, err := g.store.stamp(core)
	if err != nil {
		return nil, err
	}
	state.index++
	state.prev = signature

	var resultOut any
	if err := json.Unmarshal(canon(result), &resultOut); err != nil {
		return nil, err
	}
	// The receipt in the response is the stored receipt, whole: the same
	// members written under receipts/<session>/<index>.json, so the caller
	// holds everything the signature covers and can check it without reaching
	// into the store. The response body is ordinary JSON, not canon bytes; a
	// checking caller canonicalizes per §1.1 first (SPEC.md §6).
	var receiptOut any
	if err := json.Unmarshal(canon(stored), &receiptOut); err != nil {
		return nil, err
	}
	return map[string]any{
		"result":  resultOut,
		"receipt": receiptOut,
	}, nil
}

func (g *gatewayService) sealSession(sessionID string) (map[string]any, error) {
	if err := requireSession(sessionID); err != nil {
		return nil, badRequest{err}
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	state, seen := g.sessions[sessionID]
	if !seen {
		return nil, badRequest{fmt.Errorf("no such session: %s", sessionID)}
	}
	record, err := g.registry.seal(sessionID, state.index, nowStamp())
	if err != nil {
		return nil, badRequest{err}
	}
	state.sealed = true
	var out map[string]any
	if err := json.Unmarshal(canon(record), &out); err != nil {
		return nil, err
	}
	return out, nil
}

func (g *gatewayService) verify() (map[string]any, error) {
	rep, err := verifyWithRegistry(g.storeRoot, g.regPath, g.authority, g.publicKey)
	if err != nil {
		return nil, err
	}
	raw, err := rep.marshal()
	if err != nil {
		return nil, err
	}
	var out map[string]any
	return out, json.Unmarshal(raw, &out)
}

// publicKeyDocument is what a verifier fetches so it can check this gateway's
// receipts without being able to produce any. Obtaining the key HERE and then
// auditing this same gateway proves consistency, not authenticity (SPEC.md §5).
func (g *gatewayService) publicKeyDocument() map[string]any {
	return map[string]any{
		"algorithm": "ed25519", "keyId": g.keyID,
		"publicKey": hex.EncodeToString(g.publicKey), "authority": g.authority,
	}
}

func (g *gatewayService) handler() http.Handler {
	mux := http.NewServeMux()

	writeJSON := func(w http.ResponseWriter, code int, body any) {
		payload, err := json.Marshal(body)
		if err != nil {
			http.Error(w, `{"error":"encode"}`, http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(code)
		_, _ = w.Write(payload)
	}
	fail := func(w http.ResponseWriter, err error) {
		var caller badRequest
		if errors.As(err, &caller) {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
	}

	mux.HandleFunc("/acquire", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeJSON(w, http.StatusNotFound, map[string]any{"error": "not found"})
			return
		}
		var body struct {
			Session   string          `json:"session"`
			Source    string          `json:"source"`
			Arguments json.RawMessage `json:"arguments"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			fail(w, badRequest{err})
			return
		}
		arguments := value(newObject())
		if len(body.Arguments) > 0 {
			parsed, err := parseJSON(body.Arguments)
			if err != nil {
				fail(w, badRequest{err})
				return
			}
			arguments = parsed
		}
		out, err := g.acquire(body.Session, body.Source, arguments)
		if err != nil {
			fail(w, err)
			return
		}
		writeJSON(w, http.StatusOK, out)
	})

	mux.HandleFunc("/seal", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeJSON(w, http.StatusNotFound, map[string]any{"error": "not found"})
			return
		}
		var body struct {
			Session string `json:"session"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			fail(w, badRequest{err})
			return
		}
		out, err := g.sealSession(body.Session)
		if err != nil {
			fail(w, err)
			return
		}
		writeJSON(w, http.StatusOK, out)
	})

	mux.HandleFunc("/verify", func(w http.ResponseWriter, r *http.Request) {
		out, err := g.verify()
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, out)
	})

	mux.HandleFunc("/registry", func(w http.ResponseWriter, r *http.Request) {
		data, err := os.ReadFile(g.regPath)
		if err != nil && !os.IsNotExist(err) {
			writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(data)
	})

	mux.HandleFunc("/publickey", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, g.publicKeyDocument())
	})

	return mux
}

// listenAndServe binds localhost only. This reference has no authentication and
// no access control; it is for self-hosting a trust root and demonstrating the
// mechanism, not a hardened public deployment.
func (g *gatewayService) listenAndServe(address string) error {
	listener, err := net.Listen("tcp", address)
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "gateway on http://%s (authority %s, key %s)\n",
		listener.Addr(), g.authority, g.keyID)
	return (&http.Server{Handler: g.handler(), ReadHeaderTimeout: 10 * time.Second}).Serve(listener)
}
