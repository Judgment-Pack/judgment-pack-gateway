package main

// The routes' side of the request limits (ADR-0057, decisions 2 and 3, as
// the maintainer ruled them; gateway #507): one middleware takes a
// gateway-wide slot when a request arrives and releases what the request
// holds when its handler returns, however it ends. A route gives the slot
// back once the request's token is read (leaveBefore), so no request holds
// it across its body or its run, and charges the request to the scopes it
// reaches at the first step that knows them.

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"time"
)

// listenerReadHeaderTimeout and listenerReadTimeout bound how long a
// request's headers, and the whole request with its body, may take to
// arrive on every listener (listenerServer). A request takes a gateway-wide
// slot only once its headers are read, and gives it back once its token is
// read, so a client that sends slowly holds no slot: its headers are cut at
// the first bound, its body at the second.
const (
	listenerReadHeaderTimeout = 10 * time.Second
	listenerReadTimeout       = 30 * time.Second
)

// limitExempt are the routes the gateway-wide cap does not hold: the public
// key and its history, which a verifier fetches with no token, so verifiers
// still answer while the cap is full. /registry is held: it serves the whole
// registry log to anyone.
var limitExempt = map[string]bool{"/publickey": true, keyHistoryRoute: true}

type limitPassKey struct{}

// limitedHandler is next under the gateway-wide cap; next itself where no
// limits are configured, so a gateway without them serves as it did.
func (g *gatewayService) limitedHandler(next http.Handler) http.Handler {
	if g.limiter == nil {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if limitExempt[r.URL.Path] {
			next.ServeHTTP(w, r)
			return
		}
		pass, refused := g.limiter.enter()
		defer pass.release()
		if refused != nil {
			writeLimitRefusal(w, refused, "")
			return
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), limitPassKey{}, pass)))
	})
}

// limitPassOf is the request's pass, or the zero pass, which holds nothing,
// where no limits are configured.
func limitPassOf(r *http.Request) *limitPass {
	if p, ok := r.Context().Value(limitPassKey{}).(*limitPass); ok {
		return p
	}
	return &limitPass{}
}

// noteUnauthenticated counts a 401 on the request's limiter, if any.
func (p *limitPass) noteUnauthenticated() { p.l.noteUnauthenticated() }

// writeLimitRefusal is the 429 of a limiter refusal: Retry-After from the
// refusing state alone, and the fixed body, with refusedAt on /act. Nothing
// else is written: no stderr line, no receipt, no journal entry.
func writeLimitRefusal(w http.ResponseWriter, refused *limitRefusal, refusedAt string) {
	body := refused.body()
	if refusedAt != "" {
		body["refusedAt"] = refusedAt
	}
	payload, _ := json.Marshal(body)
	refused.setRetryAfter(w.Header())
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusTooManyRequests)
	_, _ = w.Write(payload)
}

// errLimitUncounted is the answer to a request the limiter could not
// count: refused, never served uncounted.
const errLimitUncounted = "limit: the request could not be counted"

// writeLimitFailure answers a charge's error: the 429 of a refusal, or 500
// for a request that could not be counted.
func writeLimitFailure(w http.ResponseWriter, err error, refusedAt string) {
	var refused *limitRefusal
	if errors.As(err, &refused) {
		writeLimitRefusal(w, refused, refusedAt)
		return
	}
	body := map[string]any{"error": errLimitUncounted}
	if refusedAt != "" {
		body["refusedAt"] = refusedAt
	}
	payload, _ := json.Marshal(body)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusInternalServerError)
	_, _ = w.Write(payload)
}

// limitCallerOfRequest is the key of the identity the request is
// authenticated as: a delegated request's authenticated sender, or the
// token's issuer and subject; nil with no identity.
func limitCallerOfRequest(who *caller) *limitCallerKey {
	if who == nil {
		return nil
	}
	k := limitCallerKeyOf("token", who.issuer, who.subject)
	if who.delegated != nil {
		k = limitCallerKeyOf("delegated", who.delegated.issuer, who.delegated.subject)
	}
	return &k
}

// oneScopeOf is the scope key of a caller whose reach takes one scope
// alone -- exactly one scope identifier, or the sources of none and nothing
// else -- and false for one that takes several, or every source.
func (g *gatewayService) oneScopeOf(who *caller) (string, bool) {
	reach := g.reachOf(who)
	switch {
	case reach.every:
		return "", false
	case reach.none && len(reach.ids) == 0:
		return unscopedMarker, true
	case !reach.none && len(reach.ids) == 1:
		for id := range reach.ids {
			return id, true
		}
	}
	return "", false
}

// reachedScopeKeys are the scope keys of every source a reach takes.
func (g *gatewayService) reachedScopeKeys(reach scopeReach) []string {
	var keys []string
	for key := range limitScopeKeys(reachedSources(g.sources, reach)) {
		keys = append(keys, key)
	}
	return keys
}

// chargeRequest charges the request to the scope keys given, all or
// nothing, as the caller it is authenticated as.
func chargeRequest(r *http.Request, who *caller, keys ...string) error {
	return limitPassOf(r).charge(limitCallerOfRequest(who), keys...)
}

// heldSessionScope is the scope of a session this process holds, read
// under the gateway's lock and nothing else.
func (g *gatewayService) heldSessionScope(id string) (string, bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	state := g.sessions[id]
	if state == nil {
		return "", false
	}
	return state.scope, true
}
