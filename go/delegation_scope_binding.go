package main

import "crypto/subtle"

// A chain bound to one scope identifier (spec RFC 0030 §2, Binding a chain
// to one scope identifier; §3, clause 9; SPEC.md §11.1, §11.5). A link's
// scope.scopeId binds it, clause 9 makes every link of a chain agree, and the
// request check below holds each request under a chain to that binding: once
// step 0 has resolved the chain, before step 8 and before any admission read.
// It reads no issuing host, counts nothing and dispatches nothing.

// refusalScopeIDMismatch is the request check's refusal where a refusal name
// is answered: at binding. On /acquire and /act it is answered with
// /acquire's sentence of a wrong scope (scopeRefusal), which names no scope
// identifier.
const refusalScopeIDMismatch = "scope-id-mismatch"

// bindsScope is whether the host's configuration lets its delegations be
// bound to id (scopeIds; open question 27). None by default.
func (h *delegationHost) bindsScope(id string) bool {
	return h != nil && h.scopeIDs[id]
}

// bindingRefused is case 3 of the request check for a chain on its own: a
// bound chain whose scope identifier the issuing host's entry does not name.
// It is refused at binding as at every call, so no credential is bound to a
// chain every call would be refused under.
func (d *delegationService) bindingRefused(host *delegationHost, chain *delegationChain) bool {
	id, bound := chain.scopeBinding()
	return bound && !host.bindsScope(id)
}

// scopeIDMismatch is the request check for a request that names asked, made
// by s: under a bound chain, a request that names no scope identifier, or one
// other than the chain's, or that the issuing host may not bind (cases 1 and
// 3); under an unbound chain, a request that names one (case 2). A sender
// with no chain, one the sender table authenticated for a delegated key,
// reaches no scope identifier, so one that names any is refused too. Bytes
// are compared as scopeHolds compares them, in a time that does not depend on
// where they first differ.
func (d *delegationService) scopeIDMismatch(s *delegatedSender, asked requestedScope) bool {
	if s == nil || s.credential == nil {
		return asked.named
	}
	id, bound := s.credential.chain.scopeBinding()
	if !bound {
		return asked.named
	}
	if !asked.named || subtle.ConstantTimeCompare([]byte(asked.value), []byte(id)) != 1 {
		return true
	}
	// With no delegation configured no host may bind a chain, so a bound one
	// fails closed (bindsScope of nil is false).
	var host *delegationHost
	if d != nil {
		host = d.hosts[s.credential.host]
	}
	return d.bindingRefused(host, s.credential.chain)
}

// delegatedScopeRefused is the request check for a request on /acquire or
// /act under who's delegation; false for a request under none.
//
// /act calls it at ADR-0054's step 8 (refusedAt "scope-identifier"), with the
// scope the request names, or none: a delegated /act may name a scope only
// under a chain bound to that same scope identifier.
func (g *gatewayService) delegatedScopeRefused(who *caller, asked requestedScope) bool {
	if who == nil || who.delegated == nil {
		return false
	}
	return g.delegation.scopeIDMismatch(who.delegated, asked)
}
