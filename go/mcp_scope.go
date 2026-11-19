package main

// The MCP server on platforms fixed to a scope identifier
// (docs/adr/0038-the-mcp-server-on-platforms-fixed-to-a-scope-identifier.md;
// docs/design/mcp-server.md, "Scope identifiers"). Engine configuration
// version 28 gives the mcp member one of two forms:
//
//   - scope, a scope identifier: the server is fixed to it. Its tool table
//     holds the live tools of the platforms fixed to that identifier and no
//     other, and every acquisition it forwards names it. Nothing is trusted
//     that a direct /acquire naming the identifier is not: the signer holds
//     the forward to the source's scope identifier and to the caller's token
//     (ADR-0037) as it holds any request.
//   - scopeFrom: "caller": the server serves the platforms of every scope
//     identifier, and every acquisition names the scope identifier of its
//     tool's platform. It is served over HTTP alone, where each request
//     carries its caller's token.
//
// In both, a caller is listed, and may call, the platform tools of the
// sources its verified token reaches, by the rule and the function the
// signer applies (ADR-0037, caller_scopes.go); the seal tool is listed to
// every caller, since the signer holds its /seal to the caller itself, and a
// server fixed to a scope identifier names it on every seal it forwards, so
// it seals that identifier's sessions alone (ADR-0041). A server taking its
// callers' scope identifiers bounds each one's listing on its own, and each
// caller's within the bound, so what one scope's platforms hold changes
// nothing another's caller is listed (ADR-0041). Over stdio the token is
// given at start, and its reach is read there once.
//
// A scope identifier never comes from the client: no tool's input schema
// gains a member, and a call's arguments are the platform tool's own,
// carried to the signer byte for byte and never read for one.

import (
	"encoding/json"
	"errors"
	"fmt"
)

// mcpScopeFromCaller is scopeFrom's one value.
const mcpScopeFromCaller = "caller"

// scoped is whether the server names a scope identifier on the acquisitions
// it forwards: it is fixed to one, or takes each from its tool's platform.
func (m *mcpConfig) scoped() bool { return m.scope != "" || m.scopeFromCaller }

// parseMCPScope reads mcp.scope and mcp.scopeFrom (engineVersion 28): one or
// neither, scope a scope identifier of §1.2a's form and scopeFrom the string
// "caller". A refusal names the member and the form, and quotes nothing of
// the value.
func parseMCPScope(obj *vObject, version string, m *mcpConfig) error {
	scopeValue, withScope := obj.get("scope")
	fromValue, withFrom := obj.get("scopeFrom")
	for _, member := range []struct {
		name    string
		present bool
	}{{"scope", withScope}, {"scopeFrom", withFrom}} {
		if member.present && !versionAtLeast(version, "28") {
			return fmt.Errorf("mcp.%s is a version-28 member; engineVersion %s has no mcp.%s", member.name, version, member.name)
		}
	}
	if withScope && withFrom {
		return errors.New("mcp.scope and mcp.scopeFrom are two forms of the server, one fixed to a scope identifier and one taking each caller's; give one")
	}
	if withScope {
		s, ok := stringOf(scopeValue)
		if !ok || !isScopeIdentifier(s) {
			return fmt.Errorf("mcp.scope must be a scope identifier, %s", scopeForm)
		}
		// the bytes "unscoped" are the caller scope marker, to which no
		// platform of this version is fixed (parsePlatformScope)
		if s == unscopedMarker {
			return fmt.Errorf("mcp.scope is %q, the marker of the sources of no scope identifier, to which no platform is fixed; fix the server to a platform's scope identifier, or leave mcp.scope out", unscopedMarker)
		}
		m.scope = s
	}
	if withFrom {
		if s, ok := stringOf(fromValue); !ok || s != mcpScopeFromCaller {
			return fmt.Errorf("mcp.scopeFrom must be the string %q, the one value it has", mcpScopeFromCaller)
		}
		m.scopeFromCaller = true
	}
	return nil
}

// mcpScopeFromRefusal refuses scopeFrom "caller" where no caller is held to
// scope identifiers: without identity, or with callerScopes "unchecked",
// every caller reaches every source (ADR-0037, decision 7), and a server that
// takes each caller's scope identifiers would serve every scope's tools to
// every caller.
func mcpScopeFromRefusal(m *mcpConfig, identity *identitySpec) error {
	if !m.scopeFromCaller {
		return nil
	}
	if identity == nil || identity.callers.unchecked {
		return fmt.Errorf("mcp.scopeFrom %q serves each caller the scope identifiers its token reaches, which needs identity with callerScopes checked; without identity, or with callerScopes \"unchecked\", every caller reaches every scope identifier", mcpScopeFromCaller)
	}
	return nil
}

// errStdioScopeFromCaller is the refusal of scopeFrom "caller" over stdio,
// where the host gives one token at start for the life of the process and no
// call carries its caller's: a stdio server takes mcp.scope.
var errStdioScopeFromCaller = fmt.Errorf("mcp.scopeFrom %q holds each call to its caller's token, and over --stdio one token is given at start for the life of the process; a server over --stdio is fixed to one scope identifier by mcp.scope, or serves --http", mcpScopeFromCaller)

// servedPlatforms are the platforms whose live tools the server serves: those
// fixed to its scope identifier where it is fixed to one, and every platform
// otherwise. A server of neither form serves no platform fixed to a scope
// identifier, since it names none on a forward: the configuration refuses one
// beside it, and a configuration built another way is refused here.
func servedPlatforms(cfg engineConfig) ([]platformConfig, error) {
	m := cfg.mcp
	var served []platformConfig
	for _, p := range cfg.platforms {
		switch {
		case m.scope != "":
			if p.scope == m.scope {
				served = append(served, p)
			}
		case p.scope != "" && !m.scopeFromCaller:
			return nil, fmt.Errorf("platform %s is fixed to a scope identifier, and mcp names neither scope nor scopeFrom, so the server would forward its calls naming none", p.name)
		default:
			served = append(served, p)
		}
	}
	if m.scope != "" && len(served) == 0 {
		return nil, errors.New("mcp.scope names a scope identifier no platform is fixed to, so the server would serve no platform's tool")
	}
	return served, nil
}

// scopedFrontReads holds a server that names scope or scopeFrom to reads by
// declaration (ADR-0044): each live tool of each platform it serves -- those
// fixed to its scope identifier, or in the caller form every platform, those
// of none included -- declares effect read-external, or the start is refused
// naming the platform and the tool. No decision policy holds a live tool's
// call, and a platform fixed to a scope identifier enables no write
// operation to carry one (ADR-0026, decision 4), so a propose or an act
// tool, and a tool with no declaration, is refused rather than served or
// left out. A configuration with no mcp member, or one of neither form, is
// not read here. Both starts apply it, serve's and gateway mcp's, and
// connect holds the configuration it would write to it.
func scopedFrontReads(cfg engineConfig, bindings map[string]binding) error {
	if cfg.mcp == nil || !cfg.mcp.scoped() {
		return nil
	}
	for _, p := range cfg.platforms {
		// a platform of another scope identifier is served by no server of
		// this configuration
		if cfg.mcp.scope != "" && p.scope != cfg.mcp.scope {
			continue
		}
		b, ok := bindings[p.name]
		if !ok || b.live == nil {
			continue
		}
		for _, tool := range b.live.tools {
			owner, declared := b.live.taxonomies[tool]
			if !declared || !owner.Valid() || owner.Effect != "read-external" {
				return fmt.Errorf("platform %s: tool %q is not declared effect read-external, and an MCP server that names scope or scopeFrom serves no other live tool, since no decision policy holds a live tool's call (ADR-0044); declare the tool read-external if it only reads, or serve it from a platform of no scope identifier behind an mcp that names neither", p.name, requestText(tool))
			}
		}
	}
	return nil
}

// forwardScope is the scope identifier an acquisition of the tool names, and
// whether it names one: the server's, where it is fixed to one; the tool's
// platform's, where it takes its callers', none for a platform of none; and
// none for a server of neither form. Nothing of the client's call is read.
func (s *mcpServer) forwardScope(tool mcpTool) (string, bool) {
	switch {
	case s.cfg.mcp.scope != "":
		return s.cfg.mcp.scope, true
	case s.cfg.mcp.scopeFromCaller:
		return tool.scope, tool.scope != ""
	}
	return "", false
}

// callerReach is what the caller of a token reaches (ADR-0037), computed as
// the signer computes it: every source with no identity configured, and
// otherwise the reach of the token engineToken verifies, or the refusal of a
// token out of form or wider than its subject's entry, which the signer
// answers 401 before any route.
func (s *mcpServer) callerReach(token string) (scopeReach, error) {
	if s.identity == nil {
		return reachOf(nil, nil)
	}
	if token == "" {
		return scopeReach{}, errNoBearerToken
	}
	who, err := engineToken(s.identity, s.witness, token, s.now())
	if err != nil {
		return scopeReach{}, err
	}
	return reachOf(s.identity, who)
}

// reachable is whether a caller under the token is served the tool: the seal
// tool always, whose /seal the signer holds to the caller's reach itself; a
// platform's tool always, where the server names no scope identifier and
// serves no platform fixed to one; and otherwise where the token's reach
// holds the tool's platform's scope identifier, or none -- in a server fixed
// to a scope identifier, the server's. A token whose reach cannot be read
// reaches no platform's tool.
func (s *mcpServer) reachable(tool mcpTool, reach func() scopeReach) bool {
	if tool.seal || !s.cfg.mcp.scoped() {
		return true
	}
	return reach().holds(tool.scope)
}

// callReach is the reach a message of the transport session is held to:
// over stdio, the reach of the token given at start, read there once; over
// HTTP, callerReach of the request's token, read on first use and once for
// the message. What a refusal leaves is a reach of nothing.
func (s *mcpServer) callReach(sess *mcpSession, token string) func() scopeReach {
	if sess != nil && sess.reach != nil {
		given := *sess.reach
		return func() scopeReach { return given }
	}
	var reach *scopeReach
	return func() scopeReach {
		if reach == nil {
			r, err := s.callerReach(token)
			if err != nil {
				r = scopeReach{}
			}
			reach = &r
		}
		return *reach
	}
}

// toolList is what tools/list answers a message of the transport session
// under its token: one page, no cursor, of the tools the caller is served,
// their entries rendered at start. A scoped server's caller's listing is
// assembled from the tools it reaches alone, within the listing's bound
// (heldListing.assemble), so it is the same whatever the platforms of a
// scope identifier it does not reach hold (ADR-0041).
func (s *mcpServer) toolList(sess *mcpSession, token string) []json.RawMessage {
	if !s.cfg.mcp.scoped() {
		return s.listing
	}
	reach := s.callReach(sess, token)
	names := []string{}
	for _, name := range s.order {
		if s.reachable(s.tools[name], reach) {
			names = append(names, name)
		}
	}
	return s.held.assemble(names)
}
