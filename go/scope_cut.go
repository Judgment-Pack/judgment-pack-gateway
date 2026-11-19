package main

// A verdict and an export cut by one scope identifier (SPEC.md §4, "A verdict
// by scope"; §5a; docs/adr/0042-a-seal-names-its-scope-over-a-salt-the-registry-does-not-hold.md,
// decisions 6 to 9): `gateway verify --scope S` and `gateway export --scope S`
// judge, and write, the sessions shown to be of S, and name every session
// that cannot be shown to be of S or of another, never leaving one out
// unsaid.
//
// A session is attributed by what is signed: its seal, and the scope and
// scope salt its receipts carry where they pass the signed orders (SPEC.md
// §1.4, orders 1 to 6), so that every member they carry is the gateway's.

import (
	"sort"
	"strconv"
)

// scopeHolding is what a session's receipt files say of its scope: the
// scope and scope salt of each that passes the signed orders, once each
// pair; whether one of them holds no scope; whether every file passes them,
// at the places 0 to count-1; and the signature of the last.
type scopeHolding struct {
	scopes  map[scopeNaming]bool
	noScope bool
	// signedAll is every receipt file passing the signed orders, their
	// indexes 0 to count-1: none is a file the gateway did not sign there.
	signedAll bool
	count     int64
	// last is the signature of the receipt at count-1, "" for none.
	last    string
	indexes map[int64]bool
}

func newScopeHolding() *scopeHolding {
	return &scopeHolding{scopes: map[scopeNaming]bool{}, signedAll: true, indexes: map[int64]bool{}}
}

// pastSignedOrders is whether a receipt's ladder status is past order 6
// (SPEC.md §1.4): its form, its version, its key, its signature, its place
// and its authority hold. The artifact step, and any after it, may still
// fail it; what it carries is signed all the same.
func pastSignedOrders(r *receipt, status string) bool {
	if r == nil {
		return false
	}
	switch status {
	case "malformed", "unsupported-version", "key-mismatch", "signature-mismatch", "misfiled", "authority-mismatch":
		return false
	}
	return true
}

// take reads one receipt file's ladder answer into the holding.
func (h *scopeHolding) take(r *receipt, status string) {
	h.count++
	if !pastSignedOrders(r, status) {
		h.signedAll = false
		return
	}
	h.indexes[r.callIndex] = true
	if scope, held := memberString(r.obj, "scope"); held {
		salt, _ := memberString(r.obj, "scopeSalt")
		h.scopes[scopeNaming{scope: scope, salt: salt}] = true
	} else {
		h.noScope = true
	}
}

// carriesOtherThan is whether a receipt past the signed orders carries a
// scope other than scope, or none.
func (h *scopeHolding) carriesOtherThan(scope string) bool {
	if h.noScope {
		return true
	}
	for held := range h.scopes {
		if held.scope != scope {
			return true
		}
	}
	return false
}

// done closes the holding: signedAll holds only where the indexes signed are
// exactly 0 to count-1, and last is the signature at count-1.
func (h *scopeHolding) done(signatures map[string]string) {
	for i := int64(0); i < h.count; i++ {
		if !h.indexes[i] {
			h.signedAll = false
			break
		}
	}
	if h.count > 0 {
		h.last = signatures[strconv.FormatInt(h.count-1, 10)]
	}
}

// The attribution of one session to the scope identifier a cut is of.
type attribution int

const (
	// ofAnother is a session shown to be of another scope identifier, or of
	// none: a cut leaves it out.
	ofAnother attribution = iota
	// ofTheScope is a session shown to be of the scope, or one holding a
	// receipt of it whatever its seal says: a cut keeps it.
	ofTheScope
	// unattributed is a session shown to be neither: a cut names it, keeps
	// its findings, and is incomplete.
	unattributed
)

// attribute is the attribution of the session sessionID to scope (SPEC.md
// §4, "A verdict by scope"): s its first seal that loaded, sealed whether one
// did; h its receipts' holding, nil for a sealed session the store does not
// hold; ret the removal records that loaded.
//
// Held in the store, a session is of the scope where a receipt passing the
// signed orders carries it, whatever its seal says. Otherwise:
//   - a seal of version 2 names one scope, by a digest of it in the
//     session: of the scope where that is the scope's digest, of another if
//     not;
//   - a seal of version 3 is of another scope where a receipt carries a
//     scope and salt whose digest is the seal's, and unattributed where none
//     does;
//   - a seal naming no scope (§3, §3c of version 1) is of another scope, or
//     of none, where every receipt it counts is held, passes the signed
//     orders and carries none of the scope, and of a seal after an
//     interruption the last is its head; unattributed otherwise;
//   - with no seal, the session is of another scope where a receipt passes
//     the signed orders and each that does carries another scope with a
//     scope salt, which only a release that holds a session to one scope
//     mints; unattributed otherwise.
//
// A sealed session the store does not hold is of the scope a
// session-removal record naming it states, of the scope a seal of version 2
// names, and otherwise unattributed.
func attribute(scope, sessionID string, s seal, sealed bool, h *scopeHolding, ret *retention) attribution {
	if h == nil {
		if rec, named := ret.removalOf(sessionID, s); named {
			if rec.scope == scope {
				return ofTheScope
			}
			return ofAnother
		}
		if s.scopeDigest != "" && !s.salted {
			if s.namesScope(sessionID, scope, "") {
				return ofTheScope
			}
			return ofAnother
		}
		return unattributed
	}
	for held := range h.scopes {
		if held.scope == scope {
			return ofTheScope
		}
	}
	switch {
	case sealed && s.scopeDigest != "" && !s.salted:
		if s.namesScope(sessionID, scope, "") {
			return ofTheScope
		}
		return ofAnother
	case sealed && s.scopeDigest != "":
		for held := range h.scopes {
			if s.namesScope(sessionID, held.scope, held.salt) {
				return ofAnother
			}
		}
		return unattributed
	case sealed:
		if h.signedAll && h.count == s.finalCount && (!s.interrupted || h.last == s.head) {
			return ofAnother
		}
		return unattributed
	}
	if len(h.scopes) == 0 || h.noScope {
		return unattributed
	}
	for held := range h.scopes {
		if held.salt == "" {
			return unattributed
		}
	}
	return ofAnother
}

// scopeCut is a cut by one scope identifier, as a verdict reports it: the
// scope, the sessions of it, and the sessions it could attribute to none,
// each sorted.
type scopeCut struct {
	Scope        string   `json:"scope"`
	Sessions     []string `json:"sessions"`
	Unattributed []string `json:"unattributed"`
	// kept are the sessions whose findings a verdict by scope reports: those
	// of the scope and those unattributed.
	kept map[string]bool
	// judged is, for an export by scope, the SHA-256 of each receipt file's
	// bytes as its attribution read them, by "<session>/<entry>".
	judged map[string][32]byte
}

// cutOf attributes every session the store holds (holdings, by id) and
// every sealed session it does not (seals) to scope.
func cutOf(scope string, holdings map[string]*scopeHolding, seals map[string]seal, ret *retention) *scopeCut {
	cut := &scopeCut{Scope: scope, Sessions: []string{}, Unattributed: []string{}, kept: map[string]bool{}}
	judge := func(sessionID string, a attribution) {
		switch a {
		case ofTheScope:
			cut.Sessions = append(cut.Sessions, sessionID)
		case unattributed:
			cut.Unattributed = append(cut.Unattributed, sessionID)
		default:
			return
		}
		cut.kept[sessionID] = true
	}
	for sessionID, h := range holdings {
		s, sealed := seals[sessionID]
		judge(sessionID, attribute(scope, sessionID, s, sealed, h, ret))
	}
	for sessionID, s := range seals {
		if _, held := holdings[sessionID]; !held {
			judge(sessionID, attribute(scope, sessionID, s, true, nil, ret))
		}
	}
	sort.Strings(cut.Sessions)
	sort.Strings(cut.Unattributed)
	return cut
}

// keeps is whether a verdict by scope reports a finding or an observation:
// one naming a session the cut keeps, and one naming none -- of the
// registry's walk, or of a decision record.
func (cut *scopeCut) keeps(f finding) bool {
	sessionID, named := f["sessionId"].(string)
	return !named || cut.kept[sessionID]
}

// filter keeps of findings what the cut reports.
func (cut *scopeCut) filter(findings []finding) []finding {
	kept := []finding{}
	for _, f := range findings {
		if cut.keeps(f) {
			kept = append(kept, f)
		}
	}
	return kept
}
