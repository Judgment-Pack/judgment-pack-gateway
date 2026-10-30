package connections

// The connection grant (gateway #357; spec RFC 0030 §5, a Draft). The
// standing provider authorization behind a connection is a resource a
// principal holds: custody keeps, beside the state and not in it (an earlier
// release refuses a state member it does not know), one record per
// connection of who owns it, which scopes its operations declare, which the
// provider granted and which dispatched calls used, when it was last used,
// its idle bound, and whether it is active, quarantined or revoked. The
// record carries no credential, no token, no token digest and no content.
//
// The providers whose connections have a record are those whose custody
// holds a provider grant the gateway reaches a platform with: Google Drive,
// Gmail, Notion, Databricks and Azure DevOps. A local folder, an object
// store's keys and an API key of a search or processing service have no
// record in this release.

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"
)

const (
	// grantDocument is the record of every connection grant the custody
	// holds or held.
	grantDocument = "connection-grants.json"
	// ownerReadsDocument is the operator's configuration of the owner
	// read: which issuing host answers at which address under which
	// credential, and what the removal of an owner does to a grant. It holds
	// a credential, and is never reported.
	ownerReadsDocument = "owner-reads.json"
	// grantRetiredKept is how many revoked records are kept, newest first,
	// beside the live ones.
	grantRetiredKept = 16
	// grantMaxIdleExpiry bounds a configured idle expiry: ten years.
	grantMaxIdleExpiry = int64(3660 * 24 * time.Hour / time.Millisecond)
	// grantIdleReport is how long unused a grant without an idle expiry is
	// before the report calls it idle (the RFC's open question 14).
	grantIdleReport = 90 * 24 * time.Hour
	// grantTimeLayout is the RFC's time form: UTC, exactly milliseconds.
	grantTimeLayout  = "2006-01-02T15:04:05.000Z"
	ownerReadTimeout = 5 * time.Second
	ownerReplyBytes  = 4096
	ownerReadHosts   = 16
)

// The refusals a grant adds. A refusal names no account, no path and no
// token.
const (
	ErrGrantQuarantined Error = "grant-quarantined"
	ErrGrantRevoked     Error = "grant-revoked"
	ErrGrantIdle        Error = "grant-idle-expired"
	ErrOwnerRemoved     Error = "owner-removed"
	ErrOwnerUnknown     Error = "owner-unknown"
	ErrOwnerRecorded    Error = "owner-recorded"
	ErrGrantUnknown     Error = "grant-unknown"
)

// excessScopePrefix begins the refusal of a grant that requests or holds a
// scope none of its connection's operations declares; the extra scopes
// follow it, separated by spaces.
const excessScopePrefix = "excess-scope"

func excessScope(extra []string) Error {
	return Error(excessScopePrefix + ": " + strings.Join(extra, " "))
}

// IsExcessScope reports whether err is an excess-scope refusal.
func IsExcessScope(err error) bool {
	if err == nil {
		return false
	}
	text := err.Error()
	return text == excessScopePrefix || strings.HasPrefix(text, excessScopePrefix+": ")
}

const (
	grantActive      = "active"
	grantQuarantined = "quarantined"
	grantRevoked     = "revoked"
)

// The reasons a grant was revoked.
const (
	revokedIdle         = "idle-expiry"
	revokedOwnerRemoved = "owner-removed"
	revokedOperator     = "operator"
	revokedDisconnected = "disconnected"
)

// providerGrantMayPersist is the report of a revocation the provider did
// not confirm: the credential is deleted, and the authorization may still
// exist at the provider.
const providerGrantMayPersist = "provider-grant-may-persist"

// grantProviders are the providers whose connections have a grant record.
var grantProviders = []string{"google-drive", "gmail", "notion", "databricks", "azure-devops"}

func grantProvider(kind string) bool { return slices.Contains(grantProviders, kind) }

// PrincipalRef is a person or a service as the issuing host verified it:
// its kind, issuer and subject. It carries no token and no display label.
type PrincipalRef struct {
	Kind    string `json:"kind"`
	Issuer  string `json:"issuer"`
	Subject string `json:"subject"`
}

func (p PrincipalRef) valid() bool {
	return (p.Kind == "person" || p.Kind == "service") && resourceText(p.Issuer, 512, false) && resourceText(p.Subject, 512, false)
}

// ScopeUse is a granted scope a dispatched call exercised, and when last.
type ScopeUse struct {
	Scope      string `json:"scope"`
	LastUsedAt string `json:"lastUsedAt"`
}

// GrantScopes are a grant's scopes. Granted is null where the provider's
// grant cannot be read (a pasted token whose scopes the provider does not
// report to it); used is then not derived, since no granted scope is known
// to have been exercised.
type GrantScopes struct {
	Required []string   `json:"required"`
	Granted  []string   `json:"granted"`
	Used     []ScopeUse `json:"used"`
}

// GrantRevocation is why and when a grant was revoked, and whether the
// provider confirmed it.
type GrantRevocation struct {
	Reason          string `json:"reason"`
	At              string `json:"at"`
	ProviderRevoked bool   `json:"providerRevoked"`
	Report          string `json:"report,omitempty"`
}

// grantRecord is a connection grant as custody keeps it. Generation is the
// custody's own identifier of the connection the record is of, so that a
// connection made again is a new grant; it is not reported.
type grantRecord struct {
	Connection string           `json:"connection"`
	Provider   string           `json:"provider"`
	Generation string           `json:"generation"`
	Owner      *PrincipalRef    `json:"owner"`
	OwnerHost  *string          `json:"ownerHost"`
	Scopes     GrantScopes      `json:"scopes"`
	Excess     []string         `json:"excess"`
	CreatedAt  string           `json:"createdAt"`
	LastUsedAt *string          `json:"lastUsedAt"`
	IdleExpiry *int64           `json:"idleExpiry"`
	State      string           `json:"state"`
	Revocation *GrantRevocation `json:"revocation"`
}

type grantLedger struct {
	Version int           `json:"version"`
	Grants  []grantRecord `json:"grants"`
}

// grantClock is the gateway's time for a grant; a test sets it.
var grantClock = time.Now

func grantTime(t time.Time) string { return t.UTC().Format(grantTimeLayout) }

func parseGrantTime(s string) (time.Time, bool) {
	t, err := time.Parse(grantTimeLayout, s)
	return t, err == nil && grantTime(t) == s
}

// grants is the ledger, under the custody lock; an absent one is empty.
func (s *Store) grants() (grantLedger, error) {
	l := grantLedger{Version: 1, Grants: []grantRecord{}}
	raw, err := s.read(grantDocument)
	if err != nil {
		if err == ErrStorage {
			return l, err
		}
		return l, nil
	}
	if decode(raw, &l) != nil || l.Version != 1 || l.Grants == nil {
		return grantLedger{}, ErrStorage
	}
	return l, nil
}

func (s *Store) saveGrants(l grantLedger) error {
	// The revoked records past the newest few are let go.
	retired := 0
	kept := make([]grantRecord, 0, len(l.Grants))
	for i := len(l.Grants) - 1; i >= 0; i-- {
		if l.Grants[i].State == grantRevoked {
			retired++
			if retired > grantRetiredKept {
				continue
			}
		}
		kept = append(kept, l.Grants[i])
	}
	slices.Reverse(kept)
	l.Grants = kept
	return s.write(grantDocument, l)
}

func (l *grantLedger) find(connection string) int {
	for i := len(l.Grants) - 1; i >= 0; i-- {
		if l.Grants[i].Connection == connection {
			return i
		}
	}
	return -1
}

// heldGrant is a connection custody holds now: its name, the custody's
// identifier of it, and the scopes the provider granted, known false where
// they cannot be read.
type heldGrant struct {
	connection, generation string
	granted                []string
	known                  bool
	// kept is a grant whose scopes the record holds as the provider last
	// reported them, at a consent or a renewal: custody's own value is
	// only where the record has none.
	kept bool
}

func scopeList(scope string) []string {
	out := []string{}
	for _, name := range strings.Fields(scope) {
		if !slices.Contains(out, name) {
			out = append(out, name)
		}
	}
	slices.Sort(out)
	return out
}

// heldGrants is every connection of the provider custody holds.
func heldGrants(kind string, s *Store, v *state) []heldGrant {
	switch kind {
	case "google-drive", "gmail", "notion":
		if v.Connection == nil {
			return nil
		}
		h := heldGrant{connection: kind, generation: v.Connection.ID, kept: true}
		// A Drive connection's scope is that of its recorded consent; one
		// without a record is asked for again, and its grant is not known.
		// Gmail and Notion are held to the scope asked for at every token
		// exchange (provider.exchange), which is what they were granted.
		switch kind {
		case "google-drive":
			if scope := s.consentedScope(*v.Connection); scope != "" {
				h.granted, h.known = scopeList(scope), true
			}
		case "gmail":
			h.granted, h.known = []string{gmailScope}, true
		case "notion":
			h.granted, h.known = []string{"default"}, true
		}
		return []heldGrant{h}
	case "databricks":
		if v.Databricks == nil {
			return nil
		}
		out := []heldGrant{}
		for _, c := range v.Databricks.Connections {
			h := heldGrant{connection: c.ID, generation: c.ID}
			// A service principal's token is minted for the scope the
			// connection asks; a personal access token's reach is not
			// reported to the gateway.
			if c.Auth == "service-principal" {
				h.granted, h.known = scopeList(c.scope()), true
			}
			out = append(out, h)
		}
		return out
	case "azure-devops":
		if v.AzureDevOps == nil {
			return nil
		}
		out := []heldGrant{}
		for _, c := range v.AzureDevOps.Connections {
			// A personal access token's scopes, and an Entra token's, are
			// not read by the gateway.
			out = append(out, heldGrant{connection: c.ID, generation: c.ID})
		}
		return out
	}
	return nil
}

// databricksServerOperation is the operation an MCP server's calls are: the
// server's kind, before its colon.
func databricksServerOperation(server string) string {
	kind, _, _ := strings.Cut(server, ":")
	return "mcp:" + kind
}

// grantDeclarations is, for each provider, the scopes each operation
// declares it needs: any one of those listed is enough for it. They are the
// gateway's declarations, not the provider's report of which scope a call
// exercised (few providers report one): a Drive connection is of the whole
// Drive (ADR-0010), Gmail is read-only, Notion's one scope is default;
// Databricks' are those of its pages for each managed MCP server
// (adapters/README.md) and, for a statement or a catalog listing, sql or
// unity-catalog where a narrower scope serves and all-apis otherwise; Azure
// DevOps' are the personal access token scopes of each area read.
var grantDeclarations = map[string]map[string][]string{
	"google-drive": {"read": {driveScope}, "observe": {driveScope}, "storage": {driveScope}},
	"gmail":        {"read": {gmailScope}},
	"notion":       {"read": {"default"}},
	"databricks": {
		"statement": {"sql", "all-apis"}, "catalog": {"unity-catalog", "all-apis"},
		"mcp:sql": {"sql", "all-apis"}, "mcp:genie": {"genie", "all-apis"}, "mcp:functions": {"unity-catalog", "all-apis"},
		"mcp:ai-search": {"ai-search", "all-apis"}, "mcp:unity-gateway": {"ai-gateway"},
	},
	"azure-devops": {
		"workitems.query": {"vso.work"}, "workitems.query-and-get": {"vso.work"}, "workitems.get": {"vso.work"},
		"repos.list": {"vso.code"}, "repos.items": {"vso.code"}, "repos.commits": {"vso.code"}, "pullrequests.list": {"vso.code"},
		"pipelines.list": {"vso.build"}, "pipelines.runs": {"vso.build"}, "pipelines.run": {"vso.build"},
	},
}

// grantOperations is every operation a connection offers.
func grantOperations(kind string, v *state, connection string) []string {
	switch kind {
	case "databricks":
		if v.Databricks != nil {
			for _, c := range v.Databricks.Connections {
				if c.ID == connection {
					return databricksOperations(c)
				}
			}
		}
		return []string{"statement", "catalog"}
	}
	ops := []string{}
	for op := range grantDeclarations[kind] {
		ops = append(ops, op)
	}
	return ops
}

// databricksOperations is what a Databricks connection offers: a statement,
// a catalog listing, and a call to each managed MCP server it enables.
func databricksOperations(c DatabricksConnection) []string {
	ops := []string{"statement", "catalog"}
	for _, server := range c.MCP {
		ops = append(ops, databricksServerOperation(server.Server))
	}
	return ops
}

// requiredOf is the union of the scopes the operations declare, in order,
// without repeats.
func requiredOf(kind string, ops []string) []string {
	out := []string{}
	for _, op := range ops {
		for _, scope := range grantDeclarations[kind][op] {
			if !slices.Contains(out, scope) {
				out = append(out, scope)
			}
		}
	}
	slices.Sort(out)
	return out
}

// grantRequired is the union of the scopes a connection's operations
// declare, in order, without repeats.
func grantRequired(kind string, v *state, connection string) []string {
	return requiredOf(kind, grantOperations(kind, v, connection))
}

// excessOf is the granted scopes no operation declares.
func excessOf(granted, required []string) []string {
	out := []string{}
	for _, scope := range granted {
		if !slices.Contains(required, scope) {
			out = append(out, scope)
		}
	}
	return out
}

// reconcileGrants holds the ledger to what custody holds now: a connection
// without a live record has a new one, of no owner; a record whose
// connection is gone is revoked, as disconnected; and a live record's
// required and granted scopes are those of now, a granted scope that no
// operation declares recorded as excess. It reports whether it changed the
// ledger.
func reconcileGrants(kind string, s *Store, v *state, l *grantLedger, now time.Time) bool {
	changed := false
	held := heldGrants(kind, s, v)
	for _, h := range held {
		i := l.find(h.connection)
		if i >= 0 && (l.Grants[i].State == grantRevoked || l.Grants[i].Generation != h.generation) {
			if l.Grants[i].State != grantRevoked {
				retire(&l.Grants[i], revokedDisconnected, now)
			}
			i = -1
		}
		if i < 0 {
			l.Grants = append(l.Grants, grantRecord{
				Connection: h.connection, Provider: kind, Generation: h.generation,
				Scopes: GrantScopes{Required: []string{}, Used: []ScopeUse{}}, Excess: []string{},
				CreatedAt: grantTime(now), State: grantActive,
			})
			i = len(l.Grants) - 1
			changed = true
		}
		r := &l.Grants[i]
		required := grantRequired(kind, v, h.connection)
		var granted []string
		if h.known {
			granted = h.granted
		}
		if h.kept && r.Scopes.Granted != nil {
			granted = r.Scopes.Granted
		}
		excess := []string{}
		if granted != nil {
			excess = excessOf(granted, required)
		}
		if !slices.Equal(r.Scopes.Required, required) || !slices.Equal(r.Scopes.Granted, granted) || (r.Scopes.Granted == nil) != (granted == nil) || !slices.Equal(r.Excess, excess) {
			r.Scopes.Required, r.Scopes.Granted, r.Excess = required, granted, excess
			if granted == nil {
				r.Scopes.Used = []ScopeUse{}
			} else {
				r.Scopes.Used = slices.DeleteFunc(r.Scopes.Used, func(u ScopeUse) bool { return !slices.Contains(granted, u.Scope) })
			}
			changed = true
		}
	}
	for i := range l.Grants {
		r := &l.Grants[i]
		if r.State == grantRevoked {
			continue
		}
		if !slices.ContainsFunc(held, func(h heldGrant) bool { return h.connection == r.Connection && h.generation == r.Generation }) {
			retire(r, revokedDisconnected, now)
			changed = true
		}
	}
	return changed
}

// retire marks a record revoked, the provider's confirmation not yet had.
func retire(r *grantRecord, reason string, now time.Time) {
	r.State = grantRevoked
	r.Revocation = &GrantRevocation{Reason: reason, At: grantTime(now), Report: providerGrantMayPersist}
}

// grantGate is the check the credential's every use passes under the
// custody lock: a quarantined grant admits no call, and a revoked one none.
// A connection made again since its grant was revoked is a new grant.
func (s *Store) grantGate(kind, connection, generation string) error {
	if !grantProvider(kind) {
		return nil
	}
	l, err := s.grants()
	if err != nil {
		return err
	}
	i := l.find(connection)
	if i < 0 || l.Grants[i].Generation != generation {
		return nil
	}
	if l.Grants[i].State == grantQuarantined {
		return ErrGrantQuarantined
	}
	return nil
}

// idleExpired is whether a grant has been unused for its idle bound: from
// its last use, or from its creation where it was never used. Equal is
// expired.
func idleExpired(r grantRecord, now time.Time) bool {
	if r.IdleExpiry == nil {
		return false
	}
	since := r.CreatedAt
	if r.LastUsedAt != nil {
		since = *r.LastUsedAt
	}
	t, ok := parseGrantTime(since)
	if !ok {
		// A time the record cannot be read for is taken as expired.
		return true
	}
	return !now.Before(t.Add(time.Duration(*r.IdleExpiry) * time.Millisecond))
}

// pendingRevoke is a revocation the provider is to be asked for once the
// custody lock is let go.
type pendingRevoke struct {
	p                      provider
	connection, generation string
	token                  string
}

// providerRevokes reports whether the provider offers a revocation endpoint
// the gateway calls: Google's token revocation (RFC 7009) for Drive and
// Gmail. Notion's, Databricks' and Azure DevOps' grants are revoked at the
// provider by their owner.
func (p provider) providerRevokes() bool {
	k := p.kind()
	return p.revoke != "" && (k == "google-drive" || k == "gmail")
}

// dropCredential deletes the connection's credential from custody, under
// its lock, and is the token the provider is asked to revoke, if any. A
// pending file change's journal is not touched: it is reconciled, or stays
// unknown, as before.
func (s *Store) dropCredential(kind string, v *state, connection string) (string, error) {
	token := ""
	switch kind {
	case "google-drive", "gmail", "notion":
		if v.Connection == nil {
			return "", nil
		}
		token = v.Connection.Refresh
		if token == "" {
			token = v.Connection.Access
		}
		v.Connection = nil
		v.Epoch = randomID()
		if err := s.write("state.json", v); err != nil {
			return "", err
		}
		_ = s.remove("consent.json")
	case "databricks":
		if v.Databricks == nil {
			return "", nil
		}
		v.Databricks.Connections = slices.DeleteFunc(v.Databricks.Connections, func(c DatabricksConnection) bool { return c.ID == connection })
		v.Databricks.Tokens = databricksWithout(v.Databricks.Tokens, connection)
		if err := s.write("state.json", v); err != nil {
			return "", err
		}
	case "azure-devops":
		if v.AzureDevOps == nil {
			return "", nil
		}
		v.AzureDevOps.Connections = slices.DeleteFunc(v.AzureDevOps.Connections, func(c AzureDevOpsConnection) bool { return c.ID == connection })
		if err := s.write("state.json", v); err != nil {
			return "", err
		}
	}
	return token, nil
}

// revokeLocked revokes the grant at l.Grants[i] under the custody lock: the
// credential is deleted, the record set revoked with the provider's
// confirmation not yet had. The ledger is the caller's to save.
func (s *Store) revokeLocked(p provider, v *state, l *grantLedger, i int, reason string, now time.Time) (*pendingRevoke, error) {
	r := &l.Grants[i]
	token, err := s.dropCredential(r.Provider, v, r.Connection)
	if err != nil {
		return nil, err
	}
	retire(r, reason, now)
	if token == "" || !p.providerRevokes() {
		return nil, nil
	}
	return &pendingRevoke{p: p, connection: r.Connection, generation: r.Generation, token: token}, nil
}

// finish asks the provider to revoke, and records its confirmation. Without
// one the record keeps provider-grant-may-persist.
func (r *pendingRevoke) finish(ctx context.Context, s *Store) bool {
	if r == nil {
		return false
	}
	if _, _, err := r.p.request(ctx, "POST", r.p.revoke, "", url.Values{"token": {r.token}}, 64<<10); err != nil {
		return false
	}
	return s.locked(func(v *state) error {
		l, err := s.grants()
		if err != nil {
			return err
		}
		for i := range l.Grants {
			g := &l.Grants[i]
			if g.Connection == r.connection && g.Generation == r.generation && g.State == grantRevoked && g.Revocation != nil {
				g.Revocation.ProviderRevoked, g.Revocation.Report = true, ""
				return s.saveGrants(l)
			}
		}
		return nil
	}) == nil
}

// grantUse is the gate an acquisition or an action passes before it is
// dispatched through the connection, and the record of its use. Under the
// lock, a quarantined or revoked grant refuses, a grant idle for its bound
// is revoked and refuses, and a grant holding a scope no operation declares
// refuses (every provider with a record can narrow its grant). Then, for a
// grant with an owner, the owner read is made to its issuing host, outside
// the lock: an owner removed applies the operator's removal and refuses; an
// owner whose standing is not answered refuses. Last, under the lock again,
// the use is recorded: the grant's last use, and each granted scope the
// operation declares. A grant whose record has no owner, as every grant
// made before this record, is used as before.
func (s *Store) grantUse(ctx context.Context, p provider, connection, operation string) error {
	kind := p.kind()
	if !grantProvider(kind) {
		return nil
	}
	var owner PrincipalRef
	var host, generation string
	var pending *pendingRevoke
	err := s.locked(func(v *state) error {
		l, err := s.grants()
		if err != nil {
			return err
		}
		changed := reconcileGrants(kind, s, v, &l, grantClock())
		i := l.find(connection)
		if i < 0 || l.Grants[i].State == grantRevoked {
			if changed {
				_ = s.saveGrants(l)
			}
			return ErrConnect
		}
		r := l.Grants[i]
		switch {
		case r.State == grantQuarantined:
			err = ErrGrantQuarantined
		case idleExpired(r, grantClock()):
			if pending, err = s.revokeLocked(p, v, &l, i, revokedIdle, grantClock()); err != nil {
				return err
			}
			changed, err = true, ErrGrantIdle
		case len(r.Excess) > 0:
			err = excessScope(r.Excess)
		}
		if changed {
			if e := s.saveGrants(l); e != nil {
				return e
			}
		}
		if err != nil {
			return err
		}
		generation = r.Generation
		if r.Owner != nil && r.OwnerHost != nil {
			owner, host = *r.Owner, *r.OwnerHost
		}
		return nil
	})
	if pending != nil {
		pending.finish(ctx, s)
	}
	if err != nil {
		return err
	}
	if host != "" {
		switch s.ownerStanding(ctx, host, owner) {
		case ownerCurrent:
		case ownerRemoved:
			_, _ = s.applyOwnerRemoval(ctx, p, owner, host, "")
			return ErrOwnerRemoved
		default:
			return ErrOwnerUnknown
		}
	}
	return s.locked(func(v *state) error {
		l, err := s.grants()
		if err != nil {
			return err
		}
		now := grantClock()
		reconcileGrants(kind, s, v, &l, now)
		i := l.find(connection)
		if i < 0 || l.Grants[i].Generation != generation {
			return ErrConnect
		}
		r := &l.Grants[i]
		switch r.State {
		case grantQuarantined:
			return ErrGrantQuarantined
		case grantRevoked:
			return ErrGrantRevoked
		}
		// The owner read was of the owner the record named then.
		if (r.Owner == nil) != (host == "") || r.Owner != nil && (*r.Owner != owner || *r.OwnerHost != host) {
			return ErrOwnerUnknown
		}
		at := grantTime(now)
		r.LastUsedAt = &at
		if r.Scopes.Granted != nil {
			for _, scope := range grantDeclarations[kind][operation] {
				if !slices.Contains(r.Scopes.Granted, scope) {
					continue
				}
				if j := slices.IndexFunc(r.Scopes.Used, func(u ScopeUse) bool { return u.Scope == scope }); j >= 0 {
					r.Scopes.Used[j].LastUsedAt = at
				} else {
					r.Scopes.Used = append(r.Scopes.Used, ScopeUse{scope, at})
				}
			}
			slices.SortFunc(r.Scopes.Used, func(a, b ScopeUse) int { return strings.Compare(a.Scope, b.Scope) })
		}
		return s.saveGrants(l)
	})
}

// noteGranted records the scopes the provider reported it granted, at a
// consent or at a renewal, and the excess among them: a scope added since
// (drift) is recorded at the renewal that reports it, and refused there.
func (s *Store) noteGranted(kind, generation string, granted []string) {
	_ = s.locked(func(v *state) error {
		l, err := s.grants()
		if err != nil {
			return err
		}
		reconcileGrants(kind, s, v, &l, grantClock())
		for i := range l.Grants {
			r := &l.Grants[i]
			if r.Generation == generation && r.State != grantRevoked {
				r.Scopes.Granted = granted
				r.Excess = excessOf(granted, r.Scopes.Required)
				r.Scopes.Used = slices.DeleteFunc(r.Scopes.Used, func(u ScopeUse) bool { return !slices.Contains(granted, u.Scope) })
			}
		}
		return s.saveGrants(l)
	})
}

// noteRevoked records, of a connection the owner disconnected, whether the
// provider confirmed its revocation.
func (s *Store) noteRevoked(kind, generation string, confirmed bool) {
	_ = s.locked(func(v *state) error {
		l, err := s.grants()
		if err != nil {
			return err
		}
		reconcileGrants(kind, s, v, &l, grantClock())
		for i := range l.Grants {
			r := &l.Grants[i]
			if r.Generation == generation && r.State == grantRevoked && r.Revocation != nil && confirmed {
				r.Revocation.ProviderRevoked, r.Revocation.Report = true, ""
			}
		}
		return s.saveGrants(l)
	})
}

// The owner's standing as its issuing host answers it.
const (
	ownerCurrent = "current"
	ownerRemoved = "removed"
	ownerUnknown = "unknown"
)

// ownerReadHost is an issuing host the owner read is made to: its name as
// the grant records it, the HTTPS address that answers, and the credential
// the gateway authenticates with.
type ownerReadHost struct {
	Host       string `json:"host"`
	URL        string `json:"url"`
	Credential string `json:"credential"`
}

// ownerReads is the operator's owner-read configuration: the hosts, and
// what an owner's removal does to the grants it owns, revoke (the default,
// the RFC's open question 13) or quarantine.
type ownerReads struct {
	Version int             `json:"version"`
	Removal string          `json:"removal"`
	Hosts   []ownerReadHost `json:"hosts"`
}

func (c ownerReads) valid() bool {
	if c.Version != 1 || c.Removal != revokedRemoval && c.Removal != quarantineRemoval || c.Hosts == nil || len(c.Hosts) > ownerReadHosts {
		return false
	}
	seen := map[string]bool{}
	for _, h := range c.Hosts {
		u, err := url.Parse(h.URL)
		if !flatToken(h.Host) || seen[h.Host] || err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.Fragment != "" || u.RawQuery != "" || len(h.URL) > 2048 || !resourceText(h.Credential, 4096, false) || len(h.Credential) < 8 || strings.ContainsAny(h.Credential, " \t") {
			return false
		}
		seen[h.Host] = true
	}
	return true
}

const (
	revokedRemoval    = "revoke"
	quarantineRemoval = "quarantine"
)

// flatToken is the RFC's flat token: [A-Za-z0-9._-]{1,128}, never . or ..
func flatToken(s string) bool {
	if s == "" || len(s) > 128 || s == "." || s == ".." {
		return false
	}
	for _, r := range s {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '.' || r == '_' || r == '-') {
			return false
		}
	}
	return true
}

func (s *Store) ownerReads() (ownerReads, error) {
	c := ownerReads{Version: 1, Removal: revokedRemoval, Hosts: []ownerReadHost{}}
	raw, err := s.read(ownerReadsDocument)
	if err != nil {
		if err == ErrStorage {
			return c, err
		}
		return c, nil
	}
	if decode(raw, &c) != nil || !c.valid() {
		return ownerReads{}, ErrStorage
	}
	return c, nil
}

// ownerReadClient is the client the owner read is made with; a test sets it.
var ownerReadClient = func() *http.Client {
	t := http.DefaultTransport.(*http.Transport).Clone()
	t.Proxy = nil
	t.MaxResponseHeaderBytes = 16 << 10
	t.ResponseHeaderTimeout = ownerReadTimeout
	t.TLSHandshakeTimeout = ownerReadTimeout
	t.DialContext = (&net.Dialer{Timeout: ownerReadTimeout}).DialContext
	return &http.Client{Transport: t, Timeout: ownerReadTimeout, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

// ownerStanding is the owner read: an authenticated, synchronous request to
// the owner's issuing host asking whether the owner is a current principal.
// A host the operator has not configured, a refused or late request, and an
// answer that is not exactly one of the two standings are unknown.
func (s *Store) ownerStanding(ctx context.Context, host string, owner PrincipalRef) string {
	var cfg ownerReads
	if s.locked(func(*state) error { var err error; cfg, err = s.ownerReads(); return err }) != nil {
		return ownerUnknown
	}
	i := slices.IndexFunc(cfg.Hosts, func(h ownerReadHost) bool { return h.Host == host })
	if i < 0 {
		return ownerUnknown
	}
	body, err := json.Marshal(struct {
		Host  string       `json:"host"`
		Owner PrincipalRef `json:"owner"`
	}{host, owner})
	if err != nil {
		return ownerUnknown
	}
	ctx, cancel := context.WithTimeout(ctx, ownerReadTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, "POST", cfg.Hosts[i].URL, bytes.NewReader(body))
	if err != nil {
		return ownerUnknown
	}
	req.Header.Set("Authorization", "Bearer "+cfg.Hosts[i].Credential)
	req.Header.Set("Content-Type", "application/json")
	resp, err := ownerReadClient().Do(req)
	if err != nil {
		return ownerUnknown
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, ownerReplyBytes+1))
	if err != nil || resp.StatusCode != 200 || len(raw) > ownerReplyBytes {
		return ownerUnknown
	}
	var reply struct {
		Standing string `json:"standing"`
	}
	if decode(raw, &reply) != nil {
		return ownerUnknown
	}
	switch reply.Standing {
	case ownerCurrent, ownerRemoved:
		return reply.Standing
	}
	return ownerUnknown
}

// applyOwnerRemoval revokes or quarantines every grant of this custody the
// owner owns at the host, as removal says, or as the operator configured
// where it says nothing. A quarantined grant keeps its credential and admits
// no call; a revoked one is deleted and, where the provider offers it,
// revoked there. It is the records it changed.
func (s *Store) applyOwnerRemoval(ctx context.Context, p provider, owner PrincipalRef, host, removal string) ([]grantRecord, error) {
	kind := p.kind()
	var changed []grantRecord
	var pending []*pendingRevoke
	err := s.locked(func(v *state) error {
		if removal == "" {
			cfg, err := s.ownerReads()
			if err != nil {
				// The operator's choice cannot be read: revoke, the default.
				cfg.Removal = revokedRemoval
			}
			removal = cfg.Removal
		}
		l, err := s.grants()
		if err != nil {
			return err
		}
		now := grantClock()
		reconcileGrants(kind, s, v, &l, now)
		for i := range l.Grants {
			r := &l.Grants[i]
			if r.State == grantRevoked || r.Owner == nil || *r.Owner != owner || r.OwnerHost == nil || *r.OwnerHost != host {
				continue
			}
			if removal == quarantineRemoval {
				if r.State == grantActive {
					r.State = grantQuarantined
					changed = append(changed, *r)
				}
				continue
			}
			one, err := s.revokeLocked(p, v, &l, i, revokedOwnerRemoved, now)
			if err != nil {
				return err
			}
			if one != nil {
				pending = append(pending, one)
			}
			changed = append(changed, *r)
		}
		return s.saveGrants(l)
	})
	for i, r := range pending {
		if r.finish(ctx, s) {
			for j := range changed {
				if changed[j].Generation == pending[i].generation && changed[j].Revocation != nil {
					changed[j].Revocation.ProviderRevoked, changed[j].Revocation.Report = true, ""
				}
			}
		}
	}
	return changed, err
}
