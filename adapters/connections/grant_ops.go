package connections

// The operator's side of connection grants: the connections report, and
// the operations that set an owner, an idle expiry and the owner read,
// remove an owner, revoke a grant and sweep the grants for idle expiry and
// owner standing (gateway-connections --grants OPERATION).

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"time"
)

// GrantOperations are the operations GrantOperation takes.
var GrantOperations = []string{"report", "set-owner", "set-idle-expiry", "owner-reads", "remove-owner", "revoke", "sweep"}

// GrantFinding is one thing the report says of a grant: a code, and a
// sentence that names no path, no account and no token.
type GrantFinding struct {
	Code   string `json:"code"`
	Reason string `json:"reason"`
}

// GrantReportScopes is a grant's scopes as the report gives them. Unused is
// granted minus used, the scopes to trim; null where granted is not known.
type GrantReportScopes struct {
	Required []string   `json:"required"`
	Granted  []string   `json:"granted"`
	Used     []ScopeUse `json:"used"`
	Unused   []string   `json:"unused"`
}

// GrantReport is one connection grant in the connections report. It carries
// no credential, no token, no account of the provider, no path and no
// content.
type GrantReport struct {
	Provider   string            `json:"provider"`
	Connection string            `json:"connection"`
	Owner      *PrincipalRef     `json:"owner"`
	OwnerHost  *string           `json:"ownerHost"`
	Scopes     GrantReportScopes `json:"scopes"`
	Excess     []string          `json:"excess"`
	CreatedAt  string            `json:"createdAt"`
	LastUsedAt *string           `json:"lastUsedAt"`
	IdleExpiry *int64            `json:"idleExpiry"`
	Idle       string            `json:"idle"`
	State      string            `json:"state"`
	Revocation *GrantRevocation  `json:"revocation"`
	Findings   []GrantFinding    `json:"findings"`
}

// The idle states: none (no idle expiry, and used within 90 days), within
// (an idle expiry not reached), idle (no idle expiry, and unused for 90
// days or more) and expired (its idle expiry reached; it is revoked at its
// next use or the next sweep).
const (
	idleStateNone    = "none"
	idleStateWithin  = "within"
	idleStateIdle    = "idle"
	idleStateExpired = "expired"
)

var grantReasons = map[string]string{
	"owner-missing":         "the grant has no owner record: it was made before grants recorded an owner, or none was set, and it is used as before, outside the owner-removal rule, until an owner is set",
	"excess-scope":          "the provider granted scopes that no operation of the connection declares; calls through it are refused until it is narrowed",
	"scopes-unreadable":     "the provider does not report the grant's scopes to the gateway, so neither excess nor unused scopes can be determined",
	"unused-scopes":         "some granted scopes have not been exercised by any dispatched call and can be trimmed",
	"idle":                  "the grant has no idle expiry and has not been used for 90 days or more",
	"idle-expired":          "the grant's idle expiry has passed; it is revoked at its next use or the next sweep",
	"quarantined":           "the grant's owner was removed and the operator chose quarantine: it keeps its credential and admits no call",
	providerGrantMayPersist: "the credential was deleted, but the provider did not confirm a revocation, so the authorization may still exist at the provider",
}

func finding(code string) GrantFinding { return GrantFinding{code, grantReasons[code]} }

func reportOf(r grantRecord, now time.Time) GrantReport {
	out := GrantReport{
		Provider: r.Provider, Connection: r.Connection, Owner: r.Owner, OwnerHost: r.OwnerHost,
		Scopes: GrantReportScopes{Required: r.Scopes.Required, Granted: r.Scopes.Granted, Used: r.Scopes.Used},
		Excess: r.Excess, CreatedAt: r.CreatedAt, LastUsedAt: r.LastUsedAt, IdleExpiry: r.IdleExpiry,
		State: r.State, Revocation: r.Revocation, Findings: []GrantFinding{},
	}
	if r.Scopes.Granted != nil {
		out.Scopes.Unused = []string{}
		for _, scope := range r.Scopes.Granted {
			if !slices.ContainsFunc(r.Scopes.Used, func(u ScopeUse) bool { return u.Scope == scope }) {
				out.Scopes.Unused = append(out.Scopes.Unused, scope)
			}
		}
	}
	since := r.CreatedAt
	if r.LastUsedAt != nil {
		since = *r.LastUsedAt
	}
	t, ok := parseGrantTime(since)
	switch {
	case r.IdleExpiry != nil && idleExpired(r, now):
		out.Idle = idleStateExpired
	case r.IdleExpiry != nil:
		out.Idle = idleStateWithin
	case !ok || !now.Before(t.Add(grantIdleReport)):
		out.Idle = idleStateIdle
	default:
		out.Idle = idleStateNone
	}
	if r.State == grantRevoked {
		if r.Revocation != nil && r.Revocation.Report == providerGrantMayPersist {
			out.Findings = append(out.Findings, finding(providerGrantMayPersist))
		}
		return out
	}
	if r.Owner == nil {
		out.Findings = append(out.Findings, finding("owner-missing"))
	}
	if r.State == grantQuarantined {
		out.Findings = append(out.Findings, finding("quarantined"))
	}
	if len(r.Excess) > 0 {
		out.Findings = append(out.Findings, finding("excess-scope"))
	}
	if r.Scopes.Granted == nil {
		out.Findings = append(out.Findings, finding("scopes-unreadable"))
	} else if len(out.Scopes.Unused) > 0 {
		out.Findings = append(out.Findings, finding("unused-scopes"))
	}
	switch out.Idle {
	case idleStateExpired:
		out.Findings = append(out.Findings, finding("idle-expired"))
	case idleStateIdle:
		out.Findings = append(out.Findings, finding("idle"))
	}
	return out
}

// grantProviderFor is the provider a grant of this kind is revoked through;
// a test sets it.
var grantProviderFor = func(kind string) provider {
	switch kind {
	case "gmail":
		return googleMail()
	case "notion":
		return notion()
	case "databricks":
		return databricksProvider()
	case "azure-devops":
		return azureDevOpsProvider()
	}
	return google()
}

// grantNamespace is the directory under the custody root a provider's
// custody is kept in.
func grantNamespace(kind string) string {
	if kind == "google-drive" {
		return ""
	}
	return kind
}

// openGrantStore opens a provider's custody for the principal. Where create
// is false a custody that does not exist is not made, and is nil.
func openGrantStore(kind, dir, principal string, create bool) (*Store, error) {
	if !filepath.IsAbs(dir) || !identifier.MatchString(principal) {
		return nil, ErrRequest
	}
	if !create {
		sum := sha256.Sum256([]byte(principal))
		if _, err := os.Lstat(filepath.Join(dir, grantNamespace(kind), hex.EncodeToString(sum[:]))); errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
	}
	switch kind {
	case "gmail":
		return OpenGmailStore(dir, principal)
	case "notion":
		return OpenNotionStore(dir, principal)
	case "databricks":
		return OpenDatabricksStore(dir, principal)
	case "azure-devops":
		return OpenAzureDevOpsStore(dir, principal)
	}
	return OpenStore(dir, principal)
}

// GrantOperation runs one operator operation on the principal's custody
// under dir, over the providers named (one, or every provider with grants
// where provider is empty), with the request raw, and is its answer.
func GrantOperation(ctx context.Context, dir, principal, provider, operation string, raw []byte) (any, error) {
	kinds := grantProviders
	if provider != "" {
		if !grantProvider(provider) {
			return nil, ErrRequest
		}
		kinds = []string{provider}
	}
	if len(raw) == 0 {
		raw = []byte("{}")
	}
	switch operation {
	case "report":
		var q struct{}
		if decode(raw, &q) != nil {
			return nil, ErrRequest
		}
		out := []GrantReport{}
		for _, kind := range kinds {
			s, err := openGrantStore(kind, dir, principal, false)
			if err != nil {
				return nil, err
			}
			if s == nil {
				continue
			}
			err = s.locked(func(v *state) error {
				l, err := s.grants()
				if err != nil {
					return err
				}
				now := grantClock()
				// The report reads; it reconciles what it reads, and writes nothing.
				reconcileGrants(kind, s, v, &l, now)
				for _, r := range l.Grants {
					out = append(out, reportOf(r, now))
				}
				return nil
			})
			s.Close()
			if err != nil {
				return nil, err
			}
		}
		return map[string]any{"version": 1, "connections": out}, nil
	case "set-owner", "set-idle-expiry", "revoke":
		var q struct {
			Provider   string        `json:"provider"`
			Connection string        `json:"connection"`
			Owner      *PrincipalRef `json:"owner,omitempty"`
			OwnerHost  *string       `json:"ownerHost,omitempty"`
			IdleExpiry *int64        `json:"idleExpiry"`
		}
		if decode(raw, &q) != nil || !grantProvider(q.Provider) || !flatToken(q.Connection) || provider != "" && q.Provider != provider {
			return nil, ErrRequest
		}
		switch operation {
		case "set-owner":
			if q.Owner == nil || !q.Owner.valid() || q.OwnerHost == nil || !flatToken(*q.OwnerHost) || q.IdleExpiry != nil {
				return nil, ErrRequest
			}
		case "set-idle-expiry":
			if q.Owner != nil || q.OwnerHost != nil || q.IdleExpiry != nil && (*q.IdleExpiry <= 0 || *q.IdleExpiry > grantMaxIdleExpiry) {
				return nil, ErrRequest
			}
		case "revoke":
			if q.Owner != nil || q.OwnerHost != nil || q.IdleExpiry != nil {
				return nil, ErrRequest
			}
		}
		s, err := openGrantStore(q.Provider, dir, principal, false)
		if err != nil {
			return nil, err
		}
		if s == nil {
			return nil, ErrGrantUnknown
		}
		defer s.Close()
		var out GrantReport
		var pending *pendingRevoke
		err = s.locked(func(v *state) error {
			l, err := s.grants()
			if err != nil {
				return err
			}
			now := grantClock()
			reconcileGrants(q.Provider, s, v, &l, now)
			i := l.find(q.Connection)
			if i < 0 {
				return ErrGrantUnknown
			}
			r := &l.Grants[i]
			if r.State == grantRevoked {
				return ErrGrantRevoked
			}
			switch operation {
			case "set-owner":
				// An owner is recorded once. A grant's owner changes only by
				// reassignment, which this release does not make.
				if r.Owner != nil {
					return ErrOwnerRecorded
				}
				if r.State != grantActive {
					return ErrGrantQuarantined
				}
				owner, host := *q.Owner, *q.OwnerHost
				r.Owner, r.OwnerHost = &owner, &host
			case "set-idle-expiry":
				r.IdleExpiry = q.IdleExpiry
			case "revoke":
				if pending, err = s.revokeLocked(grantProviderFor(q.Provider), v, &l, i, revokedOperator, now); err != nil {
					return err
				}
			}
			out = reportOf(*r, now)
			return s.saveGrants(l)
		})
		if err != nil {
			return nil, err
		}
		if pending.finish(ctx, s) && out.Revocation != nil {
			out.Revocation.ProviderRevoked, out.Revocation.Report = true, ""
			out.Findings = slices.DeleteFunc(out.Findings, func(f GrantFinding) bool { return f.Code == providerGrantMayPersist })
		}
		return map[string]any{"version": 1, "connections": []GrantReport{out}}, nil
	case "owner-reads":
		var q ownerReads
		if decode(raw, &q) != nil || !q.valid() {
			return nil, ErrRequest
		}
		for _, kind := range kinds {
			s, err := openGrantStore(kind, dir, principal, true)
			if err != nil {
				return nil, err
			}
			err = s.locked(func(*state) error { return s.write(ownerReadsDocument, q) })
			s.Close()
			if err != nil {
				return nil, err
			}
		}
		// The answer repeats no address and no credential.
		hosts := []string{}
		for _, h := range q.Hosts {
			hosts = append(hosts, h.Host)
		}
		return map[string]any{"version": 1, "removal": q.Removal, "hosts": hosts}, nil
	case "remove-owner":
		var q struct {
			Owner     PrincipalRef `json:"owner"`
			OwnerHost string       `json:"ownerHost"`
			Removal   string       `json:"removal,omitempty"`
		}
		if decode(raw, &q) != nil || !q.Owner.valid() || !flatToken(q.OwnerHost) || q.Removal != "" && q.Removal != revokedRemoval && q.Removal != quarantineRemoval {
			return nil, ErrRequest
		}
		out := []GrantReport{}
		for _, kind := range kinds {
			s, err := openGrantStore(kind, dir, principal, false)
			if err != nil {
				return nil, err
			}
			if s == nil {
				continue
			}
			changed, err := s.applyOwnerRemoval(ctx, grantProviderFor(kind), q.Owner, q.OwnerHost, q.Removal)
			s.Close()
			now := grantClock()
			for _, r := range changed {
				out = append(out, reportOf(r, now))
			}
			if err != nil {
				return map[string]any{"version": 1, "connections": out}, err
			}
		}
		return map[string]any{"version": 1, "connections": out}, nil
	case "sweep":
		var q struct{}
		if decode(raw, &q) != nil {
			return nil, ErrRequest
		}
		type result struct {
			Provider   string `json:"provider"`
			Connection string `json:"connection"`
			Outcome    string `json:"outcome"`
		}
		out := []result{}
		for _, kind := range kinds {
			s, err := openGrantStore(kind, dir, principal, false)
			if err != nil {
				return nil, err
			}
			if s == nil {
				continue
			}
			results, err := s.sweep(ctx, grantProviderFor(kind))
			s.Close()
			for _, r := range results {
				out = append(out, result{kind, r[0], r[1]})
			}
			if err != nil {
				return map[string]any{"version": 1, "results": out}, err
			}
		}
		return map[string]any{"version": 1, "results": out}, nil
	}
	return nil, ErrRequest
}

// sweep is the operator's periodic pass over one custody's grants: a grant
// idle for its bound is revoked, and the owner read is made for every live
// grant with an owner, a removed owner's removal applied. Each result is a
// connection and its outcome: idle-expired, owner-removed, owner-unknown or
// current. An owner read that is not answered changes nothing: the grant is
// refused at its next use.
func (s *Store) sweep(ctx context.Context, p provider) ([][2]string, error) {
	kind := p.kind()
	var out [][2]string
	var pending []*pendingRevoke
	type owned struct {
		connection string
		owner      PrincipalRef
		host       string
	}
	var reads []owned
	err := s.locked(func(v *state) error {
		l, err := s.grants()
		if err != nil {
			return err
		}
		now := grantClock()
		reconcileGrants(kind, s, v, &l, now)
		for i := range l.Grants {
			r := &l.Grants[i]
			if r.State == grantRevoked {
				continue
			}
			if idleExpired(*r, now) {
				one, err := s.revokeLocked(p, v, &l, i, revokedIdle, now)
				if err != nil {
					return err
				}
				if one != nil {
					pending = append(pending, one)
				}
				out = append(out, [2]string{r.Connection, "idle-expired"})
				continue
			}
			if r.Owner != nil && r.OwnerHost != nil {
				reads = append(reads, owned{r.Connection, *r.Owner, *r.OwnerHost})
			}
		}
		return s.saveGrants(l)
	})
	for _, r := range pending {
		r.finish(ctx, s)
	}
	if err != nil {
		return out, err
	}
	removed := map[[2]string]bool{}
	for _, r := range reads {
		key := [2]string{r.owner.Kind + "\x00" + r.owner.Issuer + "\x00" + r.owner.Subject, r.host}
		standing := ownerRemoved
		if !removed[key] {
			standing = s.ownerStanding(ctx, r.host, r.owner)
		}
		switch standing {
		case ownerRemoved:
			if !removed[key] {
				removed[key] = true
				if _, err := s.applyOwnerRemoval(ctx, p, r.owner, r.host, ""); err != nil {
					return out, err
				}
			}
			out = append(out, [2]string{r.connection, "owner-removed"})
		case ownerCurrent:
			out = append(out, [2]string{r.connection, "current"})
		default:
			out = append(out, [2]string{r.connection, "owner-unknown"})
		}
	}
	return out, nil
}
