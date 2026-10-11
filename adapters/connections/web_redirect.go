package connections

import (
	"adapters/attachment"
	"errors"
	"strings"
)

// Web redirect policies are operator configuration of the web source: the
// cross-origin redirects adapter-web may follow beyond the same-origin rule
// (docs/design/public-web-sources.md#operator-redirect-policies). The
// operator names them on the adapter's command line, as
// WebRedirectPoliciesFlag and a list; the managed local plan gives the web
// source that flag while WebRedirectPoliciesEnv, in the environment the
// companion is asked with, names a policy. Nothing a request, a model or a
// URL carries can name one.
const (
	WebRedirectPoliciesEnv  = "JPACK_WEB_REDIRECT_POLICIES"
	WebRedirectPoliciesFlag = "--redirect-policies="
	// GoogleGroundingPolicy follows one redirect from a Google grounding
	// search result's endpoint to the publisher's origin.
	GoogleGroundingPolicy = attachment.RedirectPolicyGoogleGrounding
)

// ErrWebRedirectPolicy is a list that names a policy this distribution does
// not support, names one twice, or is not names separated by single commas.
var ErrWebRedirectPolicy = errors.New("web-redirect-policy-unknown")

// WebRedirectPolicyRefusal is the one sentence a program refuses to start
// with when the operator's list is not one it can follow. It quotes nothing
// of the list.
const WebRedirectPolicyRefusal = "web-redirect-policy-unknown: the web source's redirect policies name a policy it does not support, or one twice; it supports google-grounding"

// SupportedWebRedirectPolicies are the policies this distribution can follow.
func SupportedWebRedirectPolicies() []string { return []string{GoogleGroundingPolicy} }

// ParseWebRedirectPolicies reads the operator's list: the empty string is no
// policy, and anything else is supported names separated by single commas,
// none twice. Whitespace, an empty item or an unknown name refuses the list
// whole; it is never read as a smaller list.
func ParseWebRedirectPolicies(value string) ([]string, error) {
	out := []string{}
	if value == "" {
		return out, nil
	}
	seen := map[string]bool{}
	for _, name := range strings.Split(value, ",") {
		known := false
		for _, supported := range SupportedWebRedirectPolicies() {
			known = known || name == supported
		}
		if !known || seen[name] {
			return nil, ErrWebRedirectPolicy
		}
		seen[name] = true
		out = append(out, name)
	}
	return out, nil
}

// WithWebRedirectPolicies is the plan with the web source launched with the
// operator's redirect policies, and the plan unchanged when there are none.
// Discovery (web-discovery) follows no policy and is never given the flag.
func (p LocalPlan) WithWebRedirectPolicies(policies []string) LocalPlan {
	if len(policies) == 0 {
		return p
	}
	sources := make([]LocalSource, len(p.Sources))
	copy(sources, p.Sources)
	for i := range sources {
		if sources[i].ID == "web" {
			sources[i].Args = append(append([]string{}, sources[i].Args...), WebRedirectPoliciesFlag+strings.Join(policies, ","))
		}
	}
	p.Sources = sources
	return p
}

// SourceCapabilities is what `gateway-connections --source-capabilities`
// reports: for each source with operator-configurable behaviour, what this
// distribution supports and what the operator's configuration enables.
// Version 1 names the web source's redirect policies only. It is a separate
// document from the catalog and the plan, whose readers hold their members
// closed.
type SourceCapabilities struct {
	Version int                `json:"version"`
	Sources []SourceCapability `json:"sources"`
}
type SourceCapability struct {
	ID               string               `json:"id"`
	RedirectPolicies RedirectPolicyStatus `json:"redirectPolicies"`
}

// RedirectPolicyStatus: Supported is what an operator can enable; Enabled is
// what the configuration given to this report enables, which is what the web
// source follows when it is launched from the same configuration.
type RedirectPolicyStatus struct {
	Supported []string `json:"supported"`
	Enabled   []string `json:"enabled"`
}

// ConnectionSourceCapabilities reports the web source under enabled, a list
// ParseWebRedirectPolicies admitted.
func ConnectionSourceCapabilities(enabled []string) SourceCapabilities {
	return SourceCapabilities{Version: 1, Sources: []SourceCapability{{ID: "web", RedirectPolicies: RedirectPolicyStatus{Supported: SupportedWebRedirectPolicies(), Enabled: append([]string{}, enabled...)}}}}
}
