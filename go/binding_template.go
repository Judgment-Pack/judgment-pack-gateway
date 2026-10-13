package main

import (
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// A platform's parameters and a remote binding's templates
// (docs/design/engine-config.md, "Bindings"; ADR-0015, question 1, amended
// 2026-10-13). A remote server whose URL names a tenant -- an Azure DevOps
// organization, a Databricks workspace -- takes that part from the
// platform's configuration: the binding writes {name} where the tenant's
// part goes, in its server.url and its tools, and the platform's
// `parameters` (engineVersion 8) give each name its value. The binding's
// digest pins the template and the transport; the engine fills the
// template before it builds the adapter's command line, and what the
// adapter is given, what the acquisition records as its endpoint and what
// an action receipt names as the tool's endpoint is the resolved URL, never
// the template. A placeholder no parameter gives, or a parameter no
// placeholder names, refuses the start.

// parameterName is a parameter's name and a placeholder's: a lowercase
// letter, then lowercase letters, digits and hyphens.
var parameterName = regexp.MustCompile(`^[a-z][a-z0-9-]{0,62}$`)

// parameterValue is a parameter's value: letters, digits, '.', '_' and
// '-', at most maxParameterValue bytes. Nothing in it can end a path
// segment, begin a query or a fragment, or name a user or a port, so a
// value put where the template's path takes it stays in that segment.
var parameterValue = regexp.MustCompile(`^[A-Za-z0-9._-]+$`)

// maxParameterValue is the longest value a parameter takes: a host name's
// bound.
const maxParameterValue = 253

// workspaceParameter is the one parameter a template may put where the
// host goes: a Databricks workspace's host, held to the forms the
// Databricks connection accepts (adapters/connections/databricks.go), so a
// template cannot send its credential off the workspace.
const workspaceParameter = "workspace"

// workspaceDomains are the domains a Databricks workspace's own host is
// under: on AWS, AWS GovCloud and its DoD environment, on Google Cloud, and
// on Azure. They are the connection's (databricksDomains), and a test holds
// the two lists to each other.
var workspaceDomains = []string{".cloud.databricks.com", ".cloud.databricks.us", ".cloud.databricks.mil", ".gcp.databricks.com", ".azuredatabricks.net"}

var workspaceLabel = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)

// parameterProblem is why a parameter's name or value is not of its form,
// or nil.
func parameterProblem(name, value string) error {
	if !parameterName.MatchString(name) {
		return fmt.Errorf("parameters names %q, which is not a parameter's name: a lowercase letter, then lowercase letters, digits and hyphens, at most 63", requestText(name))
	}
	if value == "" || len(value) > maxParameterValue || !parameterValue.MatchString(value) || strings.Trim(value, ".") == "" {
		return fmt.Errorf("parameters.%s is not a parameter's value: 1 to %d letters, digits, '.', '_' or '-', not dots alone, and never a secret", name, maxParameterValue)
	}
	if name == workspaceParameter && !isWorkspaceHost(value) {
		return fmt.Errorf("parameters.%s is not a Databricks workspace's host: one to three lowercase labels under %s, not the account console's", name, strings.Join(workspaceDomains, ", "))
	}
	return nil
}

// isWorkspaceHost is a Databricks workspace's host as the Databricks
// connection holds one (DatabricksWorkspace): one to three lowercase DNS
// labels, none an internationalized one, under a workspace domain, the
// first label not the account console's.
func isWorkspaceHost(host string) bool {
	if len(host) > 253 {
		return false
	}
	name := ""
	for _, domain := range workspaceDomains {
		if strings.HasSuffix(host, domain) {
			name = strings.TrimSuffix(host, domain)
			break
		}
	}
	labels := strings.Split(name, ".")
	if name == "" || len(labels) > 3 || labels[0] == "accounts" || labels[0] == "accounts-dod" {
		return false
	}
	for _, label := range labels {
		if !workspaceLabel.MatchString(label) || strings.HasPrefix(label, "xn--") {
			return false
		}
	}
	return true
}

// templatePlaceholders are the names a template's placeholders give, in
// the order they first appear, or why the template is not one: a '{' that
// does not open a placeholder of a parameter's name, or a '}' that does not
// close one.
func templatePlaceholders(s string) ([]string, error) {
	var names []string
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '}':
			return nil, errors.New("holds a } that closes no placeholder")
		case '{':
			end := strings.IndexByte(s[i:], '}')
			if end < 0 {
				return nil, errors.New("holds a { that no } closes")
			}
			name := s[i+1 : i+end]
			if !parameterName.MatchString(name) {
				return nil, fmt.Errorf("names a placeholder {%s}, which is not a parameter's name: a lowercase letter, then lowercase letters, digits and hyphens", requestText(name))
			}
			if !contains(names, name) {
				names = append(names, name)
			}
			i += end
		}
	}
	return names, nil
}

// fillTemplate is a template with each placeholder replaced by the value
// value gives it.
func fillTemplate(s string, value func(name string) string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '{' {
			end := strings.IndexByte(s[i:], '}')
			b.WriteString(value(s[i+1 : i+end]))
			i += end
			continue
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

// urlTemplateProblem is why a remote server's URL template is not one the
// engine fills, or nil: the scheme written as it is; the host written as it
// is, or {workspace} alone over https -- a placeholder anywhere else in the
// authority, beside a written host or in place of a port, could change the
// host the credential goes to; and the template, its placeholders taken as
// a one-letter value, of the endpoint form, so a query, a fragment, a user
// or plain http off loopback in its written text is refused before any
// parameter is read.
func urlTemplateProblem(template string) error {
	rest, secure := strings.CutPrefix(template, "https://")
	if !secure {
		var plain bool
		if rest, plain = strings.CutPrefix(template, "http://"); !plain {
			return errors.New("must begin with its scheme written as it is, https:// or http://; a placeholder there could change the scheme")
		}
	}
	authority, _, _ := strings.Cut(rest, "/")
	if strings.ContainsAny(authority, "{}") && (authority != "{"+workspaceParameter+"}" || !secure) {
		return errors.New("must write its host as it is, or as {workspace} alone over https: a placeholder anywhere else in the host or beside it could change the host")
	}
	sample := fillTemplate(template, func(string) string { return "x" })
	if !isRemoteEndpoint(sample) || urlParses(sample) != nil {
		return errors.New("must be of the endpoint form with its placeholders filled: https, or http at a loopback address written as one, with no user, query or fragment")
	}
	return nil
}

// bindingPlaceholders are the placeholders a binding's remote operations
// name, in their URLs and their tools, sorted.
func bindingPlaceholders(b binding) []string {
	var names []string
	for _, op := range []*operation{b.live, b.write} {
		if op == nil || op.url == "" {
			continue
		}
		for _, s := range append([]string{op.url}, op.tools...) {
			found, _ := templatePlaceholders(s)
			for _, name := range found {
				if !contains(names, name) {
					names = append(names, name)
				}
			}
		}
	}
	sort.Strings(names)
	return names
}

// resolveParameters fills a binding's remote templates with a platform's
// parameters and returns the binding the platform reaches: each URL, each
// tool and a probe resolved. It refuses a placeholder no parameter gives, a
// parameter no placeholder names, a resolved URL out of the endpoint form,
// and two tools that resolve to one name. ref names the binding in what it
// says. The binding given is not changed.
func resolveParameters(b binding, parameters map[string]string, ref string) (binding, error) {
	names := bindingPlaceholders(b)
	for _, name := range names {
		if _, given := parameters[name]; !given {
			return b, fmt.Errorf("binding %s names the placeholder {%s}, and the platform's parameters give no %s", ref, name, name)
		}
	}
	keys := make([]string, 0, len(parameters))
	for name := range parameters {
		keys = append(keys, name)
	}
	sort.Strings(keys)
	for _, name := range keys {
		if !contains(names, name) {
			return b, fmt.Errorf("parameters.%s is named by no placeholder of binding %s; a parameter nothing uses is one nobody meant", name, ref)
		}
	}
	if len(names) == 0 {
		return b, nil
	}
	value := func(name string) string { return parameters[name] }
	for _, slot := range []struct {
		name string
		op   **operation
	}{{"live", &b.live}, {"write", &b.write}} {
		op := *slot.op
		if op == nil || op.url == "" {
			continue
		}
		resolved := *op
		resolved.url = fillTemplate(op.url, value)
		if !isRemoteEndpoint(resolved.url) || urlParses(resolved.url) != nil {
			return b, fmt.Errorf("binding %s: the %s operation's URL, filled with the platform's parameters, is %q, which is not of the endpoint form: https, or http at a loopback address written as one, with no user, query or fragment, at most %d characters", ref, slot.name, requestText(resolved.url), maxRemoteEndpoint)
		}
		resolved.tools = make([]string, 0, len(op.tools))
		for _, tool := range op.tools {
			name := fillTemplate(tool, value)
			if contains(resolved.tools, name) {
				return b, fmt.Errorf("binding %s: two of the %s operation's tools resolve to %q", ref, slot.name, requestText(name))
			}
			resolved.tools = append(resolved.tools, name)
		}
		if op.probe != "" {
			resolved.probe = fillTemplate(op.probe, value)
		}
		*slot.op = &resolved
	}
	return b, nil
}
