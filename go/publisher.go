package main

// Publisher trust for customer MCP servers (gateway #357; spec RFC 0030 §5
// rule 7, a Draft). A customer binding may declare who publishes its server:
// a package in a registry, a source repository, or a domain. At
// registration (connect, a recapture with --replace included) and on the
// operator's schedule (gateway publishers --check), the gateway reads that
// publisher's liveness from public sources and keeps what it read beside
// the engine configuration (<engine.json>.publishers.json):
// maintained, unmaintained or unknown, with when. A lapsed or archived
// publisher is reported as publisher-unmaintained, and the operator's
// policy may make that a refusal. A registration whose name closely matches
// one of the integrations the gateway ships, under another publisher, is
// flagged name-lookalike. Neither the record nor its check grants anything:
// a customer binding is held to every rule it was held to before.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

const (
	publisherMaintained   = "maintained"
	publisherUnmaintained = "unmaintained"
	publisherUnknown      = "unknown"
	publisherUndeclared   = "undeclared"

	publisherPolicyReport = "report"
	publisherPolicyRefuse = "refuse"

	publishersSuffix   = ".publishers.json"
	publisherReadBytes = 8 << 20
	publisherTimeout   = 15 * time.Second
	publisherTimeForm  = "2006-01-02T15:04:05.000Z"
	maxPublishersBytes = 1 << 20
)

// publisherDecl is the publisher a customer binding declares.
type publisherDecl struct {
	kind, name string
}

var (
	npmName    = regexp.MustCompile(`^(@[a-z0-9][a-z0-9._~-]{0,213}/)?[a-z0-9][a-z0-9._~-]{0,213}$`)
	githubRepo = regexp.MustCompile(`^github\.com/([A-Za-z0-9](?:[A-Za-z0-9-]{0,38}))/([A-Za-z0-9._-]{1,100})$`)
	domainName = regexp.MustCompile(`^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?$`)
)

// parsePublisher holds a binding's publisher member to its form:
// {"kind": "registry", "name": "npm:<package>"}, {"kind": "repository",
// "name": "github.com/<owner>/<repository>"} or {"kind": "domain", "name":
// "<host name>"}. The registries and repository hosts named are the ones
// whose liveness the gateway can read.
func parsePublisher(v value) (*publisherDecl, error) {
	obj, err := requireObject(v, "publisher")
	if err != nil {
		return nil, err
	}
	if err := exactlyMembers(obj, map[string]bool{"kind": true, "name": true}, "publisher"); err != nil {
		return nil, err
	}
	kind, err := requireString(obj, "kind")
	if err != nil {
		return nil, err
	}
	name, err := requireString(obj, "name")
	if err != nil {
		return nil, err
	}
	switch kind {
	case "registry":
		pkg, ok := strings.CutPrefix(name, "npm:")
		if !ok || len(pkg) > 214 || !npmName.MatchString(pkg) {
			return nil, errors.New(`publisher: a registry publisher is "npm:<package>"`)
		}
	case "repository":
		m := githubRepo.FindStringSubmatch(name)
		if m == nil || m[2] == "." || m[2] == ".." || strings.HasSuffix(m[1], "-") {
			return nil, errors.New(`publisher: a repository publisher is "github.com/<owner>/<repository>"`)
		}
	case "domain":
		if len(name) > 253 || !domainName.MatchString(name) {
			return nil, errors.New("publisher: a domain publisher is a lower-case host name")
		}
	default:
		return nil, errors.New(`publisher: kind is "registry", "repository" or "domain"`)
	}
	return &publisherDecl{kind, name}, nil
}

// publisherRecord is what the gateway read of one platform's publisher.
// It names the binding it was read for, so a record of another binding is
// not taken for this one.
type publisherRecord struct {
	Binding   string `json:"binding"`
	Kind      string `json:"kind"`
	Name      string `json:"name"`
	State     string `json:"state"`
	CheckedAt string `json:"checkedAt"`
	Reason    string `json:"reason"`
	Lookalike string `json:"lookalike,omitempty"`
}

// publisherFile is the record of every customer platform's publisher, and
// the operator's policy: report, the default, or refuse, under which an
// unmaintained publisher refuses its registration, its acquisitions and its
// actions.
type publisherFile struct {
	Version    int                        `json:"version"`
	Policy     string                     `json:"policy"`
	Publishers map[string]publisherRecord `json:"publishers"`
}

func publishersPath(config string) string { return config + publishersSuffix }

// readPublishers is the record beside a configuration; an absent one is
// empty, under the report policy.
func readPublishers(path string) (publisherFile, error) {
	f := publisherFile{Version: 1, Policy: publisherPolicyReport, Publishers: map[string]publisherRecord{}}
	data, err := readBounded(path, maxPublishersBytes)
	if errors.Is(err, os.ErrNotExist) {
		return f, nil
	}
	if err != nil {
		return f, err
	}
	d := json.NewDecoder(strings.NewReader(string(data)))
	d.DisallowUnknownFields()
	if d.Decode(&f) != nil || f.Version != 1 || f.Policy != publisherPolicyReport && f.Policy != publisherPolicyRefuse || f.Publishers == nil {
		return f, fmt.Errorf("%s is not a publisher record", filepath.Base(path))
	}
	return f, nil
}

// writePublishers replaces the record by renaming a synced file over it.
func writePublishers(path string, f publisherFile) error {
	data, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".tmp-")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(append(data, '\n')); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

// publisherChecker reads a publisher's liveness from the npm registry,
// GitHub's repository API and RDAP; a test points it elsewhere.
type publisherChecker struct {
	client            *http.Client
	npm, github, rdap string
	now               func() time.Time
}

func defaultPublisherChecker() publisherChecker {
	t := http.DefaultTransport.(*http.Transport).Clone()
	t.Proxy = http.ProxyFromEnvironment
	t.ResponseHeaderTimeout = publisherTimeout
	t.TLSHandshakeTimeout = publisherTimeout
	t.DialContext = (&net.Dialer{Timeout: publisherTimeout}).DialContext
	return publisherChecker{
		client: &http.Client{Transport: t, Timeout: publisherTimeout},
		npm:    "https://registry.npmjs.org/", github: "https://api.github.com/repos/", rdap: "https://rdap.org/domain/",
		now: time.Now,
	}
}

// The reasons, fixed sentences that name no path, account or token.
const (
	reasonPackageDeprecated = "the package's latest version is deprecated in its registry"
	reasonPackageMissing    = "the package is not in its registry"
	reasonPackageLive       = "the registry lists the package, and its latest version is not deprecated"
	reasonRepoArchived      = "the repository is archived or disabled"
	reasonRepoMissing       = "the repository was not found"
	reasonRepoLive          = "the repository is neither archived nor disabled"
	reasonDomainExpired     = "the domain's registration has expired"
	reasonDomainPending     = "the domain is in its redemption period or pending deletion"
	reasonDomainMissing     = "the domain is not registered"
	reasonDomainLive        = "the domain's registration is current"
	reasonUnreadable        = "the publisher's liveness could not be read"
	reasonUndeclared        = "the binding declares no publisher"
)

// get is one bounded GET; the status, and the body of a 200.
func (c publisherChecker) get(ctx context.Context, endpoint, accept string) (int, []byte, error) {
	ctx, cancel := context.WithTimeout(ctx, publisherTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, "GET", endpoint, nil)
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Accept", accept)
	req.Header.Set("User-Agent", "judgment-pack-gateway publisher check")
	resp, err := c.client.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return resp.StatusCode, nil, nil
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, publisherReadBytes+1))
	if err != nil || len(body) > publisherReadBytes {
		return 0, nil, errors.New("unreadable")
	}
	return 200, body, nil
}

// check reads a declared publisher's liveness: its state, and why.
func (c publisherChecker) check(ctx context.Context, d *publisherDecl) (string, string) {
	if d == nil {
		return publisherUndeclared, reasonUndeclared
	}
	switch d.kind {
	case "registry":
		pkg := strings.TrimPrefix(d.name, "npm:")
		status, body, err := c.get(ctx, c.npm+strings.Replace(pkg, "/", "%2f", 1), "application/vnd.npm.install-v1+json")
		switch {
		case err != nil:
		case status == 404:
			return publisherUnmaintained, reasonPackageMissing
		case status == 200:
			var doc struct {
				Tags     map[string]string `json:"dist-tags"`
				Versions map[string]struct {
					Deprecated any `json:"deprecated"`
				} `json:"versions"`
			}
			if json.Unmarshal(body, &doc) != nil {
				break
			}
			latest, ok := doc.Versions[doc.Tags["latest"]]
			if !ok {
				break
			}
			if s, isText := latest.Deprecated.(string); isText && s != "" || latest.Deprecated == true {
				return publisherUnmaintained, reasonPackageDeprecated
			}
			return publisherMaintained, reasonPackageLive
		}
	case "repository":
		status, body, err := c.get(ctx, c.github+strings.TrimPrefix(d.name, "github.com/"), "application/vnd.github+json")
		switch {
		case err != nil:
		case status == 404:
			return publisherUnmaintained, reasonRepoMissing
		case status == 200:
			var repo struct {
				Archived *bool `json:"archived"`
				Disabled bool  `json:"disabled"`
			}
			if json.Unmarshal(body, &repo) != nil || repo.Archived == nil {
				break
			}
			if *repo.Archived || repo.Disabled {
				return publisherUnmaintained, reasonRepoArchived
			}
			return publisherMaintained, reasonRepoLive
		}
	case "domain":
		status, body, err := c.get(ctx, c.rdap+d.name, "application/rdap+json")
		switch {
		case err != nil:
		case status == 404:
			return publisherUnmaintained, reasonDomainMissing
		case status == 200:
			var reply struct {
				Name   string   `json:"ldhName"`
				Status []string `json:"status"`
				Events []struct {
					Action string `json:"eventAction"`
					Date   string `json:"eventDate"`
				} `json:"events"`
			}
			if json.Unmarshal(body, &reply) != nil || !strings.EqualFold(reply.Name, d.name) {
				break
			}
			for _, s := range reply.Status {
				switch strings.ToLower(s) {
				case "redemption period", "pending delete":
					return publisherUnmaintained, reasonDomainPending
				}
			}
			for _, e := range reply.Events {
				if e.Action != "expiration" {
					continue
				}
				t, err := time.Parse(time.RFC3339, e.Date)
				if err != nil {
					return publisherUnknown, reasonUnreadable
				}
				if !c.now().Before(t) {
					return publisherUnmaintained, reasonDomainExpired
				}
			}
			return publisherMaintained, reasonDomainLive
		}
	}
	return publisherUnknown, reasonUnreadable
}

// knownIntegration is an integration the gateway ships, by its name, and
// the publishers it is published under: a domain (and its subdomains), a
// repository owner on GitHub, or an npm scope.
type knownIntegration struct {
	name       string
	publishers []string
}

// knownIntegrations are the gateway's own: the catalog's bindings and the
// connection providers.
var knownIntegrations = []knownIntegration{
	{"azure-devops", []string{"domain:microsoft.com", "domain:azure.com", "domain:visualstudio.com", "repository:microsoft", "registry:@azure-devops/"}},
	{"databricks", []string{"domain:databricks.com", "repository:databricks", "registry:@databricks/"}},
	{"postgres", []string{"domain:postgresql.org"}},
	{"google-drive", []string{"domain:google.com", "domain:googleapis.com", "repository:google", "repository:googleapis"}},
	{"gmail", []string{"domain:google.com", "domain:googleapis.com", "repository:google", "repository:googleapis"}},
	{"notion", []string{"domain:notion.so", "domain:notion.com", "repository:makenotion", "registry:@notionhq/"}},
	{"obsidian", []string{"domain:obsidian.md", "repository:obsidianmd"}},
	{"aws-s3", []string{"domain:amazon.com", "domain:amazonaws.com", "repository:aws", "repository:awslabs", "registry:@aws-sdk/"}},
}

// publishedBy reports whether a declared publisher is one of a known
// integration's.
func publishedBy(d *publisherDecl, k knownIntegration) bool {
	if d == nil {
		return false
	}
	for _, p := range k.publishers {
		kind, value, _ := strings.Cut(p, ":")
		switch {
		case kind == "domain" && d.kind == "domain" && (d.name == value || strings.HasSuffix(d.name, "."+value)):
			return true
		case kind == "repository" && d.kind == "repository" && strings.EqualFold(strings.Split(d.name, "/")[1], value):
			return true
		case kind == "registry" && d.kind == "registry" && strings.HasPrefix(strings.TrimPrefix(d.name, "npm:"), value):
			return true
		}
	}
	return false
}

// confusable folds the characters a name is commonly spoofed with, and
// drops everything but letters and digits.
func confusable(s string) string {
	s = strings.ToLower(s)
	s = strings.NewReplacer("rn", "m", "vv", "w", "0", "o", "1", "l", "3", "e", "5", "s", "@", "a").Replace(s)
	var b strings.Builder
	for _, r := range s {
		if r >= 'a' && r <= 'z' || r >= '0' && r <= '9' {
			b.WriteRune(r)
		}
	}
	return b.String()
}

// editDistance is the optimal string alignment distance: insertions,
// deletions, substitutions and adjacent transpositions.
func editDistance(a, b string) int {
	ra, rb := []rune(a), []rune(b)
	d := make([][]int, len(ra)+1)
	for i := range d {
		d[i] = make([]int, len(rb)+1)
		d[i][0] = i
	}
	for j := range d[0] {
		d[0][j] = j
	}
	for i := 1; i <= len(ra); i++ {
		for j := 1; j <= len(rb); j++ {
			cost := 1
			if ra[i-1] == rb[j-1] {
				cost = 0
			}
			d[i][j] = min(d[i-1][j]+1, d[i][j-1]+1, d[i-1][j-1]+cost)
			if i > 1 && j > 1 && ra[i-1] == rb[j-2] && ra[i-2] == rb[j-1] {
				d[i][j] = min(d[i][j], d[i-2][j-2]+1)
			}
		}
	}
	return d[len(ra)][len(rb)]
}

// lookalike is the known integration a registration's names closely match
// under another publisher, or "". A name matches when, folded, it equals
// the integration's, is within one edit of it (two for a name of ten
// characters or more), or contains it.
func lookalike(names []string, d *publisherDecl) string {
	for _, k := range knownIntegrations {
		known := confusable(k.name)
		for _, name := range names {
			n := confusable(name)
			if n == "" {
				continue
			}
			bound := 1
			if len(known) >= 10 {
				bound = 2
			}
			close := n == known || editDistance(n, known) <= bound || len(known) >= 5 && strings.Contains(n, known)
			if close && !publishedBy(d, k) {
				return k.name
			}
		}
	}
	return ""
}

// publisherLines are what a registration shows of its publisher, with its
// approval: the state read, and each flag.
func publisherLines(platform string, r publisherRecord) []string {
	what := "none declared"
	if r.Kind != "" {
		what = r.Kind + " " + r.Name
	}
	lines := []string{fmt.Sprintf("%s: publisher %s: %s at %s: %s", platform, what, r.State, r.CheckedAt, r.Reason)}
	if r.State == publisherUnmaintained {
		lines = append(lines, fmt.Sprintf("%s: publisher-unmaintained: %s", platform, r.Reason))
	}
	if r.Lookalike != "" {
		lines = append(lines, fmt.Sprintf("%s: name-lookalike: the name closely matches the integration %s, which another publisher publishes", platform, r.Lookalike))
	}
	return lines
}

// readPublisher reads one customer binding's publisher now.
func (c publisherChecker) read(ctx context.Context, platform, ref string, b binding) publisherRecord {
	state, reason := c.check(ctx, b.publisher)
	r := publisherRecord{Binding: ref, State: state, Reason: reason, CheckedAt: c.now().UTC().Format(publisherTimeForm)}
	if b.publisher != nil {
		r.Kind, r.Name = b.publisher.kind, b.publisher.name
	}
	r.Lookalike = lookalike([]string{platform, b.platform}, b.publisher)
	return r
}

// errPublisherUnmaintained is the refusal the refuse policy makes.
func errPublisherUnmaintained(platform string) error {
	return fmt.Errorf("publisher-unmaintained: platform %s: the operator's publisher policy refuses a server whose publisher is unmaintained", platform)
}

// publisherRefusal is the refusal of a platform's call under the
// operator's policy: refuse, and a record of this binding saying its
// publisher is unmaintained. A record that cannot be read refuses under
// nothing it does not say; one of another binding is not this one's.
func publisherRefusal(path, platform, ref string) error {
	if path == "" {
		return nil
	}
	f, err := readPublishers(path)
	if err != nil {
		return fmt.Errorf("publisher-record-unreadable: platform %s: %v", platform, err)
	}
	r, ok := f.Publishers[platform]
	if f.Policy == publisherPolicyRefuse && ok && r.Binding == ref && r.State == publisherUnmaintained {
		return errPublisherUnmaintained(platform)
	}
	return nil
}

// connectPublisher is connect with its publisher read: a customer
// binding's publisher is read before anything is run, shown with the
// approval, refused under the refuse policy where it is unmaintained, and
// recorded once the configuration is written.
func connectPublisher(ctx context.Context, req connectRequest, host engineHost, check func(context.Context, sourceSpec) ([]byte, error), checker publisherChecker) (connectOutcome, error) {
	if req.preview != "" {
		return connect(ctx, req, host, check)
	}
	data, err := readBounded(req.config, maxEngineConfigBytes)
	if err != nil {
		return connect(ctx, req, host, check)
	}
	cfg, err := parseEngineConfig(data)
	if err != nil {
		return connect(ctx, req, host, check)
	}
	ref, b, err := pinBinding(cfg.catalog, req.binding)
	if err != nil || !b.customer {
		return connect(ctx, req, host, check)
	}
	path := publishersPath(req.config)
	f, err := readPublishers(path)
	if err != nil {
		return connectOutcome{}, err
	}
	record := checker.read(ctx, req.platform, ref, b)
	lines := publisherLines(req.platform, record)
	if f.Policy == publisherPolicyRefuse && record.State == publisherUnmaintained {
		return connectOutcome{statements: lines}, errPublisherUnmaintained(req.platform)
	}
	out, err := connect(ctx, req, host, check)
	out.statements = append(out.statements, lines...)
	if err != nil || out.written == "" {
		return out, err
	}
	if f, err = readPublishers(path); err != nil {
		return out, err
	}
	f.Publishers[req.platform] = record
	if err := writePublishers(path, f); err != nil {
		return out, fmt.Errorf("the configuration was written, and the publisher record was not: %v", err)
	}
	return out, nil
}

const publishersUsage = "usage: gateway publishers --config <engine.json> [--check] [--policy report|refuse]"

// cmdPublishers is the operator's view of the publisher record: printed as
// it stands, read again for every customer platform with --check (the
// schedule is the operator's), and its policy set with --policy.
func cmdPublishers(args []string, stdout, stderr io.Writer) int {
	return runPublishers(context.Background(), args, stdout, stderr, defaultPublisherChecker())
}

func runPublishers(ctx context.Context, args []string, stdout, stderr io.Writer, checker publisherChecker) int {
	var config, policy string
	recheck := false
	for len(args) > 0 {
		a := args[0]
		args = args[1:]
		switch {
		case a == "--check" && !recheck:
			recheck = true
		case (a == "--config" || a == "--policy") && len(args) > 0:
			target := &config
			if a == "--policy" {
				target = &policy
			}
			if *target != "" {
				fmt.Fprintln(stderr, publishersUsage)
				return 2
			}
			*target, args = args[0], args[1:]
		default:
			fmt.Fprintln(stderr, publishersUsage)
			return 2
		}
	}
	if config == "" || policy != "" && policy != publisherPolicyReport && policy != publisherPolicyRefuse {
		fmt.Fprintln(stderr, publishersUsage)
		return 2
	}
	path := publishersPath(config)
	f, err := readPublishers(path)
	if err != nil {
		fmt.Fprintln(stderr, "publishers:", printable(err.Error()))
		return 1
	}
	changed := false
	if policy != "" && policy != f.Policy {
		f.Policy, changed = policy, true
	}
	if recheck {
		data, err := readBounded(config, maxEngineConfigBytes)
		if err != nil {
			fmt.Fprintln(stderr, "publishers:", printable(err.Error()))
			return 1
		}
		cfg, err := parseEngineConfig(data)
		if err != nil {
			fmt.Fprintln(stderr, "publishers:", printable(err.Error()))
			return 1
		}
		for _, p := range cfg.platforms {
			b, err := loadBinding(cfg.catalog, p.binding)
			if err != nil {
				fmt.Fprintln(stderr, "publishers:", printable(err.Error()))
				return 1
			}
			if !b.customer {
				continue
			}
			f.Publishers[p.name] = checker.read(ctx, p.name, p.binding, b)
		}
		changed = true
	}
	if changed {
		if err := writePublishers(path, f); err != nil {
			fmt.Fprintln(stderr, "publishers:", printable(err.Error()))
			return 1
		}
	}
	names := make([]string, 0, len(f.Publishers))
	for name := range f.Publishers {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		for _, line := range publisherLines(name, f.Publishers[name]) {
			fmt.Fprintln(stdout, printable(line))
		}
	}
	fmt.Fprintf(stdout, "policy: %s\n", f.Policy)
	return 0
}
