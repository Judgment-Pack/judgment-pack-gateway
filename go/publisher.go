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
	"crypto/rand"
	"encoding/hex"
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
	// unverifiable is a publisher the public source does not show: a
	// package or a repository that is private or unpublished, a domain no
	// RDAP service answers for. It is reported, and never refused: only
	// evidence of a lapse is unmaintained.
	publisherUnverifiable = "unverifiable"
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
			return nil, errors.New("publisher: a domain publisher is a lower-case domain name")
		}
		if err := registrableDomain(name); err != nil {
			return nil, err
		}
	default:
		return nil, errors.New(`publisher: kind is "registry", "repository" or "domain"`)
	}
	return &publisherDecl{kind, name}, nil
}

// sharedPlatforms are domains under which many unrelated parties are given a
// host. The platform's registration says nothing of who publishes a host
// under it, so neither the platform's domain nor a host under it is a
// domain publisher.
var sharedPlatforms = []string{
	"vercel.app", "now.sh", "netlify.app", "netlify.com", "github.io", "gitlab.io", "herokuapp.com", "pages.dev",
	"workers.dev", "web.app", "firebaseapp.com", "appspot.com", "run.app", "azurewebsites.net", "azurestaticapps.net",
	"cloudfront.net", "amazonaws.com", "onrender.com", "fly.dev", "railway.app", "glitch.me", "repl.co", "replit.app",
	"ngrok.io", "ngrok-free.app", "ngrok.app", "deno.dev", "surge.sh", "modal.run", "hf.space", "streamlit.app",
}

// multiLabelSuffixes are public suffixes of two labels, under which the
// registrable domain has three. The core reads no public-suffix list, so
// this is a fixed, partial list: a domain under a two-label suffix it does
// not name is refused (its third label is taken for a host), and is
// declared by its repository or package instead.
var multiLabelSuffixes = map[string]bool{
	"co.uk": true, "org.uk": true, "ac.uk": true, "gov.uk": true, "ltd.uk": true, "plc.uk": true, "me.uk": true, "net.uk": true,
	"com.au": true, "net.au": true, "org.au": true, "edu.au": true, "gov.au": true, "co.nz": true, "org.nz": true, "net.nz": true,
	"co.jp": true, "ne.jp": true, "or.jp": true, "ac.jp": true, "com.br": true, "net.br": true, "org.br": true,
	"com.cn": true, "net.cn": true, "org.cn": true, "com.mx": true, "org.mx": true, "co.in": true, "net.in": true, "org.in": true,
	"co.za": true, "org.za": true, "com.sg": true, "com.hk": true, "com.tw": true, "co.kr": true, "or.kr": true,
	"com.tr": true, "com.ar": true, "co.il": true, "com.my": true, "com.ph": true, "com.vn": true, "com.pl": true, "co.id": true,
}

// registrableDomain refuses a domain publisher that is not itself a
// registrable domain: a host under one, a public suffix, or a shared
// platform or a host on it.
func registrableDomain(name string) error {
	for _, platform := range sharedPlatforms {
		if name == platform || strings.HasSuffix(name, "."+platform) {
			return fmt.Errorf("publisher: %s is a shared platform's domain, under which anyone may be given a host; declare the server's repository or package as its publisher instead", platform)
		}
	}
	labels := strings.Split(name, ".")
	want := 2
	if multiLabelSuffixes[strings.Join(labels[len(labels)-2:], ".")] {
		want = 3
	}
	switch {
	case len(labels) < want:
		return fmt.Errorf("publisher: %s is a public suffix, not a registrable domain", name)
	case len(labels) > want:
		return fmt.Errorf("publisher: a domain publisher is the registrable domain, not a host under it: declare %q", strings.Join(labels[len(labels)-want:], "."))
	}
	return nil
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

// writePublishers replaces the record beside the configuration, under the
// configuration's lock, which the caller holds (withConfigLock, or connect
// through afterWrite): every read-modify-write of the record is made under
// it, so no writer's change is lost to another's. The record is given the
// configuration's own mode and owner, through the descriptor, as connect
// gives a replaced configuration (configFile.replace): a root connect, or a
// root-run gateway publishers, over a configuration the signer owns leaves
// a record the signer can read. It is written to a file made beside it and
// renamed over it, and the directory synced.
func (f *configFile) writePublishers(pf publisherFile) error {
	data, err := json.MarshalIndent(pf, "", "  ")
	if err != nil {
		return err
	}
	name := f.base + publishersSuffix
	var nonce [8]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return err
	}
	tmp := "." + name + ".tmp-" + hex.EncodeToString(nonce[:])
	file, err := f.dir.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, f.mode)
	if err != nil {
		return err
	}
	defer f.dir.Remove(tmp)
	fail := func(err error) error {
		file.Close()
		return err
	}
	if _, err := file.Write(append(data, '\n')); err != nil {
		return fail(err)
	}
	if err := file.Chmod(f.mode); err != nil {
		return fail(err)
	}
	if err := keepOwner(file, f.owner); err != nil {
		return fail(err)
	}
	if err := syncFile(file); err != nil {
		return fail(err)
	}
	if err := file.Close(); err != nil {
		return err
	}
	if err := f.dir.Rename(tmp, name); err != nil {
		return err
	}
	return f.syncDir(".")
}

// withConfigLock runs fn holding the configuration's lock, the one connect
// holds (lockBeside): a connect that holds it is waited for up to ten
// seconds, then refused.
func withConfigLock(config string, fn func(*configFile) error) error {
	deadline := time.Now().Add(10 * time.Second)
	for {
		f, err := openConfigFile(config)
		if err == nil {
			defer f.close()
			return fn(f)
		}
		if !strings.Contains(err.Error(), "another connect holds") || time.Now().After(deadline) {
			return err
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// publisherChecker reads a publisher's liveness from the npm registry,
// GitHub's repository API and RDAP; a test points it elsewhere.
type publisherChecker struct {
	client      *http.Client
	npm, github string
	// bootstrap is the IANA RDAP bootstrap for DNS: which RDAP service
	// answers for each top-level domain.
	bootstrap string
	now       func() time.Time
}

func defaultPublisherChecker() publisherChecker {
	t := http.DefaultTransport.(*http.Transport).Clone()
	t.Proxy = http.ProxyFromEnvironment
	t.ResponseHeaderTimeout = publisherTimeout
	t.TLSHandshakeTimeout = publisherTimeout
	t.DialContext = (&net.Dialer{Timeout: publisherTimeout}).DialContext
	return publisherChecker{
		client: &http.Client{Transport: t, Timeout: publisherTimeout},
		npm:    "https://registry.npmjs.org/", github: "https://api.github.com/repos/", bootstrap: "https://data.iana.org/rdap/dns.json",
		now: time.Now,
	}
}

// The reasons, fixed sentences that name no path, account or token.
const (
	reasonPackageDeprecated   = "the package's latest version is deprecated in its registry"
	reasonPackageMissing      = "the registry shows no public package of that name: it may be private, or not published"
	reasonPackageLive         = "the registry lists the package, and its latest version is not deprecated"
	reasonRepoArchived        = "the repository is archived or disabled"
	reasonRepoMissing         = "no public repository of that name was found: it may be private, or not there"
	reasonRepoLive            = "the repository is neither archived nor disabled"
	reasonDomainExpired       = "the domain's registration has expired"
	reasonDomainPending       = "the domain is in its redemption period or pending deletion"
	reasonDomainNoService     = "no RDAP service is published for the domain's top-level domain"
	reasonDomainNotRegistered = "the registry's RDAP service answers that the domain is not registered: it lapsed and was deleted, or was never registered"
	reasonDomainLive          = "the domain's registration is current"
	reasonUnreadable          = "the publisher's liveness could not be read"
	reasonUndeclared          = "the binding declares no publisher"
)

// rdapService is the HTTPS base of the RDAP service the IANA bootstrap
// names for a top-level domain, and whether it names one.
func (c publisherChecker) rdapService(ctx context.Context, tld string) (string, bool, error) {
	status, body, err := c.get(ctx, c.bootstrap, "application/json")
	if err != nil || status != 200 {
		return "", false, errors.New("the RDAP bootstrap could not be read")
	}
	var boot struct {
		Services [][][]string `json:"services"`
	}
	if json.Unmarshal(body, &boot) != nil {
		return "", false, errors.New("the RDAP bootstrap could not be read")
	}
	for _, service := range boot.Services {
		if len(service) != 2 {
			continue
		}
		for _, entry := range service[0] {
			if !strings.EqualFold(entry, tld) {
				continue
			}
			for _, u := range service[1] {
				if strings.HasPrefix(u, "https://") {
					if !strings.HasSuffix(u, "/") {
						u += "/"
					}
					return u, true, nil
				}
			}
		}
	}
	return "", false, nil
}

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
			return publisherUnverifiable, reasonPackageMissing
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
			return publisherUnverifiable, reasonRepoMissing
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
		// The registry's own RDAP service is asked, as the IANA bootstrap
		// names it for the top-level domain. A top-level domain with no
		// service is unverifiable; the registry's 404 for the registrable
		// domain declared is evidence of a lapse: the name is free to be
		// registered by another.
		name := d.name
		service, known, err := c.rdapService(ctx, name[strings.LastIndex(name, ".")+1:])
		if err != nil {
			break
		}
		if !known {
			return publisherUnverifiable, reasonDomainNoService
		}
		status, body, err := c.get(ctx, service+"domain/"+name, "application/rdap+json")
		switch {
		case err != nil:
		case status == 404:
			return publisherUnmaintained, reasonDomainNotRegistered
		case status == 200:
			var reply struct {
				Name   string   `json:"ldhName"`
				Status []string `json:"status"`
				Events []struct {
					Action string `json:"eventAction"`
					Date   string `json:"eventDate"`
				} `json:"events"`
			}
			if json.Unmarshal(body, &reply) != nil || !strings.EqualFold(reply.Name, name) {
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

// homoglyphs are lower-case letters of the Cyrillic and Greek scripts, and
// a few Latin ones, that are drawn like a Latin letter, with that letter.
var homoglyphs = map[rune]rune{
	// Cyrillic
	'а': 'a', 'в': 'b', 'е': 'e', 'ё': 'e', 'һ': 'h', 'н': 'h', 'і': 'i', 'ї': 'i', 'ј': 'j', 'к': 'k',
	'ӏ': 'l', 'м': 'm', 'о': 'o', 'р': 'p', 'ԛ': 'q', 'г': 'r', 'ѕ': 's', 'т': 't', 'ц': 'u', 'ѵ': 'v',
	'ԝ': 'w', 'х': 'x', 'у': 'y', 'ԁ': 'd', 'ɡ': 'g', 'ԍ': 'g', 'с': 'c', 'ѡ': 'w',
	// Greek
	'α': 'a', 'β': 'b', 'ε': 'e', 'η': 'n', 'ι': 'i', 'κ': 'k', 'μ': 'u', 'ν': 'v', 'ο': 'o', 'ρ': 'p',
	'τ': 't', 'υ': 'u', 'χ': 'x', 'γ': 'y', 'ζ': 'z', 'ϲ': 'c', 'ϳ': 'j',
	// Latin look-alikes
	'ı': 'i', 'ł': 'l', 'ℓ': 'l', 'ß': 's', 'ɑ': 'a',
}

// A decomposed spelling (a letter, then a combining mark) needs no fold: the
// mark is not a letter or digit, and confusable drops it.
// accented is each Latin letter with a diacritic, from the Latin-1
// Supplement and Latin Extended-A blocks, by its base letter: what a
// Unicode decomposition would leave once its combining marks were dropped,
// which the core's standard library cannot compute.
var accented = map[rune]rune{}

func init() {
	for base, letters := range map[rune]string{
		'a': "àáâãäåāăą", 'c': "çćĉċč", 'd': "ďđ", 'e': "èéêëēĕėęě", 'g': "ĝğġģ", 'h': "ĥħ",
		'i': "ìíîïĩīĭįİ", 'j': "ĵ", 'k': "ķ", 'l': "ĺļľŀ", 'n': "ñńņňŉ", 'o': "òóôõöøōŏő",
		'r': "ŕŗř", 's': "śŝşš", 't': "ţťŧ", 'u': "ùúûüũūŭůűų", 'w': "ŵ", 'y': "ýÿŷ", 'z': "źżž",
	} {
		for _, r := range letters {
			accented[r] = base
		}
	}
}

// smallCapitals and armenian are letters drawn like a Latin letter.
var smallCapitals = map[rune]rune{
	'ᴀ': 'a', 'ʙ': 'b', 'ᴄ': 'c', 'ᴅ': 'd', 'ᴇ': 'e', 'ꜰ': 'f', 'ɢ': 'g', 'ʜ': 'h', 'ɪ': 'i', 'ᴊ': 'j', 'ᴋ': 'k',
	'ʟ': 'l', 'ᴍ': 'm', 'ɴ': 'n', 'ᴏ': 'o', 'ᴘ': 'p', 'ǫ': 'q', 'ʀ': 'r', 'ꜱ': 's', 'ᴛ': 't', 'ᴜ': 'u', 'ᴠ': 'v',
	'ᴡ': 'w', 'ʏ': 'y', 'ᴢ': 'z',
	// Armenian
	'օ': 'o', 'ս': 'u', 'հ': 'h', 'ո': 'n', 'ց': 'g', 'զ': 'q', 'ա': 'w',
}

// foldLetter is the Latin letter a letter with a diacritic, a small
// capital, an Armenian look-alike or a mathematical alphanumeric symbol
// (U+1D400 to U+1D7FF) is drawn as.
func foldLetter(r rune) (rune, bool) {
	if base, ok := accented[r]; ok {
		return base, true
	}
	if latin, ok := smallCapitals[r]; ok {
		return latin, true
	}
	switch {
	case r >= 0x1D400 && r <= 0x1D6A3:
		// Thirteen alphabets of 52 letters, capitals then small letters.
		i := (r - 0x1D400) % 52
		if i >= 26 {
			i -= 26
		}
		return 'a' + i, true
	case r >= 0x1D7CE && r <= 0x1D7FF:
		return '0' + (r-0x1D7CE)%10, true
	}
	return 0, false
}

// capitalHomoglyphs are Cyrillic and Greek capitals drawn like a Latin
// capital, with that letter.
var capitalHomoglyphs = map[rune]rune{
	'А': 'a', 'В': 'b', 'Е': 'e', 'К': 'k', 'М': 'm', 'Н': 'h', 'О': 'o', 'Р': 'p', 'С': 'c', 'Т': 't',
	'Х': 'x', 'І': 'i', 'Ј': 'j', 'Ѕ': 's', 'Ү': 'y',
	'Α': 'a', 'Β': 'b', 'Ε': 'e', 'Ζ': 'z', 'Η': 'h', 'Ι': 'i', 'Κ': 'k', 'Μ': 'm', 'Ν': 'n', 'Ο': 'o',
	'Ρ': 'p', 'Τ': 't', 'Υ': 'y', 'Χ': 'x',
}

// confusable folds the characters a name is commonly spoofed with, and
// drops everything but letters and digits.
func confusable(s string) string {
	// Capitals first: a capital of another script can look like a Latin
	// capital its own lower case does not look like (Greek Ν, ν).
	s = strings.Map(func(r rune) rune {
		if latin, ok := capitalHomoglyphs[r]; ok {
			return latin
		}
		return r
	}, s)
	s = strings.ToLower(s)
	// Letters of other scripts that a Latin letter is imitated with, and
	// the fullwidth forms, are taken for the Latin letter first.
	s = strings.Map(func(r rune) rune {
		if r >= 0xFF01 && r <= 0xFF5E {
			r -= 0xFEE0
			if r >= 'A' && r <= 'Z' {
				r += 'a' - 'A'
			}
			return r
		}
		if latin, ok := homoglyphs[r]; ok {
			return latin
		}
		if latin, ok := foldLetter(r); ok {
			return latin
		}
		return r
	}, s)
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
	switch r.State {
	case publisherUnmaintained:
		lines = append(lines, fmt.Sprintf("%s: publisher-unmaintained: %s", platform, r.Reason))
	case publisherUnverifiable:
		lines = append(lines, fmt.Sprintf("%s: publisher-unverifiable: %s", platform, r.Reason))
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
		// The reason names no path: it is answered to /acquire and /act.
		return fmt.Errorf("publisher-record-unreadable: platform %s: the publisher record could not be read", platform)
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
	// The record is written under the lock connect holds, once the
	// configuration is in place, read again there so that no other
	// writer's change is lost.
	req.afterWrite = func(held *configFile) error {
		f, err := readPublishers(path)
		if err != nil {
			return err
		}
		f.Publishers[req.platform] = record
		if err := held.writePublishers(f); err != nil {
			return fmt.Errorf("the configuration was written, and the publisher record was not: %v", err)
		}
		return nil
	}
	out, err := connect(ctx, req, host, check)
	out.statements = append(out.statements, lines...)
	return out, err
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
	// The liveness reads are made without the lock, which a connect would
	// otherwise wait for; what they read is merged into the record as it
	// stands under the lock, the policy included, so a policy set or a
	// record written meanwhile is kept.
	checked := map[string]publisherRecord{}
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
			checked[p.name] = checker.read(ctx, p.name, p.binding, b)
		}
	}
	if recheck || policy != "" {
		err := withConfigLock(config, func(held *configFile) error {
			current, err := readPublishers(path)
			if err != nil {
				return err
			}
			if policy != "" {
				current.Policy = policy
			}
			for name, r := range checked {
				// A record written since this re-check read the record --
				// by a connect or a recapture, of another binding or at
				// another time -- is kept as written: this reading is of
				// what stood before it.
				before, had := f.Publishers[name]
				now, has := current.Publishers[name]
				if has && (!had || now.Binding != before.Binding || now.CheckedAt != before.CheckedAt || now.Binding != r.Binding) {
					continue
				}
				current.Publishers[name] = r
			}
			if err := held.writePublishers(current); err != nil {
				return err
			}
			f = current
			return nil
		})
		if err != nil {
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
