package websource

import (
	"adapters/document"
	"adapters/internal/canon"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/url"
	"path"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/temoto/robotstxt"
	"golang.org/x/net/html"
)

const CrawlPages = 10
const CrawlDepth = 2
const CrawlLinks = 100
const CrawlBytes = 8 << 20
const CrawlRequests = 30
const CrawlOutput = 1 << 20
const robotsBytes = 512 << 10
const crawlerAgent = "Judgment-Pack-Web"

var errScope = errors.New("web-outside-site")
var errRobots = errors.New("web-robots-blocked")
var errRequests = errors.New("web-request-limit")

type DiscoveryPage struct {
	URL    string `json:"url"`
	From   string `json:"from"`
	Depth  int    `json:"depth"`
	Status string `json:"status"`
	Title  string `json:"title"`
	Reason string `json:"reason"`
}
type Discovery struct {
	Version       int             `json:"version"`
	Seed          string          `json:"seed"`
	Origin        string          `json:"origin"`
	Pages         []DiscoveryPage `json:"pages"`
	StopReason    string          `json:"stopReason"`
	Bytes         int             `json:"bytes"`
	Requests      int             `json:"requests"`
	ExternalLinks int             `json:"externalLinks"`
	Limits        struct {
		Pages   int `json:"pages"`
		Depth   int `json:"depth"`
		Links   int `json:"links"`
		Bytes   int `json:"bytes"`
		Seconds int `json:"seconds"`
	} `json:"limits"`
}

// Discover walks public links on exactly one HTTPS origin. The result describes
// discovery, not text read by an assistant. Each later read uses the ordinary
// web source and therefore gets its own retained, independently verified record.
// Limits and network policy are fixed by this adapter, never model arguments.
func Discover(ctx context.Context, raw []byte) ([]byte, error) {
	return discover(ctx, raw, newFetcher(), 500*time.Millisecond)
}
func discover(ctx context.Context, raw []byte, f fetcher, delay time.Duration) ([]byte, error) {
	if len(raw) > 8192 {
		return nil, ErrRequest
	}
	canonical, err := canon.Canonicalize(raw, canon.RefuseNumbers)
	if err != nil {
		return nil, ErrRequest
	}
	var req map[string]any
	if json.Unmarshal(canonical, &req) != nil || len(req) != 1 {
		return nil, ErrRequest
	}
	seed, ok := req["url"].(string)
	if !ok {
		return nil, ErrRequest
	}
	u, err := admittedURL(seed)
	if err != nil {
		return nil, err
	}
	origin := webOrigin(u)
	started := time.Now()
	ctx, cancel := context.WithTimeout(ctx, Timeout)
	defer cancel()
	result := Discovery{Version: 1, Seed: seed, Origin: origin, Pages: []DiscoveryPage{{URL: seed, From: "", Depth: 0, Status: "pending"}}, StopReason: "finished"}
	result.Limits.Pages = CrawlPages
	result.Limits.Depth = CrawlDepth
	result.Limits.Links = CrawlLinks
	result.Limits.Bytes = CrawlBytes
	result.Limits.Seconds = int(Timeout / time.Second)
	remaining, requests := CrawlBytes, 0
	var last time.Time
	var group *robotstxt.Group
	before := func(ctx context.Context, target *url.URL) error {
		if webOrigin(target) != origin {
			return errScope
		}
		if requests >= CrawlRequests {
			return errRequests
		}
		if group != nil && !group.Test(robotsPath(target)) {
			return errRobots
		}
		if !last.IsZero() {
			timer := time.NewTimer(time.Until(last.Add(delay)))
			defer timer.Stop()
			select {
			case <-timer.C:
			case <-ctx.Done():
				return ctx.Err()
			}
		}
		requests++
		last = time.Now()
		return nil
	}
	robots, err := f.readWith(ctx, origin+"/robots.txt", readPolicy{before: before, maxBytes: robotsBytes, remaining: &remaining, robots: true})
	if err != nil {
		return nil, err
	}
	var robotsOK bool
	group, robotsOK = robotRules(robots)
	if robotsOK && group != nil && group.CrawlDelay > delay {
		delay = group.CrawlDelay
	}
	seen := map[string]bool{normalizedURL(u): true}
	attempts := 0
	linkLimit := false
	if !robotsOK {
		result.StopReason = "robots-unavailable"
	}
	for i := 0; i < len(result.Pages); i++ {
		row := &result.Pages[i]
		switch {
		case !robotsOK:
			row.Status = "blocked"
			row.Reason = "web-robots-unavailable"
			continue
		case row.Depth > CrawlDepth:
			row.Status = "skipped"
			row.Reason = "depth-limit"
			if result.StopReason == "finished" {
				result.StopReason = "depth-limit"
			}
			continue
		case ctx.Err() != nil:
			row.Status = "skipped"
			row.Reason = "time-limit"
			result.StopReason = "time-limit"
			continue
		case attempts >= CrawlPages:
			row.Status = "skipped"
			row.Reason = "page-limit"
			if result.StopReason == "finished" {
				result.StopReason = "page-limit"
			}
			continue
		case remaining <= 1:
			row.Status = "skipped"
			row.Reason = "byte-limit"
			result.StopReason = "byte-limit"
			continue
		}
		attempts++
		response, readErr := f.readWith(ctx, row.URL, readPolicy{before: before, maxBytes: MaxBytes, remaining: &remaining})
		if readErr != nil {
			if errors.Is(readErr, errRequests) {
				result.StopReason = "request-limit"
			}
			row.Status = "failed"
			row.Reason = readErr.Error()
			if errors.Is(readErr, errRobots) || errors.Is(readErr, errScope) {
				row.Status = "blocked"
			}
			if ctx.Err() != nil {
				row.Reason = "time-limit"
				result.StopReason = "time-limit"
			}
			if remaining <= 1 {
				result.StopReason = "byte-limit"
			}
			continue
		}
		row.Status = "discovered"
		final, _ := url.Parse(response.url)
		seen[normalizedURL(final)] = true
		links, title, parseErr := pageLinks(ctx, response.raw, response.media, final)
		if parseErr != nil {
			row.Status = "failed"
			row.Reason = ErrMedia.Error()
			continue
		}
		row.Title = title
		from, depth := row.URL, row.Depth+1
		if len(links) >= 1000 {
			linkLimit = true
		}
		for _, candidate := range links {
			target, parseErr := final.Parse(candidate)
			if parseErr != nil {
				continue
			}
			target.Fragment = ""
			target.RawFragment = ""
			raw := normalizedURL(target)
			target, parseErr = admittedURL(raw)
			if parseErr != nil {
				continue
			}
			if webOrigin(target) != origin {
				result.ExternalLinks++
				continue
			}
			if seen[raw] {
				continue
			}
			seen[raw] = true
			if !pageExtension(target.Path) {
				continue
			}
			if len(result.Pages) >= CrawlLinks {
				linkLimit = true
				continue
			}
			result.Pages = append(result.Pages, DiscoveryPage{URL: raw, From: from, Depth: depth, Status: "pending"})
		}
	}
	if result.StopReason == "finished" && linkLimit {
		result.StopReason = "link-limit"
	}
	result.Bytes = CrawlBytes - remaining
	result.Requests = requests
	if result.Bytes > CrawlBytes {
		result.Bytes = CrawlBytes
	}
	identity, err := document.OwnIdentity()
	if err != nil {
		return nil, ErrProcessing
	}
	identity.Name = "adapter-web"
	statement, _ := canon.EncodeJSON(map[string]any{"operation": "discover", "seed": seed, "origin": origin})
	// robots.txt is the initial HTTP observation establishing the crawl policy.
	// The signed result names every subsequently visited URL and its outcome.
	acquisition := map[string]any{"adapter": identity, "endpoint": origin + "/robots.txt", "statement": string(statement), "snapshot": digest(robots.raw), "peerIdentity": "tls:" + digest(robots.tls.PeerCertificates[0].Raw), "schema": nil, "upstreamToken": nil, "observedAt": started.UTC().Format("2006-01-02T15:04:05Z")}
	encoded, err := json.Marshal(result)
	if err != nil {
		return nil, ErrProcessing
	}
	var value any
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.UseNumber()
	if decoder.Decode(&value) != nil {
		return nil, ErrProcessing
	}
	out, err := canon.EncodeJSON(map[string]any{"acquisition": acquisition, "result": value})
	if err != nil {
		return nil, ErrProcessing
	}
	if len(out) > CrawlOutput {
		return nil, ErrLimit
	}
	return out, nil
}
func originHost(u *url.URL) string {
	host := strings.ToLower(u.Hostname())
	if strings.Contains(host, ":") {
		return "[" + host + "]"
	}
	return host
}
func robotsPath(u *url.URL) string {
	p := u.EscapedPath()
	if p == "" {
		p = "/"
	}
	return p + querySuffix(u)
}
func querySuffix(u *url.URL) string {
	if u.RawQuery != "" {
		return "?" + u.RawQuery
	}
	return ""
}
func webOrigin(u *url.URL) string { return "https://" + originHost(u) }
func normalizedURL(u *url.URL) string {
	copy := *u
	copy.Host = strings.ToLower(copy.Host)
	if copy.Port() == "443" {
		copy.Host = originHost(&copy)
	}
	if copy.Path == "" {
		copy.Path = "/"
	}
	return copy.String()
}
func pageExtension(p string) bool {
	switch strings.ToLower(path.Ext(p)) {
	case ".js", ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".webp", ".woff", ".woff2", ".zip", ".mp4", ".mp3":
		return false
	}
	return true
}
func pageLinks(ctx context.Context, raw []byte, media string, base *url.URL) ([]string, string, error) {
	if media != "text/html" {
		return nil, path.Base(base.Path), nil
	}
	if !utf8.Valid(raw) {
		return nil, "", ErrMedia
	}
	z := html.NewTokenizer(bytes.NewReader(raw))
	z.SetMaxBuf(MaxBytes)
	var links []string
	documentBase := base
	baseSet := false
	var title strings.Builder
	inTitle := false
	suppressed := ""
	depth := 0
	for {
		if ctx.Err() != nil {
			return nil, "", ctx.Err()
		}
		kind := z.Next()
		switch kind {
		case html.ErrorToken:
			if !errors.Is(z.Err(), io.EOF) {
				return nil, "", ErrMedia
			}
			name := strings.Join(strings.Fields(title.String()), " ")
			if len(name) > 220 {
				name = string([]rune(name)[:min(100, len([]rune(name)))])
			}
			for i, raw := range links {
				u, err := documentBase.Parse(raw)
				if err == nil {
					links[i] = u.String()
				}
			}
			return links, name, nil
		case html.StartTagToken, html.SelfClosingTagToken:
			token := z.Token()
			tag := token.Data
			if suppressed != "" {
				if tag == suppressed {
					depth++
				}
				continue
			}
			if tag == "script" || tag == "style" || tag == "template" || tag == "noscript" || tag == "svg" {
				if kind == html.StartTagToken || tag != "svg" {
					suppressed = tag
					depth = 1
				}
				continue
			}
			if tag == "title" {
				inTitle = true
			}
			if tag == "base" && !baseSet {
				for _, attr := range token.Attr {
					if attr.Key == "href" {
						baseSet = true
						if u, err := base.Parse(attr.Val); err == nil {
							documentBase = u
						}
						break
					}
				}
			}
			if tag == "a" || tag == "area" {
				for _, attr := range token.Attr {
					if attr.Key == "href" && len(attr.Val) <= 4096 && len(links) < 1000 {
						links = append(links, strings.TrimSpace(attr.Val))
					}
				}
			}
		case html.EndTagToken:
			tag, _ := z.TagName()
			if suppressed != "" {
				if string(tag) == suppressed {
					depth--
					if depth == 0 {
						suppressed = ""
					}
				}
				continue
			}
			if string(tag) == "title" {
				inTitle = false
			}
		case html.TextToken:
			if suppressed == "" && inTitle && title.Len() < 1024 {
				title.Write(z.Text())
			}
		}
	}
}

func robotRules(robots response) (*robotstxt.Group, bool) {
	if robots.status == 200 {
		if robots.media != "text/plain" || !utf8.Valid(robots.raw) {
			return nil, false
		}
		rules, err := robotstxt.FromBytes(robots.raw)
		if err != nil {
			return nil, false
		}
		return rules.FindGroup(crawlerAgent), true
	}
	return nil, robots.status >= 400 && robots.status < 500 && robots.status != 401 && robots.status != 403 && robots.status != 429
}
