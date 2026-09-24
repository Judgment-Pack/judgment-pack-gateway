package websource

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"
)

func discoveryResult(t *testing.T, raw []byte, f fetcher) Discovery {
	t.Helper()
	out, err := discover(context.Background(), raw, f, 0)
	if err != nil {
		t.Fatal(err)
	}
	var envelope struct{ Result Discovery }
	if json.Unmarshal(out, &envelope) != nil {
		t.Fatal("bad output")
	}
	return envelope.Result
}
func TestDiscoverScopeRobotsAndDepth(t *testing.T) {
	requested := []string{}
	f := fixture(t, func(w http.ResponseWriter, r *http.Request) {
		requested = append(requested, r.URL.Path)
		if r.Header.Get("Cookie") != "" || r.Header.Get("Authorization") != "" {
			t.Error("credentials sent")
		}
		if r.URL.Path == "/robots.txt" {
			w.Header().Set("Content-Type", "text/plain")
			w.Write([]byte("User-agent: *\nDisallow: /private\n"))
			return
		}
		w.Header().Set("Content-Type", "text/html")
		switch r.URL.Path {
		case "/":
			w.Write([]byte(`<title>Home</title><a href="/child#one">child</a><a href="/child#two">duplicate</a><a href="/private">private</a><a href="https://external.example/secret">offsite</a><script><a href="/script">bad</a></script><a href="/offsite-redirect">redirect</a><a href="/private-redirect">redirect</a>`))
		case "/child":
			w.Write([]byte(`<title>Child</title><a href="/grandchild">next</a>`))
		case "/grandchild":
			w.Write([]byte(`<a href="/too-deep">next</a>`))
		case "/offsite-redirect":
			http.Redirect(w, r, "https://external.example/target", 302)
		case "/private-redirect":
			http.Redirect(w, r, "/private/final", 302)
		default:
			t.Errorf("unexpected request %s", r.URL.Path)
		}
	})
	result := discoveryResult(t, []byte(`{"url":"https://example.com/"}`), f)
	statuses := map[string]string{}
	for _, row := range result.Pages {
		statuses[row.URL] = row.Status
	}
	if statuses["https://example.com/child"] != "discovered" || statuses["https://example.com/grandchild"] != "discovered" || statuses["https://example.com/private"] != "blocked" || statuses["https://example.com/too-deep"] != "skipped" || statuses["https://example.com/offsite-redirect"] != "blocked" || statuses["https://example.com/private-redirect"] != "blocked" {
		t.Fatal(result)
	}
	if strings.Contains(strings.Join(requested, ","), "private/final") || strings.Contains(strings.Join(requested, ","), "too-deep") {
		t.Fatal(requested)
	}
	if result.ExternalLinks != 1 || result.Requests != len(requested) {
		t.Fatal(result)
	}
}
func TestDiscoverPageAndLinkBudget(t *testing.T) {
	reads := 0
	f := fixture(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/robots.txt" {
			w.WriteHeader(404)
			return
		}
		reads++
		w.Header().Set("Content-Type", "text/html")
		var page strings.Builder
		page.WriteString("<title>Page</title>")
		for i := 0; i < 120; i++ {
			fmt.Fprintf(&page, `<a href="/item?i=%d">item</a>`, i)
		}
		w.Write([]byte(page.String()))
	})
	result := discoveryResult(t, []byte(`{"url":"https://example.com/"}`), f)
	if reads != CrawlPages || len(result.Pages) > CrawlLinks || result.StopReason != "page-limit" {
		t.Fatal(reads, len(result.Pages), result.StopReason)
	}
}
func TestDiscoverUnavailableRobotsNeverFetchesContent(t *testing.T) {
	for _, status := range []int{401, 403, 429, 500} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			f := fixture(t, func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/robots.txt" {
					t.Error("fetched content")
				}
				w.WriteHeader(status)
			})
			result := discoveryResult(t, []byte(`{"url":"https://example.com/"}`), f)
			if result.StopReason != "robots-unavailable" || result.Pages[0].Status != "blocked" {
				t.Fatal(result)
			}
		})
	}
}
func TestDiscoverStrictRequestAndCancellation(t *testing.T) {
	for _, raw := range []string{`{"URL":"https://example.com/"}`, `{"url":"https://example.com/","maxPages":999}`, `{"url":"https://example.com/","url":"https://example.com/"}`, `{"url":"https://127.0.0.1/"}`, `{"url":"https://example.com/#fragment"}`} {
		if _, err := discover(context.Background(), []byte(raw), newFetcher(), 0); err == nil {
			t.Fatal("admitted", raw)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := discover(ctx, []byte(`{"url":"https://example.com/"}`), newFetcher(), 0); err == nil {
		t.Fatal("canceled discovery succeeded")
	}
}
func TestDiscoverCrawlDelayHonored(t *testing.T) {
	f := fixture(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/robots.txt" {
			w.Header().Set("Content-Type", "text/plain")
			w.Write([]byte("User-agent: Judgment-Pack-Web\nCrawl-delay: 20\n"))
			return
		}
		t.Error("fetch before delay")
	})
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	out, err := discover(ctx, []byte(`{"url":"https://example.com/"}`), f, 0)
	if err != nil {
		return
	}
	var e struct{ Result Discovery }
	json.Unmarshal(out, &e)
	if e.Result.StopReason != "time-limit" {
		t.Fatal(string(out))
	}
}

func TestDiscoverBaseAndRootRobots(t *testing.T) {
	f := fixture(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		switch r.URL.Path {
		case "/robots.txt":
			w.Header().Set("Content-Type", "text/plain")
			w.Write([]byte("User-agent: *\nDisallow: /blocked\n"))
		case "/":
			w.Write([]byte(`<base href="/docs/"><a href="policy">Policy</a><base href="https://other.example/"><a href="/blocked">Blocked</a>`))
		case "/docs/policy":
			w.Write([]byte(`<title>Policy</title>`))
		default:
			t.Errorf("unexpected %s", r.URL.Path)
		}
	})
	result := discoveryResult(t, []byte(`{"url":"https://example.com"}`), f)
	if len(result.Pages) != 3 || result.Pages[1].URL != "https://example.com/docs/policy" || result.Pages[2].Status != "blocked" {
		t.Fatal(result)
	}
}
func TestDiscoverByteBudgetIncludesFailedBodies(t *testing.T) {
	f := fixture(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/robots.txt" {
			w.WriteHeader(404)
			return
		}
		w.Header().Set("Content-Type", "text/html")
		if r.URL.Path == "/" {
			w.Write([]byte(`<a href="/large">large</a><a href="/larger">large</a><a href="/last">last</a>`))
			return
		}
		w.(http.Flusher).Flush() // unknown length exercises the overflow probe
		w.Write([]byte(strings.Repeat("x", MaxBytes)))
	})
	result := discoveryResult(t, []byte(`{"url":"https://example.com/"}`), f)
	if result.Bytes > CrawlBytes || result.StopReason != "byte-limit" || result.Pages[len(result.Pages)-1].Status != "skipped" {
		t.Fatal(result.Bytes, result.StopReason, result.Pages)
	}
}
func TestScopedReadRejectsRedirectAndRobotsBeforeFetch(t *testing.T) {
	for _, target := range []string{"https://elsewhere.example/secret", "https://example.com/blocked"} {
		t.Run(target, func(t *testing.T) {
			f := fixture(t, func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/robots.txt":
					w.Header().Set("Content-Type", "text/plain")
					w.Write([]byte("User-agent: *\nDisallow: /blocked\n"))
				case "/start":
					http.Redirect(w, r, target, 302)
				default:
					t.Errorf("forbidden fetch %s", r.URL)
				}
			})
			_, err := read(context.Background(), []byte(`{"url":"https://example.com/start","site":"https://example.com/"}`), f)
			if err == nil {
				t.Fatal("scoped redirect accepted")
			}
		})
	}
	f := fixture(t, func(w http.ResponseWriter, r *http.Request) { t.Error("must refuse before network") })
	for _, raw := range []string{`{"url":"https://elsewhere.example/","site":"https://example.com/"}`, `{"url":"https://example.com/","site":""}`, `{"url":"https://example.com/","Site":"https://example.com/"}`, `{"url":"https://example.com/","site":null}`} {
		if _, err := read(context.Background(), []byte(raw), f); err == nil {
			t.Fatal(raw)
		}
	}
}
