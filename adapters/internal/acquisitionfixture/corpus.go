//go:build gateway_acquisition_fixture

package acquisitionfixture

import (
	"encoding/json"
	"io"
	"net/http"
)

const CompanyURL = "https://" + PageHost + "/fixtures/company"
const PersonURL = "https://" + PageHost + "/fixtures/person"
const NoticeURL = "https://" + PageHost + "/fixtures/notice"

// These are invented fixture statements, not assertions about real entities.
const CompanyHTML = `<html><title>Synthetic company fixture</title><h1>Example Fixture Company</h1><p>Official website: https://example.com/fixtures/company</p><p>Location: Fixture City</p><p>Employee range: 10 to 20. Source date: 2026-01-01.</p><p>Public routing: https://example.com/fixtures/contact</p><script>Never retain executable page code.</script></html>`
const PersonHTML = `<html><title>Synthetic professional fixture</title><h1>Alex Fixture</h1><p>Company: Example Fixture Company</p><p>Professional role: Operations director</p><p>Professional biography: https://example.com/fixtures/person</p><p>Business contact page: https://example.com/fixtures/contact</p></html>`
const NoticeHTML = `<html><title>Synthetic procurement fixture</title><h1>Fixture supply notice</h1><p>Issuer: Example Fixture Company</p><p>Notice URL: https://example.com/fixtures/notice</p><p>Region: Fixture City</p><p>Published status: open</p><p>No deadline is stated.</p></html>`

func serve(w http.ResponseWriter, r *http.Request) {
	if r.Host == SearchHost && r.URL.Path == "/search" && r.Method == http.MethodPost && r.URL.RawQuery == "" {
		if r.Header.Get("Authorization") != "Bearer "+Credential {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		var request struct {
			Query      string `json:"query"`
			MaxResults int    `json:"max_results"`
		}
		raw, err := io.ReadAll(io.LimitReader(r.Body, (16<<10)+1))
		if err != nil || len(raw) > 16<<10 || json.Unmarshal(raw, &request) != nil || request.Query == "" || request.MaxResults < 1 || request.MaxResults > 10 {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"results":[{"title":"Synthetic company","url":"`+CompanyURL+`","content":"Example Fixture Company in Fixture City."},{"title":"Synthetic professional","url":"`+PersonURL+`","content":"Alex Fixture, Operations director."},{"title":"Synthetic notice","url":"`+NoticeURL+`","content":"Fixture supply notice, published open."}]}`)
		return
	}
	if r.Host != PageHost || r.Method != http.MethodGet || r.Header.Get("Authorization") != "" || r.Header.Get("Cookie") != "" {
		w.WriteHeader(http.StatusForbidden)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	switch r.URL.Path {
	case "/fixtures/company":
		_, _ = io.WriteString(w, CompanyHTML)
	case "/fixtures/person":
		_, _ = io.WriteString(w, PersonHTML)
	case "/fixtures/notice":
		_, _ = io.WriteString(w, NoticeHTML)
	case "/fixtures/start":
		w.Header().Set("Set-Cookie", "fixture-cookie=must-not-follow")
		http.Redirect(w, r, "/fixtures/company?view=full", http.StatusFound)
	case "/fixtures/leave-scope":
		http.Redirect(w, r, "/outside/company?view=full", http.StatusFound)
	case "/outside/company":
		_, _ = io.WriteString(w, CompanyHTML)
	case "/fixtures/private-redirect":
		http.Redirect(w, r, "https://127.0.0.1/private", http.StatusFound)
	case "/robots.txt":
		w.Header().Set("Content-Type", "text/plain")
		_, _ = io.WriteString(w, "User-agent: *\nAllow: /fixtures/\nDisallow: /outside/\n")
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}
