package main

import (
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
)

// delegationJournalHarness is the delegation harness served again with
// limits and the refusal journals of the filesystem kind on.
func delegationJournalHarness(t *testing.T) (*delegationHarness, *refusalJournals) {
	t.Helper()
	h := newDelegationHarness(t, false)
	cfg := refusalLimits()
	h.g.limits = cfg
	var err error
	if h.g.limiter, err = newRequestLimiter((&fakeLimitClock{}).clock(), cfg.beforeScope, cfg.entries(limitScopeKeys(h.g.sources))); err != nil {
		t.Fatal(err)
	}
	if err := h.g.openRefusalJournals(&refusalJournalConfig{maxBytes: refusalDefaultCap}, &refusalStderr{}); err != nil {
		t.Fatal(err)
	}
	h.g.refusals.start()
	t.Cleanup(h.g.refusals.stop)
	h.server.Close()
	h.server = httptest.NewServer(h.g.handler())
	t.Cleanup(h.server.Close)
	return h, h.g.refusals
}

// journaledCalls is each journal's entries as "route reason tool digest",
// "-" for a member the entry does not have.
func journaledCalls(t *testing.T, h *delegationHarness, j *refusalJournals) []string {
	t.Helper()
	j.stop()
	var got []string
	for key := range limitScopeKeys(h.g.sources) {
		for _, b := range refusalBodies(t, h.g.storeRoot, key) {
			line := []string{}
			for _, name := range []string{"route", "reason", "tool", "descriptorDigest"} {
				v, ok := memberString(b, name)
				if !ok {
					v = "-"
				}
				line = append(line, v)
			}
			got = append(got, strings.Join(line, " "))
		}
	}
	return got
}

// A refusal entry names the tool once the route resolved it to one its
// source's configuration names, and the tool's descriptor digest only
// where the operation pins a snapshot (ADR-0059's amendment): on /acquire
// and on /act, before resolution neither, after it the tool, with a pinned
// snapshot both.
func TestRefusalJournalNamesTheResolvedToolAndItsPinnedDigest(t *testing.T) {
	h, j := delegationJournalHarness(t)
	cred := h.credential(t, statement(t, nil))
	refuse := func(map[string]any) (int, string) {
		return http.StatusOK, `{"admission":"refuse","refusal":"tool-version-refused"}`
	}
	expect := func(path, body string, status int) {
		t.Helper()
		if got, out := h.present(t, path, body, cred); got != status {
			t.Fatalf("%s %s: %d %v", path, body, got, out)
		}
	}
	// before resolution: a member no route reads, and a platform none names
	expect("/acquire", `{"session":"s-r0","source":"tickets/live","bogus":true}`, http.StatusBadRequest)
	expect("/act", strings.Replace(h.actBody("s-r0", delegationKey(60), ""), `"platform":"tickets"`, `"platform":"nowhere"`, 1), http.StatusBadRequest)
	// after it, unpinned: the admission refuses the resolved tool
	h.host.setAnswer(refuse)
	expect("/acquire", h.acquireBody("s-r1", "query"), http.StatusForbidden)
	expect("/act", h.actBody("s-r1", delegationKey(61), ""), http.StatusForbidden)
	// a tool no configuration names is not a resolved one
	expect("/acquire", h.acquireBody("s-r2", "not-configured"), http.StatusForbidden)
	// pinned: each operation's own digest
	live, write := h.g.sources["tickets/live"], h.g.sources["tickets/write"]
	live.versions = map[string]string{"query": testToolDigest}
	write.versions = map[string]string{"query": testWriteDigest}
	h.g.sources["tickets/live"], h.g.sources["tickets/write"] = live, write
	expect("/acquire", h.acquireBody("s-r3", "query"), http.StatusForbidden)
	expect("/act", h.actBody("s-r3", delegationKey(62), ""), http.StatusForbidden)
	h.host.setAnswer(nil)

	// an entry is handed off after its answer is flushed, so a later
	// request's entry may be queued first: the entries, not their order
	calls := journaledCalls(t, h, j)
	slices.Sort(calls)
	got := strings.Join(calls, "\n")
	wantCalls := []string{
		"/acquire body - -",
		"/act platform - -",
		"/acquire delegation query -",
		"/act delegation query -",
		"/acquire delegation - -",
		"/acquire delegation query " + testToolDigest,
		"/act delegation query " + testWriteDigest,
	}
	slices.Sort(wantCalls)
	want := strings.Join(wantCalls, "\n")
	if got != want {
		t.Fatalf("journaled:\n%s\nwant\n%s", got, want)
	}
}

// An entry naming a descriptor digest and no tool, or a tool of "", is not
// of its form, whoever signed it (both readers; the corpus holds the
// vector).
func TestRefusalJournalReaderRefusesADigestWithoutItsTool(t *testing.T) {
	hexOf := strings.Repeat("ab", 32)
	body := func(edit func(*vObject)) *vObject {
		caller := newObject()
		caller.set("issuer", vString("https://issuer.test"))
		caller.set("subject", vString("caller-a"))
		caller.set("tokenDigest", vString("sha256:"+hexOf))
		b := newObject()
		for _, m := range [][2]string{{"kind", "refusal"}, {"scope", callerScopeA}, {"route", "/act"}, {"reason", "decision"}} {
			b.set(m[0], vString(m[1]))
		}
		b.set("status", vInt(403))
		b.set("answeredAt", vString("2026-09-12T00:00:02.000Z"))
		b.set("caller", caller)
		b.set("nonce", vString(hexOf))
		b.set("request", vString("sha256:"+hexOf))
		edit(b)
		return b
	}
	journal := refusalJournalName(callerScopeA)
	for name, edit := range map[string]func(*vObject){
		"neither":    func(*vObject) {},
		"the tool":   func(b *vObject) { b.set("tool", vString("query")) },
		"and digest": func(b *vObject) { b.set("tool", vString("query")); b.set("descriptorDigest", vString(testToolDigest)) },
	} {
		if _, ok := refusalBodyLoads(body(edit), journal); !ok {
			t.Errorf("%s: refused", name)
		}
	}
	for name, edit := range map[string]func(*vObject){
		"a digest and no tool": func(b *vObject) { b.set("descriptorDigest", vString(testToolDigest)) },
		"a tool of \"\"":       func(b *vObject) { b.set("tool", vString("")) },
		"a digest not of its form": func(b *vObject) {
			b.set("tool", vString("query"))
			b.set("descriptorDigest", vString("query"))
		},
		"a tool not a string": func(b *vObject) { b.set("tool", vInt(1)) },
	} {
		if _, ok := refusalBodyLoads(body(edit), journal); ok {
			t.Errorf("%s: read as of its form", name)
		}
	}
}
