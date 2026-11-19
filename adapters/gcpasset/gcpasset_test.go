package gcpasset

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"adapters/internal/canon"
	"adapters/internal/metadataclient"
)

var ctx = context.Background()

// resultOf is an envelope's result, canonical, and its acquisition.
func resultOf(t *testing.T, out []byte) (string, map[string]any) {
	t.Helper()
	var env struct {
		Acquisition map[string]any  `json:"acquisition"`
		Result      json.RawMessage `json:"result"`
	}
	if err := json.Unmarshal(out, &env); err != nil {
		t.Fatalf("the envelope: %v\n%s", err, out)
	}
	return canonical(t, string(env.Result)), env.Acquisition
}

func canonical(t *testing.T, text string) string {
	t.Helper()
	out, err := canon.Canonicalize([]byte(text), canon.CarryNumbersAsText)
	if err != nil {
		t.Fatalf("canonical: %v", err)
	}
	return string(out)
}

func refusal(t *testing.T, err error, reason string) *Refused {
	t.Helper()
	var r *Refused
	if !errors.As(err, &r) || r.Reason != reason {
		t.Fatalf("want a %s refusal, got %v", reason, err)
	}
	return r
}

// Decision 3, Amendment A2: two tokens, each of its one scope and each to
// its one use; cloud-platform is never requested; one list call per
// acquisition.
func TestTwoNarrowTokensEachToItsUse(t *testing.T) {
	f := newFake(t)
	cfg := f.config(t)
	if _, err := Acquire(ctx, cfg, resourceRequest()); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(f.scopes, []string{AssetScope, CheckScope}) {
		t.Fatalf("the scopes requested: %q", f.scopes)
	}
	for _, scope := range f.scopes {
		if scope == "https://www.googleapis.com/auth/cloud-platform" {
			t.Fatal("cloud-platform was requested")
		}
	}
	lists, checks := f.callsTo("/asset/"), f.callsTo("/rm/")
	if len(lists) != 1 || f.minted[lists[0].token] != AssetScope {
		t.Fatalf("one list call, with the cloudasset token: %+v", lists)
	}
	if len(checks) != 1 || f.minted[checks[0].token] != CheckScope {
		t.Fatalf("one testIamPermissions call, with the read-only token: %+v", checks)
	}
	if checks[0].path != "/rm/v3/"+testProject+":testIamPermissions" {
		t.Fatalf("the write check asks the project: %s", checks[0].path)
	}
	var asked struct{ Permissions []string }
	json.Unmarshal([]byte(checks[0].body), &asked)
	if !reflect.DeepEqual(asked.Permissions, writeList) {
		t.Fatalf("the write check asks the write list: %q", asked.Permissions)
	}
}

// Amendment A3, the metadata server: the Metadata-Flavor header sent and
// answered back; the scope read from the token-information endpoint, the
// metadata server's answer naming none.
func TestMetadataTokenSource(t *testing.T) {
	f := newFake(t)
	cfg := f.config(t)
	cfg.TokenSource, cfg.Credentials = TokenSourceMetadata, sealKeyFile(t)
	if _, err := Acquire(ctx, cfg, resourceRequest()); err != nil {
		t.Fatal(err)
	}
	if got := len(f.callsTo("/tokeninfo")); got != 2 {
		t.Fatalf("each token's scope read from the token-information endpoint: %d calls", got)
	}
	metadata := f.callsTo("/metadata/")
	if len(metadata) != 3 || !strings.HasSuffix(metadata[0].path, "/email") || metadata[1].query != "scopes="+url.QueryEscape(AssetScope) || metadata[2].query != "scopes="+url.QueryEscape(CheckScope) {
		t.Fatalf("the metadata server asked for the principal, then each token of its one scope: %+v", metadata)
	}
	// An answer on that address without Metadata-Flavor: Google is not
	// the metadata server's.
	g := newFake(t)
	g.metadataFlavor = ""
	cfg2 := cfg
	_, err := Acquire(ctx, cfg2, resourceRequest())
	var failure *TokenFailure
	if !errors.As(err, &failure) || failure.Kind != StatusTokenRefused || len(g.callsTo("/asset/")) != 0 {
		t.Fatalf("an answer without the flavor header: %v", err)
	}
	// A metadata platform's credentials file holds a sealKey of 32 bytes.
	short := filepath.Join(t.TempDir(), "short.json")
	os.WriteFile(short, []byte(`{"sealKey":"too-short"}`), 0o600)
	cfg2.Credentials = short
	if _, err := Acquire(ctx, cfg2, resourceRequest()); !errors.As(err, &failure) || failure.Kind != StatusNoCredential {
		t.Fatalf("a short sealKey: %v", err)
	}
}

// gateway #510: the metadata server is asked with the adapters' shared
// metadata client, at the link-local IP literal built in, as adapter-http's
// metadata token step asks it. A metadata server given by a name is refused
// before anything is dialed or resolved: no request reaches the stand-in,
// and no token is obtained.
func TestMetadataServerIsReachedByItsPinnedAddress(t *testing.T) {
	if endpoints.Metadata != metadataclient.Address {
		t.Fatalf("the metadata server is %q, not the pinned address", endpoints.Metadata)
	}
	f := newFake(t)
	cfg := f.config(t)
	cfg.TokenSource, cfg.Credentials = TokenSourceMetadata, sealKeyFile(t)
	if !strings.HasPrefix(f.metadata.URL, "http://127.0.0.1:") {
		t.Skipf("the stand-in is not on 127.0.0.1: %s", f.metadata.URL)
	}
	endpoints.Metadata = "http://localhost:" + strings.TrimPrefix(f.metadata.URL, "http://127.0.0.1:")
	_, err := ObtainSealed(ctx, cfg)
	var failure *TokenFailure
	if !errors.As(err, &failure) || failure.Kind != StatusNoCredential || err.Error() != "the metadata server could not be reached: no token was obtained" {
		t.Fatalf("a metadata server given by a name: %v", err)
	}
	if got := f.callsTo("/metadata/"); len(got) != 0 {
		t.Fatalf("a request reached the metadata server by its name: %+v", got)
	}
}

// Amendment A2: the scope the token was granted is the one requested, and
// nothing beyond it but the closed list of identity scopes.
func TestScopesHeldToTheOneRequested(t *testing.T) {
	cases := map[string]bool{
		AssetScope:             true,
		AssetScope + " openid": true,
		"email " + AssetScope + " https://www.googleapis.com/auth/userinfo.email": true,
		"":                            false,
		"   ":                         false,
		"openid email":                false,
		CheckScope:                    false,
		AssetScope + " " + CheckScope: false,
		AssetScope + " profile":       false,
		AssetScope + " https://www.googleapis.com/auth/cloud-platform":   false,
		AssetScope + " https://www.googleapis.com/auth/userinfo.profile": false,
		AssetScope + " OPENID": false,
	}
	for granted, want := range cases {
		if got := scopesHeld(granted, AssetScope); got != want {
			t.Errorf("scopesHeld(%q) = %v, want %v", granted, got, want)
		}
	}
	if len(identityScopes) != 3 {
		t.Fatalf("the identity-scope list is closed at three: %v", identityScopes)
	}
}

// credential-scope-unknown, failing closed: an answer that is absent,
// unreadable or holds no scopes is refused, and nothing is listed or
// checked with that token.
func TestScopeUnknownFailsClosed(t *testing.T) {
	cases := []struct {
		name      string
		member    func(string) any
		tokenInfo func(string) (int, string)
		infoCalls int
	}{
		{"a scope beyond the one requested", func(s string) any { return s + " https://www.googleapis.com/auth/cloud-platform" }, nil, 0},
		{"a scope off the identity list", func(s string) any { return s + " profile" }, nil, 0},
		{"a scope member that is not a string", func(string) any { return 5 }, nil, 0},
		{"an empty scope member", func(string) any { return "" }, nil, 0},
		{"no scope member, the endpoint failing", func(string) any { return omitScope }, func(string) (int, string) { return 500, `{}` }, 1},
		{"no scope member, the endpoint naming none", func(string) any { return omitScope }, func(string) (int, string) { return 200, `{"expires_in":3500}` }, 1},
		{"no scope member, the endpoint's scope not a string", func(string) any { return omitScope }, func(string) (int, string) { return 200, `{"scope":["x"]}` }, 1},
		{"no scope member, the endpoint not JSON", func(string) any { return omitScope }, func(string) (int, string) { return 200, `scope=x` }, 1},
		{"no scope member, the endpoint naming another scope", func(string) any { return omitScope }, func(string) (int, string) { return 200, `{"scope":"` + CheckScope + `"}` }, 1},
		{"no scope member, the endpoint naming a member twice", func(string) any { return omitScope }, func(s string) (int, string) { return 200, `{"scope":"` + s + `","scope":"` + s + `"}` }, 1},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := newFake(t)
			f.scopeMember, f.tokenInfo = c.member, c.tokenInfo
			_, err := Acquire(ctx, f.config(t), resourceRequest())
			r := refusal(t, err, ReasonScopeUnknown)
			if r.Subject != nil || string(r.Report()) != `{"refused":{"reason":"credential-scope-unknown","subject":null}}` {
				t.Fatalf("the refusal names nothing: %s", r.Report())
			}
			if len(f.callsTo("/asset/")) != 0 || len(f.callsTo("/rm/")) != 0 || len(f.callsTo("/tokeninfo")) != c.infoCalls {
				t.Fatalf("nothing used the token: %+v", f.calls)
			}
		})
	}
	// The identity scopes beside the one requested are held.
	f := newFake(t)
	f.scopeMember = func(s string) any { return "openid " + s + " email" }
	if _, err := Acquire(ctx, f.config(t), resourceRequest()); err != nil {
		t.Fatalf("identity scopes beside the requested one: %v", err)
	}
}

// credential-can-write: a grant of any write permission on any configured
// project refuses, naming the first granted in the list's order, before
// anything is listed; a call the platform answers with anything but a
// grant or none refuses as a grant does.
func TestWriteCheckRefuses(t *testing.T) {
	f := newFake(t)
	f.granted[otherProject] = []string{"storage.buckets.delete", "run.services.update"}
	cfg := f.config(t)
	cfg.Parents = []string{testProject, otherProject}
	_, err := Acquire(ctx, cfg, resourceRequest())
	r := refusal(t, err, ReasonCanWrite)
	if r.Subject == nil || *r.Subject != "run.services.update" || err.Error() != "credential-can-write: run.services.update" {
		t.Fatalf("names the first granted in the list's order: %v", err)
	}
	if string(r.Report()) != `{"refused":{"reason":"credential-can-write","subject":"run.services.update"}}` {
		t.Fatalf("the report: %s", r.Report())
	}
	if len(f.callsTo("/asset/")) != 0 || len(f.callsTo("/rm/")) != 2 {
		t.Fatalf("both projects asked, nothing listed: %+v", f.calls)
	}
	failures := map[string]func([]string) (int, string){
		"a 500":                    func([]string) (int, string) { return 500, `{"error":{"status":"INTERNAL"}}` },
		"a 403":                    func([]string) (int, string) { return 403, `{"error":{"status":"PERMISSION_DENIED"}}` },
		"an answer not JSON":       func([]string) (int, string) { return 200, `permissions` },
		"a permission not asked":   func([]string) (int, string) { return 200, `{"permissions":["storage.objects.get"]}` },
		"permissions not an array": func([]string) (int, string) { return 200, `{"permissions":"run.services.update"}` },
		"a member named twice":     func([]string) (int, string) { return 200, `{"permissions":[],"permissions":[]}` },
		"an error served as 200":   func([]string) (int, string) { return 200, `{"error":{"status":"INTERNAL"}}` },
		"another member only":      func([]string) (int, string) { return 200, `{"x":1}` },
	}
	failures["a 403 of {}"] = func([]string) (int, string) { return 403, `{}` }
	failures["a 302 to an answer of {}"] = func([]string) (int, string) { return 302, `` }
	failures["{} not served as JSON"] = func([]string) (int, string) { return 200, `{}` }
	for name, answer := range failures {
		t.Run(name, func(t *testing.T) {
			f := newFake(t)
			f.permissionsAnswer = answer
			if name == "{} not served as JSON" {
				f.permissionsType = "text/plain"
			}
			_, err := Acquire(ctx, f.config(t), resourceRequest())
			r := refusal(t, err, ReasonCanWrite)
			if r.Subject != nil || !strings.Contains(err.Error(), "neither a grant nor none") || len(f.callsTo("/asset/")) != 0 {
				t.Fatalf("a failed call refuses, naming nothing: %v", err)
			}
		})
	}
}

// The platform takes at most 100 permissions in one call: a list longer
// than that is asked in consecutive calls of at most 100, every
// permission asked once, on every project.
func TestWriteCheckInCallsOfAtMost100(t *testing.T) {
	f := newFake(t)
	cfg := f.config(t)
	cfg.Parents = []string{testProject, otherProject}
	s, err := newSource(cfg)
	if err != nil {
		t.Fatal(err)
	}
	check, err := s.checked(ctx, CheckScope)
	if err != nil {
		t.Fatal(err)
	}
	long := make([]string, 250)
	for i := range long {
		long[i] = fmt.Sprintf("example.things.write%03d", i)
	}
	if err := s.writeCheck(ctx, check.value, long); err != nil {
		t.Fatal(err)
	}
	calls := f.callsTo("/rm/")
	if len(calls) != 6 {
		t.Fatalf("three calls per project: %d", len(calls))
	}
	// The projects are asked side by side, each project's calls in order.
	for _, project := range cfg.Parents {
		var asked []string
		var own []call
		for _, c := range calls {
			if strings.Contains(c.path, project+":") {
				own = append(own, c)
			}
		}
		if len(own) != 3 {
			t.Fatalf("three calls on %s: %d", project, len(own))
		}
		for i, want := range []int{100, 100, 50} {
			var body struct{ Permissions []string }
			json.Unmarshal([]byte(own[i].body), &body)
			if len(body.Permissions) != want {
				t.Fatalf("call %d on %s asks %d", i, project, len(body.Permissions))
			}
			asked = append(asked, body.Permissions...)
		}
		if !reflect.DeepEqual(asked, long) {
			t.Fatalf("every permission asked once, in order, on %s", project)
		}
	}
	// A grant in the last call refuses as one in the first does.
	f.granted[testProject] = []string{long[249], long[120]}
	if err := s.writeCheck(ctx, check.value, long); refusal(t, err, ReasonCanWrite).Subject == nil || *refusal(t, err, ReasonCanWrite).Subject != long[120] {
		t.Fatalf("a grant past the first call: %v", err)
	}
	if got := batches(writeList, maxPermissionsPerCall); len(got) != 1 || len(writeList) > maxPermissionsPerCall {
		t.Fatalf("the write list is one call today: %d", len(got))
	}
}

// The refresh re-check (decision 3, "When"): every token obtained is
// checked before it is used, so a grant made after the start refuses the
// next token, and nothing is sealed for it.
func TestEveryTokenObtainedIsChecked(t *testing.T) {
	f := newFake(t)
	cfg := f.config(t)
	if _, err := ObtainSealed(ctx, cfg); err != nil {
		t.Fatal(err)
	}
	if got := len(f.callsTo("/rm/")); got != 1 {
		t.Fatalf("the start's token checked: %d calls", got)
	}
	f.granted[testProject] = []string{"secretmanager.versions.add"}
	out, err := ObtainSealed(ctx, cfg)
	if r := refusal(t, err, ReasonCanWrite); out != nil || *r.Subject != "secretmanager.versions.add" {
		t.Fatalf("the refreshed token refused: %s %v", out, err)
	}
	if got := len(f.callsTo("/rm/")); got != 2 {
		t.Fatalf("the refresh's token checked: %d calls", got)
	}
	if _, err := Check(ctx, cfg); refusal(t, err, ReasonCanWrite) == nil {
		t.Fatal("the operator's check refuses as the start does")
	}
}

// A write check the run's time ended before it completed is not a
// refusal: nothing the platform answered shows the credential can write,
// so the gateway must not close the source on it under credential-can-write.
// It is not a pass either: no token is sealed, and an acquisition lists
// nothing. A token-information read the run's time ended is the same.
func TestACheckTheRunsTimeEndedIsNoRefusal(t *testing.T) {
	waitForTheCaller := func(r *http.Request) {
		select {
		case <-r.Context().Done():
		case <-time.After(10 * time.Second):
		}
	}
	// within is a run's time: long enough for both tokens to be obtained,
	// so what it ends is the check.
	within := func(t *testing.T, d time.Duration) context.Context {
		c, cancel := context.WithTimeout(ctx, d)
		t.Cleanup(cancel)
		return c
	}
	var r *Refused
	t.Run("the write check", func(t *testing.T) {
		f := newFake(t)
		f.beforePermissions = waitForTheCaller
		cfg := f.config(t)
		cfg.Parents = []string{testProject, otherProject}
		out, err := ObtainSealed(within(t, time.Second), cfg)
		if out != nil || errors.As(err, &r) || !errors.Is(err, errCheckIncomplete) {
			t.Fatalf("a token-only run: %s %v", out, err)
		}
		if _, err := Acquire(within(t, time.Second), cfg, resourceRequest()); errors.As(err, &r) || !errors.Is(err, errCheckIncomplete) || len(f.callsTo("/asset/")) != 0 {
			t.Fatalf("an acquisition: %v", err)
		}
		if _, err := Check(within(t, time.Second), cfg); errors.As(err, &r) || !errors.Is(err, errCheckIncomplete) {
			t.Fatalf("the operator's check: %v", err)
		}
	})
	t.Run("a grant answered in time", func(t *testing.T) {
		// A grant answered before the time ended refuses, whatever another
		// project's calls did.
		f := newFake(t)
		f.beforePermissions = func(r *http.Request) {
			if strings.Contains(r.URL.Path, otherProject+":") {
				waitForTheCaller(r)
			}
		}
		f.granted[testProject] = []string{"run.services.update"}
		cfg := f.config(t)
		cfg.Parents = []string{testProject, otherProject}
		if _, err := ObtainSealed(within(t, 3*time.Second), cfg); refusal(t, err, ReasonCanWrite).Subject == nil {
			t.Fatalf("a grant beside a check the time ended: %v", err)
		}
	})
	t.Run("the token-information read", func(t *testing.T) {
		f := newFake(t)
		f.tokenInfo = func(string) (int, string) { time.Sleep(2 * time.Second); return 200, `{}` }
		cfg := f.config(t)
		cfg.TokenSource, cfg.Credentials = TokenSourceMetadata, sealKeyFile(t)
		if _, err := ObtainSealed(within(t, time.Second), cfg); errors.As(err, &r) || !errors.Is(err, errCheckIncomplete) {
			t.Fatalf("a token-information read the run's time ended: %v", err)
		}
	})
}

// A call that brought back no answer -- the request's own time ended, or
// the connection was dropped -- leaves the check incomplete, as the run's
// time ending does: no refusal, so nothing closes the source, and no token
// is sealed. Only an answer refuses: a status other than 200 still does,
// and a grant one call answered still refuses beside a call that had none.
func TestACheckThePlatformDidNotAnswerIsNoRefusal(t *testing.T) {
	saved := requestTimeout
	requestTimeout = 300 * time.Millisecond
	t.Cleanup(func() { requestTimeout = saved })
	var r *Refused
	incomplete := func(t *testing.T, err error) {
		t.Helper()
		if errors.As(err, &r) || !errors.Is(err, errCheckIncomplete) {
			t.Fatalf("an incomplete check, and no refusal: %v", err)
		}
	}
	drop := func([]string) (int, string) { panic(http.ErrAbortHandler) }
	t.Run("the request's time ended", func(t *testing.T) {
		f := newFake(t)
		f.beforePermissions = func(r *http.Request) {
			select {
			case <-r.Context().Done():
			case <-time.After(5 * time.Second):
			}
		}
		began := time.Now()
		out, err := ObtainSealed(ctx, f.config(t))
		if out != nil {
			t.Fatalf("nothing sealed: %s", out)
		}
		incomplete(t, err)
		if waited := time.Since(began); waited > 3*time.Second {
			t.Fatalf("ended by the request's time, not by the platform: %v", waited)
		}
	})
	t.Run("the connection was dropped", func(t *testing.T) {
		f := newFake(t)
		f.permissionsAnswer = drop
		_, err := Acquire(ctx, f.config(t), resourceRequest())
		incomplete(t, err)
		if len(f.callsTo("/asset/")) != 0 {
			t.Fatalf("nothing listed: %+v", f.calls)
		}
	})
	t.Run("the token-information read's time ended", func(t *testing.T) {
		f := newFake(t)
		f.tokenInfo = func(string) (int, string) { time.Sleep(time.Second); return 200, `{}` }
		cfg := f.config(t)
		cfg.TokenSource, cfg.Credentials = TokenSourceMetadata, sealKeyFile(t)
		_, err := ObtainSealed(ctx, cfg)
		incomplete(t, err)
	})
	t.Run("a status is an answer", func(t *testing.T) {
		f := newFake(t)
		f.permissionsAnswer = func([]string) (int, string) { return 503, `{"error":{"status":"UNAVAILABLE"}}` }
		if _, err := ObtainSealed(ctx, f.config(t)); refusal(t, err, ReasonCanWrite).Subject != nil {
			t.Fatalf("a 503 refuses, naming nothing: %v", err)
		}
	})
	t.Run("a later project's grant beside an earlier one with no answer", func(t *testing.T) {
		// The project read first in the configured order brought back no
		// answer; one read after it grants, and that grant refuses.
		f := newFake(t)
		f.beforePermissions = func(r *http.Request) {
			if strings.Contains(r.URL.Path, otherProject+":") {
				panic(http.ErrAbortHandler)
			}
		}
		f.granted[testProject] = []string{"run.services.update"}
		cfg := f.config(t)
		cfg.Parents = []string{otherProject, testProject}
		out, err := ObtainSealed(ctx, cfg)
		if r := refusal(t, err, ReasonCanWrite); out != nil || r.Subject == nil || *r.Subject != "run.services.update" {
			t.Fatalf("the later project's grant refuses: %s %v", out, err)
		}
	})
	t.Run("a grant beside a call with no answer", func(t *testing.T) {
		f := newFake(t)
		s, err := newSource(f.config(t))
		if err != nil {
			t.Fatal(err)
		}
		check, err := s.checked(ctx, CheckScope)
		if err != nil {
			t.Fatal(err)
		}
		long := make([]string, 250)
		for i := range long {
			long[i] = fmt.Sprintf("example.things.write%03d", i)
		}
		f.permissionsAnswer = func(asked []string) (int, string) {
			switch {
			case asked[0] == long[0]:
				return drop(asked)
			case contains(asked, long[150]):
				return 200, `{"permissions":["` + long[150] + `"]}`
			}
			return 200, `{}`
		}
		err = s.writeCheck(ctx, check.value, long)
		if r := refusal(t, err, ReasonCanWrite); r.Subject == nil || *r.Subject != long[150] {
			t.Fatalf("the grant answered refuses: %v", err)
		}
	})
}

// The projects are asked side by side, at most maxConcurrentChecks at
// once, so the most a configuration names is checked in a few round trips.
func TestWriteCheckAsksProjectsSideBySide(t *testing.T) {
	f := newFake(t)
	var mu sync.Mutex
	inFlight, most := 0, 0
	f.beforePermissions = func(*http.Request) {
		mu.Lock()
		inFlight++
		most = max(most, inFlight)
		mu.Unlock()
		time.Sleep(50 * time.Millisecond)
		mu.Lock()
		inFlight--
		mu.Unlock()
	}
	cfg := f.config(t)
	cfg.Parents = nil
	for i := range maxParents {
		cfg.Parents = append(cfg.Parents, fmt.Sprintf("projects/example-project-%d", i+1))
	}
	if _, err := ObtainSealed(ctx, cfg); err != nil {
		t.Fatal(err)
	}
	if got := len(f.callsTo("/rm/")); got != maxParents {
		t.Fatalf("every project asked once: %d", got)
	}
	if most < 2 || most > maxConcurrentChecks {
		t.Fatalf("projects asked at once: %d, want 2 to %d", most, maxConcurrentChecks)
	}
}

// A sealed token: an acquisition handed one lists with it and obtains
// nothing; one sealed under another configuration, or altered, is unusable.
func TestSealedToken(t *testing.T) {
	f := newFake(t)
	cfg := f.config(t)
	out, err := ObtainSealed(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	var answer struct {
		Sealed    string `json:"sealed"`
		ExpiresIn *int   `json:"expiresIn"`
	}
	if err := json.Unmarshal(out, &answer); err != nil || canon.ExactNames(out, &answer) != nil || answer.Sealed == "" || answer.ExpiresIn == nil || *answer.ExpiresIn != 3599 {
		t.Fatalf("the token-only answer: %s %v", out, err)
	}
	before := len(f.calls)
	cfg.SealedToken = answer.Sealed
	if _, err := Acquire(ctx, cfg, resourceRequest()); err != nil {
		t.Fatal(err)
	}
	if after := f.calls[before:]; len(after) != 1 || !strings.HasPrefix(after[0].path, "/asset/") {
		t.Fatalf("only the list call: %+v", after)
	}
	other := cfg
	other.Parents = []string{testProject, otherProject}
	var failure *TokenFailure
	if _, err := Acquire(ctx, other, resourceRequest()); !errors.As(err, &failure) || failure.Kind != StatusSealUnusable {
		t.Fatalf("sealed under other parents: %v", err)
	}
	altered := cfg
	altered.SealedToken = answer.Sealed[:len(answer.Sealed)-2] + "AA"
	if _, err := Acquire(ctx, altered, resourceRequest()); !errors.As(err, &failure) || failure.Kind != StatusSealUnusable {
		t.Fatalf("an altered seal: %v", err)
	}
	if strings.Contains(string(out), f.tokens()[0]) {
		t.Fatal("the sealed answer carries the token in the clear")
	}
}

// Decision 2: the 400 form, on a request that sent a page token, is the
// 410; the same form on a first page, and every other error on a later
// page, is the ordinary upstream error.
func TestExpiredPageToken(t *testing.T) {
	answer := func(status int, body string) func(*http.Request) (int, string) {
		return func(*http.Request) (int, string) { return status, body }
	}
	later := resourceRequest()
	later.PageToken = "page-1-token"
	cases := []struct {
		name    string
		req     Request
		page    func(*http.Request) (int, string)
		expired bool
	}{
		{"the form on a later page", later, answer(400, fixture(t, "expired-page-token.json")), true},
		{"the form on a first page", resourceRequest(), answer(400, fixture(t, "expired-page-token.json")), false},
		{"another field's violation", later, answer(400, fixture(t, "other-invalid-argument.json")), false},
		{"another status", later, answer(400, strings.Replace(fixture(t, "expired-page-token.json"), "INVALID_ARGUMENT", "FAILED_PRECONDITION", 1)), false},
		{"another detail type", later, answer(400, strings.Replace(fixture(t, "expired-page-token.json"), "google.rpc.BadRequest", "google.rpc.ErrorInfo", 1)), false},
		{"a 404 of the same body", later, answer(404, fixture(t, "expired-page-token.json")), false},
		{"a 500", later, answer(500, `{"error":{"status":"INTERNAL"}}`), false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := newFake(t)
			f.page = c.page
			_, err := Acquire(ctx, f.config(t), c.req)
			var expired *ReferenceExpired
			if errors.As(err, &expired) != c.expired || err == nil {
				t.Fatalf("expired=%v: %v", c.expired, err)
			}
			if c.expired && string(expired.Report()) != `{"referenceExpired":{"status":410}}` {
				t.Fatalf("the report: %s", expired.Report())
			}
			var r *Refused
			if errors.As(err, &r) {
				t.Fatalf("an upstream error is no read-only refusal: %v", err)
			}
		})
	}
	// The form held by the fixture is the one SPEC.md §6 maps; a body
	// read as another content type is not.
	if !expiredPageToken(400, "application/json", []byte(fixture(t, "expired-page-token.json"))) || expiredPageToken(400, "text/plain", []byte(fixture(t, "expired-page-token.json"))) {
		t.Fatal("the mapped form")
	}
}

// Decision 2: one list call per acquisition, the page as the request names
// it, readTime the caller's, nextPageToken returned as written and never
// followed, null on the last page.
func TestPagingIsTheCallers(t *testing.T) {
	f := newFake(t)
	req := resourceRequest()
	req.PageToken, req.PageSize, req.ReadTime = "page-1-token", 50, "2026-11-16T12:00:00Z"
	out, err := Acquire(ctx, f.config(t), req)
	if err != nil {
		t.Fatal(err)
	}
	lists := f.callsTo("/asset/")
	if len(lists) != 1 {
		t.Fatalf("one list call: %d", len(lists))
	}
	query, _ := url.ParseQuery(lists[0].query)
	if lists[0].path != "/asset/v1/"+testProject+"/assets" || query.Get("pageToken") != "page-1-token" || query.Get("pageSize") != "50" ||
		query.Get("readTime") != req.ReadTime || query.Get("contentType") != ContentResource || !reflect.DeepEqual(query["assetTypes"], req.AssetTypes) {
		t.Fatalf("the list call: %s %s", lists[0].path, lists[0].query)
	}
	result, acquisition := resultOf(t, out)
	var page struct{ NextPageToken *string }
	json.Unmarshal([]byte(result), &page)
	if page.NextPageToken == nil || *page.NextPageToken != "page-2-token-as-written" {
		t.Fatalf("the next page token as written: %s", result)
	}
	if acquisition["snapshot"] != "2026-11-16T12:00:00.000000Z" || acquisition["endpoint"] != endpoints.Asset+"/v1/"+testProject+"/assets" {
		t.Fatalf("the snapshot is the page's readTime, the endpoint the URL without its query: %v", acquisition)
	}
	var stmt map[string]any
	json.Unmarshal([]byte(acquisition["statement"].(string)), &stmt)
	if stmt["pageToken"] != "page-1-token" || stmt["readTime"] != req.ReadTime || stmt["parent"] != testProject {
		t.Fatalf("the statement: %v", stmt)
	}
	// A first page sends no token, size or time of its own.
	g := newFake(t)
	if _, err := Acquire(ctx, g.config(t), resourceRequest()); err != nil {
		t.Fatal(err)
	}
	query, _ = url.ParseQuery(g.callsTo("/asset/")[0].query)
	for _, name := range []string{"pageToken", "pageSize", "readTime"} {
		if _, present := query[name]; present {
			t.Fatalf("a first page sends no %s", name)
		}
	}
	// An empty nextPageToken is the last page: null.
	h := newFake(t)
	h.page = func(*http.Request) (int, string) { return 200, fixture(t, "iam-policy-page.json") }
	iam := resourceRequest()
	iam.ContentType = ContentIAMPolicy
	out, err = Acquire(ctx, h.config(t), iam)
	if err != nil {
		t.Fatal(err)
	}
	if result, _ := resultOf(t, out); !strings.Contains(result, `"nextPageToken":null`) {
		t.Fatalf("the last page: %s", result)
	}
}

// Decision 3, "Parents first": a request naming a parent outside the set
// is refused before any credential is used or any call made.
func TestParentNotConfiguredBeforeAnyCall(t *testing.T) {
	f := newFake(t)
	req := resourceRequest()
	req.Parent = otherProject
	_, err := Acquire(ctx, f.config(t), req)
	var notConfigured *ParentNotConfigured
	if !errors.As(err, &notConfigured) || err.Error() != `parent-not-configured: "projects/example-project-2" is not a parent this source serves` {
		t.Fatalf("refused: %v", err)
	}
	if len(f.calls) != 0 {
		t.Fatalf("no call made: %+v", f.calls)
	}
	// The parent is held before the content type and the asset types.
	req.ContentType, req.AssetTypes = "ACCESS_POLICY", []string{"compute.googleapis.com/Instance"}
	if err := Admits(f.config(t), req); !errors.As(err, &notConfigured) {
		t.Fatalf("the parent first: %v", err)
	}
	for name, mutate := range map[string]func(*Request){
		"a content type not served": func(r *Request) { r.ContentType = "ORG_POLICY" },
		"an asset type not served":  func(r *Request) { r.AssetTypes = []string{"compute.googleapis.com/Instance"} },
		"an asset type twice": func(r *Request) {
			r.AssetTypes = []string{"storage.googleapis.com/Bucket", "storage.googleapis.com/Bucket"}
		},
	} {
		r := resourceRequest()
		mutate(&r)
		if err := Admits(f.config(t), r); err == nil || errors.As(err, &notConfigured) {
			t.Fatalf("%s: %v", name, err)
		}
	}
}

// Amendment A2: projects only, by identifier; a folder is refused by name.
func TestParentsAreProjectsOnly(t *testing.T) {
	for parent, want := range map[string]string{
		"projects/example-project-1":  "",
		"projects/abcdef":             "",
		"folders/200000000001":        "is a folder, and this version reads projects only",
		"projects/100000000001":       "is not projects/<project-id>",
		"organizations/1":             "is not projects/<project-id>",
		"projects/Example-Project":    "is not projects/<project-id>",
		"projects/ends-":              "is not projects/<project-id>",
		"projects/example-project-1/": "is not projects/<project-id>",
	} {
		err := ParentProblem(parent)
		if (want == "" && err != nil) || (want != "" && (err == nil || err.Error() != want)) {
			t.Errorf("ParentProblem(%q) = %v, want %q", parent, err, want)
		}
	}
	f := newFake(t)
	cfg := f.config(t)
	cfg.Parents = []string{testProject, "folders/200000000001"}
	if _, err := Acquire(ctx, cfg, resourceRequest()); err == nil || !strings.Contains(err.Error(), "folder") || len(f.calls) != 0 {
		t.Fatalf("a folder parent refused at start: %v", err)
	}
}

// Decision 4: one projection per asset type, held by the hand-written
// fixtures; no environment value is carried in any form.
func TestProjectionPerAssetType(t *testing.T) {
	for _, c := range []struct{ page, projected string }{
		{"resources-page.json", "resources-projected.json"},
		{"run-service-v1-page.json", "run-service-v1-projected.json"},
	} {
		t.Run(c.page, func(t *testing.T) {
			f := newFake(t)
			f.page = func(*http.Request) (int, string) { return 200, fixture(t, c.page) }
			out, err := Acquire(ctx, f.config(t), resourceRequest())
			if err != nil {
				t.Fatal(err)
			}
			result, _ := resultOf(t, out)
			if want := canonical(t, fixture(t, c.projected)); result != want {
				t.Fatalf("the projection:\n got %s\nwant %s", result, want)
			}
			for _, dropped := range []string{"plain-value-never-carried", "c2VjcmV0LXZhbHVlLW5ldmVyLWNhcnJpZWQ", "dropped", "annotations", "command"} {
				if bytes.Contains(out, []byte(dropped)) {
					t.Fatalf("the envelope carries %q", dropped)
				}
			}
		})
	}
	served := map[string]bool{}
	var page struct {
		Assets []struct{ AssetType string } `json:"assets"`
	}
	json.Unmarshal([]byte(fixture(t, "resources-page.json")), &page)
	for _, a := range page.Assets {
		served[a.AssetType] = true
	}
	for _, t2 := range ServedAssetTypes() {
		if !served[t2] {
			t.Fatalf("the fixture holds no %s, so its projection is not held", t2)
		}
	}
}

// Decision 5: IAM members as written by default; count-users replaces a
// binding's user members by their count.
func TestIAMMembers(t *testing.T) {
	for _, c := range []struct{ members, projected string }{
		{"", "iam-policy-projected.json"},
		{MembersCountUsers, "iam-policy-counted.json"},
	} {
		f := newFake(t)
		f.page = func(*http.Request) (int, string) { return 200, fixture(t, "iam-policy-page.json") }
		cfg := f.config(t)
		cfg.Members = c.members
		req := resourceRequest()
		req.ContentType = ContentIAMPolicy
		out, err := Acquire(ctx, cfg, req)
		if err != nil {
			t.Fatal(err)
		}
		if result, _ := resultOf(t, out); result != canonical(t, fixture(t, c.projected)) {
			t.Fatalf("members %q:\n got %s\nwant %s", c.members, result, canonical(t, fixture(t, c.projected)))
		}
	}
}

// credential-bound-at-resource: on an IAM_POLICY page, a binding of the
// source's own principal to a role outside the read-only list refuses,
// naming the asset; a custom role is never on the list.
func TestBoundAtResource(t *testing.T) {
	policy := func(role, member string) string {
		return `{"assets":[{"name":"//run.googleapis.com/projects/example-project-1/locations/europe-west1/services/orders","assetType":"run.googleapis.com/Service",` +
			`"iamPolicy":{"bindings":[{"role":"roles/run.viewer","members":["serviceAccount:` + testEmail + `"]},{"role":"` + role + `","members":["group:ops@example.com","` + member + `"]}]}}]}`
	}
	own := "serviceAccount:" + testEmail
	cases := []struct {
		name, role, member string
		refused            bool
	}{
		{"a write role", "roles/run.developer", own, true},
		{"an owner role", "roles/owner", own, true},
		{"the principal in another case", "roles/editor", "serviceAccount:Drift-Reader@Example-Project-1.iam.gserviceaccount.com", true},
		{"the principal identifier form", "roles/secretmanager.secretVersionAdder", "principal://iam.googleapis.com/projects/-/serviceAccounts/" + testEmail, true},
		{"a custom role named as a read-only one", "projects/example-project-1/roles/viewer", own, true},
		{"an organization's custom role", "organizations/100000000009/roles/cloudasset.viewer", own, true},
		{"a read-only role", "roles/secretmanager.viewer", own, false},
		{"another principal's write role", "roles/owner", "serviceAccount:orders-runtime@example-project-1.iam.gserviceaccount.com", false},
		// A role granted to every caller is one the credential holds there.
		{"a write role granted allUsers", "roles/run.developer", "allUsers", true},
		{"a write role granted allAuthenticatedUsers", "roles/secretmanager.secretVersionAdder", "allAuthenticatedUsers", true},
		{"allUsers in another case", "roles/storage.objectAdmin", "ALLUSERS", true},
		{"a read-only role granted allUsers", "roles/storage.objectViewer", "allUsers", false},
		// A group is not resolved (README, "Resource bindings").
		{"a group's write role", "roles/owner", "group:drift-readers@example.com", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := newFake(t)
			f.page = func(*http.Request) (int, string) { return 200, policy(c.role, c.member) }
			req := resourceRequest()
			req.ContentType = ContentIAMPolicy
			out, err := Acquire(ctx, f.config(t), req)
			if !c.refused {
				if err != nil {
					t.Fatal(err)
				}
				return
			}
			r := refusal(t, err, ReasonBoundAtResource)
			if out != nil || r.Subject == nil || *r.Subject != "//run.googleapis.com/projects/example-project-1/locations/europe-west1/services/orders" {
				t.Fatalf("names the asset: %v", err)
			}
		})
	}
	// A member named in another case is not read as the member: the
	// bindings read are the ones checked and carried.
	f0 := newFake(t)
	f0.page = func(*http.Request) (int, string) {
		return 200, `{"assets":[{"name":"//storage.googleapis.com/b","assetType":"storage.googleapis.com/Bucket","iamPolicy":{"bindings":[{"role":"roles/storage.admin","members":["` + own + `"]}],"Bindings":[]}}]}`
	}
	iamReq := resourceRequest()
	iamReq.ContentType = ContentIAMPolicy
	if _, err := Acquire(ctx, f0.config(t), iamReq); refusal(t, err, ReasonBoundAtResource) == nil {
		t.Fatal("a case-variant member hid a binding")
	}
	// The check holds for the principal a sealed token carries, the
	// metadata server's.
	f := newFake(t)
	f.page = func(*http.Request) (int, string) { return 200, policy("roles/editor", own) }
	cfg := f.config(t)
	cfg.TokenSource, cfg.Credentials = TokenSourceMetadata, sealKeyFile(t)
	sealed, err := ObtainSealed(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	var answer struct{ Sealed string }
	json.Unmarshal(sealed, &answer)
	cfg.SealedToken = answer.Sealed
	req := resourceRequest()
	req.ContentType = ContentIAMPolicy
	if _, err := Acquire(ctx, cfg, req); refusal(t, err, ReasonBoundAtResource) == nil {
		t.Fatal("the metadata principal's binding")
	}
	for _, role := range ReadOnlyRoles() {
		if !strings.HasPrefix(role, "roles/") {
			t.Fatalf("the read-only list holds predefined roles only: %s", role)
		}
	}
}

// Decision 3, "Never the token": no refusal, diagnostic, report or
// envelope carries a token, its digest or any part of it.
func TestTheTokenIsNeverNamed(t *testing.T) {
	var texts []string
	var tokens []string
	collect := func(f *fake, out []byte, err error) {
		texts = append(texts, string(out))
		if err != nil {
			texts = append(texts, err.Error())
			var r *Refused
			if errors.As(err, &r) {
				texts = append(texts, string(r.Report()))
			}
		}
		tokens = append(tokens, f.tokens()...)
	}
	iam := resourceRequest()
	iam.ContentType = ContentIAMPolicy
	later := resourceRequest()
	later.PageToken = "page-1-token"
	runs := []struct {
		name  string
		setup func(*fake)
		req   Request
	}{
		{"served", func(*fake) {}, resourceRequest()},
		{"scope unknown", func(f *fake) { f.scopeMember = func(s string) any { return s + " profile" } }, resourceRequest()},
		{"can write", func(f *fake) { f.granted[testProject] = []string{"iam.serviceAccountKeys.create"} }, resourceRequest()},
		{"check failed", func(f *fake) {
			f.permissionsAnswer = func([]string) (int, string) { return 500, `{}` }
		}, resourceRequest()},
		{"bound at resource", func(f *fake) {
			f.page = func(*http.Request) (int, string) {
				return 200, `{"assets":[{"name":"//storage.googleapis.com/b","assetType":"storage.googleapis.com/Bucket","iamPolicy":{"bindings":[{"role":"roles/storage.admin","members":["serviceAccount:` + testEmail + `"]}]}}]}`
			}
		}, iam},
		{"expired", func(f *fake) {
			f.page = func(*http.Request) (int, string) { return 400, fixture(t, "expired-page-token.json") }
		}, later},
		{"an error answer quoting the token", func(f *fake) {
			f.page = func(r *http.Request) (int, string) {
				return 400, `{"error":{"status":"INVALID_ARGUMENT","message":"` + r.Header.Get("Authorization") + `"}}`
			}
		}, resourceRequest()},
		{"an answer repeating the token", func(f *fake) {
			f.page = func(r *http.Request) (int, string) {
				return 200, `{"assets":[{"name":"` + strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ") + `","assetType":"storage.googleapis.com/Bucket"}]}`
			}
		}, resourceRequest()},
	}
	for _, run := range runs {
		f := newFake(t)
		run.setup(f)
		out, err := Acquire(ctx, f.config(t), run.req)
		collect(f, out, err)
		report, err := Check(ctx, f.config(t))
		collect(f, report, err)
		sealed, err := ObtainSealed(ctx, f.config(t))
		if err != nil {
			collect(f, nil, err)
		}
		_ = sealed
	}
	if len(tokens) < 10 {
		t.Fatalf("tokens were minted: %d", len(tokens))
	}
	all := strings.Join(texts, "\n")
	for _, token := range tokens {
		sum := sha256.Sum256([]byte(token))
		if strings.Contains(all, hex.EncodeToString(sum[:])) {
			t.Fatal("a token's digest is carried")
		}
		random := strings.TrimPrefix(token, "ya29.test-")
		for i := 0; i+12 <= len(random); i++ {
			if strings.Contains(all, random[i:i+12]) {
				t.Fatalf("part of a token is carried: %q", random[i:i+12])
			}
		}
	}
}

// The answer is bounded before it is decoded, and refused, not
// truncated, past its bounds.
func TestAnswerBounds(t *testing.T) {
	deep := `{"assets":[{"name":"a","assetType":"storage.googleapis.com/Bucket","resource":{"data":` + strings.Repeat("[", 70) + strings.Repeat("]", 70) + `}}]}`
	cases := map[string]struct {
		body        string
		contentType string
		maxAnswer   int64
	}{
		"past the answer bound":       {fixture(t, "resources-page.json"), "", 1024},
		"nested past the bound":       {deep, "", 0},
		"a member named twice":        {`{"assets":[],"assets":[]}`, "", 0},
		"an asset type not requested": {`{"assets":[{"name":"a","assetType":"compute.googleapis.com/Instance"}]}`, "", 0},
		"assets not an array":         {`{"assets":{}}`, "", 0},
		"not JSON":                    {`<html>`, "", 0},
		"a text answer":               {`{"assets":[]}`, "text/plain", 0},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			f := newFake(t)
			f.page = func(*http.Request) (int, string) { return 200, c.body }
			cfg := f.config(t)
			if c.maxAnswer > 0 {
				cfg.MaxAnswer = c.maxAnswer
			}
			f.listType = c.contentType
			if _, err := Acquire(ctx, cfg, resourceRequest()); err == nil {
				t.Fatal("served")
			}
		})
	}
	// A malformed policy refuses the page rather than passing the
	// resource-binding check by being unread.
	f := newFake(t)
	f.page = func(*http.Request) (int, string) {
		return 200, `{"assets":[{"name":"a","assetType":"storage.googleapis.com/Bucket","iamPolicy":{"bindings":[{"role":"roles/owner","members":"serviceAccount:` + testEmail + `"}]}}]}`
	}
	req := resourceRequest()
	req.ContentType = ContentIAMPolicy
	if _, err := Acquire(ctx, f.config(t), req); err == nil {
		t.Fatal("a malformed policy served")
	}
}

// The request is read strictly.
func TestParseRequest(t *testing.T) {
	good := `{"parent":"projects/example-project-1","contentType":"RESOURCE","assetTypes":["storage.googleapis.com/Bucket"],"pageToken":null,"pageSize":10,"readTime":"2026-11-16T12:00:00Z"}`
	req, err := ParseRequest(strings.NewReader(good))
	if err != nil || req.PageToken != "" || req.PageSize != 10 || req.ReadTime != "2026-11-16T12:00:00Z" {
		t.Fatalf("%+v %v", req, err)
	}
	for _, bad := range []string{
		`{"parent":"projects/example-project-1","contentType":"RESOURCE"}`,
		`{"parent":"projects/example-project-1","contentType":"RESOURCE","assetTypes":[],"pageSize":10}`,
		`{"parent":"projects/example-project-1","contentType":"RESOURCE","assetTypes":["a"],"query":"x"}`,
		`{"parent":"projects/example-project-1","parent":"projects/example-project-1","contentType":"RESOURCE","assetTypes":["a"]}`,
		`{"parent":"projects/example-project-1","contentType":"RESOURCE","assetTypes":["a"],"pageSize":1001}`,
		`{"parent":"projects/example-project-1","contentType":"RESOURCE","assetTypes":["a"],"pageSize":1.5}`,
		`{"parent":"projects/example-project-1","contentType":"RESOURCE","assetTypes":["a"],"pageToken":""}`,
		`{"parent":"projects/example-project-1","contentType":"RESOURCE","assetTypes":["a"],"pageToken":"has space"}`,
		`{"parent":"projects/example-project-1","contentType":"RESOURCE","assetTypes":["a"],"readTime":"yesterday"}`,
		`{"parent":7,"contentType":"RESOURCE","assetTypes":["a"]}`,
	} {
		if _, err := ParseRequest(strings.NewReader(bad)); err == nil {
			t.Errorf("read: %s", bad)
		}
	}
}
