//go:build linux || darwin

package connections

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"
)

type deadlineTransport func(*http.Request) (*http.Response, error)

func (f deadlineTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestSearchTimeoutSettingIsDurableValidatedAndUsed(t *testing.T) {
	for _, seconds := range []int{0, 10, 75, 120} {
		t.Run(strconv.Itoa(seconds)+"s", func(t *testing.T) {
			s, b, c := searchFixture(t)
			c.TimeoutSeconds = seconds
			raw, _ := json.Marshal(c)
			if _, err := b.Handle(context.Background(), "configure", raw); err != nil {
				t.Fatal(err)
			}
			var saved SearchConnection
			s.locked(func(v *state) error { saved = v.Search.Connections[0]; return nil })
			if saved.TimeoutSeconds != seconds || saved.Revision == c.Revision {
				t.Fatal("timeout not saved under a new revision")
			}
			status, err := b.Handle(context.Background(), "status", []byte(`{}`))
			if err != nil {
				t.Fatal(err)
			}
			encoded, _ := json.Marshal(status)
			var exposed struct {
				Connections []SearchConnection
				Timeout     struct{ DefaultSeconds, MinSeconds, MaxSeconds int }
			}
			json.Unmarshal(encoded, &exposed)
			if exposed.Timeout.DefaultSeconds != 45 || exposed.Timeout.MaxSeconds != 120 || exposed.Connections[0].TimeoutSeconds != seconds || exposed.Connections[0].Credential != "" {
				t.Fatal("unsafe or missing timeout status")
			}
			calls := 0
			p := googleProvider()
			p.client = &http.Client{Transport: deadlineTransport(func(req *http.Request) (*http.Response, error) {
				calls++
				deadline, ok := req.Context().Deadline()
				remaining := time.Until(deadline)
				want := seconds
				if want == 0 {
					want = 45
				}
				if !ok || remaining > time.Duration(want)*time.Second || remaining < time.Duration(want)*time.Second-time.Second {
					t.Error("configured deadline not applied", remaining)
				}
				return nil, context.DeadlineExceeded
			})}
			_, err = searchAcquire(context.Background(), s, SearchRequest{saved.ID, saved.Revision, "public documentation", 1}, p)
			if err != Error("search-timeout") || calls != 1 {
				t.Fatal("timeout misclassified or retried", err, calls)
			}
			s.locked(func(v *state) error {
				if v.Search.Connections[0].Requests != 1 {
					t.Error("failed request not metered")
				}
				return nil
			})
		})
	}
	for _, seconds := range []int{-1, 1, 9, 121, 10000} {
		_, b, c := searchFixture(t)
		c.TimeoutSeconds = seconds
		raw, _ := json.Marshal(c)
		if _, err := b.Handle(context.Background(), "configure", raw); err != ErrRequest {
			t.Fatal("out of range timeout accepted", seconds, err)
		}
	}
}
func TestCallerCanCancelBeforeSearchTimeout(t *testing.T) {
	s, _, c := searchFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Millisecond)
	defer cancel()
	p := googleProvider()
	p.client = &http.Client{Transport: deadlineTransport(func(req *http.Request) (*http.Response, error) {
		<-req.Context().Done()
		return nil, req.Context().Err()
	})}
	start := time.Now()
	_, err := searchAcquire(ctx, s, SearchRequest{c.ID, c.Revision, "query", 1}, p)
	if err != Error("search-timeout") || time.Since(start) > time.Second {
		t.Fatal("caller deadline was not honored", err)
	}
}

// The plan gives web-search the long envelope only while a search connection
// has a timeout the ordinary one does not carry; otherwise it is main's.
func TestThePlanGivesSearchTheLongEnvelopeOnlyWhenATimeoutNeedsIt(t *testing.T) {
	for _, processing := range []bool{false, true} {
		short, long := ConnectionLocalPlanFor(processing, false), ConnectionLocalPlanFor(processing, true)
		a, _ := json.Marshal(short)
		b, _ := json.Marshal(ConnectionLocalPlanWith(processing))
		if string(a) != string(b) {
			t.Fatal("the plan without the long search envelope changed")
		}
		for i, s := range long.Sources {
			was, _ := json.Marshal(short.Sources[i])
			now, _ := json.Marshal(s)
			if s.ID != "web-search" {
				if string(was) != string(now) {
					t.Errorf("%s changed with the long search envelope", s.ID)
				}
				continue
			}
			if s.Timeout != 130 || strings.Join(s.Args, " ") != "--provider web-search --principal desk-local --long-search" || !s.Connections {
				t.Errorf("web-search = %+v", s)
			}
		}
	}
	if raw, _ := json.Marshal(ConnectionLocalPlanFor(false, false)); string(raw) != mainLocalPlan {
		t.Fatal("the ordinary plan is not main's")
	}
	if SearchAdapterTimeout+5*time.Second > SearchSourceSeconds*time.Second || SearchMaxTimeoutSeconds*time.Second+5*time.Second > SearchAdapterTimeout || (SearchShortEnvelopeSeconds+5)*time.Second > 55*time.Second {
		t.Fatal("a search deadline does not fit its envelope")
	}
}

// The plan reads the search connections as they stand, writing nothing; only
// a timeout over the ordinary envelope's asks for the long one.
func TestSearchNeedsLongEnvelopeReadsWithoutWriting(t *testing.T) {
	empty := t.TempDir()
	os.Chmod(empty, 0700)
	for _, dir := range []string{"", "relative", empty} {
		if SearchNeedsLongEnvelope(dir) {
			t.Fatalf("%q needs the long envelope", dir)
		}
	}
	if entries, _ := os.ReadDir(empty); len(entries) != 0 {
		t.Fatal("the plan created custody")
	}
	dir := t.TempDir()
	os.Chmod(dir, 0700)
	s, err := OpenSearchStore(dir, "desk-local")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	b := NewSearch(s, false)
	defer b.Close()
	c := SearchConnection{ID: "demo", Name: "Demo", Provider: "tavily", DailyLimit: 10, Credential: "tvly-test-private-key"}
	for _, seconds := range []int{0, 45, 50, 51, 120} {
		if c.Revision != "" {
			s.locked(func(v *state) error { c.Revision = v.Search.Connections[0].Revision; return nil })
		}
		c.TimeoutSeconds = seconds
		raw, _ := json.Marshal(c)
		if _, err = b.Handle(context.Background(), "configure", raw); err != nil {
			t.Fatal(seconds, err)
		}
		c.Revision, c.Credential = "set", ""
		before := tree(t, dir)
		if got := SearchNeedsLongEnvelope(dir); got != (seconds > 50) || tree(t, dir) != before {
			t.Fatalf("a timeout of %d s reads as needing the long envelope: %v, or the read wrote", seconds, got)
		}
	}
}

// tamperedSearch stores a connection with a 90-second timeout, then puts the
// stored value in its place, as a hand edit or damage would.
func tamperedSearch(t *testing.T, stored string) (string, *Store, *Broker) {
	t.Helper()
	dir := t.TempDir()
	os.Chmod(dir, 0700)
	s, err := OpenSearchStore(dir, "desk-local")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	b := NewSearch(s, false)
	t.Cleanup(b.Close)
	raw, _ := json.Marshal(SearchConnection{ID: "demo", Name: "Demo", Provider: "tavily", DailyLimit: 10, Credential: "tvly-test-private-key", TimeoutSeconds: 90})
	if _, err = b.Handle(context.Background(), "configure", raw); err != nil {
		t.Fatal(err)
	}
	if !SearchNeedsLongEnvelope(dir) {
		t.Fatal("a valid 90-second timeout does not ask for the long envelope")
	}
	held, err := s.read("state.json")
	if err != nil || !strings.Contains(string(held), `"timeoutSeconds":90`) {
		t.Fatal("no stored timeout to tamper with", err)
	}
	if err = s.write("state.json", json.RawMessage(strings.Replace(string(held), `"timeoutSeconds":90`, `"timeoutSeconds":`+stored, 1))); err != nil {
		t.Fatal(err)
	}
	return dir, s, b
}

// A stored timeout configure would refuse is neither used to choose the
// plan's envelope nor echoed by status, which reports it as invalid.
func TestATamperedStoredTimeoutIsNeitherPlannedNorEchoed(t *testing.T) {
	for _, stored := range []string{"121", "10000", "-1", `"90"`, "90.5"} {
		dir, _, b := tamperedSearch(t, stored)
		if SearchNeedsLongEnvelope(dir) {
			t.Errorf("a stored %s chose the long envelope", stored)
		}
		status, err := b.Handle(context.Background(), "status", []byte(`{}`))
		if stored == `"90"` || stored == "90.5" {
			// Not an integer at all: the state does not decode, as any
			// damaged state does not, and status says it cannot be read.
			if err != ErrStorage {
				t.Errorf("a stored %s: status %v", stored, err)
			}
			continue
		}
		encoded, _ := json.Marshal(status)
		if err != nil || !strings.Contains(string(encoded), `"timeoutSeconds":-1`) || stored != "-1" && strings.Contains(string(encoded), `"timeoutSeconds":`+stored) {
			t.Errorf("a stored %s: status %s %v", stored, encoded, err)
		}
	}
}
