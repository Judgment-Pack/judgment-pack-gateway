package main

// `gateway witness fetch`'s answers, read by a reader over an in-memory
// transport, the runtime stood in -- the probes of PR #242's cross-vendor
// review, adopted as regressions. A refusal of any read, the head or any
// statements page, the first or a later one, is quoted and credits nothing,
// the runtime not run; an answer outside its form -- a head that is not one
// statement line of SPEC.md §8.2's form among them -- leaves the reader what
// it holds under its pin, the answer said; a head of its form whose
// signature, key or trail is wrong is the runtime's to find, never a reason
// to fall back; and each witness named keeps a continuation of its own.

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
)

type answersTransport func(*http.Request) (*http.Response, error)

func (f answersTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// answer is one answer of the witness's.
func answer(status int, contentType, body string) *http.Response {
	return &http.Response{StatusCode: status, Header: http.Header{"Content-Type": {contentType}}, Body: io.NopCloser(strings.NewReader(body))}
}

// answersFixture is a witness signing under the corpus's test seed, read
// through a transport the test answers with, the runtime stood in.
type answersFixture struct {
	signer witnessSigner
	held   string // the statements the reader kept
	runs   [][]string
	mu     sync.Mutex
	urls   []string
}

func newAnswersFixture(t *testing.T, serve func(*http.Request) *http.Response) *answersFixture {
	t.Helper()
	f := &answersFixture{signer: newWitnessSigner(t)}
	lines, _ := f.signer.chain(1)
	f.held = filepath.Join(t.TempDir(), "held.jsonl")
	if err := os.WriteFile(f.held, file(lines...), 0o600); err != nil {
		t.Fatal(err)
	}
	previousHTTP, previousRuntime := witnessHTTP, witnessRuntime
	t.Cleanup(func() { witnessHTTP, witnessRuntime = previousHTTP, previousRuntime })
	witnessHTTP = &http.Client{Transport: answersTransport(func(r *http.Request) (*http.Response, error) {
		f.mu.Lock()
		f.urls = append(f.urls, r.URL.String())
		f.mu.Unlock()
		return serve(r), nil
	})}
	witnessRuntime = func(_ string, args []string) ([]byte, int, error) {
		f.runs = append(f.runs, args)
		return []byte(`{"standIn":true}`), 0, nil
	}
	return f
}

// read is the reading of the one witness, pinned, the reader holding what
// it kept.
func (f *answersFixture) read(t *testing.T, o witnessFetchOptions) witnessFetchReading {
	t.Helper()
	o.statements = []string{f.held}
	named := witnessTriple{Trail: testTrail, Origin: "https://w.example:443", KeyID: keyIDFor(f.signer.public)}
	got, err := readNamedWitness(o, named, []string{"T"}, [][]byte{f.signer.public}, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return got
}

// A refusal of a statements page -- the first, or one after a full page --
// ends the reading: quoted as the witness gave it, at the read it refused,
// nothing credited, and the runtime not run, though the reader holds a
// pinned key and statements it kept. So does a refusal of the head of any
// reason.
func TestWitnessFetchQuotesARefusalOfAnyRead(t *testing.T) {
	signer := newWitnessSigner(t)
	page, _ := signer.chain(seqs(witnessFetchPage)...)
	head := page[len(page)-1] + "\n"
	for _, tc := range []struct {
		name                 string
		serve                func(*http.Request) *http.Response
		at, reason, sentence string
		status               int
	}{
		{"a refusal of the first statements page", func(r *http.Request) *http.Response {
			if strings.HasSuffix(r.URL.Path, "/statements") {
				return answer(404, "application/json", `{"error":"the witness holds no statement for this trail","reason":"unknown-trail"}`)
			}
			return answer(200, "application/jsonl", head)
		}, "statements", "unknown-trail", sentenceRefused, 404},
		{"a refusal of a later statements page", func(r *http.Request) *http.Response {
			if strings.HasSuffix(r.URL.Path, "/statements") {
				if r.URL.Query().Get("from") == "0" {
					return answer(200, "application/jsonl", string(file(page...)))
				}
				return answer(503, "application/json", `{"error":"as many reads as the witness takes are in flight","reason":"busy"}`)
			}
			return answer(200, "application/jsonl", head)
		}, "statements", "busy", sentenceRefusedRead, 503},
		{"a refusal of the head of another reason", func(r *http.Request) *http.Response {
			return answer(503, "application/json", `{"error":"as many reads as the witness takes are in flight","reason":"busy"}`)
		}, "head", "busy", sentenceRefusedRead, 503},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newAnswersFixture(t, tc.serve)
			got := f.read(t, witnessFetchOptions{})
			if got.Outcome != fetchRefused || got.Refusal == nil || got.Refusal.At != tc.at || got.Refusal.Status != tc.status || got.Refusal.Reason != tc.reason ||
				got.Refusal.Error == "" || len(f.runs) != 0 || got.Exit != nil || !(len(got.Report) == 0 || string(got.Report) == "null") || got.Head || !slices.Contains(got.Sentences, tc.sentence) ||
				slices.Contains(got.Sentences, sentenceUnreachable) {
				t.Fatalf("%+v, refusal %+v, runs %d", got, got.Refusal, len(f.runs))
			}
		})
	}
}

func seqs(n int) []int64 {
	out := make([]int64, n)
	for i := range out {
		out[i] = int64(i + 1)
	}
	return out
}

// A head outside its form -- not JSON, two lines, a statement with a member
// the format does not define -- is an answer outside its form: the reader
// says so and reads what it holds under its pin, with no head. A head of its
// form whose signature, key or trail is wrong is handed to the runtime as
// it is, whose finding it is, and is never a reason to fall back. A
// statements page outside its form is the same as a head outside it.
func TestWitnessFetchHoldsTheHeadToItsForm(t *testing.T) {
	signer := newWitnessSigner(t)
	lines, _ := signer.chain(1)
	other, _ := signer.line(stmt{kind: "checkpoint", sequence: 1, trail: otherTrail, index: 0})
	// the signature with one hexadecimal character changed: of its form,
	// and verifying under no key
	at := strings.Index(lines[0], `"signature":"`) + len(`"signature":"`)
	flipped := lines[0][:at] + map[byte]string{'0': "1"}[lines[0][at]] + lines[0][at+1:]
	if lines[0][at] != '0' {
		flipped = lines[0][:at] + "0" + lines[0][at+1:]
	}
	for _, tc := range []struct {
		name, head, statements string
		fallback               bool
	}{
		{"a head that is not JSON", "not json\n", "", true},
		{"a head of two statement lines", lines[0] + "\n" + lines[0] + "\n", "", true},
		{"a head with no newline", lines[0], "", true},
		{"a head with a member the format does not define", strings.Replace(lines[0], `"index":0`, `"index":0,"extra":1`, 1) + "\n", "", true},
		{"a statements page outside its form", lines[0] + "\n", "{\"not\":\"a statement\"}\n", true},
		{"a head of its form with a signature that does not verify", flipped + "\n", "", false},
		{"a head of its form of another trail", other + "\n", "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newAnswersFixture(t, func(r *http.Request) *http.Response {
				if strings.HasSuffix(r.URL.Path, "/head") {
					return answer(200, "application/jsonl", tc.head)
				}
				body := string(file(lines...))
				if tc.statements != "" {
					body = tc.statements
				}
				return answer(200, "application/jsonl", body)
			})
			got := f.read(t, witnessFetchOptions{})
			if len(f.runs) != 1 {
				t.Fatalf("the runtime ran %d times: %+v", len(f.runs), got)
			}
			args := strings.Join(f.runs[0], " ")
			if tc.fallback {
				if got.Outcome != fetchNotOfForm || got.Head || strings.Contains(args, "--witness-head") || !strings.Contains(args, "--witness "+f.held) ||
					!slices.ContainsFunc(got.Sentences, func(s string) bool {
						return strings.HasPrefix(s, "The witness the receipts name answered outside its form (")
					}) {
					t.Fatalf("%+v\n%s", got, args)
				}
				return
			}
			if got.Outcome != fetchRead || !got.Head || !strings.Contains(args, "--witness-head") || strings.Contains(args, f.held) {
				t.Fatalf("a head of its form is the runtime's to read: %+v\n%s", got, args)
			}
		})
	}
}

// Each witness named keeps its own continuation, by {trail, origin,
// keyId}: two witnesses, after a change of witness, are saved to two files,
// each its own witness's, and each reading resumes from its own and fetches
// what follows it.
func TestWitnessFetchKeepsAContinuationForEachWitness(t *testing.T) {
	one := newWitnessSigner(t)
	seed := bytes.Repeat([]byte{23}, 32)
	twoPrivate := ed25519.NewKeyFromSeed(seed)
	two := witnessSigner{seed: seed, private: twoPrivate, public: twoPrivate.Public().(ed25519.PublicKey)}
	signerAt := map[string]witnessSigner{"a.example:443": one, "b.example:443": two}
	f := newAnswersFixture(t, func(r *http.Request) *http.Response {
		lines, _ := signerAt[r.URL.Host].chain(1)
		if strings.HasSuffix(r.URL.Path, "/statements") && r.URL.Query().Get("from") != "0" {
			return answer(200, "application/jsonl", "")
		}
		return answer(200, "application/jsonl", string(file(lines...)))
	})
	// The runtime saves, at the path it is handed, a continuation of the
	// witness whose key it was handed, and reports the continuation it was
	// handed to resume from.
	witnessRuntime = func(_ string, args []string) ([]byte, int, error) {
		f.runs = append(f.runs, args)
		key, err := readWitnessKeyFile(args[slices.Index(args, "--witness-key")+1])
		if err != nil {
			return nil, 0, err
		}
		s := one
		if bytes.Equal(key, two.public) {
			s = two
		}
		resumed := ""
		if at := slices.Index(args, "--witness-resume"); at >= 0 {
			data, _ := os.ReadFile(args[at+1])
			resumed = string(data)
		}
		if at := slices.Index(args, "--witness-save"); at >= 0 {
			lines, _ := s.chain(1)
			if err := os.WriteFile(args[at+1], []byte(`{"continuationVersion":"1","last":`+lines[0]+`,"latestCheckpoint":`+lines[0]+`}`), 0o600); err != nil {
				return nil, 0, err
			}
		}
		out, _ := json.Marshal(map[string]string{"resumed": resumed})
		return out, 0, nil
	}
	continuations := t.TempDir()
	named := []witnessTriple{
		{Trail: testTrail, Origin: "https://a.example:443", KeyID: keyIDFor(one.public)},
		{Trail: testTrail, Origin: "https://b.example:443", KeyID: keyIDFor(two.public)},
	}
	pins := [][]byte{one.public, two.public}
	readBoth := func(o witnessFetchOptions) []witnessFetchReading {
		var got []witnessFetchReading
		for _, w := range named {
			r, err := readNamedWitness(o, w, []string{"T"}, pins, t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			got = append(got, r)
		}
		return got
	}
	saved := readBoth(witnessFetchOptions{save: continuations})
	if saved[0].Continuation == "" || saved[0].Continuation == saved[1].Continuation {
		t.Fatalf("the two witnesses' continuations: %q and %q", saved[0].Continuation, saved[1].Continuation)
	}
	for i, w := range named {
		data, err := os.ReadFile(filepath.Join(continuations, saved[i].Continuation))
		var c struct {
			Last struct {
				KeyID string `json:"keyId"`
			} `json:"last"`
		}
		if err != nil || json.Unmarshal(data, &c) != nil || c.Last.KeyID != w.KeyID {
			t.Fatalf("witness %d's continuation holds %q, want its own %s (%v)", i, c.Last.KeyID, w.KeyID, err)
		}
	}
	f.urls = nil
	resumed := readBoth(witnessFetchOptions{resume: continuations, save: continuations})
	for i, w := range named {
		var report struct {
			Resumed string `json:"resumed"`
		}
		json.Unmarshal(resumed[i].Report, &report)
		if !strings.Contains(report.Resumed, `"keyId":"`+w.KeyID+`"`) || resumed[i].Continuation != saved[i].Continuation {
			t.Fatalf("witness %d resumed from %q", i, report.Resumed)
		}
		if want := fmt.Sprintf("https://%s/witness/trails/%s/statements?from=1&limit=%d", strings.TrimPrefix(w.Origin, "https://"), testTrail, witnessFetchPage); !slices.Contains(f.urls, want) {
			t.Fatalf("witness %d did not fetch after its own continuation: %v", i, f.urls)
		}
	}
	// a witness with no continuation of its own yet reads from index 0
	third := witnessTriple{Trail: testTrail, Origin: "https://a.example:443", KeyID: keyIDFor(one.public)}
	third.Trail = otherTrail
	f.urls = nil
	if _, err := readNamedWitness(witnessFetchOptions{resume: continuations}, third, nil, pins, t.TempDir()); err != nil {
		t.Fatal(err)
	}
	if !slices.ContainsFunc(f.urls, func(u string) bool { return strings.Contains(u, "statements?from=0") }) || slices.Contains(f.runs[len(f.runs)-1], "--witness-resume") {
		t.Fatalf("a witness with no continuation: %v %v", f.urls, f.runs[len(f.runs)-1])
	}
}
