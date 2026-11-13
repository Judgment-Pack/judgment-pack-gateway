package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// tokenBinding is an http live operation sending its credential as the
// bearer, which a token step's access token takes the place of.
const tokenBinding = `{"bindingVersion":"1","platform":"records","operations":{"live":{"shape":"http","endpoint":"https://records.example","paths":["/records"],"methods":["GET"],"bearer":"API_TOKEN","licence":"Apache-2.0"}}}`

// tokenPlatformJSON is an http platform's entry with a live credentials
// file and step, ",\"tokenStep\":{...}" or nothing, beside it.
func tokenPlatformJSON(t *testing.T, name, ref, user, step, extra string) string {
	t.Helper()
	return `"` + name + `":{"binding":"` + ref + `","credentials":{"live":{"file":"` + abs(t, t.TempDir(), name+"-live.json") + `"` + step + `}},"user":"` + user + `"` + extra + `}`
}

// atVersion is an engine configuration of the given version.
func atVersion(t *testing.T, version, catalog, extra, platforms string) string {
	t.Helper()
	return strings.Replace(engineJSON(t, catalog, extra, platforms), `"engineVersion":"1"`, `"engineVersion":"`+version+`"`, 1)
}

// A token step is a version-21 member of an http live operation's
// credentials, and of nothing else: not of history, not of write, not of
// a live operation of another shape or one sending its credential under a
// header. Each of its members is held to its form, and a refusal repeats
// no value it was given.
func TestTokenStepIsAVersion21MemberOfTheLiveCredentials(t *testing.T) {
	header := strings.Replace(tokenBinding, `"bearer":"API_TOKEN"`, `"credentialHeader":"X-Key=API_TOKEN"`, 1)
	catalog := catalogWith(t, map[string]string{"records": tokenBinding, "postgres": postgresBinding})
	headerCatalog := catalogWith(t, map[string]string{"records": header})
	ref := "records@" + digestOf(tokenBinding)
	pg := "postgres@" + digestOf(postgresBinding)
	s256 := base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	sha1 := base64.RawURLEncoding.EncodeToString(make([]byte, 20))
	federated := abs(t, t.TempDir(), "federated.jwt")
	good := `"endpoint":"https://login.example/oauth2/token","clientId":"client-7","privateKey":"SIGNING_KEY"`
	step := func(members string) string { return `,"tokenStep":{` + members + `}` }
	records := func(members, extra string) string {
		return tokenPlatformJSON(t, "records", ref, "engine-docs", step(members), extra)
	}
	warehouse := func(op, write string) string {
		credentials := ""
		for i, each := range []string{"history", "live", "write"} {
			if each == "write" && write == "" {
				continue
			}
			if i > 0 {
				credentials += ","
			}
			credentials += `"` + each + `":{"file":"` + abs(t, t.TempDir(), each+".json") + `"`
			if each == op {
				credentials += step(good)
			}
			credentials += `}`
		}
		return `"warehouse":{"binding":"` + pg + `","credentials":{` + credentials + `},"user":"engine-warehouse"` + write + `}`
	}
	for _, ok := range []struct{ name, text string }{
		{"a key with a SHA-256 thumbprint and a scope", atVersion(t, "21", catalog, ``, records(good+`,"x5t#S256":"`+s256+`","requestScope":"records.read records.list"`, ``))},
		{"a key with a SHA-1 thumbprint", atVersion(t, "21", catalog, ``, records(good+`,"x5t":"`+sha1+`"`, ``))},
		{"a federated token", atVersion(t, "21", catalog, ``, records(`"endpoint":"https://login.example/token","clientId":"client-7","federatedTokenFile":"`+federated+`"`, ``))},
		{"a token endpoint over http at a loopback address", atVersion(t, "21", catalog, ``, records(`"endpoint":"http://127.0.0.1:8400/token","clientId":"client-7","privateKey":"SIGNING_KEY"`, ``))},
	} {
		if _, sources, err := load(t, ok.text); err != nil || !sources["records/live"].tokenStep {
			t.Fatalf("%s loads: %v", ok.name, err)
		}
	}
	// Without a token step, the variable the sealed token is handed in is
	// the platform's to set, as every other.
	if _, _, err := load(t, atVersion(t, "21", catalog, ``, tokenPlatformJSON(t, "records", ref, "engine-docs", ``, `,"environment":{"ADAPTER_HTTP_SEALED_TOKEN":"x"}`))); err != nil {
		t.Fatalf("a platform with no token step sets any variable: %v", err)
	}
	cases := []struct{ name, text, want string }{
		{"version 20", atVersion(t, "20", catalog, ``, records(good, ``)), "credentials.live.tokenStep is a version-21 member; engineVersion 20 has no tokenStep"},
		{"under history", atVersion(t, "21", catalog, ``, warehouse("history", ``)), "a token step is taken by a live operation of the http shape alone"},
		{"under write", atVersion(t, "21", catalog, ``, warehouse("write", `,"write":true`)), "credentials.write.tokenStep: a token step is taken by a live operation of the http shape alone"},
		{"a live operation of the MCP shape", atVersion(t, "21", catalog, ``, warehouse("live", ``)), "binding postgres@" + digestOf(postgresBinding) + "'s live operation is not of the http shape"},
		{"a binding sending a credential header", atVersion(t, "21", headerCatalog, ``, tokenPlatformJSON(t, "records", "records@"+digestOf(header), "engine-docs", step(good), ``)), "sends its credential under credentialHeader"},
		{"not an object", atVersion(t, "21", catalog, ``, tokenPlatformJSON(t, "records", ref, "engine-docs", `,"tokenStep":"https://login.example/token"`, ``)), "tokenStep"},
		{"an unknown member", atVersion(t, "21", catalog, ``, records(good+`,"audience":"x"`, ``)), `unknown member "audience"`},
		{"no clientId", atVersion(t, "21", catalog, ``, records(`"endpoint":"https://login.example/token","privateKey":"SIGNING_KEY"`, ``)), `missing member "clientId"`},
		{"an endpoint over http off loopback", atVersion(t, "21", catalog, ``, records(`"endpoint":"http://login.example/token","clientId":"client-7","privateKey":"SIGNING_KEY"`, ``)), "endpoint must be"},
		{"an endpoint of another scheme", atVersion(t, "21", catalog, ``, records(`"endpoint":"ftp://login.example/token","clientId":"client-7","privateKey":"SIGNING_KEY"`, ``)), "endpoint must be"},
		{"an endpoint with a placeholder", atVersion(t, "21", catalog, ``, records(`"endpoint":"https://login.example/{realm}/token","clientId":"client-7","privateKey":"SIGNING_KEY"`, ``)), "names no placeholder"},
		{"a clientId with a space", atVersion(t, "21", catalog, ``, records(`"endpoint":"https://login.example/token","clientId":"client 7","privateKey":"SIGNING_KEY"`, ``)), "clientId is 1 to 256 printable ASCII characters"},
		{"an empty clientId", atVersion(t, "21", catalog, ``, records(`"endpoint":"https://login.example/token","clientId":"","privateKey":"SIGNING_KEY"`, ``)), "clientId is 1 to 256 printable ASCII characters"},
		{"a key and a federated token", atVersion(t, "21", catalog, ``, records(good+`,"federatedTokenFile":"`+federated+`"`, ``)), "exactly one of privateKey and federatedTokenFile"},
		{"neither a key nor a federated token", atVersion(t, "21", catalog, ``, records(`"endpoint":"https://login.example/token","clientId":"client-7"`, ``)), "exactly one of privateKey and federatedTokenFile"},
		{"an empty key member", atVersion(t, "21", catalog, ``, records(`"endpoint":"https://login.example/token","clientId":"client-7","privateKey":""`, ``)), "privateKey names the live credentials member"},
		{"a relative federated token file", atVersion(t, "21", catalog, ``, records(`"endpoint":"https://login.example/token","clientId":"client-7","federatedTokenFile":"federated.jwt"`, ``)), "federatedTokenFile must be an absolute path"},
		{"x5t of a SHA-256 size", atVersion(t, "21", catalog, ``, records(good+`,"x5t":"`+s256+`"`, ``)), "x5t is the base64url, unpadded, of a 20-byte thumbprint"},
		{"x5t#S256 padded", atVersion(t, "21", catalog, ``, records(good+`,"x5t#S256":"`+s256+`="`, ``)), "x5t#S256 is the base64url, unpadded, of a 32-byte thumbprint"},
		{"x5t#S256 in standard base64", atVersion(t, "21", catalog, ``, records(good+`,"x5t#S256":"`+strings.Repeat("+", 43)+`"`, ``)), "x5t#S256 is the base64url"},
		{"both thumbprints", atVersion(t, "21", catalog, ``, records(good+`,"x5t":"`+sha1+`","x5t#S256":"`+s256+`"`, ``)), "one of x5t and x5t#S256, not both"},
		{"a thumbprint beside a federated token", atVersion(t, "21", catalog, ``, records(`"endpoint":"https://login.example/token","clientId":"client-7","federatedTokenFile":"`+federated+`","x5t":"`+sha1+`"`, ``)), "beside privateKey"},
		{"a scope with two spaces", atVersion(t, "21", catalog, ``, records(good+`,"requestScope":"records.read  records.list"`, ``)), "requestScope is at most 1024 bytes of scope tokens"},
		{"an empty scope", atVersion(t, "21", catalog, ``, records(good+`,"requestScope":""`, ``)), "requestScope is at most 1024 bytes of scope tokens"},
		{"a scope with a quote", atVersion(t, "21", catalog, ``, records(good+`,"requestScope":"records\"read"`, ``)), "requestScope is at most 1024 bytes of scope tokens"},
		{"the sealed token's variable in environment", atVersion(t, "21", catalog, ``, records(good, `,"environment":{"ADAPTER_HTTP_SEALED_TOKEN":"x"}`)), "environment may not set ADAPTER_HTTP_SEALED_TOKEN"},
	}
	for _, c := range cases {
		_, _, err := load(t, c.text)
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Fatalf("%s: want %q, got %v", c.name, c.want, err)
		}
		if strings.Contains(err.Error(), "login.example") || strings.Contains(err.Error(), "client 7") {
			t.Fatalf("%s: the refusal repeats a value it was given: %v", c.name, err)
		}
	}
}

// The derived source carries the token step's flags in place of the
// binding's bearer, and a configuration without one derives the source it
// derived before the member existed, word for word, at either version.
func TestTokenStepIsDerivedInPlaceOfTheBearer(t *testing.T) {
	catalog := catalogWith(t, map[string]string{"records": tokenBinding})
	ref := "records@" + digestOf(tokenBinding)
	bin := abs(t, t.TempDir(), "bin")
	adapters := `,"adapters":"` + bin + `"`
	derive := func(version, platform string) sourceSpec {
		t.Helper()
		_, sources, err := load(t, atVersion(t, version, catalog, adapters, platform))
		if err != nil {
			t.Fatal(err)
		}
		return sources["records/live"]
	}
	plain := tokenPlatformJSON(t, "records", ref, "engine-docs", ``, ``)
	before, after := derive("20", plain), derive("21", plain)
	if !reflect.DeepEqual(before, after) || after.tokenStep || !slices.Contains(after.argv, "--bearer=API_TOKEN") {
		t.Fatalf("without a token step the source is as it was:\n%+v\n%+v", before, after)
	}
	for _, arg := range after.argv {
		for _, flag := range []string{"--token-", "--client-id", "--assertion-", "--federated-"} {
			if strings.HasPrefix(arg, flag) {
				t.Fatalf("a source with no token step carries %s", arg)
			}
		}
	}
	s256 := base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	keyed := derive("21", tokenPlatformJSON(t, "records", ref, "engine-docs",
		`,"tokenStep":{"endpoint":"https://login.example/token","clientId":"client-7","privateKey":"SIGNING_KEY","x5t#S256":"`+s256+`","requestScope":"records.read"}`, ``))
	var want []string
	for _, arg := range after.argv {
		if strings.HasPrefix(arg, "--credentials=") {
			arg = "--credentials=" + argumentValue(keyed.argv, "--credentials=")
		}
		if arg == "--bearer=API_TOKEN" {
			want = append(want, "--token-endpoint=https://login.example/token", "--client-id=client-7", "--assertion-key=SIGNING_KEY", "--assertion-x5t-s256="+s256, "--token-scope=records.read")
			continue
		}
		want = append(want, arg)
	}
	if !keyed.tokenStep || !slices.Equal(keyed.argv, want) {
		t.Fatalf("the token step's flags in place of the bearer:\n%q\n%q", keyed.argv, want)
	}
	federated := abs(t, t.TempDir(), "federated.jwt")
	byFile := derive("21", tokenPlatformJSON(t, "records", ref, "engine-docs",
		`,"tokenStep":{"endpoint":"https://login.example/token","clientId":"client-7","federatedTokenFile":"`+federated+`"}`, ``))
	if !slices.Contains(byFile.argv, "--federated-token-file="+strings.ReplaceAll(federated, `\\`, `\`)) || slices.ContainsFunc(byFile.argv, func(arg string) bool {
		return strings.HasPrefix(arg, "--bearer") || strings.HasPrefix(arg, "--assertion-")
	}) {
		t.Fatalf("a federated token step: %q", byFile.argv)
	}
}

// The signer holds one sealed token per source and scope, until the margin
// before its expiry; a token stating a lifetime no longer than the margin,
// or none, is used once; a token is dropped only when it is still the one
// held; a fetch that fails holds nothing.
func TestTokenCacheHoldsOneTokenPerSourceAndScope(t *testing.T) {
	now := time.Unix(1_000_000, 0)
	c := tokenCache{now: func() time.Time { return now }}
	fetches := 0
	next := func(lifetime int) func() (string, int, error) {
		return func() (string, int, error) {
			fetches++
			return fmt.Sprintf("sealed-%d", fetches), lifetime, nil
		}
	}
	obtain := func(key tokenKey, fetch func() (string, int, error), want string) {
		t.Helper()
		got, err := c.obtain(key, fetch)
		if err != nil || got != want {
			t.Fatalf("obtain %v: %q %v, want %q", key, got, err, want)
		}
	}
	records := tokenKey{source: "records/live"}
	obtain(records, next(600), "sealed-1")
	obtain(records, next(600), "sealed-1")
	now = now.Add(539 * time.Second)
	obtain(records, next(600), "sealed-1")
	now = now.Add(time.Second)
	obtain(records, next(600), "sealed-2")
	obtain(tokenKey{source: "records/live", scope: "region-a"}, next(600), "sealed-3")
	obtain(tokenKey{source: "docs/live"}, next(600), "sealed-4")
	obtain(records, next(600), "sealed-2")
	c.drop(records, "sealed-1")
	obtain(records, next(600), "sealed-2")
	c.drop(records, "sealed-2")
	obtain(records, next(600), "sealed-5")
	short := tokenKey{source: "short/live"}
	obtain(short, next(60), "sealed-6")
	obtain(short, next(60), "sealed-7")
	obtain(short, next(0), "sealed-8")
	obtain(short, next(0), "sealed-9")
	obtain(short, next(61), "sealed-10")
	obtain(short, next(61), "sealed-10")
	refused := errors.New("refused")
	now = now.Add(time.Hour)
	if _, err := c.obtain(records, func() (string, int, error) { return "", 0, refused }); !errors.Is(err, refused) {
		t.Fatalf("a failed fetch: %v", err)
	}
	obtain(records, next(600), "sealed-11")
}

// Concurrent acquisitions of one source wait for one token request and
// take what it obtained.
func TestTokenCacheObtainsOneTokenForConcurrentAcquisitions(t *testing.T) {
	var c tokenCache
	var fetches atomic.Int64
	release := make(chan struct{})
	key := tokenKey{source: "records/live"}
	got := make([]string, 16)
	var wg sync.WaitGroup
	for i := range got {
		wg.Add(1)
		go func() {
			defer wg.Done()
			got[i], _ = c.obtain(key, func() (string, int, error) {
				fetches.Add(1)
				<-release
				return "sealed-1", 600, nil
			})
		}()
	}
	for fetches.Load() == 0 {
		time.Sleep(time.Millisecond)
	}
	time.Sleep(100 * time.Millisecond)
	close(release)
	wg.Wait()
	if fetches.Load() != 1 || slices.ContainsFunc(got, func(s string) bool { return s != "sealed-1" }) {
		t.Fatalf("%d fetches for 16 acquisitions: %q", fetches.Load(), got)
	}
}

// A federated token is a credential as a credentials file is: owned by
// the platform's user, readable by that user alone, not a directory; the
// path the adapter is given is the one resolved. One owned by another
// platform's user -- a writing platform's -- is refused, so a token step
// never authenticates with another platform's credential.
func TestTokenStepFederatedTokenIsHeldAsACredentialsFile(t *testing.T) {
	sep := string(filepath.Separator)
	seed := filepath.Join(sep, "var", "lib", "engine", "gateway.seed")
	credentials := filepath.Join(sep, "run", "secrets", "records")
	federated := filepath.Join(sep, "run", "federated", "records.jwt")
	cfg := engineConfig{runtime: "docker", seed: seed, platforms: []platformConfig{
		{name: "records", credentials: map[string]string{"live": credentials}, user: "engine-docs", uid: 1002,
			tokenStep: &tokenStepConfig{endpoint: "https://login.example/token", clientID: "client-7", federatedTokenFile: federated}},
	}}
	three := uint64(1<<capSetuid | 1<<capSetgid | 1<<capKill)
	host := func(fs ownership) engineHost {
		return engineHost{euid: 1000, sockets: func(string) []string { return []string{filepath.Join(t.TempDir(), "absent.sock")} },
			capabilities: func() capabilitySets { return capabilitySets{known: true, effective: three, permitted: three} }, fileOwner: fs.owner, readLink: readLinkStub}
	}
	filesystem := func(edit func(ownership)) ownership {
		fs := goodFilesystem(seed, credentials, 1000, 1002)
		fs[filepath.Dir(federated)] = fileOwnership{uid: 0, mode: 0o755, dir: true}
		fs[federated] = fileOwnership{uid: 1002, mode: 0o600}
		if edit != nil {
			edit(fs)
		}
		return fs
	}
	held := ptr(cfg)
	if _, err := engineRefusals(held, host(filesystem(nil))); err != nil || held.platforms[0].tokenStep.federatedTokenFile != federated {
		t.Fatalf("a private federated token of the platform's user: %v", err)
	}
	for _, c := range []struct {
		name string
		edit func(ownership)
		want string
	}{
		{"absent", func(fs ownership) { delete(fs, federated) }, "tokenStep.federatedTokenFile"},
		{"owned by the signer", func(fs ownership) { fs[federated] = fileOwnership{uid: 1000, mode: 0o600} }, "must be owned by engine-docs"},
		{"owned by a writing platform's user", func(fs ownership) { fs[federated] = fileOwnership{uid: 1001, mode: 0o600} }, "must be owned by engine-docs"},
		{"readable beyond its owner", func(fs ownership) { fs[federated] = fileOwnership{uid: 1002, mode: 0o640} }, "readable beyond its owner (mode 0640)"},
		{"a directory", func(fs ownership) { fs[federated] = fileOwnership{uid: 1002, mode: 0o700, dir: true} }, "is a directory"},
		{"in a directory others may write", func(fs ownership) { fs[filepath.Dir(federated)] = fileOwnership{uid: 0, mode: 0o777, dir: true} }, "writable beyond its owner"},
	} {
		if _, err := engineRefusals(ptr(cfg), host(filesystem(c.edit))); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Fatalf("%s: want %q, got %v", c.name, c.want, err)
		}
	}
}

// tokenLog is a log a test reads while the service may write it.
type tokenLog struct {
	mu   sync.Mutex
	text strings.Builder
}

func (l *tokenLog) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.text.Write(p)
}

func (l *tokenLog) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.text.String()
}

// esAssertionHolds is whether a client assertion is an ES256 JWT the key
// signed, for the client, to the audience, with the thumbprint, unexpired.
func esAssertionHolds(assertion string, key *ecdsa.PublicKey, client, audience, thumbprint string) bool {
	parts := strings.Split(assertion, ".")
	if len(parts) != 3 {
		return false
	}
	var header, claims map[string]any
	for i, into := range []*map[string]any{&header, &claims} {
		raw, err := base64.RawURLEncoding.DecodeString(parts[i])
		if err != nil || json.Unmarshal(raw, into) != nil {
			return false
		}
	}
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	exp, _ := claims["exp"].(float64)
	return err == nil && len(signature) == 64 && header["alg"] == "ES256" && header["x5t#S256"] == thumbprint &&
		ecdsa.Verify(key, digest[:], new(big.Int).SetBytes(signature[:32]), new(big.Int).SetBytes(signature[32:])) &&
		claims["iss"] == client && claims["sub"] == client && claims["aud"] == audience && exp > float64(time.Now().Unix())
}

// From a configuration to a receipt with a token step (gateway #421,
// ADR-0027), by the real adapter-http against a stand-in token endpoint
// that checks the assertion with the public key and a stand-in API that
// takes only the token last issued to the platform's client: one token
// request serves two acquisitions; each platform's token is its own; a
// token the API refuses is dropped and the request is not sent again; a
// refused token request, and a step with no credential, fail with their
// own sentences, the second sending nothing; a key held in a writing
// platform's file is not used; the receipt has the members it has
// without a token step; and no token, assertion, key, federated token,
// sealed token or token endpoint's answer reaches a response, the store,
// the registry, /posture, the log or the check connect runs.
func TestTokenStepDrivesTheHTTPAdapterEndToEnd(t *testing.T) {
	dir := t.TempDir()
	bin := filepath.Join(dir, "bin")
	if err := os.MkdirAll(bin, 0o700); err != nil {
		t.Fatal(err)
	}
	buildAdapterInto(t, bin, "adapter-http")
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM := string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
	thumb := sha256.Sum256([]byte("records-certificate"))
	thumbprint := base64.RawURLEncoding.EncodeToString(thumb[:])
	const federatedText = "federated-identity-token-5f1e"
	const renewedText = "federated-identity-token-renewed-9b3d"
	const refusalText = "refusal-description-7c2a"

	var mu sync.Mutex
	current := map[string]string{} // client -> the token last issued to it
	revoked := map[string]bool{}
	requests := map[string]int{}
	hits := map[string]int{}
	var issued, assertions []string
	refuse := false
	var tokenURL string
	tokens := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		form := r.PostForm
		mu.Lock()
		defer mu.Unlock()
		client, assertion := form.Get("client_id"), form.Get("client_assertion")
		requests[client]++
		assertions = append(assertions, assertion)
		ok := !refuse && r.URL.Path == "/token" && form.Get("grant_type") == "client_credentials" &&
			form.Get("client_assertion_type") == "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
		switch client {
		case "records-client":
			ok = ok && form.Get("scope") == "records.read" && esAssertionHolds(assertion, &key.PublicKey, client, tokenURL, thumbprint)
		case "docs-client":
			ok = ok && !form.Has("scope") && (assertion == federatedText || assertion == renewedText)
		default:
			ok = false
		}
		w.Header().Set("Content-Type", "application/json")
		if !ok {
			w.WriteHeader(http.StatusBadRequest)
			io.WriteString(w, `{"error":"invalid_client","error_description":"`+refusalText+`"}`)
			return
		}
		token := fmt.Sprintf("access-%s-%d", client, len(issued)+1)
		issued = append(issued, token)
		current[client] = token
		io.WriteString(w, `{"access_token":"`+token+`","token_type":"bearer","expires_in":600}`)
	}))
	defer tokens.Close()
	tokenURL = tokens.URL + "/token"
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		hits[r.URL.Path]++
		want := map[string]string{"/records": current["records-client"], "/docs": current["docs-client"], "/plain": "static-secret"}[r.URL.Path]
		if want == "" || revoked[want] || r.Header.Get("Authorization") != "Bearer "+want {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"ok":true}`)
	}))
	defer api.Close()
	counts := func() (map[string]int, map[string]int) {
		mu.Lock()
		defer mu.Unlock()
		return copyCounts(requests), copyCounts(hits)
	}

	writeJSON := func(name string, members map[string]string) string {
		t.Helper()
		path := filepath.Join(dir, name)
		data, _ := json.Marshal(members)
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	recordsFile := writeJSON("records-live.json", map[string]string{"SIGNING_KEY": keyPEM, "API_TOKEN": "member-never-sent"})
	docsFile := writeJSON("docs-live.json", map[string]string{"API_TOKEN": "docs-member-never-sent"})
	plainFile := writeJSON("plain-live.json", map[string]string{"API_TOKEN": "static-secret"})
	warehouseFile := writeJSON("warehouse.json", map[string]string{"SERVICE_TOKEN": "secret-token", "SIGNING_KEY": keyPEM})
	federated := filepath.Join(dir, "federated.jwt")
	if err := os.WriteFile(federated, []byte(federatedText+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	httpBinding := func(name, check string) string {
		return `{"bindingVersion":"1","platform":"` + name + `","operations":{"live":{"shape":"http","endpoint":"` + api.URL + `","paths":["/` + name + `"],` +
			`"methods":["GET"],"bearer":"API_TOKEN"` + check + `,"licence":"Apache-2.0"}}}`
	}
	bindingTexts := map[string]string{"records": httpBinding("records", `,"checkPath":"/records"`), "docs": httpBinding("docs", ``), "plain": httpBinding("plain", ``), "postgres": postgresBinding}
	catalog := catalogWith(t, bindingTexts)
	escape := func(p string) string { return strings.ReplaceAll(p, `\`, `\\`) }
	platform := func(name, file, user, step string) string {
		return `"` + name + `":{"binding":"` + name + `@` + digestOf(bindingTexts[name]) + `","credentials":{"live":{"file":"` + escape(file) + `"` + step + `}},"user":"` + user + `"}`
	}
	text := `{"engineVersion":"21","authority":"gateway:test","seed":"` + escape(filepath.Join(dir, "gateway.seed")) + `","store":"` + escape(filepath.Join(dir, "store")) + `",` +
		`"registry":"` + escape(filepath.Join(dir, "registry.jsonl")) + `","decisionRecords":"` + escape(filepath.Join(dir, "decisions")) + `",` +
		`"listen":"127.0.0.1:0","catalog":"` + escape(catalog) + `","adapters":"` + escape(bin) + `","platforms":{` +
		platform("records", recordsFile, "engine-records", `,"tokenStep":{"endpoint":"`+tokenURL+`","clientId":"records-client","privateKey":"SIGNING_KEY","x5t#S256":"`+thumbprint+`","requestScope":"records.read"}`) + `,` +
		platform("docs", docsFile, "engine-docs", `,"tokenStep":{"endpoint":"`+tokenURL+`","clientId":"docs-client","federatedTokenFile":"`+escape(federated)+`"}`) + `,` +
		platform("plain", plainFile, "engine-plain", ``) + `,` +
		`"warehouse":{"binding":"postgres@` + digestOf(postgresBinding) + `","credentials":{"history":{"file":"` + escape(warehouseFile) + `"},"live":{"file":"` + escape(warehouseFile) + `"},"write":{"file":"` + escape(warehouseFile) + `"}},"user":"engine-warehouse","endpoint":"warehouse.internal:5432","write":true}}}`
	path := filepath.Join(dir, "engine.json")
	if err := os.WriteFile(path, []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, bindings, err := loadEngineConfig(path, stubAccounts(map[string]int{"engine-warehouse": 1001, "engine-docs": 1002, "engine-records": 1004, "engine-plain": 1005}))
	if err != nil {
		t.Fatal(err)
	}
	sources := deriveSources(cfg, bindings)
	if !sources["records/live"].tokenStep || !sources["docs/live"].tokenStep || sources["plain/live"].tokenStep || sources["warehouse/write"].tokenStep {
		t.Fatal("the token step is the http live sources' that declare one, alone")
	}
	// The users and the sandbox stripped, as in the end-to-end test of the
	// http shape: the switching is proved where it is implemented, and
	// adapter-sandbox's own test holds that it exits with its source's
	// status, which the token step's results are told apart by.
	for name, spec := range sources {
		spec.user, spec.sandbox = "", nil
		sources[name] = spec
	}
	var outputs []string
	keep := func(v any) {
		encoded, _ := json.Marshal(v)
		outputs = append(outputs, string(encoded))
	}
	// The check connect runs obtains a token of its own and sends it.
	report, err := runCheck(context.Background(), sources["records/live"])
	if err != nil {
		t.Fatalf("the check: %v", err)
	}
	line, err := describeSourceCheck(sources["records/live"], report)
	if err != nil || !strings.HasSuffix(line, "; GET /records answered 200") {
		t.Fatalf("the check as connect reads it: %q %v", line, err)
	}
	outputs = append(outputs, line, string(report))

	service, err := buildService(cfg.store, testSeed, cfg.authority, cfg.registry, engineServeOptions(cfg, sources, nil))
	if err != nil {
		t.Fatal(err)
	}
	var logs tokenLog
	service.reportsOut = &logs
	server := httptest.NewServer(service.handler())
	defer server.Close()
	session := 0
	acquire := func(source string) (int, map[string]any) {
		session++
		name := strings.TrimSuffix(source, "/live")
		code, body := post(t, server, "/acquire", fmt.Sprintf(`{"session":"tok-%d","source":"%s","arguments":{"path":"/%s","method":"GET"}}`, session, source, name))
		keep(body)
		return code, body
	}
	var sealed []string
	held := func(source string) string {
		service.tokens.mu.Lock()
		e := service.tokens.entries[tokenKey{source: source}]
		service.tokens.mu.Unlock()
		if e == nil {
			return ""
		}
		e.flight.Lock()
		defer e.flight.Unlock()
		if e.sealed != "" {
			sealed = append(sealed, e.sealed)
		}
		return e.sealed
	}
	fails := func(what, source, sentence string) {
		t.Helper()
		code, body := acquire(source)
		if code == http.StatusOK || !strings.Contains(fmt.Sprint(body), fmt.Sprintf(sentence, source)) || body["receipt"] != nil {
			t.Fatalf("%s: %d %v", what, code, body)
		}
	}
	succeeds := func(what, source string) map[string]any {
		t.Helper()
		code, body := acquire(source)
		if code != http.StatusOK {
			t.Fatalf("%s: %d %v", what, code, body)
		}
		return body
	}

	// One token request serves two acquisitions.
	beforeRequests, beforeHits := counts()
	first := succeeds("the first acquisition", "records/live")
	succeeds("the second acquisition", "records/live")
	requested, hit := counts()
	if requested["records-client"]-beforeRequests["records-client"] != 1 || hit["/records"]-beforeHits["/records"] != 2 {
		t.Fatalf("two acquisitions: %d token requests, %d requests to the API", requested["records-client"]-beforeRequests["records-client"], hit["/records"]-beforeHits["/records"])
	}
	recordsSealed := held("records/live")
	// Each platform's token is its own: the API takes the records token at
	// /records alone, and the docs token at /docs alone.
	succeeds("the federated platform's acquisition", "docs/live")
	if docsSealed := held("docs/live"); docsSealed == "" || docsSealed == recordsSealed {
		t.Fatalf("the federated platform's own sealed token: %q", docsSealed)
	}
	succeeds("the first platform after the federated one", "records/live")
	if requested, _ = counts(); requested["docs-client"] != 1 || requested["records-client"]-beforeRequests["records-client"] != 1 {
		t.Fatalf("each platform's own token, held: %d federated token requests, %d keyed", requested["docs-client"], requested["records-client"]-beforeRequests["records-client"])
	}
	// The receipt has the members it has without a token step.
	plain := succeeds("the platform with a static credential", "plain/live")
	receipt, plainReceipt := first["receipt"].(map[string]any), plain["receipt"].(map[string]any)
	if !reflect.DeepEqual(memberNames(receipt), memberNames(plainReceipt)) ||
		!reflect.DeepEqual(memberNames(receipt["acquisition"].(map[string]any)), memberNames(plainReceipt["acquisition"].(map[string]any))) {
		t.Fatalf("a token step's receipt and a static credential's differ in form:\n%v\n%v", receipt, plainReceipt)
	}

	// The API refuses the token: dropped, the request not sent again, and
	// the next acquisition obtains another.
	mu.Lock()
	revoked[current["records-client"]] = true
	mu.Unlock()
	beforeRequests, beforeHits = counts()
	fails("a token the API refused", "records/live", errTokenRejected)
	requested, hit = counts()
	if hit["/records"]-beforeHits["/records"] != 1 || requested["records-client"] != beforeRequests["records-client"] || held("records/live") != "" {
		t.Fatalf("a refused token: the API asked %d times, %d token requests, held %v", hit["/records"]-beforeHits["/records"], requested["records-client"]-beforeRequests["records-client"], held("records/live") != "")
	}
	succeeds("after a refused token", "records/live")
	if requested, _ = counts(); requested["records-client"] != beforeRequests["records-client"]+1 {
		t.Fatal("a refused token is obtained again")
	}
	held("records/live")

	// The token endpoint refuses: its own sentence, and nothing sent.
	mu.Lock()
	revoked[current["records-client"]] = true
	refuse = true
	mu.Unlock()
	fails("a token the API refused, again", "records/live", errTokenRejected)
	_, beforeHits = counts()
	fails("a refused token request", "records/live", errTokenRefused)
	if _, hit = counts(); hit["/records"] != beforeHits["/records"] {
		t.Fatal("a refused token request sends the request")
	}
	mu.Lock()
	refuse = false
	mu.Unlock()

	// The federated token renewed in place: the sealed token held was
	// sealed under the one before, so the adapter does not open it; it is
	// dropped, another obtained with the renewed token, and the request
	// sent once.
	if err := os.WriteFile(federated, []byte(renewedText+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	beforeRequests, beforeHits = counts()
	succeeds("after the federated token was renewed", "docs/live")
	if requested, hit = counts(); requested["docs-client"]-beforeRequests["docs-client"] != 1 || hit["/docs"]-beforeHits["/docs"] != 1 {
		t.Fatalf("a renewed federated token: %d token requests, the API asked %d times", requested["docs-client"]-beforeRequests["docs-client"], hit["/docs"]-beforeHits["/docs"])
	}
	held("docs/live")

	// No key in the platform's own file: no token is requested, though
	// the writing platform's file holds the same key under the same name.
	writeJSON("records-live.json", map[string]string{"API_TOKEN": "member-never-sent"})
	beforeRequests, beforeHits = counts()
	fails("no key", "records/live", errTokenNoCredential)
	// The federated token gone, with a sealed token held: the adapter
	// cannot open it, and nothing is sent.
	if err := os.Remove(federated); err != nil {
		t.Fatal(err)
	}
	fails("no federated token", "docs/live", errTokenNoCredential)
	requested, hit = counts()
	if !reflect.DeepEqual(requested, beforeRequests) || !reflect.DeepEqual(hit, beforeHits) {
		t.Fatalf("a step with no credential sends something: %v %v, before %v %v", requested, hit, beforeRequests, beforeHits)
	}

	// Nothing secret anywhere.
	if resp, err := http.Get(server.URL + "/posture"); err == nil {
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		outputs = append(outputs, string(body))
	}
	outputs = append(outputs, logs.String())
	for _, root := range []string{cfg.store, cfg.registry} {
		filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
			if err == nil && !d.IsDir() {
				data, _ := os.ReadFile(p)
				outputs = append(outputs, string(data))
			}
			return nil
		})
	}
	keyLines := strings.Split(strings.TrimSpace(keyPEM), "\n")
	secrets := append(append(append([]string{federatedText, renewedText, refusalText, "member-never-sent", keyLines[1], keyLines[len(keyLines)-2]}, issued...), assertions...), sealed...)
	if len(issued) < 4 || len(sealed) < 3 {
		t.Fatalf("the test saw %d tokens issued and %d sealed", len(issued), len(sealed))
	}
	all := strings.Join(outputs, "\n")
	for _, secret := range secrets {
		if secret != "" && strings.Contains(all, secret) {
			t.Fatalf("%q reached an output", secret)
		}
	}
}

// copyCounts is a copy of a map of counts.
func copyCounts(m map[string]int) map[string]int {
	out := make(map[string]int, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

// connect --replace keeps a live operation's token step, which connect has
// no flag for: an entry written without it would send the binding's bearer
// member in place of the token the step obtains. The source connect checks
// is the one serve derives, the step's flags in it; a replacement whose
// binding the step does not fit is refused, and the file left as it was.
func TestConnectReplaceKeepsTheTokenStep(t *testing.T) {
	binding := strings.Replace(recordsBinding, `"platform": "records"`, `"platform": "postgres"`, 1)
	f := newConnectFixture(t, binding, ``)
	header := strings.Replace(strings.Replace(recordsBinding, `"platform": "records"`, `"platform": "header"`, 1), `"bearer": "API_TOKEN"`, `"credentialHeader": "X-Key=API_TOKEN"`, 1)
	if err := os.WriteFile(filepath.Join(f.catalog, "header.json"), []byte(header), 0o600); err != nil {
		t.Fatal(err)
	}
	f.reports["http"] = `{"check":{"status":"succeeded","adapter":{"name":"adapter-http","version":"0.30.0","digest":"` + testImageDigest + `"},"endpoint":"https://records.example/api","peerIdentity":"tls:sha256:ab","probe":{"path":"/health","status":200}}}`
	step := `{"endpoint":"https://login.example/token","clientId":"client-7","privateKey":"SIGNING_KEY","requestScope":"records.read"}`
	entry := `"warehouse":{"binding":"postgres@` + digestOf(binding) + `","credentials":{"live":{"file":"` + escapePath(f.credentials) + `","tokenStep":` + step + `}},"user":"engine-warehouse"}`
	text := strings.Replace(strings.Replace(f.fileText(t), `"engineVersion":"1"`, `"engineVersion":"21"`, 1), `"platforms":{}`, `"platforms":{`+entry+`}`, 1)
	if err := os.WriteFile(f.config, []byte(text), 0o640); err != nil {
		t.Fatal(err)
	}
	if _, _, err := loadEngineConfig(f.config, stubAccounts(stubUsers)); err != nil {
		t.Fatal(err)
	}
	req := f.request()
	req.replace, req.endpoint = true, ""
	req.credentials = map[string]string{"live": f.credentials}
	refused := req
	refused.binding = "header"
	if _, err := connect(context.Background(), refused, f.host, f.check); err == nil || !strings.Contains(err.Error(), "platform warehouse carries credentials.live.tokenStep, which --replace keeps: credentials.live names a tokenStep, whose access token is sent as the bearer, and binding header@") {
		t.Fatalf("a replacement sending a credential header: %v", err)
	}
	if len(f.asked) != 0 || f.fileText(t) != text {
		t.Fatal("nothing is asked and nothing is written for a replacement the token step would not fit")
	}
	if _, err := connect(context.Background(), req, f.host, f.check); err != nil {
		t.Fatal(err)
	}
	if len(f.asked) != 1 || !slices.Contains(f.asked[0].argv, "--token-endpoint=https://login.example/token") || slices.Contains(f.asked[0].argv, "--bearer=API_TOKEN") || !f.asked[0].tokenStep {
		t.Fatalf("connect checked a source without the token step it keeps: %+v", f.asked)
	}
	after, bindings, err := loadEngineConfig(f.config, stubAccounts(stubUsers))
	if err != nil {
		t.Fatalf("%v\n%s", err, f.fileText(t))
	}
	want := tokenStepConfig{endpoint: "https://login.example/token", clientID: "client-7", privateKey: "SIGNING_KEY", requestScope: "records.read"}
	live := deriveSources(after, bindings)["warehouse/live"]
	if after.version != "21" || after.platforms[0].tokenStep == nil || *after.platforms[0].tokenStep != want || !reflect.DeepEqual(live.argv[1:], f.asked[0].argv[1:]) {
		t.Fatalf("the token step kept as written: version %s, %+v\n%s", after.version, after.platforms[0].tokenStep, f.fileText(t))
	}
}

// TestTokenStepStandIn is a stand-in adapter-http when the test below
// starts this binary as one, and nothing otherwise. --token-only writes
// TOKEN_STAND_IN_ANSWER and exits TOKEN_STAND_IN_EXIT; an acquisition
// records the sealed token it was handed and does as TOKEN_STAND_IN_RUN
// says: answer, exit 5 (the source refused the token), exit 6 (the sealed
// token not opened), or exit 6 the first time only.
func TestTokenStepStandIn(t *testing.T) {
	dir := os.Getenv("TOKEN_STAND_IN_DIR")
	if dir == "" {
		return
	}
	appendTo := func(name, line string) {
		f, err := os.OpenFile(filepath.Join(dir, name), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
		if err != nil {
			os.Exit(1)
		}
		f.WriteString(line + "\n")
		f.Close()
	}
	if os.Args[len(os.Args)-1] == "--token-only" {
		appendTo("token-runs", "run")
		os.Stderr.WriteString("stand-in-stderr-4e1a\n")
		os.Stdout.WriteString(os.Getenv("TOKEN_STAND_IN_ANSWER"))
		n, _ := strconv.Atoi(os.Getenv("TOKEN_STAND_IN_EXIT"))
		os.Exit(n)
	}
	appendTo("acquisitions", os.Getenv(sealedTokenVariable))
	switch os.Getenv("TOKEN_STAND_IN_RUN") {
	case "rejected":
		os.Exit(tokenExitRejectedBySource)
	case "unusable":
		os.Exit(tokenExitSealUnusable)
	case "unusable-once":
		if _, err := os.Stat(filepath.Join(dir, "once")); err != nil {
			os.WriteFile(filepath.Join(dir, "once"), nil, 0o600)
			os.Exit(tokenExitSealUnusable)
		}
	}
	os.Stdout.WriteString(`{"ok":true}`)
	os.Exit(0)
}

// The signer reads the adapter's sealed answer strictly -- exactly a
// sealed token of base64url and a lifetime of 1 to 86400 seconds or null --
// and maps each status to its own sentence, quoting nothing the adapter
// wrote; an acquisition is handed the sealed token held; one the source
// refused is dropped and not retried; one the adapter could not open is
// obtained again and the acquisition run once more, once.
func TestTokenStepReadsTheAdaptersAnswerStrictly(t *testing.T) {
	service, _ := testService(t)
	standIn := func(answer string, exit int, run string) (sourceSpec, string) {
		dir := t.TempDir()
		return sourceSpec{argv: []string{os.Args[0], "-test.run=^TestTokenStepStandIn$", "--"}, shape: "http", tokenStep: true,
			env: []string{"TOKEN_STAND_IN_DIR=" + dir, "TOKEN_STAND_IN_ANSWER=" + answer, fmt.Sprintf("TOKEN_STAND_IN_EXIT=%d", exit), "TOKEN_STAND_IN_RUN=" + run}}, dir
	}
	lines := func(dir, name string) []string {
		data, _ := os.ReadFile(filepath.Join(dir, name))
		return strings.Fields(string(data))
	}
	const good = `{"sealed":"c2VhbGVk","expiresIn":600}`
	for _, c := range []struct {
		name, answer string
		exit         int
		want         string // "" for an answer taken
	}{
		{"a lifetime", good, 0, ""},
		{"no lifetime", `{"sealed":"c2VhbGVk","expiresIn":null}`, 0, ""},
		{"no lifetime member", `{"sealed":"c2VhbGVk"}`, 0, errTokenAnswer},
		{"another member", `{"sealed":"c2VhbGVk","expiresIn":600,"token":"x"}`, 0, errTokenAnswer},
		{"a sealed token not of base64url", `{"sealed":"c2Vh+bGVk","expiresIn":600}`, 0, errTokenAnswer},
		{"an empty sealed token", `{"sealed":"","expiresIn":600}`, 0, errTokenAnswer},
		{"a lifetime of zero", `{"sealed":"c2VhbGVk","expiresIn":0}`, 0, errTokenAnswer},
		{"a lifetime past a day", `{"sealed":"c2VhbGVk","expiresIn":86401}`, 0, errTokenAnswer},
		{"a lifetime as a string", `{"sealed":"c2VhbGVk","expiresIn":"600"}`, 0, errTokenAnswer},
		{"not an object", `["c2VhbGVk"]`, 0, errTokenAnswer},
		{"no credential", good, tokenExitNoCredential, errTokenNoCredential},
		{"refused", good, tokenExitRefused, errTokenRefused},
		{"a 401 status from the token step", good, tokenExitRejectedBySource, errTokenRefused},
		{"a seal status from the token step", good, tokenExitSealUnusable, errTokenRefused},
	} {
		spec, _ := standIn(c.answer, c.exit, "ok")
		sealed, expiresIn, err := service.obtainToken("records/live", spec)
		switch {
		case c.want == "" && (err != nil || sealed != "c2VhbGVk" || (expiresIn != 600 && expiresIn != 0)):
			t.Fatalf("%s: %q %d %v", c.name, sealed, expiresIn, err)
		case c.want != "" && (err == nil || err.Error() != fmt.Sprintf(c.want, "records/live")):
			t.Fatalf("%s: want %q, got %v", c.name, fmt.Sprintf(c.want, "records/live"), err)
		}
	}
	// A failure that is not the token step's is said as any source's.
	spec, _ := standIn(good, 1, "ok")
	if _, _, err := service.obtainToken("records/live", spec); err == nil || !strings.HasPrefix(err.Error(), "source failed: ") {
		t.Fatalf("a source that failed otherwise: %v", err)
	}

	// Handed the sealed token held, and the second acquisition takes it
	// from the cache.
	spec, dir := standIn(good, 0, "ok")
	for i := 0; i < 2; i++ {
		if result, _, _, err := service.runAcquisitionSource("ok/live", spec, []byte("{}")); err != nil || result == nil {
			t.Fatalf("an acquisition handed the sealed token: %v", err)
		}
	}
	if runs, handed := lines(dir, "token-runs"), lines(dir, "acquisitions"); len(runs) != 1 || !slices.Equal(handed, []string{"c2VhbGVk", "c2VhbGVk"}) {
		t.Fatalf("%d token runs, handed %q", len(runs), handed)
	}
	// The source refused the token: dropped, not sent again, and the next
	// acquisition obtains another.
	spec, dir = standIn(good, 0, "rejected")
	if _, _, _, err := service.runAcquisitionSource("rejected/live", spec, []byte("{}")); err == nil || err.Error() != fmt.Sprintf(errTokenRejected, "rejected/live") {
		t.Fatalf("a token the source refused: %v", err)
	}
	if len(lines(dir, "acquisitions")) != 1 {
		t.Fatalf("a token the source refused was sent again: %d acquisitions", len(lines(dir, "acquisitions")))
	}
	service.runAcquisitionSource("rejected/live", spec, []byte("{}"))
	if len(lines(dir, "token-runs")) != 2 {
		t.Fatalf("a refused token was kept: %d token runs", len(lines(dir, "token-runs")))
	}
	// A sealed token the adapter could not open: obtained again, and the
	// acquisition run once more.
	spec, dir = standIn(good, 0, "unusable-once")
	if _, _, _, err := service.runAcquisitionSource("renewed/live", spec, []byte("{}")); err != nil || len(lines(dir, "token-runs")) != 2 || len(lines(dir, "acquisitions")) != 2 {
		t.Fatalf("a sealed token not opened once: %v, %d token runs, %d acquisitions", err, len(lines(dir, "token-runs")), len(lines(dir, "acquisitions")))
	}
	spec, dir = standIn(good, 0, "unusable")
	if _, _, _, err := service.runAcquisitionSource("unusable/live", spec, []byte("{}")); err == nil || err.Error() != fmt.Sprintf(errTokenRefused, "unusable/live") ||
		len(lines(dir, "token-runs")) != 2 || len(lines(dir, "acquisitions")) != 2 {
		t.Fatalf("a sealed token never opened: %v, %d token runs, %d acquisitions", err, len(lines(dir, "token-runs")), len(lines(dir, "acquisitions")))
	}
}
