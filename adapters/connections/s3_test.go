package connections

import (
	"adapters/attachment"
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"encoding/xml"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// The TLS fake receives the real fixed-origin requests and verifies SigV4
// independently (stdlib HMAC), rather than accepting any Authorization header.
type s3Fixture struct {
	t        *testing.T
	broker   *Broker
	cfg      s3Config
	server   *httptest.Server
	mu       sync.Mutex
	data     map[string][]byte
	etag     map[string]string
	hook     func(http.ResponseWriter, *http.Request) bool
	requests int
}

func testS3(t *testing.T) *s3Fixture {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("private custody is Unix-only")
	}
	dir := filepath.Join(t.TempDir(), "custody")
	s, err := OpenS3Store(dir, "test")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	cfg := s3Config{Region: "ca-central-1", Bucket: "example-bucket", Prefix: "policies/", AccessKey: "AKIAIOSFODNN7EXAMPLE", SecretKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"}
	f := &s3Fixture{t: t, broker: NewS3(s, false), cfg: cfg, data: map[string][]byte{"policies/a.txt": []byte("Policy text.\n"), "policies/z.txt": []byte("Other policy.\n")}, etag: map[string]string{}}
	f.server = httptest.NewTLSServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.server.Close)
	transport := f.server.Client().Transport.(*http.Transport).Clone()
	transport.TLSClientConfig.ServerName = f.server.Certificate().DNSNames[0]
	transport.DisableCompression = true
	// Preserve the signed origin/path while directing the test socket to TLS fake.
	baseDial := transport.DialContext
	transport.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		if addr != "s3.ca-central-1.amazonaws.com:443" {
			return nil, fmt.Errorf("unexpected origin")
		}
		return baseDial(ctx, network, strings.TrimPrefix(f.server.URL, "https://"))
	}
	f.broker.provider.client = &http.Client{Transport: transport, Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	return f
}
func (f *s3Fixture) serve(w http.ResponseWriter, r *http.Request) {
	if err := verifyS3Signature(r, f.cfg); err != nil {
		f.t.Error(err)
		w.WriteHeader(403)
		return
	}
	f.mu.Lock()
	f.requests++
	hook := f.hook
	f.mu.Unlock()
	if hook != nil && hook(w, r) {
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if r.URL.Query().Get("list-type") == "2" {
		prefix := r.URL.Query().Get("prefix")
		keys := []string{}
		for key := range f.data {
			if strings.HasPrefix(key, prefix) {
				keys = append(keys, key)
			}
		}
		sort.Strings(keys)
		start := 0
		if after := r.URL.Query().Get("start-after"); after != "" {
			start = sort.Search(len(keys), func(i int) bool { return keys[i] > after })
		}
		if token := r.URL.Query().Get("continuation-token"); token != "" {
			if !strings.HasPrefix(token, "private-page-") {
				w.WriteHeader(400)
				return
			}
			start, _ = strconv.Atoi(strings.TrimPrefix(token, "private-page-"))
		}
		limit, _ := strconv.Atoi(r.URL.Query().Get("max-keys"))
		end := min(len(keys), start+limit)
		fmt.Fprintf(w, "<ListBucketResult><Name>%s</Name><EncodingType>url</EncodingType><Prefix>%s</Prefix><IsTruncated>%t</IsTruncated>", f.cfg.Bucket, xmlText(url.PathEscape(prefix)), end < len(keys))
		if end < len(keys) {
			fmt.Fprintf(w, "<NextContinuationToken>private-page-%d</NextContinuationToken>", end)
		}
		for _, key := range keys[start:end] {
			etag := f.tag(key)
			fmt.Fprintf(w, "<Contents><Key>%s</Key><ETag>%s</ETag><Size>%d</Size><StorageClass>STANDARD</StorageClass></Contents>", xmlText(url.PathEscape(key)), xmlText(etag), len(f.data[key]))
		}
		fmt.Fprint(w, "</ListBucketResult>")
		return
	}
	key := strings.TrimPrefix(r.URL.Path, "/"+f.cfg.Bucket+"/")
	data, ok := f.data[key]
	if !ok {
		w.WriteHeader(404)
		return
	}
	etag := f.tag(key)
	if r.Header.Get("If-Match") != etag {
		w.WriteHeader(412)
		return
	}
	w.Header().Set("ETag", etag)
	w.Header().Set("Content-Length", strconv.Itoa(len(data)))
	w.Header().Set("X-Amz-Version-Id", "version-1")
	if version := r.URL.Query().Get("versionId"); version != "" && version != "version-1" {
		w.WriteHeader(404)
		return
	}
	if r.Method == "GET" {
		w.Write(data)
	}
}
func (f *s3Fixture) tag(key string) string {
	if tag := f.etag[key]; tag != "" {
		return tag
	}
	return `"` + strings.TrimPrefix(digest(f.data[key]), "sha256:") + `"`
}
func xmlText(s string) string { var b bytes.Buffer; xml.EscapeText(&b, []byte(s)); return b.String() }
func verifyS3Signature(r *http.Request, c s3Config) error {
	auth := r.Header.Get("Authorization")
	prefix := "AWS4-HMAC-SHA256 Credential=" + c.AccessKey + "/"
	if !strings.HasPrefix(auth, prefix) {
		return fmt.Errorf("missing explicit credential")
	}
	parts := strings.Split(strings.TrimPrefix(auth, prefix), ", ")
	if len(parts) != 3 {
		return fmt.Errorf("invalid signature fields")
	}
	scope := parts[0]
	names := strings.Split(strings.TrimPrefix(parts[1], "SignedHeaders="), ";")
	var headers strings.Builder
	for _, name := range names {
		value := r.Header.Get(name)
		if name == "host" {
			value = r.Host
		}
		headers.WriteString(name + ":" + strings.Join(strings.Fields(value), " ") + "\n")
	}
	query := strings.ReplaceAll(r.URL.Query().Encode(), "+", "%20")
	canonical := r.Method + "\n" + r.URL.EscapedPath() + "\n" + query + "\n" + headers.String() + "\n" + strings.Join(names, ";") + "\n" + s3EmptyHash
	timestamp := r.Header.Get("X-Amz-Date")
	if len(timestamp) != 16 {
		return fmt.Errorf("missing signed date")
	}
	scopeExpected := timestamp[:8] + "/" + c.Region + "/s3/aws4_request"
	if scope != scopeExpected {
		return fmt.Errorf("wrong signing scope")
	}
	hash := sha256.Sum256([]byte(canonical))
	toSign := "AWS4-HMAC-SHA256\n" + timestamp + "\n" + scope + "\n" + hex.EncodeToString(hash[:])
	mac := func(key []byte, value string) []byte {
		m := hmac.New(sha256.New, key)
		m.Write([]byte(value))
		return m.Sum(nil)
	}
	key := mac([]byte("AWS4"+c.SecretKey), timestamp[:8])
	key = mac(key, c.Region)
	key = mac(key, "s3")
	key = mac(key, "aws4_request")
	if strings.TrimPrefix(parts[2], "Signature=") != hex.EncodeToString(mac(key, toSign)) {
		return fmt.Errorf("invalid signature for %s", r.URL.EscapedPath())
	}
	if r.Header.Get("X-Amz-Security-Token") != c.SessionToken {
		return fmt.Errorf("wrong session token")
	}
	return nil
}
func s3Call(t *testing.T, b *Broker, method string, q any) any {
	t.Helper()
	raw, _ := json.Marshal(q)
	out, err := b.Handle(context.Background(), method, raw)
	if err != nil {
		t.Fatalf("%s: %v", method, err)
	}
	return out
}
func (f *s3Fixture) configure() { f.t.Helper(); s3Call(f.t, f.broker, "configure", f.cfg) }
func (f *s3Fixture) search() ResourcePage {
	f.t.Helper()
	return s3Call(f.t, f.broker, "search", map[string]string{"query": ""}).(ResourcePage)
}
func (f *s3Fixture) selectOne(page ResourcePage, id string) SourceSelection {
	f.t.Helper()
	return s3Call(f.t, f.broker, "select", map[string]any{"selectionContext": page.SelectionContext, "resourceIds": []string{id}}).([]SourceSelection)[0]
}
func (f *s3Fixture) read(selection SourceSelection) ([]byte, error) {
	raw, _ := json.Marshal(selection)
	return f.broker.provider.readS3(context.Background(), f.broker.store, raw)
}

func TestS3SignedReadRetainsBytesAndConsumesGrant(t *testing.T) {
	f := testS3(t)
	f.configure()
	page := f.search()
	selection := f.selectOne(page, "example-bucket/policies/a.txt")
	raw, err := f.read(selection)
	if err != nil {
		t.Fatal(err)
	}
	if attachment.Check(raw) != nil {
		t.Fatal("invalid retained document")
	}
	var doc map[string]any
	json.Unmarshal(raw, &doc)
	source := doc["provenance"].(map[string]any)["source"].(map[string]any)
	if source["provider"] != "aws-s3" || source["resourceId"] != selection.ResourceID || source["kind"] != "connection-resource" {
		t.Fatal(source)
	}
	if f.cfg.leaks(raw) || bytes.Contains(raw, []byte("Authorization")) || bytes.Contains(raw, []byte("version-1")) {
		t.Fatal("request metadata leaked")
	}
	if _, err = f.read(selection); err != ErrGrant {
		t.Fatal("replayed grant", err)
	}
	if output := os.Getenv("JPACK_S3_TEST_RECORD"); output != "" {
		if err = os.WriteFile(output, raw, 0600); err != nil {
			t.Fatal(err)
		}
	}
}
func TestS3ExactEscapedKeysAndPrefix(t *testing.T) {
	f := testS3(t)
	f.data = map[string][]byte{}
	for _, key := range []string{"space + # ? % &.txt", "café-日本語.txt", "a//b.txt", "a/../b.txt", "a/%2F/b.txt"} {
		f.data["policies/"+key] = []byte("Exact key.")
	}
	f.configure()
	page := f.search()
	for _, row := range page.Items {
		selection := f.selectOne(page, row.ID)
		if _, err := f.read(selection); err != nil {
			t.Fatalf("%s: %v", row.ID, err)
		}
	}
}
func TestS3PaginationContextAndSelectionIsolation(t *testing.T) {
	f := testS3(t)
	for i := 0; i < 30; i++ {
		f.data[fmt.Sprintf("policies/%02d.txt", i)] = []byte("x")
	}
	f.configure()
	first := f.search()
	if len(first.Items) != 24 || !first.More || !opaque.MatchString(first.NextPageToken) {
		t.Fatal(first)
	}
	raw, _ := json.Marshal(map[string]string{"query": "other", "pageToken": first.NextPageToken})
	if _, err := f.broker.Handle(context.Background(), "search", raw); err != ErrGrant {
		t.Fatal("cursor changed query", err)
	}
	second := s3Call(t, f.broker, "search", map[string]string{"query": "", "pageToken": first.NextPageToken}).(ResourcePage)
	if second.SelectionContext != first.SelectionContext || second.More {
		t.Fatal(second)
	}
	f.selectOne(second, first.Items[0].ID)
	raw, _ = json.Marshal(map[string]any{"selectionContext": first.SelectionContext, "resourceIds": []string{"example-bucket/private/secret.txt"}})
	if _, err := f.broker.Handle(context.Background(), "select", raw); err != ErrGrant {
		t.Fatal("unlisted key admitted", err)
	}
	f.search()
	raw, _ = json.Marshal(map[string]any{"selectionContext": first.SelectionContext, "resourceIds": []string{first.Items[0].ID}})
	if _, err := f.broker.Handle(context.Background(), "select", raw); err != ErrGrant {
		t.Fatal("stale search admitted", err)
	}
}
func TestS3ChangesAtSelectionAndReadRefused(t *testing.T) {
	f := testS3(t)
	f.configure()
	page := f.search()
	f.etag["policies/a.txt"] = `"new"`
	raw, _ := json.Marshal(map[string]any{"selectionContext": page.SelectionContext, "resourceIds": []string{"example-bucket/policies/a.txt"}})
	if _, err := f.broker.Handle(context.Background(), "select", raw); err != ErrChanged {
		t.Fatal("changed before selection", err)
	}
	page = f.search()
	sel := f.selectOne(page, "example-bucket/policies/a.txt")
	f.etag["policies/a.txt"] = `"newer"`
	if _, err := f.read(sel); err != ErrChanged {
		t.Fatal("changed before get", err)
	}
}
func TestS3ExpiredCredentialsDisconnectAndPrivateStore(t *testing.T) {
	f := testS3(t)
	f.cfg.AccessKey = "ASIAIOSFODNN7EXAMPLE"
	f.cfg.SessionToken = "fixture-session-token"
	f.cfg.ExpiresAt = time.Now().Add(time.Hour).UTC().Format(time.RFC3339)
	f.configure()
	page := f.search()
	sel := f.selectOne(page, page.Items[0].ID)
	f.broker.store.locked(func(v *state) error {
		v.S3.ExpiresAt = time.Now().Add(-time.Second).UTC().Format(time.RFC3339)
		return f.broker.store.write("state.json", v)
	})
	if _, err := f.read(sel); err != Error("credentials-required") {
		t.Fatal(err)
	}
	status := s3Call(t, f.broker, "status", struct{}{}).(Status)
	if status.State != "setup-required" {
		t.Fatal(status)
	}
	out := s3Call(t, f.broker, "disconnect", struct{}{}).(map[string]bool)
	if !out["disconnected"] || out["revoked"] {
		t.Fatal(out)
	}
	data, err := f.broker.store.read("state.json")
	if err != nil || f.cfg.leaks(data) {
		t.Fatal("credentials survived disconnect", err)
	}
	f.configure()
	if _, err = f.read(sel); err != ErrGrant {
		t.Fatal("grant survived reconnect", err)
	}
	info, _ := f.broker.store.root.Stat("state.json")
	if info.Mode().Perm() != 0600 {
		t.Fatal(info.Mode())
	}
}
func TestS3UnavailableMetadataAndProviderErrors(t *testing.T) {
	for _, example := range []struct {
		status int
		code   string
		want   error
	}{{403, "ExpiredToken", Error("credentials-required")}, {403, "AccessDenied", Error("permission-required")}, {403, "InvalidObjectState", Error("archived")}, {429, "SlowDown", Error("rate-limited")}, {301, "PermanentRedirect", ErrProvider}, {500, "Secret diagnostic", ErrProvider}} {
		t.Run(example.code, func(t *testing.T) {
			f := testS3(t)
			f.hook = func(w http.ResponseWriter, r *http.Request) bool {
				w.Header().Set("Location", "https://evil.invalid")
				w.WriteHeader(example.status)
				fmt.Fprintf(w, "<Error><Code>%s</Code><Message>%s</Message></Error>", example.code, f.cfg.SecretKey)
				return true
			}
			raw, _ := json.Marshal(f.cfg)
			out, err := f.broker.Handle(context.Background(), "configure", raw)
			if err != example.want || out != nil {
				t.Fatal(out, err)
			}
		})
	}
	for _, obj := range []s3Object{{Key: "a.txt", Size: 4, StorageClass: "GLACIER"}, {Key: "a.txt", Size: 4, StorageClass: "DEEP_ARCHIVE"}, {Key: "a.txt", Size: MaxFileBytes + 1}, {Key: "a.exe", Size: 4}, {Key: "a.txt", Size: 0}} {
		if obj.unavailable() == "" {
			t.Fatal(obj)
		}
	}
}
func TestS3DisconnectDuringFetchAndConfigureWins(t *testing.T) {
	for _, operation := range []string{"configure", "read"} {
		t.Run(operation, func(t *testing.T) {
			f := testS3(t)
			f.configure()
			page := f.search()
			sel := f.selectOne(page, page.Items[0].ID)
			entered, release := make(chan struct{}), make(chan struct{})
			f.hook = func(w http.ResponseWriter, r *http.Request) bool {
				if operation == "configure" && r.URL.Query().Get("list-type") == "2" || operation == "read" && r.Method == "GET" {
					close(entered)
					<-release
				}
				return false
			}
			done := make(chan error, 1)
			go func() {
				if operation == "read" {
					_, err := f.read(sel)
					done <- err
				} else {
					raw, _ := json.Marshal(f.cfg)
					_, err := f.broker.Handle(context.Background(), "configure", raw)
					done <- err
				}
			}()
			<-entered
			other := NewS3(f.broker.store, false)
			s3Call(t, other, "disconnect", struct{}{})
			close(release)
			if err := <-done; err != ErrCanceled {
				t.Fatal("disconnect lost", err)
			}
			status := s3Call(t, other, "status", struct{}{}).(Status)
			if status.State != "setup-required" {
				t.Fatal(status)
			}
		})
	}
}
func TestS3ListingRejectsMalformedAndOversizedResults(t *testing.T) {
	for _, name := range []string{"oversize", "outside-prefix", "missing-etag", "duplicate", "trailing", "cursor", "secret"} {
		t.Run(name, func(t *testing.T) {
			f := testS3(t)
			f.configure()
			f.hook = func(w http.ResponseWriter, r *http.Request) bool {
				root := "<ListBucketResult><Name>example-bucket</Name><EncodingType>url</EncodingType><Prefix>policies%2F</Prefix><IsTruncated>false</IsTruncated>"
				item := "<Contents><Key>policies%2Fa.txt</Key><ETag>&quot;tag&quot;</ETag><Size>4</Size></Contents>"
				end := "</ListBucketResult>"
				switch name {
				case "oversize":
					fmt.Fprint(w, strings.Repeat("x", (256<<10)+1))
				case "outside-prefix":
					fmt.Fprint(w, root+strings.ReplaceAll(item, "policies%2F", "private%2F")+end)
				case "missing-etag":
					fmt.Fprint(w, root+strings.ReplaceAll(item, "&quot;tag&quot;", "")+end)
				case "duplicate":
					fmt.Fprint(w, root+item+item+end)
				case "trailing":
					fmt.Fprint(w, root+item+end+"<extra/>")
				case "cursor":
					fmt.Fprint(w, root+"<NextContinuationToken>unexpected</NextContinuationToken>"+end)
				case "secret":
					fmt.Fprint(w, root+strings.ReplaceAll(item, "a.txt", f.cfg.SecretKey)+end)
				}
				return true
			}
			if _, err := f.broker.Handle(context.Background(), "search", []byte(`{"query":""}`)); err == nil {
				t.Fatal("bad list accepted")
			}
		})
	}
}
func TestS3ConfigurationRejectsImplicitOrUnsafeInputs(t *testing.T) {
	f := testS3(t)
	for _, mutate := range []func(*s3Config){func(c *s3Config) { c.Region = "evil.invalid" }, func(c *s3Config) { c.Bucket = "bucket/../other" }, func(c *s3Config) { c.Bucket = "192.168.0.1" }, func(c *s3Config) { c.AccessKey = "" }, func(c *s3Config) { c.SessionToken = "token" }, func(c *s3Config) { c.ExpiresAt = "2020-01-01T00:00:00Z" }, func(c *s3Config) { c.Prefix = "a\x00b" }} {
		cfg := f.cfg
		mutate(&cfg)
		if cfg.valid() {
			t.Fatal("unsafe config admitted")
		}
	}
	if _, err := f.broker.Handle(context.Background(), "configure", []byte(`{"profile":"default"}`)); err != ErrRequest {
		t.Fatal(err)
	}
	if f.requests != 0 {
		t.Fatal("invalid input contacted AWS")
	}
}

func TestS3AWSPathEncodingReference(t *testing.T) {
	c := s3Config{Region: "us-east-1", Bucket: "example-bucket"}
	for key, want := range map[string]string{"a+b.txt": "a%2Bb.txt", "a:b@c=d$e&f.txt": "a%3Ab%40c%3Dd%24e%26f.txt", "a//../b%2F.txt": "a//../b%252F.txt", "日本語.txt": "%E6%97%A5%E6%9C%AC%E8%AA%9E.txt"} {
		u, err := s3URL(c, key, nil)
		if err != nil || u.EscapedPath() != "/example-bucket/"+want {
			t.Fatalf("%q: %v %v", key, u, err)
		}
	}
}
func TestS3LongHTMLKeysPageWithoutLoss(t *testing.T) {
	f := testS3(t)
	f.data = map[string][]byte{}
	for i := 0; i < 24; i++ {
		key := fmt.Sprintf("policies/%02d%s.txt", i, strings.Repeat("&", 1009))
		if len(key) != 1024 {
			t.Fatal(len(key))
		}
		f.data[key] = []byte("x")
	}
	f.configure()
	page := f.search()
	seen := map[string]bool{}
	for rounds := 0; ; rounds++ {
		if rounds > 24 || ValidateResourcePage(page) != nil || len(page.Items) == 0 {
			t.Fatal("unusable page")
		}
		for _, row := range page.Items {
			if seen[row.ID] {
				t.Fatal("duplicate page item")
			}
			seen[row.ID] = true
		}
		// Long display names remain legal documents and escaping fits private custody.
		selection := f.selectOne(page, page.Items[0].ID)
		raw, err := f.read(selection)
		if err != nil || attachment.Check(raw) != nil {
			t.Fatal("long name read", err)
		}
		if !page.More {
			break
		}
		page = s3Call(t, f.broker, "search", map[string]string{"query": "", "pageToken": page.NextPageToken}).(ResourcePage)
	}
	if len(seen) != 24 {
		t.Fatal("lost rows", len(seen))
	}
}
func TestS3NullVersionIsPinned(t *testing.T) {
	f := testS3(t)
	f.configure()
	page := f.search()
	f.hook = func(w http.ResponseWriter, r *http.Request) bool {
		if r.Method == "HEAD" {
			w.Header().Set("ETag", f.tag("policies/a.txt"))
			w.Header().Set("Content-Length", strconv.Itoa(len(f.data["policies/a.txt"])))
			w.Header().Set("X-Amz-Version-Id", "null")
			return true
		}
		if r.Method == "GET" && r.URL.Query().Get("list-type") == "" {
			if r.URL.Query().Get("versionId") != "null" {
				w.WriteHeader(412)
				return true
			}
			data := f.data["policies/a.txt"]
			w.Header().Set("ETag", f.tag("policies/a.txt"))
			w.Header().Set("Content-Length", strconv.Itoa(len(data)))
			w.Header().Set("X-Amz-Version-Id", "null")
			w.Write(data)
			return true
		}
		return false
	}
	selection := f.selectOne(page, "example-bucket/policies/a.txt")
	if _, err := f.read(selection); err != nil {
		t.Fatal(err)
	}
}
func TestS3GetRefusesForgedOrOversizedBody(t *testing.T) {
	for _, name := range []string{"huge", "length", "version", "etag", "secret", "gzip"} {
		t.Run(name, func(t *testing.T) {
			f := testS3(t)
			f.configure()
			sel := f.selectOne(f.search(), "example-bucket/policies/a.txt")
			f.hook = func(w http.ResponseWriter, r *http.Request) bool {
				if r.Method != "GET" || r.URL.Query().Get("list-type") != "" {
					return false
				}
				data := f.data["policies/a.txt"]
				w.Header().Set("ETag", f.tag("policies/a.txt"))
				w.Header().Set("X-Amz-Version-Id", "version-1")
				switch name {
				case "huge":
					data = bytes.Repeat([]byte("x"), MaxFileBytes+1)
				case "length":
					data = append(data, 'x')
				case "version":
					w.Header().Set("X-Amz-Version-Id", "version-2")
				case "etag":
					w.Header().Set("ETag", `"changed"`)
				case "secret":
					data = []byte(f.cfg.SecretKey)
				case "gzip":
					w.Header().Set("Content-Encoding", "gzip")
				}
				w.Header().Set("Content-Length", strconv.Itoa(len(data)))
				w.Write(data)
				return true
			}
			if out, err := f.read(sel); err == nil || out != nil {
				t.Fatal("bad bytes released", err)
			}
		})
	}
}
func TestS3CatalogUsesExistingHostProtocolAndV2Unchanged(t *testing.T) {
	for _, p := range ConnectionCatalog().Providers {
		if p.ID == "aws-s3" {
			t.Fatal("S3 leaked into v2")
		}
	}
	var s3 ProviderDescriptor
	for _, p := range ConnectionCatalogV3().Providers {
		if p.ID == "aws-s3" {
			s3 = p
		}
	}
	if s3.Source.Record != "resource-v1" || s3.Source.Shape != "command" || s3.Auth != "credentials" || s3.Protocol != "connection-v1" || s3.QueryMode != "prefix" || len(s3.Setup) != 7 {
		t.Fatal(s3)
	}
	for _, field := range s3.Setup {
		for _, locale := range []string{"en", "fr", "es", "de", "it", "pt-PT", "pt-BR", "ko", "ja", "zh-Hans", "zh-Hant", "yue-Hant"} {
			if field.Label[locale] == "" {
				t.Fatal("untranslated field", field.Key, locale)
			}
		}
	}
}

// Opt-in fixture for unchanged-Desk acceptance. This test server is not compiled
// into a release. The transport overlay used by the smoke also lives in /tmp.
func TestS3DeskFixture(t *testing.T) {
	ready := os.Getenv("JPACK_S3_SMOKE_READY")
	if ready == "" {
		t.Skip("opt-in Desk fixture")
	}
	f := testS3(t)
	f.data["policies/a.txt"] = []byte("S3 fixture policy: reimburse approved travel.\n")
	pdf, err := os.ReadFile("../document/testdata/normal.pdf")
	if err != nil {
		t.Fatal(err)
	}
	f.data["policies/document.pdf"] = pdf
	for i := 0; i < 25; i++ {
		f.data[fmt.Sprintf("policies/%02d.txt", i)] = []byte("Fixture page.")
	}
	cert := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: f.server.Certificate().Raw})
	info, _ := json.Marshal(map[string]string{"address": strings.TrimPrefix(f.server.URL, "https://"), "serverName": f.server.Certificate().DNSNames[0], "certificate": string(cert)})
	if err = os.WriteFile(ready, info, 0600); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(20 * time.Minute)
	for time.Now().Before(deadline) {
		if _, err = os.Stat(ready + ".stop"); err == nil {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatal("smoke fixture timed out")
}

func TestS3BrowseGrantExpiryPolicyAndScopeReplacement(t *testing.T) {
	f := testS3(t)
	f.configure()
	page := f.search()
	sel := f.selectOne(page, page.Items[0].ID)
	f.broker.store.locked(func(v *state) error {
		g, e := s3Read[grant](f.broker.store, "grant-"+sel.Grant)
		if e != nil {
			return e
		}
		g.Expires = time.Now().Add(-time.Second).Unix()
		return f.broker.store.write("grant-"+sel.Grant, g)
	})
	if _, err := f.read(sel); err != ErrGrant {
		t.Fatal("expired grant admitted", err)
	}
	f.broker.store.locked(func(v *state) error {
		browse, e := s3Read[s3Browse](f.broker.store, "s3-browse.json")
		if e != nil {
			return e
		}
		browse.Expires = time.Now().Add(-time.Second).Unix()
		return f.broker.store.write("s3-browse.json", browse)
	})
	q, _ := json.Marshal(map[string]any{"selectionContext": page.SelectionContext, "resourceIds": []string{page.Items[0].ID}})
	if _, err := f.broker.Handle(context.Background(), "select", q); err != ErrGrant {
		t.Fatal("expired listing admitted", err)
	}
	page = f.search()
	sel = f.selectOne(page, page.Items[0].ID)
	blocked := NewS3(f.broker.store, true)
	s3Call(t, blocked, "status", struct{}{})
	if _, err := f.read(sel); err != ErrPolicy {
		t.Fatal("disabled source read", err)
	}
	s3Call(t, f.broker, "status", struct{}{})
	if _, err := f.read(sel); err != ErrGrant {
		t.Fatal("grant survived disable/re-enable", err)
	}
	if _, err := f.broker.Handle(context.Background(), "select", q); err != ErrGrant {
		t.Fatal("old selection survived epoch", err)
	}
	f.configure()
	page = f.search()
	sel = f.selectOne(page, page.Items[0].ID)
	prior := s3Call(t, f.broker, "status", struct{}{}).(Status).Resource.ID
	f.cfg.Prefix = "policies/z"
	f.configure()
	after := s3Call(t, f.broker, "status", struct{}{}).(Status).Resource.ID
	if prior == after {
		t.Fatal("scope identity did not change")
	}
	if _, err := f.read(sel); err != ErrGrant {
		t.Fatal("old scope grant survived", err)
	}
}
func TestS3RequestDoesNotUseAmbientCredentials(t *testing.T) {
	f := testS3(t)
	t.Setenv("AWS_ACCESS_KEY_ID", "OTHERACCESSKEYVALUE")
	t.Setenv("AWS_SECRET_ACCESS_KEY", strings.Repeat("X", 40))
	t.Setenv("AWS_SESSION_TOKEN", "OTHERSESSION")
	t.Setenv("HTTPS_PROXY", "http://127.0.0.1:1")
	t.Setenv("AWS_ENDPOINT_URL_S3", "http://127.0.0.1:1")
	// The TLS fixture independently verifies the supplied key/token and fixed host.
	f.configure()
	sel := f.selectOne(f.search(), "example-bucket/policies/a.txt")
	if _, err := f.read(sel); err != nil {
		t.Fatal(err)
	}
	production := NewS3(f.broker.store, false).provider.client
	if production.Transport.(*http.Transport).Proxy != nil {
		t.Fatal("ambient proxy enabled")
	}
}
