//go:build linux || darwin

package connections

import (
	"adapters/document"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// useBundle stands dir in for the OCR tools bundle beside the executable.
func useBundle(t *testing.T, dir string) {
	t.Helper()
	saved := ocrBundle
	t.Cleanup(func() { ocrBundle = saved })
	ocrBundle = func() string { return dir }
}

// managed is a read whose adapter the plan launched with --document-processing.
var managed = WithDocumentProcessing(context.Background())

func processingBroker(t *testing.T) (*Broker, string) {
	t.Helper()
	dir := t.TempDir()
	os.Chmod(dir, 0700)
	s, e := OpenProcessingStore(dir, "desk-local")
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { _ = s.Close() })
	return NewProcessing(s, false), dir
}
func processingState(t *testing.T, b *Broker) ProcessingStatus {
	t.Helper()
	v, e := b.Handle(context.Background(), "status", []byte(`{}`))
	if e != nil {
		t.Fatal(e)
	}
	return v.(ProcessingStatus)
}
func processingSave(t *testing.T, b *Broker, base ProcessingStatus, c ProcessingConfig) ProcessingStatus {
	t.Helper()
	v, e := processingTry(b, base, c)
	if e != nil {
		t.Fatal(e)
	}
	return v
}
func processingTry(b *Broker, base ProcessingStatus, c ProcessingConfig) (ProcessingStatus, error) {
	raw, _ := json.Marshal(map[string]any{"ifMatch": base.SHA256, "config": c})
	v, e := b.Handle(context.Background(), "configure", raw)
	if e != nil {
		return ProcessingStatus{}, e
	}
	return v.(ProcessingStatus), nil
}

// asSent is a configuration as a client sends it back: status-only members
// cleared, credentials left out.
func asSent(c ProcessingConfig) ProcessingConfig {
	c.Connections = append([]OCRConnection(nil), c.Connections...)
	for i := range c.Connections {
		c.Connections[i].Ready = false
		c.Connections[i].CredentialConfigured = false
		c.Connections[i].Credential = ""
	}
	return c
}
func azureOCR() OCRConnection {
	return OCRConnection{ID: "ocr-azure", Name: "Azure work", Kind: "azure-document-intelligence", Endpoint: "https://work.cognitiveservices.azure.com", Credential: "private-secret", Enabled: true}
}
func TestOCRRegistryPrivateCredentialsCASAndNoRetarget(t *testing.T) {
	b, dir := processingBroker(t)
	old := processingState(t, b)
	if old.Mode != "off" || len(old.Connections) != 0 {
		t.Fatal("OCR enabled without configuration")
	}
	c := old.ProcessingConfig
	c.Connections = append(c.Connections, azureOCR())
	c.Mode = "auto"
	c.Connection = "ocr-azure"
	c.TimeoutSeconds = 75
	next := processingSave(t, b, old, c)
	raw, _ := json.Marshal(next)
	if bytes.Contains(raw, []byte("private-secret")) || !next.Connections[0].CredentialConfigured {
		t.Fatal("secret disclosed or presence lost")
	}
	// The settings file is the store's: private to its owner.
	var held os.FileInfo
	filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err == nil && d.Name() == "processing.json" {
			held, _ = os.Lstat(path)
		}
		return nil
	})
	if held == nil || held.Mode().Perm() != 0600 {
		t.Fatal("settings file missing or not private")
	}
	c = asSent(next.ProcessingConfig)
	c.Connections[0].Name = "Renamed"
	latest := processingSave(t, b, next, c)
	saved, _, e := b.store.processingConfig()
	if e != nil || saved.Connections[0].Credential != "private-secret" || saved.Connections[0].Name != "Renamed" {
		t.Fatal("a save that left the credential out of an unchanged destination lost it")
	}
	// A credential left out is not carried to another destination: the
	// key would go to a host it was not entered for.
	for name, change := range map[string]func(*OCRConnection){
		"endpoint": func(p *OCRConnection) { p.Endpoint = "https://other.cognitiveservices.azure.com" },
		"kind": func(p *OCRConnection) {
			p.Kind, p.Endpoint, p.Region = "aws-textract", "", "us-east-1"
		},
	} {
		c = asSent(latest.ProcessingConfig)
		change(&c.Connections[0])
		if _, e = processingTry(b, latest, c); e != ErrRequest {
			t.Fatalf("%s change kept the old credential: %v", name, e)
		}
	}
	after, _, _ := b.store.processingConfig()
	if after.Connections[0].Endpoint != "https://work.cognitiveservices.azure.com" || after.Connections[0].Credential != "private-secret" {
		t.Fatal("a refused save changed the settings")
	}
	// Entered again with the new destination, it is taken.
	c = asSent(latest.ProcessingConfig)
	c.Connections[0].Endpoint = "https://other.cognitiveservices.azure.com"
	c.Connections[0].Credential = "other-secret"
	moved := processingSave(t, b, latest, c)
	c = asSent(moved.ProcessingConfig)
	c.Connections[0].Endpoint = "https://work.cognitiveservices.azure.com"
	c.Connections[0].Credential = "private-secret"
	latest = processingSave(t, b, moved, c)
	stale, _ := json.Marshal(map[string]any{"ifMatch": old.SHA256, "config": c})
	if _, e = b.Handle(context.Background(), "configure", stale); e != Error("processing-changed") {
		t.Fatal(e)
	}
	t.Setenv("JPACK_CONNECTIONS_DIR", dir)
	cfg := document.DefaultConfig()
	if e = ApplyDocumentProcessing(managed, &cfg); e != nil {
		t.Fatal(e)
	}
	if strings.Join(cfg.OCREnv, " ") != "JPACK_OCR_CONNECTION=ocr-azure JPACK_OCR_REVISION="+latest.SHA256 || cfg.Timeout != 75*time.Second || filepath.Base(cfg.OCR) != "ocr-cloud" || !filepath.IsAbs(cfg.OCR) || cfg.OCRName != "azure:ocr-cloud" {
		t.Fatal("choice was not pinned")
	}
	var out bytes.Buffer
	if e = RunCloudOCR(context.Background(), "ocr-azure", next.SHA256, []string{"1"}, strings.NewReader("invalid"), &out); e != Error("processing-changed") || out.Len() != 0 {
		t.Fatal("stale worker read a different configuration", e)
	}
	c = asSent(latest.ProcessingConfig)
	c.Mode = "off"
	processingSave(t, b, latest, c)
	cfg = document.DefaultConfig()
	if ApplyDocumentProcessing(managed, &cfg) != nil || cfg.OCR != "" || len(cfg.OCREnv) != 0 {
		t.Fatal("off still runs OCR")
	}
}
func TestOCRRejectsUnsafeOrIncompleteConnections(t *testing.T) {
	base := ProcessingConfig{Version: 1, Mode: "off", Connections: []OCRConnection{azureOCR()}}
	if !validProcessing(base) {
		t.Fatal("the sound base is refused")
	}
	cases := map[string]func(*OCRConnection){
		"plain http":        func(p *OCRConnection) { p.Endpoint = "http://work.cognitiveservices.azure.com" },
		"suffix host":       func(p *OCRConnection) { p.Endpoint = "https://work.cognitiveservices.azure.com.evil.invalid" },
		"any-character dot": func(p *OCRConnection) { p.Endpoint = "https://work.cognitiveservicesXazure.com" },
		"not an AI host":    func(p *OCRConnection) { p.Endpoint = "https://work.api.cognitive.microsoft.azure.com" },
		"user info":         func(p *OCRConnection) { p.Endpoint = "https://user:secret@work.cognitiveservices.azure.com" },
		"port":              func(p *OCRConnection) { p.Endpoint = "https://work.cognitiveservices.azure.com:8443" },
		"path":              func(p *OCRConnection) { p.Endpoint = "https://work.cognitiveservices.azure.com/other" },
		"query":             func(p *OCRConnection) { p.Endpoint = "https://work.cognitiveservices.azure.com/?x=1" },
		"no credential":     func(p *OCRConnection) { p.Credential = "" },
		"program on cloud":  func(p *OCRConnection) { p.Program = "/bin/sh" },
		"ready saved":       func(p *OCRConnection) { p.Ready = true },
		"presence saved":    func(p *OCRConnection) { p.CredentialConfigured = true },
		"path id":           func(p *OCRConnection) { p.ID = "../outside" },
		"relative program": func(p *OCRConnection) {
			*p = OCRConnection{ID: "local", Name: "Local", Kind: "program", Program: "ocr"}
		},
		"unclean program": func(p *OCRConnection) {
			*p = OCRConnection{ID: "local", Name: "Local", Kind: "program", Program: "/usr/bin/../../tmp/ocr"}
		},
		"program with a control": func(p *OCRConnection) {
			*p = OCRConnection{ID: "local", Name: "Local", Kind: "program", Program: "/usr/bin/ocr\t--all"}
		},
		"tesseract secret": func(p *OCRConnection) {
			*p = OCRConnection{ID: "local", Name: "Local", Kind: "tesseract", Credential: "x"}
		},
		"textract china": func(p *OCRConnection) {
			*p = OCRConnection{ID: "aws", Name: "AWS", Kind: "aws-textract", Region: "cn-north-1", Credential: `{"accessKeyId":"id","secretAccessKey":"secret"}`}
		},
		"textract dotted": func(p *OCRConnection) {
			*p = OCRConnection{ID: "aws", Name: "AWS", Kind: "aws-textract", Region: "evil.example", Credential: `{"accessKeyId":"id","secretAccessKey":"secret"}`}
		},
		"google not json": func(p *OCRConnection) {
			*p = OCRConnection{ID: "g", Name: "G", Kind: "google-document-ai", Project: "p", Location: "eu", Processor: "1", Credential: "key"}
		},
		"unknown kind": func(p *OCRConnection) { p.Kind = "other" },
	}
	for name, change := range cases {
		c := base
		c.Connections = append([]OCRConnection(nil), base.Connections...)
		change(&c.Connections[0])
		if validProcessing(c) {
			t.Errorf("accepted %s", name)
		}
	}
	for _, seconds := range []int{-1, 9, 121} {
		c := base
		c.TimeoutSeconds = seconds
		if validProcessing(c) {
			t.Errorf("accepted a timeout of %d seconds", seconds)
		}
	}
	c := base
	c.Mode = "auto"
	c.Connection = "missing"
	if validProcessing(c) {
		t.Fatal("missing selection")
	}
	c.Connection = "ocr-azure"
	c.Connections = []OCRConnection{azureOCR()}
	c.Connections[0].Enabled = false
	if validProcessing(c) {
		t.Fatal("disabled selection")
	}
	c.Connections = nil
	c.Mode, c.Connection = "off", ""
	if validProcessing(c) {
		t.Fatal("null connections")
	}
}

// Settings that cannot be read now never read as "no OCR".
func TestApplyDocumentProcessingFailsClosed(t *testing.T) {
	cfg := document.DefaultConfig()
	t.Setenv("JPACK_CONNECTIONS_DIR", "")
	if e := ApplyDocumentProcessing(managed, &cfg); e != ErrStorage || cfg.OCR != "" {
		t.Fatal("a launch for processing without its settings directory went ahead", e)
	}
	b, dir := processingBroker(t)
	t.Setenv("JPACK_CONNECTIONS_DIR", dir)
	base := processingState(t, b)
	c := base.ProcessingConfig
	c.Connections = []OCRConnection{{ID: "local", Name: "Local", Kind: "tesseract", Enabled: true}}
	c.Mode, c.Connection = "auto", "local"
	processingSave(t, b, base, c)
	// An adapter the plan did not launch for processing never reads them.
	cfg = document.DefaultConfig()
	if ApplyDocumentProcessing(context.Background(), &cfg) != nil || cfg.OCR != "" || cfg.Timeout != document.DefaultConfig().Timeout {
		t.Fatal("an adapter launched without --document-processing applied the settings")
	}
	cfg = document.DefaultConfig()
	cfg.OCR = "operator-ocr"
	if ApplyDocumentProcessing(managed, &cfg) != nil || cfg.OCR != "operator-ocr" || cfg.Timeout != document.DefaultConfig().Timeout {
		t.Fatal("the command line's --ocr was replaced")
	}
	cfg = document.DefaultConfig()
	if ApplyDocumentProcessing(managed, &cfg) != nil || filepath.Base(cfg.OCR) != "ocr-tesseract" || cfg.OCRName != "tesseract:ocr-tesseract" || len(cfg.OCREnv) != 0 || cfg.Timeout != 120*time.Second {
		t.Fatal("local processor not applied", cfg.OCR)
	}
	// A settings file that does not hold to its rules is unreadable now.
	if e := b.store.write("processing.json", map[string]any{"version": 1, "mode": "auto", "connection": "gone", "connections": []any{}}); e != nil {
		t.Fatal(e)
	}
	cfg = document.DefaultConfig()
	if e := ApplyDocumentProcessing(managed, &cfg); e != ErrStorage || cfg.OCR != "" {
		t.Fatal("invalid settings read as no OCR", e)
	}
	if _, e := b.Handle(context.Background(), "status", []byte(`{}`)); e != ErrStorage {
		t.Fatal("status of invalid settings", e)
	}
	// A store the operator blocked refuses, rather than extracting without OCR.
	blocked := NewProcessing(b.store, true)
	blocked.Handle(context.Background(), "status", []byte(`{}`))
	cfg = document.DefaultConfig()
	if e := ApplyDocumentProcessing(managed, &cfg); e != ErrPolicy {
		t.Fatal("blocked settings applied", e)
	}
}
func TestOCRTestAcceptsPDFLargerThanControlRequestWithoutStoringIt(t *testing.T) {
	b, _ := processingBroker(t)
	base := processingState(t, b)
	cfg := base.ProcessingConfig
	bundle := t.TempDir()
	useBundle(t, bundle)
	program := filepath.Join(bundle, "ocr")
	os.WriteFile(program, []byte("#!/bin/sh\n/bin/cat >/dev/null\nprintf '{\"pages\":[]}'\n"), 0700)
	cfg.Connections = []OCRConnection{{ID: "ocr-test", Name: "Test", Kind: "program", Program: program, Enabled: true}}
	next := processingSave(t, b, base, cfg)
	data, e := os.ReadFile("../document/testdata/normal.pdf")
	if e != nil {
		t.Fatal(e)
	}
	data = append(data, bytes.Repeat([]byte(" "), 70000)...)
	raw, _ := json.Marshal(map[string]any{"connection": "ocr-test", "revision": next.SHA256, "document": map[string]string{"name": "test.pdf", "mediaType": "application/pdf", "bytes": base64.StdEncoding.EncodeToString(data)}})
	if len(raw) <= ControlLineBytes {
		t.Fatal("the test document fits a control line")
	}
	v, e := b.Handle(context.Background(), "test", raw)
	if e != nil {
		t.Fatal(e)
	}
	if v.(map[string]any)["pageCount"].(int64) < 1 {
		t.Fatal("test did not extract")
	}
	after := processingState(t, b)
	if after.SHA256 != next.SHA256 {
		t.Fatal("test changed settings")
	}
	stale, _ := json.Marshal(map[string]any{"connection": "ocr-test", "revision": base.SHA256, "document": map[string]string{"name": "test.pdf", "mediaType": "application/pdf", "bytes": base64.StdEncoding.EncodeToString(data)}})
	if _, e = b.Handle(context.Background(), "test", stale); e != Error("processing-changed") {
		t.Fatal("a test ran under settings it was not asked for", e)
	}
}

type ocrTransport func(*http.Request) (*http.Response, error)

func (f ocrTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func ocrReply(code int, body string, header http.Header) *http.Response {
	return &http.Response{StatusCode: code, Body: io.NopCloser(strings.NewReader(body)), Header: header}
}
func TestCloudOCRProviderContracts(t *testing.T) {
	t.Run("google", func(t *testing.T) {
		client := &http.Client{Transport: ocrTransport(func(r *http.Request) (*http.Response, error) {
			if r.URL.String() != "https://eu-documentai.googleapis.com/v1/projects/demo/locations/eu/processors/123:process" || r.Header.Get("Authorization") != "Bearer access" {
				t.Fatal("wrong destination/auth")
			}
			var body struct {
				RawDocument struct{ Content, MimeType string }
				FieldMask   string
			}
			json.NewDecoder(r.Body).Decode(&body)
			if body.RawDocument.Content != base64.StdEncoding.EncodeToString([]byte("PNG")) || body.RawDocument.MimeType != "image/png" || body.FieldMask != "text" {
				t.Fatal("wrong image request")
			}
			return ocrReply(200, `{"document":{"text":"Recognized text"}}`, nil), nil
		})}
		text, e := cloudOCRPage(context.Background(), client, OCRConnection{Kind: "google-document-ai", Project: "demo", Location: "eu", Processor: "123"}, "access", []byte("PNG"))
		if e != nil || text != "Recognized text" {
			t.Fatal(text, e)
		}
	})
	t.Run("textract", func(t *testing.T) {
		client := &http.Client{Transport: ocrTransport(func(r *http.Request) (*http.Response, error) {
			if r.URL.Host != "textract.us-east-1.amazonaws.com" || r.Header.Get("X-Amz-Target") != "Textract.DetectDocumentText" || !strings.Contains(r.Header.Get("Authorization"), "/us-east-1/textract/aws4_request") || r.Header.Get("X-Amz-Security-Token") != "temporary" {
				t.Fatal("wrong signed request")
			}
			if strings.Contains(r.Header.Get("Authorization"), "secret") || strings.Contains(r.URL.String(), "secret") {
				t.Fatal("secret key sent")
			}
			return ocrReply(200, `{"Blocks":[{"BlockType":"PAGE"},{"BlockType":"LINE","Text":"Hello"},{"BlockType":"WORD","Text":"Hello"},{"BlockType":"LINE","Text":"World"}]}`, nil), nil
		})}
		text, e := cloudOCRPage(context.Background(), client, OCRConnection{Kind: "aws-textract", Region: "us-east-1", Credential: `{"accessKeyId":"id","secretAccessKey":"secret","sessionToken":"temporary"}`}, "", []byte("PNG"))
		if e != nil || text != "Hello\nWorld" {
			t.Fatal(text, e)
		}
	})
	t.Run("azure polling", func(t *testing.T) {
		calls := 0
		client := &http.Client{Transport: ocrTransport(func(r *http.Request) (*http.Response, error) {
			calls++
			if r.Header.Get("Ocp-Apim-Subscription-Key") != "private-secret" || strings.Contains(r.URL.String(), "private-secret") {
				t.Fatal("key missing from its header, or in the URL")
			}
			if calls == 1 {
				if r.URL.String() != "https://work.cognitiveservices.azure.com/documentintelligence/documentModels/prebuilt-read:analyze?api-version=2024-11-30" {
					t.Fatal("wrong destination", r.URL)
				}
				return ocrReply(202, "", http.Header{"Operation-Location": []string{"https://work.cognitiveservices.azure.com/documentintelligence/documentModels/prebuilt-read/analyzeResults/3fa85f64-5717-4562-b3fc-2c963f66afa6?api-version=2023-01-01&extra=1"}}), nil
			}
			// The poll is rebuilt: the result's identifier and the API version
			// sent, nothing else of the header.
			if r.Method != "GET" || r.URL.String() != "https://work.cognitiveservices.azure.com/documentintelligence/documentModels/prebuilt-read/analyzeResults/3fa85f64-5717-4562-b3fc-2c963f66afa6?api-version=2024-11-30" {
				t.Fatal("polled at another URL", r.URL)
			}
			return ocrReply(200, `{"status":"succeeded","analyzeResult":{"content":"Azure text"}}`, nil), nil
		})}
		text, e := cloudOCRPage(context.Background(), client, azureOCR(), "", []byte("PNG"))
		if e != nil || text != "Azure text" || calls != 2 {
			t.Fatal(text, e, calls)
		}
	})
	t.Run("azure refuses foreign polling URL", func(t *testing.T) {
		const results = "https://work.cognitiveservices.azure.com/documentintelligence/documentModels/prebuilt-read/analyzeResults/"
		for _, location := range []string{"https://evil.invalid/collect", "http://work.cognitiveservices.azure.com/documentintelligence/documentModels/prebuilt-read/analyzeResults/id", "https://work.cognitiveservices.azure.com:8443/documentintelligence/documentModels/prebuilt-read/analyzeResults/id", "https://work.cognitiveservices.azure.com/collect",
			// The key, as written or encoded, anywhere in the header.
			results + "id?echo=private-secret", results + "id?echo=private%2Dsecret", results + "id?api-version=2024-11-30&echo=private%252Dsecret&x=private-sec%0Aret", results + "private-secret", results + "id#private-secret", "https://private-secret@work.cognitiveservices.azure.com/documentintelligence/documentModels/prebuilt-read/analyzeResults/id",
			// An identifier of another shape.
			results + "id/more", results + "id%2Fmore", results + "", results + "%2e%2e"} {
			calls := 0
			client := &http.Client{Transport: ocrTransport(func(r *http.Request) (*http.Response, error) {
				calls++
				return ocrReply(202, "", http.Header{"Operation-Location": []string{location}}), nil
			})}
			_, e := cloudOCRPage(context.Background(), client, azureOCR(), "", []byte("PNG"))
			if e != ErrProvider || calls != 1 {
				t.Fatal("credential sent to a polling URL off its endpoint", location)
			}
		}
	})
	t.Run("azure polling ends with its context", func(t *testing.T) {
		client := &http.Client{Transport: ocrTransport(func(r *http.Request) (*http.Response, error) {
			if r.Method == "POST" {
				return ocrReply(202, "", http.Header{"Operation-Location": []string{"https://work.cognitiveservices.azure.com/documentintelligence/documentModels/prebuilt-read/analyzeResults/id"}}), nil
			}
			return ocrReply(200, `{"status":"running"}`, nil), nil
		})}
		ctx, cancel := context.WithTimeout(context.Background(), 1500*time.Millisecond)
		defer cancel()
		start := time.Now()
		if _, e := cloudOCRPage(ctx, client, azureOCR(), "", []byte("PNG")); e != ErrCanceled || time.Since(start) > 3*time.Second {
			t.Fatal("polling outlived its deadline", e)
		}
	})
	t.Run("errors redact response", func(t *testing.T) {
		client := &http.Client{Transport: ocrTransport(func(r *http.Request) (*http.Response, error) { return ocrReply(403, `private-secret`, nil), nil })}
		_, e := cloudOCRPage(context.Background(), client, azureOCR(), "", []byte("PNG"))
		if e != Error("credentials-required") || strings.Contains(e.Error(), "private-secret") {
			t.Fatal(e)
		}
	})
	t.Run("an echoed secret is not text", func(t *testing.T) {
		for _, c := range []struct {
			conn  OCRConnection
			token string
			reply string
		}{
			{OCRConnection{Kind: "google-document-ai", Project: "demo", Location: "eu", Processor: "123"}, "access-token-value", `{"document":{"text":"seen access-token-value"}}`},
			{OCRConnection{Kind: "aws-textract", Region: "us-east-1", Credential: `{"accessKeyId":"id","secretAccessKey":"secret-key-value","sessionToken":"temporary"}`}, "", `{"Blocks":[{"BlockType":"LINE","Text":"secret-key-value"}]}`},
		} {
			client := &http.Client{Transport: ocrTransport(func(r *http.Request) (*http.Response, error) { return ocrReply(200, c.reply, nil), nil })}
			if text, e := cloudOCRPage(context.Background(), client, c.conn, c.token, []byte("PNG")); e != ErrProvider || text != "" {
				t.Fatal("a reply holding the credential was taken as text", c.conn.Kind)
			}
		}
		calls := 0
		client := &http.Client{Transport: ocrTransport(func(r *http.Request) (*http.Response, error) {
			calls++
			if calls == 1 {
				return ocrReply(202, "", http.Header{"Operation-Location": []string{"https://work.cognitiveservices.azure.com/documentintelligence/documentModels/prebuilt-read/analyzeResults/id"}}), nil
			}
			return ocrReply(200, `{"status":"succeeded","analyzeResult":{"content":"key private-secret"}}`, nil), nil
		})}
		if _, e := cloudOCRPage(context.Background(), client, azureOCR(), "", []byte("PNG")); e != ErrProvider {
			t.Fatal("an Azure reply holding the key was taken as text")
		}
	})
	// JSON decoding rebuilds an escaped secret, and a record joins lines and
	// drops controls: the text is held as decoded, in a record's form.
	t.Run("an escaped or split secret is not text", func(t *testing.T) {
		google := OCRConnection{Kind: "google-document-ai", Project: "demo", Location: "eu", Processor: "123"}
		textract := OCRConnection{Kind: "aws-textract", Region: "us-east-1", Credential: `{"accessKeyId":"id","secretAccessKey":"secret-key-value","sessionToken":"temporary-session"}`}
		for _, c := range []struct {
			name   string
			conn   OCRConnection
			token  string
			reply  string
			others []string
		}{
			{"escaped token", google, "access-token-value", `{"document":{"text":"seen access\u002dtoken\u002dvalue"}}`, nil},
			{"token broken by a control", google, "access-token-value", `{"document":{"text":"access-tok\u0001en-value"}}`, nil},
			{"token split by a zero-width space", google, "access-token-value", `{"document":{"text":"access-tok\u200ben-value"}}`, nil},
			{"secret key split across lines", textract, "", `{"Blocks":[{"BlockType":"LINE","Text":"secret-key-"},{"BlockType":"LINE","Text":"value"}]}`, nil},
			{"escaped session token", textract, "", `{"Blocks":[{"BlockType":"LINE","Text":"temporary\u002dsession"}]}`, nil},
			{"another processor's secret", google, "access-token-value", `{"document":{"text":"key of another: other-secret-value"}}`, []string{"other-secret-value"}},
		} {
			client := &http.Client{Transport: ocrTransport(func(r *http.Request) (*http.Response, error) { return ocrReply(200, c.reply, nil), nil })}
			if text, e := cloudOCRPage(context.Background(), client, c.conn, c.token, []byte("PNG"), c.others...); e != ErrProvider || text != "" {
				t.Errorf("%s: taken as text %q", c.name, text)
			}
		}
		calls := 0
		client := &http.Client{Transport: ocrTransport(func(r *http.Request) (*http.Response, error) {
			calls++
			if calls == 1 {
				return ocrReply(202, "", http.Header{"Operation-Location": []string{"https://work.cognitiveservices.azure.com/documentintelligence/documentModels/prebuilt-read/analyzeResults/id"}}), nil
			}
			return ocrReply(200, `{"status":"succeeded","analyzeResult":{"content":"key private\u002dsec\nret"}}`, nil), nil
		})}
		if _, e := cloudOCRPage(context.Background(), client, azureOCR(), "", []byte("PNG")); e != ErrProvider {
			t.Error("an escaped, split Azure key was taken as text")
		}
		if got := secretsOf(OCRConnection{Kind: "google-document-ai", Credential: `{"private_key":"-----BEGIN PRIVATE KEY-----\nAAAA\nBBBB\n-----END PRIVATE KEY-----\n"}`}); len(got) != 1 || got[0] != "AAAABBBB" {
			t.Errorf("a service account's key is held as %q", got)
		}
	})
	t.Run("an oversized reply or image is refused", func(t *testing.T) {
		client := &http.Client{Transport: ocrTransport(func(r *http.Request) (*http.Response, error) {
			return ocrReply(200, `{"document":{"text":"`+strings.Repeat("a", 8<<20)+`"}}`, nil), nil
		})}
		if _, e := cloudOCRPage(context.Background(), client, OCRConnection{Kind: "google-document-ai", Project: "demo", Location: "eu", Processor: "123"}, "access", []byte("PNG")); e != ErrProvider {
			t.Fatal("reply past 8 MiB taken", e)
		}
		if _, e := cloudOCRPage(context.Background(), client, azureOCR(), "", make([]byte, cloudImageBytes+1)); e != ErrLimit {
			t.Fatal("image past its bound sent", e)
		}
	})
}

// The production client follows no redirect: the key goes to the host the
// connection names and to no other.
func TestCloudOCRClientDoesNotFollowRedirects(t *testing.T) {
	var elsewhere atomic.Int32
	other := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { elsewhere.Add(1) }))
	defer other.Close()
	named := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, other.URL+"/collect", http.StatusTemporaryRedirect)
	}))
	defer named.Close()
	client := ocrHTTPClient()
	if client.Timeout <= 0 || client.Timeout > 120*time.Second {
		t.Fatal("cloud requests have no overall deadline")
	}
	roots := named.Client().Transport.(*http.Transport).TLSClientConfig.RootCAs
	client.Transport.(*http.Transport).TLSClientConfig = &tls.Config{RootCAs: roots}
	req, _ := http.NewRequest("POST", named.URL+"/analyze", strings.NewReader("{}"))
	req.Header.Set("Ocp-Apim-Subscription-Key", "private-secret")
	if _, _, e := ocrResponse(client, req, 200, "private-secret"); e != ErrProvider || elsewhere.Load() != 0 {
		t.Fatal("a redirect was followed", e, elsewhere.Load())
	}
	if client.Transport.(*http.Transport).Proxy != nil {
		t.Fatal("cloud requests read a proxy from the environment")
	}
}

// A worker refuses, before any request is made, what its arguments, its
// settings or its operator do not allow.
func TestRunCloudOCRRefusesBeforeAnyRequest(t *testing.T) {
	b, dir := processingBroker(t)
	base := processingState(t, b)
	c := base.ProcessingConfig
	local := OCRConnection{ID: "local", Name: "Local", Kind: "tesseract", Enabled: true}
	off := azureOCR()
	off.ID, off.Enabled = "ocr-off", false
	c.Connections = []OCRConnection{azureOCR(), local, off}
	c.Mode, c.Connection = "auto", "ocr-azure"
	saved := processingSave(t, b, base, c)
	rev := saved.SHA256
	pdf := strings.NewReader("%PDF-1.4")
	run := func(args ...string) error {
		var out bytes.Buffer
		e := RunCloudOCR(context.Background(), args[0], args[1], args[2:], pdf, &out)
		if out.Len() != 0 {
			t.Fatal("a refused run wrote an answer")
		}
		return e
	}
	t.Setenv("JPACK_CONNECTIONS_DIR", "")
	if run("ocr-azure", rev, "1") == nil {
		t.Fatal("ran without the settings directory")
	}
	t.Setenv("JPACK_CONNECTIONS_DIR", dir)
	for _, args := range [][]string{{"ocr-azure", rev}, {"ocr-azure", "", "1"}, {"ocr-azure", rev, "0"}, {"ocr-azure", rev, "501"}, {"ocr-azure", rev, "1", "1"}, {"ocr-azure", rev, "one"}, {"../x", rev, "1"}} {
		if run(args...) != ErrRequest {
			t.Fatal("page or connection arguments accepted", args)
		}
	}
	if run("local", rev, "1") != Error("processing-unavailable") || run("ocr-off", rev, "1") != Error("processing-unavailable") || run("missing", rev, "1") != Error("processing-unavailable") {
		t.Fatal("a worker ran a connection that is not an enabled cloud processor")
	}
	if run("ocr-azure", base.SHA256, "1") != Error("processing-changed") {
		t.Fatal("a worker ran under another revision")
	}
	blocked := NewProcessing(b.store, true)
	blocked.Handle(context.Background(), "status", []byte(`{}`))
	if run("ocr-azure", rev, "1") != ErrPolicy {
		t.Fatal("a worker ran with its store blocked")
	}
}

// mainLocalPlan is the plan as main served it before document processing,
// byte for byte.
const mainLocalPlan = `{"version":1,"sources":[` +
	`{"id":"documents","executable":"adapter-document","args":["--max-bytes","16777216","--max-output","8388608","--timeout","30s"],"shape":"command","timeout":40,"connections":false},` +
	`{"id":"render","executable":"adapter-render","args":["--max-output","6291456"],"shape":"command","timeout":30,"connections":false},` +
	`{"id":"drive","executable":"adapter-drive","args":["--principal","desk-local"],"shape":"http","timeout":60,"connections":true},` +
	`{"id":"gmail","executable":"adapter-gmail","args":["--principal","desk-local"],"shape":"http","timeout":60,"connections":true},` +
	`{"id":"notion","executable":"adapter-sources","args":["--provider","notion","--principal","desk-local"],"shape":"mcp","timeout":60,"connections":true},` +
	`{"id":"obsidian","executable":"adapter-sources","args":["--provider","obsidian","--principal","desk-local"],"shape":"command","timeout":60,"connections":true},` +
	`{"id":"web","executable":"adapter-web","args":[],"shape":"http","timeout":60,"connections":false},` +
	`{"id":"web-discovery","executable":"adapter-web","args":["--discover"],"shape":"http","timeout":60,"connections":false},` +
	`{"id":"web-search","executable":"adapter-sources","args":["--provider","web-search","--principal","desk-local"],"shape":"http","timeout":60,"connections":true},` +
	`{"id":"aws-s3","executable":"adapter-sources","args":["--provider","aws-s3","--principal","desk-local"],"shape":"command","timeout":60,"connections":true}]}`

// With no processor configured the plan is main's, so every released desk
// takes it; with one, only the sources that may read a PDF change.
func TestThePlanChangesOnlyWhileAProcessorIsConfigured(t *testing.T) {
	for _, plan := range []LocalPlan{ConnectionLocalPlan(), ConnectionLocalPlanWith(false)} {
		if raw, _ := json.Marshal(plan); string(raw) != mainLocalPlan {
			t.Fatalf("the plan without processing is not main's:\n%s", raw)
		}
	}
	off, on := ConnectionLocalPlanWith(false), ConnectionLocalPlanWith(true)
	ocr := map[string]bool{"documents": true, "drive": true, "web": true, "aws-s3": true}
	for i, s := range on.Sources {
		was := off.Sources[i]
		if !ocr[s.ID] {
			a, _ := json.Marshal(s)
			b, _ := json.Marshal(was)
			if string(a) != string(b) {
				t.Errorf("%s changed with processing", s.ID)
			}
			continue
		}
		if s.Timeout != 150 || !s.Connections || len(s.Args) != len(was.Args)+1 || s.Args[len(s.Args)-1] != "--document-processing" || strings.Join(s.Args[:len(was.Args)], " ") != strings.Join(was.Args, " ") {
			t.Errorf("%s = %+v", s.ID, s)
		}
	}
	if ProcessingMaxTimeoutSeconds*time.Second+20*time.Second > ProcessingAdapterTimeout || ProcessingAdapterTimeout+10*time.Second > ProcessingSourceSeconds*time.Second {
		t.Fatal("the processing deadline leaves the adapters no room inside the plan")
	}
	if raw, _ := json.Marshal(off); string(raw) != mainLocalPlan {
		t.Fatal("building the processing plan changed the plan without it")
	}
}

// tree lists every name under dir with its mode, size and time.
func tree(t *testing.T, dir string) string {
	t.Helper()
	var b strings.Builder
	filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			t.Fatal(err)
		}
		st, _ := os.Lstat(path)
		fmt.Fprintf(&b, "%s %v %d %d\n", path, st.Mode(), st.Size(), st.ModTime().UnixNano())
		return nil
	})
	return b.String()
}

// The plan reads the settings as they stand, creating, locking and writing
// nothing; settings that are there and cannot be read count as configured.
func TestProcessingConfiguredReadsWithoutWriting(t *testing.T) {
	empty := t.TempDir()
	os.Chmod(empty, 0700)
	for _, dir := range []string{"", "relative", filepath.Join(empty, "absent"), empty} {
		if ProcessingConfigured(dir) {
			t.Fatalf("%q reads as configured", dir)
		}
	}
	if entries, _ := os.ReadDir(empty); len(entries) != 0 {
		t.Fatal("the plan created custody")
	}
	b, dir := processingBroker(t)
	base := processingState(t, b)
	if ProcessingConfigured(dir) {
		t.Fatal("no settings file reads as configured")
	}
	c := base.ProcessingConfig
	c.Connections = []OCRConnection{{ID: "local", Name: "Local", Kind: "tesseract", Enabled: true}}
	c.Connection = "local"
	off := processingSave(t, b, base, c)
	before := tree(t, dir)
	if ProcessingConfigured(dir) || tree(t, dir) != before {
		t.Fatal("settings that are off read as configured, or the read wrote")
	}
	c = asSent(off.ProcessingConfig)
	c.Mode = "auto"
	processingSave(t, b, off, c)
	before = tree(t, dir)
	if !ProcessingConfigured(dir) || tree(t, dir) != before {
		t.Fatal("a configured processor is not seen, or the read wrote")
	}
	if e := b.store.write("processing.json", map[string]any{"version": 2}); e != nil {
		t.Fatal(e)
	}
	if !ProcessingConfigured(dir) {
		t.Fatal("settings that cannot be read were taken for none")
	}
	os.Chmod(dir, 0755)
	defer os.Chmod(dir, 0700)
	if !ProcessingConfigured(dir) {
		t.Fatal("a store that fails custody was taken for none")
	}
}

// A record names the processor's kind, the program's file name and its
// digest, and no part of the directory it ran from, which here names a
// person.
func TestARecordNamesNoDirectoryOfItsWorker(t *testing.T) {
	b, dir := processingBroker(t)
	t.Setenv("JPACK_CONNECTIONS_DIR", dir)
	home := filepath.Join(t.TempDir(), "home", "jane-doe-example", "desk", "ocr-tools", "usr", "bin")
	if e := os.MkdirAll(home, 0700); e != nil {
		t.Fatal(e)
	}
	useBundle(t, filepath.Dir(filepath.Dir(home)))
	program := filepath.Join(home, "ocr-fixture")
	body := []byte("#!/bin/sh\n/bin/cat >/dev/null\nprintf '{\"pages\":[{\"number\":1,\"text\":\"Scanned text\"}]}'\n")
	if e := os.WriteFile(program, body, 0700); e != nil {
		t.Fatal(e)
	}
	base := processingState(t, b)
	c := base.ProcessingConfig
	c.Connections = []OCRConnection{{ID: "local", Name: "Local", Kind: "program", Program: program, Enabled: true}}
	c.Mode, c.Connection = "auto", "local"
	processingSave(t, b, base, c)
	cfg := document.DefaultConfig()
	if e := ApplyDocumentProcessing(managed, &cfg); e != nil {
		t.Fatal(e)
	}
	pdf, e := os.ReadFile("../document/testdata/scanned.pdf")
	if e != nil {
		t.Fatal(e)
	}
	identity, _ := document.OwnIdentity()
	started := time.Now()
	raw, e := processDriveDocument(context.Background(), cfg, document.Request{Name: "scan.pdf", MediaType: "application/pdf", Bytes: pdf, SHA256: digest(pdf), OCR: "auto", ReceivedAt: started}, identity, started)
	if e != nil {
		t.Fatal(e)
	}
	var record struct {
		Provenance struct {
			OCR *struct {
				Program string `json:"program"`
				Digest  string `json:"digest"`
			} `json:"ocr"`
		} `json:"provenance"`
	}
	if json.Unmarshal(raw, &record) != nil || record.Provenance.OCR == nil {
		t.Fatal("no OCR applied")
	}
	if record.Provenance.OCR.Program != "program:ocr-fixture" || record.Provenance.OCR.Digest != digest(body) {
		t.Fatal("the record does not name the kind, file name and digest", record.Provenance.OCR)
	}
	for _, part := range []string{"jane-doe-example", home, filepath.Dir(home), t.TempDir()[:len(t.TempDir())-len(filepath.Base(t.TempDir()))]} {
		if strings.Contains(string(raw), part) {
			t.Fatalf("the record names %q", part)
		}
	}
}

// The settings' revision, a digest over the file that holds the credentials,
// reaches the cloud worker in its environment: its argument list, which every
// process on the host can read, holds the page numbers alone.
func TestTheCloudWorkerIsGivenNoDigestAsAnArgument(t *testing.T) {
	b, dir := processingBroker(t)
	t.Setenv("JPACK_CONNECTIONS_DIR", dir)
	base := processingState(t, b)
	c := base.ProcessingConfig
	c.Connections = []OCRConnection{azureOCR()}
	c.Mode, c.Connection = "auto", "ocr-azure"
	saved := processingSave(t, b, base, c)
	cfg := document.DefaultConfig()
	if e := ApplyDocumentProcessing(managed, &cfg); e != nil {
		t.Fatal(e)
	}
	// The worker is a stand-in that writes down what it was given.
	seen := t.TempDir()
	cfg.OCR = filepath.Join(seen, "ocr-cloud")
	script := "#!/bin/sh\nprintf '%s\\n' \"$0\" \"$@\" > " + seen + "/argv\nprintf '%s\\n' \"$JPACK_OCR_CONNECTION\" \"$JPACK_OCR_REVISION\" > " + seen + "/env\n/bin/cat >/dev/null\nprintf '{\"pages\":[{\"number\":1,\"text\":\"Scanned\"}]}'\n"
	if e := os.WriteFile(cfg.OCR, []byte(script), 0700); e != nil {
		t.Fatal(e)
	}
	pdf, e := os.ReadFile("../document/testdata/scanned.pdf")
	if e != nil {
		t.Fatal(e)
	}
	identity, _ := document.OwnIdentity()
	started := time.Now()
	if _, e = processDriveDocument(context.Background(), cfg, document.Request{Name: "scan.pdf", MediaType: "application/pdf", Bytes: pdf, SHA256: digest(pdf), OCR: "auto", ReceivedAt: started}, identity, started); e != nil {
		t.Fatal(e)
	}
	argv, _ := os.ReadFile(filepath.Join(seen, "argv"))
	env, _ := os.ReadFile(filepath.Join(seen, "env"))
	if len(argv) == 0 || regexp.MustCompile(`[0-9a-f]{64}`).Match(argv) || strings.Contains(string(argv), "ocr-azure") {
		t.Fatalf("the worker's arguments carry the processor or a digest: %q", argv)
	}
	words := strings.Split(strings.TrimSpace(string(argv)), "\n")
	if words[0] != cfg.OCR || len(words) < 2 {
		t.Fatalf("the worker's arguments are not its name and page numbers: %q", argv)
	}
	for _, page := range words[1:] {
		if !regexp.MustCompile(`^[1-9][0-9]{0,2}$`).MatchString(page) {
			t.Fatalf("the worker was given %q, not a page number", page)
		}
	}
	if string(env) != "ocr-azure\n"+saved.SHA256+"\n" {
		t.Fatalf("the worker's environment lacks the processor and revision: %q", env)
	}
}

// A program processor runs only from the OCR tools bundle or /usr/bin, after
// every symlink is resolved; any other is refused at configure by one token,
// with the settings left as they were, and again before a run.
func TestAProgramRunsOnlyFromTheBundleOrUsrBin(t *testing.T) {
	b, dir := processingBroker(t)
	t.Setenv("JPACK_CONNECTIONS_DIR", dir)
	root := t.TempDir()
	bundle := filepath.Join(root, "desk", "ocr-tools")
	outside := filepath.Join(root, "home", "jane-doe-example", "bin")
	for _, d := range []string{filepath.Join(bundle, "usr", "bin"), outside} {
		if e := os.MkdirAll(d, 0700); e != nil {
			t.Fatal(e)
		}
	}
	useBundle(t, bundle)
	body := []byte("#!/bin/sh\n/bin/cat >/dev/null\nprintf '{\"pages\":[]}'\n")
	inBundle := filepath.Join(bundle, "usr", "bin", "ocr")
	atHome := filepath.Join(outside, "ocr")
	for _, p := range []string{inBundle, atHome} {
		if e := os.WriteFile(p, body, 0700); e != nil {
			t.Fatal(e)
		}
	}
	link := filepath.Join(bundle, "usr", "bin", "ocr-link")
	if e := os.Symlink(atHome, link); e != nil {
		t.Fatal(e)
	}
	base := processingState(t, b)
	for _, program := range []string{atHome, "bin/ocr", "ocr", link, "/usr/bin/../bin/x", bundle + "/usr/bin/../bin/ocr", filepath.Join(bundle, "usr", "bin", "missing"), bundle} {
		c := base.ProcessingConfig
		c.Connections = []OCRConnection{{ID: "local", Name: "Local", Kind: "program", Program: program, Enabled: true}}
		if _, e := processingTry(b, base, c); e != ErrProgramPlace {
			t.Errorf("program %q: %v", program, e)
		}
	}
	if processingState(t, b).SHA256 != base.SHA256 {
		t.Fatal("a refused program changed the settings")
	}
	c := base.ProcessingConfig
	c.Connections = []OCRConnection{{ID: "local", Name: "Local", Kind: "program", Program: inBundle, Enabled: true}}
	c.Mode, c.Connection = "auto", "local"
	saved := processingSave(t, b, base, c)
	if !saved.Connections[0].Ready {
		t.Fatal("a bundle program is not ready")
	}
	cfg := document.DefaultConfig()
	if e := ApplyDocumentProcessing(managed, &cfg); e != nil || cfg.OCR != inBundle {
		t.Fatal("a bundle program was not applied", e)
	}
	// Replaced since by a link to the outside, it is refused before a run.
	os.Remove(inBundle)
	if e := os.Symlink(atHome, inBundle); e != nil {
		t.Fatal(e)
	}
	cfg = document.DefaultConfig()
	if e := ApplyDocumentProcessing(managed, &cfg); e != ErrProgramPlace || cfg.OCR != "" {
		t.Fatal("a program that now resolves outside the bundle was applied", e)
	}
	if processingState(t, b).Connections[0].Ready {
		t.Fatal("a program that now resolves outside the bundle is ready")
	}
}
