package websource

import (
	"adapters/attachment"
	"adapters/document"
	"adapters/internal/canon"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/url"
	"path"
	"strings"
	"time"
	"unicode/utf8"
)

var ErrRequest = errors.New("web-invalid-request")
var ErrProcessing = errors.New("web-processing-failed")

// Read consumes exactly {"url":"https://..."}. No headers, credentials,
// redirects policy, executable, or network overrides are caller-controlled.
func Read(ctx context.Context, raw []byte) ([]byte, error) {
	return read(ctx, raw, newFetcher())
}
func read(ctx context.Context, raw []byte, f fetcher) ([]byte, error) {
	if len(raw) > 8192 {
		return nil, ErrRequest
	}
	canonical, err := canon.Canonicalize(raw, canon.RefuseNumbers)
	if err != nil {
		return nil, ErrRequest
	}
	var req struct {
		URL string `json:"url"`
	}
	dec := json.NewDecoder(bytes.NewReader(canonical))
	dec.DisallowUnknownFields()
	if dec.Decode(&req) != nil || req.URL == "" {
		return nil, ErrRequest
	}
	// encoding/json is case insensitive; enforce the contract's exact keys.
	var members map[string]any
	if json.Unmarshal(canonical, &members) != nil || len(members) != 1 || members["url"] != req.URL {
		return nil, ErrRequest
	}
	ctx, cancel := context.WithTimeout(ctx, Timeout)
	defer cancel()
	started := time.Now()
	res, err := f.read(ctx, req.URL)
	if err != nil {
		return nil, err
	}
	data, media, format := res.raw, res.media, "original-v1"
	parsed, _ := url.Parse(res.url)
	title := path.Base(parsed.Path)
	if title == "." || title == "/" || title == "" {
		title = parsed.Hostname()
	}
	if media == "text/html" {
		data, title, err = staticText(ctx, data)
		if err != nil {
			return nil, err
		}
		media = "text/plain"
		format = "static-text-v1"
		if title == "" {
			title = parsed.Hostname()
		}
		title += ".txt"
	}
	title = strings.Join(strings.Fields(title), " ")
	for len(title) > 220 {
		_, n := utf8.DecodeLastRuneInString(title)
		title = title[:len(title)-n]
	}
	identity, err := document.OwnIdentity()
	if err != nil {
		return nil, ErrProcessing
	}
	identity.Name = "adapter-web"
	cfg := document.DefaultConfig()
	cfg.MaxBytes = MaxBytes
	cfg.MaxText = MaxBytes
	cfg.MaxOutput = MaxOutput
	cfg.OCR = ""
	processing, stop := context.WithTimeout(ctx, cfg.Timeout)
	defer stop()
	encoded, err := document.Process(processing, cfg, document.Request{Name: title, MediaType: media, Bytes: data, SHA256: digest(data), OCR: "never", ReceivedAt: started}, identity, started)
	if err != nil || ctx.Err() != nil {
		return nil, ErrProcessing
	}
	var record map[string]any
	dec = json.NewDecoder(bytes.NewReader(encoded))
	dec.UseNumber()
	if dec.Decode(&record) != nil {
		return nil, ErrProcessing
	}
	record["document"].(map[string]any)["version"] = digest(data)
	record["original"] = map[string]any{"retention": "inline", "encoding": "base64", "bytes": base64.StdEncoding.EncodeToString(data)}
	record["provenance"].(map[string]any)["source"] = attachment.Source{Kind: attachment.SourceWeb, RequestedURL: req.URL, URL: res.url, Version: digest(data), ResponseDigest: digest(res.raw), MediaType: res.media, Format: format}
	checked, err := canon.EncodeJSON(record)
	if err != nil || attachment.Check(checked) != nil {
		return nil, ErrProcessing
	}
	statement, err := canon.EncodeJSON(map[string]any{"method": "GET", "requestedUrl": req.URL, "url": res.url})
	if err != nil {
		return nil, ErrProcessing
	}
	parsed.RawQuery = ""
	parsed.ForceQuery = false
	acq := map[string]any{"adapter": identity, "endpoint": parsed.String(), "statement": string(statement), "snapshot": digest(res.raw), "peerIdentity": "tls:" + digest(res.tls.PeerCertificates[0].Raw), "schema": nil, "upstreamToken": nil, "observedAt": started.UTC().Format("2006-01-02T15:04:05Z")}
	out, err := canon.EncodeJSON(map[string]any{"acquisition": acq, "result": record})
	if err != nil {
		return nil, ErrProcessing
	}
	if len(out) > MaxOutput {
		return nil, ErrLimit
	}
	return out, nil
}
func digest(data []byte) string {
	hash := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(hash[:])
}
