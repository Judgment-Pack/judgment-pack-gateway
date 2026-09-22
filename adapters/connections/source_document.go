package connections

import (
	"adapters/attachment"
	"adapters/document"
	"adapters/internal/canon"
	"context"
	"encoding/base64"
	"encoding/json"
	"strings"
	"time"
	"unicode/utf8"
)

// Preserve the returned text as a snapshot. Its version is a content digest,
// not an assertion that the live resource is immutable or complete.
func sourceDocument(ctx context.Context, provider, id, title, sourceURL string, data []byte, statement any, endpoint string) ([]byte, error) {
	if len(data) == 0 || len(data) > MaxFileBytes || !utf8.Valid(data) {
		return nil, ErrLimit
	}
	identity, err := document.OwnIdentity()
	if err != nil {
		return nil, Error("processing-failed")
	}
	identity.Name = "adapter-sources"
	name := strings.Join(strings.Fields(title), " ")
	if name == "" {
		name = provider
	}
	for len(name) > 220 {
		_, size := utf8.DecodeLastRuneInString(name)
		name = name[:len(name)-size]
	}
	name += ".txt"
	started := time.Now()
	cfg := document.DefaultConfig()
	cfg.MaxBytes = MaxFileBytes
	cfg.OCR = ""
	cfg.MaxOutput = 8 << 20
	encoded, err := processDriveDocument(ctx, cfg, document.Request{Name: name, MediaType: "text/plain", Bytes: data, SHA256: digest(data), OCR: "never", ReceivedAt: started}, identity, started)
	if err != nil {
		return nil, Error("processing-failed")
	}
	var record map[string]any
	d := json.NewDecoder(strings.NewReader(string(encoded)))
	d.UseNumber()
	if d.Decode(&record) != nil {
		return nil, Error("processing-failed")
	}
	record["document"].(map[string]any)["version"] = digest(data)
	record["original"] = map[string]any{"retention": "inline", "encoding": "base64", "bytes": base64.StdEncoding.EncodeToString(data)}
	record["provenance"].(map[string]any)["source"] = map[string]any{"kind": "connected-source", "provider": provider, "resourceId": id, "url": sourceURL, "version": digest(data), "format": "text-snapshot-v1"}
	checked, err := canon.EncodeJSON(record)
	if err != nil || attachment.Check(checked) != nil {
		return nil, Error("processing-failed")
	}
	if provider == "obsidian" {
		return checked, nil
	}
	stmt, err := canon.EncodeJSON(statement)
	if err != nil {
		return nil, ErrRequest
	}
	acquisition := map[string]any{"adapter": identity, "endpoint": endpoint, "statement": string(stmt), "snapshot": digest(data), "peerIdentity": nil, "schema": nil, "upstreamToken": nil, "observedAt": started.UTC().Format("2006-01-02T15:04:05Z")}
	out, err := canon.EncodeJSON(map[string]any{"acquisition": acquisition, "result": record})
	if err != nil {
		return nil, Error("processing-failed")
	}
	if len(out) > MaxOutputBytes {
		return nil, ErrLimit
	}
	return out, nil
}
