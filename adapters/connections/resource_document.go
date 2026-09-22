package connections

import (
	"adapters/attachment"
	"adapters/document"
	"adapters/internal/canon"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"time"
)

// ResourceDocument is the common retained-file contract for future connection
// adapters. The caller must first consume and validate its selection grant and
// bound the upstream read. This function does not acquire or authorize a source.
func ResourceDocument(ctx context.Context, provider, resourceID, name, mediaType, sourceURL string, data []byte) ([]byte, error) {
	source := attachment.Source{Kind: attachment.SourceResource, Provider: provider, ResourceID: resourceID, URL: sourceURL, Version: digest(data), Format: "retained-file-v1"}
	if len(data) == 0 || len(data) > MaxFileBytes || !attachment.ValidResourceSource(source) {
		return nil, ErrRequest
	}
	identity, err := document.OwnIdentity()
	if err != nil {
		return nil, Error("processing-failed")
	}
	identity.Name = "adapter-sources"
	cfg := document.DefaultConfig()
	cfg.MaxBytes = MaxFileBytes
	cfg.OCR = ""
	cfg.MaxOutput = 8 << 20
	started := time.Now()
	raw, err := processDriveDocument(ctx, cfg, document.Request{Name: name, MediaType: mediaType, Bytes: data, SHA256: digest(data), OCR: "never", ReceivedAt: started}, identity, started)
	if err != nil {
		return nil, err
	}
	var record map[string]any
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if decoder.Decode(&record) != nil {
		return nil, Error("processing-failed")
	}
	record["document"].(map[string]any)["version"] = source.Version
	record["original"] = map[string]any{"retention": "inline", "encoding": "base64", "bytes": base64.StdEncoding.EncodeToString(data)}
	record["provenance"].(map[string]any)["source"] = map[string]any{"kind": source.Kind, "provider": provider, "resourceId": resourceID, "url": sourceURL, "version": source.Version, "format": source.Format}
	out, err := canon.EncodeJSON(record)
	if err != nil || len(out) > MaxOutputBytes || attachment.Check(out) != nil {
		return nil, Error("processing-failed")
	}
	return out, nil
}
