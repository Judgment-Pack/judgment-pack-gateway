package connections

import (
	"adapters/attachment"
	"adapters/document"
	"adapters/internal/canon"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

type ReadRequest struct {
	Grant  string `json:"grant"`
	FileID string `json:"fileId"`
}
type metadata struct {
	ID           string `json:"id"`
	Name         string `json:"name"`
	MediaType    string `json:"mimeType"`
	Version      string `json:"version"`
	Size         string `json:"size"`
	Trashed      bool   `json:"trashed"`
	Capabilities struct {
		CanDownload bool `json:"canDownload"`
	} `json:"capabilities"`
}

func (p provider) metadata(ctx context.Context, token, id string) (metadata, error) {
	raw, _, err := p.request(ctx, "GET", p.api+"/files/"+id+"?supportsAllDrives=true&fields=id,name,mimeType,version,size,trashed,capabilities(canDownload)", token, nil, 64<<10)
	var m metadata
	if err != nil {
		return m, err
	}
	if json.Unmarshal(raw, &m) != nil || m.ID != id || m.Name == "" || len(m.Name) > 250 || strings.ContainsAny(m.Name, "\x00\r\n\x7f") || m.Version == "" || len(m.Version) > 32 || m.Trashed || !m.Capabilities.CanDownload {
		return m, ErrUnsupported
	}
	for _, r := range m.Name {
		if r < 32 {
			return m, ErrUnsupported
		}
	}
	return m, nil
}
func Read(ctx context.Context, s *Store, raw []byte) ([]byte, error) {
	return google().read(ctx, s, raw)
}
func (p provider) read(ctx context.Context, s *Store, raw []byte) ([]byte, error) {
	var req ReadRequest
	if decode(raw, &req) != nil || !opaque.MatchString(req.Grant) || !identifier.MatchString(req.FileID) {
		return nil, ErrRequest
	}
	var token string
	err := s.locked(func(v *state) error {
		if v.Disabled {
			return ErrPolicy
		}
		b, err := s.read("grant-" + req.Grant)
		if err != nil {
			return ErrGrant
		}
		var g grant
		if decode(b, &g) != nil || g.File != req.FileID || g.Expires <= time.Now().Unix() || v.Connection == nil || v.Connection.ID != g.Connection {
			return ErrGrant
		}
		if s.root.Remove("grant-"+req.Grant) != nil {
			return ErrGrant
		}
		token, err = p.access(ctx, s, v)
		return err
	})
	if err != nil {
		return nil, err
	}
	before, err := p.metadata(ctx, token, req.FileID)
	if err != nil {
		return nil, err
	}
	media, name := before.MediaType, before.Name
	path := "/files/" + req.FileID
	query := url.Values{"alt": {"media"}, "supportsAllDrives": {"true"}}
	switch media {
	case "application/vnd.google-apps.document", "application/vnd.google-apps.spreadsheet", "application/vnd.google-apps.presentation":
		path += "/export"
		media = "application/pdf"
		if !strings.HasSuffix(strings.ToLower(name), ".pdf") {
			name += ".pdf"
		}
		query = url.Values{"mimeType": {media}}
	case "application/pdf", "text/plain", "text/markdown", "text/csv", "application/json":
		size, e := strconv.ParseInt(before.Size, 10, 64)
		if e != nil || size <= 0 || size > MaxFileBytes {
			return nil, ErrLimit
		}
	default:
		return nil, ErrUnsupported
	}
	data, response, err := p.request(ctx, "GET", p.api+path+"?"+query.Encode(), token, nil, MaxFileBytes)
	if err != nil {
		return nil, err
	}
	if len(data) == 0 {
		return nil, ErrUnsupported
	}
	if query.Get("alt") == "media" {
		expected, _ := strconv.ParseInt(before.Size, 10, 64)
		if int64(len(data)) != expected {
			return nil, ErrChanged
		}
	}
	observed := time.Now().UTC().Format("2006-01-02T15:04:05Z")
	after, err := p.metadata(ctx, token, req.FileID)
	if err != nil {
		return nil, err
	}
	if before.Version != after.Version || before.MediaType != after.MediaType || before.Name != after.Name {
		return nil, ErrChanged
	}
	identity, err := document.OwnIdentity()
	if err != nil {
		return nil, Error("processing-failed")
	}
	identity.Name = "adapter-drive"
	cfg := document.DefaultConfig()
	cfg.MaxBytes = MaxFileBytes
	cfg.OCR = ""
	cfg.MaxOutput = 8 << 20
	started := time.Now()
	request := document.Request{Name: name, MediaType: media, Bytes: data, SHA256: digest(data), OCR: "never", ReceivedAt: started}
	encoded, err := document.Process(ctx, cfg, request, identity, started)
	if err != nil {
		return nil, Error("processing-failed")
	}
	var record map[string]any
	dec := json.NewDecoder(strings.NewReader(string(encoded)))
	dec.UseNumber()
	if dec.Decode(&record) != nil {
		return nil, Error("processing-failed")
	}
	record["document"].(map[string]any)["version"] = before.Version
	record["original"] = map[string]any{"retention": "inline", "encoding": "base64", "bytes": base64.StdEncoding.EncodeToString(data)}
	record["provenance"].(map[string]any)["source"] = map[string]any{"kind": "google-drive", "fileId": req.FileID, "version": before.Version, "mediaType": before.MediaType}
	recordBytes, e := canon.EncodeJSON(record)
	if e != nil || attachment.Check(recordBytes) != nil {
		return nil, Error("processing-failed")
	}
	endpoint, _ := url.Parse(p.api + path)
	statement, _ := canon.EncodeJSON(map[string]any{"method": "GET", "path": endpoint.Path, "query": queryValues(query)})
	acquisition := map[string]any{"adapter": identity, "endpoint": p.api + path, "statement": string(statement), "snapshot": before.Version, "peerIdentity": peer(response), "schema": nil, "upstreamToken": nil, "observedAt": observed}
	out, err := canon.EncodeJSON(map[string]any{"acquisition": acquisition, "result": record})
	if err != nil {
		return nil, Error("processing-failed")
	}
	if len(out) > MaxOutputBytes {
		return nil, ErrLimit
	}
	return out, nil
}
func queryValues(q url.Values) map[string]string {
	m := map[string]string{}
	for k := range q {
		m[k] = q.Get(k)
	}
	return m
}
func peer(r *http.Response) any {
	if r.TLS == nil || len(r.TLS.VerifiedChains) == 0 || len(r.TLS.PeerCertificates) == 0 {
		return nil
	}
	h := sha256.Sum256(r.TLS.PeerCertificates[0].Raw)
	return "tls:sha256:" + hex.EncodeToString(h[:])
}
