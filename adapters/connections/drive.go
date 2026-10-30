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

func (p provider) metadata(ctx context.Context, token, id string, guard func() error) (metadata, error) {
	raw, _, err := p.guardedDriveRequest(ctx, p.api+"/files/"+id+"?supportsAllDrives=true&fields=id,name,mimeType,version,size,trashed,capabilities(canDownload)", token, 64<<10, guard)
	var m metadata
	if err != nil {
		return m, err
	}
	if json.Unmarshal(raw, &m) != nil || m.ID != id || !readableName(m.Name) || !resourceText(m.Version, 32, false) || m.Trashed || !m.Capabilities.CanDownload {
		return m, ErrUnsupported
	}
	return m, nil
}

// readableName is what a file's name must be for the file to be read: not
// empty, of at most 250 bytes, and with no control character in it.
func readableName(name string) bool {
	if name == "" || len(name) > 250 || strings.ContainsRune(name, 0x7f) {
		return false
	}
	for _, r := range name {
		if r < 32 {
			return false
		}
	}
	return true
}

// readableSize is what a file's size must be for the file to be read. A
// document of Google's own has no size to say before it is exported.
func readableSize(media, size string) bool {
	if strings.HasPrefix(media, "application/vnd.google-apps.") {
		return true
	}
	n, e := strconv.ParseInt(size, 10, 64)
	return e == nil && n > 0 && n <= MaxFileBytes
}
func Read(ctx context.Context, s *Store, raw []byte) ([]byte, error) {
	return google().read(ctx, s, raw)
}
func (p provider) read(ctx context.Context, s *Store, raw []byte) ([]byte, error) {
	var req ReadRequest
	if decode(raw, &req) != nil || !opaque.MatchString(req.Grant) || !identifier.MatchString(req.FileID) {
		return nil, ErrRequest
	}
	client, credentialSnapshot, epoch, err := s.consumeGrant(req.Grant, req.FileID)
	if err != nil {
		return nil, err
	}
	if ctx, err = s.grantUse(ctx, p, p.kind(), "read"); err != nil {
		return nil, err
	}
	return p.readDriveDocument(ctx, s, req.FileID, client, credentialSnapshot, epoch, func() error {
		return s.checkConnection(credentialSnapshot, epoch)
	}, nil)
}

type driveReadProfile struct{ requestedOCR string }

// readDriveDocument is the same acquisition for a one-use selection and a
// recurring host binding. The caller supplies the current authority check;
// neither the attachment nor its acquisition envelope carries that authority.
func (p provider) readDriveDocument(ctx context.Context, s *Store, fileID string, client Client, credentialSnapshot credential, epoch string, guard func() error, profile *driveReadProfile) ([]byte, error) {
	if err := guard(); err != nil {
		return nil, err
	}
	token, err := p.access(ctx, s, client, credentialSnapshot, epoch)
	if current := guard(); current != nil {
		return nil, current
	}
	if err != nil {
		return nil, err
	}
	before, err := p.metadata(ctx, token, fileID, guard)
	if err != nil {
		return nil, err
	}
	media, name := before.MediaType, before.Name
	path := "/files/" + fileID
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
	data, response, err := p.guardedDriveRequest(ctx, p.api+path+"?"+query.Encode(), token, MaxFileBytes, guard)
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
	after, err := p.metadata(ctx, token, fileID, guard)
	if err != nil {
		return nil, err
	}
	if before.Version != after.Version || before.MediaType != after.MediaType || before.Name != after.Name || before.Size != after.Size {
		return nil, ErrChanged
	}
	identity, err := document.OwnIdentity()
	if err != nil {
		return nil, Error("processing-failed")
	}
	identity.Name = "adapter-drive"
	cfg := document.DefaultConfig()
	cfg.MaxBytes = MaxFileBytes
	if err := ApplyDocumentProcessing(ctx, &cfg); err != nil {
		return nil, err
	}
	cfg.MaxOutput = 8 << 20
	started := time.Now()
	request := document.Request{Name: name, MediaType: media, Bytes: data, SHA256: digest(data), OCR: "auto", ReceivedAt: started}
	if profile != nil {
		profile.requestedOCR = request.OCR
	}
	encoded, err := processDriveDocument(ctx, cfg, request, identity, started)
	if current := guard(); current != nil {
		return nil, current
	}
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
	record["provenance"].(map[string]any)["source"] = map[string]any{"kind": "google-drive", "fileId": fileID, "version": before.Version, "mediaType": before.MediaType}
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
	if err := guard(); err != nil {
		return nil, err
	}
	return out, nil
}

// Every provider read is bracketed by current custody checks, including a
// failed I/O. A removal/reconnect wins over an otherwise usable response.
func (p provider) guardedDriveRequest(ctx context.Context, endpoint, token string, max int64, guard func() error) ([]byte, *http.Response, error) {
	if err := guard(); err != nil {
		return nil, nil, err
	}
	raw, response, err := p.request(ctx, "GET", endpoint, token, nil, max)
	if current := guard(); current != nil {
		return nil, nil, current
	}
	return raw, response, err
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

// The processing bound recorded in the attachment must be the deadline actually
// applied, independently of the outer retrieval deadline.
func processDriveDocument(ctx context.Context, cfg document.Config, request document.Request, identity attachment.Identity, started time.Time) ([]byte, error) {
	processing, cancel := context.WithDeadline(ctx, started.Add(cfg.Timeout))
	defer cancel()
	return document.Process(processing, cfg, request, identity, started)
}

func (s *Store) consumeGrant(token, fileID string) (Client, credential, string, error) {
	var client Client
	var credentialSnapshot credential
	var epoch string
	err := s.locked(func(v *state) error {
		if v.Disabled {
			return ErrPolicy
		}
		b, err := s.read("grant-" + token)
		if err != nil {
			return ErrGrant
		}
		var g grant
		if decode(b, &g) != nil || g.File != fileID || g.Expires <= time.Now().Unix() || v.Connection == nil || v.Connection.ID != g.Connection {
			return ErrGrant
		}
		if s.remove("grant-"+token) != nil {
			return ErrGrant
		}
		client, credentialSnapshot, epoch = v.Client, *v.Connection, v.Epoch
		return nil
	})
	return client, credentialSnapshot, epoch, err
}
