package connections

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

func intString(v int64) string { return strconv.FormatInt(v, 10) }
func (b *Broker) s3StorageList(ctx context.Context, q StorageQuery) (StoragePage, error) {
	out := StoragePage{Items: []StorageFile{}, Scope: "configured-prefix", SearchMode: "names"}
	cfg, _, _, e := s3Snapshot(b.store)
	if e != nil {
		return out, e
	}
	prefix := q.Folder
	if prefix == "" {
		prefix = cfg.Prefix
	}
	if !strings.HasPrefix(prefix, cfg.Prefix) {
		return out, ErrRequest
	}
	objects, next, e := b.provider.s3List(ctx, cfg, prefix, b.storageBrowse.upstream, "", StoragePageItems)
	if e != nil {
		return out, e
	}
	if next != "" && next == b.storageBrowse.upstream {
		return out, ErrProvider
	}
	b.storageBrowse.upstream = next
	for _, obj := range objects {
		if !storageMatch(obj.Key, q.Query) {
			continue
		}
		out.Items = append(out.Items, StorageFile{ID: obj.Key, Name: obj.Key, Kind: "file", Size: obj.Size, Revision: obj.ETag, MediaType: "application/octet-stream", Editable: obj.Size <= MaxFileBytes && obj.unavailable() == "", Deletable: true})
	}
	return b.finishStoragePage(out, next != "")
}
func (b *Broker) s3StorageInspect(ctx context.Context, id string, read bool) (StorageFile, string, []byte, error) {
	var file StorageFile
	cfg, _, _, e := s3Snapshot(b.store)
	if e != nil {
		return file, "", nil, e
	}
	if !resourceText(id, 1024, false) || !strings.HasPrefix(id, cfg.Prefix) {
		return file, "", nil, ErrRequest
	}
	_, h, e := b.provider.s3Request(ctx, cfg, "HEAD", id, nil, "", 0)
	if e != nil {
		return file, "", nil, e
	}
	etag := h.Get("ETag")
	size, e := strconv.ParseInt(h.Get("Content-Length"), 10, 64)
	if e != nil || size < 0 || !validS3ETag(etag) || cfg.leaks([]byte(etag)) || cfg.leaks([]byte(h.Get("Content-Type"))) {
		return file, "", nil, ErrProvider
	}
	media := strings.Split(h.Get("Content-Type"), ";")[0]
	if media == "" {
		media = "application/octet-stream"
	}
	file = StorageFile{ID: id, Name: id, Kind: "file", Size: size, Revision: etag, MediaType: media, Editable: size <= MaxFileBytes, Deletable: true}
	if !read {
		return file, etag, nil, nil
	}
	if size > MaxFileBytes {
		return file, "", nil, ErrLimit
	}
	raw, h, e := b.provider.s3Request(ctx, cfg, "GET", id, nil, etag, MaxFileBytes)
	if e != nil {
		return file, "", nil, e
	}
	if h.Get("ETag") != etag || int64(len(raw)) != size {
		return file, "", nil, ErrChanged
	}
	return file, etag, raw, nil
}
func (p provider) s3StorageWrite(ctx context.Context, c s3Config, q StorageChange, data []byte) (string, error) {
	if c.expired() {
		return "", Error("credentials-required")
	}
	if !strings.HasPrefix(q.ID, c.Prefix) || !resourceText(q.ID, 1024, false) {
		return "", ErrRequest
	}
	endpoint, e := s3URL(c, q.ID, url.Values{})
	if e != nil {
		return "", e
	}
	method := "PUT"
	if q.Action == "delete" {
		method = "DELETE"
		data = nil
	}
	req, e := http.NewRequestWithContext(ctx, method, endpoint.String(), bytes.NewReader(data))
	if e != nil {
		return "", ErrRequest
	}
	sum := sha256.Sum256(data)
	payload := hex.EncodeToString(sum[:])
	req.Header.Set("X-Amz-Content-Sha256", payload)
	if q.Action == "create" {
		req.Header.Set("If-None-Match", "*")
	} else {
		if !validS3ETag(q.Revision) {
			return "", ErrRequest
		}
		req.Header.Set("If-Match", q.Revision)
	}
	if method == "PUT" {
		req.Header.Set("Content-Type", q.MediaType)
	}
	signer := v4.NewSigner(func(o *v4.SignerOptions) { o.DisableURIPathEscaping = true })
	if e = signer.SignHTTP(ctx, aws.Credentials{AccessKeyID: c.AccessKey, SecretAccessKey: c.SecretKey, SessionToken: c.SessionToken}, req, payload, "s3", c.Region, time.Now()); e != nil {
		return "", ErrProvider
	}
	// Deliberately no automatic mutation retry, even on throttling/transport loss.
	res, e := p.client.Do(req)
	if e != nil {
		return "", Error("operation-uncertain")
	}
	defer res.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(res.Body, 16<<10))
	if res.StatusCode == 412 || res.StatusCode == 409 {
		return "", ErrChanged
	}
	if res.StatusCode == 403 {
		return "", Error("permission-required")
	}
	if method == "PUT" && res.StatusCode != 200 || method == "DELETE" && res.StatusCode != 204 {
		return "", Error("operation-uncertain")
	}
	return q.ID, nil
}
