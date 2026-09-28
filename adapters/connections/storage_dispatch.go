package connections

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strings"
)

func (b *Broker) storageInspect(ctx context.Context, id, token string, read bool) (StorageFile, string, []byte, error) {
	if b.provider.s3 {
		return b.s3StorageInspect(ctx, id, read)
	}
	if !b.provider.obsidian {
		return b.driveStorageInspect(ctx, id, token, read)
	}
	root, e := b.storageVault()
	if e != nil {
		return StorageFile{}, "", nil, e
	}
	defer root.Close()
	f, data, e := localFile(root, id, read)
	return f, "", data, e
}
func (b *Broker) checkLocalStat(id, revision string) error {
	root, e := b.storageVault()
	if e != nil {
		return e
	}
	defer root.Close()
	if !validStoragePath(id, false) || storageNoLinks(root, id) != nil {
		return ErrRequest
	}
	st, e := root.Lstat(filepath.FromSlash(id))
	if e != nil || !st.Mode().IsRegular() || localStatRevision(st) != revision {
		return ErrChanged
	}
	return nil
}
func (b *Broker) storagePreflight(ctx context.Context, q *StorageChange, token string) (StorageFile, string, error) {
	var file StorageFile
	if q.Action != "create" {
		if q.ID == "" || q.Folder != "" || q.Revision == "" {
			return file, "", ErrRequest
		}
		if b.provider.obsidian && q.Action == "delete" && strings.HasPrefix(q.Revision, "stat:") {
			if e := b.checkLocalStat(q.ID, q.Revision); e != nil {
				return file, "", e
			}
			q.Name = path.Base(q.ID)
			return StorageFile{ID: q.ID, Name: q.Name, Revision: q.Revision, Kind: "file", Deletable: true}, "", nil
		}
		current, etag, _, e := b.storageInspect(ctx, q.ID, token, false)
		if e != nil {
			return file, "", e
		}
		if q.Revision != current.Revision || q.Name != "" && q.Name != current.Name {
			return file, "", ErrChanged
		}
		if current.Kind != "file" || q.Action == "update" && !current.Editable || q.Action == "delete" && !current.Deletable {
			return file, "", ErrUnsupported
		}
		if b.provider.kind() == "google-drive" && !validS3ETag(etag) {
			return file, "", Error("conditional-write-unavailable")
		}
		q.Name = current.Name
		return current, etag, nil
	}
	if q.ID != "" || q.Revision != "" || !resourceText(q.Name, 250, false) || strings.ContainsAny(q.Name, "/\\") || q.Name == "." || q.Name == ".." {
		return file, "", ErrRequest
	}
	if b.provider.obsidian {
		if !validStoragePath(q.Folder, true) {
			return file, "", ErrRequest
		}
		q.ID = path.Join(q.Folder, q.Name)
		if !validStoragePath(q.ID, false) {
			return file, "", ErrRequest
		}
		root, e := b.storageVault()
		if e != nil {
			return file, "", e
		}
		defer root.Close()
		if storageNoLinks(root, path.Dir(q.ID)) != nil {
			return file, "", ErrRequest
		}
		if _, e = root.Lstat(filepath.FromSlash(q.ID)); !errors.Is(e, os.ErrNotExist) {
			return file, "", ErrChanged
		}
	} else if b.provider.s3 {
		cfg, _, _, e := s3Snapshot(b.store)
		if e != nil {
			return file, "", e
		}
		prefix := q.Folder
		if prefix == "" {
			prefix = cfg.Prefix
		}
		if !strings.HasPrefix(prefix, cfg.Prefix) {
			return file, "", ErrRequest
		}
		q.ID = prefix + q.Name
		if !resourceText(q.ID, 1024, false) {
			return file, "", ErrRequest
		}
		q.Name = q.ID
	} else {
		if q.Folder != "" {
			m, _, e := b.driveStorageMeta(ctx, q.Folder, token)
			if e != nil {
				return file, "", e
			}
			if m.MediaType != "application/vnd.google-apps.folder" || !m.Capabilities.Add {
				return file, "", ErrUnsupported
			}
		}
		// Reserve a Drive ID before the review; a later ambiguous create cannot be
		// turned into a second file by resubmitting the same reviewed plan.
		raw, _, e := b.provider.request(ctx, "GET", b.provider.api+"/files/generateIds?"+url.Values{"count": {"1"}, "space": {"drive"}, "type": {"files"}}.Encode(), token, nil, 4096)
		if e != nil {
			return file, "", e
		}
		var result struct {
			IDs []string `json:"ids"`
		}
		if json.Unmarshal(raw, &result) != nil || len(result.IDs) != 1 || !identifier.MatchString(result.IDs[0]) {
			return file, "", ErrProvider
		}
		q.ID = result.IDs[0]
	}
	return StorageFile{ID: q.ID, Name: q.Name, Kind: "file"}, "", nil
}
func (b *Broker) storageApply(ctx context.Context, intent storageIntent, token string) (string, error) {
	if ctx.Err() != nil {
		return "", ErrCanceled
	}
	if e := b.store.checkConnection(credential{ID: intent.Connection}, intent.Epoch); e != nil {
		return "", e
	}
	if b.provider.obsidian {
		return b.localStorageApply(ctx, intent)
	}
	data, _ := base64.StdEncoding.DecodeString(intent.Change.Content)
	if b.provider.s3 {
		cfg, c, epoch, e := s3Snapshot(b.store)
		if e != nil {
			return "", e
		}
		if c.ID != intent.Connection || epoch != intent.Epoch {
			return "", ErrCanceled
		}
		return b.provider.s3StorageWrite(ctx, cfg, intent.Change, data)
	}
	return b.driveStorageApply(ctx, intent, token, data)
}
