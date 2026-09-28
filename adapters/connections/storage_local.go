package connections

import (
	"context"
	"encoding/base64"
	"errors"
	"io"
	"mime"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"
)

func validStoragePath(id string, folder bool) bool {
	if folder && id == "" {
		return true
	}
	if !resourceText(id, 1024, false) || strings.ContainsAny(id, "\\:") || path.Clean(id) != id || strings.HasPrefix(id, "/") {
		return false
	}
	for _, part := range strings.Split(id, "/") {
		if strings.HasPrefix(part, ".") {
			return false
		}
	}
	return true
}
func (b *Broker) storageVault(expected ...storageIntent) (*os.Root, error) {
	var name string
	e := b.store.locked(func(v *state) error {
		if v.Disabled || v.Connection == nil {
			return ErrConnect
		}
		if len(expected) != 0 && (v.Epoch != expected[0].Epoch || v.Connection.ID != expected[0].Connection) {
			return ErrCanceled
		}
		name = v.Vault
		return nil
	})
	if e != nil {
		return nil, e
	}
	return openVault(name)
}
func storageNoLinks(root *os.Root, id string) error {
	if id == "" || id == "." {
		return nil
	}
	prefix := ""
	for _, p := range strings.Split(id, "/") {
		prefix = path.Join(prefix, p)
		st, e := root.Lstat(filepath.FromSlash(prefix))
		if e != nil || st.Mode()&os.ModeSymlink != 0 {
			return ErrUnsupported
		}
	}
	return nil
}
func localFile(root *os.Root, id string, read bool) (StorageFile, []byte, error) {
	var item StorageFile
	if !validStoragePath(id, false) || storageNoLinks(root, id) != nil {
		return item, nil, ErrRequest
	}
	f, e := root.OpenFile(filepath.FromSlash(id), os.O_RDONLY|noFollow|nonBlock, 0)
	if e != nil {
		return item, nil, ErrUnsupported
	}
	defer f.Close()
	st, e := f.Stat()
	if e != nil || !st.Mode().IsRegular() {
		return item, nil, ErrUnsupported
	}
	media := mime.TypeByExtension(path.Ext(id))
	if media == "" {
		media = "application/octet-stream"
	}
	media = strings.Split(media, ";")[0]
	item = StorageFile{ID: id, Name: path.Base(id), Kind: "file", Size: st.Size(), MediaType: media, Editable: st.Size() <= MaxFileBytes, Deletable: true}
	// Read at most the supported file bound to obtain a content revision. Large
	// files remain browseable but cannot be mutated without a bounded revision.
	if st.Size() > MaxFileBytes {
		return item, nil, ErrLimit
	}
	raw, e := io.ReadAll(io.LimitReader(f, MaxFileBytes+1))
	if e != nil || len(raw) > MaxFileBytes {
		return item, nil, ErrLimit
	}
	after, e := f.Stat()
	if e != nil || !os.SameFile(st, after) || st.Size() != after.Size() || !st.ModTime().Equal(after.ModTime()) || int64(len(raw)) != st.Size() {
		return item, nil, ErrChanged
	}
	item.Revision = digest(raw)
	if !read {
		return item, nil, nil
	}
	return item, raw, nil
}
func (b *Broker) storageList(ctx context.Context, q StorageQuery, c credential, epoch, token string) (StoragePage, error) {
	if q.PageToken == "" {
		b.closeStorageBrowse()
		b.storageBrowse = &storageBrowse{query: q, epoch: epoch, connection: c.ID, until: time.Now().Add(5 * time.Minute)}
	} else {
		old := b.storageBrowse
		if old == nil || old.epoch != epoch || old.connection != c.ID || old.query.Folder != q.Folder || old.query.Query != q.Query || old.token != q.PageToken || !time.Now().Before(old.until) {
			b.closeStorageBrowse()
			return StoragePage{}, ErrGrant
		}
	}
	if b.provider.obsidian {
		return b.localStorageList(ctx, q)
	}
	if b.provider.s3 {
		return b.s3StorageList(ctx, q)
	}
	return b.driveStorageList(ctx, q, token)
}
func (b *Broker) finishStoragePage(out StoragePage, more bool) (StoragePage, error) {
	out.Truncated = out.Truncated || b.storageBrowse.truncated
	if more {
		b.storageBrowse.token = randomID()
		out.NextPageToken = b.storageBrowse.token
	} else {
		b.closeStorageBrowse()
	}
	return out, nil
}
func (b *Broker) localStorageList(ctx context.Context, q StorageQuery) (StoragePage, error) {
	out := StoragePage{Items: []StorageFile{}, Scope: "vault", SearchMode: "names"}
	browse := b.storageBrowse
	if !validStoragePath(q.Folder, true) {
		return out, ErrRequest
	}
	if browse.root == nil {
		root, e := b.storageVault()
		if e != nil {
			return out, e
		}
		browse.root = root
		folder := q.Folder
		if folder == "" {
			folder = "."
		}
		browse.folders = []string{folder}
	}
	for count := 0; count < 256 && len(out.Items) < StoragePageItems; count++ {
		if ctx.Err() != nil {
			return out, ErrCanceled
		}
		if browse.file == nil {
			if len(browse.folders) == 0 {
				return b.finishStoragePage(out, false)
			}
			browse.folder = browse.folders[0]
			browse.folders = browse.folders[1:]
			if storageNoLinks(browse.root, browse.folder) != nil {
				continue
			}
			f, e := browse.root.OpenFile(filepath.FromSlash(browse.folder), os.O_RDONLY|noFollow|nonBlock, 0)
			if e != nil {
				continue
			}
			st, e := f.Stat()
			if e != nil || !st.IsDir() {
				f.Close()
				continue
			}
			browse.file = f
		}
		names, e := browse.file.Readdirnames(1)
		if len(names) == 0 {
			browse.file.Close()
			browse.file = nil
			if e != nil && e != io.EOF {
				return out, ErrProvider
			}
			continue
		}
		browse.examined++
		if browse.examined > 10000 {
			out.Truncated = true
			return b.finishStoragePage(out, false)
		}
		id := path.Join(browse.folder, names[0])
		if !validStoragePath(id, false) {
			continue
		}
		st, e := browse.root.Lstat(filepath.FromSlash(id))
		if e != nil || st.Mode()&os.ModeSymlink != 0 {
			continue
		}
		if st.IsDir() {
			if q.Query != "" && strings.Count(id, "/") < 24 && len(browse.folders) < 256 {
				browse.folders = append(browse.folders, id)
			} else if q.Query != "" {
				browse.truncated = true
			}
			if q.Query == "" {
				out.Items = append(out.Items, StorageFile{ID: id, Name: names[0], Kind: "folder"})
			}
			continue
		}
		if !st.Mode().IsRegular() || !storageMatch(id, q.Query) {
			continue
		}
		media := strings.Split(mime.TypeByExtension(path.Ext(id)), ";")[0]
		if media == "" {
			media = "application/octet-stream"
		}
		// Browsing never opens file content. The edit/read request obtains a fresh
		// digest, which is then required for an update or delete proposal.
		revision := localStatRevision(st)
		out.Items = append(out.Items, StorageFile{ID: id, Name: names[0], Kind: "file", Size: st.Size(), Revision: revision, MediaType: media, Editable: st.Size() <= MaxFileBytes, Deletable: true})
	}
	return b.finishStoragePage(out, true)
}
func localStatRevision(st os.FileInfo) string {
	return "stat:" + st.ModTime().UTC().Format(time.RFC3339Nano) + ":" + intString(st.Size())
}
func (b *Broker) localStorageApply(ctx context.Context, intent storageIntent) (string, error) {
	q := intent.Change
	data, _ := base64.StdEncoding.DecodeString(q.Content)
	root, e := b.storageVault(intent)
	if e != nil {
		return "", e
	}
	defer root.Close()
	if !validStoragePath(q.ID, false) {
		return "", ErrRequest
	}
	parent := path.Dir(q.ID)
	if storageNoLinks(root, parent) != nil {
		return "", ErrRequest
	}
	if q.Action == "create" {
		f, e := root.OpenFile(filepath.FromSlash(q.ID), os.O_WRONLY|os.O_CREATE|os.O_EXCL|noFollow, 0600)
		if errors.Is(e, os.ErrExist) {
			return "", ErrChanged
		}
		if e != nil {
			return "", ErrProvider
		}
		_, e = f.Write(data)
		if e == nil {
			e = f.Sync()
		}
		ce := f.Close()
		if e != nil || ce != nil {
			return "", ErrProvider
		}
		return q.ID, syncStorageDirs(root, parent)
	}
	if q.Action == "delete" && strings.HasPrefix(q.Revision, "stat:") {
		st, err := root.Lstat(filepath.FromSlash(q.ID))
		if err != nil || !st.Mode().IsRegular() || localStatRevision(st) != q.Revision {
			return "", ErrChanged
		}
		if e = root.Mkdir(".jpack-trash", 0700); e != nil && !errors.Is(e, os.ErrExist) {
			return "", ErrProvider
		}
		st, e := root.Lstat(".jpack-trash")
		if e != nil || !st.IsDir() || st.Mode()&os.ModeSymlink != 0 {
			return "", ErrUnsupported
		}
		if e = root.Rename(filepath.FromSlash(q.ID), filepath.Join(".jpack-trash", intent.Plan.ID+"-"+q.Name)); e != nil {
			return "", e
		}
		return q.ID, syncStorageDirs(root, parent, ".jpack-trash", ".")
	}
	item, old, e := localFile(root, q.ID, true)
	if e != nil {
		return "", e
	}
	if item.Revision != q.Revision {
		return "", ErrChanged
	}
	if ctx.Err() != nil {
		return "", ErrCanceled
	}
	if q.Action == "delete" {
		if e = root.Mkdir(".jpack-trash", 0700); e != nil && !errors.Is(e, os.ErrExist) {
			return "", ErrProvider
		}
		st, e := root.Lstat(".jpack-trash")
		if e != nil || !st.IsDir() || st.Mode()&os.ModeSymlink != 0 {
			return "", ErrUnsupported
		}
		if e = root.Rename(filepath.FromSlash(q.ID), filepath.Join(".jpack-trash", intent.Plan.ID+"-"+q.Name)); e != nil {
			return "", e
		}
		return q.ID, syncStorageDirs(root, parent, ".jpack-trash", ".")
	}
	// Keep the previous bytes before replacing; external editors do not share
	// this host's lock, so local updates promise a revision recheck, not POSIX CAS.
	if e = root.Mkdir(".jpack-history", 0700); e != nil && !errors.Is(e, os.ErrExist) {
		return "", ErrProvider
	}
	st, e := root.Lstat(".jpack-history")
	if e != nil || !st.IsDir() || st.Mode()&os.ModeSymlink != 0 {
		return "", ErrUnsupported
	}
	backup, e := root.OpenFile(filepath.Join(".jpack-history", intent.Plan.ID), os.O_WRONLY|os.O_CREATE|os.O_EXCL|noFollow, 0600)
	if e != nil {
		return "", ErrProvider
	}
	_, e = backup.Write(old)
	if e == nil {
		e = backup.Sync()
	}
	ce := backup.Close()
	if e != nil || ce != nil {
		return "", ErrProvider
	}
	tmp := path.Join(parent, ".jpack-"+intent.Plan.ID)
	f, e := root.OpenFile(filepath.FromSlash(tmp), os.O_WRONLY|os.O_CREATE|os.O_EXCL|noFollow, 0600)
	if e != nil {
		return "", ErrProvider
	}
	defer root.Remove(filepath.FromSlash(tmp))
	_, e = f.Write(data)
	if e == nil {
		e = f.Sync()
	}
	ce = f.Close()
	if e != nil || ce != nil {
		return "", ErrProvider
	}
	current, _, e := localFile(root, q.ID, false)
	if e != nil || current.Revision != q.Revision {
		return "", ErrChanged
	}
	if e = root.Rename(filepath.FromSlash(tmp), filepath.FromSlash(q.ID)); e != nil {
		return "", e
	}
	return q.ID, syncStorageDirs(root, parent, ".jpack-history", ".")
}

func syncStorageDirs(root *os.Root, dirs ...string) error {
	for _, name := range dirs {
		dir, e := root.Open(filepath.FromSlash(name))
		if e != nil {
			return ErrProvider
		}
		e = dir.Sync()
		closeErr := dir.Close()
		if e != nil || closeErr != nil {
			return ErrProvider
		}
	}
	return nil
}
