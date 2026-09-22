package connections

import (
	"context"
	"io"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strings"
	"unicode/utf8"
)

func OpenObsidianStore(dir, principal string) (*Store, error) {
	root, err := OpenStore(dir, principal)
	if err != nil {
		return nil, err
	}
	root.Close()
	return OpenStore(filepath.Join(dir, "obsidian"), principal)
}
func NewObsidian(s *Store, disabled bool) *Broker {
	return &Broker{store: s, provider: provider{obsidian: true}, disabled: disabled}
}
func validNote(id string) bool {
	if id == "" || len(id) > 1024 || !utf8.ValidString(id) || strings.ContainsAny(id, "\\\x00\r\n:") || !strings.HasSuffix(strings.ToLower(id), ".md") || path.Clean(id) != id || strings.HasPrefix(id, "/") {
		return false
	}
	for _, c := range id {
		if c < 32 || c == 127 {
			return false
		}
	}
	for _, part := range strings.Split(id, "/") {
		if strings.HasPrefix(part, ".") {
			return false
		}
	}
	return true
}
func openVault(name string) (*os.Root, error) {
	if !filepath.IsAbs(name) || filepath.Clean(name) != name || filepath.Dir(name) == name {
		return nil, Error("invalid-vault")
	}
	st, err := os.Lstat(name)
	if err != nil || !st.IsDir() || st.Mode()&os.ModeSymlink != 0 {
		return nil, Error("invalid-vault")
	}
	root, err := os.OpenRoot(name)
	if err != nil {
		return nil, Error("invalid-vault")
	}
	info, err := root.Lstat(".obsidian")
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		root.Close()
		return nil, Error("invalid-vault")
	}
	return root, nil
}
func vaultRead(root *os.Root, id string) ([]byte, error) {
	raw, _, err := vaultReadBounded(root, id, MaxFileBytes)
	return raw, err
}
func vaultReadBounded(root *os.Root, id string, limit int) ([]byte, int, error) {
	if !validNote(id) {
		return nil, 0, ErrRequest
	}
	// Reject existing symlink components; os.Root also prevents a racing symlink
	// from escaping the authorized vault. The final open never follows a symlink.
	prefix := ""
	for _, part := range strings.Split(id, "/") {
		prefix = path.Join(prefix, part)
		st, e := root.Lstat(filepath.FromSlash(prefix))
		if e != nil || st.Mode()&os.ModeSymlink != 0 {
			return nil, 0, ErrUnsupported
		}
	}
	f, err := root.OpenFile(filepath.FromSlash(id), os.O_RDONLY|noFollow|nonBlock, 0)
	if err != nil {
		return nil, 0, ErrUnsupported
	}
	defer f.Close()
	return readVaultFile(f, limit)
}

// Keep the before/after check around the same open file, including when the
// underlying read overlaps an edit. The small interface permits deterministic
// tests of that overlap without timing-dependent filesystem races.
type vaultFile interface {
	io.Reader
	Stat() (os.FileInfo, error)
}

func readVaultFile(f vaultFile, limit int) ([]byte, int, error) {
	before, err := f.Stat()
	if err != nil || !before.Mode().IsRegular() || before.Size() > int64(limit) {
		return nil, 0, ErrLimit
	}
	raw, err := io.ReadAll(io.LimitReader(f, int64(limit)))
	if err != nil {
		return nil, len(raw), ErrLimit
	}
	after, err := f.Stat()
	if err != nil || before.Size() != after.Size() || !before.ModTime().Equal(after.ModTime()) || int64(len(raw)) != after.Size() {
		return nil, len(raw), ErrChanged
	}
	if !utf8.Valid(raw) {
		return nil, len(raw), ErrUnsupported
	}
	return raw, len(raw), nil
}
func vaultURL(name, id string) string {
	return "obsidian://open?" + strings.ReplaceAll(url.Values{"vault": {name}, "file": {strings.TrimSuffix(id, path.Ext(id))}}.Encode(), "+", "%20")
}
func (b *Broker) vaultOperation(ctx context.Context, method string, raw []byte) (any, error) {
	switch method {
	case "configure":
		var q struct {
			Path string `json:"path"`
		}
		if decode(raw, &q) != nil || len(q.Path) > 4096 {
			return nil, ErrRequest
		}
		root, err := openVault(q.Path)
		if err != nil {
			return nil, err
		}
		root.Close()
		err = b.store.locked(func(v *state) error {
			if v.Disabled {
				return ErrPolicy
			}
			if v.Connection != nil && v.Vault != q.Path {
				return Error("disconnect-first")
			}
			v.Vault = q.Path
			v.Epoch = randomID()
			v.Connection = &credential{ID: randomID(), Account: account{ID: digest([]byte(q.Path)), Name: filepath.Base(q.Path)}}
			return b.store.write("state.json", v)
		})
		return map[string]bool{"saved": err == nil}, err
	case "disconnect":
		var q struct{}
		if decode(raw, &q) != nil {
			return nil, ErrRequest
		}
		err := b.store.locked(func(v *state) error {
			v.Connection = nil
			v.Vault = ""
			v.Epoch = randomID()
			return b.store.write("state.json", v)
		})
		return map[string]bool{"disconnected": err == nil, "revoked": err == nil}, err
	case "status":
		var q struct{}
		if decode(raw, &q) != nil {
			return nil, ErrRequest
		}
		out := Status{1, "obsidian", "not-connected", nil, MaxFileBytes, 4}
		err := b.store.locked(func(v *state) error {
			if v.Connection != nil {
				out.State = "connected"
				out.Account = &v.Connection.Account
			}
			return nil
		})
		return out, err
	case "search", "select":
		_, c, epoch, err := b.connectedSnapshot()
		if err != nil {
			return nil, err
		}
		if method == "select" {
			return b.selectSources(raw, c, epoch, validNote)
		}
		var q struct {
			Query string `json:"query"`
		}
		if decode(raw, &q) != nil || len(q.Query) > 1024 || strings.ContainsAny(q.Query, "\x00\r\n") {
			return nil, ErrRequest
		}
		var name string
		err = b.store.locked(func(v *state) error {
			if v.Epoch != epoch {
				return ErrCanceled
			}
			name = v.Vault
			return nil
		})
		if err != nil {
			return nil, err
		}
		root, err := openVault(name)
		if err != nil {
			return nil, err
		}
		defer root.Close()
		out := SourceSearch{SelectionContext: epoch, Items: []SourcePreview{}}
		query := strings.ToLower(strings.TrimSpace(q.Query))
		entries, readBytes := 0, 0
		var walk func(string, int) error
		walk = func(folder string, depth int) error {
			if depth > 24 {
				out.More = true
				return nil
			}
			f, e := root.Open(filepath.FromSlash(folder))
			if e != nil {
				return nil
			}
			defer f.Close()
			for {
				names, e := f.Readdirnames(128)
				if e != nil && e != io.EOF {
					return ErrProvider
				}
				for _, child := range names {
					if ctx.Err() != nil {
						return ErrCanceled
					}
					entries++
					if entries > 10000 || readBytes >= 32<<20 || len(out.Items) >= 20 {
						out.More = true
						return io.EOF
					}
					if strings.HasPrefix(child, ".") {
						continue
					}
					id := path.Join(folder, child)
					st, err := root.Lstat(filepath.FromSlash(id))
					if err != nil || st.Mode()&os.ModeSymlink != 0 {
						continue
					}
					if st.IsDir() {
						if err = walk(id, depth+1); err != nil {
							return err
						}
						continue
					}
					if !st.Mode().IsRegular() || !validNote(id) {
						continue
					}
					match := query == "" || strings.Contains(strings.ToLower(id), query)
					if !match && st.Size() <= MaxFileBytes {
						data, consumed, err := vaultReadBounded(root, id, min(MaxFileBytes, (32<<20)-readBytes))
						readBytes += consumed // Failed and invalid-text reads also consume the budget.
						if err != nil {
							out.More = true
							continue
						}
						match = strings.Contains(strings.ToLower(string(data)), query)
					}
					if match {
						out.Items = append(out.Items, SourcePreview{ID: id, Title: strings.TrimSuffix(path.Base(id), path.Ext(id)), URL: vaultURL(c.Account.Name, id), Description: id})
					}
				}
				if e == io.EOF {
					return nil
				}
			}
		}
		err = walk(".", 0)
		if err != nil && err != io.EOF {
			return nil, err
		}
		if err = b.store.checkConnection(c, epoch); err != nil {
			return nil, err
		}
		return out, nil
	default:
		return nil, ErrRequest
	}
}
func ReadObsidian(ctx context.Context, s *Store, raw []byte) ([]byte, error) {
	return readObsidian(ctx, s, raw, sourceDocument)
}
func readObsidian(ctx context.Context, s *Store, raw []byte, snapshot func(context.Context, string, string, string, string, []byte, any, string) ([]byte, error)) ([]byte, error) {
	var q SourceSelection
	if decode(raw, &q) != nil || !opaque.MatchString(q.Grant) || !validNote(q.ResourceID) {
		return nil, ErrRequest
	}
	_, c, epoch, err := s.consumeGrant(q.Grant, q.ResourceID)
	if err != nil {
		return nil, err
	}
	var name string
	err = s.locked(func(v *state) error {
		if v.Epoch != epoch || v.Connection == nil || v.Connection.ID != c.ID {
			return ErrCanceled
		}
		name = v.Vault
		return nil
	})
	if err != nil {
		return nil, err
	}
	root, err := openVault(name)
	if err != nil {
		return nil, err
	}
	defer root.Close()
	data, err := vaultRead(root, q.ResourceID)
	if err != nil {
		return nil, err
	}
	out, err := snapshot(ctx, "obsidian", q.ResourceID, strings.TrimSuffix(path.Base(q.ResourceID), path.Ext(q.ResourceID)), vaultURL(c.Account.Name, q.ResourceID), data, nil, "")
	if err != nil {
		return nil, err
	}
	if err = s.checkConnection(c, epoch); err != nil {
		return nil, err
	}
	return out, nil
}
