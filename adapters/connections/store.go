// Package connections owns personal provider credentials and Drive operations.
// It is deliberately in the adapters module; the signer never links this code.
package connections

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"adapters/internal/canon"
)

type Error string

func (e Error) Error() string { return string(e) }

const (
	ErrRequest     Error = "invalid-request"
	ErrStorage     Error = "private-storage-unavailable"
	ErrSetup       Error = "setup-required"
	ErrPolicy      Error = "blocked-by-policy"
	ErrConnect     Error = "connect-required"
	ErrProvider    Error = "provider-unavailable"
	ErrRevoked     Error = "reconnect-required"
	ErrCanceled    Error = "canceled"
	ErrGrant       Error = "selection-expired"
	ErrLimit       Error = "file-too-large"
	ErrChanged     Error = "source-changed"
	ErrUnsupported Error = "unsupported-file"
)

var identifier = regexp.MustCompile(`^[A-Za-z0-9_-]{1,200}$`)
var opaque = regexp.MustCompile(`^[a-f0-9]{64}$`)

func randomID() string {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic("secure randomness unavailable")
	}
	return hex.EncodeToString(b[:])
}
func digest(b []byte) string { h := sha256.Sum256(b); return "sha256:" + hex.EncodeToString(h[:]) }
func decode(raw []byte, out any) error {
	if len(raw) > 64<<10 {
		return ErrRequest
	}
	if _, err := canon.Canonicalize(raw, canon.RefuseNumbers); err != nil {
		return ErrRequest
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(out) != nil {
		return ErrRequest
	}
	return nil
}

type Client struct {
	ID     string `json:"clientId"`
	Secret string `json:"clientSecret"`
}
type account struct {
	ID    string `json:"id"`
	Email string `json:"email"`
	Name  string `json:"name"`
}
type credential struct {
	ID      string  `json:"id"`
	Account account `json:"account"`
	Access  string  `json:"access"`
	Refresh string  `json:"refresh"`
	Expires int64   `json:"expires"`
}
type state struct {
	Client     Client      `json:"client"`
	Connection *credential `json:"connection"`
	Disabled   bool        `json:"disabled"`
}
type Store struct{ root *os.Root }

func OpenStore(dir, principal string) (*Store, error) {
	if !filepath.IsAbs(dir) || !identifier.MatchString(principal) {
		return nil, ErrRequest
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, ErrStorage
	}
	st, err := os.Lstat(dir)
	if err != nil || !st.IsDir() || private(st, true) != nil {
		return nil, ErrStorage
	}
	r, err := os.OpenRoot(dir)
	if err != nil {
		return nil, ErrStorage
	}
	sum := sha256.Sum256([]byte(principal))
	name := hex.EncodeToString(sum[:])
	if err = r.Mkdir(name, 0700); err != nil && !errors.Is(err, os.ErrExist) {
		r.Close()
		return nil, ErrStorage
	}
	st, err = r.Lstat(name)
	if err != nil || !st.IsDir() || private(st, true) != nil {
		r.Close()
		return nil, ErrStorage
	}
	child, err := r.OpenRoot(name)
	r.Close()
	if err != nil {
		return nil, ErrStorage
	}
	return &Store{child}, nil
}
func (s *Store) Close() error { return s.root.Close() }
func (s *Store) read(name string) ([]byte, error) {
	f, err := s.root.OpenFile(name, os.O_RDONLY|noFollow|nonBlock, 0)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, os.ErrNotExist
		}
		return nil, ErrStorage
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil || !st.Mode().IsRegular() || private(st, false) != nil || st.Size() > 64<<10 {
		return nil, ErrStorage
	}
	b, err := io.ReadAll(io.LimitReader(f, 64<<10+1))
	if err != nil || len(b) > 64<<10 {
		return nil, ErrStorage
	}
	return b, nil
}
func (s *Store) write(name string, v any) error {
	b, err := json.Marshal(v)
	if err != nil || len(b) > 64<<10 {
		return ErrStorage
	}
	tmp := ".tmp-" + randomID()
	f, err := s.root.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL|noFollow, 0600)
	if err != nil {
		return ErrStorage
	}
	defer s.root.Remove(tmp)
	if _, err = f.Write(b); err == nil {
		err = f.Sync()
	}
	ce := f.Close()
	if err != nil || ce != nil {
		return ErrStorage
	}
	if err = s.root.Rename(tmp, name); err != nil {
		return ErrStorage
	}
	return nil
}
func (s *Store) locked(fn func(*state) error) error {
	f, err := s.root.OpenFile("state.lock", os.O_CREATE|os.O_RDWR|noFollow|nonBlock, 0600)
	if err != nil {
		return ErrStorage
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil || !st.Mode().IsRegular() || private(st, false) != nil {
		return ErrStorage
	}
	until := time.Now().Add(3 * time.Second)
	for lock(f) != nil {
		if time.Now().After(until) {
			return ErrStorage
		}
		time.Sleep(10 * time.Millisecond)
	}
	defer unlock(f)
	var v state
	b, err := s.read("state.json")
	if err == nil {
		if decode(b, &v) != nil {
			return ErrStorage
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return fn(&v)
}

type grant struct {
	Connection string `json:"connection"`
	File       string `json:"file"`
	Expires    int64  `json:"expires"`
}

func (s *Store) makeGrants(c string, ids []string) ([]Selection, error) {
	// Keep abandoned picker selections bounded; only our fixed-name grant files
	// are eligible. Credentials and unrelated files are never cleanup candidates.
	directory, err := s.root.Open(".")
	if err != nil {
		return nil, ErrStorage
	}
	defer directory.Close()
	names, err := directory.Readdirnames(129)
	if err != nil && err != io.EOF {
		return nil, ErrStorage
	}
	live := 0
	for _, name := range names {
		if strings.HasPrefix(name, "grant-") && opaque.MatchString(strings.TrimPrefix(name, "grant-")) {
			raw, e := s.read(name)
			var g grant
			if e != nil || decode(raw, &g) != nil {
				return nil, ErrStorage
			}
			if g.Expires <= time.Now().Unix() || g.Connection != c {
				if s.root.Remove(name) != nil {
					return nil, ErrStorage
				}
			} else {
				live++
			}
		}
	}
	if len(names) >= 129 || live+len(ids) > 32 {
		return nil, Error("too-many-selections")
	}

	out := make([]Selection, 0, len(ids))
	for _, id := range ids {
		token := randomID()
		if err := s.write("grant-"+token, grant{c, id, time.Now().Add(5 * time.Minute).Unix()}); err != nil {
			return nil, err
		}
		out = append(out, Selection{FileID: id, Grant: token})
	}
	return out, nil
}
