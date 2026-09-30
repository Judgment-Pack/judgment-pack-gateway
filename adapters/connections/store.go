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
	"reflect"
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
	// The decoder takes a name written in another case for the name, and
	// reads the last of the two where a request holds both.
	if canon.ExactNames(raw, out) != nil {
		forget(out)
		return ErrRequest
	}
	return nil
}

// forget leaves nothing in out of a request that was read and then refused.
func forget(out any) {
	if v := reflect.ValueOf(out); v.Kind() == reflect.Pointer && !v.IsNil() {
		v.Elem().SetZero()
	}
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
	Search     *searchState `json:"search,omitempty"`
	Epoch      string       `json:"epoch"`
	Client     Client       `json:"client"`
	Connection *credential  `json:"connection"`
	Disabled   bool         `json:"disabled"`
	Redirect   string       `json:"redirect,omitempty"`
	Vault      string       `json:"vault,omitempty"`
	S3         *s3Config    `json:"s3,omitempty"`
}
type Store struct{ root *os.Root }

// consent is the record of what a connection's consent was for. It is kept
// beside the state and not in it: an earlier release reads the state, and
// refuses one that has a member it does not know. The record is of the
// tokens as they are held, the refresh token and the access token, each by
// a digest: a token that another put in their place, an earlier release's
// consent or renewal among them, is one the record says nothing of.
type consent struct {
	Connection string `json:"connection"`
	Grant      string `json:"grant"`
	Token      string `json:"token"`
	Scope      string `json:"scope"`
}

// recordConsent is called under the store's lock, once the state is written:
// at a consent, and at every renewal. Where it fails the connection is
// without a record, and is asked for again.
func (s *Store) recordConsent(c *credential, scope string) error {
	return s.write("consent.json", consent{c.ID, digest([]byte(c.Refresh)), digest([]byte(c.Access)), scope})
}

// consentedScope is the scope the consent of this credential was for, and
// nothing where no record says of the tokens as this credential holds them.
// A connection made before ADR-0010 has no record.
func (s *Store) consentedScope(c credential) string {
	raw, err := s.read("consent.json")
	var v consent
	if err != nil || decode(raw, &v) != nil || v.Connection != c.ID || v.Grant != digest([]byte(c.Refresh)) || v.Token != digest([]byte(c.Access)) {
		return ""
	}
	return v.Scope
}

// OpenGmailStore separates Gmail consent, credentials and grants from Drive.
func OpenGmailStore(dir, principal string) (*Store, error) {
	if !filepath.IsAbs(dir) {
		return nil, ErrRequest
	}
	// Validate the operator-supplied custody root before creating a provider
	// namespace beneath it. This also refuses a permissive or symlink root.
	root, err := OpenStore(dir, principal)
	if err != nil {
		return nil, err
	}
	root.Close()
	return OpenStore(filepath.Join(dir, "gmail"), principal)
}
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
	Connection string    `json:"connection"`
	File       string    `json:"file"`
	Expires    int64     `json:"expires"`
	S3         *s3Object `json:"s3,omitempty"`
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
		if err := s.write("grant-"+token, grant{Connection: c, File: id, Expires: time.Now().Add(5 * time.Minute).Unix()}); err != nil {
			return nil, err
		}
		out = append(out, Selection{FileID: id, Grant: token})
	}
	return out, nil
}
