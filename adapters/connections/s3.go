package connections

import (
	"context"
	"fmt"
	"net/http"
	"path"
	"path/filepath"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"
)

// S3 credentials are explicit inputs, never the SDK default credential chain.
// Separate custody prevents a Google/Notion grant or credential from crossing.
type s3Config struct {
	Region       string `json:"region"`
	Bucket       string `json:"bucket"`
	Prefix       string `json:"prefix"`
	AccessKey    string `json:"access-key-id"`
	SecretKey    string `json:"secret-access-key"`
	SessionToken string `json:"session-token"`
	ExpiresAt    string `json:"expires-at"`
}

var s3Region = regexp.MustCompile(`^(af|ap|ca|eu|il|me|mx|sa|us)-(central|east|west|north|south|northeast|southeast)-[1-9][0-9]?$`)
var s3Bucket = regexp.MustCompile(`^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$`)
var s3Access = regexp.MustCompile(`^[A-Z0-9]{16,128}$`)
var s3Secret = regexp.MustCompile(`^[A-Za-z0-9/+=]{40}$`)
var s3IPBucket = regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$`)

func (c s3Config) valid() bool {
	if !s3Region.MatchString(c.Region) || !s3Bucket.MatchString(c.Bucket) || s3IPBucket.MatchString(c.Bucket) || strings.Contains(c.Bucket, "..") || strings.Contains(c.Bucket, ".-") || strings.Contains(c.Bucket, "-.") || strings.HasSuffix(c.Bucket, "--x-s3") || strings.HasSuffix(c.Bucket, "--ol-s3") || strings.HasSuffix(c.Bucket, ".mrap") || strings.HasPrefix(c.Bucket, "xn--") || !resourceText(c.Prefix, 1024, true) || !s3Access.MatchString(c.AccessKey) || !s3Secret.MatchString(c.SecretKey) || !resourceText(c.SessionToken, 4096, true) {
		return false
	}
	if c.SessionToken == "" {
		return c.ExpiresAt == "" && !strings.HasPrefix(c.AccessKey, "ASIA")
	}
	expires, err := time.Parse(time.RFC3339, c.ExpiresAt)
	return err == nil && expires.After(time.Now())
}
func (c s3Config) expired() bool {
	if c.ExpiresAt == "" {
		return false
	}
	expires, err := time.Parse(time.RFC3339, c.ExpiresAt)
	return err != nil || !expires.After(time.Now())
}
func (c s3Config) scope() ResourceScope {
	name := c.Bucket + "/" + c.Prefix
	id := digest([]byte(c.Region + "\x00" + name))
	if len(name) > 1024 {
		for len(name) > 1021 {
			_, size := utf8.DecodeLastRuneInString(name)
			name = name[:len(name)-size]
		}
		name += "…"
	}
	return ResourceScope{ID: id, Name: name}
}
func (c s3Config) leaks(raw []byte) bool {
	for _, secret := range []string{c.AccessKey, c.SecretKey, c.SessionToken} {
		if secret != "" && strings.Contains(string(raw), secret) {
			return true
		}
	}
	return false
}
func OpenS3Store(dir, principal string) (*Store, error) {
	root, err := OpenStore(dir, principal)
	if err != nil {
		return nil, err
	}
	root.Close()
	return OpenStore(filepath.Join(dir, "aws-s3"), principal)
}
func NewS3(s *Store, disabled bool) *Broker {
	p := google()
	p.s3 = true
	p.auth, p.token, p.revoke, p.api = "", "", "", ""
	p.client.Transport.(*http.Transport).DisableCompression = true
	return &Broker{store: s, provider: p, disabled: disabled}
}
func s3Descriptor() Descriptor {
	return Descriptor{"aws-s3", "credentials", "form", "source-search", false, []string{"status", "configure", "disconnect", "search", "select"}}
}
func s3Catalog(p map[string]Presentation) ProviderDescriptor {
	d := ProviderDescriptor{Descriptor: s3Descriptor(), Protocol: "connection-v1", QueryMode: "prefix", Presentation: p["aws-s3"], Setup: []SetupField{}, AuthorizationEndpoints: []string{}, Source: SourceContract{"aws-s3", "command", "resource-v1"}}
	for _, key := range []string{"region", "bucket", "prefix", "access-key-id", "secret-access-key", "session-token", "expires-at"} {
		kind := "text"
		if key == "access-key-id" || key == "secret-access-key" || key == "session-token" {
			kind = "password"
		}
		d.Setup = append(d.Setup, SetupField{key, kind, p["s3-"+key].Description, key == "region" || key == "bucket" || key == "access-key-id" || key == "secret-access-key"})
	}
	return d
}

type s3Object struct {
	Epoch        string `json:"epoch,omitempty"`
	Key          string `json:"key"`
	ETag         string `json:"etag"`
	Size         int64  `json:"size"`
	StorageClass string `json:"storageClass,omitempty"`
	Version      string `json:"version,omitempty"`
}
type s3Browse struct {
	Connection string `json:"connection"`
	Epoch      string `json:"epoch"`
	Context    string `json:"context"`
	Query      string `json:"query"`
	Expires    int64  `json:"expires"`
	Page       int    `json:"page"`
	Token      string `json:"token"`
	Upstream   string `json:"upstream"`
	After      string `json:"after"`
}
type s3Page struct {
	Context string     `json:"context"`
	Objects []s3Object `json:"objects"`
}

const s3PageSize = 24
const s3RetainedPages = 8

func s3PageName(n int) string { return fmt.Sprintf("s3-page-%d.json", n%s3RetainedPages) }
func s3Read[T any](s *Store, name string) (T, error) {
	var out T
	raw, err := s.read(name)
	if err != nil {
		return out, err
	}
	if decode(raw, &out) != nil {
		return out, ErrStorage
	}
	return out, nil
}
func s3Current(v *state, c credential, epoch string) error {
	if v.Disabled {
		return ErrPolicy
	}
	if v.S3 == nil || v.Connection == nil || v.Connection.ID != c.ID || v.Epoch != epoch {
		return ErrCanceled
	}
	if v.S3.expired() {
		return Error("credentials-required")
	}
	return nil
}
func s3Snapshot(s *Store) (s3Config, credential, string, error) {
	var cfg s3Config
	var c credential
	var epoch string
	err := s.locked(func(v *state) error {
		if v.Disabled {
			return ErrPolicy
		}
		if v.S3 == nil || v.Connection == nil {
			return ErrSetup
		}
		if v.S3.expired() {
			return Error("credentials-required")
		}
		cfg, c, epoch = *v.S3, *v.Connection, v.Epoch
		return nil
	})
	return cfg, c, epoch, err
}
func (b *Broker) s3Operation(ctx context.Context, method string, raw []byte) (any, error) {
	switch method {
	case "status":
		var q struct{}
		if decode(raw, &q) != nil {
			return nil, ErrRequest
		}
		out := Status{Version: 1, Provider: "aws-s3", State: "setup-required", MaxFileBytes: MaxFileBytes, MaxFiles: 4}
		err := b.store.locked(func(v *state) error {
			if v.S3 != nil && v.Connection != nil {
				scope := v.S3.scope()
				out.Resource = &scope
				if !v.S3.expired() {
					out.State = "connected"
				}
			}
			return nil
		})
		return out, err
	case "configure":
		var cfg s3Config
		if decode(raw, &cfg) != nil || !cfg.valid() {
			return nil, ErrRequest
		}
		// Verify the explicit scope before replacing custody. Recheck the generation
		// afterwards so a concurrent disconnect/disable cannot be undone by a slow AWS call.
		var epoch string
		if err := b.store.locked(func(v *state) error {
			if v.Disabled {
				return ErrPolicy
			}
			epoch = v.Epoch
			return nil
		}); err != nil {
			return nil, err
		}
		if _, _, err := b.provider.s3List(ctx, cfg, cfg.Prefix, "", "", 1); err != nil {
			return nil, err
		}
		err := b.store.locked(func(v *state) error {
			if v.Disabled {
				return ErrPolicy
			}
			if v.Epoch != epoch {
				return ErrCanceled
			}
			if ctx.Err() != nil {
				return ErrCanceled
			}
			v.S3 = &cfg
			v.Epoch = randomID()
			scope := cfg.scope()
			v.Connection = &credential{ID: randomID(), Account: account{ID: scope.ID, Name: scope.Name}}
			return b.store.write("state.json", v)
		})
		return map[string]bool{"saved": err == nil}, err
	case "disconnect":
		var q struct{}
		if decode(raw, &q) != nil {
			return nil, ErrRequest
		}
		err := b.store.locked(func(v *state) error {
			v.S3 = nil
			v.Connection = nil
			v.Epoch = randomID()
			return b.store.write("state.json", v)
		})
		return map[string]bool{"disconnected": err == nil, "revoked": false}, err
	}
	cfg, c, epoch, err := s3Snapshot(b.store)
	if err != nil {
		return nil, err
	}
	switch method {
	case "search":
		return b.s3Search(ctx, raw, cfg, c, epoch)
	case "select":
		return b.s3Select(ctx, raw, cfg, c, epoch)
	}
	return nil, ErrRequest
}
func (b *Broker) s3Search(ctx context.Context, raw []byte, cfg s3Config, c credential, epoch string) (any, error) {
	var q struct {
		Query string `json:"query"`
		Token string `json:"pageToken"`
	}
	if decode(raw, &q) != nil || !resourceText(q.Query, 1024, true) || len(cfg.Prefix+q.Query) > 1024 || q.Token != "" && !opaque.MatchString(q.Token) {
		return nil, ErrRequest
	}
	var browse s3Browse
	err := b.store.locked(func(v *state) error {
		if e := s3Current(v, c, epoch); e != nil {
			return e
		}
		if q.Token == "" {
			browse = s3Browse{Connection: c.ID, Epoch: epoch, Context: randomID(), Query: q.Query, Expires: time.Now().Add(5 * time.Minute).Unix()}
			return b.store.write("s3-browse.json", browse)
		}
		var e error
		browse, e = s3Read[s3Browse](b.store, "s3-browse.json")
		if e != nil {
			return ErrGrant
		}
		if browse.Connection != c.ID || browse.Epoch != epoch || browse.Query != q.Query || browse.Token != q.Token || browse.Expires <= time.Now().Unix() {
			return ErrGrant
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	objects, next, err := b.provider.s3List(ctx, cfg, cfg.Prefix+q.Query, browse.Upstream, browse.After, s3PageSize)
	if err != nil {
		return nil, err
	}
	if next != "" && next == browse.Upstream {
		return nil, ErrProvider
	}
	page := ResourcePage{SelectionContext: browse.Context, Items: []ResourceItem{}, More: next != ""}
	if page.More {
		page.NextPageToken = randomID()
	}
	kept := 0
	after := ""
	for _, obj := range objects {
		size := obj.Size
		page.Items = append(page.Items, ResourceItem{ID: cfg.Bucket + "/" + obj.Key, Title: obj.Key, URL: "", SizeBytes: &size, UnavailableReason: obj.unavailable()})
		// Reserve cursor overhead before admitting a page. If a vendor page is too
		// large, resume after the last emitted key, without skipping unshown rows.
		candidate := page
		candidate.More = true
		candidate.NextPageToken = strings.Repeat("a", 64)
		if err = ValidateResourcePage(candidate); err != nil {
			page.Items = page.Items[:len(page.Items)-1]
			if kept == 0 {
				return nil, err
			}
			after = objects[kept-1].Key
			next = ""
			page.More = true
			page.NextPageToken = randomID()
			break
		}
		kept++
	}
	objects = objects[:kept]
	if err = ValidateResourcePage(page); err != nil {
		return nil, err
	}
	err = b.store.locked(func(v *state) error {
		if e := s3Current(v, c, epoch); e != nil {
			return e
		}
		current, e := s3Read[s3Browse](b.store, "s3-browse.json")
		if e != nil {
			return ErrGrant
		}
		if current != browse || browse.Expires <= time.Now().Unix() || ctx.Err() != nil {
			return ErrGrant
		}
		if e = b.store.write(s3PageName(browse.Page), s3Page{browse.Context, objects}); e != nil {
			return e
		}
		browse.Page++
		browse.Token = page.NextPageToken
		browse.Upstream = next
		browse.After = after
		return b.store.write("s3-browse.json", browse)
	})
	if err != nil {
		return nil, err
	}
	return page, nil
}
func (obj s3Object) unavailable() string {
	if obj.StorageClass == "GLACIER" || obj.StorageClass == "DEEP_ARCHIVE" {
		return "archived"
	}
	if obj.Size > MaxFileBytes {
		return "file-too-large"
	}
	if obj.Size == 0 || s3Media(obj.Key) == "" {
		return "unsupported-file"
	}
	return ""
}
func s3Media(key string) string {
	switch strings.ToLower(path.Ext(key)) {
	case ".pdf":
		return "application/pdf"
	case ".txt", ".md", ".csv", ".json", ".yaml", ".yml", ".log", ".tsv":
		return "text/plain"
	}
	return ""
}
func (b *Broker) s3Select(ctx context.Context, raw []byte, cfg s3Config, c credential, epoch string) (any, error) {
	var q struct {
		IDs     []string `json:"resourceIds"`
		Context string   `json:"selectionContext"`
	}
	if decode(raw, &q) != nil || len(q.IDs) == 0 || len(q.IDs) > 4 || !opaque.MatchString(q.Context) {
		return nil, ErrRequest
	}
	var objects []s3Object
	var browse s3Browse
	err := b.store.locked(func(v *state) error {
		if e := s3Current(v, c, epoch); e != nil {
			return e
		}
		var e error
		browse, e = s3Read[s3Browse](b.store, "s3-browse.json")
		if e != nil || browse.Context != q.Context || browse.Connection != c.ID || browse.Epoch != epoch || browse.Expires <= time.Now().Unix() {
			return ErrGrant
		}
		available := map[string]s3Object{}
		for i := max(0, browse.Page-s3RetainedPages); i < browse.Page; i++ {
			p, e := s3Read[s3Page](b.store, s3PageName(i))
			if e != nil {
				return ErrGrant
			}
			if p.Context != browse.Context {
				return ErrGrant
			}
			for _, obj := range p.Objects {
				available[cfg.Bucket+"/"+obj.Key] = obj
			}
		}
		seen := map[string]bool{}
		for _, id := range q.IDs {
			obj, ok := available[id]
			if !ok || seen[id] {
				return ErrGrant
			}
			seen[id] = true
			if reason := obj.unavailable(); reason != "" {
				return Error(reason)
			}
			objects = append(objects, obj)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	for i, obj := range objects {
		head, e := b.provider.s3Head(ctx, cfg, obj)
		if e != nil {
			return nil, e
		}
		head.Epoch = epoch
		objects[i] = head
	}
	var out []SourceSelection
	err = b.store.locked(func(v *state) error {
		if e := s3Current(v, c, epoch); e != nil {
			return e
		}
		current, e := s3Read[s3Browse](b.store, "s3-browse.json")
		if e != nil || current.Context != browse.Context || current.Expires <= time.Now().Unix() || ctx.Err() != nil {
			return ErrGrant
		}
		grants, e := b.store.makeGrants(c.ID, q.IDs)
		if e != nil {
			return e
		}
		for i, g := range grants {
			if e = b.store.write("grant-"+g.Grant, grant{Connection: c.ID, File: g.FileID, Expires: time.Now().Add(5 * time.Minute).Unix(), S3: &objects[i]}); e != nil {
				for _, g := range grants {
					_ = b.store.root.Remove("grant-" + g.Grant)
				}
				return e
			}
			out = append(out, SourceSelection{g.FileID, g.Grant})
		}
		return nil
	})
	return out, err
}
func ReadS3(ctx context.Context, s *Store, raw []byte) ([]byte, error) {
	return NewS3(s, false).provider.readS3(ctx, s, raw)
}
func (p provider) readS3(ctx context.Context, s *Store, raw []byte) ([]byte, error) {
	var q struct {
		ResourceID string `json:"resourceId"`
		Grant      string `json:"grant"`
	}
	if decode(raw, &q) != nil || !resourceText(q.ResourceID, 4096, false) || !opaque.MatchString(q.Grant) {
		return nil, ErrRequest
	}
	cfg, c, epoch, err := s3Snapshot(s)
	if err != nil {
		return nil, err
	}
	var obj s3Object
	err = s.locked(func(v *state) error {
		if e := s3Current(v, c, epoch); e != nil {
			return e
		}
		g, e := s3Read[grant](s, "grant-"+q.Grant)
		if e != nil {
			return ErrGrant
		}
		if g.Connection != c.ID || g.File != q.ResourceID || g.Expires <= time.Now().Unix() || g.S3 == nil || g.S3.Epoch != epoch || cfg.Bucket+"/"+g.S3.Key != q.ResourceID || !strings.HasPrefix(g.S3.Key, cfg.Prefix) {
			return ErrGrant
		}
		if e = s.root.Remove("grant-" + q.Grant); e != nil {
			return ErrStorage
		}
		obj = *g.S3
		return nil
	})
	if err != nil {
		return nil, err
	}
	data, err := p.s3Get(ctx, cfg, obj)
	if err != nil {
		return nil, err
	}
	if err = s.locked(func(v *state) error { return s3Current(v, c, epoch) }); err != nil {
		return nil, err
	}
	// Never serialize request headers, credentials, provider errors or signed URLs.
	out, err := ResourceDocument(ctx, "aws-s3", q.ResourceID, s3DocumentName(obj.Key), s3Media(obj.Key), "", data)
	if err != nil {
		return nil, err
	}
	err = s.locked(func(v *state) error {
		if ctx.Err() != nil {
			return ErrCanceled
		}
		return s3Current(v, c, epoch)
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

func s3DocumentName(key string) string {
	name := path.Base(key)
	ext := path.Ext(name)
	stem := strings.TrimSuffix(name, ext)
	for len(stem)+len(ext) > 255 {
		_, size := utf8.DecodeLastRuneInString(stem)
		stem = stem[:len(stem)-size]
	}
	return stem + ext
}
