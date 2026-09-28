package connections

// Storage is a personal, authenticated host control protocol. It does not run
// through /acquire or mint evidence/action receipts. The trusted host presents
// mutations to the user; the model must never receive the commit operation.
import (
	"adapters/internal/canon"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"os"
	"regexp"
	"strings"
	"time"
)

const StorageLineBytes = 6 << 20
const StoragePageItems = 24

var storageMethods = []string{"files-list", "files-read", "files-prepare", "files-commit", "files-status"}

func StorageMethod(method string) bool {
	for _, m := range storageMethods {
		if m == method {
			return true
		}
	}
	return false
}
func storageProvider(id string) bool {
	return id == "google-drive" || id == "obsidian" || id == "aws-s3"
}
func decodeStorage(raw []byte, out any) error {
	if len(raw) > StorageLineBytes || !json.Valid(raw) {
		return ErrRequest
	}
	if _, e := canon.Canonicalize(raw, canon.RefuseNumbers); e != nil {
		return ErrRequest
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(out) != nil {
		return ErrRequest
	}
	return nil
}

type StorageFile struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	Kind      string `json:"kind"`
	Size      int64  `json:"sizeBytes"`
	Revision  string `json:"revision"`
	MediaType string `json:"mediaType"`
	Editable  bool   `json:"editable"`
	Deletable bool   `json:"deletable"`
}
type StorageQuery struct {
	Folder    string `json:"folder"`
	Query     string `json:"query"`
	PageToken string `json:"pageToken"`
}
type StoragePage struct {
	Items         []StorageFile `json:"items"`
	NextPageToken string        `json:"nextPageToken,omitempty"`
	Scope         string        `json:"scope"`
	SearchMode    string        `json:"searchMode"`
	Truncated     bool          `json:"truncated"`
}
type StorageRead struct {
	File    StorageFile `json:"file"`
	Content string      `json:"contentBase64"`
}
type StorageChange struct {
	Action    string `json:"action"`
	ID        string `json:"id"`
	Folder    string `json:"folder"`
	Name      string `json:"name"`
	Revision  string `json:"revision"`
	MediaType string `json:"mediaType"`
	Content   string `json:"contentBase64"`
}
type StoragePlan struct {
	ID           string `json:"id"`
	Action       string `json:"action"`
	Target       string `json:"target"`
	Name         string `json:"name"`
	Revision     string `json:"revision"`
	Size         int    `json:"sizeBytes"`
	State        string `json:"state"`
	Expires      string `json:"expires"`
	Confirmation string `json:"confirmation"`
	Effect       string `json:"effect"`
	Error        string `json:"error,omitempty"`
}
type storageIntent struct {
	Plan       StoragePlan   `json:"plan"`
	Change     StorageChange `json:"change"`
	Epoch      string        `json:"epoch"`
	Connection string        `json:"connection"`
	ETag       string        `json:"etag"`
}
type storageBrowse struct {
	query                              StorageQuery
	epoch, connection, token, upstream string
	until                              time.Time
	root                               *os.Root
	file                               *os.File
	folders                            []string
	folder                             string
	examined                           int
	truncated                          bool
}

func (b *Broker) closeStorageBrowse() {
	if b.storageBrowse != nil {
		if b.storageBrowse.file != nil {
			b.storageBrowse.file.Close()
		}
		if b.storageBrowse.root != nil {
			b.storageBrowse.root.Close()
		}
		b.storageBrowse = nil
	}
}
func (s *Store) readStorageIntent() (storageIntent, error) {
	var out storageIntent
	f, e := s.root.OpenFile("storage-intent.json", os.O_RDONLY|noFollow|nonBlock, 0)
	if e != nil {
		return out, ErrGrant
	}
	defer f.Close()
	st, e := f.Stat()
	if e != nil || !st.Mode().IsRegular() || private(st, false) != nil || st.Size() > StorageLineBytes {
		return out, ErrStorage
	}
	raw, e := io.ReadAll(io.LimitReader(f, StorageLineBytes+1))
	if e != nil || decodeStorage(raw, &out) != nil {
		return out, ErrStorage
	}
	return out, nil
}
func (s *Store) writeStorageIntent(v storageIntent) error {
	raw, e := json.Marshal(v)
	if e != nil || len(raw) > StorageLineBytes {
		return ErrLimit
	}
	name := ".storage-" + randomID()
	f, e := s.root.OpenFile(name, os.O_CREATE|os.O_EXCL|os.O_WRONLY|noFollow, 0600)
	if e != nil {
		return ErrStorage
	}
	defer s.root.Remove(name)
	if _, e = f.Write(raw); e == nil {
		e = f.Sync()
	}
	closeErr := f.Close()
	if e != nil || closeErr != nil {
		return ErrStorage
	}
	if e = s.root.Rename(name, "storage-intent.json"); e != nil {
		return ErrStorage
	}
	dir, e := s.root.Open(".")
	if e != nil {
		return ErrStorage
	}
	defer dir.Close()
	if e = dir.Sync(); e != nil {
		return ErrStorage
	}
	return nil
}
func currentStorage(v *state, c credential, epoch string) error {
	if v.Disabled {
		return ErrPolicy
	}
	if v.Connection == nil || v.Connection.ID != c.ID || v.Epoch != epoch {
		return ErrCanceled
	}
	return nil
}
func (b *Broker) storageOperation(ctx context.Context, method string, raw []byte) (any, error) {
	client, c, epoch, e := b.connectedSnapshot()
	if e != nil {
		return nil, e
	}
	token := ""
	if b.provider.kind() == "google-drive" {
		token, e = b.provider.access(ctx, b.store, client, c, epoch)
		if e != nil {
			return nil, e
		}
	}
	switch method {
	case "files-list":
		var q StorageQuery
		if decode(raw, &q) != nil || !resourceText(q.Folder, 1024, true) || !resourceText(q.Query, 256, true) || q.PageToken != "" && !opaque.MatchString(q.PageToken) {
			return nil, ErrRequest
		}
		page, e := b.storageList(ctx, q, c, epoch, token)
		if e != nil {
			return nil, e
		}
		if e = b.store.checkConnection(c, epoch); e != nil {
			b.closeStorageBrowse()
			return nil, e
		}
		return page, nil
	case "files-read":
		var q struct {
			ID       string `json:"id"`
			Revision string `json:"revision"`
		}
		if decode(raw, &q) != nil || q.Revision == "" {
			return nil, ErrRequest
		}
		statRevision := b.provider.obsidian && strings.HasPrefix(q.Revision, "stat:")
		if statRevision {
			if e = b.checkLocalStat(q.ID, q.Revision); e != nil {
				return nil, e
			}
		}
		file, _, data, e := b.storageInspect(ctx, q.ID, token, true)
		if e != nil {
			return nil, e
		}
		if !statRevision && file.Revision != q.Revision {
			return nil, ErrChanged
		}
		if statRevision {
			if e = b.checkLocalStat(q.ID, q.Revision); e != nil {
				return nil, e
			}
		}
		if e = b.store.checkConnection(c, epoch); e != nil {
			return nil, e
		}
		return StorageRead{file, base64.StdEncoding.EncodeToString(data)}, nil
	case "files-prepare":
		var q StorageChange
		if decodeStorage(raw, &q) != nil || !resourceText(q.ID, 1024, true) || !resourceText(q.Name, 1024, true) || !resourceText(q.Folder, 1024, true) || !resourceText(q.Revision, 256, true) {
			return nil, ErrRequest
		}
		if q.Action != "create" && q.Action != "update" && q.Action != "delete" {
			return nil, ErrRequest
		}
		data, e := base64.StdEncoding.Strict().DecodeString(q.Content)
		if e != nil || len(data) > MaxFileBytes {
			return nil, ErrLimit
		}
		if q.Action == "delete" {
			if q.Content != "" || q.MediaType != "" {
				return nil, ErrRequest
			}
		} else if !validStorageMedia(q.MediaType) {
			return nil, ErrUnsupported
		}
		file, etag, e := b.storagePreflight(ctx, &q, token)
		if e != nil {
			return nil, e
		}
		plan := StoragePlan{ID: randomID(), Action: q.Action, Target: file.ID, Name: file.Name, Revision: q.Revision, Size: len(data), State: "prepared", Expires: time.Now().Add(5 * time.Minute).UTC().Format(time.RFC3339), Effect: "write"}
		if q.Action == "delete" {
			plan.Confirmation = file.Name
			plan.Effect = "delete"
			if b.provider.kind() == "google-drive" || b.provider.obsidian {
				plan.Effect = "trash"
			}
		}
		intent := storageIntent{Plan: plan, Change: q, Epoch: epoch, Connection: c.ID, ETag: etag}
		e = b.store.locked(func(v *state) error {
			if e := currentStorage(v, c, epoch); e != nil {
				return e
			}
			if prior, e := b.store.readStorageIntent(); e == nil && prior.Plan.State == "executing" && prior.Connection == c.ID && prior.Epoch == epoch {
				return Error("operation-uncertain")
			}
			return b.store.writeStorageIntent(intent)
		})
		return plan, e
	case "files-status", "files-commit":
		var q struct {
			ID           string `json:"id"`
			Confirmation string `json:"confirmation"`
		}
		if decode(raw, &q) != nil || !opaque.MatchString(q.ID) {
			return nil, ErrRequest
		}
		var intent storageIntent
		e = b.store.locked(func(v *state) error {
			if e := currentStorage(v, c, epoch); e != nil {
				return e
			}
			var e error
			intent, e = b.store.readStorageIntent()
			if e != nil {
				return e
			}
			if intent.Plan.ID != q.ID || intent.Connection != c.ID || intent.Epoch != epoch {
				return ErrGrant
			}
			return nil
		})
		if e != nil {
			return nil, e
		}
		if method == "files-status" || intent.Plan.State != "prepared" {
			if intent.Plan.State == "executing" {
				intent.Plan.State = "needs-attention"
				intent.Plan.Error = "operation-uncertain"
			}
			return intent.Plan, nil
		}
		deadline, e := time.Parse(time.RFC3339, intent.Plan.Expires)
		if e != nil || !time.Now().Before(deadline) {
			return nil, ErrGrant
		}
		if intent.Change.Action == "delete" && q.Confirmation != intent.Plan.Confirmation {
			return nil, Error("confirmation-required")
		}
		// The claim survives process loss. Reusing its ID never repeats a mutation.
		e = b.store.locked(func(v *state) error {
			if e := currentStorage(v, c, epoch); e != nil {
				return e
			}
			held, e := b.store.readStorageIntent()
			if e != nil || held.Plan.ID != q.ID || held.Plan.State != "prepared" {
				return ErrGrant
			}
			intent.Plan.State = "executing"
			return b.store.writeStorageIntent(intent)
		})
		if e != nil {
			return nil, e
		}
		target, err := b.storageApply(ctx, intent, token)
		intent.Plan.State = "completed"
		if target != "" {
			intent.Plan.Target = target
		}
		if err != nil {
			intent.Plan.State = "needs-attention"
			intent.Plan.Error = "operation-uncertain"
			if errors.Is(err, ErrChanged) || errors.Is(err, ErrUnsupported) || errors.Is(err, ErrRequest) || errors.Is(err, ErrCanceled) || errors.Is(err, ErrPolicy) || err == Error("permission-required") {
				intent.Plan.State = "refused"
				intent.Plan.Error = err.Error()
			}
		}
		intent.Change.Content = "" // settled records retain no uploaded file body
		e = b.store.locked(func(v *state) error {
			held, e := b.store.readStorageIntent()
			if e != nil || held.Plan.ID != q.ID {
				return ErrGrant
			}
			return b.store.writeStorageIntent(intent)
		})
		if e != nil {
			return nil, Error("operation-uncertain")
		}
		b.closeStorageBrowse()
		return intent.Plan, nil
	}
	return nil, ErrRequest
}

var storageMedia = regexp.MustCompile(`^[a-zA-Z0-9!#$&^_.+-]+/[a-zA-Z0-9!#$&^_.+-]+$`)

func validStorageMedia(s string) bool {
	return len(s) <= 120 && storageMedia.MatchString(s) && !strings.HasPrefix(strings.ToLower(s), "application/vnd.google-apps.")
}
func storageMatch(name, query string) bool {
	for _, word := range strings.Fields(strings.ToLower(query)) {
		if !strings.Contains(strings.ToLower(name), word) {
			return false
		}
	}
	return true
}
