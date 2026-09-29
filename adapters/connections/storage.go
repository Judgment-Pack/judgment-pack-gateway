package connections

// Storage is a personal, authenticated host control protocol. It does not run
// through /acquire or mint evidence/action receipts. The trusted host presents
// mutations to the user; the model must never receive the commit operation.
import (
	"adapters/internal/canon"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const StorageLineBytes = 6 << 20
const StoragePageItems = 24

// Includes worst-case JSON escaping of 24 bounded IDs and names.
const StorageMetadataBytes = 512 << 10

var storageMethods = []string{"files-list", "files-read", "files-prepare", "files-commit", "files-status"}

// StorageConvertMethod prepares the creation of a Google Doc from a Word file,
// by Drive's own conversion. It is Drive's alone, and a method of its own so
// that the catalog's operations stay what they are, the methods a provider
// answers: a host that does not know the method never calls it, and a
// provider that does not list it refuses it (docs/design/storage-files.md).
const StorageConvertMethod = "files-prepare-google-document"

// The one conversion: what is uploaded, and what Drive is asked to make of it.
const (
	storageWordMedia           = "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
	storageGoogleDocumentMedia = "application/vnd.google-apps.document"
	storageGoogleDocument      = "google-document"
)

func StorageMethod(method string) bool {
	for _, m := range storageMethods {
		if m == method {
			return true
		}
	}
	return false
}

// storageMethodOf reports whether a provider answers a storage method: the
// five every storage provider has, and the conversion, which is Drive's.
func storageMethodOf(provider, method string) bool {
	return storageProvider(provider) && (StorageMethod(method) || provider == "google-drive" && method == StorageConvertMethod)
}

// StorageUpload reports whether a method's request carries a file's content,
// and so whether its line may be as long as a file allows.
func StorageUpload(method string) bool {
	return method == "files-prepare" || method == StorageConvertMethod
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
	if canon.ExactNames(raw, out) != nil {
		forget(out)
		return ErrRequest
	}
	return nil
}

type StorageFile struct {
	Context   string `json:"context"`
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
	Context       string        `json:"context"`
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
	Context   string `json:"context"`
	Action    string `json:"action"`
	ID        string `json:"id"`
	Folder    string `json:"folder"`
	Name      string `json:"name"`
	Revision  string `json:"revision"`
	MediaType string `json:"mediaType"`
	Content   string `json:"contentBase64"`
	// ConvertTo is set by the conversion's own method and by nothing a
	// caller writes: files-prepare refuses a request that carries it.
	ConvertTo string `json:"convertTo,omitempty"`
}

// exactStrings holds a request to its members by their exact names: each
// required one is present, none is present that is neither required nor
// optional, and every value is a JSON string. The decoder alone takes a name
// whatever its case, and takes null for a string.
func exactStrings(raw []byte, required, optional []string) bool {
	// What is no JSON object has no members, and so none that is required.
	var members map[string]json.RawMessage
	json.Unmarshal(raw, &members)
	known := 0
	for _, name := range required {
		if _, has := members[name]; !has {
			return false
		}
		known++
	}
	for _, name := range optional {
		if _, has := members[name]; has {
			known++
		}
	}
	if known != len(members) {
		return false
	}
	for _, value := range members {
		if !bytes.HasPrefix(value, []byte{'"'}) {
			return false
		}
	}
	return true
}

// wordFraming reports whether a file is framed as a Word file is. It begins
// as an archive's first entry does; it ends with an archive's end record,
// whose comment runs to the end of the file; and it holds the name of the part
// every package of this kind has. No entry is read and nothing is
// decompressed: this is a test of three signatures and not of an archive. It
// keeps out some of what is no Word file and says nothing of whether what it
// admits is one.
func wordFraming(data []byte) bool {
	if !bytes.HasPrefix(data, []byte("PK\x03\x04")) || !bytes.Contains(data, []byte("[Content_Types].xml")) {
		return false
	}
	// The end record is 22 bytes, and the comment its last two state after it.
	for at := len(data) - 22; at >= 0; at-- {
		if bytes.HasPrefix(data[at:], []byte("PK\x05\x06")) && at+22+int(binary.LittleEndian.Uint16(data[at+20:])) == len(data) {
			return true
		}
	}
	return false
}

// storageChangeRequest is what files-prepare takes: a change without the
// member the conversion's method sets. A request that carries that member,
// whatever its value, carries a member the method does not know.
type storageChangeRequest struct {
	Context   string `json:"context"`
	Action    string `json:"action"`
	ID        string `json:"id"`
	Folder    string `json:"folder"`
	Name      string `json:"name"`
	Revision  string `json:"revision"`
	MediaType string `json:"mediaType"`
	Content   string `json:"contentBase64"`
}

// StorageConversion is what files-prepare-google-document takes: where the
// document is to be, its name, and the Word file it is made from. The folder
// may be left out; the other four are required.
type StorageConversion struct {
	Context   string `json:"context"`
	Folder    string `json:"folder"`
	Name      string `json:"name"`
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
	// ConvertTo says what the file becomes, where it becomes something other
	// than the file uploaded, so that a person sees it before they confirm.
	ConvertTo string `json:"convertTo,omitempty"`
	// Folder is where a conversion puts the document, since the plan of one
	// has no target to find it by. It is absent where no folder was named.
	Folder string `json:"folder,omitempty"`
	// ProviderStatus is the status of the provider's answer, as three
	// digits, where a conversion's outcome is not known although the
	// provider answered in full.
	ProviderStatus string `json:"providerStatus,omitempty"`
}

// storageAnswered is an outcome that is not known although the provider
// answered in full. It is the status of that answer.
type storageAnswered int

func (storageAnswered) Error() string { return "operation-uncertain" }

// storedPlan is a plan as a caller is told of it. One that was claimed and
// not settled is one whose outcome is not known.
func storedPlan(plan StoragePlan) StoragePlan {
	if plan.State == "executing" {
		plan.State = "needs-attention"
		plan.Error = "operation-uncertain"
	}
	return plan
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
		if errors.Is(e, os.ErrNotExist) {
			// os.Root may report ENOENT for a dangling link. Only an absent
			// directory entry is proof that no prior record exists.
			if _, statErr := s.root.Lstat("storage-intent.json"); errors.Is(statErr, os.ErrNotExist) {
				return out, ErrGrant
			}
		}
		return out, ErrStorage
	}
	defer f.Close()
	st, e := f.Stat()
	if e != nil || !st.Mode().IsRegular() || private(st, false) != nil || st.Size() > StorageLineBytes {
		return out, ErrStorage
	}
	raw, e := io.ReadAll(io.LimitReader(f, StorageLineBytes+1))
	if e != nil || decodeStorage(raw, &out) != nil || !opaque.MatchString(out.Plan.ID) || out.Connection == "" || out.Epoch == "" {
		return out, ErrStorage
	}
	switch out.Plan.State {
	case "prepared", "executing", "completed", "refused", "needs-attention":
	default:
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
	if b.provider.kind() == "google-drive" && method != "files-status" && method != "files-commit" {
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
		page.Context = storageContext(c, epoch)
		for i := range page.Items {
			page.Items[i].Context = page.Context
		}
		return page, nil
	case "files-read":
		var q struct {
			Context  string `json:"context"`
			ID       string `json:"id"`
			Revision string `json:"revision"`
		}
		if decode(raw, &q) != nil || q.Revision == "" {
			return nil, ErrRequest
		}
		if q.Context != storageContext(c, epoch) {
			return nil, ErrChanged
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
		file.Context = storageContext(c, epoch)
		return StorageRead{file, base64.StdEncoding.EncodeToString(data)}, nil
	case "files-prepare", StorageConvertMethod:
		var q StorageChange
		if method == StorageConvertMethod {
			// The conversion has a request of its own, with no action, no
			// target and no revision: it creates, and what it creates has no
			// name in Drive until Drive has made it.
			var conversion StorageConversion
			if decodeStorage(raw, &conversion) != nil || !exactStrings(raw, []string{"context", "name", "mediaType", "contentBase64"}, []string{"folder"}) {
				return nil, ErrRequest
			}
			q = StorageChange{Context: conversion.Context, Action: "create", Folder: conversion.Folder, Name: conversion.Name, MediaType: conversion.MediaType, Content: conversion.Content, ConvertTo: storageGoogleDocument}
		} else {
			var change storageChangeRequest
			if decodeStorage(raw, &change) != nil {
				return nil, ErrRequest
			}
			q = StorageChange{Context: change.Context, Action: change.Action, ID: change.ID, Folder: change.Folder, Name: change.Name, Revision: change.Revision, MediaType: change.MediaType, Content: change.Content}
		}
		if !resourceText(q.ID, 1024, true) || !resourceText(q.Name, 1024, true) || !resourceText(q.Folder, 1024, true) || !resourceText(q.Revision, 256, true) {
			return nil, ErrRequest
		}
		if q.Context != storageContext(c, epoch) {
			return nil, ErrChanged
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
		// A conversion is of a Word file and of nothing else. The media type is
		// the caller's word for it, and the file is held to be framed as a Word
		// file is. One that is not is refused here, and no upload is spent on
		// it. What Drive makes of any file is Drive's to say, and was not tried.
		if q.ConvertTo != "" && (q.MediaType != storageWordMedia || !wordFraming(data)) {
			return nil, ErrUnsupported
		}
		file, etag, e := b.storagePreflight(ctx, &q, token)
		if e != nil {
			return nil, e
		}
		plan := StoragePlan{ID: randomID(), Action: q.Action, Target: file.ID, Name: file.Name, Revision: q.Revision, Size: len(data), State: "prepared", Expires: time.Now().Add(5 * time.Minute).UTC().Format(time.RFC3339), Effect: "write", ConvertTo: q.ConvertTo}
		if q.ConvertTo != "" {
			plan.Folder = q.Folder
		}
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
			prior, err := b.store.readStorageIntent()
			if err != nil && !errors.Is(err, ErrGrant) {
				return err
			}
			if err == nil && (prior.Plan.State == "executing" || prior.Plan.State == "needs-attention") && prior.Connection == c.ID && prior.Epoch == epoch {
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
			return storedPlan(intent.Plan), nil
		}
		deadline, e := time.Parse(time.RFC3339, intent.Plan.Expires)
		if e != nil || !time.Now().Before(deadline) {
			return nil, ErrGrant
		}
		if intent.Change.Action == "delete" && q.Confirmation != intent.Plan.Confirmation {
			return nil, Error("confirmation-required")
		}
		// Status and settled replay are local, even when provider credentials expire.
		if b.provider.kind() == "google-drive" {
			token, e = b.provider.access(ctx, b.store, client, c, epoch)
			if e != nil {
				return nil, e
			}
		}
		// The claim survives process loss. Reusing its ID never repeats a mutation.
		var claimed *StoragePlan
		e = b.store.locked(func(v *state) error {
			if e := currentStorage(v, c, epoch); e != nil {
				return e
			}
			held, e := b.store.readStorageIntent()
			if e != nil || held.Plan.ID != q.ID {
				return ErrGrant
			}
			// Another committer claimed the plan after this one read it. The
			// plan was sent, or is being sent, and this commit says what is
			// stored of it: it is not a plan that expired.
			if held.Plan.State != "prepared" {
				claimed = &held.Plan
				return nil
			}
			if !time.Now().Before(deadline) {
				return ErrGrant
			}
			intent.Plan.State = "executing"
			return b.store.writeStorageIntent(intent)
		})
		if e != nil {
			return nil, e
		}
		if claimed != nil {
			return storedPlan(*claimed), nil
		}
		target, err := b.storageApply(ctx, intent, token)
		intent.Plan.State = "completed"
		if target != "" {
			intent.Plan.Target = target
		}
		if err != nil {
			intent.Plan.State = "needs-attention"
			intent.Plan.Error = "operation-uncertain"
			// Drive made a file and did not say it is a Google Doc. The file is
			// named in the plan's target, and a person looks at it.
			if err == errConversionUnconfirmed {
				intent.Plan.Error = err.Error()
			}
			// Drive answered in full and the outcome is still not known. What
			// it answered is kept, for the person who looks.
			// A status is three digits, and one that is not is not kept.
			var answered storageAnswered
			if errors.As(err, &answered) && answered >= 100 && answered <= 999 {
				intent.Plan.ProviderStatus = strconv.Itoa(int(answered))
			}
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

// errConversionUnconfirmed is a create by conversion that Drive answered with
// a file that is not a Google Doc.
const errConversionUnconfirmed = Error("conversion-unconfirmed")

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

// A public opaque generation marker, not an authorization token. It prevents
// an editor or caller rebinding an old file selection to a new connection.
func storageContext(c credential, epoch string) string { return digest([]byte(c.ID + "\x00" + epoch)) }
