package connections

// Recurring source reads are a private, authenticated host control protocol.
// A binding records the host's explicit recurring-read request; it is never
// inferred from a picker grant and never offered through model-facing tools.
import (
	"adapters/attachment"
	"adapters/internal/canon"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"time"
)

const SourceObservationLineBytes = MaxOutputBytes + ControlLineBytes
const SourceBindingActiveLimit = 32
const SourceBindingOperationLimit = 48

const (
	ErrSourceBinding  Error = "source-binding-unavailable"
	ErrSourceConflict Error = "source-binding-idempotency-conflict"
	ErrSourceLimit    Error = "source-binding-limit"
)

var sourceMethods = []string{"source-bind", "source-bindings", "source-revoke", "source-observe"}

func sourceMethodOf(provider, method string) bool {
	if provider != "google-drive" {
		return false
	}
	for _, name := range sourceMethods {
		if method == name {
			return true
		}
	}
	return false
}

type SourceIdentity struct {
	Provider   string `json:"provider"`
	AccountID  string `json:"accountId"`
	ResourceID string `json:"resourceId"`
}
type SourceLifecycle struct {
	Kind string `json:"kind"`
}
type SourceBinding struct {
	Version     int             `json:"version"`
	OperationID string          `json:"operationId"`
	BindingID   string          `json:"bindingId"`
	Source      SourceIdentity  `json:"source"`
	CreatedAt   string          `json:"createdAt"`
	State       string          `json:"state"`
	Coverage    string          `json:"coverage"`
	Lifecycle   SourceLifecycle `json:"lifecycle"`
}
type SourceBindings struct {
	Version  int             `json:"version"`
	Bindings []SourceBinding `json:"bindings"`
}
type SourceContent struct {
	BytesDigest string `json:"bytesDigest"`
	ByteLength  int64  `json:"byteLength"`
	MediaType   string `json:"mediaType"`
}
type SourceExtraction struct {
	Content             SourceContent `json:"content"`
	Profile             string        `json:"profile"`
	Processor           string        `json:"processor"`
	ProcessorVersion    string        `json:"processorVersion"`
	ConfigurationDigest string        `json:"configurationDigest"`
}
type SourceObservation struct {
	Version        int              `json:"version"`
	BindingID      string           `json:"bindingId"`
	ObservationID  string           `json:"observationId"`
	Source         SourceIdentity   `json:"source"`
	SourceRevision string           `json:"sourceRevision"`
	ObservedAt     string           `json:"observedAt"`
	Availability   string           `json:"availability"`
	Content        SourceContent    `json:"content"`
	Extraction     SourceExtraction `json:"extraction"`
	Lifecycle      SourceLifecycle  `json:"lifecycle"`
	Coverage       string           `json:"coverage"`
	Document       json.RawMessage  `json:"document"`
}

type sourceBindRequest struct {
	OperationID      string `json:"operationId"`
	ResourceID       string `json:"resourceId"`
	SelectionContext string `json:"selectionContext"`
	Consent          string `json:"consent"`
}
type sourceBindingRecord struct {
	OperationID   string `json:"operationId"`
	BindingID     string `json:"bindingId"`
	RequestDigest string `json:"requestDigest"`
	Connection    string `json:"connection"`
	Epoch         string `json:"epoch"`
	AccountID     string `json:"accountId"`
	ResourceID    string `json:"resourceId"`
	CreatedAt     string `json:"createdAt"`
	Revoked       bool   `json:"revoked"`
}
type sourceBindingStore struct {
	Version    string                `json:"version"`
	Operations []sourceBindingRecord `json:"operations"`
}

func (r sourceBindingRecord) public() SourceBinding {
	state := "active"
	if r.Revoked {
		state = "revoked"
	}
	return SourceBinding{1, r.OperationID, r.BindingID, SourceIdentity{"google-drive", r.AccountID, r.ResourceID}, r.CreatedAt, state, "snapshot-only", SourceLifecycle{"not-exposed"}}
}

// Separate from state.json so that older releases keep reading their own
// closed state format. No credential is copied into a binding or its receipt.
// Receipts are never evicted: exhausting the bound refuses new operations,
// rather than allowing an uncertain retry to recreate a revoked binding.
func (s *Store) sourceBindings() (sourceBindingStore, error) {
	data, err := s.read("source-bindings.json")
	if errors.Is(err, os.ErrNotExist) {
		return sourceBindingStore{"1", []sourceBindingRecord{}}, nil
	}
	var out sourceBindingStore
	if err != nil || decode(data, &out) != nil || out.Version != "1" || out.Operations == nil || len(out.Operations) > SourceBindingOperationLimit {
		return out, ErrStorage
	}
	ops, bindings := map[string]bool{}, map[string]bool{}
	for _, r := range out.Operations {
		stamp, err := time.Parse("2006-01-02T15:04:05Z", r.CreatedAt)
		if !opaque.MatchString(r.OperationID) || !opaque.MatchString(r.BindingID) || !opaque.MatchString(r.Connection) || !opaque.MatchString(r.Epoch) || !identifier.MatchString(r.AccountID) || !identifier.MatchString(r.ResourceID) || !validDigest(r.RequestDigest) || err != nil || stamp.UTC().Format("2006-01-02T15:04:05Z") != r.CreatedAt || ops[r.OperationID] || bindings[r.BindingID] {
			return out, ErrStorage
		}
		request, err := canon.EncodeJSON(sourceBindRequest{r.OperationID, r.ResourceID, r.Epoch, "recurring-read"})
		if err == nil {
			request, err = canon.Canonicalize(request, canon.RefuseNumbers)
		}
		if err != nil || digest(request) != r.RequestDigest {
			return out, ErrStorage
		}
		ops[r.OperationID], bindings[r.BindingID] = true, true
	}
	return out, nil
}

// ExportSourceObservations is a custody's observation journal -- the
// recurring bindings' operation records, which hold no credential
// (ADR-0020) -- for an audit export (`gateway export --observations`): the
// document as the custody holds it, read under the custody lock once it
// reads as a journal, or the empty journal where the namespace holds none
// yet. A custody that is not there is os.ErrNotExist, and nothing is made
// for it; one that is there gains at most the lock file every custody
// operation makes.
func ExportSourceObservations(dir, principal string) ([]byte, error) {
	if !filepath.IsAbs(dir) || !identifier.MatchString(principal) {
		return nil, ErrRequest
	}
	s, err := peekStore(dir, principal)
	if err != nil {
		return nil, err
	}
	defer s.Close()
	var journal []byte
	err = s.locked(func(*state) error {
		if _, err := s.sourceBindings(); err != nil {
			return err
		}
		data, err := s.read("source-bindings.json")
		if errors.Is(err, os.ErrNotExist) {
			journal, err = json.Marshal(sourceBindingStore{"1", []sourceBindingRecord{}})
			return err
		}
		journal = data
		return err
	})
	if err != nil {
		return nil, err
	}
	return journal, nil
}

func validDigest(value string) bool {
	return len(value) == 71 && value[:7] == "sha256:" && opaque.MatchString(value[7:])
}

func (s *Store) sourceConnection(v *state) error {
	if v.Disabled {
		return ErrPolicy
	}
	if v.Connection == nil {
		return ErrConnect
	}
	if !opaque.MatchString(v.Epoch) || !opaque.MatchString(v.Connection.ID) || !identifier.MatchString(v.Connection.Account.ID) || s.consentedScope(*v.Connection) != driveScope {
		return ErrRevoked
	}
	return nil
}
func sourceCurrent(v *state, r sourceBindingRecord) bool {
	return v.Connection != nil && v.Connection.ID == r.Connection && v.Connection.Account.ID == r.AccountID && v.Epoch == r.Epoch
}

func (b *Broker) sourceOperation(ctx context.Context, method string, raw []byte) (any, error) {
	switch method {
	case "source-bind":
		var q sourceBindRequest
		if decode(raw, &q) != nil || !exactStrings(raw, []string{"operationId", "resourceId", "selectionContext", "consent"}, nil) || !opaque.MatchString(q.OperationID) || !identifier.MatchString(q.ResourceID) || !opaque.MatchString(q.SelectionContext) || q.Consent != "recurring-read" {
			return nil, ErrRequest
		}
		canonical, _ := canon.EncodeJSON(q)
		canonical, _ = canon.Canonicalize(canonical, canon.RefuseNumbers)
		requestDigest := digest(canonical)
		var out SourceBinding
		err := b.store.locked(func(v *state) error {
			if err := b.store.sourceConnection(v); err != nil {
				return err
			}
			store, err := b.store.sourceBindings()
			if err != nil {
				return err
			}
			active := 0
			for _, r := range store.Operations {
				if r.OperationID == q.OperationID {
					if r.RequestDigest != requestDigest {
						return ErrSourceConflict
					}
					if !sourceCurrent(v, r) {
						return ErrSourceBinding
					}
					out = r.public()
					return nil
				}
				if !r.Revoked && sourceCurrent(v, r) {
					active++
				}
			}
			if v.Epoch != q.SelectionContext {
				return ErrRequest
			}
			if active >= SourceBindingActiveLimit || len(store.Operations) >= SourceBindingOperationLimit {
				return ErrSourceLimit
			}
			r := sourceBindingRecord{q.OperationID, randomID(), requestDigest, v.Connection.ID, v.Epoch, v.Connection.Account.ID, q.ResourceID, time.Now().UTC().Format("2006-01-02T15:04:05Z"), false}
			store.Operations = append(store.Operations, r)
			if err := b.store.write("source-bindings.json", store); err != nil {
				return err
			}
			out = r.public()
			return nil
		})
		if err != nil {
			return nil, err
		}
		return out, nil
	case "source-bindings":
		var empty struct{}
		if decode(raw, &empty) != nil {
			return nil, ErrRequest
		}
		out := SourceBindings{1, []SourceBinding{}}
		err := b.store.locked(func(v *state) error {
			if err := b.store.sourceConnection(v); err != nil {
				return err
			}
			store, err := b.store.sourceBindings()
			if err != nil {
				return err
			}
			for _, r := range store.Operations {
				if sourceCurrent(v, r) {
					out.Bindings = append(out.Bindings, r.public())
				}
			}
			return nil
		})
		if err != nil {
			return nil, err
		}
		return out, nil
	case "source-revoke", "source-observe":
		var q struct {
			BindingID string `json:"bindingId"`
		}
		if decode(raw, &q) != nil || !exactStrings(raw, []string{"bindingId"}, nil) || !opaque.MatchString(q.BindingID) {
			return nil, ErrRequest
		}
		if method == "source-observe" {
			return b.observeSource(ctx, q.BindingID)
		}
		err := b.store.locked(func(v *state) error {
			return b.store.revokeSourceBinding(v, q.BindingID)
		})
		if err != nil {
			return nil, err
		}
		return map[string]bool{"revoked": true}, nil
	}
	return nil, ErrRequest
}

func (s *Store) revokeSourceBinding(v *state, id string) error {
	if err := s.sourceConnection(v); err != nil {
		return err
	}
	store, err := s.sourceBindings()
	if err != nil {
		return err
	}
	for i, r := range store.Operations {
		if r.BindingID == id {
			if !sourceCurrent(v, r) {
				return ErrSourceBinding
			}
			if r.Revoked {
				return nil
			}
			store.Operations[i].Revoked = true
			return s.write("source-bindings.json", store)
		}
	}
	return nil
}

// A successful interactive Drive reconsent invalidates recurring authority,
// even though legacy picker grants and storage plans intentionally keep their
// connection ID/epoch. Ordinary access-token refresh does not call this method.
// Tombstones are committed before replacing credentials: a failed later write
// may conservatively revoke a binding, but can never restore old authority.
func (s *Store) invalidateSourceBindings(v *state) error {
	store, err := s.sourceBindings()
	if err != nil {
		return err
	}
	changed := false
	for i, r := range store.Operations {
		if !r.Revoked && sourceCurrent(v, r) {
			store.Operations[i].Revoked, changed = true, true
		}
	}
	if !changed {
		return nil
	}
	return s.write("source-bindings.json", store)
}

func (s *Store) sourceBindingAt(v *state, id string) (sourceBindingRecord, error) {
	if err := s.sourceConnection(v); err != nil {
		return sourceBindingRecord{}, err
	}
	store, err := s.sourceBindings()
	if err != nil {
		return sourceBindingRecord{}, err
	}
	for _, r := range store.Operations {
		if r.BindingID == id && !r.Revoked && sourceCurrent(v, r) {
			return r, nil
		}
	}
	return sourceBindingRecord{}, ErrSourceBinding
}

func (s *Store) currentSourceBinding(id string) (sourceBindingRecord, Client, credential, string, error) {
	var record sourceBindingRecord
	var client Client
	var c credential
	var epoch string
	err := s.locked(func(v *state) error {
		r, err := s.sourceBindingAt(v, id)
		if err != nil {
			return err
		}
		record, client, c, epoch = r, v.Client, *v.Connection, v.Epoch
		return nil
	})
	return record, client, c, epoch, err
}

func (b *Broker) observeSource(ctx context.Context, id string) (any, error) {
	r, client, c, epoch, err := b.store.currentSourceBinding(id)
	if err != nil {
		return nil, err
	}
	guard := func() error {
		if ctx.Err() != nil {
			return ErrCanceled
		}
		current, currentClient, _, _, err := b.store.currentSourceBinding(id)
		if err != nil {
			return err
		}
		if current != r || currentClient != client {
			return ErrSourceBinding
		}
		return nil
	}
	if err := b.store.grantUse(ctx, b.provider, b.provider.kind(), "observe"); err != nil {
		return nil, err
	}
	var profile driveReadProfile
	raw, err := b.provider.readDriveDocument(ctx, b.store, r.ResourceID, client, c, epoch, guard, &profile)
	if err != nil {
		return nil, err
	}
	var envelope struct {
		Acquisition struct {
			ObservedAt string `json:"observedAt"`
		} `json:"acquisition"`
		Result json.RawMessage `json:"result"`
	}
	if json.Unmarshal(raw, &envelope) != nil || attachment.Check(envelope.Result) != nil {
		return nil, Error("processing-failed")
	}
	var record attachment.Record
	if json.Unmarshal(envelope.Result, &record) != nil || record.Original.Bytes == nil || record.Provenance.Processor == nil || record.Document.Version == nil {
		return nil, Error("processing-failed")
	}
	original, err := base64.StdEncoding.DecodeString(*record.Original.Bytes)
	if err != nil || len(original) == 0 || len(original) > MaxFileBytes || digest(original) != record.Document.ID || record.Document.Size != int64(len(original)) || record.Provenance.Source.FileID != r.ResourceID || record.Provenance.Source.Version != *record.Document.Version {
		return nil, Error("processing-failed")
	}
	configurationDigest, err := sourceProcessingDigest(record, profile.requestedOCR)
	if err != nil {
		return nil, Error("processing-failed")
	}
	// The retained extraction artifact is the exact canonical attachment record,
	// including its status and extraction limits. Original bytes have their own
	// identity, and the provider revision remains an independent opaque value.
	documentBytes, err := canon.Canonicalize(envelope.Result, canon.RefuseNumbers)
	if err != nil {
		return nil, Error("processing-failed")
	}
	out := SourceObservation{1, id, randomID(), r.public().Source, *record.Document.Version, envelope.Acquisition.ObservedAt, "present", SourceContent{digest(original), int64(len(original)), record.Document.MediaType}, SourceExtraction{SourceContent{digest(documentBytes), int64(len(documentBytes)), "application/vnd.jpack.attachment+json"}, "attachment-record-v1/canon", *record.Provenance.Processor, record.Provenance.Adapter.Version, configurationDigest}, SourceLifecycle{"not-exposed"}, "snapshot-only", documentBytes}
	encoded, err := canon.EncodeJSON(out)
	if err == nil {
		encoded, err = canon.Canonicalize(encoded, canon.RefuseNumbers)
	}
	if err != nil || len(encoded) > MaxOutputBytes {
		return nil, Error("response-too-large")
	}
	accepted, err := b.store.admitSourceObservation(ctx, r, client, out)
	if err != nil {
		return nil, err
	}
	return *accepted, nil
}

// Admission linearizes at the assignment under the same custody lock that
// commits revocation. No artifact enters the host's reply on a failed check.
// Pipe delivery may occur later: a subsequent revocation cannot retract an
// already admitted response, and the consuming host must fence its own state.
func (s *Store) admitSourceObservation(ctx context.Context, expected sourceBindingRecord, client Client, observation SourceObservation) (*SourceObservation, error) {
	var accepted *SourceObservation
	err := s.locked(func(v *state) error {
		if ctx.Err() != nil {
			return ErrCanceled
		}
		current, err := s.sourceBindingAt(v, expected.BindingID)
		if err != nil {
			return err
		}
		if current != expected || v.Client != client || observation.BindingID != expected.BindingID || observation.Source != expected.public().Source {
			return ErrSourceBinding
		}
		accepted = &observation
		return nil
	})
	return accepted, err
}

// This profile identifies the actual processing recorded with the artifact:
// bounds, processor/adapter identity, actual request mode and applied OCR
// program. Runtime values (timestamps, duration and OCR page numbers) are
// excluded. This digest is not the identity of unrecorded external settings.
func sourceProcessingDigest(record attachment.Record, requestedOCR string) (string, error) {
	if requestedOCR != "auto" && requestedOCR != "never" {
		return "", Error("processing-failed")
	}
	var ocr any
	if record.Provenance.OCR != nil {
		ocr = map[string]any{"program": record.Provenance.OCR.Program, "digest": record.Provenance.OCR.Digest}
	}
	configuration, err := canon.EncodeJSON(map[string]any{"profile": "drive-document-processing-v1", "bounds": record.Processing.Bounds, "requestOCR": requestedOCR, "adapter": record.Provenance.Adapter, "processor": record.Provenance.Processor, "ocr": ocr})
	if err == nil {
		configuration, err = canon.Canonicalize(configuration, canon.RefuseNumbers)
	}
	if err != nil {
		return "", err
	}
	return digest(configuration), nil
}
