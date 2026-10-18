//go:build linux || darwin

package connections

import (
	"adapters/attachment"
	"adapters/internal/canon"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

type sourceTransport func(*http.Request) (*http.Response, error)

func (f sourceTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func sourceReply(status int, body string) *http.Response {
	return &http.Response{StatusCode: status, Header: http.Header{}, Body: io.NopCloser(strings.NewReader(body)), ContentLength: -1}
}

// All acquisition and extraction are real. Only the provider's HTTP transport
// is synthetic, so authorization races do not need a network listener.
func sourceBroker(t *testing.T) (*Broker, string, *atomic.Int32) {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	s, err := OpenStore(dir, "alice")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	if err := s.locked(func(v *state) error {
		v.Epoch = randomID()
		v.Client = Client{"source-test.apps.googleusercontent.com", "source-client-secret"}
		v.Connection = &credential{ID: randomID(), Account: account{ID: "account-A", Email: "person@example.test", Name: "Person"}, Access: "source-access-private", Refresh: "source-refresh-private", Expires: time.Now().Add(time.Hour).Unix()}
		if err := s.write("state.json", v); err != nil {
			return err
		}
		return s.recordConsent(v.Connection, driveScope)
	}); err != nil {
		t.Fatal(err)
	}
	b := New(s, false)
	b.provider.revoke = ""
	t.Cleanup(b.Close)
	count := &atomic.Int32{}
	b.provider.client = &http.Client{Transport: sourceTransport(func(r *http.Request) (*http.Response, error) {
		count.Add(1)
		if r.Header.Get("Authorization") != "Bearer source-access-private" {
			t.Error("missing provider authentication")
		}
		if r.URL.Query().Get("alt") == "media" {
			return sourceReply(200, "A test policy document."), nil
		}
		return sourceReply(200, `{"id":"file-A","name":"policy.txt","mimeType":"text/plain","version":"7","size":"23","capabilities":{"canDownload":true}}`), nil
	})}
	return b, dir, count
}
func sourceBindBody(t *testing.T, b *Broker, operation string) sourceBindRequest {
	t.Helper()
	var epoch string
	if err := b.store.locked(func(v *state) error { epoch = v.Epoch; return nil }); err != nil {
		t.Fatal(err)
	}
	return sourceBindRequest{operation, "file-A", epoch, "recurring-read"}
}
func bindSource(t *testing.T, b *Broker) SourceBinding {
	t.Helper()
	out, err := b.Handle(context.Background(), "source-bind", mustJSON(sourceBindBody(t, b, randomID())))
	if err != nil {
		t.Fatal(err)
	}
	return out.(SourceBinding)
}
func observeSource(t *testing.T, b *Broker, id string) SourceObservation {
	t.Helper()
	out, err := b.Handle(context.Background(), "source-observe", mustJSON(map[string]string{"bindingId": id}))
	if err != nil {
		t.Fatal(err)
	}
	return out.(SourceObservation)
}
func revokeSource(t *testing.T, b *Broker, id string) {
	t.Helper()
	out, err := b.Handle(context.Background(), "source-revoke", mustJSON(map[string]string{"bindingId": id}))
	if err != nil || out.(map[string]bool)["revoked"] != true {
		t.Fatal(out, err)
	}
}

func TestSourceBindingRequiresSeparateExplicitRecurringConsent(t *testing.T) {
	b, _, count := sourceBroker(t)
	body := sourceBindBody(t, b, randomID())
	for name, change := range map[string]func(map[string]any){
		"no consent":            func(v map[string]any) { delete(v, "consent") },
		"null consent":          func(v map[string]any) { v["consent"] = nil },
		"picker consent":        func(v map[string]any) { v["consent"] = "one-use" },
		"picker grant":          func(v map[string]any) { v["grant"] = randomID() },
		"old epoch":             func(v map[string]any) { v["selectionContext"] = randomID() },
		"no operation identity": func(v map[string]any) { delete(v, "operationId") },
		"resource escape":       func(v map[string]any) { v["resourceId"] = "../state.json" },
	} {
		t.Run(name, func(t *testing.T) {
			var v map[string]any
			json.Unmarshal(mustJSON(body), &v)
			change(v)
			if out, err := b.Handle(context.Background(), "source-bind", mustJSON(v)); err != ErrRequest || out != nil {
				t.Fatal(out, err)
			}
		})
	}
	selected, err := b.Handle(context.Background(), "select", mustJSON(map[string]any{"resourceIds": []string{"file-A"}, "selectionContext": body.SelectionContext}))
	if err != nil {
		t.Fatal(err)
	}
	grant := selected.([]SourceSelection)[0].Grant
	if out, err := b.Handle(context.Background(), "source-observe", mustJSON(map[string]string{"bindingId": grant})); err != ErrSourceBinding || out != nil {
		t.Fatal("picker grant became recurring authority", out, err)
	}
	if out, err := b.Handle(context.Background(), "source-bindings", []byte(`{}`)); err != nil || len(out.(SourceBindings).Bindings) != 0 || count.Load() != 0 {
		t.Fatal(out, err, count.Load())
	}
	if err := b.store.root.Remove("consent.json"); err != nil {
		t.Fatal(err)
	}
	if out, err := b.Handle(context.Background(), "source-bind", mustJSON(body)); err != ErrRevoked || out != nil {
		t.Fatal("old OAuth consent promoted", out, err)
	}
}

func TestSourceBindingRecoveryAndIndependentRevocation(t *testing.T) {
	b, _, count := sourceBroker(t)
	body := sourceBindBody(t, b, randomID())
	first, err := b.Handle(context.Background(), "source-bind", mustJSON(body))
	if err != nil {
		t.Fatal(err)
	}
	recovered, err := b.Handle(context.Background(), "source-bind", mustJSON(body))
	if err != nil || recovered.(SourceBinding) != first.(SourceBinding) {
		t.Fatal("retry created another binding", recovered, err)
	}
	body.ResourceID = "file-B"
	if out, err := b.Handle(context.Background(), "source-bind", mustJSON(body)); err != ErrSourceConflict || out != nil {
		t.Fatal(out, err)
	}
	body.ResourceID = "file-A"
	second := bindSource(t, b)
	one := first.(SourceBinding)
	if second.BindingID == one.BindingID {
		t.Fatal("independent policies share revocation")
	}
	revokeSource(t, b, one.BindingID)
	revokeSource(t, b, one.BindingID)
	recovered, err = b.Handle(context.Background(), "source-bind", mustJSON(body))
	if err != nil || recovered.(SourceBinding).State != "revoked" || recovered.(SourceBinding).BindingID != one.BindingID {
		t.Fatal("retry recreated revoked authority", recovered, err)
	}
	if out, err := b.Handle(context.Background(), "source-observe", mustJSON(map[string]string{"bindingId": one.BindingID})); out != nil || err != ErrSourceBinding || count.Load() != 0 {
		t.Fatal(out, err, count.Load())
	}
	observeSource(t, b, second.BindingID)
	listed, err := b.Handle(context.Background(), "source-bindings", []byte(`{}`))
	if err != nil || len(listed.(SourceBindings).Bindings) != 2 || listed.(SourceBindings).Bindings[0].OperationID != one.OperationID || listed.(SourceBindings).Bindings[0].State != "revoked" {
		t.Fatal(listed, err)
	}
}

func TestSourceObservationRetainsRealOriginalExtractionAndOpaqueRevisionAfterRestart(t *testing.T) {
	b, dir, count := sourceBroker(t)
	binding := bindSource(t, b)
	one := observeSource(t, b, binding.BindingID)
	if path := os.Getenv("JPACK_TEST_SOURCE_OBSERVATION"); path != "" {
		artifact, err := canon.EncodeJSON(one)
		if err == nil {
			artifact, err = canon.Canonicalize(artifact, canon.RefuseNumbers)
		}
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, artifact, 0600); err != nil {
			t.Fatal(err)
		}
	}
	s, err := OpenStore(dir, "alice")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	restarted := New(s, false)
	defer restarted.Close()
	restarted.provider = b.provider
	two := observeSource(t, restarted, binding.BindingID)
	if one.ObservationID == two.ObservationID || one.Content != two.Content || count.Load() != 6 {
		t.Fatal("recurring read lost identity", one.Content, two.Content, count.Load())
	}
	prior := restarted.provider.client.Transport
	restarted.provider.client = &http.Client{Transport: sourceTransport(func(r *http.Request) (*http.Response, error) {
		res, err := prior.RoundTrip(r)
		if r.URL.Query().Get("alt") != "media" {
			data, _ := io.ReadAll(res.Body)
			res.Body.Close()
			res.Body = io.NopCloser(strings.NewReader(strings.ReplaceAll(string(data), `"version":"7"`, `"version":"opaque-new"`)))
		}
		return res, err
	})}
	three := observeSource(t, restarted, binding.BindingID)
	if three.Content != one.Content || one.SourceRevision != "7" || three.SourceRevision != "opaque-new" || three.ObservationID == one.ObservationID {
		t.Fatal("bytes replaced provider revision", three)
	}
	for _, o := range []SourceObservation{one, two, three} {
		var record attachment.Record
		if err := json.Unmarshal(o.Document, &record); err != nil || attachment.Check(o.Document) != nil {
			t.Fatal(err)
		}
		original, _ := base64.StdEncoding.DecodeString(*record.Original.Bytes)
		canonical, _ := canon.Canonicalize(o.Document, canon.RefuseNumbers)
		if string(original) != "A test policy document." || o.Content.BytesDigest != digest(original) || o.Content.ByteLength != int64(len(original)) || o.Extraction.Content.BytesDigest != digest(canonical) || o.Extraction.Content.ByteLength != int64(len(canonical)) || o.Source.ResourceID != "file-A" || o.Source.AccountID != "account-A" || o.Source.Provider != "google-drive" || o.Availability != "present" || o.Coverage != "snapshot-only" || o.Lifecycle.Kind != "not-exposed" || o.SourceRevision != *record.Document.Version || o.Extraction.Processor != *record.Provenance.Processor || o.Extraction.ProcessorVersion != record.Provenance.Adapter.Version || !validDigest(o.Extraction.ConfigurationDigest) {
			t.Fatalf("unbound observation: %+v", o)
		}
		encoded := string(mustJSON(o))
		if strings.Contains(encoded, "source-access-private") || strings.Contains(encoded, "source-refresh-private") || strings.Contains(encoded, "source-client-secret") || strings.Contains(encoded, "receipt") {
			t.Fatal("private control or receipt claim escaped")
		}
	}
	if one.Extraction.ConfigurationDigest != three.Extraction.ConfigurationDigest {
		t.Fatal("source revision became extraction configuration")
	}
}

func TestSourceBindingDisconnectAndReconnectInvalidateOldAccountAndEpoch(t *testing.T) {
	b, _, count := sourceBroker(t)
	body := sourceBindBody(t, b, randomID())
	out, err := b.Handle(context.Background(), "source-bind", mustJSON(body))
	if err != nil {
		t.Fatal(err)
	}
	binding := out.(SourceBinding)
	if _, err := b.Handle(context.Background(), "disconnect", []byte(`{}`)); err != nil {
		t.Fatal(err)
	}
	if out, err := b.Handle(context.Background(), "source-observe", mustJSON(map[string]string{"bindingId": binding.BindingID})); out != nil || err != ErrConnect {
		t.Fatal(out, err)
	}
	if err := b.store.locked(func(v *state) error {
		v.Connection = &credential{ID: randomID(), Account: account{ID: "account-B"}, Access: "new-access", Refresh: "new-refresh", Expires: time.Now().Add(time.Hour).Unix()}
		if err := b.store.write("state.json", v); err != nil {
			return err
		}
		return b.store.recordConsent(v.Connection, driveScope)
	}); err != nil {
		t.Fatal(err)
	}
	if out, err := b.Handle(context.Background(), "source-observe", mustJSON(map[string]string{"bindingId": binding.BindingID})); out != nil || err != ErrSourceBinding || count.Load() != 0 {
		t.Fatal(out, err, count.Load())
	}
	if out, err := b.Handle(context.Background(), "source-bind", mustJSON(body)); out != nil || err != ErrSourceBinding {
		t.Fatal("old uncertain operation re-created on new account", out, err)
	}
	listed, err := b.Handle(context.Background(), "source-bindings", []byte(`{}`))
	if err != nil || len(listed.(SourceBindings).Bindings) != 0 {
		t.Fatal("old account history exposed", listed, err)
	}
	oldEpoch := body.SelectionContext
	body = sourceBindBody(t, b, randomID())
	body.SelectionContext = oldEpoch
	if out, err := b.Handle(context.Background(), "source-bind", mustJSON(body)); out != nil || err != ErrRequest {
		t.Fatal("stale selection context accepted", out, err)
	}
}

func TestSourceExtractionRetainsVolatileRecordIdentityWithoutInventingConfigurationChanges(t *testing.T) {
	b, _, _ := sourceBroker(t)
	binding := bindSource(t, b)
	o := observeSource(t, b, binding.BindingID)
	var record attachment.Record
	if err := json.Unmarshal(o.Document, &record); err != nil {
		t.Fatal(err)
	}
	record.Provenance.ObservedAt = "2026-10-18T00:00:00Z"
	record.Processing.DurationMs += 123
	changed, err := canon.EncodeJSON(record)
	if err != nil || attachment.Check(changed) != nil {
		t.Fatal(err)
	}
	config, err := sourceProcessingDigest(record, "auto")
	if err != nil || config != o.Extraction.ConfigurationDigest || digest(changed) == o.Extraction.Content.BytesDigest {
		t.Fatal("volatile processing changed configuration or lost artifact identity", err)
	}
	requested, err := sourceProcessingDigest(record, "never")
	if err != nil || requested == config {
		t.Fatal("actual requested OCR mode lost", err)
	}
	record.Provenance.OCR = &attachment.OCR{Program: "local-ocr", Digest: digest([]byte("local-ocr")), Pages: []int64{1}}
	applied, err := sourceProcessingDigest(record, "auto")
	if err != nil || applied == config {
		t.Fatal("applied OCR identity lost", err)
	}
	record.Provenance.OCR.Pages = []int64{2}
	pages, err := sourceProcessingDigest(record, "auto")
	if err != nil || pages != applied {
		t.Fatal("OCR result pages became configuration", err)
	}
}

func TestSourceProcessingDigestUsesCanonicalProfileAcrossStructAndMapEncodings(t *testing.T) {
	b, _, _ := sourceBroker(t)
	binding := bindSource(t, b)
	o := observeSource(t, b, binding.BindingID)
	var record attachment.Record
	if err := json.Unmarshal(o.Document, &record); err != nil {
		t.Fatal(err)
	}
	var generic map[string]any
	decoder := json.NewDecoder(strings.NewReader(string(o.Document)))
	decoder.UseNumber()
	if err := decoder.Decode(&generic); err != nil {
		t.Fatal(err)
	}
	processing := generic["processing"].(map[string]any)
	provenance := generic["provenance"].(map[string]any)
	// A consumer has maps decoded from canonical record bytes, not the
	// producer's Go struct declaration order. Both must name one profile.
	profile := map[string]any{"profile": "drive-document-processing-v1", "bounds": processing["bounds"], "requestOCR": "auto", "adapter": provenance["adapter"], "processor": provenance["processor"], "ocr": nil}
	raw, err := canon.EncodeJSON(profile)
	if err == nil {
		raw, err = canon.Canonicalize(raw, canon.RefuseNumbers)
	}
	if err != nil {
		t.Fatal(err)
	}
	got, err := sourceProcessingDigest(record, "auto")
	if err != nil || got != digest(raw) || o.Extraction.ConfigurationDigest != digest(raw) {
		t.Fatal("configuration depends on Go struct order", got, digest(raw), err)
	}
}

func TestSourceObservationOfGoogleNativeDocumentRetainsExportBytesAndProviderRevision(t *testing.T) {
	b, _, _ := sourceBroker(t)
	binding := bindSource(t, b)
	data, err := os.ReadFile("../document/testdata/normal.pdf")
	if err != nil {
		t.Fatal(err)
	}
	b.provider.client.Transport = sourceTransport(func(r *http.Request) (*http.Response, error) {
		if strings.HasSuffix(r.URL.Path, "/export") {
			if r.URL.Query().Get("mimeType") != "application/pdf" || len(r.URL.Query()) != 1 {
				t.Error("native export changed contract")
			}
			return sourceReply(200, string(data)), nil
		}
		return sourceReply(200, `{"id":"file-A","name":"Policy","mimeType":"application/vnd.google-apps.document","version":"native-revision","capabilities":{"canDownload":true}}`), nil
	})
	o := observeSource(t, b, binding.BindingID)
	var record attachment.Record
	json.Unmarshal(o.Document, &record)
	if o.Content.BytesDigest != digest(data) || o.Content.ByteLength != int64(len(data)) || o.Content.MediaType != "application/pdf" || o.SourceRevision != "native-revision" || record.Provenance.Source.MediaType != "application/vnd.google-apps.document" || o.Extraction.Processor != attachment.ProcessorPDF {
		t.Fatal("export bytes replaced source identity", o)
	}
}

// Revoke through a second companion/store, as another host operation can do
// while provider I/O is in flight. No request after the winning revocation is
// sent; no response already in flight becomes an accepted observation.
func TestSourceObservationRevocationWinsDuringEveryProviderRead(t *testing.T) {
	for _, at := range []int32{1, 2, 3} {
		t.Run(fmt.Sprint(at), func(t *testing.T) {
			b, dir, count := sourceBroker(t)
			binding := bindSource(t, b)
			s, err := OpenStore(dir, "alice")
			if err != nil {
				t.Fatal(err)
			}
			defer s.Close()
			other := New(s, false)
			defer other.Close()
			prior := b.provider.client.Transport
			b.provider.client.Transport = sourceTransport(func(r *http.Request) (*http.Response, error) {
				res, err := prior.RoundTrip(r)
				if count.Load() == at {
					revokeSource(t, other, binding.BindingID)
				}
				return res, err
			})
			out, err := b.Handle(context.Background(), "source-observe", mustJSON(map[string]string{"bindingId": binding.BindingID}))
			if out != nil || err != ErrSourceBinding || count.Load() != at {
				t.Fatal("stale read accepted or continued", out, err, count.Load())
			}
		})
	}
}

func TestSourceObservationFinalAdmissionSerializesWithRevocation(t *testing.T) {
	b, _, _ := sourceBroker(t)
	binding := bindSource(t, b)
	observation := observeSource(t, b, binding.BindingID)
	expected, client, _, _, err := b.store.currentSourceBinding(binding.BindingID)
	if err != nil {
		t.Fatal(err)
	}
	// Hold the shared custody lock while admission starts, then commit the
	// real revoke mutation under that lock before letting admission proceed.
	held, revoke, revoked, release := make(chan struct{}), make(chan struct{}), make(chan error, 1), make(chan struct{})
	lockDone := make(chan error, 1)
	go func() {
		lockDone <- b.store.locked(func(v *state) error {
			close(held)
			<-revoke
			err := b.store.revokeSourceBinding(v, binding.BindingID)
			revoked <- err
			<-release
			return err
		})
	}()
	<-held
	type admission struct {
		observation *SourceObservation
		err         error
	}
	done := make(chan admission, 1)
	started := make(chan struct{})
	go func() {
		close(started)
		accepted, err := b.store.admitSourceObservation(context.Background(), expected, client, observation)
		done <- admission{accepted, err}
	}()
	<-started
	close(revoke)
	if err := <-revoked; err != nil {
		t.Fatal(err)
	}
	close(release)
	if err := <-lockDone; err != nil {
		t.Fatal(err)
	}
	result := <-done
	if result.observation != nil || result.err != ErrSourceBinding {
		t.Fatal("revocation won but artifact was admitted", result)
	}
	if out, err := b.Handle(context.Background(), "source-observe", mustJSON(map[string]string{"bindingId": binding.BindingID})); out != nil || err != ErrSourceBinding {
		t.Fatal(out, err)
	}
	// The opposite order is explicit too: revocation cannot retract a snapshot
	// already admitted to the host, but it refuses every subsequent admission.
	second := bindSource(t, b)
	expected, client, _, _, err = b.store.currentSourceBinding(second.BindingID)
	if err != nil {
		t.Fatal(err)
	}
	observation.BindingID = second.BindingID
	accepted, err := b.store.admitSourceObservation(context.Background(), expected, client, observation)
	if err != nil || accepted == nil {
		t.Fatal(accepted, err)
	}
	revokeSource(t, b, second.BindingID)
	if accepted == nil || accepted.Content != observation.Content {
		t.Fatal("already admitted response was retracted")
	}
	if later, err := b.store.admitSourceObservation(context.Background(), expected, client, observation); later != nil || err != ErrSourceBinding {
		t.Fatal("post-revoke admission accepted", later, err)
	}
}

func TestSourceObservationReconnectWinsDuringProviderReadAndTokenRenewal(t *testing.T) {
	for _, stage := range []string{"metadata-before", "download", "metadata-after", "token-renewal"} {
		t.Run(stage, func(t *testing.T) {
			b, dir, count := sourceBroker(t)
			binding := bindSource(t, b)
			s, err := OpenStore(dir, "alice")
			if err != nil {
				t.Fatal(err)
			}
			defer s.Close()
			other := New(s, false)
			other.provider.revoke = ""
			defer other.Close()
			if stage == "token-renewal" {
				if err := s.locked(func(v *state) error { v.Connection.Expires = 0; return s.write("state.json", v) }); err != nil {
					t.Fatal(err)
				}
			}
			prior := b.provider.client.Transport
			b.provider.client.Transport = sourceTransport(func(r *http.Request) (*http.Response, error) {
				var res *http.Response
				if stage == "token-renewal" {
					if r.Method != "POST" || !strings.Contains(r.URL.Path, "token") {
						t.Error("renewal was not first provider I/O")
					}
					count.Add(1)
					res = sourceReply(200, `{"access_token":"renewed-private","refresh_token":"renewed-refresh","expires_in":3600,"token_type":"Bearer"}`)
				} else {
					res, err = prior.RoundTrip(r)
				}
				at := map[string]int32{"metadata-before": 1, "download": 2, "metadata-after": 3, "token-renewal": 1}[stage]
				if count.Load() == at {
					if _, err := other.Handle(context.Background(), "disconnect", []byte(`{}`)); err != nil {
						t.Fatal(err)
					}
					if err := s.locked(func(v *state) error {
						v.Connection = &credential{ID: randomID(), Account: account{ID: "account-A"}, Access: "new-access", Refresh: "new-refresh", Expires: time.Now().Add(time.Hour).Unix()}
						if err := s.write("state.json", v); err != nil {
							return err
						}
						return s.recordConsent(v.Connection, driveScope)
					}); err != nil {
						t.Fatal(err)
					}
				}
				return res, err
			})
			out, err := b.Handle(context.Background(), "source-observe", mustJSON(map[string]string{"bindingId": binding.BindingID}))
			wantCalls := map[string]int32{"metadata-before": 1, "download": 2, "metadata-after": 3, "token-renewal": 1}[stage]
			if out != nil || err != ErrSourceBinding || count.Load() != wantCalls {
				t.Fatal("old connection returned accepted bytes", out, err, count.Load())
			}
			if err := s.locked(func(v *state) error {
				if v.Connection.Access != "new-access" {
					t.Fatal("renewal restored old credential")
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestSourceObservationRevokedWhileRealOCRIsRunningReturnsNoArtifact(t *testing.T) {
	b, dir, count := sourceBroker(t)
	binding := bindSource(t, b)
	processing, processingDir := processingBroker(t)
	t.Setenv("JPACK_CONNECTIONS_DIR", processingDir)
	bundle := t.TempDir()
	useBundle(t, bundle)
	entered, release := filepath.Join(bundle, "entered"), filepath.Join(bundle, "release")
	quote := func(s string) string { return "'" + strings.ReplaceAll(s, "'", "'\\''") + "'" }
	program := filepath.Join(bundle, "ocr")
	script := "#!/bin/sh\n/bin/cat >/dev/null\n: > " + quote(entered) + "\nwhile [ ! -e " + quote(release) + " ]; do /bin/sleep 0.01; done\nprintf '{\"pages\":[{\"number\":1,\"text\":\"Observed policy\"}]}'\n"
	if err := os.WriteFile(program, []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	base := processingState(t, processing)
	cfg := base.ProcessingConfig
	cfg.Mode, cfg.Connection, cfg.TimeoutSeconds = "auto", "local", 10
	cfg.Connections = []OCRConnection{{ID: "local", Name: "Local", Kind: "program", Program: program, Enabled: true}}
	processingSave(t, processing, base, cfg)
	data, err := os.ReadFile("../document/testdata/scanned.pdf")
	if err != nil {
		t.Fatal(err)
	}
	b.provider.client.Transport = sourceTransport(func(r *http.Request) (*http.Response, error) {
		count.Add(1)
		if r.URL.Query().Get("alt") == "media" {
			return sourceReply(200, string(data)), nil
		}
		return sourceReply(200, fmt.Sprintf(`{"id":"file-A","name":"policy.pdf","mimeType":"application/pdf","version":"7","size":"%d","capabilities":{"canDownload":true}}`, len(data))), nil
	})
	s, err := OpenStore(dir, "alice")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	other := New(s, false)
	defer other.Close()
	type result struct {
		out any
		err error
	}
	done := make(chan result, 1)
	ctx, cancel := context.WithTimeout(WithDocumentProcessing(context.Background()), 5*time.Second)
	defer cancel()
	go func() {
		out, err := b.Handle(ctx, "source-observe", mustJSON(map[string]string{"bindingId": binding.BindingID}))
		done <- result{out, err}
	}()
	defer os.WriteFile(release, nil, 0600)
	deadline := time.Now().Add(3 * time.Second)
	for {
		if _, err := os.Stat(entered); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("real extraction did not reach OCR")
		}
		time.Sleep(time.Millisecond)
	}
	revokeSource(t, other, binding.BindingID)
	if err := os.WriteFile(release, nil, 0600); err != nil {
		t.Fatal(err)
	}
	select {
	case result := <-done:
		if result.out != nil || result.err != ErrSourceBinding || count.Load() != 3 {
			t.Fatal("revoked extracted artifact accepted", result.out, result.err, count.Load())
		}
	case <-time.After(5 * time.Second):
		t.Fatal("extraction did not finish")
	}
}

func TestSourceObservationRefusesChangedFailedUnsupportedAndOversizeWithoutWithdrawal(t *testing.T) {
	for _, example := range []struct {
		name     string
		response func(*http.Request, int) *http.Response
		want     error
	}{
		{"changed during read", func(r *http.Request, n int) *http.Response {
			if r.URL.Query().Get("alt") == "media" {
				return sourceReply(200, "A test policy document.")
			}
			revision := "7"
			if n == 3 {
				revision = "8"
			}
			return sourceReply(200, fmt.Sprintf(`{"id":"file-A","name":"policy.txt","mimeType":"text/plain","version":%q,"size":"23","capabilities":{"canDownload":true}}`, revision))
		}, ErrChanged},
		{"provider failure", func(*http.Request, int) *http.Response { return sourceReply(503, `private provider failure`) }, ErrProvider},
		{"access denied", func(*http.Request, int) *http.Response { return sourceReply(403, `{}`) }, ErrProvider},
		{"resource absent", func(*http.Request, int) *http.Response { return sourceReply(404, `{}`) }, ErrProvider},
		{"trashed", func(*http.Request, int) *http.Response {
			return sourceReply(200, `{"id":"file-A","name":"policy.txt","mimeType":"text/plain","version":"7","size":"23","trashed":true,"capabilities":{"canDownload":true}}`)
		}, ErrUnsupported},
		{"size bound", func(*http.Request, int) *http.Response {
			return sourceReply(200, `{"id":"file-A","name":"policy.txt","mimeType":"text/plain","version":"7","size":"4194305","capabilities":{"canDownload":true}}`)
		}, ErrLimit},
		{"stream bound", func(r *http.Request, _ int) *http.Response {
			if r.URL.Query().Get("alt") == "media" {
				return sourceReply(200, strings.Repeat("x", MaxFileBytes+1))
			}
			return sourceReply(200, `{"id":"file-A","name":"policy.txt","mimeType":"text/plain","version":"7","size":"4194304","capabilities":{"canDownload":true}}`)
		}, ErrLimit},
	} {
		t.Run(example.name, func(t *testing.T) {
			b, _, _ := sourceBroker(t)
			binding := bindSource(t, b)
			calls := 0
			b.provider.client.Transport = sourceTransport(func(r *http.Request) (*http.Response, error) { calls++; return example.response(r, calls), nil })
			if out, err := b.Handle(context.Background(), "source-observe", mustJSON(map[string]string{"bindingId": binding.BindingID})); out != nil || err != example.want {
				t.Fatal("partial observation escaped", out, err)
			}
			listed, err := b.Handle(context.Background(), "source-bindings", []byte(`{}`))
			if err != nil || len(listed.(SourceBindings).Bindings) != 1 || listed.(SourceBindings).Bindings[0].State != "active" {
				t.Fatal("failure withdrew recurring consent", listed, err)
			}
		})
	}
}

func TestSourceBindingBoundsNeverEvictRevokedOperationIdentity(t *testing.T) {
	b, _, _ := sourceBroker(t)
	body := sourceBindBody(t, b, randomID())
	one, err := b.Handle(context.Background(), "source-bind", mustJSON(body))
	if err != nil {
		t.Fatal(err)
	}
	for i := 1; i < SourceBindingActiveLimit; i++ {
		bindSource(t, b)
	}
	if out, err := b.Handle(context.Background(), "source-bind", mustJSON(sourceBindBody(t, b, randomID()))); out != nil || err != ErrSourceLimit {
		t.Fatal(out, err)
	}
	revokeSource(t, b, one.(SourceBinding).BindingID)
	for i := SourceBindingActiveLimit; i < SourceBindingOperationLimit; i++ {
		next := bindSource(t, b)
		revokeSource(t, b, next.BindingID)
	}
	if out, err := b.Handle(context.Background(), "source-bind", mustJSON(sourceBindBody(t, b, randomID()))); out != nil || err != ErrSourceLimit {
		t.Fatal(out, err)
	}
	recovered, err := b.Handle(context.Background(), "source-bind", mustJSON(body))
	if err != nil || recovered.(SourceBinding).State != "revoked" || recovered.(SourceBinding).BindingID != one.(SourceBinding).BindingID {
		t.Fatal("capacity cleanup revived grant", recovered, err)
	}
	data, err := os.ReadFile(filepath.Join(b.store.root.Name(), "source-bindings.json"))
	if err != nil || len(data) > 64<<10 {
		t.Fatal(len(data), err)
	}
}

func TestOnlyDriveCatalogsAdvertiseRecurringHostControls(t *testing.T) {
	for _, p := range ConnectionCatalogV3().Providers {
		for _, method := range sourceMethods {
			if p.supports(method) != (p.ID == "google-drive") || sourceMethodOf(p.ID, method) != (p.ID == "google-drive") {
				t.Fatal("unimplemented recurring control advertised", p.ID, method)
			}
		}
	}
	for _, p := range ConnectionCatalog().Providers {
		for _, method := range sourceMethods {
			if p.supports(method) {
				t.Fatal("v2 compatibility changed", p.ID, method)
			}
		}
	}
	if got := declaredCapabilities("drive"); len(got) != 0 {
		t.Fatal("recurring consent became a research capability", got)
	}
}
