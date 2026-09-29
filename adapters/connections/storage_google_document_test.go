//go:build linux || darwin

package connections

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"mime"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// A stand-in for Drive, which records what it was asked. Nothing here was
// tried against a Google account.
type driveConversionFake struct {
	t         *testing.T
	server    *httptest.Server
	reserved  int
	uploads   int
	metadata  map[string]any
	media     string
	body      []byte
	query     string
	folder    string
	answer    string
	status    int
	dropReply bool
}

const wordMedia = "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
const googleDocumentMedia = "application/vnd.google-apps.document"

// The first bytes of an archive, and then bytes that are no Word file: the
// controls read the first four and leave the rest to Drive.
var wordBytes = []byte("PK\x03\x04 the rest of a Word file")

func newDriveConversionFake(t *testing.T) (*driveConversionFake, *Broker) {
	t.Helper()
	s := testStore(t, "drive-conversion")
	s.locked(func(v *state) error {
		v.Epoch = "epoch"
		v.Connection = &credential{ID: "connection", Access: "private-token", Expires: time.Now().Add(time.Hour).Unix()}
		return s.write("state.json", v)
	})
	f := &driveConversionFake{t: t, answer: `{"id":"made-document","mimeType":"` + googleDocumentMedia + `"}`, status: 200,
		folder: `{"id":"a-folder","name":"Reports","mimeType":"application/vnd.google-apps.folder","version":"1","capabilities":{"canAddChildren":true}}`}
	f.server = httptest.NewTLSServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.server.Close)
	b := New(s, false)
	b.provider.api = f.server.URL + "/drive/v3"
	b.provider.client = f.server.Client()
	t.Cleanup(b.Close)
	return f, b
}

func (f *driveConversionFake) serve(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Authorization") != "Bearer private-token" {
		f.t.Error("a request without the access token")
	}
	if r.Method == "GET" {
		if strings.HasSuffix(r.URL.Path, "/generateIds") {
			f.reserved++
			io.WriteString(w, `{"ids":["reserved-file"]}`)
			return
		}
		io.WriteString(w, f.folder)
		return
	}
	f.uploads++
	f.query = r.URL.RawQuery
	if r.Method != "POST" || r.URL.Path != "/upload/drive/v3/files" {
		f.t.Errorf("the upload was %s %s", r.Method, r.URL.Path)
	}
	if r.Header.Get("If-Match") != "" {
		f.t.Error("a create carried a condition")
	}
	kind, params, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || kind != "multipart/related" {
		f.t.Errorf("the upload's content type was %q", r.Header.Get("Content-Type"))
		w.WriteHeader(400)
		return
	}
	reader := multipart.NewReader(r.Body, params["boundary"])
	first, err := reader.NextPart()
	if err != nil {
		f.t.Error(err)
		return
	}
	f.metadata = map[string]any{}
	if json.NewDecoder(first).Decode(&f.metadata) != nil {
		f.t.Error("the metadata was not JSON")
	}
	second, err := reader.NextPart()
	if err != nil {
		f.t.Error(err)
		return
	}
	f.media = second.Header.Get("Content-Type")
	f.body, _ = io.ReadAll(second)
	if _, err = reader.NextPart(); err != io.EOF {
		f.t.Error("the upload had more than two parts")
	}
	if f.dropReply {
		// The upload reached Drive and its answer is lost on the way back.
		hijacker, ok := w.(http.Hijacker)
		if !ok {
			f.t.Fatal("the stand-in cannot drop a connection")
		}
		conn, _, err := hijacker.Hijack()
		if err != nil {
			f.t.Fatal(err)
		}
		conn.Close()
		return
	}
	w.WriteHeader(f.status)
	io.WriteString(w, f.answer)
}

func conversion(name string, content []byte) StorageConversion {
	return StorageConversion{Name: name, MediaType: wordMedia, Content: base64.StdEncoding.EncodeToString(content)}
}

// conversionJSON is a request with the connection's context, as a host has it
// from a listing.
func conversionJSON(t *testing.T, b *Broker, q any) []byte {
	t.Helper()
	var data map[string]any
	if err := json.Unmarshal(mustJSON(q), &data); err != nil {
		t.Fatal(err)
	}
	if value, _ := data["context"].(string); value == "" {
		_, c, epoch, err := b.connectedSnapshot()
		if err != nil {
			t.Fatal(err)
		}
		data["context"] = storageContext(c, epoch)
	}
	return mustJSON(data)
}

func prepareConversion(t *testing.T, b *Broker, q any) (StoragePlan, error) {
	t.Helper()
	v, err := b.Handle(context.Background(), StorageConvertMethod, conversionJSON(t, b, q))
	if err != nil {
		return StoragePlan{}, err
	}
	var plan StoragePlan
	if err = json.Unmarshal(mustJSON(v), &plan); err != nil {
		t.Fatal(err)
	}
	return plan, nil
}

func TestAGoogleDocIsMadeOfAWordFileByOneUpload(t *testing.T) {
	f, b := newDriveConversionFake(t)
	q := conversion("Quarterly report", wordBytes)
	q.Folder = "a-folder"
	plan, err := prepareConversion(t, b, q)
	if err != nil {
		t.Fatal(err)
	}
	if f.uploads != 0 {
		t.Fatal("preparing uploaded")
	}
	if f.reserved != 0 {
		t.Fatal("preparing reserved an ID, which Drive takes for no file it converts")
	}
	want := StoragePlan{ID: plan.ID, Action: "create", Name: "Quarterly report", Size: len(wordBytes), State: "prepared", Expires: plan.Expires, Effect: "write", ConvertTo: "google-document"}
	if plan != want {
		t.Fatalf("the plan was %+v", plan)
	}
	done := storageCall[StoragePlan](t, b, "files-commit", map[string]string{"id": plan.ID})
	want.State, want.Target = "completed", "made-document"
	if done != want {
		t.Fatalf("the plan after the commit was %+v", done)
	}
	if f.uploads != 1 || f.reserved != 0 {
		t.Fatalf("%d uploads and %d reserved IDs", f.uploads, f.reserved)
	}
	if len(f.metadata) != 3 || f.metadata["name"] != "Quarterly report" || f.metadata["mimeType"] != googleDocumentMedia {
		t.Fatalf("the metadata was %v", f.metadata)
	}
	if parents, _ := f.metadata["parents"].([]any); len(parents) != 1 || parents[0] != "a-folder" {
		t.Fatalf("the metadata's parents were %v", f.metadata["parents"])
	}
	if _, has := f.metadata["id"]; has {
		t.Fatal("the metadata carried an ID")
	}
	if f.media != wordMedia || string(f.body) != string(wordBytes) {
		t.Fatalf("what was uploaded was %q, as %q", f.body, f.media)
	}
	if f.query != "uploadType=multipart&supportsAllDrives=true&fields=id,mimeType" {
		t.Fatalf("the upload's query was %q", f.query)
	}

	// A second commit and a status say what is stored, and send nothing.
	again := storageCall[StoragePlan](t, b, "files-commit", map[string]string{"id": plan.ID})
	status := storageCall[StoragePlan](t, b, "files-status", map[string]string{"id": plan.ID})
	if again != want || status != want || f.uploads != 1 {
		t.Fatalf("after the commit: %+v, %+v, %d uploads", again, status, f.uploads)
	}
	intent, err := b.store.readStorageIntent()
	if err != nil || intent.Change.Content != "" {
		t.Fatal("the settled record kept the file", err)
	}
}

func TestAGoogleDocWithNoFolderAsksNothingOfDriveBeforeTheCommit(t *testing.T) {
	f, b := newDriveConversionFake(t)
	asked := 0
	inner := f.server.Config.Handler
	f.server.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		asked++
		inner.ServeHTTP(w, r)
	})
	plan, err := prepareConversion(t, b, conversion("Notes", wordBytes))
	if err != nil || asked != 0 {
		t.Fatalf("preparing made %d requests: %v", asked, err)
	}
	done := storageCall[StoragePlan](t, b, "files-commit", map[string]string{"id": plan.ID})
	if done.State != "completed" || done.Target != "made-document" || asked != 1 {
		t.Fatalf("%+v after %d requests", done, asked)
	}
	if _, has := f.metadata["parents"]; has || len(f.metadata) != 2 {
		t.Fatalf("the metadata was %v", f.metadata)
	}
}

func TestAGoogleDocIsMadeOnlyInAFolderThatTakesOne(t *testing.T) {
	for name, folder := range map[string]string{
		"a file":                   `{"id":"a-folder","name":"Reports","mimeType":"text/plain","version":"1","capabilities":{"canAddChildren":true}}`,
		"a folder that takes none": `{"id":"a-folder","name":"Reports","mimeType":"application/vnd.google-apps.folder","version":"1","capabilities":{"canAddChildren":false}}`,
	} {
		f, b := newDriveConversionFake(t)
		f.folder = folder
		q := conversion("Notes", wordBytes)
		q.Folder = "a-folder"
		if _, err := prepareConversion(t, b, q); err != ErrUnsupported {
			t.Fatalf("%s: %v", name, err)
		}
		if f.uploads != 0 || f.reserved != 0 {
			t.Fatalf("%s: %d uploads, %d reserved", name, f.uploads, f.reserved)
		}
	}
}

func TestWhatDriveMadeIsHeldToBeAGoogleDocByItsOwnWord(t *testing.T) {
	for name, row := range map[string]struct {
		answer        string
		status        int
		state, reason string
		target        string
	}{
		"the Word file, kept as it was":  {`{"id":"made-file","mimeType":"` + wordMedia + `"}`, 200, "needs-attention", "conversion-unconfirmed", "made-file"},
		"no media type":                  {`{"id":"made-file"}`, 200, "needs-attention", "conversion-unconfirmed", "made-file"},
		"another Google type":            {`{"id":"made-file","mimeType":"application/vnd.google-apps.spreadsheet"}`, 200, "needs-attention", "conversion-unconfirmed", "made-file"},
		"created":                        {`{"id":"made-document","mimeType":"` + googleDocumentMedia + `"}`, 201, "completed", "", "made-document"},
		"no ID":                          {`{"mimeType":"` + googleDocumentMedia + `"}`, 200, "needs-attention", "operation-uncertain", ""},
		"an ID that is none":             {`{"id":"../made","mimeType":"` + googleDocumentMedia + `"}`, 200, "needs-attention", "operation-uncertain", ""},
		"an answer that is not JSON":     {`made-document`, 200, "needs-attention", "operation-uncertain", ""},
		"a failure of Drive's":           {`{"id":"made-document","mimeType":"` + googleDocumentMedia + `"}`, 500, "needs-attention", "operation-uncertain", ""},
		"a refusal of Drive's":           {`{"id":"made-document","mimeType":"` + googleDocumentMedia + `"}`, 403, "refused", "permission-required", ""},
		"a conflict":                     {`{"id":"made-document","mimeType":"` + googleDocumentMedia + `"}`, 409, "refused", "source-changed", ""},
		"a condition that failed":        {`{"id":"made-document","mimeType":"` + googleDocumentMedia + `"}`, 412, "refused", "source-changed", ""},
		"a media type that is no string": {`{"id":"made-file","mimeType":5}`, 200, "needs-attention", "operation-uncertain", ""},
		"an ID that is no string":        {`{"id":5,"mimeType":"` + googleDocumentMedia + `"}`, 200, "needs-attention", "operation-uncertain", ""},
	} {
		f, b := newDriveConversionFake(t)
		f.answer, f.status = row.answer, row.status
		plan, err := prepareConversion(t, b, conversion("Notes", wordBytes))
		if err != nil {
			t.Fatal(name, err)
		}
		done := storageCall[StoragePlan](t, b, "files-commit", map[string]string{"id": plan.ID})
		if done.State != row.state || done.Error != row.reason || done.Target != row.target || done.ConvertTo != "google-document" {
			t.Fatalf("%s: %+v", name, done)
		}
		again := storageCall[StoragePlan](t, b, "files-commit", map[string]string{"id": plan.ID})
		if again != done || f.uploads != 1 {
			t.Fatalf("%s: a second commit gave %+v after %d uploads", name, again, f.uploads)
		}
		// What is not known stops the next change, of either kind.
		_, err = prepareConversion(t, b, conversion("Notes", wordBytes))
		if uncertain := row.state == "needs-attention"; uncertain != (err == Error("operation-uncertain")) {
			t.Fatalf("%s: the next plan: %v", name, err)
		}
	}
}

func TestAnAnswerThatIsLostLeavesThePlanUncertainAndIsNotSentAgain(t *testing.T) {
	f, b := newDriveConversionFake(t)
	f.dropReply = true
	plan, err := prepareConversion(t, b, conversion("Notes", wordBytes))
	if err != nil {
		t.Fatal(err)
	}
	done := storageCall[StoragePlan](t, b, "files-commit", map[string]string{"id": plan.ID})
	if done.State != "needs-attention" || done.Error != "operation-uncertain" || done.Target != "" {
		t.Fatalf("%+v", done)
	}
	f.dropReply = false
	again := storageCall[StoragePlan](t, b, "files-commit", map[string]string{"id": plan.ID})
	if again != done || f.uploads != 1 {
		t.Fatalf("a second commit gave %+v after %d uploads", again, f.uploads)
	}
}

func TestAConversionIsOfAWordFileAndOfNothingElse(t *testing.T) {
	f, b := newDriveConversionFake(t)
	over := append([]byte("PK\x03\x04"), make([]byte, MaxFileBytes-3)...)
	most := over[:MaxFileBytes]
	for name, row := range map[string]struct {
		q    any
		want error
	}{
		"text":                       {StorageConversion{Name: "n", MediaType: "text/plain", Content: base64.StdEncoding.EncodeToString(wordBytes)}, ErrUnsupported},
		"a Google Doc":               {StorageConversion{Name: "n", MediaType: googleDocumentMedia, Content: base64.StdEncoding.EncodeToString(wordBytes)}, ErrUnsupported},
		"the media type in capitals": {StorageConversion{Name: "n", MediaType: strings.ToUpper(wordMedia), Content: base64.StdEncoding.EncodeToString(wordBytes)}, ErrUnsupported},
		"no media type":              {StorageConversion{Name: "n", Content: base64.StdEncoding.EncodeToString(wordBytes)}, ErrUnsupported},
		"no file":                    {conversion("n", nil), ErrUnsupported},
		"three bytes of four":        {conversion("n", []byte("PK\x03")), ErrUnsupported},
		"an archive that is empty":   {conversion("n", []byte("PK\x05\x06")), ErrUnsupported},
		"text called a Word file":    {conversion("n", []byte("a report")), ErrUnsupported},
		"a file over the bound":      {conversion("n", over), ErrLimit},
		"content that is not base64": {StorageConversion{Name: "n", MediaType: wordMedia, Content: "PK!"}, ErrLimit},
		"no name":                    {conversion("", wordBytes), ErrRequest},
		"a name with a path":         {conversion("reports/n", wordBytes), ErrRequest},
		"a folder that is no ID":     {StorageConversion{Name: "n", Folder: "a folder", MediaType: wordMedia, Content: base64.StdEncoding.EncodeToString(wordBytes)}, ErrRequest},
		"another connection":         {map[string]string{"context": "another", "name": "n", "mediaType": wordMedia, "contentBase64": base64.StdEncoding.EncodeToString(wordBytes)}, ErrChanged},
		"an action":                  {map[string]string{"action": "create", "name": "n", "mediaType": wordMedia, "contentBase64": base64.StdEncoding.EncodeToString(wordBytes)}, ErrRequest},
		"a target":                   {map[string]string{"id": "existing-file", "name": "n", "mediaType": wordMedia, "contentBase64": base64.StdEncoding.EncodeToString(wordBytes)}, ErrRequest},
		"a revision":                 {map[string]string{"revision": "1", "name": "n", "mediaType": wordMedia, "contentBase64": base64.StdEncoding.EncodeToString(wordBytes)}, ErrRequest},
		"what it is converted to":    {map[string]string{"convertTo": "google-document", "name": "n", "mediaType": wordMedia, "contentBase64": base64.StdEncoding.EncodeToString(wordBytes)}, ErrRequest},
	} {
		if _, err := prepareConversion(t, b, row.q); err != row.want {
			t.Fatalf("%s: %v", name, err)
		}
		if _, err := b.store.readStorageIntent(); err != ErrGrant {
			t.Fatalf("%s: a plan was stored: %v", name, err)
		}
	}
	if f.uploads != 0 || f.reserved != 0 {
		t.Fatalf("%d uploads, %d reserved", f.uploads, f.reserved)
	}
	// The bound is the one every file has, and a file at it is taken.
	plan, err := prepareConversion(t, b, conversion("n", most))
	if err != nil || plan.Size != MaxFileBytes {
		t.Fatalf("a file at the bound: %+v, %v", plan, err)
	}
}

func TestAnOrdinaryChangeCannotAskForAConversion(t *testing.T) {
	f, b := newDriveConversionFake(t)
	for _, action := range []string{"create", "update", "delete"} {
		q := StorageChange{Action: action, Name: "n", MediaType: wordMedia, Content: base64.StdEncoding.EncodeToString(wordBytes), ConvertTo: "google-document"}
		if _, err := b.Handle(context.Background(), "files-prepare", storageJSON(t, b, "files-prepare", q)); err != ErrRequest {
			t.Fatalf("%s: %v", action, err)
		}
	}
	if f.uploads != 0 || f.reserved != 0 {
		t.Fatalf("%d uploads, %d reserved", f.uploads, f.reserved)
	}
	// An ordinary create is as it was: an ID is reserved and sent, the file
	// keeps its media type, and neither the plan nor what is stored names a
	// conversion.
	f.answer = `{"id":"reserved-file"}`
	q := StorageChange{Action: "create", Name: "report.docx", MediaType: wordMedia, Content: base64.StdEncoding.EncodeToString(wordBytes)}
	raw, err := b.Handle(context.Background(), "files-prepare", storageJSON(t, b, "files-prepare", q))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(mustJSON(raw)), "convertTo") {
		t.Fatalf("an ordinary plan names a conversion: %s", mustJSON(raw))
	}
	plan := raw.(StoragePlan)
	done := storageCall[StoragePlan](t, b, "files-commit", map[string]string{"id": plan.ID})
	if done.State != "completed" || done.Target != "reserved-file" || done.ConvertTo != "" || f.reserved != 1 || f.uploads != 1 {
		t.Fatalf("%+v, %d reserved, %d uploads", done, f.reserved, f.uploads)
	}
	if f.metadata["id"] != "reserved-file" || f.metadata["mimeType"] != wordMedia || f.query != "uploadType=multipart&supportsAllDrives=true&fields=id" {
		t.Fatalf("the metadata was %v and the query %q", f.metadata, f.query)
	}
	stored, err := b.store.root.ReadFile("storage-intent.json")
	if err != nil || strings.Contains(string(stored), "convertTo") {
		t.Fatalf("what is stored of an ordinary plan names a conversion: %v", err)
	}
	// Drive's answer to an ordinary create is held to the reserved ID, as before.
	f.answer = `{"id":"another-file"}`
	q.Name = "second.docx"
	plan = storageCall[StoragePlan](t, b, "files-prepare", q)
	done = storageCall[StoragePlan](t, b, "files-commit", map[string]string{"id": plan.ID})
	if done.State != "needs-attention" || done.Error != "operation-uncertain" || done.Target != "reserved-file" {
		t.Fatalf("%+v", done)
	}
}

func TestTheConversionIsDrivesAlone(t *testing.T) {
	vault, _ := storageVaultFixture(t)
	s3 := testS3(t)
	gmail := NewGmail(testStore(t, "gmail-conversion"), false)
	t.Cleanup(gmail.Close)
	request := mustJSON(conversion("n", wordBytes))
	for name, b := range map[string]*Broker{"a local vault": vault, "S3": s3.broker, "Gmail": gmail} {
		if _, err := b.Handle(context.Background(), StorageConvertMethod, request); err != ErrRequest {
			t.Fatalf("%s: %v", name, err)
		}
	}
	for _, provider := range ConnectionCatalogV3().Providers {
		offered := 0
		for _, operation := range provider.Operations {
			if operation == StorageConvertMethod {
				offered++
			}
		}
		if want := provider.ID == "google-drive"; want != (offered == 1) || offered > 1 {
			t.Fatalf("%s offers the conversion %d times", provider.ID, offered)
		}
		// A desk takes at most sixteen operations of a provider, each an
		// identifier, and refuses the catalog otherwise.
		if len(provider.Operations) > 16 {
			t.Fatalf("%s has %d operations", provider.ID, len(provider.Operations))
		}
		for _, operation := range provider.Operations {
			if !identifier.MatchString(operation) {
				t.Fatalf("%s: %q is no identifier", provider.ID, operation)
			}
		}
	}
	for method, want := range map[string]bool{"files-prepare": true, StorageConvertMethod: true, "files-commit": false, "files-read": false, "files-list": false, "files-status": false, "": false, "files-prepare-google": false} {
		if StorageUpload(method) != want {
			t.Fatalf("%q carries a file: %v", method, !want)
		}
	}
}
