//go:build linux || darwin

package connections

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"io"
	"mime"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
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
	refreshes int
	metadata  map[string]any
	media     string
	body      []byte
	query     string
	found     string
	answer    string
	status    int
	dropReply bool
	// token is the connection's token, where it is not the one the
	// stand-in gives out.
	token string
	// refreshing runs while Drive's token endpoint is answering, which is
	// after a commit has read its plan and before it claims it.
	refreshing func()
}

const wordMedia = "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
const googleDocumentMedia = "application/vnd.google-apps.document"

// wordFile is a Word file: the one the rendering adapter's example record
// holds, which is what a desk sends here.
func wordFile(t *testing.T) []byte {
	t.Helper()
	raw, err := os.ReadFile("../../testdata/rendering/examples/refund-decision.record.json")
	if err != nil {
		t.Fatal(err)
	}
	var record struct {
		File struct {
			MediaType string `json:"mediaType"`
			Bytes     string `json:"bytes"`
		} `json:"file"`
	}
	if err = json.Unmarshal(raw, &record); err != nil || record.File.MediaType != wordMedia {
		t.Fatal("the example is not a record of a Word file", err)
	}
	file, err := base64.StdEncoding.DecodeString(record.File.Bytes)
	if err != nil || len(file) == 0 {
		t.Fatal("the example holds no file", err)
	}
	return file
}

// framed is the least that is framed as a Word file is: the first entry's
// signature, the name of the part every package has, and an end record with
// its comment. It is no Word file.
func framed(comment string) []byte {
	end := make([]byte, 22)
	copy(end, "PK\x05\x06")
	binary.LittleEndian.PutUint16(end[20:], uint16(len(comment)))
	return []byte("PK\x03\x04[Content_Types].xml" + string(end) + comment)
}

func newDriveConversionFake(t *testing.T) (*driveConversionFake, *Broker) {
	t.Helper()
	s := testStore(t, "drive-conversion")
	s.locked(func(v *state) error {
		v.Epoch = "epoch"
		v.Connection = &credential{ID: "connection", Access: "private-token", Expires: time.Now().Add(time.Hour).Unix()}
		return s.write("state.json", v)
	})
	f := &driveConversionFake{t: t, answer: `{"id":"made-document","mimeType":"` + googleDocumentMedia + `"}`, status: 200,
		found: `{"id":"a-folder","name":"Reports","mimeType":"application/vnd.google-apps.folder","version":"1","capabilities":{"canAddChildren":true}}`}
	f.server = httptest.NewTLSServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.server.Close)
	return f, f.broker(s)
}

// broker is another process's broker over the same custody.
func (f *driveConversionFake) broker(s *Store) *Broker {
	b := New(s, false)
	b.provider.api = f.server.URL + "/drive/v3"
	b.provider.token = f.server.URL + "/token"
	b.provider.client = f.server.Client()
	f.t.Cleanup(b.Close)
	return b
}

func (f *driveConversionFake) serve(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/token" {
		f.refreshes++
		if run := f.refreshing; run != nil {
			f.refreshing = nil
			run()
		}
		io.WriteString(w, `{"access_token":"private-token","expires_in":3600,"token_type":"Bearer"}`)
		return
	}
	if token := r.Header.Get("Authorization"); token != "Bearer private-token" && token != "Bearer "+f.token {
		f.t.Error("a request without the access token")
	}
	if r.Method == "GET" {
		if strings.HasSuffix(r.URL.Path, "/generateIds") {
			f.reserved++
			io.WriteString(w, `{"ids":["reserved-file"]}`)
			return
		}
		w.Header().Set("ETag", `"etag-1"`)
		io.WriteString(w, f.found)
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

// members is a conversion's request as its members, to take one out or put
// one in.
func members(t *testing.T, q StorageConversion, change func(map[string]any)) map[string]any {
	t.Helper()
	var data map[string]any
	if err := json.Unmarshal(mustJSON(q), &data); err != nil {
		t.Fatal(err)
	}
	data["context"] = "the connection's"
	change(data)
	return data
}

// conversionJSON is a request with the connection's context, as a host has it
// from a listing.
func conversionJSON(t *testing.T, b *Broker, q any) []byte {
	t.Helper()
	var data map[string]any
	if err := json.Unmarshal(mustJSON(q), &data); err != nil {
		t.Fatal(err)
	}
	if value, has := data["context"]; has && (value == "" || value == "the connection's") {
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

// renewing makes the connection's token one that is about to expire, so that
// the next call that needs it asks for another.
func renewing(t *testing.T, b *Broker) {
	t.Helper()
	if err := b.store.locked(func(v *state) error {
		v.Connection.Refresh, v.Connection.Expires = "refresh", time.Now().Unix()
		return b.store.write("state.json", v)
	}); err != nil {
		t.Fatal(err)
	}
}

func TestAGoogleDocIsMadeOfAWordFileByOneUpload(t *testing.T) {
	f, b := newDriveConversionFake(t)
	file := wordFile(t)
	q := conversion("Quarterly report", file)
	q.Folder = "a-folder"
	before := time.Now()
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
	if !opaque.MatchString(plan.ID) {
		t.Fatalf("the plan's ID was %q", plan.ID)
	}
	if expires, err := time.Parse(time.RFC3339, plan.Expires); err != nil || expires.Before(before.Add(5*time.Minute).Truncate(time.Second)) || expires.After(time.Now().Add(5*time.Minute)) {
		t.Fatalf("the plan expires at %q: %v", plan.Expires, err)
	}
	want := StoragePlan{ID: plan.ID, Action: "create", Name: "Quarterly report", Size: len(file), State: "prepared", Expires: plan.Expires, Effect: "write", ConvertTo: "google-document", Folder: "a-folder"}
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
	if parents, _ := f.metadata["parents"].([]any); len(parents) != 1 || parents[0] != "a-folder" {
		t.Fatalf("the metadata's parents were %v", f.metadata["parents"])
	}
	// Three members, so none is an ID.
	if len(f.metadata) != 3 || f.metadata["name"] != "Quarterly report" || f.metadata["mimeType"] != googleDocumentMedia {
		t.Fatalf("the metadata was %v", f.metadata)
	}
	if f.media != wordMedia || string(f.body) != string(file) {
		t.Fatalf("what was uploaded was %d bytes, as %q", len(f.body), f.media)
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

func TestAGoogleDocWithNoFolderAsksNothingOfDrivesFilesBeforeTheCommit(t *testing.T) {
	f, b := newDriveConversionFake(t)
	asked := 0
	inner := f.server.Config.Handler
	f.server.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		asked++
		inner.ServeHTTP(w, r)
	})
	// The folder may be empty, and may be left out.
	for _, q := range []any{conversion("Notes", wordFile(t)), members(t, conversion("Notes", wordFile(t)), func(m map[string]any) { delete(m, "folder") })} {
		asked, f.uploads = 0, 0
		plan, err := prepareConversion(t, b, q)
		if err != nil || asked != 0 || plan.Folder != "" || strings.Contains(string(mustJSON(plan)), "folder") {
			t.Fatalf("preparing made %d requests and the plan was %s: %v", asked, mustJSON(plan), err)
		}
		done := storageCall[StoragePlan](t, b, "files-commit", map[string]string{"id": plan.ID})
		if done.State != "completed" || done.Target != "made-document" || asked != 1 {
			t.Fatalf("%+v after %d requests", done, asked)
		}
		if _, has := f.metadata["parents"]; has || len(f.metadata) != 2 {
			t.Fatalf("the metadata was %v", f.metadata)
		}
	}
	// A token that is about to expire is renewed, which asks Drive's files
	// nothing.
	renewing(t, b)
	asked = 0
	if _, err := prepareConversion(t, b, conversion("Notes", wordFile(t))); err != nil || asked != 1 || f.refreshes != 1 {
		t.Fatalf("preparing with a token to renew made %d requests, %d of them for a token: %v", asked, f.refreshes, err)
	}
}

func TestAGoogleDocIsMadeOnlyInAFolderThatTakesOne(t *testing.T) {
	for name, folder := range map[string]string{
		"a file":                   `{"id":"a-folder","name":"Reports","mimeType":"text/plain","version":"1","capabilities":{"canAddChildren":true}}`,
		"a folder that takes none": `{"id":"a-folder","name":"Reports","mimeType":"application/vnd.google-apps.folder","version":"1","capabilities":{"canAddChildren":false}}`,
	} {
		f, b := newDriveConversionFake(t)
		f.found = folder
		q := conversion("Notes", wordFile(t))
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
	made := `{"id":"made-document","mimeType":"` + googleDocumentMedia + `"}`
	for name, row := range map[string]struct {
		answer                string
		status                int
		state, reason, target string
		answered              string
	}{
		"ok":                                                         {made, 200, "completed", "", "made-document", ""},
		"created":                                                    {made, 201, "completed", "", "made-document", ""},
		"the Word file, kept as it was":                              {`{"id":"made-file","mimeType":"` + wordMedia + `"}`, 200, "needs-attention", "conversion-unconfirmed", "made-file", ""},
		"no media type":                                              {`{"id":"made-file"}`, 201, "needs-attention", "conversion-unconfirmed", "made-file", ""},
		"another Google type":                                        {`{"id":"made-file","mimeType":"application/vnd.google-apps.spreadsheet"}`, 200, "needs-attention", "conversion-unconfirmed", "made-file", ""},
		"a media type that is no string":                             {`{"id":"made-file","mimeType":5}`, 200, "needs-attention", "conversion-unconfirmed", "made-file", ""},
		"a media type that is null":                                  {`{"id":"made-file","mimeType":null}`, 200, "needs-attention", "conversion-unconfirmed", "made-file", ""},
		"no ID":                                                      {`{"mimeType":"` + googleDocumentMedia + `"}`, 200, "needs-attention", "operation-uncertain", "", "200"},
		"an ID that is none":                                         {`{"id":"../made","mimeType":"` + googleDocumentMedia + `"}`, 200, "needs-attention", "operation-uncertain", "", "200"},
		"an ID that is no string":                                    {`{"id":5,"mimeType":"` + googleDocumentMedia + `"}`, 201, "needs-attention", "operation-uncertain", "", "201"},
		"an answer that is not JSON":                                 {`made-document`, 200, "needs-attention", "operation-uncertain", "", "200"},
		"an answer that is a list":                                   {`["made-document"]`, 200, "needs-attention", "operation-uncertain", "", "200"},
		"an answer that is a list of numbers":                        {`[7,8]`, 200, "needs-attention", "operation-uncertain", "", "200"},
		"an answer that is a list of answers":                        {`[` + made + `]`, 200, "needs-attention", "operation-uncertain", "", "200"},
		"an answer that is null":                                     {`null`, 200, "needs-attention", "operation-uncertain", "", "200"},
		"an answer that is a string":                                 {`"made-document"`, 200, "needs-attention", "operation-uncertain", "", "200"},
		"an answer after a byte order mark":                          {"\xef\xbb\xbf" + made, 200, "needs-attention", "operation-uncertain", "", "200"},
		"an answer after a space":                                    {" \n" + made + "\n", 200, "completed", "", "made-document", ""},
		"no answer":                                                  {``, 200, "needs-attention", "operation-uncertain", "", "200"},
		"the ID of another status":                                   {made, 202, "needs-attention", "operation-uncertain", "", "202"},
		"elsewhere":                                                  {made, 307, "needs-attention", "operation-uncertain", "", "307"},
		"a request Drive does not take":                              {made, 400, "needs-attention", "operation-uncertain", "", "400"},
		"a token Drive does not take":                                {made, 401, "needs-attention", "operation-uncertain", "", "401"},
		"a folder that has gone":                                     {made, 404, "needs-attention", "operation-uncertain", "", "404"},
		"too many requests":                                          {made, 429, "needs-attention", "operation-uncertain", "", "429"},
		"a failure of Drive's":                                       {made, 500, "needs-attention", "operation-uncertain", "", "500"},
		"an answer that holds the token":                             {`{"id":"private-token","mimeType":"` + googleDocumentMedia + `"}`, 200, "needs-attention", "operation-uncertain", "", "200"},
		"a token beside the ID":                                      {`{"id":"made-document","mimeType":"` + googleDocumentMedia + `","name":"private-token"}`, 201, "needs-attention", "operation-uncertain", "", "201"},
		"a token written with an escape":                             {`{"id":"private\u002dtoken","mimeType":"` + googleDocumentMedia + `"}`, 200, "needs-attention", "operation-uncertain", "", "200"},
		"a token with an escape, beside the ID":                      {`{"id":"made-document","mimeType":"` + googleDocumentMedia + `","name":"a private\u002dtoken"}`, 200, "needs-attention", "operation-uncertain", "", "200"},
		"a token with an escape, in a name":                          {`{"id":"made-document","mimeType":"` + googleDocumentMedia + `","private\u002dtoken":true}`, 200, "needs-attention", "operation-uncertain", "", "200"},
		"a token with an escape, deep in the answer":                 {`{"id":"made-document","mimeType":"` + googleDocumentMedia + `","owners":[{"names":["private\u002dtoken"]}]}`, 200, "needs-attention", "operation-uncertain", "", "200"},
		"a token with an escape, in an ID given twice":               {`{"id":"private\u002dtoken","id":"made-document","mimeType":"` + googleDocumentMedia + `"}`, 200, "needs-attention", "operation-uncertain", "", "200"},
		"a token with an escape, after a number":                     {`{"version":7,"id":"private\u002dtoken","mimeType":"` + googleDocumentMedia + `"}`, 200, "needs-attention", "operation-uncertain", "", "200"},
		"a token with an escape, beside the ID and after a number":   {`{"version":7,"id":"made-document","mimeType":"` + googleDocumentMedia + `","name":"private\u002dtoken"}`, 200, "needs-attention", "operation-uncertain", "", "200"},
		"a token with an escape, after a number no float holds":      {`{"version":1e1000,"id":"private\u002dtoken","mimeType":"` + googleDocumentMedia + `"}`, 201, "needs-attention", "operation-uncertain", "", "201"},
		"an answer with a number no float holds":                     {`{"version":1e1000,"id":"made-document","mimeType":"` + googleDocumentMedia + `"}`, 200, "completed", "", "made-document", ""},
		"an ID that is the token but for its end":                    {`{"id":"private-toke","tail":"n","mimeType":"` + googleDocumentMedia + `"}`, 200, "needs-attention", "operation-uncertain", "", "200"},
		"an ID that is the middle of the token":                      {`{"id":"rivate-toke","mimeType":"` + googleDocumentMedia + `"}`, 200, "needs-attention", "operation-uncertain", "", "200"},
		"an ID that is one letter of the token":                      {`{"id":"v","mimeType":"` + googleDocumentMedia + `"}`, 200, "needs-attention", "operation-uncertain", "", "200"},
		"an ID that is the token in capitals":                        {`{"id":"PRIVATE-TOKEN","mimeType":"` + googleDocumentMedia + `"}`, 200, "completed", "", "PRIVATE-TOKEN", ""},
		"an ID that is no string, and an ID under another name":      {`{"id":5,"ID":"made-document","mimeType":"` + googleDocumentMedia + `"}`, 200, "needs-attention", "operation-uncertain", "", "200"},
		"a media type that is no string, and one under another name": {`{"id":"made-file","mimeType":5,"MIMETYPE":"` + googleDocumentMedia + `"}`, 200, "needs-attention", "conversion-unconfirmed", "made-file", ""},
		"an answer with more than the two":                           {`{"kind":"drive#file","id":"made-document","owners":[{"names":["a person"]}],"mimeType":"` + googleDocumentMedia + `","version":7}`, 200, "completed", "", "made-document", ""},
		"an ID given twice":                                          {`{"id":"made-document","id":"made-document","mimeType":"` + googleDocumentMedia + `"}`, 200, "needs-attention", "operation-uncertain", "", "200"},
		"a media type given twice":                                   {`{"id":"made-file","mimeType":"` + googleDocumentMedia + `","mimeType":"` + googleDocumentMedia + `"}`, 200, "needs-attention", "conversion-unconfirmed", "made-file", ""},
		"an ID under another name":                                   {`{"ID":"made-document","mimeType":"` + googleDocumentMedia + `"}`, 200, "needs-attention", "operation-uncertain", "", "200"},
		"a media type under another name":                            {`{"id":"made-file","MIMETYPE":"` + googleDocumentMedia + `"}`, 200, "needs-attention", "conversion-unconfirmed", "made-file", ""},
		"an answer and more":                                         {made + ` {}`, 200, "needs-attention", "operation-uncertain", "", "200"},
		"an answer cut short":                                        {made[:len(made)-1], 200, "needs-attention", "operation-uncertain", "", "200"},
		"an ID with no value":                                        {`{"id":,"mimeType":"` + googleDocumentMedia + `"}`, 200, "needs-attention", "operation-uncertain", "", "200"},
		"an answer longer than is read":                              {`{"id":"made-document","mimeType":"` + googleDocumentMedia + `","name":"` + strings.Repeat("n", 64<<10) + `"}`, 200, "needs-attention", "operation-uncertain", "", ""},
		"a refusal of Drive's":                                       {made, 403, "refused", "permission-required", "", ""},
		"a conflict":                                                 {made, 409, "refused", "source-changed", "", ""},
		"a condition that failed":                                    {made, 412, "refused", "source-changed", "", ""},
		"a refusal longer than is read":                              {strings.Repeat("n", 64<<10+1), 403, "needs-attention", "operation-uncertain", "", ""},
	} {
		f, b := newDriveConversionFake(t)
		f.answer, f.status = row.answer, row.status
		plan, err := prepareConversion(t, b, conversion("Notes", wordFile(t)))
		if err != nil {
			t.Fatal(name, err)
		}
		done := storageCall[StoragePlan](t, b, "files-commit", map[string]string{"id": plan.ID})
		plan.State, plan.Error, plan.Target, plan.ProviderStatus = row.state, row.reason, row.target, row.answered
		if done != plan {
			t.Fatalf("%s: %+v", name, done)
		}
		again := storageCall[StoragePlan](t, b, "files-commit", map[string]string{"id": plan.ID})
		status := storageCall[StoragePlan](t, b, "files-status", map[string]string{"id": plan.ID})
		if again != done || status != done || f.uploads != 1 {
			t.Fatalf("%s: a second commit gave %+v and a status %+v after %d uploads", name, again, status, f.uploads)
		}
		// What needs attention stops the next change, of either kind: the
		// trashing of the file that was made is one.
		uncertain := row.state == "needs-attention"
		if _, err = prepareConversion(t, b, conversion("Notes", wordFile(t))); uncertain != (err == Error("operation-uncertain")) || !uncertain && err != nil {
			t.Fatalf("%s: the next conversion: %v", name, err)
		}
		if uncertain {
			f.found = `{"id":"made-file","name":"Notes","mimeType":"` + wordMedia + `","version":"1","size":"3","capabilities":{"canEdit":true,"canDownload":true,"canTrash":true}}`
			trash := StorageChange{Action: "delete", ID: "made-file", Revision: "1"}
			if _, err = b.Handle(context.Background(), "files-prepare", storageJSON(t, b, "files-prepare", trash)); err != Error("operation-uncertain") {
				t.Fatalf("%s: the trashing of the file: %v", name, err)
			}
		}
		if f.uploads != 1 {
			t.Fatalf("%s: %d uploads", name, f.uploads)
		}
	}
}

func TestAnAnswerThatIsLostLeavesThePlanUncertainAndIsNotSentAgain(t *testing.T) {
	f, b := newDriveConversionFake(t)
	f.dropReply = true
	q := conversion("Notes", wordFile(t))
	q.Folder = "a-folder"
	plan, err := prepareConversion(t, b, q)
	if err != nil {
		t.Fatal(err)
	}
	done := storageCall[StoragePlan](t, b, "files-commit", map[string]string{"id": plan.ID})
	// The plan says where to look and by what name, and no more is known.
	plan.State, plan.Error = "needs-attention", "operation-uncertain"
	if done != plan || done.Folder != "a-folder" || done.Name != "Notes" || done.Target != "" || done.ProviderStatus != "" {
		t.Fatalf("%+v", done)
	}
	f.dropReply = false
	again := storageCall[StoragePlan](t, b, "files-commit", map[string]string{"id": plan.ID})
	status := storageCall[StoragePlan](t, b, "files-status", map[string]string{"id": plan.ID})
	if again != done || status != done || f.uploads != 1 {
		t.Fatalf("a second commit gave %+v and a status %+v after %d uploads", again, status, f.uploads)
	}
}

// Two processes commit one plan. Each reads it as prepared, and one of them
// has claimed and sent it by the time the other comes to claim it.
func TestACommitThatFindsItsPlanClaimedSaysWhatIsStoredOfIt(t *testing.T) {
	for name, stored := range map[string]string{"settled": "", "claimed and not settled": "executing"} {
		f, b := newDriveConversionFake(t)
		other := f.broker(b.store)
		plan, err := prepareConversion(t, b, conversion("Notes", wordFile(t)))
		if err != nil {
			t.Fatal(err)
		}
		renewing(t, b)
		var first StoragePlan
		f.refreshing = func() {
			first = storageCall[StoragePlan](t, other, "files-commit", map[string]string{"id": plan.ID})
			if stored == "" {
				return
			}
			// The other process ended after its claim and before it settled.
			intent, err := b.store.readStorageIntent()
			if err != nil {
				t.Fatal(err)
			}
			intent.Plan.State = stored
			if err = b.store.writeStorageIntent(intent); err != nil {
				t.Fatal(err)
			}
		}
		second, err := b.Handle(context.Background(), "files-commit", mustJSON(map[string]string{"id": plan.ID}))
		if first.State != "completed" || first.Target != "made-document" || f.uploads != 1 || f.refreshes != 2 {
			t.Fatalf("%s: the first commit gave %+v, after %d uploads and %d renewals", name, first, f.uploads, f.refreshes)
		}
		want := first
		if stored != "" {
			want.State, want.Error = "needs-attention", "operation-uncertain"
		}
		if err != nil || second != any(want) {
			t.Fatalf("%s: the second commit gave %+v, %v", name, second, err)
		}
	}
	// A plan that was replaced while the commit renewed its token is one
	// that expired.
	f, b := newDriveConversionFake(t)
	other := f.broker(b.store)
	plan, err := prepareConversion(t, b, conversion("Notes", wordFile(t)))
	if err != nil {
		t.Fatal(err)
	}
	renewing(t, b)
	f.refreshing = func() {
		if _, err := prepareConversion(t, other, conversion("Other notes", wordFile(t))); err != nil {
			t.Fatal(err)
		}
	}
	if out, err := b.Handle(context.Background(), "files-commit", mustJSON(map[string]string{"id": plan.ID})); err != ErrGrant || out != nil || f.uploads != 0 {
		t.Fatalf("the commit of a plan that was replaced gave %+v, %v, after %d uploads", out, err, f.uploads)
	}
}

func TestAConversionIsOfAWordFileAndOfNothingElse(t *testing.T) {
	f, b := newDriveConversionFake(t)
	file := wordFile(t)
	text := base64.StdEncoding.EncodeToString(file)
	over := append(framed(""), make([]byte, MaxFileBytes)...)
	end := framed("")[len(framed(""))-22:]
	change := func(how func(map[string]any)) map[string]any { return members(t, conversion("n", file), how) }
	for name, row := range map[string]struct {
		q    any
		want error
	}{
		"text":                                   {StorageConversion{Name: "n", MediaType: "text/plain", Content: text}, ErrUnsupported},
		"a Google Doc":                           {StorageConversion{Name: "n", MediaType: googleDocumentMedia, Content: text}, ErrUnsupported},
		"the media type in capitals":             {StorageConversion{Name: "n", MediaType: strings.ToUpper(wordMedia), Content: text}, ErrUnsupported},
		"a media type that is empty":             {StorageConversion{Name: "n", Content: text}, ErrUnsupported},
		"a file that is empty":                   {conversion("n", nil), ErrUnsupported},
		"four bytes":                             {conversion("n", []byte("PK\x03\x04")), ErrUnsupported},
		"an archive that is empty":               {conversion("n", end), ErrUnsupported},
		"text called a Word file":                {conversion("n", []byte("a report")), ErrUnsupported},
		"a Word file cut short":                  {conversion("n", file[:len(file)-1]), ErrUnsupported},
		"a Word file with a byte more":           {conversion("n", append(append([]byte{}, file...), 0)), ErrUnsupported},
		"a Word file after a byte":               {conversion("n", append([]byte{0}, file...)), ErrUnsupported},
		"an archive that is no package":          {conversion("n", []byte("PK\x03\x04[Content_Types]_xml"+string(end))), ErrUnsupported},
		"a first entry that begins as none does": {conversion("n", append([]byte("PK\x03\x05[Content_Types].xml"), end...)), ErrUnsupported},
		"no end record":                          {conversion("n", []byte("PK\x03\x04[Content_Types].xml"+strings.Repeat("\x00", 22))), ErrUnsupported},
		"a comment cut short":                    {conversion("n", framed("comment")[:len(framed("comment"))-1]), ErrUnsupported},
		"a comment with a byte more":             {conversion("n", append(framed("comment"), 0)), ErrUnsupported},
		"an end record, and 65,536 bytes":        {conversion("n", append(framed(""), make([]byte, 65536)...)), ErrUnsupported},
		"a file over the bound":                  {conversion("n", over), ErrLimit},
		"content that is not base64":             {StorageConversion{Name: "n", MediaType: wordMedia, Content: "PK!"}, ErrLimit},
		"a name that is empty":                   {conversion("", file), ErrRequest},
		"a name with a path":                     {conversion("reports/n", file), ErrRequest},
		"a folder that is no ID":                 {StorageConversion{Name: "n", Folder: "a folder", MediaType: wordMedia, Content: text}, ErrRequest},
		"another connection":                     {change(func(m map[string]any) { m["context"] = "another" }), ErrChanged},
		"no context":                             {change(func(m map[string]any) { delete(m, "context") }), ErrRequest},
		"no name":                                {change(func(m map[string]any) { delete(m, "name") }), ErrRequest},
		"no name, and text":                      {change(func(m map[string]any) { delete(m, "name"); m["mediaType"] = "text/plain" }), ErrRequest},
		"no content, and text":                   {change(func(m map[string]any) { delete(m, "contentBase64"); m["mediaType"] = "text/plain" }), ErrRequest},
		"a name of 251 bytes":                    {conversion(strings.Repeat("n", 251), file), ErrRequest},
		"a name that is a dot":                   {conversion(".", file), ErrRequest},
		"a name with a control":                  {conversion("n\x01", file), ErrRequest},
		"a folder of 201 bytes":                  {StorageConversion{Name: "n", Folder: strings.Repeat("f", 201), MediaType: wordMedia, Content: text}, ErrRequest},
		"no media type":                          {change(func(m map[string]any) { delete(m, "mediaType") }), ErrRequest},
		"no content":                             {change(func(m map[string]any) { delete(m, "contentBase64") }), ErrRequest},
		"a folder that is null":                  {change(func(m map[string]any) { m["folder"] = nil }), ErrRequest},
		"a name that is null":                    {change(func(m map[string]any) { m["name"] = nil }), ErrRequest},
		"a name and a NAME":                      {change(func(m map[string]any) { m["NAME"] = "n" }), ErrRequest},
		"a Name for a name":                      {change(func(m map[string]any) { delete(m, "name"); m["Name"] = "n" }), ErrRequest},
		"a Folder":                               {change(func(m map[string]any) { m["Folder"] = "a-folder" }), ErrRequest},
		"an action":                              {change(func(m map[string]any) { m["action"] = "create" }), ErrRequest},
		"a target":                               {change(func(m map[string]any) { m["id"] = "existing-file" }), ErrRequest},
		"a revision":                             {change(func(m map[string]any) { m["revision"] = "1" }), ErrRequest},
		"what it is converted to":                {change(func(m map[string]any) { m["convertTo"] = "google-document" }), ErrRequest},
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
	// What is framed as a Word file is taken, whatever it is: the least that
	// is framed so, with a comment and with the longest, and a file at the
	// bound every file has.
	most := append(framed(""), make([]byte, MaxFileBytes-len(framed(""))-22)...)
	most = append(most, end...)
	for name, content := range map[string][]byte{"the least": framed(""), "a comment": framed("comment"), "the longest comment": framed(strings.Repeat("c", 65535)), "a file at the bound": most} {
		plan, err := prepareConversion(t, b, conversion("n", content))
		if err != nil || plan.Size != len(content) {
			t.Fatalf("%s: %+v, %v", name, plan, err)
		}
	}
	if len(most) != MaxFileBytes || len(over) <= MaxFileBytes {
		t.Fatal("the files of this test are not at the bound and over it")
	}
}

func TestAnOrdinaryChangeCannotAskForAConversion(t *testing.T) {
	f, b := newDriveConversionFake(t)
	file := wordFile(t)
	f.found = `{"id":"existing-file","name":"report.docx","mimeType":"` + wordMedia + `","version":"1","size":"3","capabilities":{"canEdit":true,"canDownload":true,"canTrash":true}}`
	// Each change is one files-prepare takes, until it carries the member.
	for name, change := range map[string]StorageChange{
		"create": {Action: "create", Name: "report.docx", MediaType: wordMedia, Content: base64.StdEncoding.EncodeToString(file)},
		"update": {Action: "update", ID: "existing-file", Revision: "1", MediaType: wordMedia, Content: base64.StdEncoding.EncodeToString(file)},
		"delete": {Action: "delete", ID: "existing-file", Revision: "1"},
	} {
		if _, err := b.Handle(context.Background(), "files-prepare", storageJSON(t, b, "files-prepare", change)); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		for _, value := range []any{"google-document", "", nil, "word"} {
			var data map[string]any
			if err := json.Unmarshal(storageJSON(t, b, "files-prepare", change), &data); err != nil {
				t.Fatal(err)
			}
			data["convertTo"] = value
			if _, err := b.Handle(context.Background(), "files-prepare", mustJSON(data)); err != ErrRequest {
				t.Fatalf("%s, with convertTo %v: %v", name, value, err)
			}
		}
	}
	if f.uploads != 0 {
		t.Fatalf("%d uploads", f.uploads)
	}
	// An ordinary create is as it was: an ID is reserved and sent, the file
	// keeps its media type, and neither the plan nor what is stored names a
	// conversion, a folder or a status.
	f.reserved = 0
	f.answer = `{"id":"reserved-file"}`
	q := StorageChange{Action: "create", Folder: "existing-file", Name: "report.docx", MediaType: wordMedia, Content: base64.StdEncoding.EncodeToString(file)}
	f.found = `{"id":"existing-file","name":"Reports","mimeType":"application/vnd.google-apps.folder","version":"1","capabilities":{"canAddChildren":true}}`
	raw, err := b.Handle(context.Background(), "files-prepare", storageJSON(t, b, "files-prepare", q))
	if err != nil {
		t.Fatal(err)
	}
	for _, member := range []string{"convertTo", "folder", "providerStatus"} {
		if strings.Contains(string(mustJSON(raw)), member) {
			t.Fatalf("an ordinary plan has the member %s: %s", member, mustJSON(raw))
		}
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
	if err != nil || strings.Contains(string(stored), "convertTo") || strings.Contains(string(stored), "providerStatus") {
		t.Fatalf("what is stored of an ordinary plan names a conversion: %v", err)
	}
	// An ordinary file is of any media type and any bytes, as before.
	q = StorageChange{Action: "create", Name: "notes.txt", MediaType: "text/plain", Content: base64.StdEncoding.EncodeToString([]byte("notes"))}
	plan = storageCall[StoragePlan](t, b, "files-prepare", q)
	if done = storageCall[StoragePlan](t, b, "files-commit", map[string]string{"id": plan.ID}); done.State != "completed" || f.metadata["mimeType"] != "text/plain" {
		t.Fatalf("%+v, as %v", done, f.metadata["mimeType"])
	}
	// Drive's answer to an ordinary create is held to the reserved ID and to
	// its status, as before, and its status is not kept.
	for name, answer := range map[string]struct {
		body   string
		status int
	}{"another ID": {`{"id":"another-file"}`, 200}, "an ID that is no string": {`{"id":5}`, 200}, "an ID that is no string, and the ID": {`{"id":5,"id":"reserved-file"}`, 200}, "no answer": {``, 200}, "another status": {`{"id":"reserved-file"}`, 202}, "a failure": {`{"id":"reserved-file"}`, 500}} {
		f, b := newDriveConversionFake(t)
		f.answer, f.status = answer.body, answer.status
		plan = storageCall[StoragePlan](t, b, "files-prepare", q)
		done = storageCall[StoragePlan](t, b, "files-commit", map[string]string{"id": plan.ID})
		plan.State, plan.Error = "needs-attention", "operation-uncertain"
		if done != plan || done.Target != "reserved-file" {
			t.Fatalf("%s: %+v", name, done)
		}
	}
	// These answers to an ordinary create are taken, as before. One holds
	// the token: the ID is the reserved one, which the answer did not choose.
	for name, answer := range map[string]string{
		"an answer that holds the token":            `{"id":"reserved-file","name":"private-token"}`,
		"the ID, and an ID that is null":            `{"id":"reserved-file","id":null}`,
		"the ID under another name":                 `{"ID":"reserved-file"}`,
		"the ID and a number beside it":             `{"id":"reserved-file","version":7}`,
		"the ID and a number no float holds":        `{"version":1e1000,"id":"reserved-file"}`,
		"the ID and a media type that is no string": `{"id":"reserved-file","mimeType":5}`,
	} {
		for _, status := range []int{200, 201} {
			f, b := newDriveConversionFake(t)
			f.answer, f.status = answer, status
			plan = storageCall[StoragePlan](t, b, "files-prepare", q)
			if done = storageCall[StoragePlan](t, b, "files-commit", map[string]string{"id": plan.ID}); done.State != "completed" || done.Target != "reserved-file" {
				t.Fatalf("%s, %d: %+v", name, status, done)
			}
		}
	}
}

// What the commit takes from Drive's answer to a conversion, by itself. The
// media type is given with an ID that is taken and with no other.
func TestWhatIsReadOfDrivesAnswerToAConversion(t *testing.T) {
	const token = "abcdEFGH01234567qrstUVWX89012345"
	for name, row := range map[string]struct{ answer, id, media string }{
		"both":                                    {`{"id":"a-file","mimeType":"a/type"}`, "a-file", "a/type"},
		"both, in the other order":                {`{"mimeType":"a/type","id":"a-file"}`, "a-file", "a/type"},
		"an ID alone":                             {`{"id":"a-file"}`, "a-file", ""},
		"a media type alone":                      {`{"mimeType":"a/type"}`, "", ""},
		"an ID that is no identifier":             {`{"id":"a file","mimeType":"a/type"}`, "a file", "a/type"},
		"an ID that is empty":                     {`{"id":"","mimeType":"a/type"}`, "", ""},
		"an ID that is a number":                  {`{"id":7,"mimeType":"a/type"}`, "", ""},
		"an ID that is null":                      {`{"id":null,"mimeType":"a/type"}`, "", ""},
		"a media type that is a number":           {`{"id":"a-file","mimeType":7}`, "a-file", ""},
		"a media type that is a list":             {`{"id":"a-file","mimeType":["a/type"]}`, "a-file", ""},
		"an ID given twice":                       {`{"id":"a-file","mimeType":"a/type","id":"a-file"}`, "", ""},
		"an ID given twice, by an escape":         {`{"id":"a-file","mimeType":"a/type","\u0069d":"a-file"}`, "", ""},
		"an ID given by an escape":                {`{"\u0069d":"a-file","mimeType":"a/type"}`, "a-file", "a/type"},
		"a media type given twice":                {`{"id":"a-file","mimeType":"a/type","mimeType":"a/type"}`, "a-file", ""},
		"an ID in an inner object":                {`{"file":{"id":"a-file","mimeType":"a/type"}}`, "", ""},
		"an inner ID beside the ID":               {`{"file":{"id":"another","mimeType":"b/type"},"id":"a-file","mimeType":"a/type"}`, "a-file", "a/type"},
		"names in capitals":                       {`{"ID":"a-file","MIMETYPE":"a/type"}`, "", ""},
		"numbers of every kind":                   {`{"a":0,"b":-1.5e-300,"c":1e1000,"d":123456789012345678901234567890,"id":"a-file","mimeType":"a/type"}`, "a-file", "a/type"},
		"no object":                               {`["a-file"]`, "", ""},
		"a list of numbers":                       {`[7,8]`, "", ""},
		"a list of objects":                       {`[{"id":"a-file","mimeType":"a/type"}]`, "", ""},
		"a number":                                {`7`, "", ""},
		"a string":                                {`"a-file"`, "", ""},
		"null":                                    {`null`, "", ""},
		"nothing":                                 {``, "", ""},
		"an object and more":                      {`{"id":"a-file","mimeType":"a/type"}{}`, "", ""},
		"an object cut short":                     {`{"id":"a-file","mimeType":"a/type"`, "", ""},
		"the token":                               {`{"id":"` + token + `","mimeType":"a/type"}`, "", ""},
		"the token in an ID":                      {`{"id":"a-` + token + `-b","mimeType":"a/type"}`, "", ""},
		"the token with an escape":                {`{"id":"abcd\u0045FGH01234567qrstUVWX89012345","mimeType":"a/type"}`, "", ""},
		"the token after a number":                {`{"n":1e1000,"id":"abcd\u0045FGH01234567qrstUVWX89012345","mimeType":"a/type"}`, "", ""},
		"the token beside the ID":                 {`{"id":"a-file","mimeType":"a/type","x":["abcd\u0045FGH01234567qrstUVWX89012345"]}`, "", ""},
		"the token beside the ID, after a number": {`{"n":7,"id":"a-file","mimeType":"a/type","x":"abcd\u0045FGH01234567qrstUVWX89012345"}`, "", ""},
		"the token beside the ID, after a number no float holds": {`{"n":-1e-1000,"id":"a-file","mimeType":"a/type","x":"abcd\u0045FGH01234567qrstUVWX89012345"}`, "", ""},
		"the token as a name":          {`{"id":"a-file","mimeType":"a/type","abcd\u0045FGH01234567qrstUVWX89012345":1}`, "", ""},
		"the token in two":             {`{"id":"a-file","mimeType":"a/type","x":"abcdEFGH01234567","y":"qrstUVWX89012345"}`, "a-file", "a/type"},
		"the token but for its end":    {`{"id":"abcdEFGH01234567qrstUVWX8901234","tail":"5","mimeType":"a/type"}`, "", ""},
		"the token but for its start":  {`{"id":"bcdEFGH01234567qrstUVWX89012345","mimeType":"a/type"}`, "", ""},
		"a part of the token and more": {`{"id":"abcdEFGH01234567qrstUVWX8901234-","mimeType":"a/type"}`, "abcdEFGH01234567qrstUVWX8901234-", "a/type"},
		"the token in other letters":   {`{"id":"ABCDefgh01234567QRSTuvwx89012345","mimeType":"a/type"}`, "ABCDefgh01234567QRSTuvwx89012345", "a/type"},
	} {
		if id, media := conversionAnswer([]byte(row.answer), token); id != row.id || media != row.media {
			t.Errorf("%s: an ID of %q and a media type of %q", name, id, media)
		}
	}
}

// A token is looked for in the answer as the answer is written, too, and so
// where it stands as something other than a string.
func TestATokenIsLookedForInTheAnswerAsItIsWritten(t *testing.T) {
	for token, row := range map[string]struct{ state, target string }{"12345": {"needs-attention", ""}, "12346": {"completed", "made-document"}} {
		f, b := newDriveConversionFake(t)
		f.token = token
		f.answer = `{"id":"made-document","mimeType":"` + googleDocumentMedia + `","version":12345}`
		if err := b.store.locked(func(v *state) error {
			v.Connection.Access = token
			return b.store.write("state.json", v)
		}); err != nil {
			t.Fatal(err)
		}
		plan, err := prepareConversion(t, b, conversion("Notes", wordFile(t)))
		if err != nil {
			t.Fatal(err)
		}
		if done := storageCall[StoragePlan](t, b, "files-commit", map[string]string{"id": plan.ID}); done.State != row.state || done.Target != row.target {
			t.Fatalf("a token of %s: %+v", token, done)
		}
	}
}

// answering is a provider that answers every request with one status and
// nothing else, which no server of the tests can be made to do for a status
// that is not three digits.
type answering int

func (status answering) RoundTrip(*http.Request) (*http.Response, error) {
	return &http.Response{StatusCode: int(status), Header: http.Header{}, Body: io.NopCloser(strings.NewReader(`{}`))}, nil
}

func TestTheStatusOfDrivesAnswerIsThreeDigitsOrIsNotKept(t *testing.T) {
	for status, kept := range map[int]string{0: "", 9: "", 99: "", 100: "100", 204: "204", 599: "599", 999: "999", 1000: "", -404: ""} {
		_, b := newDriveConversionFake(t)
		plan, err := prepareConversion(t, b, conversion("Notes", wordFile(t)))
		if err != nil {
			t.Fatal(err)
		}
		b.provider.client = &http.Client{Transport: answering(status)}
		done := storageCall[StoragePlan](t, b, "files-commit", map[string]string{"id": plan.ID})
		plan.State, plan.Error, plan.ProviderStatus = "needs-attention", "operation-uncertain", kept
		if done != plan {
			t.Fatalf("%d: %+v", status, done)
		}
	}
}

func TestTheConversionIsDrivesAlone(t *testing.T) {
	vault, _ := storageVaultFixture(t)
	s3 := testS3(t)
	gmail := NewGmail(testStore(t, "gmail-conversion"), false)
	t.Cleanup(gmail.Close)
	notion := NewNotion(testStore(t, "notion-conversion"), false)
	t.Cleanup(notion.Close)
	request := mustJSON(conversion("n", wordFile(t)))
	for name, b := range map[string]*Broker{"a local vault": vault, "S3": s3.broker, "Gmail": gmail, "Notion": notion} {
		if _, err := b.Handle(context.Background(), StorageConvertMethod, request); err != ErrRequest {
			t.Fatalf("%s: %v", name, err)
		}
	}
	// A provider that is no storage has none of the storage methods.
	for name, b := range map[string]*Broker{"Gmail": gmail, "Notion": notion} {
		for _, method := range storageMethods {
			if _, err := b.Handle(context.Background(), method, []byte(`{}`)); err != ErrRequest {
				t.Fatalf("%s, %s: %v", name, method, err)
			}
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

// A release from before the conversion reads a stored record into the members
// it knew, and strictly. The record of a conversion is one it cannot read.
func TestARecordOfAConversionIsNotOneAnEarlierReleaseReads(t *testing.T) {
	type earlierChange struct {
		Context   string `json:"context"`
		Action    string `json:"action"`
		ID        string `json:"id"`
		Folder    string `json:"folder"`
		Name      string `json:"name"`
		Revision  string `json:"revision"`
		MediaType string `json:"mediaType"`
		Content   string `json:"contentBase64"`
	}
	type earlierPlan struct {
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
	type earlierIntent struct {
		Plan       earlierPlan   `json:"plan"`
		Change     earlierChange `json:"change"`
		Epoch      string        `json:"epoch"`
		Connection string        `json:"connection"`
		ETag       string        `json:"etag"`
	}
	_, b := newDriveConversionFake(t)
	ordinary := StorageChange{Action: "create", Name: "notes.txt", MediaType: "text/plain", Content: base64.StdEncoding.EncodeToString([]byte("notes"))}
	storageCall[StoragePlan](t, b, "files-prepare", ordinary)
	stored, err := b.store.root.ReadFile("storage-intent.json")
	var earlier earlierIntent
	if err != nil || decodeStorage(stored, &earlier) != nil || earlier.Change.Name != "notes.txt" {
		t.Fatalf("the record of an ordinary plan is not one an earlier release reads: %v", err)
	}
	if _, err = prepareConversion(t, b, conversion("Notes", wordFile(t))); err != nil {
		t.Fatal(err)
	}
	stored, err = b.store.root.ReadFile("storage-intent.json")
	if err != nil || decodeStorage(stored, &earlier) != ErrRequest {
		t.Fatalf("the record of a conversion is one an earlier release reads: %v", err)
	}

	// The way out the contract gives. A conversion that was completed, or
	// one that needs attention and was looked at, leaves its record until
	// an ordinary change is prepared, after a reconnection where the plan
	// needed attention. That change's record is one an earlier release reads.
	for name, answer := range map[string]string{"completed": `{"id":"made-document","mimeType":"` + googleDocumentMedia + `"}`, "needs-attention": `{"id":"made-file"}`} {
		f, b := newDriveConversionFake(t)
		f.answer = answer
		plan, err := prepareConversion(t, b, conversion("Notes", wordFile(t)))
		if err != nil {
			t.Fatal(err)
		}
		if done := storageCall[StoragePlan](t, b, "files-commit", map[string]string{"id": plan.ID}); done.State != name {
			t.Fatalf("%s: %+v", name, done)
		}
		storageCall[StoragePlan](t, b, "files-status", map[string]string{"id": plan.ID})
		if stored, err = b.store.root.ReadFile("storage-intent.json"); err != nil || decodeStorage(stored, &earlier) != ErrRequest {
			t.Fatalf("%s: reading the status changed the record: %v", name, err)
		}
		if name == "needs-attention" {
			if err = b.store.locked(func(v *state) error {
				v.Epoch = "another epoch"
				return b.store.write("state.json", v)
			}); err != nil {
				t.Fatal(err)
			}
		}
		storageCall[StoragePlan](t, b, "files-prepare", ordinary)
		if stored, err = b.store.root.ReadFile("storage-intent.json"); err != nil || decodeStorage(stored, &earlier) != nil || earlier.Change.Name != "notes.txt" {
			t.Fatalf("%s: the record of the ordinary plan prepared afterwards is not one an earlier release reads: %v", name, err)
		}
	}
}
