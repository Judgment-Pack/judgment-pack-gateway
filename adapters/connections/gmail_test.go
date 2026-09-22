//go:build linux || darwin

package connections

import (
	"adapters/attachment"
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"sync/atomic"
	"testing"
)

func testGmail(t *testing.T) (*Broker, *atomic.Int32) {
	t.Helper()
	dir := t.TempDir()
	os.Chmod(dir, 0700)
	store, err := OpenGmailStore(dir, "alice")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	b := NewGmail(store, false)
	t.Cleanup(b.Close)
	if _, err := b.Handle(context.Background(), "configure", mustJSON(Client{"mail.apps.googleusercontent.com", "synthetic-secret"})); err != nil {
		t.Fatal(err)
	}
	reads := &atomic.Int32{}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/token":
			r.ParseForm()
			if r.Form.Get("code_verifier") == "" {
				t.Error("missing PKCE verifier")
			}
			io.WriteString(w, `{"access_token":"mail-private-token","refresh_token":"mail-private-refresh","expires_in":3600,"token_type":"Bearer","scope":"https://www.googleapis.com/auth/gmail.readonly"}`)
		case "/profile":
			io.WriteString(w, `{"emailAddress":"alice@example.test"}`)
		case "/messages":
			if r.Header.Get("Authorization") != "Bearer mail-private-token" || r.URL.Query().Get("maxResults") != "10" || r.URL.Query().Get("includeSpamTrash") != "false" {
				t.Error("search authorization/bounds")
			}
			io.WriteString(w, `{"messages":[{"id":"abc1","threadId":"abc2"}],"nextPageToken":"next"}`)
		case "/messages/abc1":
			reads.Add(1)
			if r.Method != "GET" || r.Header.Get("Authorization") != "Bearer mail-private-token" {
				t.Error("unsafe message request")
			}
			m := mailMessage{ID: "abc1", ThreadID: "abc2", HistoryID: "7", Payload: mailPart{MimeType: "text/plain", Headers: []mailHeader{{"Subject", "A policy email"}, {"From", "alice@example.test"}, {"Date", "2026-09-18"}}}}
			if r.URL.Query().Get("format") == "full" {
				m.Payload.Body.Data = base64.RawURLEncoding.EncodeToString([]byte("A test email body."))
				m.Payload.Body.Size = 18
			}
			json.NewEncoder(w).Encode(m)
		case "/revoke":
			io.WriteString(w, `{}`)
		default:
			t.Errorf("unexpected endpoint %s", r.URL.Path)
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(server.Close)
	b.provider = provider{server.URL + "/auth", server.URL + "/token", server.URL + "/revoke", server.URL, server.Client(), true, false, false, false}
	f := start(t, b, "connect")
	u, _ := url.Parse(f.URL)
	if u.Query().Get("scope") != gmailScope || u.Query().Get("trigger_onepick") != "" || u.Query().Get("code_challenge_method") != "S256" {
		t.Fatal("Gmail scope/authorization contract")
	}
	callback := u.Query().Get("redirect_uri") + "?" + url.Values{"state": {u.Query().Get("state")}, "code": {"synthetic-code"}}.Encode()
	r, err := http.Get(callback)
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, r.Body)
	r.Body.Close()
	state, err := b.Handle(context.Background(), "poll", mustJSON(map[string]string{"id": f.ID}))
	if err != nil || state.(FlowResult).State != "complete" {
		t.Fatalf("%+v %v", state, err)
	}
	return b, reads
}
func TestGmailSearchSelectAndVerifiedTextExport(t *testing.T) {
	b, reads := testGmail(t)
	ctx := context.Background()
	status, err := b.Handle(ctx, "status", nil)
	if err != nil || status.(Status).Provider != "gmail" || status.(Status).Account.Email != "alice@example.test" {
		t.Fatal(status, err)
	}
	list, err := b.Handle(ctx, "search", []byte(`{"query":"from:alice@example.test"}`))
	if err != nil || len(list.(MailSearch).Messages) != 1 || list.(MailSearch).Messages[0].Subject != "A policy email" {
		t.Fatal(list, err)
	}
	if strings.Contains(string(mustJSON(list)), "test email body") {
		t.Fatal("search disclosed message body")
	}
	selected, err := b.Handle(ctx, "select", mailSelectRequest(t, b, "abc1"))
	if err != nil {
		t.Fatal(err)
	}
	selection := selected.([]MailSelection)[0]
	out, err := b.provider.readMail(ctx, b.store, mustJSON(selection))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(out), "mail-private") {
		t.Fatal("credential escaped into acquisition")
	}
	var packet struct {
		Result json.RawMessage `json:"result"`
	}
	json.Unmarshal(out, &packet)
	if err := attachment.Check(packet.Result); err != nil {
		t.Fatal(err)
	}
	var record attachment.Record
	json.Unmarshal(packet.Result, &record)
	if record.Provenance.Source.Kind != attachment.SourceGmail || record.Provenance.Source.MessageID != "abc1" || record.Provenance.Source.Format != "text-export-v1" || !strings.Contains(record.Content.Pages[0].Text, "A test email body.") {
		t.Fatalf("wrong exported content: %+v", record)
	}
	if reads.Load() != 3 {
		t.Fatalf("unexpected read count %d", reads.Load())
	}
	if _, err := b.provider.readMail(ctx, b.store, mustJSON(selection)); err != ErrGrant {
		t.Fatalf("replay: %v", err)
	}
	if path := os.Getenv("JPACK_TEST_GMAIL_RECORD"); path != "" {
		if err := os.WriteFile(path, packet.Result, 0600); err != nil {
			t.Fatal(err)
		}
	}
}
func TestGmailSelectionScopeAndDisconnect(t *testing.T) {
	b, reads := testGmail(t)
	ctx := context.Background()
	for _, method := range []string{"send", "delete", "modify", "pick"} {
		if _, err := b.Handle(ctx, method, []byte(`{}`)); err != ErrRequest {
			t.Fatalf("%s accepted: %v", method, err)
		}
	}
	for _, q := range []string{`{"messageIds":["../token"]}`, `{"messageIds":["abc1","abc1"]}`, `{"messageIds":[]}`, `{"messageIds":["a","b","c","d","e"]}`} {
		var request map[string]any
		json.Unmarshal([]byte(q), &request)
		var valid map[string]any
		json.Unmarshal(mailSelectRequest(t, b, "abc1"), &valid)
		request["selectionContext"] = valid["selectionContext"]
		if _, err := b.Handle(ctx, "select", mustJSON(request)); err != ErrRequest {
			t.Fatalf("bad selection accepted: %s %v", q, err)
		}
	}
	r, err := b.Handle(ctx, "select", mailSelectRequest(t, b, "abc1"))
	if err != nil {
		t.Fatal(err)
	}
	g := r.([]MailSelection)[0]
	wrong := g
	wrong.MessageID = "abc2"
	if _, err := b.provider.readMail(ctx, b.store, mustJSON(wrong)); err != ErrGrant {
		t.Fatal("substitution", err)
	}
	if _, err := b.Handle(ctx, "disconnect", nil); err != nil {
		t.Fatal(err)
	}
	if _, err := b.provider.readMail(ctx, b.store, mustJSON(g)); err != ErrGrant {
		t.Fatal("read after disconnect", err)
	}
	if reads.Load() != 0 {
		t.Fatal("unauthorized read")
	}
}
func TestGmailCustodyNamespaceAndPermissions(t *testing.T) {
	dir := t.TempDir()
	os.Chmod(dir, 0700)
	drive, err := OpenStore(dir, "alice")
	if err != nil {
		t.Fatal(err)
	}
	defer drive.Close()
	mail, err := OpenGmailStore(dir, "alice")
	if err != nil {
		t.Fatal(err)
	}
	defer mail.Close()
	if err := drive.write("state.json", state{Client: Client{ID: "drive.apps.googleusercontent.com"}}); err != nil {
		t.Fatal(err)
	}
	if err := mail.locked(func(v *state) error {
		if v.Client.ID != "" {
			t.Error("Drive configuration crossed provider namespace")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	os.Chmod(dir, 0777)
	if got, err := OpenGmailStore(dir, "bob"); err == nil {
		got.Close()
		t.Fatal("permissive custody root accepted")
	}
}
func TestGmailBodyRenderingIsBoundedAndDoesNotLoadResources(t *testing.T) {
	makePart := func(media, body string) mailPart {
		p := mailPart{MimeType: media}
		p.Body.Data = base64.RawURLEncoding.EncodeToString([]byte(body))
		p.Body.Size = int64(len(body))
		return p
	}
	for _, tc := range []struct {
		name string
		part mailPart
		want string
		err  error
	}{
		{"table boundaries", makePart("text/html", "<table><tr><th>Limit</th><th>Actual</th></tr><tr><td>10</td><td>20</td></tr></table>"), "\nLimit\tActual\t\n10\t20\t\n", nil},
		{"paragraph boundaries", makePart("text/html", "<p>first</p>second<h2>Heading</h2>third"), "\nfirst\nsecond\nHeading\nthird", nil},
		{"inline emphasis", makePart("text/html", "inter<strong>net</strong>"), "internet", nil},
		{"empty alternative", mailPart{MimeType: "multipart/alternative", Parts: []mailPart{makePart("text/plain", " \r\n"), makePart("text/html", "<p>available</p>")}}, "\navailable\n", nil},
		{"plain", makePart("text/plain", "plain body"), "plain body", nil},
		{"html", makePart("text/html", `<html><head><style>hidden</style></head><body><p>Visible &amp; readable<img src="https://example.invalid/track"><script>hidden</script></p></body></html>`), "\nVisible & readable\n", nil},
		{"alternative", mailPart{MimeType: "multipart/alternative", Parts: []mailPart{makePart("text/plain", "once"), makePart("text/html", "<p>twice</p>")}}, "once", nil},
		{"separate body", func() mailPart { p := makePart("text/plain", ""); p.Body.AttachmentID = "external-body"; return p }(), "", ErrUnsupported},
		{"excluded attachment", func() mailPart {
			p := makePart("text/plain", "private attachment")
			p.Filename = "attached.txt"
			return p
		}(), "", nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			budget := 256
			got, err := mailText(tc.part, 0, &budget)
			if got != tc.want || err != tc.err {
				t.Fatalf("%q %v", got, err)
			}
		})
	}
	deep := makePart("text/plain", "body")
	for i := 0; i < 22; i++ {
		deep = mailPart{MimeType: "multipart/mixed", Parts: []mailPart{deep}}
	}
	budget := 256
	if _, err := mailText(deep, 0, &budget); err != ErrLimit {
		t.Fatal("deep MIME accepted", err)
	}
	if mailJSONBounded([]byte(strings.Repeat("[", 65) + strings.Repeat("]", 65))) {
		t.Fatal("deep JSON accepted")
	}
}

// Bind selection to the connection that returned the user's search results.
func mailSelectRequest(t *testing.T, b *Broker, ids ...string) []byte {
	t.Helper()
	var epoch string
	if err := b.store.locked(func(v *state) error { epoch = v.Epoch; return nil }); err != nil {
		t.Fatal(err)
	}
	return mustJSON(map[string]any{"messageIds": ids, "selectionContext": epoch})
}
func TestGmailSelectionRefusesConnectionChangedAfterSearch(t *testing.T) {
	b, _ := testGmail(t)
	ctx := context.Background()
	found, err := b.Handle(ctx, "search", nil)
	if err != nil {
		t.Fatal(err)
	}
	request := mustJSON(map[string]any{"messageIds": []string{"abc1"}, "selectionContext": found.(MailSearch).SelectionContext})
	if err := b.store.locked(func(v *state) error {
		v.Epoch = randomID()
		v.Connection.ID = "new-account"
		return b.store.write("state.json", v)
	}); err != nil {
		t.Fatal(err)
	}
	if result, err := b.Handle(ctx, "select", request); err != ErrCanceled || result != nil {
		t.Fatalf("stale selection accepted: %v %v", result, err)
	}
}
