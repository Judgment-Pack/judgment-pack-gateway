//go:build linux || darwin

package connections

import (
	"adapters/attachment"
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

// Regression cases reproduced during the independent Gmail review.
func regressionMailPart(media, body string) mailPart {
	p := mailPart{MimeType: media}
	p.Body.Size = int64(len(body))
	p.Body.Data = base64.RawURLEncoding.EncodeToString([]byte(body))
	return p
}

func TestGmailRegressionSearchDoesNotReturnMetadataAfterDisconnect(t *testing.T) {
	b, _ := testGmail(t)
	entered, release := make(chan struct{}), make(chan struct{})
	original := b.provider.client.Transport
	b.provider.client = &http.Client{Transport: pausedTransport(func(r *http.Request) (*http.Response, error) {
		if r.URL.Path == "/messages" {
			close(entered)
			<-release
		}
		return original.RoundTrip(r)
	})}
	type response struct {
		value any
		err   error
	}
	done := make(chan response, 1)
	go func() {
		value, err := b.Handle(context.Background(), "search", []byte(`{"query":"private"}`))
		done <- response{value, err}
	}()
	<-entered
	other := NewGmail(b.store, false)
	other.provider = b.provider
	t.Cleanup(other.Close)
	result, disconnectErr := other.Handle(context.Background(), "disconnect", nil)
	close(release)
	reply := <-done
	if disconnectErr != nil {
		t.Fatal(result, disconnectErr)
	}
	if reply.err != ErrCanceled {
		t.Fatalf("expected canceled search, got %v", reply.err)
	}
	// gateway-connections/main.go serializes Result even when Error is set.
	wire := string(mustJSON(map[string]any{"id": "search", "result": reply.value, "error": reply.err.Error()}))
	if reply.value != nil {
		t.Fatalf("canceled search still releases provider metadata: %s", wire)
	}
}

func TestGmailRegressionEmptyPlainAlternativeFallsBackToHTML(t *testing.T) {
	b, _ := testGmail(t)
	selected, err := b.Handle(context.Background(), "select", mailSelectRequest(t, b, "abc1"))
	if err != nil {
		t.Fatal(err)
	}
	selection := selected.([]MailSelection)[0]
	original := b.provider.client.Transport
	b.provider.client = &http.Client{Transport: pausedTransport(func(r *http.Request) (*http.Response, error) {
		if r.URL.Path == "/messages/abc1" && r.URL.Query().Get("format") == "full" {
			m := mailMessage{ID: "abc1", ThreadID: "abc2", HistoryID: "7", Payload: mailPart{MimeType: "multipart/alternative", Headers: []mailHeader{{"Subject", "HTML-only content with empty plain fallback"}}, Parts: []mailPart{regressionMailPart("text/plain", ""), regressionMailPart("text/html", "<p>Usable body</p>")}}}
			return fakeResponse(r, mustJSON(m)), nil
		}
		return original.RoundTrip(r)
	})}
	out, err := b.provider.readMail(context.Background(), b.store, mustJSON(selection))
	if err != nil {
		t.Fatalf("valid HTML alternative lost: %v", err)
	}
	var envelope struct{ Result attachment.Record }
	if json.Unmarshal(out, &envelope) != nil || !strings.Contains(envelope.Result.Content.Pages[0].Text, "Usable body") {
		t.Fatal("HTML alternative not exported")
	}
}

func TestGmailRegressionHTMLExportDoesNotJoinIndependentNumbers(t *testing.T) {
	b, _ := testGmail(t)
	selected, err := b.Handle(context.Background(), "select", mailSelectRequest(t, b, "abc1"))
	if err != nil {
		t.Fatal(err)
	}
	selection := selected.([]MailSelection)[0]
	original := b.provider.client.Transport
	b.provider.client = &http.Client{Transport: pausedTransport(func(r *http.Request) (*http.Response, error) {
		if r.URL.Path == "/messages/abc1" && r.URL.Query().Get("format") == "full" {
			part := regressionMailPart("text/html", "<table><tr><th>Debit</th><th>Credit</th></tr><tr><td>10</td><td>20</td></tr></table>")
			part.Headers = []mailHeader{{"Subject", "Invoice"}}
			return fakeResponse(r, mustJSON(mailMessage{ID: "abc1", ThreadID: "abc2", HistoryID: "7", Payload: part})), nil
		}
		return original.RoundTrip(r)
	})}
	out, err := b.provider.readMail(context.Background(), b.store, mustJSON(selection))
	if err != nil {
		t.Fatal(err)
	}
	var envelope struct{ Result attachment.Record }
	if err := json.Unmarshal(out, &envelope); err != nil {
		t.Fatal(err)
	}
	record := envelope.Result
	if strings.Contains(record.Content.Pages[0].Text, "1020") {
		t.Fatalf("export accepted as processing.status=%s and signed-envelope-ready text contains invented merged amount: %q", record.Processing.Status, record.Content.Pages[0].Text)
	}
}

func TestGmailRegressionFetchesExternalBodyButExcludesFileAttachment(t *testing.T) {
	b, _ := testGmail(t)
	selected, err := b.Handle(context.Background(), "select", mailSelectRequest(t, b, "abc1"))
	if err != nil {
		t.Fatal(err)
	}
	original := b.provider.client.Transport
	bodyRequests := 0
	body := "Externally stored body"
	b.provider.client = &http.Client{Transport: pausedTransport(func(r *http.Request) (*http.Response, error) {
		switch {
		case r.URL.Path == "/messages/abc1" && r.URL.Query().Get("format") == "full":
			textPart := mailPart{MimeType: "text/plain"}
			textPart.Body.Size = int64(len(body))
			textPart.Body.AttachmentID = "body-1"
			filePart := mailPart{MimeType: "text/plain", Filename: "excluded.txt"}
			filePart.Body.Size = 20
			filePart.Body.AttachmentID = "file-1"
			return fakeResponse(r, mustJSON(mailMessage{ID: "abc1", ThreadID: "abc2", HistoryID: "7", Payload: mailPart{MimeType: "multipart/mixed", Parts: []mailPart{textPart, filePart}}})), nil
		case strings.Contains(r.URL.Path, "/attachments/"):
			if r.URL.Path != "/messages/abc1/attachments/body-1" || r.Method != "GET" {
				t.Errorf("unexpected separate attachment request: %s %s", r.Method, r.URL.Path)
			}
			bodyRequests++
			return fakeResponse(r, mustJSON(map[string]any{"size": len(body), "data": base64.RawURLEncoding.EncodeToString([]byte(body))})), nil
		default:
			return original.RoundTrip(r)
		}
	})}
	out, err := b.provider.readMail(context.Background(), b.store, mustJSON(selected.([]MailSelection)[0]))
	if err != nil || bodyRequests != 1 || !strings.Contains(string(out), body) {
		t.Fatalf("external body result err=%v requests=%d", err, bodyRequests)
	}
}

func TestGmailRegressionCharsetsAndAggregateBounds(t *testing.T) {
	p := regressionMailPart("text/plain", "caf\xe9")
	p.Headers = []mailHeader{{"Content-Type", "text/plain; charset=iso-8859-1"}}
	budget := 256
	if out, err := mailText(p, 0, &budget); err != nil || out != "café" {
		t.Fatalf("legacy charset: %q %v", out, err)
	}
	p.Headers = []mailHeader{{"Content-Type", "text/plain; charset=not-a-real-charset"}}
	budget = 256
	if _, err := mailText(p, 0, &budget); err != ErrUnsupported {
		t.Fatal("unknown charset accepted", err)
	}
	b, _ := testGmail(t)
	part := regressionMailPart("text/plain", "body")
	part.Body.Size = MaxFileBytes + 1
	nodes, requests, total := 256, 8, 0
	if _, err := b.provider.mailBody(context.Background(), "fake", "abc1", part, 0, &nodes, &requests, &total); err != ErrLimit {
		t.Fatal("body size bound", err)
	}
	part.Body.Size = MaxFileBytes
	nodes, requests, total = 256, 8, 1
	if _, err := b.provider.mailBody(context.Background(), "fake", "abc1", part, 0, &nodes, &requests, &total); err != ErrLimit {
		t.Fatal("aggregate body bound", err)
	}
	part.Body.Size = 4
	part.Body.AttachmentID = "body-1"
	nodes, requests, total = 256, 0, 0
	if _, err := b.provider.mailBody(context.Background(), "fake", "abc1", part, 0, &nodes, &requests, &total); err != ErrLimit {
		t.Fatal("request count bound", err)
	}
}
