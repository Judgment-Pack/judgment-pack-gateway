package connections

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"mime"
	"net/url"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"

	"adapters/attachment"
	"adapters/document"
	"adapters/internal/canon"
	"golang.org/x/net/html"
	"golang.org/x/net/html/charset"
)

var messageID = regexp.MustCompile(`^[a-f0-9]{1,64}$`)
var historyID = regexp.MustCompile(`^[0-9]{1,32}$`)

type MailSelection struct {
	MessageID string `json:"messageId"`
	Grant     string `json:"grant"`
}
type mailHeader struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}
type mailPart struct {
	MimeType string       `json:"mimeType"`
	Filename string       `json:"filename"`
	Headers  []mailHeader `json:"headers"`
	Body     struct {
		Size         int64  `json:"size"`
		Data         string `json:"data"`
		AttachmentID string `json:"attachmentId"`
	} `json:"body"`
	Parts []mailPart `json:"parts"`
}
type mailMessage struct {
	ID           string   `json:"id"`
	ThreadID     string   `json:"threadId"`
	HistoryID    string   `json:"historyId"`
	SizeEstimate int64    `json:"sizeEstimate"`
	Payload      mailPart `json:"payload"`
}
type MailPreview struct {
	ID      string `json:"id"`
	Subject string `json:"subject"`
	From    string `json:"from"`
	Date    string `json:"date"`
}
type MailSearch struct {
	SelectionContext string        `json:"selectionContext"`
	Messages         []MailPreview `json:"messages"`
	NextPageToken    string        `json:"nextPageToken,omitempty"`
}

func (p provider) mailAccount(ctx context.Context, token string) (account, error) {
	raw, _, err := p.request(ctx, "GET", p.api+"/profile", token, nil, 64<<10)
	if err != nil {
		return account{}, err
	}
	var v struct {
		Email string `json:"emailAddress"`
	}
	if json.Unmarshal(raw, &v) != nil || len(v.Email) == 0 || len(v.Email) > 320 || !strings.Contains(v.Email, "@") || strings.ContainsAny(v.Email, "\r\n\x00") {
		return account{}, ErrProvider
	}
	return account{ID: strings.TrimPrefix(digest([]byte(strings.ToLower(v.Email))), "sha256:"), Email: v.Email, Name: v.Email}, nil
}
func (p provider) mailMessage(ctx context.Context, token, id, format string) (mailMessage, error) {
	var v mailMessage
	if !messageID.MatchString(id) {
		return v, ErrRequest
	}
	q := url.Values{"format": {format}}
	if format == "metadata" {
		q["metadataHeaders"] = []string{"Subject", "From", "Date"}
	}
	bound := int64(64 << 10)
	if format == "full" {
		bound = 8 << 20
	}
	raw, _, err := p.request(ctx, "GET", p.api+"/messages/"+id+"?"+q.Encode(), token, nil, bound)
	if err != nil {
		return v, err
	}
	if !mailJSONBounded(raw) || json.Unmarshal(raw, &v) != nil || v.ID != id || !messageID.MatchString(v.ThreadID) || !historyID.MatchString(v.HistoryID) {
		return v, ErrProvider
	}
	return v, nil
}
func header(headers []mailHeader, name string) string {
	for _, h := range headers {
		if strings.EqualFold(h.Name, name) {
			return h.Value
		}
	}
	return ""
}
func readableHeader(headers []mailHeader, name string) string {
	raw := header(headers, name)
	decoder := &mime.WordDecoder{CharsetReader: charset.NewReaderLabel}
	if decoded, err := decoder.DecodeHeader(raw); err == nil {
		raw = decoded
	}
	return strings.Join(strings.Fields(raw), " ")
}
func previewHeader(headers []mailHeader, name string) string {
	v := readableHeader(headers, name)
	r := []rune(v)
	if len(r) > 256 {
		r = r[:256]
	}
	return string(r)
}
func (b *Broker) mailOperation(ctx context.Context, method string, raw []byte) (any, error) {
	var client Client
	var credentials credential
	var epoch string
	err := b.store.locked(func(v *state) error {
		if v.Disabled {
			return ErrPolicy
		}
		if v.Connection == nil {
			return ErrConnect
		}
		client, credentials, epoch = v.Client, *v.Connection, v.Epoch
		return nil
	})
	if err != nil {
		return nil, err
	}
	if method == "select" {
		var q struct {
			IDs              []string `json:"messageIds"`
			SelectionContext string   `json:"selectionContext"`
		}
		if decode(raw, &q) != nil || !opaque.MatchString(q.SelectionContext) || len(q.IDs) == 0 || len(q.IDs) > 4 {
			return nil, ErrRequest
		}
		seen := map[string]bool{}
		for _, id := range q.IDs {
			if !messageID.MatchString(id) || seen[id] {
				return nil, ErrRequest
			}
			seen[id] = true
		}
		var selected []MailSelection
		err = b.store.locked(func(v *state) error {
			if v.Disabled || v.Epoch != epoch || q.SelectionContext != v.Epoch || v.Connection == nil || v.Connection.ID != credentials.ID {
				return ErrCanceled
			}
			grants, err := b.store.makeGrants(credentials.ID, q.IDs)
			for _, g := range grants {
				selected = append(selected, MailSelection{g.FileID, g.Grant})
			}
			return err
		})
		if err != nil {
			return nil, err
		}
		return selected, nil
	}
	var q struct {
		Query     string `json:"query"`
		PageToken string `json:"pageToken"`
	}
	if decode(raw, &q) != nil || len(q.Query) > 1024 || len(q.PageToken) > 2048 || strings.ContainsAny(q.Query+q.PageToken, "\x00\r\n") {
		return nil, ErrRequest
	}
	token, err := b.provider.access(ctx, b.store, client, credentials, epoch)
	if err != nil {
		return nil, err
	}
	query := url.Values{"maxResults": {"10"}, "includeSpamTrash": {"false"}}
	if q.Query != "" {
		query.Set("q", q.Query)
	}
	if q.PageToken != "" {
		query.Set("pageToken", q.PageToken)
	}
	data, _, err := b.provider.request(ctx, "GET", b.provider.api+"/messages?"+query.Encode(), token, nil, 64<<10)
	if err != nil {
		return nil, err
	}
	var list struct {
		Messages []struct {
			ID string `json:"id"`
		} `json:"messages"`
		NextPageToken string `json:"nextPageToken"`
	}
	if json.Unmarshal(data, &list) != nil || len(list.Messages) > 10 || len(list.NextPageToken) > 2048 {
		return nil, ErrProvider
	}
	out := MailSearch{SelectionContext: epoch, Messages: []MailPreview{}, NextPageToken: list.NextPageToken}
	for _, item := range list.Messages {
		m, err := b.provider.mailMessage(ctx, token, item.ID, "metadata")
		if err != nil {
			return nil, err
		}
		out.Messages = append(out.Messages, MailPreview{m.ID, previewHeader(m.Payload.Headers, "Subject"), previewHeader(m.Payload.Headers, "From"), previewHeader(m.Payload.Headers, "Date")})
	}
	// Do not return newly fetched metadata after another companion disconnects.
	err = b.store.locked(func(v *state) error {
		if v.Disabled || v.Epoch != epoch || v.Connection == nil || v.Connection.ID != credentials.ID {
			return ErrCanceled
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// mailText produces a bounded text export. Attachments and external resources
// are excluded. multipart/alternative chooses one body, not duplicated variants.
func mailFile(part mailPart) bool {
	return part.Filename != "" || strings.HasPrefix(strings.ToLower(strings.TrimSpace(header(part.Headers, "Content-Disposition"))), "attachment")
}

// Skip a known empty alternative without fetching an unused body. Invalid
// encoded content remains selected so normal validation fails closed.
func mailPartHasBody(part mailPart) bool {
	if part.Body.AttachmentID != "" {
		return part.Body.Size != 0
	}
	if len(part.Body.Data) > 6<<20 {
		return true
	}
	data, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(part.Body.Data, "="))
	return err != nil || part.Body.Size != int64(len(data)) || strings.TrimSpace(string(data)) != ""
}

func mailBodyParts(part mailPart) []mailPart {
	if strings.EqualFold(part.MimeType, "multipart/alternative") {
		for _, preferred := range []string{"text/plain", "text/html"} {
			for _, child := range part.Parts {
				if strings.EqualFold(child.MimeType, preferred) && !mailFile(child) && mailPartHasBody(child) {
					return []mailPart{child}
				}
			}
		}
		if len(part.Parts) > 0 {
			return part.Parts[len(part.Parts)-1:]
		}
	}
	return part.Parts
}

// Gmail can store a body part separately even when it is not a file attachment.
// Retrieve only selected body alternatives, with aggregate request/byte bounds.
func (p provider) mailBody(ctx context.Context, token, id string, part mailPart, depth int, nodes, requests, bytes *int) (mailPart, error) {
	*nodes--
	if depth > 20 || *nodes < 0 {
		return part, ErrLimit
	}
	if mailFile(part) {
		return part, nil
	}
	if strings.HasPrefix(strings.ToLower(part.MimeType), "multipart/") {
		children := mailBodyParts(part)
		part.Parts = make([]mailPart, 0, len(children))
		for _, child := range children {
			next, err := p.mailBody(ctx, token, id, child, depth+1, nodes, requests, bytes)
			if err != nil {
				return part, err
			}
			part.Parts = append(part.Parts, next)
		}
		return part, nil
	}
	if !strings.EqualFold(part.MimeType, "text/plain") && !strings.EqualFold(part.MimeType, "text/html") {
		return part, nil
	}
	if part.Body.Size < 0 || part.Body.Size > MaxFileBytes || int64(*bytes)+part.Body.Size > MaxFileBytes {
		return part, ErrLimit
	}
	*bytes += int(part.Body.Size)
	if part.Body.AttachmentID == "" {
		return part, nil
	}
	*requests--
	if *requests < 0 || len(part.Body.AttachmentID) > 2048 || !regexp.MustCompile(`^[A-Za-z0-9_-]+$`).MatchString(part.Body.AttachmentID) {
		return part, ErrLimit
	}
	raw, _, err := p.request(ctx, "GET", p.api+"/messages/"+id+"/attachments/"+part.Body.AttachmentID, token, nil, 6<<20)
	if err != nil {
		return part, err
	}
	var body struct {
		Size int64  `json:"size"`
		Data string `json:"data"`
	}
	if json.Unmarshal(raw, &body) != nil || body.Size != part.Body.Size {
		return part, ErrProvider
	}
	part.Body.Data = body.Data
	part.Body.AttachmentID = ""
	return part, nil
}

func mailText(part mailPart, depth int, budget *int) (string, error) {
	*budget--
	if depth > 20 || *budget < 0 {
		return "", ErrLimit
	}
	if mailFile(part) {
		return "", nil
	}
	media := strings.ToLower(part.MimeType)
	if strings.HasPrefix(media, "multipart/") {
		parts := mailBodyParts(part)
		if media == "multipart/alternative" && len(parts) == 1 {
			return mailText(parts[0], depth+1, budget)
		}
		var out strings.Builder
		for _, child := range parts {
			text, err := mailText(child, depth+1, budget)
			if err != nil {
				return "", err
			}
			if out.Len()+len(text)+1 > MaxFileBytes {
				return "", ErrLimit
			}
			if text != "" {
				out.WriteString(text)
				out.WriteByte('\n')
			}
		}
		return out.String(), nil
	}
	if media != "text/plain" && media != "text/html" {
		return "", nil
	}
	if part.Body.AttachmentID != "" {
		return "", ErrUnsupported
	}
	if part.Body.Size < 0 || part.Body.Size > MaxFileBytes || len(part.Body.Data) > 6<<20 {
		return "", ErrLimit
	}
	data, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(part.Body.Data, "="))
	if err != nil || int64(len(data)) != part.Body.Size {
		return "", ErrProvider
	}
	_, params, err := mime.ParseMediaType(header(part.Headers, "Content-Type"))
	if err != nil && header(part.Headers, "Content-Type") != "" {
		return "", ErrUnsupported
	}
	label := strings.ToLower(params["charset"])
	if label != "" && label != "utf-8" && label != "us-ascii" {
		reader, err := charset.NewReaderLabel(label, strings.NewReader(string(data)))
		if err != nil {
			return "", ErrUnsupported
		}
		data, err = io.ReadAll(io.LimitReader(reader, MaxFileBytes+1))
		if err != nil {
			return "", ErrProvider
		}
	}
	if len(data) > MaxFileBytes {
		return "", ErrLimit
	}
	if !utf8.Valid(data) {
		return "", ErrUnsupported
	}
	if media == "text/plain" {
		return string(data), nil
	}
	tokenizer := html.NewTokenizer(strings.NewReader(string(data)))
	var out strings.Builder
	suppressed := ""
	for {
		typeOf := tokenizer.Next()
		if typeOf == html.ErrorToken {
			if tokenizer.Err() != io.EOF {
				return "", ErrUnsupported
			}
			break
		}
		switch typeOf {
		case html.StartTagToken, html.SelfClosingTagToken:
			name, _ := tokenizer.TagName()
			tag := string(name)
			if suppressed == "" && (tag == "script" || tag == "style" || tag == "head") {
				suppressed = tag
			}
			if suppressed == "" {
				mailHTMLBoundary(&out, tag)
			}
		case html.EndTagToken:
			name, _ := tokenizer.TagName()
			if string(name) == suppressed {
				suppressed = ""
			} else if suppressed == "" {
				mailHTMLBoundary(&out, string(name))
			}
		case html.TextToken:
			if suppressed == "" {
				out.Write(tokenizer.Text())
			}
		}
		if out.Len() > MaxFileBytes {
			return "", ErrLimit
		}
	}
	return out.String(), nil
}

// Preserve visible word/number boundaries when removing layout markup.
// Inline elements deliberately do not add spaces (e.g. inter<strong>net</strong>).
func mailHTMLBoundary(out *strings.Builder, tag string) {
	switch tag {
	case "td", "th":
		if out.Len() > 0 {
			last := out.String()[out.Len()-1]
			if last != '\t' && last != '\n' {
				out.WriteByte('\t')
			}
		}
	case "br", "hr", "p", "div", "li", "tr", "table", "thead", "tbody", "tfoot", "ul", "ol", "dl", "dt", "dd", "h1", "h2", "h3", "h4", "h5", "h6", "section", "article", "header", "footer", "blockquote", "pre", "address", "figure", "figcaption":
		if out.Len() == 0 || out.String()[out.Len()-1] != '\n' {
			out.WriteByte('\n')
		}
	}
}

func ReadGmail(ctx context.Context, s *Store, raw []byte) ([]byte, error) {
	return googleMail().readMail(ctx, s, raw)
}
func (p provider) readMail(ctx context.Context, s *Store, raw []byte) ([]byte, error) {
	var req MailSelection
	if decode(raw, &req) != nil || !opaque.MatchString(req.Grant) || !messageID.MatchString(req.MessageID) {
		return nil, ErrRequest
	}
	client, credentials, epoch, err := s.consumeGrant(req.Grant, req.MessageID)
	if err != nil {
		return nil, err
	}
	token, err := p.access(ctx, s, client, credentials, epoch)
	if err != nil {
		return nil, err
	}
	m, err := p.mailMessage(ctx, token, req.MessageID, "full")
	if err != nil {
		return nil, err
	}
	nodes, requests, bodyBytes := 256, 8, 0
	m.Payload, err = p.mailBody(ctx, token, req.MessageID, m.Payload, 0, &nodes, &requests, &bodyBytes)
	if err != nil {
		return nil, err
	}
	budget := 256
	body, err := mailText(m.Payload, 0, &budget)
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(body) == "" {
		return nil, ErrUnsupported
	}
	var text strings.Builder
	text.WriteString("Gmail message export (attachments excluded)\n")
	for _, name := range []string{"Subject", "From", "To", "Cc", "Date"} {
		v := readableHeader(m.Payload.Headers, name)
		if len(v) > 8192 {
			return nil, ErrLimit
		}
		if v != "" {
			text.WriteString(name + ": " + v + "\n")
		}
	}
	text.WriteByte('\n')
	text.WriteString(body)
	data := []byte(text.String())
	if len(data) > MaxFileBytes {
		return nil, ErrLimit
	}
	after, err := p.mailMessage(ctx, token, req.MessageID, "metadata")
	if err != nil {
		return nil, err
	}
	if after.HistoryID != m.HistoryID || after.ThreadID != m.ThreadID {
		return nil, ErrChanged
	}
	identity, err := document.OwnIdentity()
	if err != nil {
		return nil, Error("processing-failed")
	}
	identity.Name = "adapter-gmail"
	name := previewHeader(m.Payload.Headers, "Subject")
	if name == "" {
		name = "Gmail"
	}
	for len(name) > 220 {
		_, size := utf8.DecodeLastRuneInString(name)
		name = name[:len(name)-size]
	}
	name += ".txt"
	started := time.Now()
	cfg := document.DefaultConfig()
	cfg.MaxBytes = MaxFileBytes
	cfg.OCR = ""
	cfg.MaxOutput = 8 << 20
	encoded, err := processDriveDocument(ctx, cfg, document.Request{Name: name, MediaType: "text/plain", Bytes: data, SHA256: digest(data), OCR: "never", ReceivedAt: started}, identity, started)
	if err != nil {
		return nil, Error("processing-failed")
	}
	var record map[string]any
	decoder := json.NewDecoder(strings.NewReader(string(encoded)))
	decoder.UseNumber()
	if decoder.Decode(&record) != nil {
		return nil, Error("processing-failed")
	}
	record["document"].(map[string]any)["version"] = m.HistoryID
	record["original"] = map[string]any{"retention": "inline", "encoding": "base64", "bytes": base64.StdEncoding.EncodeToString(data)}
	record["provenance"].(map[string]any)["source"] = map[string]any{"kind": "gmail", "messageId": m.ID, "threadId": m.ThreadID, "version": m.HistoryID, "format": "text-export-v1"}
	checked, err := canon.EncodeJSON(record)
	if err != nil || attachment.Check(checked) != nil {
		return nil, Error("processing-failed")
	}
	endpoint, _ := url.Parse(p.api + "/messages/" + req.MessageID)
	statement, _ := canon.EncodeJSON(map[string]any{"method": "GET", "path": endpoint.Path, "query": map[string]string{"format": "full"}})
	acquisition := map[string]any{"adapter": identity, "endpoint": endpoint.String(), "statement": string(statement), "snapshot": m.HistoryID, "peerIdentity": nil, "schema": nil, "upstreamToken": nil, "observedAt": started.UTC().Format("2006-01-02T15:04:05Z")}
	out, err := canon.EncodeJSON(map[string]any{"acquisition": acquisition, "result": record})
	if err != nil {
		return nil, Error("processing-failed")
	}
	if len(out) > MaxOutputBytes {
		return nil, ErrLimit
	}
	return out, nil
}

// Bound JSON structure before allocating recursive MIME objects. The byte cap
// separately bounds large body strings; the part walker enforces a tighter MIME cap.
func mailJSONBounded(raw []byte) bool {
	d := json.NewDecoder(strings.NewReader(string(raw)))
	depth, count := 0, 0
	for {
		token, err := d.Token()
		if err == io.EOF {
			return depth == 0
		}
		if err != nil {
			return false
		}
		count++
		if count > 12000 {
			return false
		}
		if delimiter, ok := token.(json.Delim); ok {
			switch delimiter {
			case '{', '[':
				depth++
			case '}', ']':
				depth--
			}
		}
		if depth > 64 {
			return false
		}
	}
}
