package connections

import (
	"adapters/mcphttp"
	"context"
	"encoding/json"
	"net/url"
	"regexp"
	"strings"
)

var notionID = regexp.MustCompile(`^(?:[a-f0-9]{32}|[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})$`)
var notionTools = []string{"notion-get-tool-access", "notion-search", "notion-ai-search", "notion-fetch"}

type SourceSelection struct {
	ResourceID string `json:"resourceId"`
	Grant      string `json:"grant"`
}
type SourcePreview struct {
	ID          string `json:"id"`
	Title       string `json:"title"`
	URL         string `json:"url"`
	Description string `json:"description,omitempty"`
}
type SourceSearch struct {
	SelectionContext string          `json:"selectionContext"`
	Items            []SourcePreview `json:"items"`
	More             bool            `json:"more"`
}

func (p provider) notionClient(ctx context.Context, s *Store, client Client, c credential, epoch string) (*mcphttp.Client, string, error) {
	token, err := p.access(ctx, s, client, c, epoch)
	if err != nil {
		return nil, "", err
	}
	m, err := mcphttp.New(p.api, token, notionTools, p.client)
	if err != nil {
		return nil, "", ErrProvider
	}
	if err = m.Initialize(ctx); err != nil {
		return nil, "", notionError(err)
	}
	return m, token, nil
}
func notionText(raw []byte) (string, error) {
	var r struct {
		Error   bool `json:"isError"`
		Content []struct {
			Type string `json:"type"`
			Text string `json:"text"`
		} `json:"content"`
	}
	if json.Unmarshal(raw, &r) != nil || r.Error || len(r.Content) == 0 || len(r.Content) > 64 {
		return "", ErrProvider
	}
	var out strings.Builder
	for _, b := range r.Content {
		if b.Type != "text" {
			continue
		}
		if out.Len()+len(b.Text)+1 > MaxFileBytes {
			return "", ErrLimit
		}
		if out.Len() > 0 {
			out.WriteByte('\n')
		}
		out.WriteString(b.Text)
	}
	if out.Len() == 0 {
		return "", ErrUnsupported
	}
	return out.String(), nil
}
func (b *Broker) connectedSnapshot() (Client, credential, string, error) {
	var client Client
	var c credential
	var epoch string
	err := b.store.locked(func(v *state) error {
		if v.Disabled {
			return ErrPolicy
		}
		if v.Connection == nil {
			return ErrConnect
		}
		client, c, epoch = v.Client, *v.Connection, v.Epoch
		return nil
	})
	return client, c, epoch, err
}
func (s *Store) checkConnection(c credential, epoch string) error {
	return s.locked(func(v *state) error {
		if v.Disabled {
			return ErrPolicy
		}
		if v.Epoch != epoch || v.Connection == nil || v.Connection.ID != c.ID {
			return ErrCanceled
		}
		return nil
	})
}
func (b *Broker) selectSources(raw []byte, c credential, epoch string, valid func(string) bool) (any, error) {
	var q struct {
		IDs     []string `json:"resourceIds"`
		Context string   `json:"selectionContext"`
	}
	if decode(raw, &q) != nil || len(q.IDs) == 0 || len(q.IDs) > 4 || q.Context != epoch {
		return nil, ErrRequest
	}
	seen := map[string]bool{}
	for _, id := range q.IDs {
		if !valid(id) || seen[id] {
			return nil, ErrRequest
		}
		seen[id] = true
	}
	var selections []SourceSelection
	err := b.store.locked(func(v *state) error {
		if v.Disabled {
			return ErrPolicy
		}
		if v.Epoch != epoch || v.Connection == nil || v.Connection.ID != c.ID {
			return ErrCanceled
		}
		grants, err := b.store.makeGrants(c.ID, q.IDs)
		if err != nil {
			return err
		}
		for _, g := range grants {
			selections = append(selections, SourceSelection{g.FileID, g.Grant})
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return selections, nil
}
func (b *Broker) notionOperation(ctx context.Context, method string, raw []byte) (any, error) {
	client, c, epoch, err := b.connectedSnapshot()
	if err != nil {
		return nil, err
	}
	if method == "select" {
		return b.selectSources(raw, c, epoch, notionID.MatchString)
	}
	var q struct {
		Query string `json:"query"`
	}
	if decode(raw, &q) != nil || strings.TrimSpace(q.Query) == "" || len(q.Query) > 1024 || strings.ContainsAny(q.Query, "\x00\r\n") {
		return nil, ErrRequest
	}
	m, token, err := b.provider.notionClient(ctx, b.store, client, c, epoch)
	if err != nil {
		return nil, err
	}
	defer m.Close(ctx)
	tools, err := m.Tools(ctx)
	if err != nil {
		return nil, notionError(err)
	}
	access, err := m.CallTool(ctx, "notion-get-tool-access", map[string]any{})
	if err != nil {
		return nil, notionError(err)
	}
	text, err := notionText(access)
	if err != nil {
		return nil, err
	}
	var rights struct {
		Tools map[string]struct {
			Status string `json:"status"`
		} `json:"current_tool_access"`
	}
	if json.Unmarshal([]byte(text), &rights) != nil {
		return nil, ErrProvider
	}
	tool := "notion-search"
	status := rights.Tools["search"].Status
	if _, ok := tools["notion-ai-search"]; ok && (rights.Tools["ai_search"].Status == "available" || status == "") {
		tool = "notion-ai-search"
		status = rights.Tools["ai_search"].Status
	}
	if _, ok := tools[tool]; !ok {
		return nil, ErrUnsupported
	}
	if status != "available" && status != "available_with_limit" && !(tool == "notion-ai-search" && (status == "upgrade_required" || status == "plan_required")) {
		return nil, ErrUnsupported
	}
	result, err := m.CallTool(ctx, tool, map[string]any{"query": q.Query, "query_type": "internal"})
	if err != nil {
		return nil, notionError(err)
	}
	text, err = notionText(result)
	if err != nil {
		return nil, err
	}
	var matches struct {
		Results []struct {
			ID    string `json:"id"`
			Title string `json:"title"`
			URL   string `json:"url"`
		} `json:"results"`
		More bool `json:"has_more"`
	}
	if json.Unmarshal([]byte(text), &matches) != nil || len(matches.Results) > 100 {
		return nil, ErrProvider
	}
	out := SourceSearch{SelectionContext: epoch, Items: []SourcePreview{}, More: matches.More}
	seen := map[string]bool{}
	for _, item := range matches.Results {
		// Never fetch connected-app URLs, even when Notion includes them in search.
		if strings.Contains(item.Title+item.URL, token) {
			return nil, ErrProvider
		}
		if !notionID.MatchString(item.ID) || !notionPageURL(item.URL, item.ID) || seen[item.ID] {
			continue
		}
		if len(out.Items) >= 20 {
			out.More = true
			break
		}
		seen[item.ID] = true
		title := strings.Join(strings.Fields(item.Title), " ")
		runes := []rune(title)
		if len(runes) > 128 {
			title = string(runes[:128])
		}
		if title == "" {
			title = item.ID
		}
		out.Items = append(out.Items, SourcePreview{ID: item.ID, Title: title, URL: item.URL})
	}
	if err = b.store.checkConnection(c, epoch); err != nil {
		return nil, err
	}
	return out, nil
}
func notionPageURL(raw, id string) bool {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.User != nil || u.Port() != "" || len(raw) > 2048 {
		return false
	}
	host := u.Hostname()
	if host != "notion.so" && host != "www.notion.so" && host != "notion.com" && host != "www.notion.com" {
		return false
	}
	return strings.HasSuffix(strings.ReplaceAll(u.Path, "-", ""), strings.ReplaceAll(id, "-", ""))
}
func ReadNotion(ctx context.Context, s *Store, raw []byte) ([]byte, error) {
	return notion().readNotion(ctx, s, raw)
}
func (p provider) readNotion(ctx context.Context, s *Store, raw []byte) ([]byte, error) {
	var q SourceSelection
	if decode(raw, &q) != nil || !opaque.MatchString(q.Grant) || !notionID.MatchString(q.ResourceID) {
		return nil, ErrRequest
	}
	client, c, epoch, err := s.consumeGrant(q.Grant, q.ResourceID)
	if err != nil {
		return nil, err
	}
	m, token, err := p.notionClient(ctx, s, client, c, epoch)
	if err != nil {
		return nil, err
	}
	defer m.Close(ctx)
	result, err := m.CallTool(ctx, "notion-fetch", map[string]any{"id": q.ResourceID})
	if err != nil {
		return nil, notionError(err)
	}
	text, err := notionText(result)
	if err != nil {
		return nil, err
	}
	title := "Notion page"
	pageURL := "https://www.notion.so/" + strings.ReplaceAll(q.ResourceID, "-", "")
	// Preserve the readable text exactly; incomplete upstream snapshots are refused.
	var page struct {
		Title     string `json:"title"`
		URL       string `json:"url"`
		Text      string `json:"text"`
		Truncated bool   `json:"truncated"`
	}
	if json.Unmarshal([]byte(text), &page) == nil {
		if page.Text != "" {
			text = page.Text
		}
		if page.Truncated {
			return nil, Error("source-incomplete")
		}
		if page.Title != "" {
			title = page.Title
		}
		if page.URL != "" && notionPageURL(page.URL, q.ResourceID) {
			pageURL = page.URL
		}
	}
	if strings.Contains(text+title+pageURL, token) {
		return nil, ErrProvider
	}
	out, err := sourceDocument(ctx, "notion", q.ResourceID, title, pageURL, []byte(text), map[string]any{"tool": "notion-fetch", "arguments": map[string]string{"id": q.ResourceID}}, p.api)
	if err != nil {
		return nil, err
	}
	if err = s.checkConnection(c, epoch); err != nil {
		return nil, err
	}
	return out, nil
}
