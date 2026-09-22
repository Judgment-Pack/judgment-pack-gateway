package connections

import (
	"adapters/attachment"
	"encoding/json"
	"unicode"
	"unicode/utf8"
)

const ControlLineBytes = 64 << 10
const ResourcePageBytes = 48 << 10
const ResourcePageItems = 50

// Public scope metadata never carries credentials or a signed download URL.
type ResourceScope struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}
type ResourceItem struct {
	ID                string `json:"id"`
	Title             string `json:"title"`
	URL               string `json:"url"`
	Description       string `json:"description,omitempty"`
	SizeBytes         *int64 `json:"sizeBytes,omitempty"`
	UnavailableReason string `json:"unavailableReason,omitempty"`
}
type ResourcePage struct {
	SelectionContext string         `json:"selectionContext"`
	Items            []ResourceItem `json:"items"`
	More             bool           `json:"more"`
	NextPageToken    string         `json:"nextPageToken,omitempty"`
}

// ValidateResourcePage bounds the common source-search result for resource-v1.
// Adapters own cursor custody, query/resource binding and the actual read policy.
// More is true only with a usable cursor; an empty page can still continue.
func ValidateResourcePage(page ResourcePage) error {
	if !resourceText(page.SelectionContext, 256, false) || page.Items == nil || len(page.Items) > ResourcePageItems || page.More != (page.NextPageToken != "") || page.NextPageToken != "" && !resourceText(page.NextPageToken, 4096, false) {
		return ErrRequest
	}
	seen := map[string]bool{}
	for _, item := range page.Items {
		if !resourceText(item.ID, 4096, false) || seen[item.ID] || !resourceText(item.Title, 1024, false) || !resourceText(item.Description, 2048, true) || item.SizeBytes != nil && (*item.SizeBytes < 0 || *item.SizeBytes > 9007199254740991) {
			return ErrRequest
		}
		seen[item.ID] = true
		source := attachment.Source{Provider: "resource", ResourceID: item.ID, URL: item.URL, Version: digest(nil), Format: "retained-file-v1"}
		if !attachment.ValidResourceSource(source) {
			return ErrRequest
		}
		switch item.UnavailableReason {
		case "", "archived", "permission-required", "not-downloadable", "unsupported-file", "file-too-large", "source-unavailable":
		default:
			return ErrRequest
		}
	}
	raw, err := json.Marshal(page)
	if err != nil || len(raw) > ResourcePageBytes {
		return Error("response-too-large")
	}
	return nil
}
func resourceText(s string, max int, empty bool) bool {
	if !utf8.ValidString(s) || len(s) > max || !empty && s == "" {
		return false
	}
	for _, r := range s {
		if unicode.IsControl(r) {
			return false
		}
	}
	return true
}
