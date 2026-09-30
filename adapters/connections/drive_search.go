package connections

import (
	"context"
	"encoding/json"
	"net/url"
	"strings"
)

// driveReadable is the media types adapter-drive reads. A search offers a
// file of no other, so that what is offered can be read once it is chosen.
var driveReadable = []string{"application/pdf", "text/plain", "text/markdown", "text/csv", "application/json", "application/vnd.google-apps.document", "application/vnd.google-apps.spreadsheet", "application/vnd.google-apps.presentation"}

const driveSearchItems = 20

// driveOperation is search and select for Drive, under the contract Notion's
// have. A search is of the connected Drive (ADR-0010): with words, what
// Drive finds for them, in the order Drive gives them; without, what was
// changed last. It offers what adapter-drive would take by what Drive says of
// a file: its kind, its name, its size, and that it may be downloaded. A
// selection is of what a search gave or of any other file's ID: a grant says
// that the host asked to read a file, and nothing of who chose it.
func (b *Broker) driveOperation(ctx context.Context, method string, raw []byte) (any, error) {
	client, c, epoch, err := b.connectedSnapshot()
	if err != nil {
		return nil, err
	}
	if method == "select" {
		return b.selectSources(raw, c, epoch, identifier.MatchString)
	}
	var q struct {
		Query string `json:"query"`
	}
	if decode(raw, &q) != nil || len(q.Query) > 1024 || strings.ContainsAny(q.Query, "\x00\r\n") {
		return nil, ErrRequest
	}
	token, err := b.provider.access(ctx, b.store, client, c, epoch)
	if err != nil {
		return nil, err
	}
	kinds := make([]string, len(driveReadable))
	for i, media := range driveReadable {
		kinds[i] = "mimeType = '" + media + "'"
	}
	query := "trashed = false and (" + strings.Join(kinds, " or ") + ")"
	values := url.Values{"spaces": {"drive"}, "pageSize": {"20"}, "fields": {"nextPageToken,incompleteSearch,files(id,name,mimeType,size,capabilities(canDownload))"}, "supportsAllDrives": {"true"}, "includeItemsFromAllDrives": {"true"}}
	// Drive refuses an order asked of a search by words.
	if words := strings.TrimSpace(q.Query); words != "" {
		query += " and fullText contains '" + strings.NewReplacer("\\", "\\\\", "'", "\\'").Replace(words) + "'"
	} else {
		values.Set("orderBy", "modifiedTime desc")
	}
	values.Set("q", query)
	data, _, err := b.provider.request(ctx, "GET", b.provider.api+"/files?"+values.Encode(), token, nil, 128<<10)
	if err != nil {
		return nil, err
	}
	var found struct {
		Files []struct {
			ID           string `json:"id"`
			Name         string `json:"name"`
			MediaType    string `json:"mimeType"`
			Size         string `json:"size"`
			Capabilities struct {
				CanDownload bool `json:"canDownload"`
			} `json:"capabilities"`
		} `json:"files"`
		Next       string `json:"nextPageToken"`
		Incomplete bool   `json:"incompleteSearch"`
	}
	if json.Unmarshal(data, &found) != nil || len(found.Files) > driveSearchItems || len(found.Next) > 4096 {
		return nil, ErrProvider
	}
	out := SourceSearch{SelectionContext: epoch, Items: []SourcePreview{}, More: found.Next != "" || found.Incomplete}
	seen := map[string]bool{}
	for _, file := range found.Files {
		// An answer that holds the token as it is written is refused where
		// it is read. This refuses one that holds it escaped.
		if strings.Contains(file.ID+file.Name+file.MediaType, token) {
			return nil, ErrProvider
		}
		if !identifier.MatchString(file.ID) || seen[file.ID] || !driveOffers(file.MediaType) || !readableName(file.Name) || !readableSize(file.MediaType, file.Size) || !file.Capabilities.CanDownload {
			continue
		}
		seen[file.ID] = true
		title := strings.Join(strings.Fields(strings.Map(shown, file.Name)), " ")
		if title == "" {
			title = file.ID
		}
		if runes := []rune(title); len(runes) > 128 {
			title = string(runes[:128])
		}
		// The address is made of the ID. None that Drive gives is taken.
		out.Items = append(out.Items, SourcePreview{ID: file.ID, Title: title, URL: "https://drive.google.com/open?id=" + file.ID, Description: file.MediaType})
	}
	if err = b.store.checkConnection(c, epoch); err != nil {
		return nil, err
	}
	return out, nil
}

func driveOffers(media string) bool {
	for _, readable := range driveReadable {
		if media == readable {
			return true
		}
	}
	return false
}

// shown takes out of a name, for showing it, the characters Unicode gives
// the property Bidi_Control: the marks that set or turn the direction of the
// text about them. A name with a control character is offered by no search.
func shown(r rune) rune {
	if r == 0x061c || r == 0x200e || r == 0x200f || r >= 0x202a && r <= 0x202e || r >= 0x2066 && r <= 0x2069 {
		return ' '
	}
	return r
}
