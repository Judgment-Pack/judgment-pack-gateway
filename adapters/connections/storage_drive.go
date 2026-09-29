package connections

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"mime/multipart"
	"net/http"
	"net/textproto"
	"net/url"
	"strconv"
	"strings"
)

const driveStorageFields = "id,name,mimeType,version,size,trashed,capabilities(canDownload,canEdit,canTrash,canAddChildren)"

type driveStorageMeta struct {
	ID           string `json:"id"`
	Name         string `json:"name"`
	MediaType    string `json:"mimeType"`
	Version      string `json:"version"`
	Size         string `json:"size"`
	Trashed      bool   `json:"trashed"`
	Capabilities struct {
		Download bool `json:"canDownload"`
		Edit     bool `json:"canEdit"`
		Trash    bool `json:"canTrash"`
		Add      bool `json:"canAddChildren"`
	} `json:"capabilities"`
}

func (m driveStorageMeta) file() (StorageFile, error) {
	if !identifier.MatchString(m.ID) || !resourceText(m.Name, 250, false) || !resourceText(m.Version, 64, false) || m.Trashed || len(m.MediaType) > 120 || !storageMedia.MatchString(m.MediaType) {
		return StorageFile{}, ErrUnsupported
	}
	size := int64(0)
	if m.Size != "" {
		var e error
		size, e = strconv.ParseInt(m.Size, 10, 64)
		if e != nil || size < 0 {
			return StorageFile{}, ErrProvider
		}
	}
	kind := "file"
	if m.MediaType == "application/vnd.google-apps.folder" {
		kind = "folder"
	}
	return StorageFile{ID: m.ID, Name: m.Name, Kind: kind, Size: size, Revision: m.Version, MediaType: m.MediaType, Editable: kind == "file" && m.Capabilities.Edit && size <= MaxFileBytes && !strings.HasPrefix(m.MediaType, "application/vnd.google-apps."), Deletable: kind == "file" && m.Capabilities.Trash}, nil
}
func (b *Broker) driveStorageList(ctx context.Context, q StorageQuery, token string) (StoragePage, error) {
	out := StoragePage{Items: []StorageFile{}, Scope: "account-files", SearchMode: "provider-index"}
	query := "trashed = false"
	if q.Folder != "" {
		if !identifier.MatchString(q.Folder) {
			return out, ErrRequest
		}
		query += " and '" + q.Folder + "' in parents"
	}
	if q.Query != "" {
		value := strings.NewReplacer("\\", "\\\\", "'", "\\'").Replace(q.Query)
		query += " and fullText contains '" + value + "'"
	}
	values := url.Values{"q": {query}, "spaces": {"drive"}, "pageSize": {"24"}, "fields": {"nextPageToken,incompleteSearch,files(" + driveStorageFields + ")"}, "supportsAllDrives": {"true"}, "includeItemsFromAllDrives": {"true"}}
	// Drive refuses an order asked of a search by words, and gives what it
	// finds by relevance. A listing without words asks for Drive's order
	// "folder,name".
	if q.Query == "" {
		values.Set("orderBy", "folder,name")
	}
	if b.storageBrowse.upstream != "" {
		values.Set("pageToken", b.storageBrowse.upstream)
	}
	raw, _, e := b.provider.request(ctx, "GET", b.provider.api+"/files?"+values.Encode(), token, nil, 128<<10)
	if e != nil {
		return out, e
	}
	var result struct {
		Files      []driveStorageMeta `json:"files"`
		Next       string             `json:"nextPageToken"`
		Incomplete bool               `json:"incompleteSearch"`
	}
	if json.Unmarshal(raw, &result) != nil || len(result.Files) > StoragePageItems || !resourceText(result.Next, 4096, true) {
		return out, ErrProvider
	}
	for _, m := range result.Files {
		f, e := m.file()
		if e != nil {
			return out, e
		}
		out.Items = append(out.Items, f)
	}
	if result.Next != "" && result.Next == b.storageBrowse.upstream {
		return out, ErrProvider
	}
	b.storageBrowse.upstream = result.Next
	out.Truncated = result.Incomplete
	return b.finishStoragePage(out, result.Next != "")
}
func (b *Broker) driveStorageMeta(ctx context.Context, id, token string) (driveStorageMeta, string, error) {
	var m driveStorageMeta
	if !identifier.MatchString(id) {
		return m, "", ErrRequest
	}
	raw, res, e := b.provider.request(ctx, "GET", b.provider.api+"/files/"+id+"?supportsAllDrives=true&fields="+url.QueryEscape(driveStorageFields), token, nil, 64<<10)
	if e != nil {
		return m, "", e
	}
	if json.Unmarshal(raw, &m) != nil || m.ID != id {
		return m, "", ErrProvider
	}
	if _, e = m.file(); e != nil {
		return m, "", e
	}
	return m, res.Header.Get("ETag"), nil
}
func (b *Broker) driveStorageInspect(ctx context.Context, id, token string, read bool) (StorageFile, string, []byte, error) {
	m, etag, e := b.driveStorageMeta(ctx, id, token)
	if e != nil {
		return StorageFile{}, "", nil, e
	}
	f, e := m.file()
	if e != nil {
		return f, "", nil, e
	}
	if !read {
		return f, etag, nil, nil
	}
	if f.Kind != "file" || strings.HasPrefix(f.MediaType, "application/vnd.google-apps.") || !m.Capabilities.Download {
		return f, "", nil, ErrUnsupported
	}
	if f.Size > MaxFileBytes {
		return f, "", nil, ErrLimit
	}
	raw, _, e := b.provider.request(ctx, "GET", b.provider.api+"/files/"+id+"?alt=media&supportsAllDrives=true", token, nil, MaxFileBytes)
	if e != nil {
		return f, "", nil, e
	}
	after, _, e := b.driveStorageMeta(ctx, id, token)
	if e != nil {
		return f, "", nil, e
	}
	if after.Version != m.Version || after.Name != m.Name || int64(len(raw)) != f.Size {
		return f, "", nil, ErrChanged
	}
	return f, etag, raw, nil
}
func (b *Broker) driveStorageApply(ctx context.Context, intent storageIntent, token string, data []byte) (string, error) {
	q := intent.Change
	if q.Action != "create" {
		f, etag, _, e := b.driveStorageInspect(ctx, q.ID, token, false)
		if e != nil {
			return "", e
		}
		if f.Revision != q.Revision || f.Name != q.Name || etag != intent.ETag {
			return "", ErrChanged
		}
		if q.Action == "delete" && !f.Deletable || q.Action == "update" && !f.Editable {
			return "", ErrUnsupported
		}
	}
	method, path, contentType, body := "PATCH", b.provider.api+"/files/"+q.ID+"?supportsAllDrives=true&fields=id", "application/json", []byte(`{"trashed":true}`)
	if q.Action != "delete" {
		var buffer bytes.Buffer
		writer := multipart.NewWriter(&buffer)
		part, e := writer.CreatePart(textproto.MIMEHeader{"Content-Type": {"application/json; charset=UTF-8"}})
		if e != nil {
			return "", ErrProvider
		}
		metadata := map[string]any{"name": q.Name, "mimeType": q.MediaType}
		if q.Action == "create" {
			// A conversion is asked for by the media type of what is to be
			// made, and carries no ID: Drive takes none for a file it converts.
			if q.ConvertTo == storageGoogleDocument {
				metadata["mimeType"] = storageGoogleDocumentMedia
			} else {
				metadata["id"] = q.ID
			}
			if q.Folder != "" {
				metadata["parents"] = []string{q.Folder}
			}
		}
		if json.NewEncoder(part).Encode(metadata) != nil {
			return "", ErrProvider
		}
		part, e = writer.CreatePart(textproto.MIMEHeader{"Content-Type": {q.MediaType}})
		if e != nil {
			return "", ErrProvider
		}
		if _, e = part.Write(data); e != nil {
			return "", e
		}
		if writer.Close() != nil {
			return "", ErrProvider
		}
		contentType = "multipart/related; boundary=" + writer.Boundary()
		body = buffer.Bytes()
		base := strings.TrimSuffix(b.provider.api, "/drive/v3")
		path = base + "/upload/drive/v3/files"
		if q.Action == "create" {
			method = "POST"
		} else {
			path += "/" + q.ID
		}
		path += "?uploadType=multipart&supportsAllDrives=true&fields=id"
		if q.ConvertTo != "" {
			path += ",mimeType"
		}
	}
	req, e := http.NewRequestWithContext(ctx, method, path, bytes.NewReader(body))
	if e != nil {
		return "", ErrRequest
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", contentType)
	if q.Action != "create" {
		if !validS3ETag(intent.ETag) {
			return "", ErrUnsupported
		}
		req.Header.Set("If-Match", intent.ETag)
	}
	res, e := b.provider.client.Do(req)
	if e != nil {
		return "", Error("operation-uncertain")
	}
	defer res.Body.Close()
	raw, e := io.ReadAll(io.LimitReader(res.Body, 64<<10+1))
	if e != nil || len(raw) > 64<<10 {
		return "", Error("operation-uncertain")
	}
	if res.StatusCode == 412 || res.StatusCode == 409 {
		return "", ErrChanged
	}
	if res.StatusCode == 403 {
		return "", Error("permission-required")
	}
	if q.ConvertTo != "" {
		// Drive answered in full, and the answer does not say that a file
		// was made or names none that is taken. Its status is kept for the
		// person.
		id, media := conversionAnswer(raw, token)
		if res.StatusCode != 200 && res.StatusCode != 201 || !identifier.MatchString(id) {
			return "", storageAnswered(res.StatusCode)
		}
		// The ID is Drive's to give. What was made is held to be a Google
		// Doc by Drive's own word, and where it is not, the file that was
		// made is named so that a person can find it.
		if media != storageGoogleDocumentMedia {
			return id, errConversionUnconfirmed
		}
		return id, nil
	}
	// An ordinary change's answer is read as it always was, and held to the
	// ID that was reserved for it.
	if res.StatusCode != 200 && res.StatusCode != 201 {
		return "", Error("operation-uncertain")
	}
	var reply struct {
		ID string `json:"id"`
	}
	if json.Unmarshal(raw, &reply) != nil || reply.ID != q.ID {
		return "", Error("operation-uncertain")
	}
	return reply.ID, nil
}

// conversionAnswer reads the ID and the media type out of Drive's answer to a
// conversion. Each is read on its own and by its exact name, and is empty
// where the answer does not give it once and as a string. An answer from which
// no ID is taken gives no media type either.
//
// No ID is taken from an answer that is not one JSON object, from one in which
// the access token can be read, or where the ID is itself a part of the token.
// The ID of a conversion is whatever the answer says it is, and this keeps an
// answer that repeats the token from putting it in a plan. It is no defence
// against a provider that means to pass the token on: an ID is 200 characters
// of the provider's choosing.
func conversionAnswer(raw []byte, token string) (id, media string) {
	var members map[string]json.RawMessage
	if json.Unmarshal(raw, &members) != nil {
		return "", ""
	}
	// The token is looked for in the answer as it is written, and in every
	// string of it as the string reads once it is decoded, names included.
	// A number is left as it is written, so that none ends the reading.
	if bytes.Contains(raw, []byte(token)) {
		return "", ""
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	for {
		t, err := d.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return "", ""
		}
		if text, is := t.(string); is && strings.Contains(text, token) {
			return "", ""
		}
	}
	// The answer is read again for how often it gives each member, since a
	// member given twice is given by neither.
	given := map[string]int{}
	d = json.NewDecoder(bytes.NewReader(raw))
	d.Token()
	for d.More() {
		name, _ := d.Token()
		var value json.RawMessage
		d.Decode(&value)
		given[name.(string)]++
	}
	if given["id"] == 1 {
		json.Unmarshal(members["id"], &id)
	}
	if strings.Contains(token, id) {
		return "", ""
	}
	if given["mimeType"] == 1 {
		json.Unmarshal(members["mimeType"], &media)
	}
	return id, media
}
