package render

import (
	"archive/zip"
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"

	"adapters/attachment"
	"adapters/internal/canon"
)

// Record is the version 1 render record of docs/design/rendering.md: what
// was asked for, the file, how it was rendered, and the adapter's account of
// itself.
type Record struct {
	RenderVersion string         `json:"renderVersion"`
	Request       RequestSummary `json:"request"`
	File          File           `json:"file"`
	Rendering     Rendering      `json:"rendering"`
	Provenance    Provenance     `json:"provenance"`
}

// RequestSummary is what the request asked for. The content itself is not
// repeated: ContentDigest identifies it.
type RequestSummary struct {
	Format        string  `json:"format"`
	Title         string  `json:"title"`
	Language      *string `json:"language"`
	ContentDigest string  `json:"contentDigest"`
	Blocks        int64   `json:"blocks"`
	TextBytes     int64   `json:"textBytes"`
	Cites         *Cites  `json:"cites"`
}

// Cites is what the caller said the document reports. The adapter records it
// and checks nothing about it.
type Cites struct {
	Decision string `json:"decision"`
}

// File is the rendered file.
type File struct {
	MediaType string `json:"mediaType"`
	Size      int64  `json:"size"`
	SHA256    string `json:"sha256"`
	Encoding  string `json:"encoding"`
	Bytes     string `json:"bytes"`
}

// Rendering is how the file was made.
type Rendering struct {
	Status     string   `json:"status"`
	Renderer   Renderer `json:"renderer"`
	Bounds     Bounds   `json:"bounds"`
	DurationMs int64    `json:"durationMs"`
}

// Renderer is what made the file: this module's own writer.
type Renderer struct {
	Kind string `json:"kind"`
	Name string `json:"name"`
}

// Bounds are the bounds that applied.
type Bounds struct {
	MaxRequestBytes int64 `json:"maxRequestBytes"`
	MaxBlocks       int64 `json:"maxBlocks"`
	MaxFileBytes    int64 `json:"maxFileBytes"`
	MaxOutputBytes  int64 `json:"maxOutputBytes"`
	TimeoutMs       int64 `json:"timeoutMs"`
}

// Provenance is the adapter's account of itself and of when it read the
// request.
type Provenance struct {
	Adapter    attachment.Identity `json:"adapter"`
	ObservedAt string              `json:"observedAt"`
}

const (
	// recordNesting is how deep a record nests: the record, a member of it,
	// and a member of that.
	recordNesting = 3

	// StatusComplete is the one status of a version 1 record: a rendering
	// is whole, or it is refused and there is no record.
	StatusComplete = "complete"
	// RendererModule is the kind of a renderer that is this module's code.
	RendererModule = "module"
)

// Check is the reference check of a version 1 render record: that it has
// the record's members and no others, that each is of its form, and that the
// file is what the record says of it -- the base64 is the one standard padded
// encoding of bytes of the stated size whose SHA-256 is the stated digest,
// and those bytes are an archive whose parts, read out of it, hold no more
// than the bound the record states for the file. It says nothing of whether
// the file is a correct rendering of any content, nor of what the parts are.
func Check(raw []byte) error {
	if !nestedWithin(raw, recordNesting) {
		return errors.New("the record nests deeper than a record does")
	}
	if _, err := canon.Canonicalize(raw, canon.RefuseNumbers); err != nil {
		return errors.New("the record is not JSON of the canonical domain")
	}
	top, err := exactMembers(raw, map[string]bool{"renderVersion": true, "request": true, "file": true, "rendering": true, "provenance": true})
	if err != nil {
		return fmt.Errorf("record: %v", err)
	}
	var version string
	if !stringInto(top["renderVersion"], &version) || version != RecordVersion {
		return fmt.Errorf("renderVersion is not %q", RecordVersion)
	}

	request, err := exactMembers(top["request"], map[string]bool{"format": true, "title": true, "language": true, "contentDigest": true, "blocks": true, "textBytes": true, "cites": true})
	if err != nil {
		return fmt.Errorf("request: %v", err)
	}
	var format, title, contentDigest string
	if !stringInto(request["format"], &format) || format != FormatDocx {
		return fmt.Errorf("request.format is not %q", FormatDocx)
	}
	if !stringInto(request["title"], &title) || !validTitle(title) {
		return errors.New("request.title is not a title")
	}
	if !isNull(request["language"]) {
		var language string
		if !stringInto(request["language"], &language) || len(language) > maxLanguageSize || !languageForm.MatchString(language) {
			return errors.New("request.language is neither null nor a language tag")
		}
	}
	if !stringInto(request["contentDigest"], &contentDigest) || !attachment.ValidDigest(contentDigest) {
		return errors.New("request.contentDigest is not a digest")
	}
	if blocks, ok := integerOf(request["blocks"]); !ok || blocks < 1 {
		return errors.New("request.blocks is not a positive integer")
	}
	if _, ok := integerOf(request["textBytes"]); !ok {
		return errors.New("request.textBytes is not a non-negative integer")
	}
	if !isNull(request["cites"]) {
		cites, err := exactMembers(request["cites"], map[string]bool{"decision": true})
		if err != nil {
			return fmt.Errorf("request.cites: %v", err)
		}
		var decision string
		if !stringInto(cites["decision"], &decision) || !attachment.ValidDigest(decision) {
			return errors.New("request.cites.decision is not a digest")
		}
	}

	file, err := exactMembers(top["file"], map[string]bool{"mediaType": true, "size": true, "sha256": true, "encoding": true, "bytes": true})
	if err != nil {
		return fmt.Errorf("file: %v", err)
	}
	var mediaType, digest, encoding, encoded string
	if !stringInto(file["mediaType"], &mediaType) || mediaType != MediaTypeDocx {
		return errors.New("file.mediaType is not the media type of the format")
	}
	size, ok := integerOf(file["size"])
	if !ok || size < 1 {
		return errors.New("file.size is not a positive integer")
	}
	if !stringInto(file["sha256"], &digest) || !attachment.ValidDigest(digest) {
		return errors.New("file.sha256 is not a digest")
	}
	if !stringInto(file["encoding"], &encoding) || encoding != "base64" {
		return errors.New("file.encoding is not \"base64\"")
	}
	if !stringInto(file["bytes"], &encoded) || !attachment.CanonicalBase64(encoded) {
		return errors.New("file.bytes is not the one standard padded base64 encoding of its bytes")
	}
	data, _ := base64.StdEncoding.DecodeString(encoded)
	if int64(len(data)) != size {
		return errors.New("file.size is not the size of the file")
	}
	if digestOf(data) != digest {
		return errors.New("file.sha256 is not the digest of the file")
	}

	rendering, err := exactMembers(top["rendering"], map[string]bool{"status": true, "renderer": true, "bounds": true, "durationMs": true})
	if err != nil {
		return fmt.Errorf("rendering: %v", err)
	}
	var status string
	if !stringInto(rendering["status"], &status) || status != StatusComplete {
		return fmt.Errorf("rendering.status is not %q", StatusComplete)
	}
	renderer, err := exactMembers(rendering["renderer"], map[string]bool{"kind": true, "name": true})
	if err != nil {
		return fmt.Errorf("rendering.renderer: %v", err)
	}
	var kind, name string
	if !stringInto(renderer["kind"], &kind) || kind != RendererModule {
		return fmt.Errorf("rendering.renderer.kind is not %q", RendererModule)
	}
	if !stringInto(renderer["name"], &name) || name != RendererDocx {
		return errors.New("rendering.renderer.name is not the renderer of the format")
	}
	bounds, err := exactMembers(rendering["bounds"], map[string]bool{"maxRequestBytes": true, "maxBlocks": true, "maxFileBytes": true, "maxOutputBytes": true, "timeoutMs": true})
	if err != nil {
		return fmt.Errorf("rendering.bounds: %v", err)
	}
	for _, member := range []string{"maxRequestBytes", "maxBlocks", "maxFileBytes", "maxOutputBytes", "timeoutMs"} {
		if n, ok := integerOf(bounds[member]); !ok || n < 1 {
			return fmt.Errorf("rendering.bounds.%s is not a positive integer", member)
		}
	}
	maxFile, _ := integerOf(bounds["maxFileBytes"])
	if size > maxFile {
		return errors.New("file.size is past rendering.bounds.maxFileBytes")
	}
	if err := partsWithin(data, maxFile); err != nil {
		return err
	}
	if _, ok := integerOf(rendering["durationMs"]); !ok {
		return errors.New("rendering.durationMs is not a non-negative integer")
	}

	provenance, err := exactMembers(top["provenance"], map[string]bool{"adapter": true, "observedAt": true})
	if err != nil {
		return fmt.Errorf("provenance: %v", err)
	}
	adapter, err := exactMembers(provenance["adapter"], map[string]bool{"name": true, "version": true, "digest": true})
	if err != nil {
		return fmt.Errorf("provenance.adapter: %v", err)
	}
	var adapterIs, adapterVersion, adapterDigest, observedAt string
	if !stringInto(adapter["name"], &adapterIs) || adapterIs != adapterName {
		return fmt.Errorf("provenance.adapter.name is not %q", adapterName)
	}
	if !stringInto(adapter["version"], &adapterVersion) || adapterVersion == "" {
		return errors.New("provenance.adapter.version is not a non-empty string")
	}
	if !stringInto(adapter["digest"], &adapterDigest) || !attachment.ValidDigest(adapterDigest) {
		return errors.New("provenance.adapter.digest is not a digest")
	}
	if !stringInto(provenance["observedAt"], &observedAt) {
		return errors.New("provenance.observedAt is not a string")
	}
	if at, err := time.Parse(stampLayout, observedAt); err != nil || at.Format(stampLayout) != observedAt {
		return errors.New("provenance.observedAt is not a UTC instant to the second")
	}
	return nil
}

// partsWithin holds a Word file to the bound on what its parts hold: it is
// a ZIP archive, the sizes its entries state come to no more than the bound,
// and each entry read out of the archive holds what it states. No more is
// read of an entry than it states and one byte, so that what is read of the
// whole file is within the bound and one byte an entry.
func partsWithin(file []byte, most int64) error {
	archive, err := zip.NewReader(bytes.NewReader(file), int64(len(file)))
	if err != nil {
		return errors.New("file.bytes is not a ZIP archive")
	}
	var stated uint64
	for _, entry := range archive.File {
		if entry.UncompressedSize64 > uint64(most) {
			return errors.New("the parts of the file hold more than rendering.bounds.maxFileBytes")
		}
		if stated += entry.UncompressedSize64; stated > uint64(most) {
			return errors.New("the parts of the file hold more than rendering.bounds.maxFileBytes")
		}
	}
	for _, entry := range archive.File {
		part, err := entry.Open()
		if err != nil {
			return errors.New("a part of the file cannot be read out of it")
		}
		held, err := io.Copy(io.Discard, io.LimitReader(part, int64(entry.UncompressedSize64)+1))
		part.Close()
		// The archive's reader fails a part that holds more or less than
		// it states, or whose checksum is not its own. The length is
		// compared here as well, so that the bound does not rest on that.
		if err != nil || uint64(held) != entry.UncompressedSize64 {
			return errors.New("a part of the file does not hold what the archive states of it")
		}
	}
	return nil
}

func isNull(raw json.RawMessage) bool {
	return string(bytes.TrimSpace(raw)) == "null"
}
