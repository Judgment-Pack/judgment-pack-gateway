package render

import (
	"bytes"
	"compress/flate"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"hash/crc32"
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
// and those bytes are the archive the module's writer writes, of seven parts
// that, read out of it, hold no more than the bound the record states for
// the file. It says nothing of whether the file is a correct rendering of any
// content, nor of what the parts hold.
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
	// Each bound is one the adapter can be configured with: positive, and
	// no more than its ceiling. A record that states a bound past its
	// ceiling is one no adapter wrote.
	for _, bound := range []struct {
		member  string
		ceiling int64
	}{
		{"maxRequestBytes", maxRequestCeiling},
		{"maxBlocks", maxBlocksCeiling},
		{"maxFileBytes", maxFileCeiling},
		{"maxOutputBytes", maxOutputCeiling},
		{"timeoutMs", timeoutCeiling.Milliseconds()},
	} {
		if n, ok := integerOf(bounds[bound.member]); !ok || n < 1 || n > bound.ceiling {
			return fmt.Errorf("rendering.bounds.%s is not a positive integer of at most %d", bound.member, bound.ceiling)
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

// localHeaderLength is the length of the header an entry of a ZIP archive
// begins with, before its name.
const localHeaderLength = 30

// partsWithin holds a Word file to being the archive this module's writer
// writes, and to the bound on what its parts hold.
//
// The seven parts are taken out of the file from where the writer puts them:
// one after another from the first byte, each a header, its name and its
// data. The archive of those parts is then written again by the writer's own
// code and compared with the file. A file that is that archive, byte for
// byte, holds nothing the writer does not write: no other entry, no comment,
// no byte before, between or after, and no header that says other than the
// directory does. So no byte of the file belongs to two parts, and what is
// read of the file to check it is the file.
//
// The sizes the parts state come to no more than the bound, and each part,
// inflated, holds what it states under the checksum it states, and its data
// holds that and nothing after it. No more is asked of a part's inflater than
// the part states and one byte; what the inflater holds inside itself beyond
// that is its own, and is of a fixed size.
//
// It says what the archive is. It does not read the parts as XML, and says
// nothing of what they hold.
func partsWithin(file []byte, most int64) error {
	notTheWriters := errors.New("file.bytes is not an archive of the seven parts as the adapter writes one")
	parts := make([]packed, 0, len(partNames))
	var stated int64
	at := 0
	for _, name := range partNames {
		data := at + localHeaderLength + len(name)
		if data > len(file) {
			return notTheWriters
		}
		header := file[at:data]
		long := func(i int) uint32 {
			return uint32(header[i]) | uint32(header[i+1])<<8 | uint32(header[i+2])<<16 | uint32(header[i+3])<<24
		}
		p := packed{name: name, sum: long(14), unpacked: long(22)}
		// The compressed size is the archive's own 32 bits, held to the
		// file's length before it is added to anything.
		compressed := int64(long(18))
		if compressed > int64(len(file)-data) {
			return notTheWriters
		}
		at = data + int(compressed)
		p.data = file[data:at]
		parts = append(parts, p)
		stated += int64(p.unpacked)
	}
	// Seven sizes of 32 bits each do not pass what 64 bits count. The bound
	// is held before the archive is written again: it is at most the
	// ceiling of the bound on a file, far below the size at which an
	// archive states a part in another way.
	if stated > most {
		return errors.New("the parts of the file hold more than rendering.bounds.maxFileBytes")
	}
	again, err := archiveOf(parts)
	if err != nil || !bytes.Equal(again, file) {
		return notTheWriters
	}
	for _, p := range parts {
		data := bytes.NewReader(p.data)
		part := flate.NewReader(data)
		held, sum, err := readNoMoreThan(part, int64(p.unpacked)+1)
		part.Close()
		if err != nil || held != int64(p.unpacked) || sum != p.sum || data.Len() != 0 {
			return errors.New("a part of the file does not hold what the archive states of it")
		}
	}
	return nil
}

// readNoMoreThan reads r to its end, or until it has been given most bytes,
// whichever comes first, and returns how many it was given and their
// checksum. It asks r for no byte past most: a part that would inflate to far
// more than it states is read as far as what it states and one byte, which is
// enough to know that it holds more.
func readNoMoreThan(r io.Reader, most int64) (int64, uint32, error) {
	sum := crc32.NewIEEE()
	held, err := io.Copy(sum, io.LimitReader(r, most))
	return held, sum.Sum32(), err
}

func isNull(raw json.RawMessage) bool {
	return string(bytes.TrimSpace(raw)) == "null"
}
