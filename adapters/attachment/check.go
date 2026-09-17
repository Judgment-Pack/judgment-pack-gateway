package attachment

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"adapters/internal/canon"
)

// Problems are the rules a record breaks, one each: the rule's identifier,
// a colon, and a sentence.
type Problems []string

func (p Problems) Error() string { return strings.Join(p, "; ") }

// Check holds a record's bytes to the rules of docs/design/attachments.md,
// version 1, and returns every rule it breaks, or nil. It is the reference
// check of the note: where the two disagree, the note is right and Check
// is a defect. It checks what the record alone can show; that a record is
// what the adapter derived from a document takes the document.
func Check(raw []byte) error {
	if _, err := canon.Canonicalize(raw, canon.RefuseNumbers); err != nil {
		return Problems{"canonical-domain: the record is not in the canonical domain: " + err.Error()}
	}
	c := &checker{}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return Problems{"decode: the record does not decode: " + err.Error()}
	}
	c.shape(v)
	if len(c.problems) > 0 {
		return c.problems
	}
	var rec Record
	if err := json.Unmarshal(raw, &rec); err != nil {
		return Problems{"decode: the record does not decode into its types: " + err.Error()}
	}
	c.values(&rec)
	c.pages(&rec)
	c.status(&rec)
	c.codes(&rec)
	c.declaration(&rec)
	c.encryption(&rec)
	c.source(&rec)
	c.ocr(&rec)
	if len(c.problems) > 0 {
		return c.problems
	}
	return nil
}

type checker struct{ problems Problems }

// fail records that rule, by its identifier, is broken.
func (c *checker) fail(rule, format string, args ...any) {
	c.problems = append(c.problems, rule+": "+fmt.Sprintf(format, args...))
}

// --- the member set and the types ---------------------------------------

// object holds v to an object whose members are exactly those named, each
// of the type its spec names: string, integer, boolean, object or array,
// with "|null" where null is allowed. It returns the object, or nil.
func (c *checker) object(path string, v any, members map[string]string) map[string]any {
	obj, ok := v.(map[string]any)
	if !ok {
		c.fail("not-object", "%s is not an object", path)
		return nil
	}
	for name := range obj {
		if _, known := members[name]; !known {
			c.fail("member-unknown", "%s has a member version 1 does not name: %q", path, name)
		}
	}
	names := make([]string, 0, len(members))
	for name := range members {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		spec := members[name]
		value, present := obj[name]
		if !present {
			c.fail("member-absent", "%s.%s is absent", path, name)
			continue
		}
		kind, nullable := strings.CutSuffix(spec, "|null")
		if value == nil {
			if !nullable {
				c.fail("member-null", "%s.%s is null", path, name)
			}
			continue
		}
		if !isKind(value, kind) {
			c.fail("member-type", "%s.%s is not a %s", path, name, kind)
		}
	}
	return obj
}

func isKind(v any, kind string) bool {
	switch kind {
	case "string":
		_, ok := v.(string)
		return ok
	case "integer":
		n, ok := v.(json.Number)
		if !ok {
			return false
		}
		_, err := n.Int64()
		return err == nil
	case "boolean":
		_, ok := v.(bool)
		return ok
	case "object":
		_, ok := v.(map[string]any)
		return ok
	case "array":
		_, ok := v.([]any)
		return ok
	}
	return false
}

func (c *checker) shape(v any) {
	rec := c.object("record", v, map[string]string{
		"attachmentVersion": "string", "document": "object", "original": "object",
		"content": "object", "processing": "object", "provenance": "object",
	})
	if rec == nil {
		return
	}
	if doc := c.object("document", rec["document"], map[string]string{
		"id": "string", "name": "string", "mediaType": "string", "detectedMediaType": "string|null",
		"size": "integer", "version": "string|null", "encryption": "object|null",
	}); doc != nil && doc["encryption"] != nil {
		c.object("document.encryption", doc["encryption"], map[string]string{
			"handler": "string|null", "revision": "integer|null", "opened": "boolean",
		})
	}
	c.object("original", rec["original"], map[string]string{
		"retention": "string", "encoding": "string|null", "bytes": "string|null",
	})
	if content := c.object("content", rec["content"], map[string]string{
		"kind": "string", "extraction": "string", "pageCount": "integer", "truncated": "boolean",
		"chars": "integer", "pages": "array",
	}); content != nil {
		items, _ := content["pages"].([]any)
		for i, item := range items {
			c.object(fmt.Sprintf("content.pages[%d]", i), item, map[string]string{
				"number": "integer", "status": "string", "extraction": "string", "text": "string",
				"chars": "integer", "unmapped": "integer",
			})
		}
	}
	if processing := c.object("processing", rec["processing"], map[string]string{
		"status": "string", "errors": "array", "bounds": "object", "durationMs": "integer",
	}); processing != nil {
		items, _ := processing["errors"].([]any)
		for i, item := range items {
			c.object(fmt.Sprintf("processing.errors[%d]", i), item, map[string]string{
				"code": "string", "message": "string", "page": "integer|null",
			})
		}
		if processing["bounds"] != nil {
			c.object("processing.bounds", processing["bounds"], map[string]string{
				"maxBytes": "integer", "maxPages": "integer", "maxTextBytes": "integer",
				"maxInflateBytes": "integer", "maxOcrOutputBytes": "integer", "timeoutMs": "integer",
			})
		}
	}
	if prov := c.object("provenance", rec["provenance"], map[string]string{
		"adapter": "object", "source": "object", "observedAt": "string", "processor": "string|null", "ocr": "object|null",
	}); prov != nil {
		c.object("provenance.adapter", prov["adapter"], map[string]string{"name": "string", "version": "string", "digest": "string"})
		c.object("provenance.source", prov["source"], map[string]string{"kind": "string"})
		if prov["ocr"] != nil {
			if ocr := c.object("provenance.ocr", prov["ocr"], map[string]string{"program": "string", "digest": "string", "pages": "array"}); ocr != nil {
				items, _ := ocr["pages"].([]any)
				for i, item := range items {
					if !isKind(item, "integer") {
						c.fail("member-type", "provenance.ocr.pages[%d] is not an integer", i)
					}
				}
			}
		}
	}
}

// --- each value on its own ------------------------------------------------

var (
	digestForm    = regexp.MustCompile(`\Asha256:[0-9a-f]{64}\z`)
	mediaTypeForm = regexp.MustCompile(`\A[a-z0-9][a-z0-9!#$&^_.+-]{0,126}/[a-z0-9][a-z0-9!#$&^_.+-]{0,126}\z`)
	stampForm     = regexp.MustCompile(`\A[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z\z`)
)

func oneOf(value string, allowed ...string) bool {
	for _, a := range allowed {
		if value == a {
			return true
		}
	}
	return false
}

// ValidName is the rule for document.name: 1 to 255 bytes of UTF-8 and no
// character from U+0000 to U+001F or U+007F.
func ValidName(name string) bool {
	if len(name) < 1 || len(name) > 255 || !utf8.ValidString(name) {
		return false
	}
	for _, r := range name {
		if r < 0x20 || r == 0x7f {
			return false
		}
	}
	return true
}

// ValidMediaType is the syntax of document.mediaType.
func ValidMediaType(mediaType string) bool { return mediaTypeForm.MatchString(mediaType) }

// ValidDigest is the digest form.
func ValidDigest(digest string) bool { return digestForm.MatchString(digest) }

// CanonicalBase64 reports whether s is standard padded base64 that decodes,
// with every unused bit zero: the one encoding of its bytes.
func CanonicalBase64(s string) bool {
	data, err := base64.StdEncoding.Strict().DecodeString(s)
	return err == nil && len(data) > 0 && base64.StdEncoding.EncodeToString(data) == s
}

func (c *checker) values(rec *Record) {
	if rec.AttachmentVersion != Version {
		c.fail("version", "attachmentVersion is %q, not %q", rec.AttachmentVersion, Version)
	}
	d := rec.Document
	if !ValidDigest(d.ID) {
		c.fail("id-digest", "document.id is not a digest")
	}
	if !ValidName(d.Name) {
		c.fail("name", "document.name is not 1 to 255 bytes of UTF-8 without a control character")
	}
	if !ValidMediaType(d.MediaType) {
		c.fail("media-type", "document.mediaType is not a lowercase type/subtype without parameters")
	}
	if d.DetectedMediaType != nil && !oneOf(*d.DetectedMediaType, MediaPDF, MediaText) {
		c.fail("detected-media-type", "document.detectedMediaType is %q", *d.DetectedMediaType)
	}
	if d.Size < 0 {
		c.fail("size-negative", "document.size is negative")
	}
	o := rec.Original
	if !oneOf(o.Retention, RetentionCaller, RetentionInline) {
		c.fail("retention", "original.retention is %q", o.Retention)
	}
	if o.Encoding != nil && *o.Encoding != "base64" {
		c.fail("encoding", "original.encoding is %q", *o.Encoding)
	}
	if o.Bytes != nil && !CanonicalBase64(*o.Bytes) {
		c.fail("bytes-base64", "original.bytes is not canonical standard base64 of at least one byte")
	}
	ct := rec.Content
	if ct.Kind != "text" {
		c.fail("content-kind", "content.kind is %q", ct.Kind)
	}
	if !oneOf(ct.Extraction, ExtractionTextLayer, ExtractionOCR, ExtractionMixed, ExtractionVerbatim, ExtractionNone) {
		c.fail("content-extraction", "content.extraction is %q", ct.Extraction)
	}
	if ct.PageCount < 0 || ct.Chars < 0 {
		c.fail("counts-negative", "content.pageCount or content.chars is negative")
	}
	for i, p := range ct.Pages {
		if p.Number < 1 || p.Chars < 0 || p.Unmapped < 0 {
			c.fail("page-counts", "content.pages[%d] has a number below 1 or a negative count", i)
		}
		if !oneOf(p.Status, PageOK, PageNoText, PageNeedsOCR, PageFailed) {
			c.fail("page-status", "content.pages[%d].status is %q", i, p.Status)
		}
		if !oneOf(p.Extraction, ExtractionTextLayer, ExtractionOCR, ExtractionVerbatim, ExtractionNone) {
			c.fail("page-extraction", "content.pages[%d].extraction is %q", i, p.Extraction)
		}
		if !IsNormalized(p.Text) {
			c.fail("text-normalised", "content.pages[%d].text is not a text normalisation can yield", i)
		}
	}
	pr := rec.Processing
	if !oneOf(pr.Status, StatusComplete, StatusPartial, StatusFailed) {
		c.fail("status", "processing.status is %q", pr.Status)
	}
	for i, e := range pr.Errors {
		if _, known := codeClass[e.Code]; !known {
			c.fail("code-known", "processing.errors[%d].code %q is not a version 1 code", i, e.Code)
		}
		if len(e.Message) > 512 {
			c.fail("message-length", "processing.errors[%d].message is longer than 512 bytes", i)
		}
		if e.Page != nil && *e.Page < 1 {
			c.fail("error-page", "processing.errors[%d].page is below 1", i)
		}
	}
	b := pr.Bounds
	if b.MaxBytes < 1 || b.MaxPages < 1 || b.MaxTextBytes < 1 || b.MaxInflateBytes < 1 || b.MaxOcrOutputBytes < 1 || b.TimeoutMs < 1 {
		c.fail("bounds-positive", "processing.bounds holds a bound below 1")
	}
	if pr.DurationMs < 0 {
		c.fail("duration-negative", "processing.durationMs is negative")
	}
	pv := rec.Provenance
	if pv.Adapter.Name == "" || !ValidDigest(pv.Adapter.Digest) {
		c.fail("adapter-identity", "provenance.adapter has an empty name or a digest that is not one")
	}
	if pv.Source.Kind != SourceInline {
		c.fail("source-kind", "provenance.source.kind is %q, which version 1 does not name", pv.Source.Kind)
	}
	if !stampForm.MatchString(pv.ObservedAt) {
		c.fail("observed-at-form", "provenance.observedAt is not YYYY-MM-DDThh:mm:ssZ")
	} else if _, err := time.Parse("2006-01-02T15:04:05Z", pv.ObservedAt); err != nil {
		c.fail("observed-at-time", "provenance.observedAt is not a time: %v", err)
	}
	if pv.Processor != nil && *pv.Processor == "" {
		c.fail("processor-empty", "provenance.processor is empty")
	}
	if pv.OCR != nil {
		if pv.OCR.Program == "" || !ValidDigest(pv.OCR.Digest) {
			c.fail("ocr-identity", "provenance.ocr has an empty program or a digest that is not one")
		}
	}
}

// --- pages, and what is derived from them -----------------------------------

func (c *checker) pages(rec *Record) {
	ct := rec.Content
	var chars, textBytes int64
	methods := map[string]bool{}
	var last int64
	for i, p := range ct.Pages {
		if p.Number <= last {
			c.fail("page-order", "content.pages[%d].number %d does not ascend", i, p.Number)
		}
		last = p.Number
		if p.Chars != int64(utf8.RuneCountInString(p.Text)) {
			c.fail("page-chars", "content.pages[%d].chars is %d and its text has %d scalar values", i, p.Chars, utf8.RuneCountInString(p.Text))
		}
		chars += p.Chars
		textBytes += int64(len(p.Text))
		switch p.Status {
		case PageOK:
			if p.Text == "" || p.Extraction == ExtractionNone {
				c.fail("page-ok", "content.pages[%d] is ok with empty text or extraction none", i)
			}
		case PageNoText:
			if p.Text != "" || p.Extraction == ExtractionNone {
				c.fail("page-no-text", "content.pages[%d] is no-text with text or extraction none", i)
			}
		case PageNeedsOCR, PageFailed:
			if p.Text != "" || p.Extraction != ExtractionNone {
				c.fail("page-without-text", "content.pages[%d] is %s with text or an extraction", i, p.Status)
			}
		}
		if p.Extraction != ExtractionTextLayer && p.Unmapped != 0 {
			c.fail("unmapped-method", "content.pages[%d] counts unmapped glyphs on a page that is not text-layer", i)
		}
		if p.Unmapped > int64(strings.Count(p.Text, "\xef\xbf\xbd")) {
			c.fail("unmapped-count", "content.pages[%d].unmapped exceeds the U+FFFD in its text", i)
		}
		if p.Extraction != ExtractionNone {
			methods[p.Extraction] = true
		}
	}
	if int64(len(ct.Pages)) > ct.PageCount {
		c.fail("pages-past-count", "content lists %d pages and pageCount is %d", len(ct.Pages), ct.PageCount)
	}
	if last > ct.PageCount {
		c.fail("page-past-count", "content lists page %d past pageCount %d", last, ct.PageCount)
	}
	if ct.PageCount > rec.Processing.Bounds.MaxPages {
		c.fail("count-past-max-pages", "content.pageCount %d is past maxPages %d", ct.PageCount, rec.Processing.Bounds.MaxPages)
	}
	if ct.Chars != chars {
		c.fail("content-chars", "content.chars is %d and the pages sum to %d", ct.Chars, chars)
	}
	if textBytes > rec.Processing.Bounds.MaxTextBytes {
		c.fail("text-budget", "the listed text is %d bytes, past maxTextBytes %d", textBytes, rec.Processing.Bounds.MaxTextBytes)
	}
	want := ExtractionNone
	switch {
	case methods[ExtractionVerbatim] && len(methods) == 1:
		want = ExtractionVerbatim
	case methods[ExtractionTextLayer] && methods[ExtractionOCR] && len(methods) == 2:
		want = ExtractionMixed
	case methods[ExtractionTextLayer] && len(methods) == 1:
		want = ExtractionTextLayer
	case methods[ExtractionOCR] && len(methods) == 1:
		want = ExtractionOCR
	case len(methods) > 0:
		want = ""
	}
	if want == "" {
		c.fail("extraction-mix", "the pages mix verbatim with another extraction")
	} else if ct.Extraction != want {
		c.fail("extraction-derived", "content.extraction is %q and the pages derive %q", ct.Extraction, want)
	}
	if int64(len(ct.Pages)) < ct.PageCount && !ct.Truncated {
		c.fail("truncated-listing", "fewer pages are listed than counted and the record is not truncated")
	}
}

func (c *checker) status(rec *Record) {
	want := StatusPartial
	switch {
	case len(rec.Content.Pages) == 0:
		want = StatusFailed
		if len(rec.Processing.Errors) == 0 {
			c.fail("failed-without-error", "no page is listed and no error says why")
		}
	case len(rec.Processing.Errors) == 0 && !rec.Content.Truncated:
		want = StatusComplete
	}
	if rec.Processing.Status != want {
		c.fail("status-derived", "processing.status is %q and the pages and errors derive %q", rec.Processing.Status, want)
	}
}

// --- the codes --------------------------------------------------------------

// A code's class: which statuses a record carrying it can have, and whether
// its page is required, forbidden, or named by its own rule.
type class struct {
	statuses string // "failed", "partial", or "either"
	page     string // "none", "failed-page" (a listed failed page), or "text" (text-over-bound's rule)
	once     bool
}

var codeClass = map[string]class{
	CodeMediaTypeUnsupported: {"failed", "none", true},
	CodeMediaTypeMismatch:    {"failed", "none", true},
	CodeDocumentOverBound:    {"failed", "none", true},
	CodeDocumentEmpty:        {"failed", "none", true},
	CodePDFMalformed:         {"failed", "none", true},
	CodePDFEncrypted:         {"failed", "none", true},
	CodePDFUnsupported:       {"partial", "failed-page", false},
	CodePDFPageFailed:        {"partial", "failed-page", false},
	CodeStreamOverBound:      {"partial", "failed-page", false},
	CodePDFPagesOverBound:    {"either", "none", true},
	CodeTextOverBound:        {"either", "text", false},
	CodeTimeout:              {"either", "none", true},
	CodeOCRNotRun:            {"partial", "none", true},
	CodeOCRFailed:            {"partial", "none", true},
	CodeOCRIncomplete:        {"partial", "none", true},
	CodeOCRTimeout:           {"partial", "none", true},
}

func (c *checker) codes(rec *Record) {
	pages := rec.Content.Pages
	byNumber := map[int64]Page{}
	needsOCR := false
	ocrPages := false
	for _, p := range pages {
		byNumber[p.Number] = p
		if p.Status == PageNeedsOCR {
			needsOCR = true
		}
		if p.Extraction == ExtractionOCR {
			ocrPages = true
		}
	}
	seen := map[string]int{}
	failedPages := map[int64]bool{}
	budgetOnNeedsOCR := false
	for i, e := range rec.Processing.Errors {
		cl, known := codeClass[e.Code]
		if !known {
			continue
		}
		seen[e.Code]++
		if cl.once && seen[e.Code] == 2 {
			c.fail("code-once", "processing.errors carries %s more than once", e.Code)
		}
		switch cl.statuses {
		case "failed":
			if rec.Processing.Status != StatusFailed {
				c.fail("code-failed-only", "processing.errors[%d] is %s, which only a failed record carries", i, e.Code)
			}
		case "partial":
			if rec.Processing.Status != StatusPartial {
				c.fail("code-partial-only", "processing.errors[%d] is %s, which only a partial record carries", i, e.Code)
			}
		}
		switch cl.page {
		case "none":
			if e.Page != nil {
				c.fail("code-page-forbidden", "processing.errors[%d] is %s with a page", i, e.Code)
			}
		case "failed-page":
			if e.Page == nil {
				c.fail("code-page-required", "processing.errors[%d] is %s without a page", i, e.Code)
			} else if p, ok := byNumber[*e.Page]; !ok || p.Status != PageFailed {
				c.fail("code-failed-page", "processing.errors[%d] is %s and page %d is not a listed failed page", i, e.Code, *e.Page)
			} else {
				failedPages[*e.Page] = true
			}
		case "text":
			switch {
			case e.Page == nil:
				c.fail("code-page-required", "processing.errors[%d] is %s without a page", i, e.Code)
			case byNumber[*e.Page].Status == PageNeedsOCR:
				budgetOnNeedsOCR = true
			case *e.Page == int64(len(pages))+1 && *e.Page <= rec.Content.PageCount && lastListed(pages) == int64(len(pages)):
				// Step 3 or 5: the first page not listed, every page before it listed.
			default:
				c.fail("text-over-bound-page", "processing.errors[%d] is %s and page %d is neither a listed page that needs OCR nor the first page not listed", i, e.Code, *e.Page)
			}
		}
	}
	for _, p := range pages {
		if p.Status == PageFailed && !failedPages[p.Number] {
			c.fail("failed-page-unnamed", "page %d is failed and no error names it", p.Number)
		}
	}
	if seen[CodePDFPagesOverBound] > 0 && (!rec.Content.Truncated || rec.Content.PageCount != rec.Processing.Bounds.MaxPages) {
		c.fail("pages-over-bound", "pdf-pages-over-bound with a record that is not truncated at maxPages")
	}
	if seen[CodeTimeout] > 0 && seen[CodeOCRTimeout] > 0 {
		c.fail("deadline-once", "both timeout and ocr-timeout: one deadline records one code")
	}
	outcomes := seen[CodeOCRNotRun] + seen[CodeOCRFailed] + seen[CodeOCRIncomplete] + seen[CodeOCRTimeout]
	if outcomes > 1 {
		c.fail("ocr-outcome-once", "more than one of ocr-not-run, ocr-failed, ocr-incomplete and ocr-timeout: one document has one OCR outcome")
	}
	if outcomes > 0 && !needsOCR {
		c.fail("ocr-outcome-without-page", "an OCR outcome is reported and no listed page needs OCR")
	}
	if (seen[CodeOCRNotRun] > 0 || seen[CodeOCRFailed] > 0 || seen[CodeOCRTimeout] > 0) && ocrPages {
		c.fail("ocr-applied-nothing", "a page took an OCR answer in a record whose OCR program applied nothing")
	}
	if needsOCR && outcomes == 0 && seen[CodeTimeout] == 0 && !budgetOnNeedsOCR {
		c.fail("needs-ocr-unexplained", "a listed page needs OCR and no error says why")
	}
}

func lastListed(pages []Page) int64 {
	if len(pages) == 0 {
		return 0
	}
	return pages[len(pages)-1].Number
}

// --- the declaration, the encryption, the source, the OCR provenance --------

func (c *checker) declaration(rec *Record) {
	d := rec.Document
	codes := map[string]bool{}
	for _, e := range rec.Processing.Errors {
		codes[e.Code] = true
	}
	noExtractor := codes[CodeMediaTypeUnsupported] || codes[CodeMediaTypeMismatch] || codes[CodeDocumentOverBound] || codes[CodeDocumentEmpty]
	if noExtractor != (rec.Provenance.Processor == nil) {
		c.fail("processor-null", "provenance.processor is null exactly when no extractor ran, and this record says otherwise")
	}
	processor, processed := ProcessedMediaTypes[d.MediaType]
	if processed == codes[CodeMediaTypeUnsupported] {
		c.fail("media-type-unsupported", "document.mediaType %q and media-type-unsupported disagree", d.MediaType)
	}
	if codes[CodeMediaTypeMismatch] || !processed {
		if d.DetectedMediaType != nil {
			c.fail("detected-unprocessed", "document.detectedMediaType is set on a record whose declaration was not processed")
		}
	}
	if rec.Provenance.Processor == nil {
		if len(rec.Content.Pages) != 0 || rec.Content.PageCount != 0 || rec.Content.Truncated {
			c.fail("no-extractor-pages", "a record with no extractor counts or lists pages")
		}
		return
	}
	if *rec.Provenance.Processor != processor {
		c.fail("processor-type", "provenance.processor %q does not read %q", *rec.Provenance.Processor, d.MediaType)
	}
	want := MediaPDF
	if processor == ProcessorText {
		want = MediaText
	}
	if d.DetectedMediaType == nil || *d.DetectedMediaType != want {
		c.fail("detected-read", "document.detectedMediaType is not %q for a %s document that was read", want, d.MediaType)
	}
	for i, p := range rec.Content.Pages {
		if processor == ProcessorText && (p.Extraction == ExtractionTextLayer || p.Extraction == ExtractionOCR || p.Number != 1) {
			c.fail("text-document-page", "content.pages[%d] is not the one verbatim page of a text document", i)
		}
		if processor == ProcessorPDF && p.Extraction == ExtractionVerbatim {
			c.fail("pdf-verbatim", "content.pages[%d] is verbatim in a PDF", i)
		}
	}
	if processor == ProcessorText && rec.Content.PageCount != 1 {
		c.fail("text-document-count", "a text document counts %d pages", rec.Content.PageCount)
	}
}

func (c *checker) encryption(rec *Record) {
	enc := rec.Document.Encryption
	encrypted := false
	for _, e := range rec.Processing.Errors {
		if e.Code == CodePDFEncrypted {
			encrypted = true
		}
	}
	if enc == nil {
		if encrypted {
			c.fail("encryption-undeclared", "pdf-encrypted on a record that declares no encryption")
		}
		return
	}
	if rec.Provenance.Processor == nil || *rec.Provenance.Processor != ProcessorPDF {
		c.fail("encryption-not-pdf", "document.encryption on a record that is not a read PDF")
	}
	if enc.Opened == encrypted {
		c.fail("encryption-opened", "document.encryption.opened is %v and pdf-encrypted is %v: a document not opened is exactly one reported encrypted", enc.Opened, encrypted)
	}
	if enc.Opened && (enc.Handler == nil || *enc.Handler != HandlerStandard || enc.Revision == nil || *enc.Revision < MinRevision || *enc.Revision > MaxRevision) {
		c.fail("encryption-handler", "document.encryption is opened with a handler or revision version 1 does not open")
	}
}

func (c *checker) source(rec *Record) {
	if rec.Provenance.Source.Kind != SourceInline {
		return
	}
	o := rec.Original
	if o.Retention != RetentionCaller || o.Encoding != nil || o.Bytes != nil {
		c.fail("inline-original", "an inline document's original is not the caller's, without bytes")
	}
	if rec.Document.Version != nil {
		c.fail("inline-version", "an inline document has a version")
	}
	if rec.Document.Size < 1 {
		c.fail("inline-empty", "an inline document is empty, which is refused at the request")
	}
	if rec.Document.Size > rec.Processing.Bounds.MaxBytes {
		c.fail("inline-over-bound", "an inline document is past maxBytes, which is refused at the request")
	}
	for _, e := range rec.Processing.Errors {
		if e.Code == CodeDocumentOverBound || e.Code == CodeDocumentEmpty {
			c.fail("inline-refused-code", "an inline document reports %s, which is refused at the request", e.Code)
		}
	}
}

func (c *checker) ocr(rec *Record) {
	var want []int64
	for _, p := range rec.Content.Pages {
		if p.Extraction == ExtractionOCR {
			want = append(want, p.Number)
		}
	}
	got := rec.Provenance.OCR
	switch {
	case got == nil && len(want) > 0:
		c.fail("ocr-provenance-null", "pages took OCR answers and provenance.ocr is null")
	case got != nil && len(want) == 0:
		c.fail("ocr-provenance-set", "provenance.ocr is set and no page took an OCR answer")
	case got != nil && fmt.Sprint(got.Pages) != fmt.Sprint(want):
		c.fail("ocr-provenance-pages", "provenance.ocr.pages is %v and the OCR pages are %v", got.Pages, want)
	}
}
