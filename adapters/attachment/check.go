package attachment

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
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
// is a defect. Beside each value and each page, it holds the record to the
// note's processing steps: the step that ended the run, and what each step
// on the way leaves in the record. It checks what the record alone can
// show; that a record is what the adapter derived from a document takes the
// document.
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
	c.errors(&rec)
	c.steps(&rec)
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
		sourceMembers := map[string]string{"kind": "string"}
		if source, ok := prov["source"].(map[string]any); ok && source["kind"] == SourceGoogleDrive {
			sourceMembers["fileId"] = "string"
			sourceMembers["version"] = "string"
			sourceMembers["mediaType"] = "string"
		}
		c.object("provenance.source", prov["source"], sourceMembers)
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

// MaxBytesCeiling is the largest maxBytes whose read bound,
// 4 x ceil(maxBytes / 3) + 65,536, is at most 2^53 - 1.
const MaxBytesCeiling = 6755399441006589

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
	// The read bound, 4 x ceil(maxBytes / 3) + 65,536, is a figure derived
	// from maxBytes, and stays a canonical integer only up to this maxBytes.
	if b.MaxBytes > MaxBytesCeiling {
		c.fail("bounds-derived", "processing.bounds.maxBytes %d derives a read bound past the canonical domain's integers", b.MaxBytes)
	}
	if pr.DurationMs < 0 {
		c.fail("duration-negative", "processing.durationMs is negative")
	}
	pv := rec.Provenance
	if pv.Adapter.Name == "" || !ValidDigest(pv.Adapter.Digest) {
		c.fail("adapter-identity", "provenance.adapter has an empty name or a digest that is not one")
	}
	if pv.Source.Kind != SourceInline && pv.Source.Kind != SourceGoogleDrive {
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
	for i, p := range ct.Pages {
		if p.Number != int64(i+1) {
			c.fail("page-contiguous", "content.pages[%d] is page %d: pages are listed from page 1 without a gap", i, p.Number)
		}
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
}

func (c *checker) status(rec *Record) {
	want := StatusPartial
	switch {
	case len(rec.Content.Pages) == 0:
		want = StatusFailed
	case len(rec.Processing.Errors) == 0 && !rec.Content.Truncated:
		want = StatusComplete
	}
	if rec.Processing.Status != want {
		c.fail("status-derived", "processing.status is %q and the pages and errors derive %q", rec.Processing.Status, want)
	}
}

// --- the errors, each on its own -------------------------------------------

// pageFailureCodes are the codes that name a failed page, one each.
var pageFailureCodes = map[string]bool{CodePDFPageFailed: true, CodePDFUnsupported: true, CodeStreamOverBound: true}

// declarationCodes are the codes of a record no extractor read.
var declarationCodes = map[string]bool{CodeMediaTypeUnsupported: true, CodeMediaTypeMismatch: true, CodeDocumentOverBound: true, CodeDocumentEmpty: true}

// ocrCodes are the codes of an OCR run's outcome.
var ocrCodes = map[string]bool{CodeOCRNotRun: true, CodeOCRFailed: true, CodeOCRIncomplete: true, CodeOCRTimeout: true}

// codeClass says, per code, whether its page is required or forbidden and
// whether a record carries it at most once.
var codeClass = map[string]struct{ page, once bool }{
	CodeMediaTypeUnsupported: {false, true},
	CodeMediaTypeMismatch:    {false, true},
	CodeDocumentOverBound:    {false, true},
	CodeDocumentEmpty:        {false, true},
	CodePDFMalformed:         {false, true},
	CodePDFEncrypted:         {false, true},
	CodePDFUnsupported:       {true, false},
	CodePDFPageFailed:        {true, false},
	CodeStreamOverBound:      {true, false},
	CodePDFPagesOverBound:    {false, true},
	CodeTextOverBound:        {true, false},
	CodeTimeout:              {false, true},
	CodeOCRNotRun:            {false, true},
	CodeOCRFailed:            {false, true},
	CodeOCRIncomplete:        {false, true},
	CodeOCRTimeout:           {false, true},
}

func (c *checker) errors(rec *Record) {
	seen := map[string]int{}
	for i, e := range rec.Processing.Errors {
		cl, known := codeClass[e.Code]
		if !known {
			continue
		}
		seen[e.Code]++
		if cl.once && seen[e.Code] == 2 {
			c.fail("code-once", "processing.errors carries %s more than once", e.Code)
		}
		if cl.page && e.Page == nil {
			c.fail("code-page-required", "processing.errors[%d] is %s without a page", i, e.Code)
		}
		if !cl.page && e.Page != nil {
			c.fail("code-page-forbidden", "processing.errors[%d] is %s with a page", i, e.Code)
		}
	}
}

// --- the steps ----------------------------------------------------------------

// steps holds the record to the step that ended the run: the declaration
// (step 2), a text document (step 3), or a PDF (steps 4 to 6).
func (c *checker) steps(rec *Record) {
	d := rec.Document
	processor, processed := ProcessedMediaTypes[d.MediaType]
	counts := map[string]int{}
	for _, e := range rec.Processing.Errors {
		counts[e.Code]++
	}
	if rec.Provenance.Processor == nil {
		c.declarationStep(rec, counts, processed)
		return
	}
	switch got := *rec.Provenance.Processor; {
	case got != ProcessorPDF && got != ProcessorText:
		c.fail("processor-type", "provenance.processor %q is not one version 1 names", got)
		return
	case !processed || got != processor:
		c.fail("processor-type", "provenance.processor %q does not read %q", got, d.MediaType)
	}
	want := MediaPDF
	if *rec.Provenance.Processor == ProcessorText {
		want = MediaText
	}
	if d.DetectedMediaType == nil || *d.DetectedMediaType != want {
		c.fail("detected-read", "document.detectedMediaType is not %q for a %s document that was read", want, d.MediaType)
	}
	if *rec.Provenance.Processor == ProcessorText {
		c.textStep(rec)
		return
	}
	c.pdfSteps(rec, counts)
}

// declarationStep is a record step 2 ended: one of the declaration's codes
// and nothing else.
func (c *checker) declarationStep(rec *Record, counts map[string]int, processed bool) {
	errs := rec.Processing.Errors
	if len(errs) != 1 || !declarationCodes[errs[0].Code] || len(rec.Content.Pages) != 0 || rec.Content.PageCount != 0 || rec.Content.Truncated {
		c.fail("declaration-outcome", "a record no extractor read carries exactly one of media-type-unsupported, media-type-mismatch, document-over-bound and document-empty, and no content")
	}
	if (counts[CodeMediaTypeUnsupported] > 0 && processed) || (counts[CodeMediaTypeMismatch] > 0 && !processed) {
		c.fail("media-type-unsupported", "document.mediaType %q and the declaration's code disagree", rec.Document.MediaType)
	}
	if rec.Document.DetectedMediaType != nil {
		c.fail("detected-unprocessed", "document.detectedMediaType is set on a record no extractor read")
	}
}

// textStep is step 3: the one verbatim page, or nothing listed under
// text-over-bound, and never more text than the document has bytes.
func (c *checker) textStep(rec *Record) {
	errs, pages := rec.Processing.Errors, rec.Content.Pages
	if rec.Content.PageCount != 1 {
		c.fail("text-document-count", "a text document counts %d pages", rec.Content.PageCount)
	}
	listed := len(pages) == 1 && len(errs) == 0 && !rec.Content.Truncated && pages[0].Extraction == ExtractionVerbatim && (pages[0].Status == PageOK || pages[0].Status == PageNoText)
	overBudget := len(pages) == 0 && len(errs) == 1 && errs[0].Code == CodeTextOverBound && errs[0].Page != nil && *errs[0].Page == 1 && rec.Content.Truncated
	if !listed && !overBudget {
		c.fail("text-document-outcome", "a text document is its one verbatim page, or no page under text-over-bound on page 1")
	}
	// Normalisation never lengthens valid UTF-8, so the text is at most the
	// document's size, and a document past the budget is longer than it.
	if listed && int64(len(pages[0].Text)) > rec.Document.Size {
		c.fail("text-document-size", "a text document of %d bytes lists %d bytes of text", rec.Document.Size, len(pages[0].Text))
	}
	// A U+FEFF that begins the text survived step 1 only behind something
	// steps 2 to 4 removed, so the document had at least one byte more.
	if listed && strings.HasPrefix(pages[0].Text, "\xef\xbb\xbf") && int64(len(pages[0].Text)) >= rec.Document.Size {
		c.fail("text-document-size", "a text document of %d bytes lists a text of %d bytes that begins with U+FEFF, which needs a removed byte before it", rec.Document.Size, len(pages[0].Text))
	}
	if overBudget && rec.Document.Size <= rec.Processing.Bounds.MaxTextBytes {
		c.fail("text-document-size", "a text document of %d bytes cannot be past maxTextBytes %d", rec.Document.Size, rec.Processing.Bounds.MaxTextBytes)
	}
}

// pdfSteps are steps 4 to 6.
func (c *checker) pdfSteps(rec *Record, counts map[string]int) {
	errs, pages := rec.Processing.Errors, rec.Content.Pages
	n, k := rec.Content.PageCount, int64(len(pages))
	// Step 2 let the PDF reader run only on bytes holding %PDF-.
	if rec.Document.Size < int64(len("%PDF-")) {
		c.fail("pdf-size", "a PDF the reader read is %d bytes, shorter than the %%PDF- header step 2 requires", rec.Document.Size)
	}
	// Step 4 ended at a defect: its one error, and nothing else.
	if counts[CodePDFMalformed]+counts[CodePDFEncrypted] > 0 {
		if len(errs) != 1 || k != 0 || n != 0 || rec.Content.Truncated {
			c.fail("walk-defect", "a walk that ended at a defect carries its one error and counts, lists and truncates nothing")
		}
		return
	}
	for _, e := range errs {
		if !pdfStepCode(e.Code) {
			c.fail("stray-error", "%s is not a code steps 4 to 6 record", e.Code)
		}
	}
	for i, p := range pages {
		if p.Extraction == ExtractionVerbatim {
			c.fail("pdf-verbatim", "content.pages[%d] is verbatim in a PDF", i)
		}
	}
	bound := counts[CodePDFPagesOverBound] > 0
	if bound && n != rec.Processing.Bounds.MaxPages {
		c.fail("pages-over-bound", "pdf-pages-over-bound with pageCount %d, not maxPages %d", n, rec.Processing.Bounds.MaxPages)
	}
	if n == 0 && !(len(errs) == 1 && counts[CodeTimeout] == 1) {
		c.fail("walk-empty", "a PDF with no page counted is a walk the deadline ended, under timeout alone")
	}
	if want := bound || k < n || n == 0; rec.Content.Truncated != want {
		c.fail("truncated", "content.truncated is %v and the walk and the listing derive %v", rec.Content.Truncated, want)
	}
	listed := map[int64]Page{}
	for _, p := range pages {
		listed[p.Number] = p
	}
	// Each failed page is named by exactly one failure, and each failure
	// names a failed page.
	named := map[int64]int{}
	for i, e := range errs {
		if !pageFailureCodes[e.Code] || e.Page == nil {
			continue
		}
		named[*e.Page]++
		if listed[*e.Page].Status != PageFailed {
			c.fail("failed-page-errors", "processing.errors[%d] is %s and page %d is not a listed failed page", i, e.Code, *e.Page)
		}
	}
	for _, p := range pages {
		if p.Status == PageFailed && named[p.Number] != 1 {
			c.fail("failed-page-errors", "failed page %d is named by %d failures, not one", p.Number, named[p.Number])
		}
	}
	// Step 5's stop: the first page not listed under text-over-bound, or the
	// deadline. A text-over-bound on a listed page is step 6's.
	stopBudget := false
	var ocrBudget []int64
	for i, e := range errs {
		if e.Code != CodeTextOverBound || e.Page == nil {
			continue
		}
		switch p := *e.Page; {
		case p == k+1 && p <= n && !stopBudget:
			stopBudget = true
		case listed[p].Status == PageNeedsOCR:
			ocrBudget = append(ocrBudget, p)
		default:
			c.fail("text-over-bound-page", "processing.errors[%d] is text-over-bound and page %d is neither the first page not listed nor a listed page that needs OCR", i, p)
		}
	}
	stopTimeout := n == 0
	if k < n && !stopBudget {
		if counts[CodeTimeout] == 0 {
			c.fail("extraction-stop", "pages %d to %d are counted and not listed, and neither timeout nor text-over-bound says why", k+1, n)
		}
		stopTimeout = true
	}
	c.ocrStep(rec, counts, stopTimeout, ocrBudget)
}

func pdfStepCode(code string) bool {
	return code == CodePDFPagesOverBound || code == CodeTimeout || code == CodeTextOverBound || pageFailureCodes[code] || ocrCodes[code]
}

// ocrStep is step 6: none when there was no page needing OCR or the
// deadline ended step 4 or 5; otherwise exactly one outcome -- not run, the
// deadline before the start, failed, ended at the deadline, or an admitted
// answer, applied in ascending page order up to a budget stop.
func (c *checker) ocrStep(rec *Record, counts map[string]int, stopTimeout bool, ocrBudget []int64) {
	var needs, applied []int64
	for _, p := range rec.Content.Pages {
		if p.Status == PageNeedsOCR {
			needs = append(needs, p.Number)
		}
		if p.Extraction == ExtractionOCR {
			applied = append(applied, p.Number)
		}
	}
	startTimeout := counts[CodeTimeout] == 1 && !stopTimeout
	outcomeCodes := counts[CodeOCRNotRun] + counts[CodeOCRFailed] + counts[CodeOCRIncomplete] + counts[CodeOCRTimeout]
	work := (len(needs) > 0 || len(applied) > 0) && !stopTimeout
	if !work {
		if outcomeCodes > 0 || startTimeout || len(ocrBudget) > 0 || len(applied) > 0 {
			c.fail("ocr-without-work", "an OCR outcome or answer in a record where step 6 did not run")
		}
		return
	}
	admitted := len(applied) > 0 || counts[CodeOCRIncomplete] > 0 || len(ocrBudget) > 0
	outcomes := counts[CodeOCRNotRun] + counts[CodeOCRFailed] + counts[CodeOCRTimeout]
	if startTimeout {
		outcomes++
	}
	if admitted {
		outcomes++
	}
	if outcomes != 1 {
		c.fail("ocr-outcome", "pages needed OCR and the record carries %d OCR outcomes, not one", outcomes)
		return
	}
	if !admitted {
		return
	}
	if len(ocrBudget) > 1 {
		c.fail("ocr-outcome", "an admitted answer stops at the text budget once, and the record names %d pages", len(ocrBudget))
		return
	}
	incomplete := counts[CodeOCRIncomplete] > 0
	c.ocrAnswerSize(rec, applied, ocrBudget)
	if len(ocrBudget) == 1 {
		cut := ocrBudget[0]
		for _, p := range applied {
			if p > cut {
				c.fail("ocr-outcome", "page %d took an OCR answer after the budget stopped the answers at page %d", p, cut)
			}
		}
		if !incomplete {
			for _, p := range needs {
				if p < cut {
					c.fail("ocr-outcome", "page %d needs OCR before the budget stop at page %d, and the answer was complete", p, cut)
				}
			}
		}
		// The page the budget stopped at was answered, so an incomplete
		// answer left out some other page that still needs OCR.
		if incomplete {
			other := false
			for _, p := range needs {
				if p != cut {
					other = true
				}
			}
			if !other {
				c.fail("ocr-outcome", "ocr-incomplete beside a budget stop at page %d, and no other page still needs OCR", cut)
			}
		}
		return
	}
	if incomplete && len(needs) == 0 {
		c.fail("ocr-outcome", "ocr-incomplete and no page still needs OCR")
	}
	if !incomplete && len(needs) > 0 {
		c.fail("ocr-outcome", "an admitted, complete answer within the budget and page %d still needs OCR", needs[0])
	}
}

// ocrAnswerSize holds an admitted answer to maxOcrOutputBytes: the answer
// was at most that many bytes, and the pages the record shows it answered
// need at least this many. The smallest answer is {"pages":[]}, 12 bytes;
// each entry {"number":N,"text":"T"} is 21 bytes, the digits of N, and T's
// JSON encoding, which is never shorter than T's UTF-8 bytes, which in turn
// are never shorter than T normalised; entries are separated by commas. An
// applied page's T is at least its text; the page a budget stop names had a
// T longer than the budget left before it. Pages whose answer the record
// does not show are not counted, so this bound is never too high.
func (c *checker) ocrAnswerSize(rec *Record, applied, ocrBudget []int64) {
	pages := map[int64]Page{}
	var layerBytes int64
	for _, p := range rec.Content.Pages {
		pages[p.Number] = p
		if p.Extraction == ExtractionTextLayer {
			layerBytes += int64(len(p.Text))
		}
	}
	digits := func(n int64) int64 { return int64(len(fmt.Sprint(n))) }
	least := int64(12)
	entries := 0
	usedBefore := layerBytes
	for _, n := range applied {
		least += 21 + digits(n) + int64(len(pages[n].Text))
		usedBefore += int64(len(pages[n].Text))
		entries++
	}
	for _, n := range ocrBudget {
		left := rec.Processing.Bounds.MaxTextBytes - usedBefore
		if left < 0 {
			left = 0
		}
		least += 21 + digits(n) + left + 1
		entries++
	}
	if entries > 1 {
		least += int64(entries - 1)
	}
	if least > rec.Processing.Bounds.MaxOcrOutputBytes {
		c.fail("ocr-answer-size", "the OCR answer the record shows needs at least %d bytes, past maxOcrOutputBytes %d", least, rec.Processing.Bounds.MaxOcrOutputBytes)
	}
}

// --- the encryption, the source, the OCR provenance --------------------------

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
	if rec.Provenance.Source.Kind == SourceGoogleDrive {
		src, o := rec.Provenance.Source, rec.Original
		if !regexp.MustCompile(`^[A-Za-z0-9_-]{1,200}$`).MatchString(src.FileID) || src.Version == "" || len(src.Version) > 32 || !mediaTypeForm.MatchString(src.MediaType) || rec.Document.Version == nil || *rec.Document.Version != src.Version {
			c.fail("drive-source", "Drive source identity/version is invalid")
		}
		if o.Retention != RetentionInline || o.Encoding == nil || *o.Encoding != "base64" || o.Bytes == nil {
			c.fail("drive-original", "Drive original must be retained inline")
			return
		}
		raw, err := base64.StdEncoding.Strict().DecodeString(*o.Bytes)
		hash := sha256.Sum256(raw)
		if err != nil || len(raw) == 0 || base64.StdEncoding.EncodeToString(raw) != *o.Bytes || int64(len(raw)) != rec.Document.Size || rec.Document.Size > rec.Processing.Bounds.MaxBytes || "sha256:"+hex.EncodeToString(hash[:]) != rec.Document.ID {
			c.fail("drive-original", "Drive original bytes do not match the document")
		}
		return
	}

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
