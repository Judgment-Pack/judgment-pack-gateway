// Package attachment is the document attachment record, version 1, of
// docs/design/attachments.md: its types, its vocabularies, the text
// normalisation every page's text passes through, and Check, the reference
// check of the note's rules. It holds no document processing -- that is
// adapter-document's -- so a producer and a test of a consumer can both use
// it, and the examples under testdata/attachments/examples answer to it.
package attachment

// Version is the record's attachmentVersion.
const Version = "1"

// Record is the result the gateway attests.
type Record struct {
	AttachmentVersion string     `json:"attachmentVersion"`
	Document          Document   `json:"document"`
	Original          Original   `json:"original"`
	Content           Content    `json:"content"`
	Processing        Processing `json:"processing"`
	Provenance        Provenance `json:"provenance"`
}

// Document is the document's identity.
type Document struct {
	ID                string      `json:"id"`
	Name              string      `json:"name"`
	MediaType         string      `json:"mediaType"`
	DetectedMediaType *string     `json:"detectedMediaType"`
	Size              int64       `json:"size"`
	Version           *string     `json:"version"`
	Encryption        *Encryption `json:"encryption"`
}

// Encryption is what a PDF declares about its encryption: the handler and
// revision as declared, null where the document declares none that reads
// as a name or an integer, and whether the adapter opened it.
type Encryption struct {
	Handler  *string `json:"handler"`
	Revision *int64  `json:"revision"`
	Opened   bool    `json:"opened"`
}

// Original says where the bytes are.
type Original struct {
	Retention string  `json:"retention"`
	Encoding  *string `json:"encoding"`
	Bytes     *string `json:"bytes"`
}

// Content is what was extracted.
type Content struct {
	Kind       string `json:"kind"`
	Extraction string `json:"extraction"`
	PageCount  int64  `json:"pageCount"`
	Truncated  bool   `json:"truncated"`
	Chars      int64  `json:"chars"`
	Pages      []Page `json:"pages"`
}

// Page is one listed page.
type Page struct {
	Number     int64  `json:"number"`
	Status     string `json:"status"`
	Extraction string `json:"extraction"`
	Text       string `json:"text"`
	Chars      int64  `json:"chars"`
	Unmapped   int64  `json:"unmapped"`
}

// Processing is what was done.
type Processing struct {
	Status     string  `json:"status"`
	Errors     []Error `json:"errors"`
	Bounds     Bounds  `json:"bounds"`
	DurationMs int64   `json:"durationMs"`
}

// Error is one condition the record reports.
type Error struct {
	Code    string `json:"code"`
	Message string `json:"message"`
	Page    *int64 `json:"page"`
}

// Bounds are the bounds that applied.
type Bounds struct {
	MaxBytes          int64 `json:"maxBytes"`
	MaxPages          int64 `json:"maxPages"`
	MaxTextBytes      int64 `json:"maxTextBytes"`
	MaxInflateBytes   int64 `json:"maxInflateBytes"`
	MaxOcrOutputBytes int64 `json:"maxOcrOutputBytes"`
	TimeoutMs         int64 `json:"timeoutMs"`
}

// Provenance says who did it, and how.
type Provenance struct {
	Adapter    Identity `json:"adapter"`
	Source     Source   `json:"source"`
	ObservedAt string   `json:"observedAt"`
	Processor  *string  `json:"processor"`
	OCR        *OCR     `json:"ocr"`
}

// Identity is the adapter as it describes itself.
type Identity struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Digest  string `json:"digest"`
}

// Source is where the bytes came from.
type Source struct {
	Kind      string `json:"kind"`
	FileID    string `json:"fileId,omitempty"`
	Version   string `json:"version,omitempty"`
	MediaType string `json:"mediaType,omitempty"`
}

// OCR is the provenance of applied OCR answers.
type OCR struct {
	Program string  `json:"program"`
	Digest  string  `json:"digest"`
	Pages   []int64 `json:"pages"`
}

// The vocabularies of version 1.
const (
	StatusComplete = "complete"
	StatusPartial  = "partial"
	StatusFailed   = "failed"

	PageOK       = "ok"
	PageNoText   = "no-text"
	PageNeedsOCR = "needs-ocr"
	PageFailed   = "failed"

	ExtractionTextLayer = "text-layer"
	ExtractionOCR       = "ocr"
	ExtractionMixed     = "mixed"
	ExtractionVerbatim  = "verbatim"
	ExtractionNone      = "none"

	RetentionCaller = "caller"
	RetentionInline = "inline"

	SourceInline      = "inline"
	SourceGoogleDrive = "google-drive"

	ProcessorPDF  = "adapter-document/pdf/1"
	ProcessorText = "adapter-document/text/1"

	MediaPDF  = "application/pdf"
	MediaText = "text/plain"

	// HandlerStandard is the one security handler version 1 opens, for
	// revisions MinRevision to MaxRevision.
	HandlerStandard = "Standard"
	MinRevision     = 2
	MaxRevision     = 6
)

// The error codes of version 1.
const (
	CodeMediaTypeUnsupported = "media-type-unsupported"
	CodeMediaTypeMismatch    = "media-type-mismatch"
	CodeDocumentOverBound    = "document-over-bound"
	CodeDocumentEmpty        = "document-empty"
	CodePDFMalformed         = "pdf-malformed"
	CodePDFEncrypted         = "pdf-encrypted"
	CodePDFUnsupported       = "pdf-unsupported"
	CodePDFPageFailed        = "pdf-page-failed"
	CodePDFPagesOverBound    = "pdf-pages-over-bound"
	CodeTextOverBound        = "text-over-bound"
	CodeStreamOverBound      = "stream-over-bound"
	CodeTimeout              = "timeout"
	CodeOCRNotRun            = "ocr-not-run"
	CodeOCRFailed            = "ocr-failed"
	CodeOCRIncomplete        = "ocr-incomplete"
	CodeOCRTimeout           = "ocr-timeout"
)

// ProcessedMediaTypes are the declarations version 1 processes, by the
// processor that reads them.
var ProcessedMediaTypes = map[string]string{
	"application/pdf":  ProcessorPDF,
	"text/plain":       ProcessorText,
	"text/markdown":    ProcessorText,
	"text/csv":         ProcessorText,
	"application/json": ProcessorText,
}
