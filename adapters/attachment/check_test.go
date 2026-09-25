package attachment

import (
	"encoding/json"
	"errors"
	"math/rand"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// The contract's own artifacts, beside the note, from this package's
// directory.
var (
	examplesDir = filepath.Join("..", "..", "testdata", "attachments", "examples")
	vectorsPath = filepath.Join("..", "..", "testdata", "attachments", "normalisation-v1.json")
)

func examples(t *testing.T) map[string][]byte {
	t.Helper()
	paths, err := filepath.Glob(filepath.Join(examplesDir, "*.json"))
	if err != nil || len(paths) == 0 {
		t.Fatalf("no examples under %s: %v", examplesDir, err)
	}
	out := map[string][]byte{}
	for _, path := range paths {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		out[strings.TrimSuffix(filepath.Base(path), ".json")] = data
	}
	return out
}

func TestEveryExampleKeepsTheRules(t *testing.T) {
	for name, data := range examples(t) {
		if err := Check(data); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestNormalisationVectors(t *testing.T) {
	data, err := os.ReadFile(vectorsPath)
	if err != nil {
		t.Fatal(err)
	}
	var file struct {
		Vectors []struct{ Name, Input, Output string }
	}
	if err := json.Unmarshal(data, &file); err != nil {
		t.Fatal(err)
	}
	if len(file.Vectors) == 0 {
		t.Fatal("no vectors")
	}
	for _, v := range file.Vectors {
		if got := NormalizeText(v.Input); got != v.Output {
			t.Errorf("%s: NormalizeText(%q) = %q, want %q", v.Name, v.Input, got, v.Output)
		}
		if !IsNormalized(v.Output) {
			t.Errorf("%s: IsNormalized(%q) is false for a normalisation's output", v.Name, v.Output)
		}
	}
}

// IsNormalized is exactly the set of NormalizeText's outputs: every output
// is in it, and every member is the output of itself, or of itself behind a
// line feed when it begins with U+FEFF.
func TestIsNormalizedIsTheSetOfOutputs(t *testing.T) {
	alphabet := []string{"a", "\xc3\xa9", " ", "\t", "\n", "\r", "\x00", "\x0b", "\x7f", "\xef\xbb\xbf", "\xc2\xa0", "\xc2\x85", "\xef\xbf\xbd"}
	rng := rand.New(rand.NewSource(1))
	for i := 0; i < 20000; i++ {
		var b strings.Builder
		for n := rng.Intn(12); n > 0; n-- {
			b.WriteString(alphabet[rng.Intn(len(alphabet))])
		}
		s := b.String()
		out := NormalizeText(s)
		if !IsNormalized(out) {
			t.Fatalf("NormalizeText(%q) = %q, which IsNormalized refuses", s, out)
		}
		if IsNormalized(s) {
			source := s
			if strings.HasPrefix(s, "\xef\xbb\xbf") {
				source = "\n" + s
			}
			if NormalizeText(source) != s {
				t.Fatalf("IsNormalized(%q) and it is not the output of %q", s, source)
			}
		}
	}
}

// mutate decodes an example, changes it, and encodes it again.
func mutate(t *testing.T, data []byte, change func(map[string]any)) []byte {
	t.Helper()
	var v map[string]any
	dec := json.NewDecoder(strings.NewReader(string(data)))
	dec.UseNumber()
	if err := dec.Decode(&v); err != nil {
		t.Fatal(err)
	}
	change(v)
	out, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func obj(v any, path ...string) map[string]any {
	m := v.(map[string]any)
	for _, p := range path {
		m = m[p].(map[string]any)
	}
	return m
}

func pagesOf(v map[string]any) []any { return obj(v, "content")["pages"].([]any) }
func page(v map[string]any, i int) map[string]any {
	return pagesOf(v)[i].(map[string]any)
}
func errorsOf(v map[string]any) []any { return obj(v, "processing")["errors"].([]any) }
func setErrors(v map[string]any, errs ...map[string]any) {
	list := make([]any, len(errs))
	for i, e := range errs {
		list[i] = e
	}
	obj(v, "processing")["errors"] = list
}
func errorOf(code string, page any) map[string]any {
	return map[string]any{"code": code, "message": "m", "page": page}
}
func num(n int) json.Number { return json.Number(strconv.Itoa(n)) }

// Each broken record is refused, and refused for the rule it breaks: one of
// the problems must carry the rule's identifier, so a record refused for
// some other reason does not pass.
func TestCheckRefusesEachBrokenRule(t *testing.T) {
	ex := examples(t)
	cases := []struct {
		name, base, want string
		change           func(map[string]any)
	}{
		// the canonical domain, the member set, the types
		{"a fraction", "complete-text-layer", "canonical-domain", func(v map[string]any) { obj(v, "document")["size"] = json.Number("1.5") }},
		{"an unknown member", "complete-text-layer", "member-unknown", func(v map[string]any) { obj(v, "document")["extra"] = true }},
		{"an absent member", "complete-text-layer", "member-absent", func(v map[string]any) { delete(obj(v, "provenance"), "ocr") }},
		{"a null that is not allowed", "complete-text-layer", "member-null", func(v map[string]any) { obj(v, "document")["name"] = nil }},
		{"a string where an integer goes", "complete-text-layer", "member-type", func(v map[string]any) { obj(v, "document")["size"] = "12" }},
		{"an inline source with an extra member", "complete-text-layer", "member-unknown", func(v map[string]any) { obj(v, "provenance", "source")["extra"] = 1 }},
		// each value on its own
		{"a second version", "complete-text-layer", "version", func(v map[string]any) { v["attachmentVersion"] = "2" }},
		{"a digest in capitals", "complete-text-layer", "id-digest", func(v map[string]any) {
			obj(v, "document")["id"] = "sha256:" + strings.Repeat("A", 64)
		}},
		{"a digest with a line feed after it", "complete-text-layer", "id-digest", func(v map[string]any) {
			obj(v, "document")["id"] = obj(v, "document")["id"].(string) + "\n"
		}},
		{"a control in the name", "complete-text-layer", "name", func(v map[string]any) { obj(v, "document")["name"] = "a\x01b" }},
		{"a name of 256 bytes", "complete-text-layer", "name", func(v map[string]any) { obj(v, "document")["name"] = strings.Repeat("n", 256) }},
		{"a media type with a parameter", "complete-text-layer", "media-type", func(v map[string]any) {
			obj(v, "document")["mediaType"] = "application/pdf; x=1"
		}},
		{"a detected type outside the two", "complete-verbatim-text", "detected-media-type", func(v map[string]any) { obj(v, "document")["detectedMediaType"] = "text/csv" }},
		{"non-canonical base64", "complete-text-layer", "bytes-base64", func(v map[string]any) { obj(v, "original")["bytes"] = "Zh==" }},
		{"an unknown page status", "complete-text-layer", "page-status", func(v map[string]any) { page(v, 0)["status"] = "done" }},
		{"a carriage return in text", "complete-text-layer", "text-normalised", func(v map[string]any) {
			page(v, 0)["text"] = "a\r\nb"
			page(v, 0)["chars"] = num(4)
		}},
		{"a trailing line feed in text", "complete-text-layer", "text-normalised", func(v map[string]any) {
			p := page(v, 0)
			p["text"] = p["text"].(string) + "\n"
		}},
		{"a leading blank line in text", "complete-text-layer", "text-normalised", func(v map[string]any) {
			p := page(v, 0)
			p["text"] = " \n" + p["text"].(string)
		}},
		{"an unknown code", "partial-needs-ocr", "code-known", func(v map[string]any) { setErrors(v, errorOf("made-up", nil)) }},
		{"a message past 512 bytes", "partial-needs-ocr", "message-length", func(v map[string]any) {
			errorsOf(v)[0].(map[string]any)["message"] = strings.Repeat("m", 513)
		}},
		{"a zero bound", "complete-text-layer", "bounds-positive", func(v map[string]any) { obj(v, "processing", "bounds")["maxTextBytes"] = num(0) }},
		{"a maxBytes whose read bound leaves the canonical domain", "complete-text-layer", "bounds-derived", func(v map[string]any) {
			obj(v, "processing", "bounds")["maxBytes"] = json.Number("6755399441006590")
		}},
		{"a calendar date that does not exist", "complete-text-layer", "observed-at-time", func(v map[string]any) {
			obj(v, "provenance")["observedAt"] = "2026-02-30T00:00:00Z"
		}},
		{"an invented source kind", "complete-text-layer", "source-kind", func(v map[string]any) { obj(v, "provenance", "source")["kind"] = "drive" }},
		// pages
		{"pages out of order", "complete-text-layer", "page-contiguous", func(v map[string]any) {
			ps := pagesOf(v)
			ps[0], ps[1] = ps[1], ps[0]
		}},
		{"chars that do not count the text", "complete-text-layer", "page-chars", func(v map[string]any) { page(v, 0)["chars"] = num(1) }},
		{"an ok page with no text", "complete-text-layer", "page-ok", func(v map[string]any) {
			page(v, 0)["text"] = ""
			page(v, 0)["chars"] = num(0)
		}},
		{"a no-text page with text", "complete-text-layer", "page-no-text", func(v map[string]any) {
			page(v, 2)["text"] = "x"
			page(v, 2)["chars"] = num(1)
		}},
		{"a needs-ocr page with an extraction", "partial-needs-ocr", "page-without-text", func(v map[string]any) { page(v, 0)["extraction"] = "text-layer" }},
		{"unmapped glyphs on a verbatim page", "complete-verbatim-text", "unmapped-method", func(v map[string]any) { page(v, 0)["unmapped"] = num(1) }},
		{"unmapped glyphs not in the text", "complete-text-layer", "unmapped-count", func(v map[string]any) { page(v, 0)["unmapped"] = num(1) }},
		{"more pages listed than counted", "complete-text-layer", "pages-past-count", func(v map[string]any) { obj(v, "content")["pageCount"] = num(2) }},
		{"a count past maxPages", "partial-truncated-pages", "count-past-max-pages", func(v map[string]any) { obj(v, "processing", "bounds")["maxPages"] = num(49) }},
		{"content chars that do not sum", "complete-text-layer", "content-chars", func(v map[string]any) { obj(v, "content")["chars"] = num(1) }},
		{"text past the budget", "complete-text-layer", "text-budget", func(v map[string]any) { obj(v, "processing", "bounds")["maxTextBytes"] = num(10) }},
		{"an extraction the pages do not derive", "complete-mixed-with-ocr", "extraction-derived", func(v map[string]any) { obj(v, "content")["extraction"] = "text-layer" }},
		{"a blank text-layer document called none", "complete-text-layer", "extraction-derived", func(v map[string]any) {
			for i := 0; i < 2; i++ {
				page(v, i)["status"] = "no-text"
				page(v, i)["text"] = ""
				page(v, i)["chars"] = num(0)
			}
			obj(v, "content")["chars"] = num(0)
			obj(v, "content")["extraction"] = "none"
		}},
		{"fewer pages listed than counted, not truncated", "partial-timeout", "truncated", func(v map[string]any) { obj(v, "content")["truncated"] = false }},
		// status
		{"complete while truncated", "complete-text-layer", "status-derived", func(v map[string]any) {
			obj(v, "content")["truncated"] = true
			obj(v, "content")["pageCount"] = num(4)
		}},
		{"partial with pages and no errors", "partial-needs-ocr", "status-derived", func(v map[string]any) {
			setErrors(v)
			for i := 0; i < 2; i++ {
				page(v, i)["status"] = "no-text"
				page(v, i)["extraction"] = "text-layer"
			}
			obj(v, "content")["extraction"] = "text-layer"
		}},
		{"failed with a page", "failed-malformed", "status-derived", func(v map[string]any) {
			obj(v, "content")["pages"] = []any{map[string]any{"number": num(1), "status": "ok", "extraction": "text-layer", "text": "x", "chars": num(1), "unmapped": num(0)}}
			obj(v, "content")["pageCount"] = num(1)
			obj(v, "content")["chars"] = num(1)
			obj(v, "content")["extraction"] = "text-layer"
		}},
		{"no page and no error", "failed-malformed", "walk-empty", func(v map[string]any) { setErrors(v) }},
		// codes
		{"a defect beside an OCR outcome", "partial-needs-ocr", "walk-defect", func(v map[string]any) {
			setErrors(v, errorOf("ocr-not-run", nil), errorOf("pdf-malformed", nil))
		}},
		{"an OCR outcome beside a defect", "failed-malformed", "walk-defect", func(v map[string]any) {
			setErrors(v, errorOf("pdf-malformed", nil), errorOf("ocr-not-run", nil))
		}},
		{"a document-level code with a page", "partial-needs-ocr", "code-page-forbidden", func(v map[string]any) { setErrors(v, errorOf("ocr-not-run", num(1))) }},
		{"pdf-page-failed without a page", "complete-text-layer", "code-page-required", func(v map[string]any) {
			page(v, 2)["status"] = "failed"
			page(v, 2)["extraction"] = "none"
			obj(v, "processing")["status"] = "partial"
			setErrors(v, errorOf("pdf-page-failed", nil))
		}},
		{"a failed page no error names", "complete-text-layer", "failed-page-errors", func(v map[string]any) {
			page(v, 2)["status"] = "failed"
			page(v, 2)["extraction"] = "none"
			obj(v, "processing")["status"] = "partial"
			setErrors(v, errorOf("timeout", nil))
		}},
		{"text-over-bound on a page that is neither", "partial-text-over-bound", "text-over-bound-page", func(v map[string]any) {
			errorsOf(v)[0].(map[string]any)["page"] = num(3)
		}},
		{"text-over-bound without a page", "partial-text-over-bound", "code-page-required", func(v map[string]any) {
			errorsOf(v)[0].(map[string]any)["page"] = nil
		}},
		{"a page bound not truncated", "partial-truncated-pages", "pages-over-bound", func(v map[string]any) {
			obj(v, "processing", "bounds")["maxPages"] = num(60)
		}},
		{"a code twice", "partial-needs-ocr", "code-once", func(v map[string]any) {
			setErrors(v, errorOf("ocr-not-run", nil), errorOf("ocr-not-run", nil))
		}},
		{"two deadline codes", "partial-ocr-failed", "ocr-outcome", func(v map[string]any) {
			setErrors(v, errorOf("timeout", nil), errorOf("ocr-timeout", nil))
		}},
		{"two OCR outcomes", "partial-needs-ocr", "ocr-outcome", func(v map[string]any) {
			setErrors(v, errorOf("ocr-not-run", nil), errorOf("ocr-failed", nil))
		}},
		{"an OCR outcome with no page needing OCR", "complete-text-layer", "ocr-without-work", func(v map[string]any) {
			obj(v, "processing")["status"] = "partial"
			setErrors(v, errorOf("ocr-not-run", nil))
		}},
		{"a needs-ocr page no error explains", "partial-needs-ocr", "ocr-outcome", func(v map[string]any) {
			setErrors(v, errorOf("pdf-pages-over-bound", nil))
			obj(v, "content")["truncated"] = true
			obj(v, "processing", "bounds")["maxPages"] = num(2)
		}},
		{"ocr-failed beside an applied answer", "partial-ocr-incomplete", "ocr-outcome", func(v map[string]any) {
			setErrors(v, errorOf("ocr-failed", nil))
		}},
		// the declaration
		{"a PDF with no processor", "complete-text-layer", "declaration-outcome", func(v map[string]any) { obj(v, "provenance")["processor"] = nil }},
		{"an unsupported record with a processor", "failed-unsupported-type", "processor-type", func(v map[string]any) {
			obj(v, "provenance")["processor"] = "adapter-document/pdf/1"
		}},
		{"a processed type called unsupported", "failed-unsupported-type", "media-type-unsupported", func(v map[string]any) {
			obj(v, "document")["mediaType"] = "text/csv"
		}},
		{"a read record of an unprocessed type", "complete-text-layer", "processor-type", func(v map[string]any) {
			obj(v, "document")["mediaType"] = "application/zip"
		}},
		{"a mismatch with a detected type", "failed-mismatch", "detected-unprocessed", func(v map[string]any) {
			obj(v, "document")["detectedMediaType"] = "application/pdf"
		}},
		{"a text document read as a PDF", "complete-verbatim-text", "processor-type", func(v map[string]any) {
			obj(v, "provenance")["processor"] = "adapter-document/pdf/1"
		}},
		{"a text document with PDF detection", "complete-verbatim-text", "detected-read", func(v map[string]any) {
			obj(v, "document")["detectedMediaType"] = "application/pdf"
		}},
		{"a text document with two pages", "complete-verbatim-text", "text-document-count", func(v map[string]any) { obj(v, "content")["pageCount"] = num(2) }},
		{"a verbatim page in a PDF", "complete-text-layer", "pdf-verbatim", func(v map[string]any) {
			for i := 0; i < 3; i++ {
				page(v, i)["extraction"] = "verbatim"
			}
			obj(v, "content")["extraction"] = "verbatim"
		}},
		// encryption
		{"opened false without pdf-encrypted", "complete-encrypted-opened", "encryption-opened", func(v map[string]any) {
			obj(v, "document", "encryption")["opened"] = false
		}},
		{"pdf-encrypted on a document opened", "failed-encrypted", "encryption-opened", func(v map[string]any) {
			obj(v, "document", "encryption")["opened"] = true
			obj(v, "document", "encryption")["revision"] = num(4)
		}},
		{"opened false under a timeout met after pages were counted", "partial-timeout", "encryption-opened", func(v map[string]any) {
			obj(v, "document")["encryption"] = map[string]any{"handler": "Standard", "revision": num(4), "opened": false}
		}},
		{"opened with a handler version 1 does not open", "complete-encrypted-opened", "encryption-handler", func(v map[string]any) {
			obj(v, "document", "encryption")["handler"] = "Adobe.PubSec"
		}},
		{"opened at revision 99", "complete-encrypted-opened", "encryption-handler", func(v map[string]any) {
			obj(v, "document", "encryption")["revision"] = num(99)
		}},
		{"pdf-encrypted with no encryption declared", "failed-malformed", "encryption-undeclared", func(v map[string]any) {
			setErrors(v, errorOf("pdf-encrypted", nil))
		}},
		// Drive records retain and bind originals.
		{"Drive version mismatch", "complete-text-layer", "drive-source", func(v map[string]any) {
			obj(v, "provenance")["source"] = map[string]any{"kind": "google-drive", "fileId": "file-A", "version": "7", "mediaType": "application/pdf"}
		}},
		{"Drive missing original", "complete-text-layer", "drive-original", func(v map[string]any) {
			obj(v, "provenance")["source"] = map[string]any{"kind": "google-drive", "fileId": "file-A", "version": "7", "mediaType": "application/pdf"}
			obj(v, "document")["version"] = "7"
		}},
		{"Drive altered original", "complete-text-layer", "drive-original", func(v map[string]any) {
			obj(v, "provenance")["source"] = map[string]any{"kind": "google-drive", "fileId": "file-A", "version": "7", "mediaType": "application/pdf"}
			obj(v, "document")["version"] = "7"
			obj(v, "original")["retention"] = "inline"
			obj(v, "original")["encoding"] = "base64"
			obj(v, "original")["bytes"] = "YWJj"
		}},
		// the inline source
		{"an inline document with a version", "complete-text-layer", "inline-version", func(v map[string]any) { obj(v, "document")["version"] = "7" }},
		{"an inline document retained inline", "complete-text-layer", "inline-original", func(v map[string]any) {
			obj(v, "original")["retention"] = "inline"
			obj(v, "original")["encoding"] = "base64"
			obj(v, "original")["bytes"] = "AAAA"
		}},
		{"an empty inline document", "complete-verbatim-text", "inline-empty", func(v map[string]any) { obj(v, "document")["size"] = num(0) }},
		{"an inline document past maxBytes", "complete-text-layer", "inline-over-bound", func(v map[string]any) { obj(v, "processing", "bounds")["maxBytes"] = num(10) }},
		{"an inline document-over-bound record", "failed-unsupported-type", "inline-refused-code", func(v map[string]any) {
			setErrors(v, errorOf("document-over-bound", nil))
			obj(v, "document")["mediaType"] = "application/pdf"
		}},
		// OCR provenance
		{"OCR pages with no provenance", "complete-mixed-with-ocr", "ocr-provenance-null", func(v map[string]any) { obj(v, "provenance")["ocr"] = nil }},
		{"provenance with no OCR page", "complete-text-layer", "ocr-provenance-set", func(v map[string]any) {
			obj(v, "provenance")["ocr"] = map[string]any{"program": "p", "digest": "sha256:" + strings.Repeat("0", 64), "pages": []any{num(2)}}
		}},
		{"provenance naming another page", "complete-mixed-with-ocr", "ocr-provenance-pages", func(v map[string]any) {
			obj(v, "provenance", "ocr")["pages"] = []any{num(1)}
		}},
		// cases for the rules the examples above do not reach
		{"an array for the record", "complete-text-layer", "not-object", func(v map[string]any) { v["document"] = []any{} }},
		{"a negative size", "failed-unsupported-type", "size-negative", func(v map[string]any) { obj(v, "document")["size"] = num(-1) }},
		{"an unknown retention", "complete-text-layer", "retention", func(v map[string]any) { obj(v, "original")["retention"] = "server" }},
		{"an unknown encoding", "complete-text-layer", "encoding", func(v map[string]any) { obj(v, "original")["encoding"] = "hex" }},
		{"another content kind", "complete-text-layer", "content-kind", func(v map[string]any) { obj(v, "content")["kind"] = "table" }},
		{"an unknown content extraction", "complete-text-layer", "content-extraction", func(v map[string]any) { obj(v, "content")["extraction"] = "vision" }},
		{"a negative page count", "failed-malformed", "counts-negative", func(v map[string]any) { obj(v, "content")["pageCount"] = num(-1) }},
		{"a page numbered zero", "complete-verbatim-text", "page-counts", func(v map[string]any) { page(v, 0)["number"] = num(0) }},
		{"an unknown page extraction", "complete-text-layer", "page-extraction", func(v map[string]any) { page(v, 0)["extraction"] = "vision" }},
		{"an unknown status", "complete-text-layer", "status", func(v map[string]any) { obj(v, "processing")["status"] = "done" }},
		{"an error on page zero", "partial-text-over-bound", "error-page", func(v map[string]any) { errorsOf(v)[0].(map[string]any)["page"] = num(0) }},
		{"a negative duration", "complete-text-layer", "duration-negative", func(v map[string]any) { obj(v, "processing")["durationMs"] = num(-1) }},
		{"an adapter with no name", "complete-text-layer", "adapter-identity", func(v map[string]any) { obj(v, "provenance", "adapter")["name"] = "" }},
		{"a stamp with fractional seconds", "complete-text-layer", "observed-at-form", func(v map[string]any) {
			obj(v, "provenance")["observedAt"] = "2026-09-16T14:05:11.5Z"
		}},
		{"an empty processor", "complete-text-layer", "processor-empty", func(v map[string]any) { obj(v, "provenance")["processor"] = "" }},
		{"an OCR program with no name", "complete-mixed-with-ocr", "ocr-identity", func(v map[string]any) { obj(v, "provenance", "ocr")["program"] = "" }},
		{"a page listed past the count", "complete-text-layer", "page-contiguous", func(v map[string]any) { page(v, 2)["number"] = num(4) }},
		{"verbatim beside text-layer", "complete-text-layer", "extraction-mix", func(v map[string]any) { page(v, 2)["extraction"] = "verbatim" }},
		{"a failure naming a page that did not fail", "partial-ocr-failed", "failed-page-errors", func(v map[string]any) {
			setErrors(v, errorOf("ocr-failed", nil), errorOf("pdf-page-failed", num(2)))
		}},
		{"a record with no extractor counting pages", "failed-unsupported-type", "declaration-outcome", func(v map[string]any) { obj(v, "content")["pageCount"] = num(1) }},
		{"a text page that is not page 1", "complete-verbatim-text", "text-document-count", func(v map[string]any) {
			page(v, 0)["number"] = num(2)
			obj(v, "content")["pageCount"] = num(2)
		}},
		{"encryption on a text document", "complete-verbatim-text", "encryption-not-pdf", func(v map[string]any) {
			obj(v, "document")["encryption"] = map[string]any{"handler": "Standard", "revision": num(4), "opened": true}
		}},
		{"an inline document reporting document-empty", "failed-unsupported-type", "inline-refused-code", func(v map[string]any) {
			setErrors(v, errorOf("document-empty", nil))
			obj(v, "document")["mediaType"] = "application/pdf"
		}},
		// round 4: records the steps cannot write
		{"page 1 skipped", "complete-text-layer", "page-contiguous", func(v map[string]any) {
			obj(v, "content")["pages"] = pagesOf(v)[1:]
			obj(v, "content")["chars"] = num(105)
			obj(v, "content")["truncated"] = true
			obj(v, "processing")["status"] = "partial"
			setErrors(v, errorOf("timeout", nil))
		}},
		{"every page listed and truncated", "complete-text-layer", "truncated", func(v map[string]any) {
			obj(v, "content")["truncated"] = true
			obj(v, "processing")["status"] = "partial"
		}},
		{"a walk deadline not truncated", "failed-malformed", "truncated", func(v map[string]any) { setErrors(v, errorOf("timeout", nil)) }},
		{"counted pages omitted with no stop", "complete-text-layer", "extraction-stop", func(v map[string]any) {
			obj(v, "content")["pages"] = pagesOf(v)[:1]
			obj(v, "content")["chars"] = page(v, 0)["chars"]
			obj(v, "content")["truncated"] = true
			obj(v, "processing")["status"] = "partial"
			obj(v, "processing", "bounds")["maxPages"] = num(3)
			setErrors(v, errorOf("pdf-pages-over-bound", nil))
		}},
		{"two declaration codes", "failed-unsupported-type", "declaration-outcome", func(v map[string]any) {
			setErrors(v, errorOf("media-type-unsupported", nil), errorOf("media-type-mismatch", nil))
		}},
		{"a declaration code with a PDF code", "failed-mismatch", "declaration-outcome", func(v map[string]any) {
			setErrors(v, errorOf("media-type-mismatch", nil), errorOf("pdf-malformed", nil))
		}},
		{"a defect with pages counted", "failed-malformed", "walk-defect", func(v map[string]any) {
			obj(v, "content")["pageCount"] = num(1)
			obj(v, "content")["truncated"] = true
		}},
		{"a text document needing OCR", "complete-blank-text", "text-document-outcome", func(v map[string]any) {
			page(v, 0)["status"] = "needs-ocr"
			page(v, 0)["extraction"] = "none"
			obj(v, "content")["extraction"] = "none"
			obj(v, "processing")["status"] = "partial"
			setErrors(v, errorOf("ocr-not-run", nil))
		}},
		{"a text document with a failed page", "complete-blank-text", "text-document-outcome", func(v map[string]any) {
			page(v, 0)["status"] = "failed"
			page(v, 0)["extraction"] = "none"
			obj(v, "content")["extraction"] = "none"
			obj(v, "processing")["status"] = "partial"
			setErrors(v, errorOf("pdf-page-failed", num(1)))
		}},
		{"text longer than its document", "complete-verbatim-text", "text-document-size", func(v map[string]any) { obj(v, "document")["size"] = num(1) }},
		{"a text document past a budget it fits", "complete-verbatim-text", "text-document-size", func(v map[string]any) {
			obj(v, "content")["pages"] = []any{}
			obj(v, "content")["chars"] = num(0)
			obj(v, "content")["extraction"] = "none"
			obj(v, "content")["truncated"] = true
			obj(v, "processing")["status"] = "failed"
			setErrors(v, errorOf("text-over-bound", num(1)))
		}},
		{"applied OCR answers and a deadline before the start", "complete-mixed-with-ocr", "ocr-outcome", func(v map[string]any) {
			obj(v, "processing")["status"] = "partial"
			setErrors(v, errorOf("timeout", nil))
		}},
		{"a deadline before the start and ocr-not-run", "partial-needs-ocr", "ocr-outcome", func(v map[string]any) {
			setErrors(v, errorOf("timeout", nil), errorOf("ocr-not-run", nil))
		}},
		{"ocr-not-run and an OCR budget stop", "partial-needs-ocr", "ocr-outcome", func(v map[string]any) {
			setErrors(v, errorOf("ocr-not-run", nil), errorOf("text-over-bound", num(1)))
		}},
		{"an answer applied after the budget stop", "partial-ocr-over-budget", "ocr-outcome", func(v map[string]any) {
			page(v, 1)["status"] = "needs-ocr"
			page(v, 1)["extraction"] = "none"
			page(v, 1)["text"] = ""
			page(v, 1)["chars"] = num(0)
			page(v, 2)["status"] = "ok"
			page(v, 2)["extraction"] = "ocr"
			page(v, 2)["text"] = "x"
			page(v, 2)["chars"] = num(1)
			obj(v, "content")["chars"] = num(37)
			obj(v, "provenance", "ocr")["pages"] = []any{num(3)}
			errorsOf(v)[0].(map[string]any)["page"] = num(2)
		}},
		{"one omitted page named twice", "partial-text-over-bound", "text-over-bound-page", func(v map[string]any) {
			setErrors(v, errorOf("text-over-bound", num(2)), errorOf("text-over-bound", num(2)))
		}},
		{"a failed page named by two failures", "complete-text-layer", "failed-page-errors", func(v map[string]any) {
			page(v, 2)["status"] = "failed"
			page(v, 2)["extraction"] = "none"
			obj(v, "processing")["status"] = "partial"
			setErrors(v, errorOf("pdf-page-failed", num(3)), errorOf("stream-over-bound", num(3)))
		}},
		{"a declaration code among a PDF's steps", "partial-needs-ocr", "stray-error", func(v map[string]any) {
			setErrors(v, errorOf("ocr-not-run", nil), errorOf("media-type-mismatch", nil))
		}},
		{"an unknown processor", "complete-text-layer", "processor-type", func(v map[string]any) { obj(v, "provenance")["processor"] = "adapter-document/docx/1" }},
		// branches of shared rules
		{"an OCR page number that is a string", "complete-mixed-with-ocr", "member-type", func(v map[string]any) {
			obj(v, "provenance", "ocr")["pages"] = []any{"2"}
		}},
		{"two OCR budget stops", "partial-ocr-over-budget", "ocr-outcome", func(v map[string]any) {
			page(v, 1)["status"] = "needs-ocr"
			page(v, 1)["extraction"] = "none"
			page(v, 1)["text"] = ""
			page(v, 1)["chars"] = num(0)
			obj(v, "content")["chars"] = num(36)
			obj(v, "content")["extraction"] = "text-layer"
			obj(v, "provenance")["ocr"] = nil
			setErrors(v, errorOf("text-over-bound", num(2)), errorOf("text-over-bound", num(3)))
		}},
		{"a page before the budget stop left unanswered by a complete answer", "partial-ocr-over-budget", "ocr-outcome", func(v map[string]any) {
			page(v, 1)["status"] = "needs-ocr"
			page(v, 1)["extraction"] = "none"
			page(v, 1)["text"] = ""
			page(v, 1)["chars"] = num(0)
			obj(v, "content")["chars"] = num(36)
			obj(v, "content")["extraction"] = "text-layer"
			obj(v, "provenance")["ocr"] = nil
		}},
		{"ocr-incomplete with nothing left needing OCR", "complete-mixed-with-ocr", "ocr-outcome", func(v map[string]any) {
			obj(v, "processing")["status"] = "partial"
			setErrors(v, errorOf("ocr-incomplete", nil))
		}},
		{"a complete answer leaving a page needing OCR", "partial-ocr-incomplete", "ocr-outcome", func(v map[string]any) { setErrors(v) }},
		// round 5
		{"ocr-incomplete beside a budget stop with nothing else left", "partial-ocr-over-budget", "ocr-outcome", func(v map[string]any) {
			setErrors(v, errorOf("text-over-bound", num(3)), errorOf("ocr-incomplete", nil))
		}},
		{"applied answers past the OCR output bound", "complete-mixed-with-ocr", "ocr-answer-size", func(v map[string]any) {
			obj(v, "processing", "bounds")["maxOcrOutputBytes"] = num(1)
		}},
		{"an empty admitted answer past a tiny output bound", "partial-ocr-incomplete", "ocr-answer-size", func(v map[string]any) {
			page(v, 1)["status"] = "needs-ocr"
			page(v, 1)["extraction"] = "none"
			page(v, 1)["text"] = ""
			page(v, 1)["chars"] = num(0)
			obj(v, "content")["chars"] = num(36)
			obj(v, "content")["extraction"] = "text-layer"
			obj(v, "provenance")["ocr"] = nil
			obj(v, "processing", "bounds")["maxOcrOutputBytes"] = num(11)
		}},
		{"a budget stop the output bound could not carry", "partial-ocr-over-budget", "ocr-answer-size", func(v map[string]any) {
			obj(v, "processing", "bounds")["maxTextBytes"] = num(100)
			obj(v, "processing", "bounds")["maxOcrOutputBytes"] = num(100)
		}},
		{"a text of only U+FEFF from three bytes", "complete-verbatim-text", "text-document-size", func(v map[string]any) {
			page(v, 0)["text"] = "\xef\xbb\xbf"
			page(v, 0)["chars"] = num(1)
			obj(v, "content")["chars"] = num(1)
			obj(v, "document")["size"] = num(3)
		}},
		{"invalid web source", "complete-verbatim-text", "web-source", func(v map[string]any) {
			obj(v, "provenance")["source"] = map[string]any{"kind": "web", "requestedUrl": "http://localhost", "url": "https://example.com", "version": "bad", "responseDigest": "bad", "mediaType": "text/plain", "format": "original-v1"}
		}},
		{"invalid generic resource", "complete-verbatim-text", "connection-resource", func(v map[string]any) {
			obj(v, "provenance")["source"] = map[string]any{"kind": "connection-resource", "provider": "fixture", "resourceId": "x", "url": "", "version": "bad", "format": "retained-file-v1"}
		}},
		{"invalid connected source", "complete-verbatim-text", "connected-source", func(v map[string]any) {
			obj(v, "provenance")["source"] = map[string]any{"kind": "connected-source", "provider": "unknown", "resourceId": "x", "url": "https://example.invalid", "version": "bad", "format": "text-snapshot-v1"}
		}},
		{"invalid Gmail message identity", "complete-verbatim-text", "gmail-source", func(v map[string]any) {
			obj(v, "provenance")["source"] = map[string]any{"kind": "gmail", "messageId": "bad/id", "threadId": "abc2", "version": "7", "format": "text-export-v1"}
			obj(v, "document")["version"] = "7"
		}},
		{"a PDF read from one byte", "failed-malformed", "pdf-size", func(v map[string]any) { obj(v, "document")["size"] = num(1) }},
	}
	names := map[string]bool{}
	covered := map[string]bool{}
	for _, c := range cases {
		if names[c.name] {
			t.Fatalf("case %q twice", c.name)
		}
		names[c.name] = true
		base, ok := ex[c.base]
		if !ok {
			t.Fatalf("%s: no example %s", c.name, c.base)
		}
		err := Check(mutate(t, base, c.change))
		var problems Problems
		if !errors.As(err, &problems) {
			t.Errorf("%s: accepted (%v)", c.name, err)
			continue
		}
		found := false
		for _, p := range problems {
			if strings.HasPrefix(p, c.want+": ") {
				found = true
			}
		}
		if !found {
			t.Errorf("%s: refused, but not under %s: %v", c.name, c.want, err)
		}
		covered[c.want] = true
	}

	// Every rule check.go can fail under has a case above: a rule added
	// without one fails here. "decode" is not reachable once the canonical
	// domain and the member types have held, and is the one exception.
	source, err := os.ReadFile("check.go")
	if err != nil {
		t.Fatal(err)
	}
	var missing []string
	for _, m := range regexp.MustCompile(`c\.fail\("([a-z0-9-]+)"`).FindAllStringSubmatch(string(source), -1) {
		if !covered[m[1]] {
			missing = append(missing, m[1])
		}
	}
	sort.Strings(missing)
	if len(missing) > 0 {
		t.Errorf("rules with no case: %s", strings.Join(missing, ", "))
	}
}

// Records the steps can write, near the rules above: each is accepted.
func TestCheckAcceptsWhatTheStepsCanWrite(t *testing.T) {
	if 4*((MaxBytesCeiling+2)/3)+65536 > 1<<53-1 || 4*((MaxBytesCeiling+1+2)/3)+65536 <= 1<<53-1 {
		t.Fatalf("MaxBytesCeiling %d is not the largest maxBytes whose read bound is canonical", MaxBytesCeiling)
	}
	ex := examples(t)
	cases := []struct {
		name, base string
		change     func(map[string]any)
	}{
		{"ocr-incomplete beside a budget stop, another page unanswered", "partial-ocr-over-budget", func(v map[string]any) {
			pages := pagesOf(v)
			fourth := map[string]any{"number": num(4), "status": "needs-ocr", "extraction": "none", "text": "", "chars": num(0), "unmapped": num(0)}
			obj(v, "content")["pages"] = append(pages, fourth)
			obj(v, "content")["pageCount"] = num(4)
			setErrors(v, errorOf("text-over-bound", num(3)), errorOf("ocr-incomplete", nil))
		}},
		{"an answer exactly at the output bound's lower limit", "complete-mixed-with-ocr", func(v map[string]any) {
			text := page(v, 1)["text"].(string)
			obj(v, "processing", "bounds")["maxOcrOutputBytes"] = num(12 + 21 + 1 + len(text))
		}},
		{"a text beginning with U+FEFF from one byte more", "complete-verbatim-text", func(v map[string]any) {
			page(v, 0)["text"] = "\xef\xbb\xbf"
			page(v, 0)["chars"] = num(1)
			obj(v, "content")["chars"] = num(1)
			obj(v, "document")["size"] = num(4)
		}},
		{"a PDF read from five bytes", "failed-malformed", func(v map[string]any) { obj(v, "document")["size"] = num(5) }},
		{"maxBytes at its ceiling", "complete-text-layer", func(v map[string]any) {
			obj(v, "processing", "bounds")["maxBytes"] = json.Number("6755399441006589")
		}},
	}
	for _, c := range cases {
		if err := Check(mutate(t, ex[c.base], c.change)); err != nil {
			t.Errorf("%s: refused: %v", c.name, err)
		}
	}
}
