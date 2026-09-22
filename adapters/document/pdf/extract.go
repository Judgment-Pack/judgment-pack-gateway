package pdf

import (
	"context"
	"errors"
	"fmt"
	"unicode/utf8"
)

// Options bound one extraction.
type Options struct {
	// MaxPages bounds the pages counted and listed; finding a page past it
	// ends the walk at the page bound.
	MaxPages int
	// MaxTextBytes is the text budget: the sum of listed pages' normalised
	// text in bytes of UTF-8.
	MaxTextBytes int
	// MaxInflateTotal and MaxInflateOne bound stream inflation.
	MaxInflateTotal, MaxInflateOne int64
}

// PageStatus is what became of one listed page.
type PageStatus string

const (
	PageOK       PageStatus = "ok"
	PageNoText   PageStatus = "no-text"
	PageNeedsOCR PageStatus = "needs-ocr"
	PageFailed   PageStatus = "failed"
)

// Page is one listed page, as docs/design/attachments.md's "Page outcomes"
// assigns it for a PDF's text layer: Text is normalised, and empty for
// every status but ok.
type Page struct {
	Number   int
	Status   PageStatus
	Text     string
	Unmapped int
}

// Problem is one condition the record reports, with the page it belongs
// to or 0 for the document. Its message is the reader's own words and
// carries nothing of the document's content.
type Problem struct {
	Code    string
	Message string
	Page    int
}

// Result is what Extract yields: step 4 and step 5 of the note's "How a
// document is processed". Fatal is set when the walk ended at a defect
// (pdf-malformed or pdf-encrypted); nothing is listed then, PageCount is 0
// and Truncated false. TimedOut says a deadline check found the deadline
// passed, in the walk or in extraction, and timeout is among Problems.
type Result struct {
	Encryption *Encryption
	PageCount  int
	Truncated  bool
	Pages      []Page
	Problems   []Problem
	Fatal      *Problem
	TimedOut   bool
	// TextBytes is the sum of listed pages' text in bytes.
	TextBytes int
}

const (
	// maxPageTreeDepth bounds the page tree's nesting.
	maxPageTreeDepth = 64
	// maxPageTreeNodes bounds the nodes visited while walking it.
	maxPageTreeNodes = 1 << 20
	// maxPageWorkBytes bounds the work one page may cost the reader beyond
	// what its bounds on memory already cover: the bytes of the file its
	// content streams hold as they lie in it, the bytes of every form
	// XObject it draws, each time it is drawn, and a charge for each filter
	// applied on its behalf. A /Contents array may name one stream any number
	// of times, a page may draw one form any number of times, and a filter
	// that yields little charges the inflation budget that little for each of
	// them: what the page costs to read is bounded here rather than there.
	maxPageWorkBytes = 64 << 20
	// filterStepBytes is what one entry of a stream's filter list costs
	// against the page's work, charged as the entry is read and whether or
	// not it names a filter the reader applies: a list is read for every
	// stream it belongs to, and a list of a hundred thousand filters that
	// yields nothing is work whatever it yields.
	filterStepBytes = 256
)

// Extract reads the document within the options and the context's
// deadline. It never panics on input: a defect met while the document is
// opened or its page tree walked is Fatal, and one met on a page fails
// that page.
func Extract(ctx context.Context, data []byte, opt Options) *Result {
	result := &Result{}
	d, stop := walk(ctx, data, opt, result)
	if stop != nil {
		return result
	}
	extractPages(ctx, d, opt, result)
	return result
}

// walk is step 4: open the document and count its pages. It returns the
// document and the pages to extract, or a non-nil stop when the adapter
// goes straight to step 7.
func walk(ctx context.Context, data []byte, opt Options, result *Result) (d *walked, stop error) {
	defer func() {
		if r := recover(); r != nil {
			result.Fatal = &Problem{Code: "pdf-malformed", Message: "the reader could not continue past a defect in the file before the page tree was walked"}
			result.Pages, result.PageCount, result.Truncated = nil, 0, false
			d, stop = nil, errStopped
		}
	}()
	budget := &inflateBudget{total: opt.MaxInflateTotal, one: opt.MaxInflateOne}
	const unopened = "the file has no usable cross-reference, trailer or catalog, and scanning found none"
	doc, openErr := open(ctx, data, budget)
	if isDeadline(openErr) {
		return nil, endedAtDeadline(result, openedPastDeadline)
	}
	if doc == nil {
		message := unopened
		if isBound(openErr) {
			message = boundMessage
		}
		result.Fatal = &Problem{Code: "pdf-malformed", Message: message}
		return nil, errStopped
	}
	// The trailer was read: the encryption dictionary it names is read before
	// the catalog is looked for, a trailer that names none included.
	enc, err := doc.openEncryption()
	result.Encryption = enc
	if err != nil {
		if result.Encryption == nil {
			result.Encryption = &Encryption{}
		}
		result.Encryption.Opened = false
		if deadlineMet(ctx) != nil {
			// The deadline passed while the trailer's own objects were read:
			// that is the deadline, not a dictionary that cannot be read.
			return nil, endedAtDeadline(result, openedPastDeadline)
		}
		message := "the encryption dictionary could not be read, so the document was not opened"
		switch {
		case errors.Is(err, errPassword):
			message = "the document is encrypted and a user password is required"
		case !errors.Is(err, errMalformed):
			message = "the document is encrypted with a security handler or revision version 1 does not open"
		}
		result.Fatal = &Problem{Code: "pdf-encrypted", Message: message}
		return nil, errStopped
	}
	if openErr != nil {
		result.Fatal = &Problem{Code: "pdf-malformed", Message: unopened}
		return nil, errStopped
	}
	// A bound met finding the root ends the walk at the root's first check.
	pagesRoot := doc.pagesRoot()
	if pagesRoot == nil {
		if deadlineMet(ctx) != nil {
			return nil, endedAtDeadline(result, openedPastDeadline)
		}
		message := "the file names no page tree, and scanning found none"
		if doc.walkDefect() != "" {
			message = doc.walkDefect()
		}
		result.Fatal = &Problem{Code: "pdf-malformed", Message: message}
		return nil, errStopped
	}
	w := &walker{d: doc, ctx: ctx, visited: map[ref]bool{}, limit: opt.MaxPages}
	ending := w.node(pagesRoot, inherited{}, 0)
	switch ending {
	case walkDefect:
		result.Fatal = &Problem{Code: "pdf-malformed", Message: w.defect}
		return nil, errStopped
	case walkDeadline:
		result.PageCount = len(w.pages)
		return nil, endedAtDeadline(result, fmt.Sprintf("the deadline passed while the page tree was walked, after %d pages were counted", result.PageCount))
	case walkBound:
		result.Truncated = true
		result.Problems = append(result.Problems, Problem{Code: "pdf-pages-over-bound", Message: fmt.Sprintf("the document has more than %d pages; pages past the bound were not counted", opt.MaxPages)})
	}
	if len(w.pages) == 0 {
		result.Fatal = &Problem{Code: "pdf-malformed", Message: "the page tree holds no page"}
		result.Truncated = false
		return nil, errStopped
	}
	result.PageCount = len(w.pages)
	return &walked{doc: doc, pages: w.pages}, nil
}

var errStopped = errors.New("stopped")

// openedPastDeadline is the deadline met before the page tree was walked: in
// the cross-reference, the trailer, the encryption dictionary the trailer
// names, or the scan that rebuilds a damaged cross-reference.
const openedPastDeadline = "the deadline passed while the document was opened, before its page tree was walked"

// endedAtDeadline ends the walk at the deadline, as step 4 of the note has
// it: what was counted stands, the record is truncated, and timeout says
// where the deadline was met. It returns the stop the caller returns.
func endedAtDeadline(result *Result, message string) error {
	result.Truncated = true
	result.TimedOut = true
	result.Problems = append(result.Problems, Problem{Code: "timeout", Message: message})
	return errStopped
}

// boundMessage is the defect of a document opened or walked past a bound.
const boundMessage = "the file has a structure past a bound the reader holds, met while it was opened or its page tree walked"

type walked struct {
	doc   *Document
	pages []pageNode
}

// extractPages is step 5.
func extractPages(ctx context.Context, w *walked, opt Options, result *Result) {
	fontRefs := map[ref]*font{}
	for i, pn := range w.pages {
		number := i + 1
		if deadlineMet(ctx) != nil {
			result.TimedOut = true
			result.Truncated = true
			result.Problems = append(result.Problems, Problem{Code: "timeout", Message: notListed("the deadline had passed before page %d was extracted", number, len(w.pages))})
			return
		}
		w.doc.startPageWork()
		content, err := pageContent(w.doc, pn.dict)
		var pr pageResult
		if err == nil {
			remaining := opt.MaxTextBytes - result.TextBytes
			if remaining < 0 {
				remaining = 0
			}
			pr = w.doc.interpretPage(ctx, content, pn.resources, remaining, fontRefs)
			err = pr.err
		}
		if err != nil && deadlineMet(ctx) != nil && isDeadline(err) {
			result.TimedOut = true
			result.Truncated = true
			result.Problems = append(result.Problems, Problem{Code: "timeout", Message: notListed("the deadline passed while page %d was extracted", number, len(w.pages))})
			return
		}
		if err != nil {
			code, message := pageFailure(err, number)
			result.Pages = append(result.Pages, Page{Number: number, Status: PageFailed})
			result.Problems = append(result.Problems, Problem{Code: code, Message: message, Page: number})
			continue
		}
		if pr.cut {
			result.Truncated = true
			result.Problems = append(result.Problems, Problem{Code: "text-over-bound", Message: notListed(fmt.Sprintf("listing page %%d would take the text past %d bytes", opt.MaxTextBytes), number, len(w.pages)), Page: number})
			return
		}
		page := Page{Number: number}
		switch {
		case pr.text != "":
			page.Status, page.Text, page.Unmapped = PageOK, pr.text, pr.unmapped
		case pr.hasImage:
			page.Status = PageNeedsOCR
		default:
			page.Status = PageNoText
		}
		result.TextBytes += len(page.Text)
		result.Pages = append(result.Pages, page)
	}
}

// notListed completes a message with the pages it leaves unlisted.
func notListed(format string, number, last int) string {
	head := fmt.Sprintf(format, number)
	if number == last {
		return fmt.Sprintf("%s; page %d is not listed", head, number)
	}
	return fmt.Sprintf("%s; pages %d to %d are not listed", head, number, last)
}

// pageFailure maps the error that stopped a page to its code and message.
func pageFailure(err error, number int) (string, string) {
	switch {
	case errors.Is(err, errUnsupportedFilter):
		return "pdf-unsupported", fmt.Sprintf("the content of page %d uses a stream filter the reader does not implement", number)
	case errors.Is(err, errInflateBound):
		return "stream-over-bound", fmt.Sprintf("a stream of page %d inflates past the bound", number)
	case errors.Is(err, errTooManyOperators):
		return "pdf-page-failed", fmt.Sprintf("page %d has more operators than the reader interprets", number)
	case errors.Is(err, errContentUnread):
		return "pdf-page-failed", fmt.Sprintf("the content of page %d could not be read", number)
	case errors.Is(err, errStructureBound):
		return "pdf-page-failed", fmt.Sprintf("the content of page %d is past a structure bound the reader holds", number)
	default:
		return "pdf-page-failed", fmt.Sprintf("the content of page %d could not be interpreted", number)
	}
}

// Chars is how many Unicode scalar values a page's text holds.
func (p Page) Chars() int { return utf8.RuneCountInString(p.Text) }

// inherited are the page attributes a Pages node passes down.
type inherited struct {
	resources Dict
}

type pageNode struct {
	dict      Dict
	resources Dict
}

// pagesRoot is the page tree's root: the catalog's /Pages, or, for a file
// whose catalog lost it, a /Type /Pages node with no /Parent found by
// rebuilding the cross-reference.
func (d *Document) pagesRoot() Dict {
	if catalog := d.dictOf(d.trailer["Root"]); catalog != nil {
		if root := d.dictOf(catalog["Pages"]); root != nil {
			return root
		}
	}
	if !d.reconstructed {
		err := d.reconstruct()
		if err == nil {
			if catalog := d.dictOf(d.trailer["Root"]); catalog != nil {
				if root := d.dictOf(catalog["Pages"]); root != nil {
					return root
				}
			}
		}
		if isDeadline(err) {
			// The walk ends at the deadline; the caller reads it from the
			// context.
			return nil
		}
		if d.noteBound(err); d.bound != nil {
			return nil
		}
	}
	return d.findPagesRoot()
}

// walkEnding is how a page-tree walk ended.
type walkEnding int

const (
	walkComplete walkEnding = iota
	walkBound
	walkDeadline
	walkDefect
)

type walker struct {
	d       *Document
	ctx     context.Context
	visited map[ref]bool
	nodes   int
	limit   int // maxPages: a page found past it ends the walk
	pages   []pageNode
	defect  string
}

// node walks one page-tree node depth-first, the deadline checked before
// it. A node reached twice is walked once. A bound met reading the tree, an
// object stream that could not be decoded, or a node's /Kids that is present
// and cannot be read or is not an array, ends the walk at a defect: skipping
// it would count the pages around it as though they were all the document
// holds.
func (w *walker) node(node Dict, inh inherited, depth int) walkEnding {
	if deadlineMet(w.ctx) != nil {
		return walkDeadline
	}
	if depth > maxPageTreeDepth || w.nodes >= maxPageTreeNodes {
		w.defect = "the page tree is deeper or larger than the reader walks"
		return walkDefect
	}
	w.nodes++
	if res := w.d.dictOf(node["Resources"]); res != nil {
		inh.resources = res
	}
	typ, _ := w.d.nameOf(node["Type"])
	// A /Kids that is null is one that is absent.
	kids, kidsRead := w.d.resolveRead(node["Kids"])
	if defect := w.d.walkDefect(); defect != "" {
		w.defect = defect
		return walkDefect
	}
	if typ == "Page" || (kids == nil && kidsRead && typ != "Pages") {
		if len(w.pages) == w.limit {
			return walkBound
		}
		w.pages = append(w.pages, pageNode{dict: node, resources: inh.resources})
		return walkComplete
	}
	if !kidsRead {
		w.defect = "a page-tree node's /Kids could not be read"
		return walkDefect
	}
	kidArray, isArray := kids.(Array)
	if kids != nil && !isArray {
		w.defect = "a page-tree node's /Kids is not an array"
		return walkDefect
	}
	for _, kid := range kidArray {
		if r, ok := kid.(ref); ok {
			if w.visited[r] {
				continue
			}
			w.visited[r] = true
		}
		child := w.d.dictOf(kid)
		if child == nil {
			w.defect = "a page-tree node could not be read"
			return walkDefect
		}
		if ending := w.node(child, inh, depth+1); ending != walkComplete {
			return ending
		}
	}
	return walkComplete
}

// findPagesRoot looks, after reconstruction, for a /Type /Pages node with
// no /Parent.
func (d *Document) findPagesRoot() Dict {
	nums := make([]int, 0, len(d.xref))
	for num := range d.xref {
		nums = append(nums, num)
	}
	sortInts(nums)
	for _, num := range nums {
		// Each step of this loop may resolve a whole object.
		if d.deadlineNow() {
			return nil
		}
		e := d.xref[num]
		// An object the reader can see is not a page tree without parsing it
		// is not parsed, as the catalog the rebuild looks for is not: without
		// that, this search reads and holds every object the file declares.
		// Only an object the window settles is skipped; one it cannot is
		// resolved, as is one inside an object stream, which has no bytes of
		// the file to look at.
		if !e.inStream && d.notOfType(e, "Pages") {
			continue
		}
		dict, ok := d.resolve(ref{num, e.gen}).(Dict)
		if !ok {
			continue
		}
		if dict["Type"] == Name("Pages") {
			if _, hasParent := dict["Parent"]; !hasParent {
				return dict
			}
		}
	}
	return nil
}

// errContentUnread is a page whose /Contents is present and is not content
// the reader could read: a reference to an object it could not read, or a
// value other than a stream or an array of streams.
var errContentUnread = errors.New("the page's content could not be read")

// pageContent concatenates a page's content streams with a newline
// between, as the specification requires them to be read. A page whose
// /Contents is absent or null has empty content.
func pageContent(d *Document, page Dict) (out []byte, err error) {
	defer func() {
		if r := recover(); r != nil {
			out, err = nil, errPageDefect
		}
	}()
	appendStream := func(v object) error {
		// One element of a /Contents array is a whole stream to decode, which
		// may be as long as the file: the deadline is read before each of
		// them, so that a page whose /Contents names one stream a thousand
		// times ends at the deadline and not a thousand decodes after it.
		if err := deadlineMet(d.ctx); err != nil {
			return fmt.Errorf("the deadline passed while a page's content streams were read: %w", err)
		}
		o, read := d.resolveRead(v)
		s, ok := o.(*stream)
		if !read || !ok {
			return errContentUnread
		}
		if err := d.chargeWork(int64(len(s.raw))); err != nil {
			// No stream went past an inflate bound, and the bytes read are
			// past what reading one page may cost.
			return err
		}
		data, err := d.decodeStream(s, false, heldByPage)
		if err != nil {
			return err
		}
		if len(out)+len(data)+1 > maxContentBytes {
			// No stream went past an inflate bound: the page's content is
			// past a structure bound.
			return structureBound("a page's content streams past %d bytes", maxContentBytes)
		}
		out = append(out, data...)
		out = append(out, '\n')
		return nil
	}
	contents, read := d.resolveRead(page["Contents"])
	if !read {
		return nil, errContentUnread
	}
	switch c := contents.(type) {
	case nil:
	case *stream:
		if err := appendStream(c); err != nil {
			return nil, err
		}
	case Array:
		for _, item := range c {
			if err := appendStream(item); err != nil {
				return nil, err
			}
		}
	default:
		return nil, errContentUnread
	}
	return out, nil
}
