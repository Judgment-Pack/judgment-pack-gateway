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
)

// Extract reads the document within the options and the context's
// deadline. It never panics on input: a defect met while the document is
// opened or its page tree walked is Fatal, and one met on a page fails
// that page.
//
// A reading of a document's pages stands on the cross-reference the reader
// had when it began. Reading an object may rebuild that cross-reference --
// the file's own was damaged where it pointed -- and an object number then
// names other bytes: the nodes walked, the resources they carry, the fonts
// built from them and the text taken through those fonts were all read under
// a cross-reference the document no longer has. Such a reading is begun again
// under the rebuilt one rather than mended piece by piece, so that what the
// record carries was read under one cross-reference throughout. A document is
// rebuilt at most once -- reconstruct records that it ran and every caller of
// it reads that record first -- so the second reading stands; the inflate
// budget is not given back, since it is what reading this document has cost.
func Extract(ctx context.Context, data []byte, opt Options) *Result {
	result := &Result{}
	doc, stop := openDocument(ctx, data, opt, result)
	if stop != nil {
		return result
	}
	encryption := result.Encryption
	for again := 0; ; again++ {
		w, generation, stop := walkPages(ctx, doc, opt, result)
		if stop == nil {
			extractPages(ctx, w, opt, result)
		}
		if doc.generation == generation {
			return result
		}
		if again > 0 {
			// A document rebuilt twice is one the reader cannot hold to one
			// cross-reference, and pages read under two of them are not the
			// document's pages.
			*result = Result{Encryption: encryption, Fatal: &Problem{Code: "pdf-malformed", Message: "the file's cross-reference was rebuilt again while its pages were read, and the reader holds no reading of it under one cross-reference"}}
			return result
		}
		// The cross-reference was rebuilt: the encryption dictionary its
		// trailer names may be another dictionary, deriving another key, and
		// the content the pages hold is encrypted under the one the rebuilt
		// document names. Nothing of the pages is read under the handler the
		// old one gave.
		*result = Result{}
		if stop := establishEncryption(ctx, doc, result); stop != nil {
			return result
		}
		encryption = result.Encryption
	}
}

// openDocument is the first part of step 4: open the document and read the
// encryption dictionary the trailer names. It returns the document, or a
// non-nil stop when the adapter goes straight to step 7.
func openDocument(ctx context.Context, data []byte, opt Options, result *Result) (doc *Document, stop error) {
	defer func() {
		if r := recover(); r != nil {
			result.Fatal = &Problem{Code: "pdf-malformed", Message: "the reader could not continue past a defect in the file before the page tree was walked"}
			result.Pages, result.PageCount, result.Truncated = nil, 0, false
			doc, stop = nil, errStopped
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
	if stop := establishEncryption(ctx, doc, result); stop != nil {
		return nil, stop
	}
	if openErr != nil {
		result.Fatal = &Problem{Code: "pdf-malformed", Message: unopened}
		return nil, errStopped
	}
	return doc, nil
}

// establishEncryption reads the encryption dictionary the trailer names and
// installs the handler the document is read through, under the
// cross-reference the document has now. Reading that dictionary may rebuild
// the cross-reference, and the dictionary the rebuilt trailer names may be
// another one deriving another key: it is read again under the new one, and
// without the handler the old one gave, so that nothing of the document is
// read through a key its own cross-reference does not name. A document is
// rebuilt once, so one reading after the rebuild stands.
func establishEncryption(ctx context.Context, doc *Document, result *Result) error {
	for again := 0; ; again++ {
		generation := doc.generation
		doc.crypt = nil
		enc, err := doc.openEncryption()
		if doc.generation != generation && again == 0 {
			continue
		}
		result.Encryption = enc
		if err == nil {
			return nil
		}
		if result.Encryption == nil {
			result.Encryption = &Encryption{}
		}
		result.Encryption.Opened = false
		if ctx.Err() != nil {
			// The deadline passed while the trailer's own objects were read:
			// that is the deadline, not a dictionary that cannot be read.
			return endedAtDeadline(result, openedPastDeadline)
		}
		message := "the encryption dictionary could not be read, so the document was not opened"
		switch {
		case errors.Is(err, errPassword):
			message = "the document is encrypted and a user password is required"
		case !errors.Is(err, errMalformed):
			message = "the document is encrypted with a security handler or revision version 1 does not open"
		}
		result.Fatal = &Problem{Code: "pdf-encrypted", Message: message}
		return errStopped
	}
}

// walkPages is the rest of step 4: find the page tree and count its pages. It
// returns the pages to extract and the generation of the cross-reference the
// walk stood on, so that the caller can tell a reading that outlived it.
func walkPages(ctx context.Context, doc *Document, opt Options, result *Result) (d *walked, generation int, stop error) {
	defer func() {
		if r := recover(); r != nil {
			result.Fatal = &Problem{Code: "pdf-malformed", Message: "the reader could not continue past a defect in the file before the page tree was walked"}
			result.Pages, result.PageCount, result.Truncated = nil, 0, false
			d, stop = nil, errStopped
		}
	}()
	// A bound met finding the root ends the walk at the root's first check.
	// Looking for the root may rebuild the cross-reference, and the catalog
	// that named it is then not the document's catalog: the root is looked
	// for again under the one the rebuild produced, so that this walk is of
	// the tree the rebuilt catalog names. The generation returned is still
	// the one the walk began on, so that the caller reads the document again
	// from the top -- the encryption dictionary the rebuilt trailer names
	// included, which is not this walk's to establish.
	generation = doc.generation
	pagesRoot, rootRef := doc.pagesRoot()
	if doc.generation != generation {
		pagesRoot, rootRef = doc.pagesRoot()
	}
	if pagesRoot == nil {
		if ctx.Err() != nil {
			return nil, generation, endedAtDeadline(result, openedPastDeadline)
		}
		message := "the file names no page tree, and scanning found none"
		if doc.walkDefect() != "" {
			message = doc.walkDefect()
		}
		result.Fatal = &Problem{Code: "pdf-malformed", Message: message}
		return nil, generation, errStopped
	}
	w := &walker{d: doc, ctx: ctx, path: map[ref]bool{}, limit: opt.MaxPages}
	if rootRef != (ref{}) {
		// The root stands under itself as any other node does: a tree whose
		// root is among its own kids holds the pages below it once.
		w.path[rootRef] = true
	}
	ending := w.node(pagesRoot, inherited{}, 0)
	switch ending {
	case walkDefect:
		result.Fatal = &Problem{Code: "pdf-malformed", Message: w.defect}
		return nil, generation, errStopped
	case walkDeadline:
		result.PageCount = len(w.pages)
		return nil, generation, endedAtDeadline(result, fmt.Sprintf("the deadline passed while the page tree was walked, after %d pages were counted", result.PageCount))
	case walkBound:
		result.Truncated = true
		result.Problems = append(result.Problems, Problem{Code: "pdf-pages-over-bound", Message: fmt.Sprintf("the document has more than %d pages; pages past the bound were not counted", opt.MaxPages)})
	}
	if len(w.pages) == 0 {
		result.Fatal = &Problem{Code: "pdf-malformed", Message: "the page tree holds no page"}
		result.Truncated = false
		return nil, generation, errStopped
	}
	result.PageCount = len(w.pages)
	return &walked{doc: doc, pages: w.pages}, generation, nil
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
	for i, pn := range w.pages {
		number := i + 1
		if ctx.Err() != nil {
			result.TimedOut = true
			result.Truncated = true
			result.Problems = append(result.Problems, Problem{Code: "timeout", Message: notListed("the deadline had passed before page %d was extracted", number, len(w.pages))})
			return
		}
		content, err := pageContent(w.doc, pn.dict)
		var pr pageResult
		if err == nil {
			remaining := opt.MaxTextBytes - result.TextBytes
			if remaining < 0 {
				remaining = 0
			}
			pr = w.doc.interpretPage(ctx, content, pn.resources, remaining)
			err = pr.err
		}
		if err != nil && ctx.Err() != nil && errors.Is(err, ctx.Err()) {
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
// rebuilding the cross-reference. It returns the reference the catalog named
// it by, so that the walk can hold the root under itself as it holds every
// other node; a root found by scanning is returned with no reference, since
// the search hands back the node and not the number it was found under.
func (d *Document) pagesRoot() (Dict, ref) {
	named := func() (Dict, ref) {
		catalog := d.dictOf(d.trailer["Root"])
		if catalog == nil {
			return nil, ref{}
		}
		root := d.dictOf(catalog["Pages"])
		if root == nil {
			return nil, ref{}
		}
		if r, ok := catalog["Pages"].(ref); ok {
			return root, r
		}
		return root, ref{}
	}
	if root, r := named(); root != nil {
		return root, r
	}
	if !d.reconstructed {
		err := d.reconstruct()
		if err == nil {
			if root, r := named(); root != nil {
				return root, r
			}
		}
		if isDeadline(err) {
			// The walk ends at the deadline; the caller reads it from the
			// context.
			return nil, ref{}
		}
		// A bound met rebuilding is the file's, as it is wherever an object
		// read sends the reader scanning.
		if d.noteFileBound(err); d.fileBound != nil {
			return nil, ref{}
		}
	}
	return d.findPagesRoot(), ref{}
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
	d   *Document
	ctx context.Context
	// path holds the nodes the walk stands under, so that a node that is its
	// own ancestor is walked once. A node named twice by a tree that holds no
	// cycle is two nodes, and a page named twice is two pages: that is what
	// the tree says, and what a viewer shows.
	path   map[ref]bool
	nodes  int
	limit  int // maxPages: a page found past it ends the walk
	pages  []pageNode
	defect string
}

// node walks one page-tree node depth-first, the deadline checked before
// it. A node under itself is not walked again. A bound met reading the tree,
// an object stream that could not be decoded, or a node's /Kids that is
// present and cannot be read or is not an array, ends the walk at a defect:
// skipping it would count the pages around it as though they were all the
// document holds.
func (w *walker) node(node Dict, inh inherited, depth int) walkEnding {
	if w.ctx.Err() != nil {
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
		r, isRef := kid.(ref)
		if isRef {
			if w.path[r] {
				// A node under itself: what lies below it is what is being
				// walked, and walking it again would not end.
				continue
			}
			w.path[r] = true
		}
		child := w.d.dictOf(kid)
		if child == nil {
			// Why it could not be read, where reading it met something the
			// reader can name: a bound, or a stream of objects it could not
			// take the node out of.
			w.defect = "a page-tree node could not be read"
			if defect := w.d.walkDefect(); defect != "" {
				w.defect = defect
			}
			return walkDefect
		}
		ending := w.node(child, inh, depth+1)
		if isRef {
			delete(w.path, r)
		}
		if ending != walkComplete {
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
		dict, ok := d.resolve(ref{num, d.xref[num].gen}).(Dict)
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
		o, read := d.resolveRead(v)
		s, ok := o.(*stream)
		if !read || !ok {
			return errContentUnread
		}
		data, err := d.decodeStream(s, false)
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
