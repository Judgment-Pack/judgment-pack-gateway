package pdf

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"math"
	"regexp"
	"strconv"
	"time"
)

const (
	// maxHeaderSearch is how far into the file the %PDF- header may lie.
	maxHeaderSearch = 1024
	// maxTrailerSearch is how far from the end startxref is looked for.
	maxTrailerSearch = 2048
	// maxXrefSections bounds the /Prev and /XRefStm chain.
	maxXrefSections = 64
	// maxXrefEntries bounds the entries one cross-reference section may
	// declare, and the object numbers a document may have.
	maxXrefEntries = 1 << 22
	// maxObjects bounds the indirect objects parsed in one document.
	maxObjects = 1 << 18
	// maxRefDepth bounds a chain of references resolving to references and
	// the indirect objects being read recursively, including stream lengths.
	maxRefDepth = 32
	// maxObjStmObjects bounds the objects one object stream declares.
	maxObjStmObjects = 1 << 16
	// maxScanObjects bounds what reconstruction by scanning records.
	maxScanObjects = 1 << 18
	// entriesPerCheck is how often the deadline is consulted while a document
	// is opened: once per this many cross-reference entries, scanned objects
	// or trailers, so the clock is read on a cadence and not per byte.
	entriesPerCheck = 4096
	// endstreamBlock is the bytes searched for the "endstream" of a stream
	// whose /Length does not locate one; the file's own "endstream" offsets,
	// indexed one per block of that size, answer beyond it.
	endstreamBlock = 4096
	// parsedBytesPerFileByte is how many bytes of parsed objects a document
	// may hold for each byte of the file, and for each byte the file's streams
	// have inflated. What a file costs to hold is not its length: the smallest
	// dictionary a file can spell, "<</A 1>>", is eight bytes of file and a Go
	// map of about 370 bytes held, and a pair of coordinates, "[0 0]", is five
	// bytes and about a hundred. This many bytes for each byte read admits the
	// densest of those shapes several times over while it bounds a file whose
	// objects hold the same bytes over and over: "k 0 obj (" with no closing
	// parenthesis gives every object a copy of the rest of the file, and what
	// the reader holds then grows with the square of the file.
	parsedBytesPerFileByte = 160
	// maxParsedBytesHeld is what a document's parsed objects may hold whatever
	// its length: the multiple above bounds a small file, and this bounds
	// every file, so that the reader's memory has a ceiling and not only a
	// ratio. A file large enough to reach it is read as far as it and no
	// further, as one past any other structure bound is. It is set above what
	// an ordinary document of the densest shape costs -- five hundred pages of
	// two thousand one-member dictionaries each, which an eight-megabyte file
	// holds, are charged about 570 MB -- so that a document of that shape is
	// read whole. It is not a bound on overlapping structure alone: a document
	// that holds a great deal without overlapping anything meets it too, which
	// is what the pages above are measured against, and a document is as
	// likely to be stopped first by a bound on one of its structures.
	maxParsedBytesHeld = 1 << 30
)

// What holding a parsed value costs, in the bytes this package charges for
// it. Each is at or above what Go retains for that shape on the platform the
// reader was measured on -- the retained-heap delta of a hundred thousand
// values of each -- so that the charge bounds the memory and not the other
// way about; TestBoundsChargeCoversWhatIsRetained holds them to that.
const (
	// parsedSlotBytes is one element of an array: the interface pair in the
	// backing array, with the room append leaves beyond the length.
	parsedSlotBytes = 24
	// parsedArrayBytes is an array of no elements: the slice header the
	// interface holding it points at.
	parsedArrayBytes = 24
	// parsedDictBytes is a dictionary of no members: Go's map, whose smallest
	// form is a header and a whole group of slots.
	parsedDictBytes = 384
	// parsedMemberBytes is one member of a dictionary beyond its name: its
	// slot in the map and its share of what the map grows by.
	parsedMemberBytes = 96
	// parsedStringBytes is the header of a name or a string, beyond the bytes
	// it carries, which are charged rounded up to what Go allocates for them.
	parsedStringBytes = 24
	// parsedValueBytes is the allocation a number, a boolean or a reference
	// makes when it is held in an interface.
	parsedValueBytes = 16
)

// grownBytes is what a buffer a builder appended into holds: a slice grown
// by appending takes more room than the bytes put in it, half as much again
// past the doubling the small sizes get, and the allocator rounds that up
// again. A value read from a file is built that way, so what it holds is
// charged that way, wherever the charge is taken.
func grownBytes(n int64) int64 { return goSizeClass(n + n/4) }

// goSizeClass is at or above what Go's allocator gives a block of n bytes:
// its size classes are finer than the powers of two up to the largest of
// them, and a block past that is rounded up to whole pages. A slice grown by
// appending reaches the same figures, since append doubles what it holds
// while it is small.
func goSizeClass(n int64) int64 {
	if n <= 0 {
		return 0
	}
	if n <= 8 {
		return 8
	}
	if n <= 32<<10 {
		size := int64(8)
		for size < n {
			size *= 2
		}
		return size
	}
	const page = 8 << 10
	return (n + page - 1) / page * page
}

// xrefEntry says where an object is: at an offset in the file, or inside
// an object stream at an index.
type xrefEntry struct {
	offset   int64
	inStream bool
	stmNum   int
	stmIndex int
	gen      int
}

// Document is an opened PDF: the file, its cross-reference, its trailer,
// and the caches that keep any object from being parsed twice.
type Document struct {
	data []byte
	// ctx carries the extraction's deadline into opening the document: the
	// loops whose work grows with the file read it on the cadence below. It
	// is the caller's context for a document open() built, and nil for one a
	// test builds by hand, where the deadline never passes.
	ctx context.Context
	// checks counts what has been read since the deadline was last consulted.
	checks int
	// endstream holds, for each block of endstreamBlock bytes of the file, the
	// offset of the first "endstream" at or after that block's start, or -1
	// where the file has none; nil until a stream's /Length first fails to
	// locate one.
	endstream []int
	xref      map[int]xrefEntry
	trailer   Dict
	// reconstructed is set when the cross-reference was rebuilt by
	// scanning the file for objects.
	reconstructed bool
	cache         map[int]object
	// objStms caches parsed object streams by their object number; nil
	// for one that could not be read.
	objStms map[int]*objStm
	// objStmHeaders keeps the order and offsets each object stream's
	// header declared.
	objStmHeaders map[int]*objStmParsed
	parsed        int
	// parsedBytes is what everything the document holds costs to hold: its
	// objects, its trailer, the headers of its object streams, and the work
	// the rebuild does on its way to them. It is released only where the
	// storage itself is given up, since a value dropped from the cache may
	// still be held by the walk that asked for it.
	parsedBytes int64
	// headTypes keeps what reading an object's head settled about it, by the
	// offset it lies at: a cross-reference may name one offset for many
	// object numbers, and the head is read once for the offset.
	headTypes map[int64]headType
	// pageWork is what has been read and decoded for the page being
	// extracted, and pageWorking says a page is being extracted at all: the
	// same streams are read while the document is opened, where no page
	// answers for them.
	pageWork    int64
	pageWorking bool
	crypt       *cryptHandler
	// budget is the inflation budget shared by every stream of the document.
	budget *inflateBudget
	// resolving guards against a reference cycle through object streams.
	resolving map[int]bool
	// fontBudget counts what the document's fonts hold, and cmaps the CMap
	// streams read, by stream, nil for one not used.
	fontBudget fontBudget
	cmaps      map[*stream]*cmap
	// fontRefs holds the fonts built from an object by the reference that
	// named it, so that a font shared by pages is built once. It is dropped
	// wherever the object cache is: a rebuilt cross-reference gives an object
	// number other bytes, and a font built from the bytes a number named
	// before is not the font the page names now.
	fontRefs map[ref]*font
	// generation counts the cross-references the document's objects have been
	// read under. It is advanced wherever the reader drops what it read under
	// one, so that a reading of the document's pages that began under an
	// earlier one can tell that what it gathered no longer stands.
	generation int
	// reading is how many reads are under way, and readGeneration the
	// cross-reference the outermost of them began on. What a read publishes
	// -- an object, a font, a CMap, a header, a bound -- belongs to the
	// cross-reference its own operation began on, however many objects it
	// resolves on the way: a read that met a rebuild half way through is
	// abandoned whole, and the objects it goes on to touch are not the
	// rebuilt document's reading of them.
	reading        int
	readGeneration int
	// scanning is set while the cross-reference is being rebuilt by scanning
	// the file. The reads the scan makes are its own -- begun again under the
	// cross-reference it is building, whatever read it was called from -- and
	// what they meet is the file's: see reconstruct and noteBoundAt.
	scanning bool
	// bound is the first structure or inflate bound met while reading an
	// object the cross-reference named, which leaves that object unread; the
	// walk ends at it. It belongs to that cross-reference: a rebuild drops it,
	// and an object still past a bound under the new one meets it again.
	bound error
	// fileBound is the first bound met reading the file itself rather than an
	// object of one cross-reference: the objects a scan of the whole file
	// finds, the objects read in one document, a bound met while the
	// cross-reference was being rebuilt. A rebuild does not drop it -- it is
	// no defect of the cross-reference being replaced -- and the walk ends at
	// it as it ends at the other.
	fileBound error
	// undecoded is the first error met loading a stream the cross-reference
	// names as an object stream -- a stream that cannot be decoded, or that is
	// not an object stream -- which leaves the objects it holds unread; the
	// walk ends at it too.
	undecoded error
	// noObjects is the failure of a scan that found no object in the file at
	// all. Such a scan replaces the cross-reference with an empty one, so the
	// document holds no object under any number: that is the file's own
	// failure and not one cross-reference's, as a bound the scan met is, and
	// a rebuild does not drop it. The walk ends at it, and a document is
	// scanned once, so every reading made after it refuses the file.
	noObjects error
	// scanUnfinished is the failure of a scan the reader could not finish: a
	// defect it could not continue past was met after it had replaced the
	// cross-reference and before it had written the whole of the one it was
	// building. What the document holds is the part of a cross-reference the
	// scan had reached, which is a reading of neither the file nor the
	// cross-reference it replaced: that is the file's own failure, as a scan
	// that found no object is, and a rebuild does not drop it. The walk ends
	// at it, and a document is scanned once, so every reading made after it
	// refuses the file.
	scanUnfinished error
}

// unread is what the cache holds for an object the reader could not read,
// so that it is not read again and is told apart from the null object.
type unread struct{ err error }

// objStm is a parsed object stream: the object numbers it holds, in order,
// with the offset of each within its decoded data.
type objStm struct {
	data    []byte
	offsets map[int]int
}

var errMalformed = errors.New("malformed")

// malformed wraps a reason as a structural failure of the document.
func malformed(format string, args ...any) error {
	return fmt.Errorf("%w: %s", errMalformed, fmt.Sprintf(format, args...))
}

// malformedBy is malformed with the error that caused it kept, so that a
// bound under it is still a bound.
func malformedBy(err error, format string, args ...any) error {
	return fmt.Errorf("%w: %s: %w", errMalformed, fmt.Sprintf(format, args...), err)
}

// isBound reports whether err is a bound met rather than damage: a structure
// past a structure bound, or a stream past the inflate bound. Damage may be
// recovered from by scanning the file; a bound is not.
func isBound(err error) bool {
	return errors.Is(err, errStructureBound) || errors.Is(err, errInflateBound)
}

// noteBound keeps the first bound among the errors that left an object unread.
func (d *Document) noteBound(err error) {
	if d.bound == nil && isBound(err) {
		d.bound = err
	}
}

// noteBoundAt is noteBound for a read that began under the generation given.
// A read whose cross-reference was replaced while it ran says nothing about
// the document that replaced it: its bound goes with the objects it read.
//
// A bound the scan that rebuilds the cross-reference met is the file's own,
// wherever in the scan it was met: the scan reads the file, not the objects
// of one cross-reference, and rebuilding does not drop what it met.
func (d *Document) noteBoundAt(generation int, err error) {
	if d.scanning {
		d.noteFileBound(err)
		return
	}
	if d.generation == generation {
		d.noteBound(err)
	}
}

// noteFileBound keeps the first bound met reading the file rather than an
// object of one cross-reference. Rebuilding the cross-reference does not drop
// it: the file is the same file.
func (d *Document) noteFileBound(err error) {
	if d.fileBound == nil && isBound(err) {
		d.fileBound = err
	}
}

// undecodedMessage is the defect of a document with an object stream that
// could not be decoded, met while it was opened or its page tree walked.
const undecodedMessage = "the file has an object stream the reader could not decode, met while it was opened or its page tree walked"

// noObjectsMessage is the defect of a document whose cross-reference was
// rebuilt by a scan that found no object in the file at all: the document
// holds none, and what was read under the cross-reference the scan replaced
// is not a reading of it.
const noObjectsMessage = "scanning the file for objects found none, and the cross-reference the scan replaced is gone"

// scanUnfinishedMessage is the defect of a document whose scan could not be
// finished: the cross-reference it was writing is written in part, and the one
// it replaced is gone. It is a failure of its own and not the failure of a
// scan that found no object: the scan may have found many, and a record that
// said none were found would say of the file something the reader did not
// meet.
const scanUnfinishedMessage = "scanning the file for objects could not be finished, and the cross-reference the scan replaced is gone"

// walkDefect is the message of the defect a walk ends at, a bound first, or
// "" when reading objects has met none.
func (d *Document) walkDefect() string {
	switch {
	case d.bound != nil, d.fileBound != nil:
		return boundMessage
	case d.noObjects != nil:
		return noObjectsMessage
	case d.scanUnfinished != nil:
		return scanUnfinishedMessage
	case d.undecoded != nil:
		return undecodedMessage
	}
	return ""
}

// beginRead marks an operation that reads objects: the cross-reference it
// begins on is the one everything it publishes belongs to, and an operation
// nested inside another keeps the outer one's. The returned function ends it.
func (d *Document) beginRead() func() {
	if d.reading == 0 {
		d.readGeneration = d.generation
	}
	d.reading++
	return func() { d.reading-- }
}

// readingGeneration is the cross-reference the read under way began on, and
// the document's own where none is.
func (d *Document) readingGeneration() int {
	if d.reading == 0 {
		return d.generation
	}
	return d.readGeneration
}

// scanEnded is what a scan leaves behind where it ends after it has begun
// writing its own cross-reference and before it has finished it: the entries
// it wrote stand, since what it reached is what it read of the file, and
// nothing read under the cross-reference it replaced does. Replacement and
// invalidation are one step, and this is the second half of it for the ways
// out that are not the scan's own end.
//
// The generation is not advanced here, and the failures of the objects being
// dropped are not: a scan that ended at a bound ended before it replaced the
// cross-reference this document will be read under, and the reading that
// meets the failure it left is the reading that began before it. What ends
// such a reading is the failure itself -- a bound the scan met, which is the
// file's own -- or the deadline, at which every route ends.
func (d *Document) scanEnded(err error) error {
	d.dropCachedObjects()
	return err
}

// forgetObjects drops everything the reader holds of the objects a
// cross-reference named: the objects themselves, the object streams they were
// read out of, and the fonts and CMaps built from them. It is called wherever
// that cross-reference is replaced, since an object number then names other
// bytes, and an object, a stream of objects, a font or a CMap held under a
// number is the bytes that number named before.
//
// It advances the generation, which is how a reading of the document knows
// that the cross-reference under which it began is not the one the document
// has now.
func (d *Document) forgetObjects() {
	d.generation++
	d.dropCachedObjects()
	// The failures of the objects being dropped go with them: a bound met in
	// an object the old cross-reference named, or a stream of objects it
	// could not decode, is a defect of a document this one no longer is, and
	// the same object read again under the new one will meet it again if it
	// is still there. What is not given back is what reading the file has
	// cost -- the inflate budget, the objects counted, the font budget --
	// since a file that made the reader read it twice has spent it twice.
	d.bound = nil
	d.undecoded = nil
}

// dropCachedObjects drops what the reader holds of the objects it has read,
// without saying that they were read under a cross-reference the document no
// longer has: the same cross-reference names the same objects, and reading
// one again finds what it found before. Installing the security handler drops
// them this way -- what was read before it was read undecrypted -- and so
// does the end of a rebuild, which is one replacement and not two.
func (d *Document) dropCachedObjects() {
	d.cache = map[int]object{}
	d.objStms = map[int]*objStm{}
	d.objStmHeaders = nil
	d.fontRefs = nil
	d.cmaps = nil
}

// deadlinePassed reports whether the deadline has passed, reading the clock
// once every entriesPerCheck calls: a loop over a file's cross-reference
// entries or scanned objects consults it without a read of its own per entry.
func (d *Document) deadlinePassed() bool {
	d.checks++
	if d.checks%entriesPerCheck != 0 {
		return false
	}
	return d.deadlineNow()
}

// deadlineNow reads the deadline, for a loop each of whose steps parses or
// resolves a whole object: there the read is small beside the step.
func (d *Document) deadlineNow() bool { return deadlineMet(d.ctx) != nil }

// deadlineMet is the one reading of a deadline this package makes, and is
// what every check of it goes through. A context's error is set by a timer
// the runtime schedules, which may not have run: the clock is read as well,
// so that a deadline the clock has reached stops the work whether or not the
// context has caught up. The error is the context's own where it has one, and
// the deadline's where the clock decided; nil is a deadline still to come, or
// a context that declares none.
func deadlineMet(ctx context.Context) error {
	if ctx == nil {
		return nil
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if at, ok := ctx.Deadline(); ok && !time.Now().Before(at) {
		return context.DeadlineExceeded
	}
	return nil
}

// deadline is the error a loop ends at when the deadline has passed. It is
// neither damage nor a bound: the run ends at the deadline, as it does when
// the deadline passes while the page tree is walked.
func (d *Document) deadline() error {
	err := deadlineMet(d.ctx)
	if err == nil {
		err = context.DeadlineExceeded
	}
	return fmt.Errorf("the deadline passed while the document was opened: %w", err)
}

// isDeadline reports whether err is the deadline met while the document was
// opened.
func isDeadline(err error) bool {
	return errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled)
}

// errNoCatalog is a document whose trailer, read or rebuilt, names no
// catalog: open returns it with the document, whose encryption dictionary is
// read before the document is refused.
var errNoCatalog = fmt.Errorf("%w: no catalog: the trailer names no /Root and scanning found none", errMalformed)

// open reads the cross-reference and the trailer, rebuilding both by
// scanning when the file's own are damaged, within the context's deadline. A
// bound met while reading them is returned, not rebuilt from, and so is a
// deadline met reading them. It does not open encryption; the caller does,
// once it has read the trailer. A trailer that names no catalog is
// errNoCatalog, returned with the document.
func open(ctx context.Context, data []byte, budget *inflateBudget) (*Document, error) {
	header := bytes.Index(data[:min(len(data), maxHeaderSearch)], []byte("%PDF-"))
	if header < 0 {
		return nil, malformed("no %%PDF- header in the first %d bytes", maxHeaderSearch)
	}
	// Offsets in the file are relative to the header, which some writers
	// leave junk in front of.
	data = data[header:]
	d := &Document{ctx: ctx, data: data, xref: map[int]xrefEntry{}, trailer: Dict{}, cache: map[int]object{}, objStms: map[int]*objStm{}, budget: budget, resolving: map[int]bool{}}
	if err := d.readXref(); err != nil {
		if isBound(err) || isDeadline(err) {
			return nil, err
		}
		if !d.reconstructed {
			// Everything read from the cross-reference now being thrown away
			// goes with it, the objects it named and what was built from
			// them, and so does what was met while it was read: a bound or an
			// object stream that could not be decoded is a defect of a
			// cross-reference this document no longer has, and it would
			// otherwise end the walk of a page tree the rebuild recovers
			// whole.
			d.xref = map[int]xrefEntry{}
			d.trailer = Dict{}
			d.forgetObjects()
			d.headTypes = nil
			// Opening's abandoned cross-reference is the only owner here:
			// neither a walk nor a page can hold its objects yet. Only this
			// opening reset releases the parsed storage charge.
			d.parsedBytes = 0
			if err := d.reconstruct(); err != nil {
				return nil, err
			}
		}
		// A rebuild that already ran -- from an object read while the
		// cross-reference was being read -- scanned the whole file, and what
		// it found is this document's cross-reference. Scanning the same
		// bytes again would find the same objects and charge the file for
		// them twice, so a document is rebuilt once however its opening goes.
	}
	if _, ok := d.trailer["Root"]; !ok {
		// A trailer without a catalog: rebuild and look for one.
		if !d.reconstructed {
			if err := d.reconstruct(); err != nil {
				return nil, err
			}
		}
		if _, ok := d.trailer["Root"]; !ok {
			return d, errNoCatalog
		}
	}
	return d, nil
}

// readXref follows startxref through every section.
func (d *Document) readXref() error {
	tail := d.data
	if len(tail) > maxTrailerSearch {
		tail = tail[len(tail)-maxTrailerSearch:]
	}
	i := bytes.LastIndex(tail, []byte("startxref"))
	if i < 0 {
		return malformed("no startxref")
	}
	lex := newLexer(tail, i+len("startxref"))
	t, err := lex.next()
	if err != nil || t.kind != tokInteger || t.i < 0 || t.i >= int64(len(d.data)) {
		return malformed("startxref names no offset in the file")
	}
	seen := map[int64]bool{}
	queue := []int64{t.i}
	for sections := 0; len(queue) > 0; {
		// A section is a whole cross-reference read: the deadline is read
		// before each of them, and within them by entries.
		if d.deadlineNow() {
			return d.deadline()
		}
		offset := queue[0]
		queue = queue[1:]
		if seen[offset] {
			continue
		}
		if sections == maxXrefSections {
			return structureBound("cross-reference chain past %d sections", maxXrefSections)
		}
		sections++
		seen[offset] = true
		generation := d.generation
		trailer, err := d.readXrefSection(offset)
		if d.generation != generation {
			// The section's own read rebuilt the cross-reference. The
			// sections still queued were named by the trailers of sections
			// this document no longer has -- a /Prev, a hybrid file's
			// /XRefStm -- and where those offsets lead is nothing this
			// document says: the traversal ends here and the queue is
			// dropped. The cross-reference is the rebuilt one, which the scan
			// filled, and what the scan itself met is the file's and stands.
			return nil
		}
		if err != nil {
			return err
		}
		// The newest section is read first, so a member already set wins.
		for k, v := range trailer {
			if _, ok := d.trailer[k]; !ok {
				d.trailer[k] = v
			}
		}
		// A hybrid file's /XRefStm is read before /Prev: its entries
		// override the table's for the objects it names.
		for _, key := range []Name{"XRefStm", "Prev"} {
			if v, ok := trailer[key]; ok {
				if n, ok := v.(int64); ok && n >= 0 && n < int64(len(d.data)) {
					queue = append(queue, n)
				} else {
					return malformed("/%s names no offset in the file", key)
				}
			}
		}
	}
	if len(d.xref) == 0 {
		return malformed("cross-reference names no object")
	}
	return nil
}

// readXrefSection reads one section: a table beginning with "xref", or a
// cross-reference stream. It returns the section's trailer dictionary.
func (d *Document) readXrefSection(offset int64) (Dict, error) {
	// Reading one section is one read: a cross-reference stream's /Length,
	// the objects it decodes through, its /W, its /Index and the /Prev of its
	// trailer are fields of one object, resolved one after another. Where one
	// of them rebuilds the cross-reference, the fields after it are fields of
	// a section this document no longer has, and nothing of them -- an object,
	// a bound -- is published. See beginRead. The section is the whole of the
	// read whichever chain reaches it: a /Prev, a hybrid file's /XRefStm, or
	// the startxref the file ends with.
	defer d.beginRead()()
	generation := d.generation
	trailer, err := d.readXrefSectionAt(offset, generation)
	if d.generation != generation {
		// The read found the cross-reference rebuilt: this section is a
		// section of a document this one no longer is, and neither what it
		// read nor what it met is the rebuilt document's. Its entries, its
		// trailer -- and with them the /Prev and /XRefStm that would carry
		// the chain on from it -- and its failure are all discarded, a bound
		// of its own fields among them. What the scan that rebuilt met is
		// the file's and is kept: see noteFileBound.
		return nil, nil
	}
	return trailer, err
}

// readXrefSectionAt is the read of one section, within the scope
// readXrefSection begins for it. generation is the cross-reference the
// section began under: the fields of a cross-reference stream are resolved
// from here on, its /Length among them, and a field that rebuilds leaves the
// ones after it fields of a section this document no longer has.
func (d *Document) readXrefSectionAt(offset int64, generation int) (Dict, error) {
	lex := newLexer(d.data, int(offset)).within(d.budgeted())
	lex.skipSpace()
	if bytes.HasPrefix(d.data[lex.pos:], []byte("xref")) {
		lex.pos += len("xref")
		return d.readXrefTable(lex)
	}
	// "N G obj" with a stream of /Type /XRef.
	num, _, body, err := d.parseIndirectAt(int(offset))
	if d.generation != generation {
		// Locating the stream's data resolved its /Length, and that read
		// rebuilt the cross-reference: the stream it reached is a stream of a
		// document this one no longer is. Nothing of it is read -- not one
		// entry -- and what it met is discarded with it, as readXrefSection
		// discards what this returns.
		return nil, nil
	}
	if err != nil {
		return nil, malformedBy(err, "cross-reference at offset %d", offset)
	}
	s, ok := body.(*stream)
	if !ok {
		return nil, malformed("cross-reference at offset %d is neither a table nor a stream", offset)
	}
	_ = num
	return d.readXrefStream(s, generation)
}

func (d *Document) readXrefTable(lex *lexer) (Dict, error) {
	// The trailer this returns is kept for the life of the document, so it is
	// built within the document's allowance as every other held value is.
	p := &parser{lex: lex, allow: d.budgeted()}
	for {
		lex.skipSpace()
		if bytes.HasPrefix(d.data[lex.pos:], []byte("trailer")) {
			lex.pos += len("trailer")
			obj, err := p.parseObject(0)
			if err != nil {
				return nil, malformedBy(err, "trailer")
			}
			dict, ok := obj.(Dict)
			if !ok {
				return nil, malformed("trailer is not a dictionary")
			}
			return dict, nil
		}
		t, err := lex.next()
		if err != nil {
			return nil, malformed("cross-reference table: %v", err)
		}
		if t.kind != tokInteger {
			return nil, malformed("cross-reference table: expected a subsection start")
		}
		start := t.i
		t, err = lex.next()
		if err != nil || t.kind != tokInteger {
			return nil, malformed("cross-reference table: expected a subsection count")
		}
		count := t.i
		if start < 0 || count < 0 {
			return nil, malformed("cross-reference subsection %d %d out of range", start, count)
		}
		if start > maxXrefEntries || count > maxXrefEntries-start {
			return nil, structureBound("cross-reference subsection %d %d past %d objects", start, count, maxXrefEntries)
		}
		for i := int64(0); i < count; i++ {
			if d.deadlinePassed() {
				return nil, d.deadline()
			}
			// Entries are "oooooooooo ggggg n" but writers get the width
			// wrong; tokens are read instead of fixed columns.
			t1, err := lex.next()
			if err != nil || t1.kind != tokInteger {
				return nil, malformed("cross-reference entry %d: expected an offset", start+i)
			}
			t2, err := lex.next()
			if err != nil || t2.kind != tokInteger {
				return nil, malformed("cross-reference entry %d: expected a generation", start+i)
			}
			t3, err := lex.next()
			if err != nil || t3.kind != tokKeyword || (t3.keyword != "n" && t3.keyword != "f") {
				return nil, malformed("cross-reference entry %d: expected n or f", start+i)
			}
			num := int(start + i)
			if t3.keyword == "n" {
				if _, taken := d.xref[num]; !taken {
					d.xref[num] = xrefEntry{offset: t1.i, gen: int(t2.i)}
				}
			} else if _, taken := d.xref[num]; !taken {
				// A free entry in a newer section shadows an older
				// in-use one: record it as absent.
				d.xref[num] = xrefEntry{offset: -1}
			}
		}
	}
}

// readXrefStream reads the entries of a cross-reference stream. generation is
// the cross-reference the section began under, and not the one this read
// finds: the stream's own /Length was resolved before this, and a section
// abandoned there declares no entry either.
func (d *Document) readXrefStream(s *stream, generation int) (Dict, error) {
	if s.dict["Type"] != Name("XRef") {
		return nil, malformed("cross-reference stream is not /Type /XRef")
	}
	data, err := d.decodeStream(s, true, heldByDocument)
	if err != nil {
		return nil, malformedBy(err, "cross-reference stream")
	}
	w, ok := d.resolve(s.dict["W"]).(Array)
	if !ok || len(w) < 3 {
		return nil, malformed("cross-reference stream /W is not an array of three")
	}
	var widths [3]int
	total := 0
	for i := 0; i < 3; i++ {
		n, ok := d.resolve(w[i]).(int64)
		if !ok || n < 0 || n > 8 {
			return nil, malformed("cross-reference stream /W entry out of range")
		}
		widths[i] = int(n)
		total += int(n)
	}
	if total == 0 {
		return nil, malformed("cross-reference stream /W is all zero")
	}
	size, _ := d.resolve(s.dict["Size"]).(int64)
	var index []int64
	if idx, ok := d.resolve(s.dict["Index"]).(Array); ok {
		for _, v := range idx {
			n, ok := d.resolve(v).(int64)
			if !ok {
				return nil, malformed("cross-reference stream /Index is not integers")
			}
			index = append(index, n)
		}
	} else {
		index = []int64{0, size}
	}
	if len(index)%2 != 0 {
		return nil, malformed("cross-reference stream /Index has an odd length")
	}
	// The fields are all resolved by here, and the entries below are read
	// from the bytes alone. Where resolving one of them rebuilt the
	// cross-reference, this section names the objects of a document the
	// reader no longer has: it declares none of them, and what its own
	// remaining fields are past -- the bound its /Index holds below -- is a
	// bound of that document and not of this one. See readXrefSection, which
	// discards what this returns.
	if d.generation != generation {
		return nil, nil
	}
	pos := 0
	readField := func(width int) int64 {
		var v int64
		for i := 0; i < width; i++ {
			v = v<<8 | int64(data[pos])
			pos++
		}
		return v
	}
	for i := 0; i < len(index); i += 2 {
		start, count := index[i], index[i+1]
		if start < 0 || count < 0 {
			return nil, malformed("cross-reference stream /Index out of range")
		}
		if start > maxXrefEntries || count > maxXrefEntries-start {
			return nil, structureBound("cross-reference stream /Index %d %d past %d objects", start, count, maxXrefEntries)
		}
		for j := int64(0); j < count; j++ {
			if d.deadlinePassed() {
				return nil, d.deadline()
			}
			if pos+total > len(data) {
				// A short stream: what was read stands.
				return s.dict, nil
			}
			typ := int64(1)
			if widths[0] > 0 {
				typ = readField(widths[0])
			}
			f2 := readField(widths[1])
			f3 := readField(widths[2])
			num := int(start + j)
			if _, taken := d.xref[num]; taken {
				continue
			}
			switch typ {
			case 0:
				d.xref[num] = xrefEntry{offset: -1}
			case 1:
				d.xref[num] = xrefEntry{offset: f2, gen: int(f3)}
			case 2:
				if f2 < 0 || f3 < 0 {
					continue
				}
				if f2 > maxXrefEntries || f3 > maxObjStmObjects {
					return nil, structureBound("cross-reference stream entry %d names an object stream or index past the bound", num)
				}
				d.xref[num] = xrefEntry{inStream: true, stmNum: int(f2), stmIndex: int(f3)}
			}
		}
	}
	return s.dict, nil
}

var objHeader = regexp.MustCompile(`(?s)(\d{1,10})[ \t\r\n\f\x00]+(\d{1,5})[ \t\r\n\f\x00]+obj\b`)

// reconstruct rebuilds the cross-reference by scanning the file for
// "N G obj", the last occurrence of each number winning, and the trailer
// from every "trailer" dictionary and every cross-reference stream found,
// the last /Root winning; failing those, from an object of /Type /Catalog.
// A bound met while scanning ends it with that bound.
func (d *Document) reconstruct() error {
	d.reconstructed = true
	// The scan reads objects of its own: the streams it finds, the object
	// streams they name, a catalog among them. Those reads are the scan's and
	// not the caller's. A caller whose own read met the rebuild publishes
	// nothing -- the objects it goes on to touch are not this document's --
	// but the scan is the rebuilding of this document and reads under the
	// cross-reference it is building, so its reads are begun again here,
	// outermost, and what they meet stands: an object it could not read is
	// marked unread, and a bound it met is the file's own, since the scan
	// reads the file and not the objects of one cross-reference. The caller's
	// read is put back afterwards, and still publishes nothing.
	//
	// The references the abandoned caller was resolving through are put aside
	// with its read: how deep the scan's own reads go is how many references
	// the scan followed, and the chain a caller was half way down when the
	// rebuild began is no part of it. A depth the scan reports is the file's,
	// so it must be the scan's own depth that reaches it.
	reading, readGeneration, scanning, resolving := d.reading, d.readGeneration, d.scanning, d.resolving
	d.reading, d.scanning, d.resolving = 0, true, map[int]bool{}
	defer func() {
		d.reading, d.readGeneration, d.scanning, d.resolving = reading, readGeneration, scanning, resolving
	}()
	// The work allowance of a page being extracted is put aside with that
	// read. The scan is a reading of the file, not of the page whose resolve
	// began it: what it decodes is charged to the balance every other reading
	// of the file spends, and a bound it meets there is the file's own,
	// exactly as they are for a scan begun at the file's own startxref. A page
	// half way through its allowance would otherwise lend the scan what little
	// it had left, so that the same objects are read or refused by where the
	// scan happened to begin -- and what the scan decoded would go uncharged
	// against the file, since a page's work is charged instead of the
	// document's balance. The page's scope is put back as it stood and no
	// better: what it spent before the scan stays spent, what the scan spent
	// stays on the document's balance, and nothing is given back.
	pageWork, pageWorking := d.pageWork, d.pageWorking
	d.pageWork, d.pageWorking = 0, false
	defer func() { d.pageWork, d.pageWorking = pageWork, pageWorking }()
	found := 0
	matches := objHeader.FindAllSubmatchIndex(d.data, maxScanObjects+1)
	if len(matches) > maxScanObjects {
		return structureBound("more than %d objects found by scanning", maxScanObjects)
	}
	// The rebuilt cross-reference is the scan's alone, so the scan begins from
	// an empty one. Everything read under the cross-reference being replaced
	// goes with it, and so does every entry it held: a number the scan does not
	// find is a number the file the scan read holds no object of, and the
	// offset the damaged cross-reference gave for it names other bytes. An
	// entry left standing would otherwise be read under the rebuilt
	// cross-reference, and what a page reads would depend on which
	// cross-reference stood before the scan rather than on the file.
	//
	// From here the document's cross-reference is the scan's, whichever way
	// the scan leaves: replacing it and giving up what was read under the one
	// it replaced are one step, so that no reading made after the scan can be
	// made from the entries of one cross-reference beside the objects of
	// another. Every way out below therefore goes through scanEnded, and each
	// of them leaves a document the reader must stop at rather than answer
	// from -- a failure of the file's own, or the deadline.
	d.xref = map[int]xrefEntry{}
	// A panic is a way out too, and the rule holds for it as it holds for the
	// returns: a defect the scan could not continue past leaves the document
	// holding the part of a cross-reference the scan had written, so the
	// reading made under the one it replaced is given up here exactly as the
	// zero-found exit gives it up -- the objects, the fonts and the CMaps
	// dropped, and the generation advanced, so that a reading begun before the
	// scan can tell that what it gathered no longer stands. The failure is the
	// file's own, since the scan reads the file and not the objects of one
	// cross-reference, and a rebuild does not drop it: a scan the reader could
	// not finish leaves a document the reader must stop at, whatever part of
	// the file the scan had reached. The panic is raised again so that the
	// reading above ends where it would have ended -- the page being
	// interpreted is reported as the page the reader could not continue
	// through -- and so that this restores what the scan replaced and decides
	// nothing else.
	defer func() {
		if r := recover(); r != nil {
			d.forgetObjects()
			d.scanUnfinished = malformed("the scan of the file could not be finished")
			panic(r)
		}
	}()
	for _, m := range matches {
		if d.deadlinePassed() {
			return d.scanEnded(d.deadline())
		}
		// The match must begin at a token boundary, not inside a number.
		if m[0] > 0 && isRegular(d.data[m[0]-1]) {
			continue
		}
		num, err1 := strconv.Atoi(string(d.data[m[2]:m[3]]))
		gen, err2 := strconv.Atoi(string(d.data[m[4]:m[5]]))
		if err1 != nil || err2 != nil {
			continue
		}
		d.xref[num] = xrefEntry{offset: int64(m[0]), gen: gen}
		found++
	}
	if found == 0 {
		// The file the scan read holds no object at all, so the
		// cross-reference it replaces is replaced by nothing. The reading made
		// under the old one is invalidated exactly as a scan that found
		// objects invalidates it, and the failure is kept as the file's own --
		// a bound the scan met is kept the same way -- so that every route
		// that reads the document after this refuses the file instead of
		// answering, under a number the file names nothing at, out of what the
		// discarded cross-reference read there.
		d.forgetObjects()
		err := malformed("no object found by scanning the file")
		d.noObjects = err
		return err
	}
	// Trailer dictionaries, in file order; a later /Root wins.
	trailer := Dict{}
	for _, key := range []Name{"Root", "Encrypt", "ID", "Info"} {
		if v, ok := d.trailer[key]; ok {
			trailer[key] = v
		}
	}
	for at := 0; ; {
		// Each step of this loop may parse a value that runs to the end of the
		// file -- a "trailer" followed by a string that is never closed is
		// exactly that -- so the deadline is read before each of them and not
		// once per so many of them.
		if d.deadlineNow() {
			return d.scanEnded(d.deadline())
		}
		i := bytes.Index(d.data[at:], []byte("trailer"))
		if i < 0 {
			break
		}
		at = at + i + len("trailer")
		lex := newLexer(d.data, at).within(d.budgeted())
		// A trailer is a dictionary; a "trailer" followed by anything else is
		// the word in some other place in the file, and is not parsed. Comments
		// and whitespace may lie between the two, and a comment runs to the end
		// of its line -- which may be the end of the file -- so what skipping
		// them examined is charged, and the scan for the next candidate goes on
		// from where they ended rather than reading them again for every
		// "trailer" that shares the line.
		// The lexer charges the whitespace and comments it skips here, and the
		// bytes of the candidate it goes on to read: a file of candidates that
		// each read the rest of it spends the allowance and ends this loop,
		// rather than being read once for every one of them. What was skipped
		// is also behind the scan now, so the next candidate is looked for
		// past it and the same comment is not read again.
		lex.skipSpace()
		at = lex.pos
		if d.parsedSpent() {
			err := errParsedBudget()
			d.noteFileBound(err)
			return d.scanEnded(err)
		}
		isDict := bytes.HasPrefix(d.data[lex.pos:], []byte("<<"))
		var obj object
		var err error
		if isDict {
			p := &parser{lex: lex, allow: lex.room}
			obj, err = p.parseObject(0)
		}
		if err != nil && isBound(err) {
			// A candidate past a bound is not a candidate to pass over: the
			// file has more structure than the reader holds, and the next
			// candidate would meet the same bound after reading as far again.
			d.noteFileBound(err)
			return d.scanEnded(err)
		}
		if !isDict || err != nil {
			continue
		}
		if dict, ok := obj.(Dict); ok {
			for k, v := range dict {
				trailer[k] = v
			}
		}
	}
	// Cross-reference streams found by scanning contribute their
	// dictionaries and the objects in the object streams they name.
	nums := make([]int, 0, len(d.xref))
	for num := range d.xref {
		nums = append(nums, num)
	}
	sortInts(nums)
	d.forgetObjects()
	// objStmFound is an object stream the scan found, kept until the trailer
	// it is registered under has been gathered.
	type objStmFound struct {
		num int
		s   *stream
	}
	var deferred []objStmFound
	for _, num := range nums {
		// Each step of this loop may parse a whole object.
		if d.deadlineNow() {
			return d.deadline()
		}
		e := d.xref[num]
		if e.inStream || e.offset < 0 {
			continue
		}
		// Only look at objects that are streams of a type we care about
		// without parsing everything: a cheap prefix check on the bytes.
		head := d.objectHead(e, 512)
		if !bytes.Contains(head, []byte("/XRef")) && !bytes.Contains(head, []byte("/ObjStm")) {
			continue
		}
		_, _, body, err := d.parseIndirectAt(int(e.offset))
		if err != nil {
			if isBound(err) {
				return err
			}
			continue
		}
		s, ok := body.(*stream)
		if !ok {
			continue
		}
		switch s.dict["Type"] {
		case Name("XRef"):
			for _, key := range []Name{"Root", "Encrypt", "ID", "Info"} {
				if v, ok := s.dict[key]; ok {
					trailer[key] = v
				}
			}
		case Name("ObjStm"):
			// Objects inside a stream are registered where the file has
			// no object of that number at an offset: an object at an
			// offset is the newer form in an incrementally updated file
			// more often than not, and the scan cannot tell. The stream is
			// decoded below rather than here: it is decoded like any other,
			// and which key it is decrypted with is what the trailer this
			// scan is still gathering says, not what the trailer being
			// replaced said. The file is not scanned again for it.
			deferred = append(deferred, objStmFound{num: num, s: s})
		}
	}
	// The rebuilt trailer stands before the object streams it names are
	// decoded, and the handler it names is established before them: an object
	// stream read through the key the old trailer named is read through a key
	// this document does not have, and an object it holds would go
	// unregistered -- a number no later reading could recover, since the scan
	// runs once. A handler that does not open leaves the objects it would
	// have decoded unregistered, and the caller reads the encryption
	// dictionary again and reports it: see establishEncryption.
	d.trailer = trailer
	d.crypt = nil
	// What was read through the handler being replaced goes with it, the
	// encryption dictionary the rebuilt trailer names among them: an object
	// resolved while the scan ran -- an object stream's /Length naming that
	// dictionary, say -- was read through the old key, and a dictionary whose
	// strings were deciphered with it is no reading of the dictionary this
	// document names.
	d.dropCachedObjects()
	_, _ = d.openEncryption()
	for _, found := range deferred {
		// Each step of this loop may decode a whole object stream.
		if d.deadlineNow() {
			return d.deadline()
		}
		st, err := d.loadObjStm(found.num, found.s)
		if err != nil {
			if isBound(err) {
				// A bound met decoding an object stream the scan found, or
				// reading its header, ends the scan as every other bound it
				// meets does: the caller keeps it as the file's own, since
				// the scan reads the file and not the objects of one
				// cross-reference.
				return err
			}
			continue
		}
		idx := 0
		for _, inner := range st.order {
			if _, taken := d.xref[inner]; inner != unreadableObject && !taken {
				d.xref[inner] = xrefEntry{inStream: true, stmNum: found.num, stmIndex: idx}
			}
			idx++
		}
	}
	if _, ok := trailer["Root"]; !ok {
		// Find a catalog by parsing candidates whose bytes mention it.
		for _, num := range nums {
			// Each step of this loop may resolve a whole object.
			if d.deadlineNow() {
				return d.deadline()
			}
			e := d.xref[num]
			if e.inStream || e.offset < 0 {
				continue
			}
			if d.notOfType(e, "Catalog") {
				continue
			}
			if dict, ok := d.resolve(ref{num, e.gen}).(Dict); ok && dict["Type"] == Name("Catalog") {
				trailer["Root"] = ref{num, e.gen}
				break
			}
		}
	}
	// The same rebuild, still: what the search above cached is dropped, and
	// the generation has already moved once for this cross-reference. The
	// trailer itself was put in place above, before the object streams it
	// names were decoded.
	// The cumulative charge stays: a walk, the trailer, or an abandoned
	// reading can still hold objects no cache names.
	d.dropCachedObjects()
	return nil
}

// parseIndirectAt reads "N G obj <object> [stream]" at an offset and
// returns the number, generation and object; the number and generation
// also when the object after them cannot be parsed. A stream's data is located
// by its /Length when that is plausible, and otherwise by the next
// "endstream", which nextEndstream finds without searching the rest of the
// file for each stream that needs it.
func (d *Document) parseIndirectAt(offset int) (int, int, object, error) {
	if offset < 0 || offset >= len(d.data) {
		return 0, 0, nil, fmt.Errorf("offset %d outside the file", offset)
	}
	// The allowance is the lexer's from its first token, so the bytes this
	// reads of the file are charged however the read ends: a candidate whose
	// object cannot be parsed has still been read, and a file of candidates
	// that each read the rest of it would otherwise be read once for every
	// one of them at no cost.
	allow := d.budgeted()
	lex := newLexer(d.data, offset).within(allow)
	t1, err := lex.next()
	if err != nil || t1.kind != tokInteger {
		return 0, 0, nil, errors.New("no object number")
	}
	t2, err := lex.next()
	if err != nil || t2.kind != tokInteger {
		return 0, 0, nil, errors.New("no generation number")
	}
	t3, err := lex.next()
	if err != nil || t3.kind != tokKeyword || t3.keyword != "obj" {
		return 0, 0, nil, errors.New("no obj keyword")
	}
	num, gen := int(t1.i), int(t2.i)
	p := &parser{lex: lex, allow: allow}
	body, err := p.parseObject(0)
	if err != nil {
		var kw errKeyword
		if errors.As(err, &kw) && kw.keyword == "endobj" {
			return num, gen, nil, nil // an empty object
		}
		return num, gen, nil, err
	}
	if !lex.peekKeyword("stream") {
		return num, gen, body, nil
	}
	dict, ok := body.(Dict)
	if !ok {
		return 0, 0, nil, errors.New("stream without a dictionary")
	}
	// Consume "stream" and the end-of-line after it.
	lex.skipSpace()
	lex.pos += len("stream")
	if lex.pos < len(d.data) && d.data[lex.pos] == '\r' {
		lex.pos++
	}
	if lex.pos < len(d.data) && d.data[lex.pos] == '\n' {
		lex.pos++
	}
	start := lex.pos
	if start > len(d.data) {
		start = len(d.data)
	}
	length := -1
	if l, ok, err := d.resolveLength(dict["Length"], num); err != nil {
		return num, gen, nil, err
	} else if ok {
		length = l
	}
	end := -1
	if length >= 0 && start+length <= len(d.data) {
		// Plausible when "endstream" follows within a little whitespace.
		after := d.data[start+length:]
		after = bytes.TrimLeft(after[:min(len(after), 4)], " \r\n\t")
		if bytes.HasPrefix(d.data[start+length+(min(len(d.data[start+length:]), 4)-len(after)):], []byte("endstream")) {
			end = start + length
		}
	}
	if end < 0 {
		i := d.nextEndstream(start)
		if i < 0 {
			end = len(d.data)
		} else {
			end = i
			// Drop the end-of-line the writer put before "endstream".
			if end > start && d.data[end-1] == '\n' {
				end--
			}
			if end > start && d.data[end-1] == '\r' {
				end--
			}
		}
	}
	return num, gen, &stream{dict: dict, raw: d.data[start:end], num: num, gen: gen}, nil
}

var endstreamKeyword = []byte("endstream")

// nextEndstream is the offset of the first "endstream" at or after start, or
// -1 when the file has none there. It is the answer a search of the rest of
// the file would give, at the cost of one block: the file's own offsets are
// indexed once, so a file of many streams whose /Length locates nothing costs
// its size and not that times the streams.
func (d *Document) nextEndstream(start int) int {
	if start < 0 || start >= len(d.data) {
		return -1
	}
	if d.endstream == nil {
		d.indexEndstreams()
	}
	// A match beginning in start's own block is found by searching it, the
	// search reaching the length of the keyword less one byte into the block
	// after it so that a match across their edge is found whole and no match
	// beginning past the edge is found at all; the index holds the first match
	// at or after every later block's start.
	block := start / endstreamBlock
	next := (block + 1) * endstreamBlock
	stop := min(next+len(endstreamKeyword)-1, len(d.data))
	if i := bytes.Index(d.data[start:stop], endstreamKeyword); i >= 0 {
		return start + i
	}
	if block+1 < len(d.endstream) {
		return d.endstream[block+1]
	}
	return -1
}

// indexEndstreams records, for each block of the file, the offset of the
// first "endstream" at or after that block's start, in one pass up the file.
func (d *Document) indexEndstreams() {
	index := make([]int, len(d.data)/endstreamBlock+2)
	for i := range index {
		index[i] = -1
	}
	// A match is the answer for every block from the first without one up to
	// its own, since the matches before it all lie below those blocks.
	unfilled := 0
	for at := 0; at < len(d.data); {
		i := bytes.Index(d.data[at:], endstreamKeyword)
		if i < 0 {
			break
		}
		at += i
		for b := unfilled; b <= at/endstreamBlock; b++ {
			index[b] = at
		}
		if next := at/endstreamBlock + 1; next > unfilled {
			unfilled = next
		}
		at++
	}
	d.endstream = index
}

// resolveLength resolves a stream's /Length without recursing into the
// object being parsed.
func (d *Document) resolveLength(v object, self int) (int, bool, error) {
	for depth := 0; ; depth++ {
		switch x := v.(type) {
		case int64:
			if x >= 0 && x <= int64(len(d.data)) {
				return int(x), true, nil
			}
		case ref:
			if x.num == self {
				return 0, false, nil
			}
			if depth == maxRefDepth {
				return 0, false, structureBound("stream length references past %d", maxRefDepth)
			}
			var read bool
			v, read = d.objectRead(x.num)
			if read {
				continue
			}
			if failed, ok := d.cache[x.num].(unread); ok && isBound(failed.err) {
				return 0, false, failed.err
			}
		}
		return 0, false, nil
	}
}

// resolve follows references until a direct object, through object
// streams, with a cache so no object is parsed twice. An object that cannot
// be read resolves to nil, as the null object does; resolveRead tells the two
// apart.
func (d *Document) resolve(v object) object {
	o, _ := d.resolveRead(v)
	return o
}

// resolveRead is resolve, reporting whether every reference followed led to
// an object the reader read: false for a reference to a number the
// cross-reference does not name or names as free, to an object that cannot
// be parsed, through a cycle, or past a bound.
func (d *Document) resolveRead(v object) (object, bool) {
	// A chain of references is one read: where following it rebuilds the
	// cross-reference, the numbers after the rebuild are not the numbers the
	// chain began in, and nothing of what they name is published. See
	// beginRead.
	defer d.beginRead()()
	generation := d.readingGeneration()
	for depth := 0; ; depth++ {
		r, ok := v.(ref)
		if !ok {
			return v, true
		}
		if depth == maxRefDepth {
			d.noteBoundAt(generation, structureBound("references to references past %d", maxRefDepth))
			return nil, false
		}
		if v, ok = d.objectRead(r.num); !ok {
			return nil, false
		}
	}
}

// object fetches the object with the number given, or nil.
func (d *Document) object(num int) object {
	v, _ := d.objectRead(num)
	return v
}

// parsedLeft is what is left of the document's allowance.
func (d *Document) parsedLeft() int64 { return d.parsedBudget() - d.parsedBytes }

// parsedBudget is what the objects a document holds may cost to hold: the
// file's own bytes and the bytes its streams have inflated so far,
// parsedBytesPerFileByte times over, and never more than maxParsedBytesHeld.
// The objects of an object stream are parsed out of inflated bytes rather
// than out of the file, so the allowance grows with what was inflated --
// which the inflation budget bounds -- and not without end.
func (d *Document) parsedBudget() int64 {
	inflated := int64(0)
	if d.budget != nil {
		inflated = d.budget.used
	}
	budget := parsedBytesPerFileByte * (int64(len(d.data)) + inflated)
	if budget > maxParsedBytesHeld {
		budget = maxParsedBytesHeld
	}
	return budget
}

// parsedSpent reports that the objects held cost all the document may hold,
// so that the next one is not parsed to find out.
func (d *Document) parsedSpent() bool { return d.parsedBytes >= d.parsedBudget() }

// chargeParsed charges what a parsed value costs to hold, and reports
// whether the document may hold it. A charge that does not fit leaves the
// budget spent, as a stream stopped at the inflation budget's total leaves
// that spent: everything read after it finds nothing left, so that a file
// whose objects each hold the rest of it is parsed a few times over and not
// once per object.
func (d *Document) chargeParsed(n int64) bool {
	limit := d.parsedBudget()
	if n < 0 || n > limit-d.parsedBytes {
		d.parsedBytes = limit
		return false
	}
	d.parsedBytes += n
	return true
}

// allowance is what one parse may spend of a document's budget. The parser
// spends it as it builds a value, member by member and element by element,
// so that a value past what the document may hold stops while it is being
// built and not once it exists and the memory is taken.
type allowance struct {
	// doc is the document whose balance this spends. Every allowance on one
	// document spends that one balance rather than a copy of it: two parses
	// that each took what was left when they began -- a cross-reference table
	// and the trailer it ends with are two -- would otherwise spend the same
	// bytes twice over.
	doc *Document
	// left is the balance of an allowance of its own, used where doc is nil,
	// as the operands of one page's content are.
	left int64
	// past names the bound a parse ends at when the allowance runs out; the
	// document's own where it is nil.
	past func() error
}

// exhausted is the error a parse ends with when this allowance runs out.
func (a *allowance) exhausted() error {
	if a != nil && a.past != nil {
		return a.past()
	}
	return errParsedBudget()
}

// budgeted is an allowance that spends the document's balance itself.
func (d *Document) budgeted() *allowance { return &allowance{doc: d} }

// take spends n, and reports whether it fit. A charge that does not fit
// leaves nothing, so every charge after it fails too and the value being
// built is abandoned where it stands.
func (a *allowance) take(n int64) bool {
	switch {
	case a == nil:
		return true
	case a.doc != nil:
		// The document's own balance, read and spent in one step, so that
		// what this parse takes is not offered to another.
		return a.doc.chargeParsed(n)
	case n < 0 || n > a.left:
		a.left = 0
		return false
	default:
		a.left -= n
		return true
	}
}

// remaining is what this allowance may still spend.
func (a *allowance) remaining() int64 {
	switch {
	case a == nil:
		return 1 << 62
	case a.doc != nil:
		return a.doc.parsedLeft()
	default:
		return a.left
	}
}

// startPageWork opens the work allowance of one page: what decoding the
// streams read on its behalf costs, the forms it draws and the filters
// applied to them included. It is opened for each page and spent by it
// alone, so one page's content cannot spend another's.
func (d *Document) startPageWork() { d.pageWork = 0; d.pageWorking = true }

// chargeWork charges work done for the page being extracted, and returns the
// bound to fail the page with when it is past what one page may cost. Work
// done while the document is opened or its page tree walked is charged to no
// page and bounded by the budgets that cover it.
func (d *Document) chargeWork(n int64) error {
	if !d.pageWorking {
		// No page answers for this: a stream decoded while the document is
		// opened or rebuilt is read on the document's own account, and is
		// charged against what the document may read and hold, which is the
		// balance every other reading of the file spends.
		if !d.chargeParsed(n) {
			return errParsedBudget()
		}
		return nil
	}
	if n < 0 || n > maxPageWorkBytes-d.pageWork {
		d.pageWork = maxPageWorkBytes
		return structureBound("reading one page cost more than %d bytes of streams read and filters applied", maxPageWorkBytes)
	}
	d.pageWork += n
	return nil
}

// errParsedBudget is the document past the bytes its parsed objects may
// hold. It is a structure bound: the file has more structure than the reader
// holds, and rebuilding the cross-reference would find the same bytes.
func errParsedBudget() error {
	return structureBound("the objects read hold more than %d bytes for each byte of the file and of what it inflates to, or more than %d bytes in all", parsedBytesPerFileByte, maxParsedBytesHeld)
}

// parsedBytesOf is what holding a value costs beyond the slot that refers to
// it, by the same reckoning the parser spends as it builds one: a name's or a
// string's own bytes rounded up to what Go allocates for them, a stream's
// bytes as they lie in the file, and for an array or a dictionary what its
// elements or members cost beyond theirs. A value holds no other value twice
// and none holds itself, since a reference is held as a number, so this walk
// ends within the nesting the parser admits.
func parsedBytesOf(o object) int64 {
	switch x := o.(type) {
	case String:
		return parsedStringBytes + grownBytes(int64(len(x)))
	case Name:
		return parsedStringBytes + grownBytes(int64(len(x)))
	case Array:
		n := int64(parsedArrayBytes)
		for _, item := range x {
			n += parsedSlotBytes + parsedBytesOf(item)
		}
		return n
	case Dict:
		n := int64(parsedDictBytes)
		for name, v := range x {
			n += parsedMemberBytes + grownBytes(int64(len(name))) + parsedBytesOf(v)
		}
		return n
	case *stream:
		// A stream's raw bytes are the file's own, which the reader holds
		// once however many streams point into them; what a stream adds is
		// its dictionary and the header that points at the bytes.
		return parsedStringBytes + parsedBytesOf(x.dict)
	}
	return parsedValueBytes
}

// headWindow is how much of an object the rebuild reads to decide whether
// parsing it could answer what it is looking for: enough for a dictionary's
// first members, and little enough that reading it for every object the file
// declares costs one pass over the file.
const headWindow = 1 << 10

// headType is what reading an object's head settled about it: the type it
// declares, or that the window settled nothing.
type headType struct {
	typ     Name
	settled bool
}

// notOfType reports that the object at an entry is certainly not of the type
// wanted, so that the rebuild need not parse it. The window at the entry's
// offset is lexed, not searched: a name is read with its #xx escapes
// resolved, so /Pa#67es is /Pages, and a dictionary is read member by member,
// so a /Type that lies past a long first member is still found.
//
// Only a positive answer excludes: a window that holds a whole dictionary
// whose /Type is a name and is not the one wanted, or that shows the object
// beginning as something other than a dictionary. Everything else is
// inconclusive and leaves the object a candidate, to be parsed under the
// document's allowance as it was before any of this was looked at: a
// dictionary that runs past the window, a /Type that is a reference or is
// absent, a header the window cuts in two, a run of whitespace or a comment
// that fills the window before the dictionary begins, and a window that ends
// on the first half of the "<<" that would have opened one.
//
// What it reads is charged, and what it settled is kept by offset: a
// cross-reference may name one offset for thousands of object numbers, and
// reading the same head for each of them is work the file did not pay for.
func (d *Document) notOfType(e xrefEntry, want Name) bool {
	if d.parsedSpent() {
		// Nothing is left to read with, so nothing can be settled.
		return false
	}
	if known, ok := d.headTypes[e.offset]; ok {
		return known.settled && known.typ != want
	}
	known := d.readHeadType(e)
	if d.headTypes == nil {
		d.headTypes = map[int64]headType{}
	}
	d.headTypes[e.offset] = known
	return known.settled && known.typ != want
}

// readHeadType reads the head of the object at an entry and reports what it
// settled, charging the bytes it read to the document's allowance.
func (d *Document) readHeadType(e xrefEntry) headType {
	head := d.objectHead(e, headWindow)
	if len(head) == 0 {
		return headType{settled: true}
	}
	// The window is lexed on its own, so a string or a name that runs past it
	// ends with it and cannot reach into the rest of the file.
	cut := len(head) == headWindow
	lex := newLexer(head, 0).within(d.budgeted())
	// "N G obj" first, where the window holds it; an object at an offset the
	// cross-reference names need not have a header at all.
	for i := 0; i < 3; i++ {
		save := lex.pos
		t, err := lex.next()
		if err != nil {
			return headType{}
		}
		if cut && t.end >= len(head) {
			// The window ends inside this token: the object's number, its
			// generation or the "obj" that follows them is cut in two, and
			// what it is cannot be read from here.
			return headType{}
		}
		if t.kind == tokKeyword && t.keyword == "obj" {
			break
		}
		if t.kind != tokInteger {
			lex.pos = save
			break
		}
	}
	lex.skipSpace()
	rest := head[lex.pos:]
	if cut && len(rest) <= 1 {
		// The header, or the space and comments after it, filled the window:
		// what the object begins with is past what was read.
		return headType{}
	}
	if !bytes.HasPrefix(rest, []byte("<<")) {
		if cut && len(rest) == 1 && rest[0] == '<' {
			// The window ends between the two angle brackets of a dictionary
			// that may well open there.
			return headType{}
		}
		// Not a dictionary where the window can see: a page tree and a
		// catalog are dictionaries, so this is not one of them.
		return headType{settled: true}
	}
	p := &parser{lex: lex, allow: lex.room}
	obj, err := p.parseObject(0)
	if err != nil {
		return headType{}
	}
	dict, ok := obj.(Dict)
	if !ok {
		return headType{}
	}
	if lex.pos >= len(head) && cut {
		// The dictionary filled the window: what it holds past the window is
		// unread, so nothing here excludes it.
		return headType{}
	}
	typ, ok := dict["Type"].(Name)
	if !ok {
		return headType{}
	}
	return headType{typ: typ, settled: true}
}

// objectHead is the first n bytes of the file at an entry's offset, for a
// look at what an object holds that costs no parse. It is empty for an entry
// whose offset lies outside the file, which a cross-reference row may name
// however damaged the file is: the offset is read as a 64-bit number, and
// the end of the window is computed as one, so that neither the slice nor the
// addition can leave the file.
func (d *Document) objectHead(e xrefEntry, n int) []byte {
	if e.inStream || e.offset < 0 || e.offset >= int64(len(d.data)) {
		return nil
	}
	end := e.offset + int64(n)
	if end > int64(len(d.data)) {
		end = int64(len(d.data))
	}
	return d.data[e.offset:end]
}

// objectRead fetches the object with the number given, and reports whether
// the reader read it.
func (d *Document) objectRead(num int) (object, bool) {
	if v, ok := d.cache[num]; ok {
		if _, failed := v.(unread); failed {
			return nil, false
		}
		return v, true
	}
	if d.resolving[num] {
		return nil, false
	}
	e, ok := d.xref[num]
	if !ok || (!e.inStream && e.offset < 0) {
		return nil, false
	}
	// The cross-reference this read stands on. Reading an object may rebuild
	// it -- an offset that holds no object sends the reader scanning the file
	// -- and what was read before that is of a document this one no longer
	// is: it goes back to the caller, whose own reading is discarded, and is
	// published to nothing.
	defer d.beginRead()()
	generation := d.readingGeneration()
	if len(d.resolving) >= maxRefDepth {
		err := structureBound("indirect object reads nested past %d", maxRefDepth)
		d.noteBoundAt(generation, err)
		d.publish(generation, num, unread{err: err})
		return nil, false
	}
	if d.parsed >= maxObjects {
		// The objects read in one document, which a rebuild does not give
		// back: the file has cost them however its cross-reference is read.
		d.noteFileBound(structureBound("more than %d objects read", maxObjects))
		return nil, false
	}
	if d.parsedSpent() {
		// The objects already held cost everything the document may hold:
		// this one is left unread rather than parsed and then refused, so
		// that a file of objects that each hold the rest of it is not parsed
		// once per object.
		err := errParsedBudget()
		d.noteBoundAt(generation, err)
		d.publish(generation, num, unread{err: err})
		return nil, false
	}
	d.parsed++
	d.resolving[num] = true
	defer delete(d.resolving, num)
	var v object
	if e.inStream {
		var read bool
		if v, read = d.objectFromStream(num, e); !read {
			d.publish(generation, num, unread{})
			return nil, false
		}
	} else {
		n, gen, body, err := d.parseIndirectAt(int(e.offset))
		if n == num && isBound(err) {
			// The object is where the cross-reference says, and past a
			// bound: rebuilding the cross-reference finds the same bytes.
			d.noteBoundAt(generation, err)
			d.publish(generation, num, unread{err: err})
			return nil, false
		}
		if err != nil || n != num {
			// The offset does not hold this object: a damaged
			// cross-reference. Rebuild once and try again.
			if !d.reconstructed {
				err := d.reconstruct()
				if err == nil {
					delete(d.resolving, num)
					return d.objectRead(num)
				}
				// A bound met rebuilding is the file's: it scanned the file
				// itself, not an object one cross-reference named.
				d.noteFileBound(err)
			}
			d.publish(generation, num, unread{})
			return nil, false
		}
		if d.crypt != nil && !d.isEncryptionDictionary(num) {
			body = d.crypt.decryptObject(body, num, gen)
		}
		v = body
	}
	d.publish(generation, num, v)
	return v, true
}

// isEncryptionDictionary reports whether the number is the one the trailer's
// /Encrypt names. That dictionary's own strings are not encrypted (7.6.1):
// they are read as they stand whichever read reaches it -- the opening of the
// handler, which reads it with no handler installed, or an ordinary reference
// from another object's field, which may be read while one is -- so that the
// dictionary a handler is opened from is the same dictionary either way.
func (d *Document) isEncryptionDictionary(num int) bool {
	r, ok := d.trailer["Encrypt"].(ref)
	return ok && r.num == num
}

// publish records in the object cache what a read that began under the
// generation given found, and drops it where the cross-reference has been
// replaced since: an object read under the old one is not this document's
// object, and a read that straddled the rebuild must leave nothing of itself
// behind for the reading that follows.
func (d *Document) publish(generation, num int, v object) {
	if d.generation == generation {
		d.cache[num] = v
	}
}

// objectFromStream reads the object with the number given out of an object
// stream, and reports whether it read one.
func (d *Document) objectFromStream(num int, e xrefEntry) (object, bool) {
	// The cross-reference this read stands on, as objectRead holds one, read
	// before anything is resolved: what a stream of objects held under the
	// old one is not what this number names now.
	defer d.beginRead()()
	generation := d.readingGeneration()
	st, ok := d.objStmHeaders[e.stmNum]
	if !ok {
		if _, tried := d.objStms[e.stmNum]; tried {
			return nil, false
		}
		s, isStream := d.resolve(ref{e.stmNum, 0}).(*stream)
		if !isStream {
			d.markObjStm(generation, e.stmNum)
			return nil, false
		}
		loaded, err := d.loadObjStm(e.stmNum, s)
		if err != nil {
			// The failure of a read that straddled a rebuild is the old
			// cross-reference's, as its objects are: the stream this number
			// names now has not been read at all.
			d.noteBoundAt(generation, err)
			if d.generation == generation && d.undecoded == nil && !isBound(err) {
				d.undecoded = err
			}
			d.markObjStm(generation, e.stmNum)
			return nil, false
		}
		st = loaded
	}
	if st == nil {
		return nil, false
	}
	// The object is found by the number wanted, which the stream's own header
	// says where to read: the cross-reference entry's stmIndex names a
	// position in that header, and a position is not a name. An entry that
	// names the position of another object would otherwise have this number's
	// object read out of that one's bytes, and the record would carry, under
	// the number the page asked for, whatever the stream holds there.
	//
	// A header that declares one number twice says two things about it, and
	// the number alone no longer picks a body out. There the entry's position
	// decides, and only where the header declares this number at it: the
	// reader takes the body the file's own two statements agree on, and none
	// where they do not.
	off, ok := st.offsets[num]
	if st.twice[num] {
		if e.stmIndex < 0 || e.stmIndex >= len(st.order) || st.order[e.stmIndex] != num || st.offsetAt[e.stmIndex] < 0 {
			return nil, false
		}
		off, ok = st.offsetAt[e.stmIndex], true
	}
	if !ok {
		// The stream does not declare this object: it is unread, as an object
		// no cross-reference names is.
		return nil, false
	}
	// A lexer per object over the stream's data, as parseIndirectAt starts
	// one per object over the file, and charged the same way: an object
	// followed by a comment that runs to the end of the data is otherwise
	// read to that end once for every object the stream holds.
	allow := d.budgeted()
	lex := newLexer(st.data, off).within(allow)
	p := &parser{lex: lex, allow: allow}
	v, err := p.parseObject(0)
	if err != nil {
		d.noteBoundAt(generation, err)
		return nil, false
	}
	return v, true
}

// objStmParsed is an object stream's decoded data with its header read: the
// numbers the header declares in the order it declares them, the offset each
// pair gives, the offset by number for the numbers it declares once, and the
// numbers it declares more than once, which no number alone can find.
type objStmParsed struct {
	data     []byte
	offsets  map[int]int
	order    []int
	offsetAt []int
	twice    map[int]bool
}

func (d *Document) loadObjStm(num int, s *stream) (*objStmParsed, error) {
	defer d.beginRead()()
	generation := d.readingGeneration()
	if s.dict["Type"] != Name("ObjStm") {
		return nil, errors.New("not an object stream")
	}
	data, err := d.decodeStream(s, false, heldByDocument)
	if err != nil {
		return nil, err
	}
	n, _ := d.resolve(s.dict["N"]).(int64)
	first, _ := d.resolve(s.dict["First"]).(int64)
	if n > maxObjStmObjects {
		return nil, structureBound("object stream of more than %d objects", maxObjStmObjects)
	}
	if n < 0 || first < 0 || first > int64(len(data)) {
		return nil, errors.New("object stream header out of range")
	}
	// The header declares a number and an offset for each of the /N places it
	// has. Every place is kept, whether or not the reader can use it: the
	// cross-reference names an object by the place the header gives it, so a
	// place dropped would move every place after it. A number is declared by
	// its place whether or not the offset beside it is one the stream holds,
	// which is what makes a number declared twice a number no place alone
	// finds.
	// The header read from the stream is held for the life of the document,
	// so each place is charged for its ordered number and offset and for the
	// maps that find its number and count duplicates. The data itself is not
	// charged here: it is
	// either the file's own bytes, which the reader holds once, or bytes an
	// inflation charged to the budget that bounds them.
	// The header is read within the document's allowance, as every other
	// reading of bytes is: a stream whose header region begins with something
	// that runs to the end of it is read once and not once for every stream
	// that shares those bytes.
	lex := newLexer(data[:first], 0).within(d.budgeted())
	st := &objStmParsed{data: data, offsets: map[int]int{}}
	declared := map[int]int{}
	body := int64(len(data)) - first
	for i := int64(0); i < n; i++ {
		// Each declared place keeps two ordered slots and may have entries
		// in both the number-count and offset maps (or the duplicate map).
		// Reserve before publishing either the number or its place.
		if !d.chargeParsed(2*parsedMemberBytes + 2*parsedSlotBytes) {
			return nil, errParsedBudget()
		}
		t1, err1 := lex.next()
		if lex.spent {
			return nil, errParsedBudget()
		}
		if isBound(err1) {
			// A token of the header past a bound of the lexer is a bound and
			// not damage, and a bound is not read past: the header is no
			// reading at all, and what the places before it declared is
			// published no more than what the places after it would have. The
			// bound goes back to the caller, which keeps it as the file's
			// where the scan was the one reading, and as the
			// cross-reference's where an object of it was.
			return nil, err1
		}
		if err1 != nil || t1.kind == tokEOF {
			// The header ends, or holds a token the lexer could not read:
			// where the pairs after this one begin is not known, and the
			// places they would have are unreadable.
			break
		}
		inner, at := unreadableObject, -1
		if t1.kind == tokInteger && t1.i >= 0 && t1.i <= maxXrefEntries {
			// The number is declared by its place before the offset beside
			// it is read: a pair whose offset the header does not hold is a
			// place that holds no object, and the number is declared there
			// all the same -- which is what makes a number declared at two
			// places one no place alone finds.
			inner = int(t1.i)
			declared[inner]++
		}
		t2, err2 := lex.next()
		if lex.spent {
			return nil, errParsedBudget()
		}
		if isBound(err2) {
			// The offset beside the number is past a bound of the lexer: the
			// header is read no further than a bound either, whichever of its
			// two tokens met one.
			return nil, err2
		}
		if err2 != nil || t2.kind == tokEOF {
			st.order = append(st.order, inner)
			st.offsetAt = append(st.offsetAt, -1)
			break
		}
		// The offset is from the first object's, and lies within what the
		// stream holds after it. A negative one would name the header.
		if inner != unreadableObject && t2.kind == tokInteger && t2.i >= 0 && t2.i <= body {
			at = int(first + t2.i)
		}
		st.order = append(st.order, inner)
		st.offsetAt = append(st.offsetAt, at)
	}
	for int64(len(st.order)) < n {
		if !d.chargeParsed(2 * parsedSlotBytes) {
			return nil, errParsedBudget()
		}
		st.order = append(st.order, unreadableObject)
		st.offsetAt = append(st.offsetAt, -1)
	}
	for i, inner := range st.order {
		switch {
		case inner == unreadableObject || st.offsetAt[i] < 0:
		case declared[inner] > 1:
			// Declared at more than one place: no place alone names it, and
			// the cross-reference entry's own place decides.
			if st.twice == nil {
				st.twice = map[int]bool{}
			}
			st.twice[inner] = true
			delete(st.offsets, inner)
		default:
			st.offsets[inner] = st.offsetAt[i]
		}
	}
	if lex.spent {
		return nil, errParsedBudget()
	}
	if d.generation == generation {
		d.objStms[num] = &objStm{data: data, offsets: st.offsets}
		d.objStmOrder(num, st)
	}
	return st, nil
}

// unreadableObject stands in the order of an object stream's header for a
// pair the reader could not read: no object number, and no cross-reference
// entry naming that place finds an object at it.
const unreadableObject = -1

// markObjStm records that an object stream was tried and could not be read,
// unless the cross-reference that named it has since been replaced.
func (d *Document) markObjStm(generation, num int) {
	if d.generation == generation {
		d.objStms[num] = nil
	}
}

// objStmOrder keeps the parsed header beside the cached stream so that
// objectFromStream can index it; kept in a second map to leave objStm's
// shape simple.
func (d *Document) objStmOrder(num int, st *objStmParsed) {
	if d.objStmHeaders == nil {
		d.objStmHeaders = map[int]*objStmParsed{}
	}
	d.objStmHeaders[num] = st
}

// dictOf resolves v and returns it as a dictionary, or nil. A stream's
// dictionary is returned for a stream.
func (d *Document) dictOf(v object) Dict {
	switch x := d.resolve(v).(type) {
	case Dict:
		return x
	case *stream:
		return x.dict
	}
	return nil
}

// arrayOf resolves v and returns it as an array, or nil.
func (d *Document) arrayOf(v object) Array {
	a, _ := d.resolve(v).(Array)
	return a
}

// intOf resolves v and returns it as an integer, with ok false otherwise.
// A real with no fraction within the int64 range is admitted, since writers
// emit "3.0". Where the document's own declaration is recorded, a real is
// not an integer: see declaredInteger.
func (d *Document) intOf(v object) (int64, bool) {
	switch x := d.resolve(v).(type) {
	case int64:
		return x, true
	case float64:
		if x >= -(1<<63) && x < 1<<63 && x == math.Trunc(x) {
			return int64(x), true
		}
	}
	return 0, false
}

// numOf resolves v and returns it as a float.
func (d *Document) numOf(v object) (float64, bool) {
	switch x := d.resolve(v).(type) {
	case int64:
		return float64(x), true
	case float64:
		return x, true
	}
	return 0, false
}

// nameOf resolves v and returns it as a name.
func (d *Document) nameOf(v object) (Name, bool) {
	n, ok := d.resolve(v).(Name)
	return n, ok
}

func sortInts(a []int) {
	// Insertion sort would be quadratic on large files; use the standard
	// library's sort through a small shim to keep imports local.
	sortSlice(a)
}
