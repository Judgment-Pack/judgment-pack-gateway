package pdf

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"math"
	"regexp"
	"strconv"
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
	// have inflated. A file whose objects do not overlap is parsed about once:
	// each of its bytes belongs to one object, and holding a byte costs more
	// than the byte -- an array element is an interface and a slot where the
	// file has "1 ", a dictionary member a map entry where the file has
	// "/A 1" -- so a well-formed file reaches a small multiple of its length
	// and never this one. What it bounds is a file whose objects hold the same
	// bytes over and over: "k 0 obj (" with no closing parenthesis gives every
	// object a copy of the rest of the file, and what the reader holds then
	// grows with the square of the file rather than with the file.
	parsedBytesPerFileByte = 16
	// parsedItemBytes is what one parsed value costs to hold beyond its own
	// bytes -- an interface and what it points at -- and parsedMemberBytes what
	// one dictionary member costs beyond its name: a map entry and its value.
	parsedItemBytes   = 16
	parsedMemberBytes = 48
)

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
	// parsedBytes is what the objects the document holds cost to hold, with
	// the values the rebuild parses on its way to a trailer counted while it
	// parses them; it is released with the cache it was charged for.
	parsedBytes int64
	crypt       *cryptHandler
	// budget is the inflation budget shared by every stream of the document.
	budget *inflateBudget
	// resolving guards against a reference cycle through object streams.
	resolving map[int]bool
	// fontBudget counts what the document's fonts hold, and cmaps the CMap
	// streams read, by stream, nil for one not used.
	fontBudget fontBudget
	cmaps      map[*stream]*cmap
	// bound is the first structure or inflate bound met while reading an
	// object, which leaves that object unread; the walk ends at it.
	bound error
	// undecoded is the first error met loading a stream the cross-reference
	// names as an object stream -- a stream that cannot be decoded, or that is
	// not an object stream -- which leaves the objects it holds unread; the
	// walk ends at it too.
	undecoded error
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

// undecodedMessage is the defect of a document with an object stream that
// could not be decoded, met while it was opened or its page tree walked.
const undecodedMessage = "the file has an object stream the reader could not decode, met while it was opened or its page tree walked"

// walkDefect is the message of the defect a walk ends at, a bound first, or
// "" when reading objects has met none.
func (d *Document) walkDefect() string {
	switch {
	case d.bound != nil:
		return boundMessage
	case d.undecoded != nil:
		return undecodedMessage
	}
	return ""
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
func (d *Document) deadlineNow() bool {
	return d.ctx != nil && d.ctx.Err() != nil
}

// deadline is the error a loop ends at when the deadline has passed. It is
// neither damage nor a bound: the run ends at the deadline, as it does when
// the deadline passes while the page tree is walked.
func (d *Document) deadline() error {
	return fmt.Errorf("the deadline passed while the document was opened: %w", d.ctx.Err())
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
		d.xref = map[int]xrefEntry{}
		d.trailer = Dict{}
		d.cache = map[int]object{}
		d.objStms = map[int]*objStm{}
		if err := d.reconstruct(); err != nil {
			return nil, err
		}
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
		trailer, err := d.readXrefSection(offset)
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
	lex := newLexer(d.data, int(offset))
	lex.skipSpace()
	if bytes.HasPrefix(d.data[lex.pos:], []byte("xref")) {
		lex.pos += len("xref")
		return d.readXrefTable(lex)
	}
	// "N G obj" with a stream of /Type /XRef.
	num, _, body, err := d.parseIndirectAt(int(offset))
	if err != nil {
		return nil, malformedBy(err, "cross-reference at offset %d", offset)
	}
	s, ok := body.(*stream)
	if !ok {
		return nil, malformed("cross-reference at offset %d is neither a table nor a stream", offset)
	}
	_ = num
	return d.readXrefStream(s)
}

func (d *Document) readXrefTable(lex *lexer) (Dict, error) {
	p := &parser{lex: lex}
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

func (d *Document) readXrefStream(s *stream) (Dict, error) {
	if s.dict["Type"] != Name("XRef") {
		return nil, malformed("cross-reference stream is not /Type /XRef")
	}
	data, err := d.decodeStream(s, true)
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
	found := 0
	matches := objHeader.FindAllSubmatchIndex(d.data, maxScanObjects+1)
	if len(matches) > maxScanObjects {
		return structureBound("more than %d objects found by scanning", maxScanObjects)
	}
	for _, m := range matches {
		if d.deadlinePassed() {
			return d.deadline()
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
		return malformed("no object found by scanning the file")
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
			return d.deadline()
		}
		i := bytes.Index(d.data[at:], []byte("trailer"))
		if i < 0 {
			break
		}
		at = at + i + len("trailer")
		lex := newLexer(d.data, at)
		// A trailer is a dictionary; a "trailer" followed by anything else is
		// the word in some other place in the file, and is not parsed. Comments
		// and whitespace may lie between the two.
		lex.skipSpace()
		if !bytes.HasPrefix(d.data[lex.pos:], []byte("<<")) {
			continue
		}
		p := &parser{lex: lex}
		obj, err := p.parseObject(0)
		// A candidate is charged the bytes it read of the file, whether or not
		// they parsed: what one holds is about what it read, and a file of
		// candidates that each read the rest of it ends this loop at the bound
		// rather than reading the file once for every one of them.
		if !d.chargeParsed(int64(lex.pos - at)) {
			return errParsedBudget()
		}
		if err != nil {
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
	d.cache = map[int]object{}
	d.releaseParsed()
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
			// more often than not, and the scan cannot tell.
			st, err := d.loadObjStm(num, s)
			if err != nil {
				if isBound(err) {
					return err
				}
				continue
			}
			idx := 0
			for _, inner := range st.order {
				if _, taken := d.xref[inner]; !taken {
					d.xref[inner] = xrefEntry{inStream: true, stmNum: num, stmIndex: idx}
				}
				idx++
			}
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
			if !bytes.Contains(d.objectHead(e, 256), []byte("/Catalog")) {
				continue
			}
			if dict, ok := d.resolve(ref{num, e.gen}).(Dict); ok && dict["Type"] == Name("Catalog") {
				trailer["Root"] = ref{num, e.gen}
				break
			}
		}
	}
	d.trailer = trailer
	d.cache = map[int]object{}
	d.releaseParsed()
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
	lex := newLexer(d.data, offset)
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
	p := &parser{lex: lex}
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
	for depth := 0; ; depth++ {
		r, ok := v.(ref)
		if !ok {
			return v, true
		}
		if depth == maxRefDepth {
			d.noteBound(structureBound("references to references past %d", maxRefDepth))
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

// parsedBudget is what the objects a document holds may cost to hold: the
// file's own bytes and the bytes its streams have inflated so far,
// parsedBytesPerFileByte times over. The objects of an object stream are
// parsed out of inflated bytes rather than out of the file, so the allowance
// grows with what was inflated -- which the inflation budget bounds -- and
// not without end.
func (d *Document) parsedBudget() int64 {
	inflated := int64(0)
	if d.budget != nil {
		inflated = d.budget.used
	}
	return parsedBytesPerFileByte * (int64(len(d.data)) + inflated)
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

// releaseParsed drops the charges of objects the reader no longer holds,
// called where the cache they were charged for is emptied.
func (d *Document) releaseParsed() { d.parsedBytes = 0 }

// errParsedBudget is the document past the bytes its parsed objects may
// hold. It is a structure bound: the file has more structure than the reader
// holds, and rebuilding the cross-reference would find the same bytes.
func errParsedBudget() error {
	return structureBound("the objects read hold more than %d bytes for each byte of the file and of what it inflates to", parsedBytesPerFileByte)
}

// parsedBytesOf is what holding a parsed value costs, near enough to charge
// it: its own bytes for a string, a name or a stream, whose bytes are the
// file's own, and for an array or a dictionary what its elements or members
// cost beyond theirs. A value holds no other value twice and no value holds
// itself, since a reference is held as a number, so this walk ends within the
// nesting the parser admits.
func parsedBytesOf(o object) int64 {
	switch x := o.(type) {
	case String:
		return parsedItemBytes + int64(len(x))
	case Name:
		return parsedItemBytes + int64(len(x))
	case Array:
		n := int64(parsedItemBytes)
		for _, item := range x {
			n += parsedItemBytes + parsedBytesOf(item)
		}
		return n
	case Dict:
		n := int64(parsedItemBytes)
		for name, v := range x {
			n += parsedMemberBytes + int64(len(name)) + parsedBytesOf(v)
		}
		return n
	case *stream:
		return int64(len(x.raw)) + parsedBytesOf(x.dict)
	}
	return parsedItemBytes
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
	if len(d.resolving) >= maxRefDepth {
		err := structureBound("indirect object reads nested past %d", maxRefDepth)
		d.noteBound(err)
		d.cache[num] = unread{err: err}
		return nil, false
	}
	if d.parsed >= maxObjects {
		d.noteBound(structureBound("more than %d objects read", maxObjects))
		return nil, false
	}
	if d.parsedSpent() {
		// The objects already held cost everything the document may hold:
		// this one is left unread rather than parsed and then refused, so
		// that a file of objects that each hold the rest of it is not parsed
		// once per object.
		err := errParsedBudget()
		d.noteBound(err)
		d.cache[num] = unread{err: err}
		return nil, false
	}
	d.parsed++
	d.resolving[num] = true
	defer delete(d.resolving, num)
	var v object
	if e.inStream {
		var read bool
		if v, read = d.objectFromStream(e); !read {
			d.cache[num] = unread{}
			return nil, false
		}
	} else {
		n, gen, body, err := d.parseIndirectAt(int(e.offset))
		if n == num && isBound(err) {
			// The object is where the cross-reference says, and past a
			// bound: rebuilding the cross-reference finds the same bytes.
			d.noteBound(err)
			d.cache[num] = unread{err: err}
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
				d.noteBound(err)
			}
			d.cache[num] = unread{}
			return nil, false
		}
		if d.crypt != nil {
			body = d.crypt.decryptObject(body, num, gen)
		}
		v = body
	}
	if !d.chargeParsed(parsedBytesOf(v)) {
		// The object is read, and holding it would take the document past
		// what its objects may hold: it is left unread, as one past any other
		// structure bound is, and the budget is spent so that the objects
		// after it are not parsed either.
		err := errParsedBudget()
		d.noteBound(err)
		d.cache[num] = unread{err: err}
		return nil, false
	}
	d.cache[num] = v
	return v, true
}

// objectFromStream reads an object out of an object stream, and reports
// whether it read one.
func (d *Document) objectFromStream(e xrefEntry) (object, bool) {
	st, ok := d.objStmHeaders[e.stmNum]
	if !ok {
		if _, tried := d.objStms[e.stmNum]; tried {
			return nil, false
		}
		s, isStream := d.resolve(ref{e.stmNum, 0}).(*stream)
		if !isStream {
			d.objStms[e.stmNum] = nil
			return nil, false
		}
		loaded, err := d.loadObjStm(e.stmNum, s)
		if err != nil {
			d.noteBound(err)
			if d.undecoded == nil && !isBound(err) {
				d.undecoded = err
			}
			d.objStms[e.stmNum] = nil
			return nil, false
		}
		st = loaded
	}
	if st == nil {
		return nil, false
	}
	// Find the object by its index in the header; the entry's stmIndex
	// names the position, but writers disagree, so the number found at
	// that index is checked against the number wanted via the offsets map.
	if e.stmIndex < 0 || e.stmIndex >= len(st.order) {
		return nil, false
	}
	num := st.order[e.stmIndex]
	off, ok := st.offsets[num]
	if !ok {
		return nil, false
	}
	lex := newLexer(st.data, off)
	p := &parser{lex: lex}
	v, err := p.parseObject(0)
	if err != nil {
		d.noteBound(err)
		return nil, false
	}
	return v, true
}

// objStmParsed is an object stream's decoded data with its header read.
type objStmParsed struct {
	data    []byte
	offsets map[int]int
	order   []int
}

func (d *Document) loadObjStm(num int, s *stream) (*objStmParsed, error) {
	if s.dict["Type"] != Name("ObjStm") {
		return nil, errors.New("not an object stream")
	}
	data, err := d.decodeStream(s, false)
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
	lex := newLexer(data[:first], 0)
	st := &objStmParsed{data: data, offsets: map[int]int{}}
	for i := int64(0); i < n; i++ {
		t1, err := lex.next()
		if err != nil || t1.kind != tokInteger {
			break
		}
		t2, err := lex.next()
		if err != nil || t2.kind != tokInteger {
			break
		}
		off := first + t2.i
		if t1.i < 0 || t1.i > maxXrefEntries || off < 0 || off > int64(len(data)) {
			continue
		}
		st.offsets[int(t1.i)] = int(off)
		st.order = append(st.order, int(t1.i))
	}
	d.objStms[num] = &objStm{data: data, offsets: st.offsets}
	d.objStmOrder(num, st)
	return st, nil
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
