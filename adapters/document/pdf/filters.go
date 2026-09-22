package pdf

import (
	"bytes"
	"compress/flate"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"hash/adler32"
	"io"
)

// inflateBudget is what a document's streams may inflate to in total,
// and any one of them: a small file that inflates without end is stopped
// here, not by memory. Every filter and predictor charges the bytes it
// produces to used as it produces them, including one that then stops at a
// defect, so each step of a stream with several filters counts; one stopped
// at the total leaves it spent, and every filter or predictor after it finds
// nothing left.
type inflateBudget struct {
	total, one int64
	used       int64
}

// decoded is one filter's or predictor's output, held within the budget.
type decoded struct {
	budget *inflateBudget
	limit  int64
	buf    []byte
	over   bool
}

// output begins a decoder's output. Its limit is the per-stream bound or
// what is left of the total, whichever is smaller; a decoder that finds
// nothing left is past the bound before it produces anything. sizeHint is
// what the caller expects to produce, and is capped at the limit.
func (b *inflateBudget) output(sizeHint int) (*decoded, error) {
	limit := b.one
	if remaining := b.total - b.used; remaining < limit {
		limit = remaining
	}
	if limit <= 0 {
		return nil, errInflateBound
	}
	if sizeHint < 0 {
		sizeHint = 0
	}
	if int64(sizeHint) > limit {
		sizeHint = int(limit)
	}
	return &decoded{budget: b, limit: limit, buf: make([]byte, 0, sizeHint)}, nil
}

// Write appends p to the output and charges it. When p would take the output
// past its limit, nothing of p is kept, the output is charged up to its limit
// -- so an output limited by what was left of the total leaves the total
// spent -- and the bound is reported, for this write and any after it.
func (o *decoded) Write(p []byte) (int, error) {
	if o.over {
		return 0, errInflateBound
	}
	room := o.limit - int64(len(o.buf))
	if int64(len(p)) > room {
		o.budget.used += room
		o.over = true
		return 0, errInflateBound
	}
	o.budget.used += int64(len(p))
	o.buf = append(o.buf, p...)
	return len(p), nil
}

// WriteByte is Write for one byte.
func (o *decoded) WriteByte(c byte) error {
	if o.over || int64(len(o.buf)) >= o.limit {
		_, err := o.Write([]byte{c})
		return err
	}
	o.budget.used++
	o.buf = append(o.buf, c)
	return nil
}

var (
	errInflateBound      = errors.New("stream inflates past the bound")
	errUnsupportedFilter = errors.New("unsupported filter")
)

// charged is a decoder's output that is charged to the budget and kept
// nowhere: what an inline image decodes to is not the page's text, and the
// reader decodes it only to learn how many of its bytes the encoding took.
// The checksum of what passed through is kept, since a zlib stream ends with
// the checksum of what it decodes to and the reader has decoded it.
type charged struct {
	budget *inflateBudget
	limit  int64
	held   int64
	sum    hash.Hash32
}

// discard begins an output that is charged and dropped, with the bound the
// budget gives any other output.
func (b *inflateBudget) discard() (*charged, error) {
	limit := b.one
	if remaining := b.total - b.used; remaining < limit {
		limit = remaining
	}
	if limit <= 0 {
		return nil, errInflateBound
	}
	return &charged{budget: b, limit: limit, sum: adler32.New()}, nil
}

func (c *charged) Write(p []byte) (int, error) {
	room := c.limit - c.held
	if int64(len(p)) > room {
		c.budget.used += room
		c.held = c.limit
		return 0, errInflateBound
	}
	c.budget.used += int64(len(p))
	c.held += int64(len(p))
	c.sum.Write(p)
	return len(p), nil
}

// filterSpec is one filter and its parameters.
type filterSpec struct {
	name  Name
	parms Dict
}

// filtersOf reads /Filter and /DecodeParms (or their abbreviations) from a
// stream dictionary.
func (d *Document) filtersOf(dict Dict) ([]filterSpec, error) {
	fv, ok := dict["Filter"]
	if !ok {
		fv = dict["F"]
		// /F is also a file specification; only a name or array counts.
		switch fv.(type) {
		case Name, Array:
		default:
			fv = nil
		}
	}
	pv, ok := dict["DecodeParms"]
	if !ok {
		pv = dict["DP"]
	}
	var specs []filterSpec
	switch f := d.resolve(fv).(type) {
	case nil:
		return nil, nil
	case Name:
		specs = []filterSpec{{name: f, parms: d.dictOf(pv)}}
	case Array:
		parms := d.arrayOf(pv)
		for i, item := range f {
			name, ok := d.nameOf(item)
			if !ok {
				return nil, malformed("/Filter array holds a non-name")
			}
			var p Dict
			if i < len(parms) {
				p = d.dictOf(parms[i])
			} else if len(f) == 1 {
				p = d.dictOf(pv)
			}
			specs = append(specs, filterSpec{name: name, parms: p})
		}
	default:
		return nil, malformed("/Filter is neither a name nor an array")
	}
	return specs, nil
}

// decodeStream decrypts (unless the stream is exempt) and applies every
// standard filter, refusing an image filter and any it does not know.
// noDecrypt is for cross-reference streams, which are never encrypted.
func (d *Document) decodeStream(s *stream, noDecrypt bool) ([]byte, error) {
	// Decoding a stream is one read: its filters, their parameters and its
	// length are fields of one dictionary. See beginRead.
	defer d.beginRead()()
	data := s.raw
	if d.crypt != nil && !noDecrypt && s.dict["Type"] != Name("XRef") {
		var err error
		data, err = d.crypt.decryptStream(s, data)
		if err != nil {
			return nil, err
		}
	}
	specs, err := d.filtersOf(s.dict)
	if err != nil {
		return nil, err
	}
	for _, f := range specs {
		switch f.name {
		case "FlateDecode", "Fl":
			data, err = d.inflate(data)
		case "LZWDecode", "LZW":
			early := int64(1)
			if f.parms != nil {
				if v, ok := d.intOf(f.parms["EarlyChange"]); ok {
					early = v
				}
			}
			data, err = d.lzwDecode(data, early != 0)
		case "ASCIIHexDecode", "AHx":
			data, err = d.asciiHexDecode(data)
		case "ASCII85Decode", "A85":
			data, err = d.ascii85Decode(data)
		case "RunLengthDecode", "RL":
			data, err = d.runLengthDecode(data)
		case "Crypt":
			// /Identity, or the document's filter already applied.
		case "DCTDecode", "DCT", "JPXDecode", "JBIG2Decode", "CCITTFaxDecode", "CCF":
			return nil, fmt.Errorf("%w: %s", errUnsupportedFilter, f.name)
		default:
			return nil, fmt.Errorf("%w: %s", errUnsupportedFilter, f.name)
		}
		if err != nil {
			return nil, err
		}
		if f.parms != nil {
			data, err = d.applyPredictor(data, f.parms)
			if err != nil {
				return nil, err
			}
		}
	}
	return data, nil
}

// errDeflateData is deflate data that ends before its final block, or that
// is not deflate data where it is read: a stream that cannot be decoded.
var errDeflateData = errors.New("FlateDecode: the deflate data is cut off or corrupt")

// inflateDeflate reads raw deflate data to the end of its final block into an
// output within the budget, charging every byte as it is read. Data that
// ends before the final block, or is corrupt, is not decoded, whatever was
// produced before the defect; bytes after the final block are not read.
// wrote reports whether the data was taken as deflate data: decoded, stopped
// at a bound, or stopped at a defect after producing something.
func (d *Document) inflateDeflate(data []byte) (out []byte, wrote bool, err error) {
	o, err := d.budget.output(0)
	if err != nil {
		return nil, false, err
	}
	fr := flate.NewReader(bytes.NewReader(data))
	defer fr.Close()
	_, err = io.Copy(o, fr)
	switch {
	case err == nil:
		return o.buf, true, nil
	case errors.Is(err, errInflateBound):
		return nil, true, err
	}
	return nil, len(o.buf) > 0, errDeflateData
}

// zlibHeader reports whether data begins with the two bytes of a zlib
// header, as compress/zlib reads them, that names no preset dictionary.
func zlibHeader(data []byte) bool {
	if len(data) < 2 {
		return false
	}
	cmf, flg := data[0], data[1]
	return cmf&0x0f == 8 && cmf>>4 <= 7 && (uint16(cmf)<<8|uint16(flg))%31 == 0 && flg&0x20 == 0
}

// inflate applies FlateDecode: zlib, or raw deflate when the zlib header is
// missing, after any leading whitespace. The deflate data must reach the end
// of its final block. The zlib trailer after it, the Adler-32 checksum, is not
// read: a trailer missing or wrong after deflate data that ended cleanly is
// common damage, and is not taken as a stream that cannot be decoded.
func (d *Document) inflate(data []byte) ([]byte, error) {
	trimmed := bytes.TrimLeft(data, " \r\n\t")
	if len(trimmed) == 0 {
		if _, err := d.budget.output(0); err != nil {
			return nil, err
		}
		return nil, nil
	}
	if zlibHeader(trimmed) {
		out, wrote, err := d.inflateDeflate(trimmed[2:])
		if err == nil || wrote {
			return out, err
		}
		// Nothing decoded after what looked like a zlib header: the header
		// may be the first bytes of raw deflate data.
	}
	out, _, err := d.inflateDeflate(trimmed)
	return out, err
}

// lzwDecode implements the LZW variant PDF uses (TIFF-style, MSB-first,
// with early code-length change by default), which the standard library's
// compress/lzw does not.
func (d *Document) lzwDecode(data []byte, early bool) ([]byte, error) {
	out, err := d.budget.output(len(data) * 2)
	if err != nil {
		return nil, err
	}
	if _, _, err := d.lzwDecodeTo(data, early, out); err != nil {
		return nil, err
	}
	return out.buf, nil
}

// lzwDecodeTo decodes the codes of data into out, and reports how many bytes
// of data they took and whether the end-of-data code ended them. Data that
// runs out before that code ends where it ends, which a stream may do and the
// end of an inline image may not: the caller is told which happened. The
// deadline is read as the codes are, on the cadence the package reads it at,
// since a stream of clear codes produces nothing to charge and would
// otherwise run to the end of what it was given.
func (d *Document) lzwDecodeTo(data []byte, early bool, out io.Writer) (consumed int, ended bool, err error) {
	const (
		clearCode = 256
		eodCode   = 257
	)
	// The literals stand for themselves whatever the table holds: a clear
	// code resets what was learnt after them, and does not build them again.
	dict := make([][]byte, 4096)
	literals := make([]byte, 256)
	for i := range literals {
		literals[i] = byte(i)
		dict[i] = literals[i : i+1 : i+1]
	}
	next := 258
	codeLen := 9
	var prev []byte
	var bitBuf uint32
	bitCount := 0
	pos := 0
	earlyDelta := 0
	if early {
		earlyDelta = 1
	}
	for {
		if d.deadlinePassed() {
			return pos, false, d.deadline()
		}
		for bitCount < codeLen {
			if pos >= len(data) {
				return pos, false, nil
			}
			bitBuf = bitBuf<<8 | uint32(data[pos])
			pos++
			bitCount += 8
		}
		code := int(bitBuf >> uint(bitCount-codeLen) & (1<<uint(codeLen) - 1))
		bitCount -= codeLen
		switch {
		case code == clearCode:
			next = 258
			codeLen = 9
			prev = nil
			continue
		case code == eodCode:
			return pos, true, nil
		}
		var entry []byte
		switch {
		case code < next && dict[code] != nil:
			entry = dict[code]
		case code == next && prev != nil:
			entry = append(append([]byte{}, prev...), prev[0])
		default:
			return pos, false, malformed("LZWDecode: code %d outside the table", code)
		}
		if _, err := out.Write(entry); err != nil {
			return pos, false, err
		}
		if prev != nil && next < 4096 {
			dict[next] = append(append([]byte{}, prev...), entry[0])
			next++
		}
		if next+earlyDelta >= 1<<uint(codeLen) && codeLen < 12 {
			codeLen++
		}
		prev = entry
	}
}

func (d *Document) asciiHexDecode(data []byte) ([]byte, error) {
	out, err := d.budget.output(len(data) / 2)
	if err != nil {
		return nil, err
	}
	var pending byte
	half := false
	for _, c := range data {
		if c == '>' {
			break
		}
		if isWhitespace(c) {
			continue
		}
		v, ok := hexValue(c)
		if !ok {
			return nil, malformed("ASCIIHexDecode: not a hex digit")
		}
		if half {
			if err := out.WriteByte(pending<<4 | v); err != nil {
				return nil, err
			}
			half = false
		} else {
			pending, half = v, true
		}
	}
	if half {
		if err := out.WriteByte(pending << 4); err != nil {
			return nil, err
		}
	}
	return out.buf, nil
}

// ascii85Decode decodes the whole of an ASCII85 stream, to its "~>" or its
// end: groups of five characters to four bytes, 'z' between groups to four
// zero bytes, and a final group of two to four characters to one byte fewer
// than it has. Bytes up to and including the space are skipped wherever they
// fall; any other byte outside the encoding, or a final group of one
// character, is a defect.
func (d *Document) ascii85Decode(data []byte) ([]byte, error) {
	data = bytes.TrimLeft(data, " \r\n\t")
	data = bytes.TrimPrefix(data, []byte("<~"))
	if i := bytes.Index(data, []byte("~>")); i >= 0 {
		data = data[:i]
	}
	out, err := d.budget.output(len(data) / 5 * 4)
	if err != nil {
		return nil, err
	}
	var group [4]byte
	var v uint32
	n := 0
	for _, c := range data {
		switch {
		case c <= ' ':
			continue
		case c == 'z' && n == 0:
			if _, err := out.Write(zeroGroup[:]); err != nil {
				return nil, err
			}
			continue
		case '!' <= c && c <= 'u':
			v = v*85 + uint32(c-'!')
			n++
		default:
			return nil, malformed("ASCII85Decode: a byte outside the encoding")
		}
		if n == 5 {
			binary.BigEndian.PutUint32(group[:], v)
			if _, err := out.Write(group[:]); err != nil {
				return nil, err
			}
			v, n = 0, 0
		}
	}
	switch n {
	case 0:
	case 1:
		return nil, malformed("ASCII85Decode: a final group of one character")
	default:
		// A short final group stands for its characters padded with the
		// largest digit; it yields one byte fewer than it has characters.
		for i := n; i < 5; i++ {
			v = v*85 + 84
		}
		binary.BigEndian.PutUint32(group[:], v)
		if _, err := out.Write(group[:n-1]); err != nil {
			return nil, err
		}
	}
	return out.buf, nil
}

var zeroGroup [4]byte

func (d *Document) runLengthDecode(data []byte) ([]byte, error) {
	out, err := d.budget.output(len(data))
	if err != nil {
		return nil, err
	}
	var run [128]byte
	for i := 0; i < len(data); {
		l := int(data[i])
		i++
		switch {
		case l == 128:
			return out.buf, nil
		case l < 128:
			end := i + l + 1
			if end > len(data) {
				end = len(data)
			}
			if _, err := out.Write(data[i:end]); err != nil {
				return nil, err
			}
			i = end
		default:
			if i >= len(data) {
				return out.buf, nil
			}
			n := 257 - l
			for j := 0; j < n; j++ {
				run[j] = data[i]
			}
			if _, err := out.Write(run[:n]); err != nil {
				return nil, err
			}
			i++
		}
	}
	return out.buf, nil
}

// applyPredictor undoes the PNG and TIFF predictors of /DecodeParms.
func (d *Document) applyPredictor(data []byte, parms Dict) ([]byte, error) {
	predictor, _ := d.intOf(parms["Predictor"])
	if predictor <= 1 {
		return data, nil
	}
	colors := int64(1)
	if v, ok := d.intOf(parms["Colors"]); ok {
		colors = v
	}
	bpc := int64(8)
	if v, ok := d.intOf(parms["BitsPerComponent"]); ok {
		bpc = v
	}
	columns := int64(1)
	if v, ok := d.intOf(parms["Columns"]); ok {
		columns = v
	}
	if colors < 1 || colors > 64 || columns < 1 || columns > 1<<20 || (bpc != 1 && bpc != 2 && bpc != 4 && bpc != 8 && bpc != 16) {
		return nil, malformed("predictor parameters out of range")
	}
	bpp := int((colors*bpc + 7) / 8)
	if bpp < 1 {
		bpp = 1
	}
	rowLen := int((colors*bpc*columns + 7) / 8)
	// A row the data ends inside is undone as far as the data goes, which is
	// what a reader of PDFs shows for the files that carry one: every byte of
	// such a row is undone against bytes before it, all of them present, so
	// what comes out is what the row holds and nothing is invented. Leaving
	// it out instead would empty a stream whose one row the data does not
	// hold to its end -- a page listed as holding no text where the file
	// holds text the reader dropped without a word.
	if predictor == 2 {
		if bpc != 8 {
			return nil, fmt.Errorf("%w: TIFF predictor with %d bits per component", errUnsupportedFilter, bpc)
		}
		// Undone in a copy: data may be bytes another stream or the file
		// still holds.
		out, err := d.budget.output(len(data))
		if err != nil {
			return nil, err
		}
		if _, err := out.Write(data); err != nil {
			return nil, err
		}
		for r := 0; r < len(out.buf); r += rowLen {
			row := out.buf[r:min(r+rowLen, len(out.buf))]
			for i := bpp; i < len(row); i++ {
				row[i] += row[i-bpp]
			}
		}
		return out.buf, nil
	}
	if predictor < 10 || predictor > 15 {
		return nil, fmt.Errorf("%w: predictor %d", errUnsupportedFilter, predictor)
	}
	out, err := d.budget.output(len(data))
	if err != nil {
		return nil, err
	}
	// Each row is its filter type and then its bytes, written as they lie in
	// the data and undone in place against the row before them in the output:
	// no row is allocated, and no row longer than the data is. Only the last
	// row can be one the data ends inside, and it is undone as far as it goes.
	for r := 0; r < len(data); r += rowLen + 1 {
		ft := data[r]
		if ft > 4 {
			return nil, malformed("PNG predictor: filter type %d", ft)
		}
		held := min(rowLen, len(data)-(r+1))
		start := len(out.buf)
		if _, err := out.Write(data[r+1 : r+1+held]); err != nil {
			return nil, err
		}
		row := out.buf[start:]
		var prior []byte
		if start >= rowLen {
			prior = out.buf[start-rowLen : start]
		}
		for i := 0; i < held; i++ {
			var left, up, upLeft byte
			if i >= bpp {
				left = row[i-bpp]
				if prior != nil {
					upLeft = prior[i-bpp]
				}
			}
			if prior != nil {
				up = prior[i]
			}
			switch ft {
			case 1:
				row[i] += left
			case 2:
				row[i] += up
			case 3:
				row[i] += byte((int(left) + int(up)) / 2)
			case 4:
				row[i] += paeth(left, up, upLeft)
			}
		}
	}
	return out.buf, nil
}

func paeth(a, b, c byte) byte {
	p := int(a) + int(b) - int(c)
	pa, pb, pc := abs(p-int(a)), abs(p-int(b)), abs(p-int(c))
	if pa <= pb && pa <= pc {
		return a
	}
	if pb <= pc {
		return b
	}
	return c
}

func abs(x int) int {
	if x < 0 {
		return -x
	}
	return x
}

// Where a filter's own data ends. An inline image carries no length the
// reader can believe -- viewers disagree over /L, and a boundary taken from a
// declaration is one reading of the page rather than the page -- so for an
// image a filter encodes the reader asks the filter: every filter framed
// below ends its data at the end its own encoding gives it, and that is where
// the image ends. What a framing decodes is charged to the document's inflate
// budget and dropped, the reader wanting the offset and not the picture; the
// input is bounded by the caller, which hands over at most the bytes one
// inline image may hold; and the deadline is read as the work goes, since a
// stream that decodes to nothing is still a stream to walk.
//
// That end is the encoding's structure and not a decoder's verdict on what it
// holds. The fax and JPEG framings walk the markers and decode no row and no
// block, so the end they give is the structural end -- an end-of-block, an
// end-of-image -- that the decoders this reader's maintainers can name stop
// at, and data that holds nothing but those markers frames all the same. A
// decoder that validates the rows or the blocks may refuse such an image and
// recover some other reading of the page; that recovery is not this reader's
// boundary, and the record says what the encoding's own structure says.
//
// The filters framed here are the seven the specification's inline-image
// abbreviation list holds -- ASCIIHexDecode, ASCII85Decode, LZWDecode,
// FlateDecode, RunLengthDecode, CCITTFaxDecode and DCTDecode (Table 93).
// JBIG2Decode and JPXDecode are not in that list and are not framed here:
// where an inline image encoded by one ends is not something this reader
// establishes.

// errFilterNotFramed is a filter whose data this reader does not frame. It is
// told from a framing that met a bound or found no end: those are the image's
// defect, reported on the page, and this one is the reader's reach.
var errFilterNotFramed = errors.New("the reader does not frame this filter's data")

// errFilterUnended is encoded data that does not end within what the reader
// was given.
var errFilterUnended = errors.New("the encoded data of an inline image does not end")

// filterFraming is the offset at which the data of a stream encoded by the
// filter named ends. errFilterNotFramed says the reader does not frame this
// filter, errFilterUnended that the data holds no end within what it was
// given, and any other error is the encoding's own defect or a bound met
// framing it -- the page's problem, and no reason to read the image another
// way.
func (d *Document) filterFraming(filter Name, parms object, data []byte) (int, error) {
	switch filter {
	case "AHx", "ASCIIHexDecode":
		return d.asciiHexFraming(data)
	case "A85", "ASCII85Decode":
		return d.ascii85Framing(data)
	case "RL", "RunLengthDecode":
		return d.runLengthFraming(data)
	case "Fl", "FlateDecode":
		return d.flateFraming(data)
	case "LZW", "LZWDecode":
		early := true
		if p := d.dictOf(firstParms(parms)); p != nil {
			if v, ok := d.intOf(p["EarlyChange"]); ok {
				early = v != 0
			}
		}
		return d.lzwFraming(data, early)
	case "DCT", "DCTDecode":
		return d.jpegFraming(data)
	case "CCF", "CCITTFaxDecode":
		return d.ccittFraming(firstParms(parms), data)
	}
	return 0, errFilterNotFramed
}

// firstParms is the decode parameters of the first filter, which a stream
// with one filter may write as a dictionary and one with several as an array.
func firstParms(parms object) object {
	if a, ok := parms.(Array); ok {
		if len(a) == 0 {
			return nil
		}
		return a[0]
	}
	return parms
}

// asciiHexFraming is where hexadecimal data ends: at the '>' of 7.4.2. The
// bytes before it are hexadecimal digits and white space and nothing else --
// a byte outside the encoding is no ASCIIHexDecode data, and where such an
// image ends is not something the file establishes.
func (d *Document) asciiHexFraming(data []byte) (int, error) {
	for i, c := range data {
		if d.deadlinePassed() {
			return 0, d.deadline()
		}
		switch {
		case c == '>':
			return i + 1, nil
		case isWhitespace(c):
		default:
			if _, ok := hexValue(c); !ok {
				return 0, malformed("ASCIIHexDecode: a byte outside the encoding")
			}
		}
	}
	return 0, errFilterUnended
}

// ascii85Framing is where base-85 data ends: at the "~>" of 7.4.3. What
// stands before it is the encoding's own alphabet, in groups of five: 'z'
// stands for a whole group of zeros and only between groups, white space
// falls anywhere -- white space being the six bytes of 7.2.3 and not every
// byte below a space -- a group of five encodes a number no larger than a
// four-byte word, and so does a final group of fewer, which stands for as
// many bytes as it has characters less one. A final group of one character
// encodes nothing.
func (d *Document) ascii85Framing(data []byte) (int, error) {
	at := 0
	if bytes.HasPrefix(data, []byte("<~")) {
		at = 2
	}
	group, value := 0, uint64(0)
	for i := at; i < len(data); i++ {
		if d.deadlinePassed() {
			return 0, d.deadline()
		}
		c := data[i]
		switch {
		case c == '~':
			if i+1 >= len(data) {
				// The byte that would end the data is not among the bytes
				// the reader was given: what it was given holds no end.
				return 0, errFilterUnended
			}
			if data[i+1] != '>' {
				return 0, malformed("ASCII85Decode: a tilde that ends nothing")
			}
			if group == 1 {
				return 0, malformed("ASCII85Decode: a final group of one character")
			}
			if group > 1 && !ascii85Representable(value, group) {
				return 0, malformed("ASCII85Decode: a final group past the largest word")
			}
			return i + 2, nil
		case isWhitespace(c):
		case c == 'z':
			if group != 0 {
				return 0, malformed("ASCII85Decode: a z inside a group")
			}
		case '!' <= c && c <= 'u':
			value = value*85 + uint64(c-'!')
			group++
			if group == 5 {
				if value > 0xFFFFFFFF {
					return 0, malformed("ASCII85Decode: a group past the largest word")
				}
				group, value = 0, 0
			}
		default:
			return 0, malformed("ASCII85Decode: a byte outside the encoding")
		}
	}
	return 0, errFilterUnended
}

// ascii85Representable reports whether a final group of fewer than five
// characters stands for a number a four-byte word holds. 7.4.3 has such a
// group completed with the character 'u', the largest the alphabet has, so a
// group the completion carries past the word is a group no four bytes encode.
func ascii85Representable(value uint64, group int) bool {
	for ; group < 5; group++ {
		value = value*85 + uint64('u'-'!')
	}
	return value <= 0xFFFFFFFF
}

// runLengthFraming is where run-length encoded data ends: at the
// end-of-data byte, 128. It reads the length of each run and not the run, so
// nothing of the image is held.
func (d *Document) runLengthFraming(data []byte) (int, error) {
	for i := 0; i < len(data); {
		if d.deadlinePassed() {
			return 0, d.deadline()
		}
		l := int(data[i])
		i++
		switch {
		case l == 128:
			return i, nil
		case l < 128:
			i += l + 1
		default:
			i++
		}
	}
	return 0, errFilterUnended
}

// flateFraming is where a zlib stream ends: its two header bytes, the deflate
// data through its final block, and the four bytes of the Adler-32 checksum
// of what it decodes to, which the reader has decoded and so can check. PDF's
// FlateDecode is that whole wrapper (Table 6): data with no header, with no
// checksum, or with one that is not the checksum of the data is not a stream
// this reader can say the end of.
func (d *Document) flateFraming(data []byte) (int, error) {
	if !zlibHeader(data) {
		return 0, malformed("FlateDecode: no zlib header")
	}
	n, sum, err := d.deflateConsumed(data[2:])
	if err != nil {
		return 0, err
	}
	end := 2 + n + 4
	if end > len(data) {
		return 0, errFilterUnended
	}
	if declared := binary.BigEndian.Uint32(data[2+n : end]); declared != sum {
		return 0, malformed("FlateDecode: the checksum is not the checksum of the data")
	}
	return end, nil
}

// deflateConsumed reads the deflate data at the head of data to the end of its
// final block, and reports how many bytes of data that took and the Adler-32
// checksum of what it decoded to. What it decodes is charged to the inflate
// budget and dropped. A budget met while it reads is returned as it is -- it
// is the page's problem, and the image's end stays unknown -- and data that
// ends inside its final block holds no end of its own, and data that is not
// deflate data at all is the encoding's own defect and told apart from it. The deadline is read as the input is, so that blocks decoding to
// nothing do not run past it.
func (d *Document) deflateConsumed(data []byte) (int, uint32, error) {
	out, err := d.budget.discard()
	if err != nil {
		return 0, 0, err
	}
	left := &deadlineBytes{d: d, r: bytes.NewReader(data)}
	fr := flate.NewReader(left)
	defer fr.Close()
	if _, err := io.Copy(out, fr); err != nil {
		switch {
		case errors.Is(err, errInflateBound), isDeadline(err):
			return 0, 0, err
		case errors.Is(err, io.ErrUnexpectedEOF), errors.Is(err, io.EOF):
			// The data ends inside the deflate stream: the bytes the reader
			// was given do not hold its end, which is not the same as their
			// not being deflate data at all.
			return 0, 0, errFilterUnended
		}
		return 0, 0, malformed("FlateDecode: the deflate data is not deflate data")
	}
	return len(data) - left.r.Len(), out.sum.Sum32(), nil
}

// deadlineBytes is the bytes a decoder reads, with the deadline read as they
// are read: a decoder that produces nothing charges nothing, and would
// otherwise walk to the end of what it was given whatever the clock says. A
// byte at a time is read on the package's cadence and a block at a time on
// every call, since the cadence counts readings and a block is many.
type deadlineBytes struct {
	d *Document
	r *bytes.Reader
}

func (b *deadlineBytes) Read(p []byte) (int, error) {
	// A read that hands over many bytes at once is the work of many readings
	// of one byte, so the clock is read on each such call rather than on the
	// cadence, which counts calls: a stream of whole blocks is handed over in
	// a few hundred of them and would otherwise never reach one reading.
	if b.d.deadlineNow() {
		return 0, b.d.deadline()
	}
	return b.r.Read(p)
}

func (b *deadlineBytes) ReadByte() (byte, error) {
	if b.d.deadlinePassed() {
		return 0, b.d.deadline()
	}
	return b.r.ReadByte()
}

// lzwFraming is where LZW data ends: after the end-of-data code, 257. Data
// that runs out before that code is data whose end the reader has not seen --
// the bytes it was given are all it may read of the image, and the code that
// ends the stream may lie past them.
func (d *Document) lzwFraming(data []byte, early bool) (int, error) {
	out, err := d.budget.discard()
	if err != nil {
		return 0, err
	}
	consumed, ended, err := d.lzwDecodeTo(data, early, out)
	switch {
	case err != nil:
		return 0, err
	case !ended:
		return 0, errFilterUnended
	}
	return consumed, nil
}

// ccittFraming is where Group 3 or Group 4 fax data ends: at the
// end-of-facsimile-block of T.6 -- two end-of-line codes -- or the
// return-to-control of T.4, six of them. An end-of-line is eleven zero bits
// and a one, which no concatenation of the codes either standard defines can
// hold, so a run of eleven zeros in valid coded data is an end-of-line
// wherever it begins, and the fill bits a writer may put before one are zeros
// counted with it. Where rows may be one- or two-dimensional a tag bit
// follows each end-of-line and belongs to it.
//
// Two shapes are not framed. Data whose /DecodeParms turns the end-of-block
// off carries no end of its own. And data written with /EncodedByteAlign
// begins each row on a byte boundary, so the fill zeros before a row and the
// leading zeros of the codeword after them make eleven zeros and a one at a
// row boundary: a run there is a row and not an end-of-line, and telling them
// apart means decoding the rows, which this reader does not do.
func (d *Document) ccittFraming(parms object, data []byte) (int, error) {
	k := int64(0)
	if p := d.dictOf(parms); p != nil {
		if v, ok := p["EndOfBlock"].(bool); ok && !v {
			return 0, errFilterNotFramed
		}
		if v, ok := d.intOf(p["EndOfBlock"]); ok && v == 0 {
			return 0, errFilterNotFramed
		}
		if v, ok := p["EncodedByteAlign"].(bool); ok && v {
			return 0, errFilterNotFramed
		}
		if v, ok := d.intOf(p["EncodedByteAlign"]); ok && v != 0 {
			return 0, errFilterNotFramed
		}
		if v, ok := d.intOf(p["K"]); ok {
			k = v
		}
	}
	// T.6 ends a block with two end-of-lines; T.4 with six.
	need := 2
	if k >= 0 {
		need = 6
	}
	zeros, seen, tagged := 0, 0, false
	for at := 0; at < len(data)*8; at++ {
		if at%8 == 0 && d.deadlinePassed() {
			return 0, d.deadline()
		}
		if !tagged && at%8 == 0 && data[at/8] == 0 {
			zeros += 8
			at += 7
			continue
		}
		one := data[at/8]&(1<<uint(7-at%8)) != 0
		if tagged {
			// The bit after an end-of-line where rows may be one- or
			// two-dimensional: it says which this row is, and is consumed
			// with the end-of-line rather than breaking the run of them.
			tagged, zeros = false, 0
			if seen >= need {
				return byteOf(at, len(data)), nil
			}
			continue
		}
		if !one {
			zeros++
			continue
		}
		if zeros >= 11 {
			seen++
			zeros = 0
			if k > 0 {
				tagged = true
				continue
			}
			if seen >= need {
				return byteOf(at, len(data)), nil
			}
			continue
		}
		seen, zeros = 0, 0
	}
	return 0, errFilterUnended
}

// byteOf is the offset after the byte the bit at lies in, bounded by what the
// reader was given: fax data ends on a byte boundary whatever bit its last
// end-of-line ends on.
func byteOf(at, length int) int {
	end := (at + 1 + 7) / 8
	if end > length {
		end = length
	}
	return end
}

// jpegFraming is where a JPEG ends: at its end-of-image marker, found by
// walking the markers of the file. Nothing is decoded -- the reader needs
// where the image ends, not what it shows, and an image whose entropy-coded
// data holds no block still ends at its end-of-image. Entropy-coded data
// holds bytes that read as markers and are not: FF 00 is a sample byte and
// FF D0 to FF D7 are restarts, so that data is walked to the next marker that
// is one.
func (d *Document) jpegFraming(data []byte) (int, error) {
	if len(data) < 2 || data[0] != 0xFF || data[1] != 0xD8 {
		return 0, malformed("DCTDecode: no start-of-image marker")
	}
	for i := 2; i+1 < len(data); {
		if d.deadlinePassed() {
			return 0, d.deadline()
		}
		if data[i] != 0xFF {
			// Not where a marker begins: the file is not one this reader can
			// walk, and it says so rather than guessing at an end.
			return 0, malformed("DCTDecode: a marker was expected")
		}
		marker := data[i+1]
		switch {
		case marker == 0xFF:
			// Fill bytes stand before a marker.
			i++
			continue
		case marker == 0xD9:
			return i + 2, nil
		case marker == 0x01 || (marker >= 0xD0 && marker <= 0xD7):
			// Markers that carry no segment.
			i += 2
			continue
		}
		if i+3 >= len(data) {
			return 0, errFilterUnended
		}
		length := int(data[i+2])<<8 | int(data[i+3])
		if length < 2 {
			return 0, malformed("DCTDecode: a segment shorter than its own length")
		}
		i += 2 + length
		if marker != 0xDA {
			continue
		}
		// The start of a scan: entropy-coded data runs to the next marker
		// that is one. FF 00 is a sample byte, and a restart -- which the
		// fill bytes 4.10 of ITU T.81 allows may stand before, so that FF FF
		// D0 is one restart and not a marker the data ends at -- resumes the
		// data rather than ending it.
		for i+1 < len(data) {
			if d.deadlinePassed() {
				return 0, d.deadline()
			}
			if data[i] != 0xFF {
				i++
				continue
			}
			j := i + 1
			for j < len(data) && data[j] == 0xFF {
				// A run of fill bytes is as long as the writer made it, and
				// walking it is the same work as walking any other bytes:
				// the clock is read across it as it is across them.
				if d.deadlinePassed() {
					return 0, d.deadline()
				}
				j++
			}
			if j >= len(data) {
				i = j - 1
				break
			}
			if data[j] == 0x00 || (data[j] >= 0xD0 && data[j] <= 0xD7) {
				i = j + 1
				continue
			}
			// A marker of its own: the scan ends at the fill byte before it,
			// which the walk above reads as the marker's first byte.
			i = j - 1
			break
		}
	}
	return 0, errFilterUnended
}
