package pdf

import (
	"bytes"
	"compress/flate"
	"encoding/binary"
	"errors"
	"fmt"
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
	out, _, err := d.lzwDecodeConsumed(data, early)
	return out, err
}

// lzwDecodeConsumed is lzwDecode, reporting as well how many bytes of data
// the codes it read took: the end-of-data code lies inside the last of them,
// and a caller looking for where the stream ends -- an inline image's, whose
// length nothing else states -- needs the byte after it.
func (d *Document) lzwDecodeConsumed(data []byte, early bool) ([]byte, int, error) {
	out, err := d.budget.output(len(data) * 2)
	if err != nil {
		return nil, 0, err
	}
	const (
		clearCode = 256
		eodCode   = 257
	)
	dict := make([][]byte, 4096)
	reset := func() int {
		for i := 0; i < 256; i++ {
			dict[i] = []byte{byte(i)}
		}
		return 258
	}
	next := reset()
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
		for bitCount < codeLen {
			if pos >= len(data) {
				return out.buf, pos, nil
			}
			bitBuf = bitBuf<<8 | uint32(data[pos])
			pos++
			bitCount += 8
		}
		code := int(bitBuf >> uint(bitCount-codeLen) & (1<<uint(codeLen) - 1))
		bitCount -= codeLen
		switch {
		case code == clearCode:
			next = reset()
			codeLen = 9
			prev = nil
			continue
		case code == eodCode:
			return out.buf, pos, nil
		}
		var entry []byte
		switch {
		case code < next && dict[code] != nil:
			entry = dict[code]
		case code == next && prev != nil:
			entry = append(append([]byte{}, prev...), prev[0])
		default:
			return nil, 0, malformed("LZWDecode: code %d outside the table", code)
		}
		if _, err := out.Write(entry); err != nil {
			return nil, 0, err
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

// Where a filter's own data ends. An inline image states no length that must
// be believed, so for an image a filter encodes the reader asks the filter:
// every filter below frames its data, and where the framing ends the image's
// data ends. Nothing of what such an image shows is kept -- the reader
// decodes an inline image only to learn where the content after it resumes --
// but what a decode produces is charged to the document's inflate budget as
// any stream's output is, and the input is bounded by the caller, which hands
// over at most the bytes one inline image may hold.

// filterFraming is where the data of a stream encoded by the filter named
// ends, as offsets into data at which its end may lie; it is empty for a
// filter whose framing this reader does not read -- CCITTFaxDecode,
// JBIG2Decode, JPXDecode, Crypt and any it does not know -- and for data
// whose framing does not end within what it was given.
func (d *Document) filterFraming(filter Name, parms object, data []byte) []int {
	switch filter {
	case "AHx", "ASCIIHexDecode":
		// The end-of-data marker of 7.4.2.
		if i := bytes.IndexByte(data, '>'); i >= 0 {
			return []int{i + 1}
		}
	case "A85", "ASCII85Decode":
		if i := bytes.Index(data, []byte("~>")); i >= 0 {
			return []int{i + 2}
		}
	case "RL", "RunLengthDecode":
		if n := runLengthFraming(data); n >= 0 {
			return []int{n}
		}
	case "Fl", "FlateDecode":
		return d.flateFraming(data)
	case "LZW", "LZWDecode":
		early := true
		if p := d.dictOf(firstParms(parms)); p != nil {
			if v, ok := d.intOf(p["EarlyChange"]); ok {
				early = v != 0
			}
		}
		if _, n, err := d.lzwDecodeConsumed(data, early); err == nil && n > 0 {
			return []int{n}
		}
	case "DCT", "DCTDecode":
		if n := jpegFraming(data); n > 0 {
			return []int{n}
		}
	}
	return nil
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

// runLengthFraming is where run-length encoded data ends: at the end-of-data
// byte, 128. It reads the length of each run and not the run, so nothing of
// the image is held.
func runLengthFraming(data []byte) int {
	for i := 0; i < len(data); {
		l := int(data[i])
		i++
		switch {
		case l == 128:
			return i
		case l < 128:
			i += l + 1
		default:
			i++
		}
	}
	return -1
}

// flateFraming is where a deflate stream at the head of data ends: after the
// Adler-32 checksum that closes a zlib stream, and at the end of the deflate
// data itself for data that carries no checksum -- a writer that left it out
// is common damage, and either is an end the reader will take, the complete
// stream first.
func (d *Document) flateFraming(data []byte) []int {
	head := 0
	if zlibHeader(data) {
		head = 2
	}
	n, ok := d.deflateConsumed(data[head:])
	if !ok {
		return nil
	}
	if head == 2 {
		return []int{head + n + 4, head + n}
	}
	return []int{n}
}

// deflateConsumed reads the deflate data at the head of data to the end of its
// final block, and reports how many bytes of data that took. The bytes it
// decodes to are charged to the inflate budget and dropped.
func (d *Document) deflateConsumed(data []byte) (int, bool) {
	out, err := d.budget.output(0)
	if err != nil {
		return 0, false
	}
	// A bytes.Reader reads one byte at a time when the decompressor asks for
	// one, so what it has left is what the deflate data did not take.
	left := bytes.NewReader(data)
	fr := flate.NewReader(left)
	defer fr.Close()
	if _, err := io.Copy(out, fr); err != nil {
		return 0, false
	}
	return len(data) - left.Len(), true
}

// jpegFraming is where a JPEG ends: at its end-of-image marker, found by
// walking the markers of the file. Nothing is decoded -- the reader needs
// where the image ends, not what it shows. Entropy-coded data holds bytes
// that read as markers and are not: FF 00 is a sample byte and FF D0 to FF D7
// are restarts, so that data is walked to the next marker that is one.
func jpegFraming(data []byte) int {
	if len(data) < 2 || data[0] != 0xFF || data[1] != 0xD8 {
		return -1
	}
	for i := 2; i+1 < len(data); {
		if data[i] != 0xFF {
			// Not where a marker begins: the file is not one this reader can
			// walk, and it says so rather than guessing at an end.
			return -1
		}
		marker := data[i+1]
		switch {
		case marker == 0xFF:
			// Fill bytes stand before a marker.
			i++
			continue
		case marker == 0xD9:
			return i + 2
		case marker == 0x01 || (marker >= 0xD0 && marker <= 0xD7):
			// Markers that carry no segment.
			i += 2
			continue
		}
		if i+3 >= len(data) {
			return -1
		}
		length := int(data[i+2])<<8 | int(data[i+3])
		if length < 2 {
			return -1
		}
		i += 2 + length
		if marker != 0xDA {
			continue
		}
		// The start of a scan: entropy-coded data runs to the next marker
		// that is one.
		for i+1 < len(data) {
			if data[i] == 0xFF && data[i+1] != 0x00 && !(data[i+1] >= 0xD0 && data[i+1] <= 0xD7) {
				break
			}
			i++
		}
	}
	return -1
}
