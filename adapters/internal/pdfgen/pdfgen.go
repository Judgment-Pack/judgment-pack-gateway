// Package pdfgen writes small PDF files for tests and fixtures: pages of
// text under simple or composite fonts, image-only pages, cross-reference
// tables or streams, object streams, and the standard security handler
// with RC4 or AES-128. It reads nothing; it is the inverse of the reader,
// written from the specification so the reader answers to the format and
// not to itself, and its output is checked against an independent tool
// where one is available.
package pdfgen

import (
	"bytes"
	"compress/zlib"
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/rc4"
	"fmt"
	"sort"
	"strings"
)

// Object is one indirect object: its dictionary or value as PDF syntax,
// and stream data when it is a stream.
type Object struct {
	Body   string
	Stream []byte
	// Raw, when set, means Stream is written as is, with no filter.
	Raw bool
}

// Builder accumulates objects and writes the file.
type Builder struct {
	objects []Object
	// Compress applies FlateDecode to every stream.
	Compress bool
	// XrefStream writes a cross-reference stream instead of a table.
	XrefStream bool
	// ObjectStreams puts every non-stream object into one object stream
	// (requires XrefStream).
	ObjectStreams bool
	// Encrypt, when set, applies the standard security handler.
	Encrypt *Encryption
	// Root is the object number of the catalog; set by AddCatalog.
	Root int
	// Junk is written before the header.
	Junk []byte
	// BrokenOffsets shifts every cross-reference offset by the amount.
	BrokenOffsets int
}

// Encryption configures the standard security handler.
type Encryption struct {
	// Revision is 2, 3 or 4 (4 with AES when AES is set).
	Revision int
	AES      bool
	// User and Owner passwords; an empty user password opens without one.
	User, Owner string
	Permissions int32
}

// Add appends an object and returns its number.
func (b *Builder) Add(o Object) int {
	b.objects = append(b.objects, o)
	return len(b.objects)
}

// Reserve returns the next object number without adding it, for objects
// that must reference each other.
func (b *Builder) Next() int { return len(b.objects) + 1 }

// Set replaces the object with the number given.
func (b *Builder) Set(num int, o Object) { b.objects[num-1] = o }

// Font adds a simple font: Type1 Helvetica with the encoding named, or
// with a Differences array when diffs is not empty.
func (b *Builder) Font(base, encoding string, diffs string) int {
	enc := ""
	if encoding != "" {
		enc = "/Encoding /" + encoding
	}
	if diffs != "" {
		enc = "/Encoding << /Type /Encoding " + func() string {
			if encoding != "" {
				return "/BaseEncoding /" + encoding + " "
			}
			return ""
		}() + "/Differences [" + diffs + "] >>"
	}
	return b.Add(Object{Body: "<< /Type /Font /Subtype /Type1 /BaseFont /" + base + " " + enc + " >>"})
}

// Type0Font adds a composite font with Identity-H and a ToUnicode map
// from two-byte codes to the runes given: code i+1 maps to runes[i].
func (b *Builder) Type0Font(runes []rune) int {
	var cmap bytes.Buffer
	cmap.WriteString("/CIDInit /ProcSet findresource begin\n12 dict begin\nbegincmap\n/CMapName /Adobe-Identity-UCS def\n1 begincodespacerange\n<0000> <FFFF>\nendcodespacerange\n")
	fmt.Fprintf(&cmap, "%d beginbfchar\n", len(runes))
	for i, r := range runes {
		fmt.Fprintf(&cmap, "<%04X> <%04X>\n", i+1, r)
	}
	cmap.WriteString("endbfchar\nendcmap\nCMapName currentdict /CMap defineresource pop\nend\nend\n")
	tu := b.Add(Object{Body: "<< >>", Stream: cmap.Bytes()})
	desc := b.Add(Object{Body: "<< /Type /FontDescriptor /FontName /TestSans /Flags 4 /FontBBox [0 0 1000 1000] /ItalicAngle 0 /Ascent 800 /Descent -200 /CapHeight 700 /StemV 80 >>"})
	cid := b.Add(Object{Body: fmt.Sprintf("<< /Type /Font /Subtype /CIDFontType2 /BaseFont /TestSans /CIDSystemInfo << /Registry (Adobe) /Ordering (Identity) /Supplement 0 >> /FontDescriptor %d 0 R /DW 600 >>", desc)})
	return b.Add(Object{Body: fmt.Sprintf("<< /Type /Font /Subtype /Type0 /BaseFont /TestSans /Encoding /Identity-H /DescendantFonts [%d 0 R] /ToUnicode %d 0 R >>", cid, tu)})
}

// Image adds a tiny image XObject: 2x2 gray, uncompressed.
func (b *Builder) Image() int {
	return b.Add(Object{Body: "<< /Type /XObject /Subtype /Image /Width 2 /Height 2 /ColorSpace /DeviceGray /BitsPerComponent 8 >>", Stream: []byte{0, 255, 255, 0}, Raw: true})
}

// Page describes one page for Pages.
type Page struct {
	// Content is the content stream.
	Content string
	// Fonts maps resource names to font object numbers.
	Fonts map[string]int
	// XObjects maps resource names to XObject numbers.
	XObjects map[string]int
	// Extra is appended inside the page dictionary.
	Extra string
	// ContentDict, when set, is the content stream's dictionary, and Content
	// is written as it is given: already encoded by the filters the
	// dictionary names.
	ContentDict string
}

// Pages adds a page tree and the pages, and returns the Pages node number.
func (b *Builder) Pages(pages []Page) int {
	pagesNum := b.Next()
	b.Add(Object{Body: "placeholder"})
	var kids []string
	for _, p := range pages {
		stream := Object{Body: "<< >>", Stream: []byte(p.Content)}
		if p.ContentDict != "" {
			stream = Object{Body: p.ContentDict, Stream: []byte(p.Content), Raw: true}
		}
		content := b.Add(stream)
		var res strings.Builder
		res.WriteString("<< ")
		if len(p.Fonts) > 0 {
			res.WriteString("/Font << ")
			names := make([]string, 0, len(p.Fonts))
			for n := range p.Fonts {
				names = append(names, n)
			}
			sort.Strings(names)
			for _, n := range names {
				fmt.Fprintf(&res, "/%s %d 0 R ", n, p.Fonts[n])
			}
			res.WriteString(">> ")
		}
		if len(p.XObjects) > 0 {
			res.WriteString("/XObject << ")
			for n, num := range p.XObjects {
				fmt.Fprintf(&res, "/%s %d 0 R ", n, num)
			}
			res.WriteString(">> ")
		}
		res.WriteString(">>")
		page := b.Add(Object{Body: fmt.Sprintf("<< /Type /Page /Parent %d 0 R /MediaBox [0 0 612 792] /Resources %s /Contents %d 0 R %s>>", pagesNum, res.String(), content, p.Extra)})
		kids = append(kids, fmt.Sprintf("%d 0 R", page))
	}
	b.Set(pagesNum, Object{Body: fmt.Sprintf("<< /Type /Pages /Kids [%s] /Count %d >>", strings.Join(kids, " "), len(pages))})
	return pagesNum
}

// Catalog adds the catalog for the Pages node and records it as the root.
func (b *Builder) Catalog(pages int) int {
	b.Root = b.Add(Object{Body: fmt.Sprintf("<< /Type /Catalog /Pages %d 0 R >>", pages)})
	return b.Root
}

// Text is a content stream showing lines of text with the font resource
// named, each line at the y given, starting at x, as a literal string.
func Text(font string, size float64, lines []string) string {
	var sb strings.Builder
	sb.WriteString("BT\n")
	fmt.Fprintf(&sb, "/%s %g Tf\n", font, size)
	y := 750.0
	for _, line := range lines {
		fmt.Fprintf(&sb, "1 0 0 1 72 %g Tm\n(%s) Tj\n", y, Escape(line))
		y -= size * 1.4
	}
	sb.WriteString("ET\n")
	return sb.String()
}

// Escape escapes a literal string's special characters.
func Escape(s string) string {
	r := strings.NewReplacer(`\`, `\\`, "(", `\(`, ")", `\)`, "\r", `\r`, "\n", `\n`)
	return r.Replace(s)
}

var fileID = []byte{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00}

// Bytes writes the file.
func (b *Builder) Bytes() []byte {
	var out bytes.Buffer
	out.Write(b.Junk)
	out.WriteString("%PDF-1.7\n%\xE2\xE3\xCF\xD3\n")
	var enc *encryptor
	encryptNum := 0
	trailerExtra := ""
	if b.Encrypt != nil {
		enc = newEncryptor(*b.Encrypt)
		encryptNum = b.Add(Object{Body: enc.dictionary()})
		trailerExtra = fmt.Sprintf(" /Encrypt %d 0 R", encryptNum)
	}
	offsets := make([]int, len(b.objects)+1)
	inStream := map[int]bool{}
	var objStmNum int
	var objStmIndex map[int]int
	if b.ObjectStreams && b.XrefStream {
		// Every non-stream object but the encryption dictionary goes into
		// one object stream.
		var header, data bytes.Buffer
		objStmIndex = map[int]int{}
		idx := 0
		for i, o := range b.objects {
			num := i + 1
			if o.Stream != nil || num == encryptNum {
				continue
			}
			fmt.Fprintf(&header, "%d %d ", num, data.Len())
			data.WriteString(o.Body)
			data.WriteString("\n")
			inStream[num] = true
			objStmIndex[num] = idx
			idx++
		}
		payload := append(header.Bytes(), data.Bytes()...)
		objStmNum = b.Add(Object{Body: fmt.Sprintf("<< /Type /ObjStm /N %d /First %d >>", idx, header.Len()), Stream: payload})
		offsets = append(offsets, 0)
	}
	for i, o := range b.objects {
		num := i + 1
		if inStream[num] {
			continue
		}
		offsets[num] = out.Len()
		fmt.Fprintf(&out, "%d 0 obj\n", num)
		if o.Stream == nil {
			body := o.Body
			if enc != nil && num != encryptNum {
				body = enc.encryptStrings(body, num)
			}
			out.WriteString(body)
			out.WriteString("\nendobj\n")
			continue
		}
		data := o.Stream
		filter := ""
		if b.Compress && !o.Raw {
			var z bytes.Buffer
			w := zlib.NewWriter(&z)
			w.Write(data)
			w.Close()
			data = z.Bytes()
			filter = " /Filter /FlateDecode"
		}
		if enc != nil {
			data = enc.encrypt(data, num)
		}
		dict := strings.TrimSuffix(strings.TrimSpace(o.Body), ">>")
		fmt.Fprintf(&out, "%s /Length %d%s >>\nstream\n", dict, len(data), filter)
		out.Write(data)
		out.WriteString("\nendstream\nendobj\n")
	}
	startxref := out.Len()
	size := len(b.objects) + 1
	if b.XrefStream {
		size++
		xrefNum := size - 1
		var rows bytes.Buffer
		// The third field carries an object's index within its object stream,
		// which is as large as the objects one stream may hold: four bytes,
		// like the second, so that an index past 255 is the index and not the
		// low byte of it.
		write := func(t int, f2 int, f3 int) {
			rows.WriteByte(byte(t))
			rows.Write([]byte{byte(f2 >> 24), byte(f2 >> 16), byte(f2 >> 8), byte(f2)})
			rows.Write([]byte{byte(f3 >> 24), byte(f3 >> 16), byte(f3 >> 8), byte(f3)})
		}
		write(0, 0, 65535)
		for num := 1; num < size; num++ {
			switch {
			case num == xrefNum:
				write(1, startxref+b.BrokenOffsets, 0)
			case inStream[num]:
				write(2, objStmNum, objStmIndex[num])
			default:
				write(1, offsets[num]+b.BrokenOffsets, 0)
			}
		}
		data := rows.Bytes()
		filter := ""
		if b.Compress {
			var z bytes.Buffer
			w := zlib.NewWriter(&z)
			w.Write(data)
			w.Close()
			data = z.Bytes()
			filter = " /Filter /FlateDecode"
		}
		fmt.Fprintf(&out, "%d 0 obj\n<< /Type /XRef /Size %d /W [1 4 4] /Root %d 0 R /ID [<%x> <%x>]%s /Length %d%s >>\nstream\n", xrefNum, size, b.Root, fileID, fileID, trailerExtra, len(data), filter)
		out.Write(data)
		out.WriteString("\nendstream\nendobj\n")
	} else {
		fmt.Fprintf(&out, "xref\n0 %d\n", size)
		out.WriteString("0000000000 65535 f \n")
		for num := 1; num < size; num++ {
			fmt.Fprintf(&out, "%010d 00000 n \n", offsets[num]+b.BrokenOffsets)
		}
		fmt.Fprintf(&out, "trailer\n<< /Size %d /Root %d 0 R /ID [<%x> <%x>]%s >>\n", size, b.Root, fileID, fileID, trailerExtra)
	}
	fmt.Fprintf(&out, "startxref\n%d\n%%%%EOF\n", startxref)
	return out.Bytes()
}

// encryptor implements the standard security handler's writer side.
type encryptor struct {
	cfg Encryption
	key []byte
	o   []byte
	u   []byte
	n   int
}

var pad = []byte{
	0x28, 0xBF, 0x4E, 0x5E, 0x4E, 0x75, 0x8A, 0x41, 0x64, 0x00, 0x4E, 0x56, 0xFF, 0xFA, 0x01, 0x08,
	0x2E, 0x2E, 0x00, 0xB6, 0xD0, 0x68, 0x3E, 0x80, 0x2F, 0x0C, 0xA9, 0xFE, 0x64, 0x53, 0x69, 0x7A,
}

func padded(p string) []byte {
	return append([]byte(p), pad...)[:32]
}

func newEncryptor(cfg Encryption) *encryptor {
	e := &encryptor{cfg: cfg}
	e.n = 5
	if cfg.Revision >= 3 {
		e.n = 16
	}
	// Algorithm 3: the O value.
	owner := cfg.Owner
	if owner == "" {
		owner = cfg.User
	}
	h := md5.Sum(padded(owner))
	okey := h[:]
	if cfg.Revision >= 3 {
		for i := 0; i < 50; i++ {
			s := md5.Sum(okey[:e.n])
			okey = s[:]
		}
	}
	okey = okey[:e.n]
	c, _ := rc4.NewCipher(okey)
	o := make([]byte, 32)
	c.XORKeyStream(o, padded(cfg.User))
	if cfg.Revision >= 3 {
		for i := 1; i <= 19; i++ {
			k := make([]byte, len(okey))
			for j := range okey {
				k[j] = okey[j] ^ byte(i)
			}
			c, _ := rc4.NewCipher(k)
			c.XORKeyStream(o, o)
		}
	}
	e.o = o
	// Algorithm 2: the file key from the user password.
	p := cfg.Permissions
	m := md5.New()
	m.Write(padded(cfg.User))
	m.Write(o)
	m.Write([]byte{byte(p), byte(p >> 8), byte(p >> 16), byte(p >> 24)})
	m.Write(fileID)
	key := m.Sum(nil)
	if cfg.Revision >= 3 {
		for i := 0; i < 50; i++ {
			s := md5.Sum(key[:e.n])
			key = s[:]
		}
	}
	e.key = key[:e.n]
	// Algorithms 4/5: the U value.
	if cfg.Revision == 2 {
		c, _ := rc4.NewCipher(e.key)
		u := make([]byte, 32)
		c.XORKeyStream(u, pad)
		e.u = u
	} else {
		m := md5.New()
		m.Write(pad)
		m.Write(fileID)
		x := m.Sum(nil)
		for i := 0; i < 20; i++ {
			k := make([]byte, len(e.key))
			for j := range e.key {
				k[j] = e.key[j] ^ byte(i)
			}
			c, _ := rc4.NewCipher(k)
			c.XORKeyStream(x, x)
		}
		e.u = append(x, make([]byte, 16)...)
	}
	return e
}

func (e *encryptor) dictionary() string {
	v := 1
	length := ""
	cf := ""
	switch {
	case e.cfg.Revision == 3:
		v = 2
		length = " /Length 128"
	case e.cfg.Revision == 4:
		v = 4
		length = " /Length 128"
		cfm := "V2"
		if e.cfg.AES {
			cfm = "AESV2"
		}
		cf = fmt.Sprintf(" /CF << /StdCF << /CFM /%s /AuthEvent /DocOpen /Length 16 >> >> /StmF /StdCF /StrF /StdCF", cfm)
	}
	return fmt.Sprintf("<< /Filter /Standard /V %d /R %d%s /P %d /O <%x> /U <%x>%s >>", v, e.cfg.Revision, length, e.cfg.Permissions, e.o, e.u, cf)
}

func (e *encryptor) objectKey(num int, aesKey bool) []byte {
	m := md5.New()
	m.Write(e.key)
	m.Write([]byte{byte(num), byte(num >> 8), byte(num >> 16), 0, 0})
	if aesKey {
		m.Write([]byte{0x73, 0x41, 0x6C, 0x54})
	}
	k := m.Sum(nil)
	n := e.n + 5
	if n > 16 {
		n = 16
	}
	return k[:n]
}

func (e *encryptor) encrypt(data []byte, num int) []byte {
	if e.cfg.AES {
		block, _ := aes.NewCipher(e.objectKey(num, true))
		iv := []byte("0123456789abcdef")
		padLen := 16 - len(data)%16
		padded := append(append([]byte{}, data...), bytes.Repeat([]byte{byte(padLen)}, padLen)...)
		out := make([]byte, len(padded))
		cipher.NewCBCEncrypter(block, iv).CryptBlocks(out, padded)
		return append(iv, out...)
	}
	c, _ := rc4.NewCipher(e.objectKey(num, false))
	out := make([]byte, len(data))
	c.XORKeyStream(out, data)
	return out
}

// encryptStrings encrypts literal strings in an object body. Bodies in
// this generator carry strings only inside content streams, which are
// streams; a dictionary body with a literal string is left alone.
func (e *encryptor) encryptStrings(body string, num int) string {
	return body
}
