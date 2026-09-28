package render

import (
	"archive/zip"
	"bytes"
	"compress/flate"
	"encoding/xml"
	"errors"
	"fmt"
	"hash/crc32"
	"strings"
)

// A Word file is a ZIP archive of XML parts. writeDocx writes one whose bytes
// are a function of the document and of this code: the parts are written in
// one fixed order, each under one fixed timestamp, each compressed here
// before it is stored, so that its sizes and its checksum are in its header
// and no part of the archive is written from the environment. Nothing in a
// part is random and nothing is a time.
//
// What it writes is the text and the structure it was given. How a reader
// lays that out, and whether it has the fonts to show it, is the reader's.
//
// The parts are XML, which says the same thing at greater length than the
// request did, and which compresses well: a file of a few kilobytes can hold
// parts of many megabytes. So the bound on the file is held over what the
// parts hold as well as over the archive, and the document part stops being
// written at the first block that begins past the bound.

// Every entry carries one timestamp, the earliest a ZIP archive can state:
// the first of January 1980, at midnight. An entry written raw states its
// date and its time in the archive's own form, a day in the low five bits of
// the date, a month in the next four, and the years since 1980 above them.
const (
	archiveDate    uint16 = 1<<5 | 1
	archiveTime    uint16 = 0
	archiveVersion uint16 = 20
)

const (
	xmlHeader = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>` + "\n"

	nsWord          = "http://schemas.openxmlformats.org/wordprocessingml/2006/main"
	nsRelationships = "http://schemas.openxmlformats.org/officeDocument/2006/relationships"
	nsPackageRels   = "http://schemas.openxmlformats.org/package/2006/relationships"

	relDocument  = nsRelationships + "/officeDocument"
	relCore      = "http://schemas.openxmlformats.org/package/2006/relationships/metadata/core-properties"
	relStyles    = nsRelationships + "/styles"
	relNumbering = nsRelationships + "/numbering"
	relHyperlink = nsRelationships + "/hyperlink"

	// The numbering definitions every file carries: one for a list with
	// bullets, one for a numbered list. Each list of a document is an
	// instance of one of them, so that a numbered list begins at one.
	abstractBullets = 0
	abstractNumbers = 1

	codeFont = "Courier New"

	// tableWidth is the width a table's columns share, in twentieths of a
	// point: six and a quarter inches, which fits between one-inch margins
	// on an A4 page and on a Letter page. The table itself is given as the
	// whole width of the text, so a reader fits the columns to its page.
	tableWidth = 9000
)

// errPartsOverBound is a file whose parts would hold more than the bound.
var errPartsOverBound = errors.New("the parts of the file hold more than the bound")

// part is one entry of the archive.
type part struct {
	name string
	data string
}

// writeDocx writes the file, or returns errPartsOverBound where its parts
// together would hold more than most bytes. The archive itself is for the
// caller to hold to its bound.
func writeDocx(doc Document, most int64) ([]byte, error) {
	w := &docxWriter{targets: map[string]int{}, most: most}
	body := w.body(doc)
	if w.over {
		return nil, errPartsOverBound
	}
	parts := []part{
		{"[Content_Types].xml", contentTypes},
		{"_rels/.rels", packageRelationships},
		{"docProps/core.xml", coreProperties(doc)},
		{"word/document.xml", body},
		{"word/_rels/document.xml.rels", w.relationships()},
		{"word/styles.xml", styles(doc.Language)},
		{"word/numbering.xml", w.numbering()},
	}
	var held int64
	for _, p := range parts {
		held += int64(len(p.data))
	}
	if held > most {
		return nil, errPartsOverBound
	}
	var out bytes.Buffer
	archive := zip.NewWriter(&out)
	for _, p := range parts {
		if err := store(archive, p); err != nil {
			return nil, err
		}
	}
	if err := archive.Close(); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}

// store compresses a part and writes it with its sizes and its checksum in
// its header, which is what keeps the archive free of the trailing
// descriptors a streamed entry carries.
func store(archive *zip.Writer, p part) error {
	var compressed bytes.Buffer
	deflate, err := flate.NewWriter(&compressed, flate.BestCompression)
	if err != nil {
		return err
	}
	if _, err := deflate.Write([]byte(p.data)); err != nil {
		return err
	}
	if err := deflate.Close(); err != nil {
		return err
	}
	header := &zip.FileHeader{
		Name: p.name,
		// An entry written raw states its own versions: 2.0, the version
		// of the archive format that a deflated entry needs to be read.
		CreatorVersion:     archiveVersion,
		ReaderVersion:      archiveVersion,
		Method:             zip.Deflate,
		ModifiedDate:       archiveDate,
		ModifiedTime:       archiveTime,
		CRC32:              crc32.ChecksumIEEE([]byte(p.data)),
		CompressedSize64:   uint64(compressed.Len()),
		UncompressedSize64: uint64(len(p.data)),
	}
	entry, err := archive.CreateRaw(header)
	if err != nil {
		return err
	}
	_, err = entry.Write(compressed.Bytes())
	return err
}

const contentTypes = xmlHeader +
	`<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">` +
	`<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>` +
	`<Default Extension="xml" ContentType="application/xml"/>` +
	`<Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>` +
	`<Override PartName="/word/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.styles+xml"/>` +
	`<Override PartName="/word/numbering.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.numbering+xml"/>` +
	`<Override PartName="/docProps/core.xml" ContentType="application/vnd.openxmlformats-package.core-properties+xml"/>` +
	`</Types>`

const packageRelationships = xmlHeader +
	`<Relationships xmlns="` + nsPackageRels + `">` +
	`<Relationship Id="rId1" Type="` + relDocument + `" Target="word/document.xml"/>` +
	`<Relationship Id="rId2" Type="` + relCore + `" Target="docProps/core.xml"/>` +
	`</Relationships>`

// coreProperties carries the title and, where the request gave one, the
// language. It carries no time and no author.
func coreProperties(doc Document) string {
	var b strings.Builder
	b.WriteString(xmlHeader)
	b.WriteString(`<cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties" xmlns:dc="http://purl.org/dc/elements/1.1/">`)
	b.WriteString(`<dc:title>` + escape(doc.Title) + `</dc:title>`)
	if doc.Language != "" {
		b.WriteString(`<dc:language>` + escape(doc.Language) + `</dc:language>`)
	}
	b.WriteString(`</cp:coreProperties>`)
	return b.String()
}

// styles is the styles part: the defaults, the six heading styles, the
// style of a list's paragraphs, the character style of a link, and the
// table style. The language, where one was given, is the default language
// of every run.
func styles(language string) string {
	var b strings.Builder
	b.WriteString(xmlHeader)
	b.WriteString(`<w:styles xmlns:w="` + nsWord + `">`)
	b.WriteString(`<w:docDefaults><w:rPrDefault><w:rPr><w:sz w:val="22"/><w:szCs w:val="22"/>`)
	if language != "" {
		tag := escape(language)
		b.WriteString(`<w:lang w:val="` + tag + `" w:eastAsia="` + tag + `" w:bidi="` + tag + `"/>`)
	}
	b.WriteString(`</w:rPr></w:rPrDefault><w:pPrDefault><w:pPr><w:spacing w:after="160" w:line="259" w:lineRule="auto"/></w:pPr></w:pPrDefault></w:docDefaults>`)
	b.WriteString(`<w:style w:type="paragraph" w:default="1" w:styleId="Normal"><w:name w:val="Normal"/><w:qFormat/></w:style>`)
	for level, size := range []int{32, 26, 24, 22, 22, 22} {
		n := level + 1
		fmt.Fprintf(&b, `<w:style w:type="paragraph" w:styleId="Heading%d"><w:name w:val="heading %d"/><w:basedOn w:val="Normal"/><w:next w:val="Normal"/><w:qFormat/>`, n, n)
		fmt.Fprintf(&b, `<w:pPr><w:keepNext/><w:spacing w:before="240" w:after="80"/><w:outlineLvl w:val="%d"/></w:pPr>`, level)
		fmt.Fprintf(&b, `<w:rPr><w:b/><w:bCs/><w:sz w:val="%d"/><w:szCs w:val="%d"/></w:rPr></w:style>`, size, size)
	}
	b.WriteString(`<w:style w:type="paragraph" w:styleId="ListParagraph"><w:name w:val="List Paragraph"/><w:basedOn w:val="Normal"/><w:qFormat/><w:pPr><w:spacing w:after="60"/><w:contextualSpacing/></w:pPr></w:style>`)
	b.WriteString(`<w:style w:type="character" w:default="1" w:styleId="DefaultParagraphFont"><w:name w:val="Default Paragraph Font"/></w:style>`)
	b.WriteString(`<w:style w:type="character" w:styleId="Hyperlink"><w:name w:val="Hyperlink"/><w:basedOn w:val="DefaultParagraphFont"/><w:rPr><w:color w:val="0563C1"/><w:u w:val="single"/></w:rPr></w:style>`)
	b.WriteString(`<w:style w:type="table" w:default="1" w:styleId="TableNormal"><w:name w:val="Normal Table"/><w:tblPr><w:tblInd w:w="0" w:type="dxa"/><w:tblCellMar><w:top w:w="0" w:type="dxa"/><w:left w:w="108" w:type="dxa"/><w:bottom w:w="0" w:type="dxa"/><w:right w:w="108" w:type="dxa"/></w:tblCellMar></w:tblPr></w:style>`)
	b.WriteString(`<w:style w:type="table" w:styleId="TableGrid"><w:name w:val="Table Grid"/><w:basedOn w:val="TableNormal"/><w:tblPr><w:tblBorders>`)
	for _, edge := range []string{"top", "left", "bottom", "right", "insideH", "insideV"} {
		b.WriteString(`<w:` + edge + ` w:val="single" w:sz="4" w:space="0" w:color="auto"/>`)
	}
	b.WriteString(`</w:tblBorders></w:tblPr></w:style>`)
	b.WriteString(`</w:styles>`)
	return b.String()
}

// docxWriter holds what the body leaves for the other parts to state: the
// targets of its links, in the order it met them, and the lists it holds.
type docxWriter struct {
	// targets maps a link's target to the number of its relationship.
	targets map[string]int
	order   []string
	// lists is, for each list of the document in order, whether it is
	// numbered.
	lists []bool
	// most is the bound on what the parts hold, and over that the document
	// part alone has passed it, after which no further block is written.
	most int64
	over bool
}

// The relationships of the document part: the styles, the numbering, and
// then one for each distinct target, in the order the body met them.
const firstLinkRelationship = 3

func (w *docxWriter) relationship(target string) string {
	n, known := w.targets[target]
	if !known {
		n = firstLinkRelationship + len(w.order)
		w.targets[target] = n
		w.order = append(w.order, target)
	}
	return fmt.Sprintf("rId%d", n)
}

func (w *docxWriter) relationships() string {
	var b strings.Builder
	b.WriteString(xmlHeader)
	b.WriteString(`<Relationships xmlns="` + nsPackageRels + `">`)
	b.WriteString(`<Relationship Id="rId1" Type="` + relStyles + `" Target="styles.xml"/>`)
	b.WriteString(`<Relationship Id="rId2" Type="` + relNumbering + `" Target="numbering.xml"/>`)
	for i, target := range w.order {
		fmt.Fprintf(&b, `<Relationship Id="rId%d" Type="%s" Target="%s" TargetMode="External"/>`, firstLinkRelationship+i, relHyperlink, escape(target))
	}
	b.WriteString(`</Relationships>`)
	return b.String()
}

func (w *docxWriter) numbering() string {
	var b strings.Builder
	b.WriteString(xmlHeader)
	b.WriteString(`<w:numbering xmlns:w="` + nsWord + `">`)
	fmt.Fprintf(&b, `<w:abstractNum w:abstractNumId="%d"><w:multiLevelType w:val="singleLevel"/><w:lvl w:ilvl="0"><w:start w:val="1"/><w:numFmt w:val="bullet"/><w:lvlText w:val="•"/><w:lvlJc w:val="left"/><w:pPr><w:ind w:left="720" w:hanging="360"/></w:pPr></w:lvl></w:abstractNum>`, abstractBullets)
	fmt.Fprintf(&b, `<w:abstractNum w:abstractNumId="%d"><w:multiLevelType w:val="singleLevel"/><w:lvl w:ilvl="0"><w:start w:val="1"/><w:numFmt w:val="decimal"/><w:lvlText w:val="%%1."/><w:lvlJc w:val="left"/><w:pPr><w:ind w:left="720" w:hanging="360"/></w:pPr></w:lvl></w:abstractNum>`, abstractNumbers)
	for i, numbered := range w.lists {
		abstract := abstractBullets
		if numbered {
			abstract = abstractNumbers
		}
		fmt.Fprintf(&b, `<w:num w:numId="%d"><w:abstractNumId w:val="%d"/><w:lvlOverride w:ilvl="0"><w:startOverride w:val="1"/></w:lvlOverride></w:num>`, i+1, abstract)
	}
	b.WriteString(`</w:numbering>`)
	return b.String()
}

func (w *docxWriter) body(doc Document) string {
	var b strings.Builder
	b.WriteString(xmlHeader)
	b.WriteString(`<w:document xmlns:w="` + nsWord + `" xmlns:r="` + nsRelationships + `"><w:body>`)
	for i, block := range doc.Blocks {
		if int64(b.Len()) > w.most {
			w.over = true
			return ""
		}
		switch block.Type {
		case BlockHeading:
			w.paragraph(&b, fmt.Sprintf(`<w:pStyle w:val="Heading%d"/>`, block.Level), block.Runs, false)
		case BlockParagraph:
			w.paragraph(&b, "", block.Runs, false)
		case BlockList:
			w.lists = append(w.lists, block.Ordered)
			properties := fmt.Sprintf(`<w:pStyle w:val="ListParagraph"/><w:numPr><w:ilvl w:val="0"/><w:numId w:val="%d"/></w:numPr>`, len(w.lists))
			for _, item := range block.Items {
				w.paragraph(&b, properties, item, false)
			}
		case BlockTable:
			w.table(&b, block)
			// A table is followed by a paragraph where nothing else
			// follows it, and where another table does: a body does not
			// end at a table, and two tables with nothing between them are
			// read as one.
			if i == len(doc.Blocks)-1 || doc.Blocks[i+1].Type == BlockTable {
				b.WriteString(`<w:p/>`)
			}
		}
	}
	b.WriteString(`</w:body></w:document>`)
	return b.String()
}

func (w *docxWriter) table(b *strings.Builder, block Block) {
	// A table takes the whole width of the text, and its columns share it
	// equally. Every column states its width, in the grid and in each cell:
	// a reader given a grid of columns with no widths may refuse the file.
	columns := len(block.Rows[0])
	width := tableWidth / columns
	b.WriteString(`<w:tbl><w:tblPr><w:tblStyle w:val="TableGrid"/><w:tblW w:w="5000" w:type="pct"/></w:tblPr><w:tblGrid>`)
	for range columns {
		fmt.Fprintf(b, `<w:gridCol w:w="%d"/>`, width)
	}
	b.WriteString(`</w:tblGrid>`)
	row := func(cells []Cell, header bool) {
		b.WriteString(`<w:tr>`)
		if header {
			b.WriteString(`<w:trPr><w:tblHeader/></w:trPr>`)
		}
		for _, cell := range cells {
			fmt.Fprintf(b, `<w:tc><w:tcPr><w:tcW w:w="%d" w:type="dxa"/></w:tcPr>`, width)
			w.paragraph(b, "", cell, header)
			b.WriteString(`</w:tc>`)
		}
		b.WriteString(`</w:tr>`)
	}
	if block.Header != nil {
		row(block.Header, true)
	}
	for _, cells := range block.Rows {
		row(cells, false)
	}
	b.WriteString(`</w:tbl>`)
}

// paragraph writes one paragraph: its properties, where it has any, and its
// runs. bold makes every run of it bold, which is how a header row is
// written.
func (w *docxWriter) paragraph(b *strings.Builder, properties string, runs []Run, bold bool) {
	b.WriteString(`<w:p>`)
	if properties != "" {
		b.WriteString(`<w:pPr>` + properties + `</w:pPr>`)
	}
	for _, run := range runs {
		if run.Link != "" {
			b.WriteString(`<w:hyperlink r:id="` + w.relationship(run.Link) + `" w:history="1">`)
		}
		b.WriteString(`<w:r>`)
		// The properties of a run are written in the order the schema
		// gives them: the style, the fonts, bold, italic.
		var properties strings.Builder
		if run.Link != "" {
			properties.WriteString(`<w:rStyle w:val="Hyperlink"/>`)
		}
		if run.Code {
			properties.WriteString(`<w:rFonts w:ascii="` + codeFont + `" w:hAnsi="` + codeFont + `" w:cs="` + codeFont + `"/>`)
		}
		if run.Bold || bold {
			properties.WriteString(`<w:b/><w:bCs/>`)
		}
		if run.Italic {
			properties.WriteString(`<w:i/><w:iCs/>`)
		}
		if properties.Len() > 0 {
			b.WriteString(`<w:rPr>` + properties.String() + `</w:rPr>`)
		}
		text(b, run.Text)
		b.WriteString(`</w:r>`)
		if run.Link != "" {
			b.WriteString(`</w:hyperlink>`)
		}
	}
	b.WriteString(`</w:p>`)
}

// text writes a run's text: a line feed as a break, a tab as a tab, and
// everything between them as text whose spaces are kept.
func text(b *strings.Builder, s string) {
	flush := func(segment string) {
		if segment != "" {
			b.WriteString(`<w:t xml:space="preserve">` + escape(segment) + `</w:t>`)
		}
	}
	start := 0
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '\n':
			flush(s[start:i])
			b.WriteString(`<w:br/>`)
			start = i + 1
		case '\t':
			flush(s[start:i])
			b.WriteString(`<w:tab/>`)
			start = i + 1
		}
	}
	flush(s[start:])
}

// escape writes text as XML character data, which also serves inside a
// quoted attribute: the five characters XML reserves are written as
// references, and nothing else is changed.
func escape(s string) string {
	var b strings.Builder
	// EscapeText writes to a builder, which does not fail.
	_ = xml.EscapeText(&b, []byte(s))
	return b.String()
}
