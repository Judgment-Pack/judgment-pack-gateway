//go:build ignore

// make_fixtures writes the fixtures docs/design/attachments.md names,
// from the generator in adapters/internal/pdfgen, deterministically:
//
//	cd adapters && go run ./document/testdata/make_fixtures.go
//
// fixtures_test.go holds each fixture to the record it yields.
package main

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"adapters/internal/pdfgen"
)

func main() {
	dir := "document/testdata"
	if len(os.Args) > 1 {
		dir = os.Args[1]
	}
	for name, data := range Fixtures() {
		if err := os.WriteFile(filepath.Join(dir, name), data, 0o644); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	}
}

// Fixtures returns every fixture by file name.
func Fixtures() map[string][]byte {
	out := map[string][]byte{}
	normal := func() *pdfgen.Builder {
		b := &pdfgen.Builder{Compress: true}
		helv := b.Font("Helvetica", "WinAnsiEncoding", "")
		lig := b.Font("Times-Roman", "WinAnsiEncoding", "1 /fi")
		t0 := b.Type0Font([]rune("Composite text"))
		page1 := pdfgen.Text("F1", 12, []string{"Federal Skilled Worker Program", "Minimum requirements", "caf\xe9 na\xefve"}) +
			"BT /F2 12 Tf 1 0 0 1 72 600 Tm (\\001nal) Tj ET\n"
		var codes strings.Builder
		for i := range "Composite text" {
			codes.WriteString(string([]byte{0, byte(i + 1)}))
		}
		page2 := "BT /F3 14 Tf 1 0 0 1 72 700 Tm <" + hexOf(codes.String()) + "> Tj ET\n"
		b.Catalog(b.Pages([]pdfgen.Page{
			{Content: page1, Fonts: map[string]int{"F1": helv, "F2": lig}},
			{Content: page2, Fonts: map[string]int{"F3": t0}},
			{Content: ""},
		}))
		return b
	}
	out["normal.pdf"] = normal().Bytes()
	{
		b := &pdfgen.Builder{Compress: true}
		img := b.Image()
		b.Catalog(b.Pages([]pdfgen.Page{
			{Content: "q 612 0 0 792 0 0 cm /Im1 Do Q\n", XObjects: map[string]int{"Im1": img}},
			{Content: "q 612 0 0 792 0 0 cm /Im1 Do Q\n", XObjects: map[string]int{"Im1": img}},
		}))
		out["scanned.pdf"] = b.Bytes()
	}
	{
		b := &pdfgen.Builder{Compress: true}
		img := b.Image()
		helv := b.Font("Helvetica", "WinAnsiEncoding", "")
		b.Catalog(b.Pages([]pdfgen.Page{
			{Content: pdfgen.Text("F1", 12, []string{"Re: your application", "Decision letter"}), Fonts: map[string]int{"F1": helv}},
			{Content: "q 612 0 0 792 0 0 cm /Im1 Do Q\n", XObjects: map[string]int{"Im1": img}},
		}))
		out["mixed.pdf"] = b.Bytes()
	}
	{
		b := normalBase(false)
		b.Encrypt = &pdfgen.Encryption{Revision: 3, Owner: "owner", Permissions: -3904}
		out["encrypted-rc4.pdf"] = b.Bytes()
		b = normalBase(true)
		b.Encrypt = &pdfgen.Encryption{Revision: 4, AES: true, Owner: "owner", Permissions: -1}
		out["encrypted-aes.pdf"] = b.Bytes()
		b = normalBase(false)
		b.Encrypt = &pdfgen.Encryption{Revision: 3, User: "secret", Owner: "owner", Permissions: -1}
		out["encrypted-user.pdf"] = b.Bytes()
	}
	{
		data := normal().Bytes()
		// Cut inside the second page's content stream: the first page's
		// objects survive, the cross-reference is gone.
		cut := bytes.Index(data, []byte("2 0 obj"))
		if cut < 0 {
			cut = len(data) / 2
		}
		out["malformed-truncated.pdf"] = data[:len(data)*2/3]
		b := normal()
		b.BrokenOffsets = 13
		out["malformed-xref.pdf"] = b.Bytes()
	}
	out["not-a-pdf.pdf"] = []byte("This is a text file that was named as a PDF.\n")
	{
		b := &pdfgen.Builder{Compress: true}
		helv := b.Font("Helvetica", "WinAnsiEncoding", "")
		var pages []pdfgen.Page
		for i := 1; i <= 60; i++ {
			pages = append(pages, pdfgen.Page{Content: pdfgen.Text("F1", 12, []string{fmt.Sprintf("Page %d", i)}), Fonts: map[string]int{"F1": helv}})
		}
		b.Catalog(b.Pages(pages))
		out["many-pages.pdf"] = b.Bytes()
	}
	{
		b := &pdfgen.Builder{Compress: true}
		helv := b.Font("Helvetica", "WinAnsiEncoding", "")
		bomb := strings.Repeat(" ", 20<<20)
		b.Catalog(b.Pages([]pdfgen.Page{
			{Content: bomb, Fonts: map[string]int{"F1": helv}},
			{Content: pdfgen.Text("F1", 12, []string{"after the bomb"}), Fonts: map[string]int{"F1": helv}},
		}))
		out["inflate-bomb.pdf"] = b.Bytes()
	}
	out["notes.txt"] = []byte("\xEF\xBB\xBFline one\r\nline two\rline three\n")
	return out
}

func normalBase(objectStreams bool) *pdfgen.Builder {
	b := &pdfgen.Builder{Compress: true, XrefStream: objectStreams, ObjectStreams: objectStreams}
	helv := b.Font("Helvetica", "WinAnsiEncoding", "")
	b.Catalog(b.Pages([]pdfgen.Page{{Content: pdfgen.Text("F1", 12, []string{"Confidential policy", "Section 1"}), Fonts: map[string]int{"F1": helv}}}))
	return b
}

func hexOf(s string) string {
	const digits = "0123456789ABCDEF"
	var sb strings.Builder
	for i := 0; i < len(s); i++ {
		sb.WriteByte(digits[s[i]>>4])
		sb.WriteByte(digits[s[i]&15])
	}
	return sb.String()
}
