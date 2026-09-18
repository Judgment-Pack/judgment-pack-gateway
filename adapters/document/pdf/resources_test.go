package pdf

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"adapters/internal/pdfgen"
)

func TestEscapedNamesHaveTheSameDecodedBound(t *testing.T) {
	for _, unit := range []string{"A", "#41"} {
		for _, n := range []int{maxNameBytes, maxNameBytes + 1} {
			tok, err := newLexer([]byte("/"+strings.Repeat(unit, n)), 0).next()
			if n == maxNameBytes {
				if err != nil || string(tok.name) != strings.Repeat("A", n) {
					t.Fatalf("%q at the bound: name length %d, error %v", unit, len(tok.name), err)
				}
			} else if !errors.Is(err, errStructureBound) {
				t.Fatalf("%q past the bound: name length %d, error %v", unit, len(tok.name), err)
			}
		}
	}
}

// Stream lengths can resolve other streams while those streams are being
// parsed. This nesting needs a bound in addition to reference-to-reference
// chains. A failed length must fail its content instead of using fallback
// scanning to hide the bound; a later readable page has its own result.
func TestIndirectStreamLengthsHaveABoundedReadDepth(t *testing.T) {
	if !isolated(t, 4<<20, 256<<20) {
		return
	}
	for _, shape := range []struct {
		count   int
		streams bool
	}{{maxRefDepth / 2, true}, {4096, true}, {maxRefDepth / 2, false}, {maxRefDepth + 1, false}} {
		count := shape.count
		b := &pdfgen.Builder{}
		for i := 1; i <= count; i++ {
			body := fmt.Sprintf("%d 0 R", i+1)
			if shape.streams || i == 1 {
				body = fmt.Sprintf("<< /Length %d 0 R >>\nstream\n\nendstream", i+1)
			}
			b.Add(pdfgen.Object{Body: body})
		}
		b.Add(pdfgen.Object{Body: "0"})
		font := b.Font("Helvetica", "WinAnsiEncoding", "")
		b.Catalog(b.Pages([]pdfgen.Page{{Extra: "/Contents 1 0 R"}, {Content: shown("next", 700), Fonts: map[string]int{"F1": font}}}))
		r := extract(t, b.Bytes())
		if r.Fatal != nil || len(r.Pages) != 2 || r.Pages[1].Text != "next" {
			t.Fatalf("%d nested lengths: fatal %+v pages %+v", count, r.Fatal, r.Pages)
		}
		if count < maxRefDepth {
			if r.Pages[0].Status != PageNoText || len(r.Problems) != 0 {
				t.Fatalf("within the bound: pages %+v problems %+v", r.Pages, r.Problems)
			}
		} else if r.Pages[0].Status != PageFailed || len(r.Problems) != 1 || r.Problems[0].Code != "pdf-page-failed" {
			t.Fatalf("past the bound: pages %+v problems %+v", r.Pages, r.Problems)
		}
	}
}

func TestFormInheritsTheSelectedFont(t *testing.T) {
	b := &pdfgen.Builder{}
	font := b.Font("Helvetica", "WinAnsiEncoding", "")
	form := b.Add(pdfgen.Object{Body: "<< /Type /XObject /Subtype /Form /BBox [0 0 612 792] >>", Stream: []byte("BT 72 700 Td (ABC) Tj ET /Missing 30 Tf")})
	b.Catalog(b.Pages([]pdfgen.Page{{Content: "/F1 12 Tf /Fm Do BT 72 680 Td (DEF) Tj ET", Fonts: map[string]int{"F1": font}, XObjects: map[string]int{"Fm": form}}}))
	data := b.Bytes()
	r := extract(t, data)
	if r.Fatal != nil || len(r.Pages) != 1 || r.Pages[0].Text != "ABC\nDEF" || r.Pages[0].Unmapped != 0 {
		t.Fatalf("fatal %+v pages %+v problems %+v", r.Fatal, r.Pages, r.Problems)
	}
	crossCheckWithPoppler(t, data, []string{"ABC", "DEF"})
}

func TestInvalidUTF16MappingsCountTheGlyphAsUnmapped(t *testing.T) {
	for _, c := range []struct {
		name, destination, text string
		unmapped                int
	}{
		{"high surrogate", "D800", "�", 1},
		{"low surrogate", "DC00", "�", 1},
		{"unpaired surrogate after a scalar", "0041D800", "�", 1},
		{"high surrogate before a scalar", "D8000041", "�", 1},
		{"trailing byte", "004100", "�", 1},
		{"surrogate pair", "D834DD1E", "𝄞", 0},
		{"declared replacement character", "FFFD", "�", 0},
	} {
		t.Run(c.name, func(t *testing.T) {
			b := &pdfgen.Builder{}
			mapping := "begincmap 1 begincodespacerange <0000> <FFFF> endcodespacerange 1 beginbfchar <0001> <" + c.destination + "> endbfchar endcmap"
			font := cidFont(b, "", b.Add(pdfgen.Object{Body: "<< >>", Stream: []byte(mapping)}))
			b.Catalog(b.Pages([]pdfgen.Page{{Content: "BT /F1 12 Tf <0001> Tj ET", Fonts: map[string]int{"F1": font}}}))
			r := extract(t, b.Bytes())
			if r.Fatal != nil || len(r.Pages) != 1 || r.Pages[0].Text != c.text || r.Pages[0].Unmapped != c.unmapped {
				t.Fatalf("fatal %+v pages %+v problems %+v", r.Fatal, r.Pages, r.Problems)
			}
		})
	}
}
