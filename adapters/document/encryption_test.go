package document

import (
	"bytes"
	"fmt"
	"strings"
	"testing"

	"adapters/attachment"
	"adapters/internal/pdfgen"
)

// A trailer whose /Encrypt is null names no encryption dictionary: the record
// declares none and is complete. One with no catalog whose encryption does not
// open is pdf-encrypted with its encryption declared; one whose encryption
// opens is pdf-malformed with its encryption declared and opened. The check
// admits each.
func TestEncryptionDeclaredOrNotInTheRecord(t *testing.T) {
	cfg := DefaultConfig()
	font := func(b *pdfgen.Builder) int { return b.Font("Helvetica", "WinAnsiEncoding", "") }

	b := &pdfgen.Builder{}
	f := font(b)
	b.Catalog(b.Pages([]pdfgen.Page{{Content: pdfgen.Text("F1", 12, []string{"Hello"}), Fonts: map[string]int{"F1": f}}}))
	data := b.Bytes()
	root := []byte(fmt.Sprintf("/Root %d 0 R /ID", b.Root))
	if bytes.Count(data, root) != 1 {
		t.Fatal("the trailer's /Root is not found once")
	}
	data = bytes.Replace(data, root, []byte(fmt.Sprintf("/Root %d 0 R /Encrypt null /ID", b.Root)), 1)
	rec := processed(t, cfg, mustParse(t, cfg, requestJSON("n.pdf", "application/pdf", data, "")), nil)
	if rec.Processing.Status != attachment.StatusComplete || rec.Document.Encryption != nil || rec.Content.Pages[0].Text != "Hello" {
		t.Fatalf("/Encrypt null: %s %+v %+v", codes(rec), rec.Document.Encryption, rec.Content.Pages)
	}

	withoutCatalog := func(b *pdfgen.Builder, extra string) []byte {
		f := font(b)
		b.Pages([]pdfgen.Page{{Content: pdfgen.Text("F1", 12, []string{"Hello"}), Fonts: map[string]int{"F1": f}}})
		data := b.Bytes()
		if bytes.Count(data, []byte("/Root 0 0 R ")) != 1 || bytes.Count(data, []byte("/ID [")) != 1 {
			t.Fatal("the trailer is not the generator's")
		}
		data = bytes.Replace(data, []byte("/Root 0 0 R "), nil, 1)
		return bytes.Replace(data, []byte("/ID ["), []byte(extra+"/ID ["), 1)
	}
	b = &pdfgen.Builder{}
	zeros := strings.Repeat("00", 32)
	enc := b.Add(pdfgen.Object{Body: "<< /Filter /Standard /V 2 /R 3 /Length 128 /O <" + zeros + "> /U <" + zeros + "> /P -4 >>"})
	rec = processed(t, cfg, mustParse(t, cfg, requestJSON("e.pdf", "application/pdf", withoutCatalog(b, fmt.Sprintf("/Encrypt %d 0 R ", enc)), "")), nil)
	if codes(rec) != attachment.CodePDFEncrypted || rec.Document.Encryption == nil || rec.Document.Encryption.Opened || rec.Document.Encryption.Revision == nil || *rec.Document.Encryption.Revision != 3 {
		t.Fatalf("not opened: %s %+v", codes(rec), rec.Document.Encryption)
	}
	b = &pdfgen.Builder{Encrypt: &pdfgen.Encryption{Revision: 3, Owner: "owner", Permissions: -4}}
	rec = processed(t, cfg, mustParse(t, cfg, requestJSON("o.pdf", "application/pdf", withoutCatalog(b, ""), "")), nil)
	if codes(rec) != attachment.CodePDFMalformed || rec.Document.Encryption == nil || !rec.Document.Encryption.Opened {
		t.Fatalf("opened: %s %+v", codes(rec), rec.Document.Encryption)
	}
}

// A document whose encryption dictionary declares a revision the canonical
// domain cannot carry, or a real, is still a record the check admits: the
// revision is null, and the document is pdf-encrypted.
func TestEncryptionRevisionInTheRecord(t *testing.T) {
	cfg := DefaultConfig()
	for declared, want := range map[string]string{
		"9007199254740992": "null",
		"4.0":              "null",
		"4":                "4",
	} {
		b := &pdfgen.Builder{}
		enc := b.Add(pdfgen.Object{Body: "<< /Filter /Standard /V 4 /R " + declared + " /P -1 /O <00> /U <00> >>"})
		font := b.Font("Helvetica", "WinAnsiEncoding", "")
		b.Catalog(b.Pages([]pdfgen.Page{{Content: pdfgen.Text("F1", 12, []string{"Hello"}), Fonts: map[string]int{"F1": font}}}))
		data := b.Bytes()
		root := []byte(fmt.Sprintf("/Root %d 0 R /ID", b.Root))
		if bytes.Count(data, root) != 1 {
			t.Fatal("the trailer's /Root is not found once")
		}
		data = bytes.Replace(data, root, []byte(fmt.Sprintf("/Root %d 0 R /Encrypt %d 0 R /ID", b.Root, enc)), 1)
		// processed holds the record to attachment.Check.
		rec := processed(t, cfg, mustParse(t, cfg, requestJSON("e.pdf", "application/pdf", data, "")), nil)
		if codes(rec) != attachment.CodePDFEncrypted || rec.Document.Encryption == nil || rec.Document.Encryption.Opened {
			t.Fatalf("/R %s: %s %+v", declared, codes(rec), rec.Document.Encryption)
		}
		got := "null"
		if r := rec.Document.Encryption.Revision; r != nil {
			got = fmt.Sprint(*r)
		}
		if got != want {
			t.Errorf("/R %s: revision %s, want %s", declared, got, want)
		}
	}
}
