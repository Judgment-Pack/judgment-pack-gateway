package document

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"adapters/attachment"
	"adapters/internal/pdfgen"
)

// readingsFrom is a deadline that passes at the reading of it numbered n and
// at every reading after it, counting every reading; with n of zero it never
// passes.
type readingsFrom struct {
	context.Context
	n, reads int
}

func (c *readingsFrom) Err() error {
	c.reads++
	if c.n > 0 && c.reads >= c.n {
		return context.DeadlineExceeded
	}
	return nil
}

func (c *readingsFrom) Deadline() (time.Time, bool) { return time.Time{}, false }

// stoppedEncryption is a one-page document showing "Hello", encrypted with
// RC4 under revision 4 and the empty user password, in which the field of the
// encryption dictionary given is an object of its own: its value followed by
// a comment of 40,000 bytes, which the reader reads the deadline in. A
// deadline that passes there leaves the field unread.
func stoppedEncryption(t *testing.T, field, value string) []byte {
	t.Helper()
	b := &pdfgen.Builder{Encrypt: &pdfgen.Encryption{Revision: 4, Permissions: -4}}
	f := b.Font("Helvetica", "WinAnsiEncoding", "")
	b.Catalog(b.Pages([]pdfgen.Page{{Content: pdfgen.Text("F1", 12, []string{"Hello"}), Fonts: map[string]int{"F1": f}}}))
	held := b.Add(pdfgen.Object{Body: value + " %" + strings.Repeat("x", 40000) + "\n"})
	b.Encrypt.Dictionary = func(dict string) string {
		declared := fmt.Sprintf("/%s %s ", field, value)
		if strings.Count(dict, declared) != 1 {
			t.Fatalf("the dictionary does not declare %q once: %s", declared, dict)
		}
		return strings.Replace(dict, declared, fmt.Sprintf("/%s %d 0 R ", field, held), 1)
	}
	return b.Bytes()
}

// A deadline that passes while the encryption dictionary is read, before the
// document is opened, is a record of its own: encryption declared and not
// opened, the timeout its one error, no page counted -- and no pdf-encrypted,
// which says a password is required or the handler is not one version 1
// opens, and neither is so. A field the deadline left unread is null, not the
// value the reader takes a field it does not find for: with time left, the
// same file declares it and opens. The check admits the record at every
// reading the deadline can pass at, through the stream filter's name, the
// revision and the handler's name each made an object of its own.
func TestATimedOutEncryptionIsARecordTheCheckAdmits(t *testing.T) {
	cfg := DefaultConfig()
	for _, c := range []struct {
		field, value string
		// unread says what the record holds where the field is unread.
		unread func(*attachment.Encryption) bool
	}{
		{"StmF", "/StdCF", func(e *attachment.Encryption) bool {
			return e.Handler != nil && *e.Handler == "Standard" && e.Revision != nil && *e.Revision == 4
		}},
		{"R", "4", func(e *attachment.Encryption) bool { return e.Revision == nil && e.Handler != nil }},
		{"Filter", "/Standard", func(e *attachment.Encryption) bool { return e.Handler == nil }},
	} {
		t.Run(c.field, func(t *testing.T) {
			data := stoppedEncryption(t, c.field, c.value)
			req := mustParse(t, cfg, requestJSON("e.pdf", "application/pdf", data, ""))
			live := &readingsFrom{Context: context.Background()}
			whole := processedIn(t, live, cfg, req, nil)
			if whole.Processing.Status != attachment.StatusComplete || whole.Document.Encryption == nil || !whole.Document.Encryption.Opened || whole.Content.Pages[0].Text != "Hello" {
				t.Fatalf("with no deadline: %s %+v %+v", codes(whole), whole.Document.Encryption, whole.Content.Pages)
			}
			if e := whole.Document.Encryption; e.Handler == nil || *e.Handler != "Standard" || e.Revision == nil || *e.Revision != 4 {
				t.Fatalf("with no deadline the handler and revision read as %v and %v", e.Handler, e.Revision)
			}
			stopped := 0
			for n := 1; n <= live.reads; n++ {
				p := &processor{cfg: cfg, identity: testIdentity, reading: fixedNow(), now: fixedNow}
				out, err := p.process(&readingsFrom{Context: context.Background(), n: n}, req)
				if err != nil {
					t.Fatal(err)
				}
				if err := attachment.Check(out); err != nil {
					t.Fatalf("deadline at reading %d: %v\n%s", n, err, out)
				}
				rec := decodeRecord(t, out)
				if e := rec.Document.Encryption; e != nil && !e.Opened {
					if codes(rec) != attachment.CodeTimeout || rec.Content.PageCount != 0 || !c.unread(e) {
						t.Fatalf("deadline at reading %d: not opened, with %s, %d pages counted, handler %v, revision %v", n, codes(rec), rec.Content.PageCount, e.Handler, e.Revision)
					}
					stopped++
				}
			}
			t.Logf("%d readings; the deadline left the encryption unopened at %d of them", live.reads, stopped)
			if stopped == 0 {
				t.Fatal("no reading position left the encryption unopened")
			}
		})
	}
}

// decodeRecord decodes a record the processor wrote.
func decodeRecord(t *testing.T, out []byte) attachment.Record {
	t.Helper()
	var rec attachment.Record
	dec := json.NewDecoder(bytes.NewReader(out))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&rec); err != nil {
		t.Fatalf("record does not decode: %v\n%s", err, out)
	}
	return rec
}

// encryptedHello is a one-page document showing "Hello", encrypted with RC4
// under revision 4 and the empty user password, its encryption dictionary
// rewritten by change and the builder set by build.
func encryptedHello(change func(string) string, build func(*pdfgen.Builder)) []byte {
	b := &pdfgen.Builder{Encrypt: &pdfgen.Encryption{Revision: 4, Permissions: -4, Dictionary: change}}
	if build != nil {
		build(b)
	}
	f := b.Font("Helvetica", "WinAnsiEncoding", "")
	b.Catalog(b.Pages([]pdfgen.Page{{Content: pdfgen.Text("F1", 12, []string{"Hello"}), Fonts: map[string]int{"F1": f}}}))
	return b.Bytes()
}

// A rebuild of the cross-reference reads the encryption dictionary its
// trailer names, and opens it, before it decodes the object stream the
// catalog, the pages and the font lie in; a deadline that stops the rebuild
// after that leaves a document that was opened, and the record says so --
// the declaration the rebuild read and opened true, with the timeout the
// opening met and no page counted -- rather than taking the declaration
// back. The file names every object one byte from where it stands. At every
// reading position the record passes the check, a declaration a record has
// read is read by the record of every later position too, and so is an
// opening; and some record says the encryption opened and the deadline
// passed while the document was opened.
func TestARebuildsOpeningIsWhatTheRecordDeclares(t *testing.T) {
	cfg := DefaultConfig()
	data := encryptedHello(nil, func(b *pdfgen.Builder) { b.XrefStream, b.ObjectStreams, b.BrokenOffsets = true, true, 1 })
	req := mustParse(t, cfg, requestJSON("e.pdf", "application/pdf", data, ""))
	live := &readingsFrom{Context: context.Background()}
	whole := processedIn(t, live, cfg, req, nil)
	if e := whole.Document.Encryption; e == nil || !e.Opened || e.Handler == nil || *e.Handler != "Standard" || whole.Content.Pages[0].Text != "Hello" {
		t.Fatalf("with no deadline: %s %+v", codes(whole), whole.Document.Encryption)
	}
	declared, opened, rebuiltOpen := false, false, 0
	for n := 1; n <= live.reads; n++ {
		p := &processor{cfg: cfg, identity: testIdentity, reading: fixedNow(), now: fixedNow}
		out, err := p.process(&readingsFrom{Context: context.Background(), n: n}, req)
		if err != nil {
			t.Fatal(err)
		}
		if err := attachment.Check(out); err != nil {
			t.Fatalf("deadline at reading %d: %v\n%s", n, err, out)
		}
		rec := decodeRecord(t, out)
		e := rec.Document.Encryption
		if declared && (e == nil || e.Handler == nil || e.Revision == nil) {
			t.Fatalf("deadline at reading %d: the declaration a deadline at an earlier reading left read is taken back: %+v", n, e)
		}
		if opened && (e == nil || !e.Opened) {
			t.Fatalf("deadline at reading %d: the opening a deadline at an earlier reading left made is taken back: %+v", n, e)
		}
		if e != nil && e.Handler != nil && e.Revision != nil {
			declared = true
		}
		if e != nil && e.Opened {
			opened = true
			if len(rec.Processing.Errors) == 1 && strings.Contains(rec.Processing.Errors[0].Message, "while the document was opened") {
				rebuiltOpen++
			}
		}
	}
	t.Logf("%d readings; the record says the encryption opened and the deadline passed while the document was opened at %d of them", live.reads, rebuiltOpen)
	if rebuiltOpen == 0 {
		t.Fatal("no record says the encryption opened and the deadline then stopped the opening: the rebuild's opening was taken back")
	}
}
