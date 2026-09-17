package pdf

import (
	"bytes"
	"fmt"
	"strings"
	"testing"

	"adapters/internal/pdfgen"
)

// withEncryptionDictionary is normalDocument with the dictionary given as
// the encryption dictionary its trailer names. Nothing in it is encrypted.
func withEncryptionDictionary(t *testing.T, dictionary string) []byte {
	t.Helper()
	b := &pdfgen.Builder{}
	num := b.Add(pdfgen.Object{Body: dictionary})
	data := normalDocument(b)
	root := []byte(fmt.Sprintf("/Root %d 0 R /ID", b.Root))
	if bytes.Count(data, root) != 1 {
		t.Fatalf("the trailer's /Root is not found once")
	}
	return bytes.Replace(data, root, []byte(fmt.Sprintf("/Root %d 0 R /Encrypt %d 0 R /ID", b.Root, num)), 1)
}

// The encryption dictionary's /R is recorded as declared only when it is an
// integer within the canonical domain's range; a real, even one with no
// fraction, an integer past that range and anything that is not an integer
// literal are recorded as null. The document is not opened.
func TestDeclaredRevisionIsAnIntegerInTheCanonicalRange(t *testing.T) {
	integer := func(i int64) *int64 { return &i }
	for _, c := range []struct {
		declared string
		want     *int64
	}{
		{"/R 4", integer(4)},
		{"/R +4", integer(4)},
		{"/R 0", integer(0)},
		{"/R 9007199254740991", integer(9007199254740991)},
		{"/R -9007199254740991", integer(-9007199254740991)},
		{"/R 9007199254740992", nil},
		{"/R -9007199254740992", nil},
		{"/R 9223372036854775807", nil},
		{"/R 99999999999999999999", nil},
		{"/R 4.0", nil},
		{"/R 4.", nil},
		{"/R 1.5", nil},
		{"/R --4", nil},
		{"/R ++4", nil},
		{"/R -", nil},
		{"/R (4)", nil},
		{"/R /4", nil},
		{"", nil},
	} {
		data := withEncryptionDictionary(t, "<< /Filter /Standard /V 4 "+c.declared+" /P -1 /O <00> /U <00> >>")
		r := extract(t, data)
		if r.Fatal == nil || r.Fatal.Code != "pdf-encrypted" || len(r.Pages) != 0 {
			t.Errorf("%q: fatal %+v, %d pages", c.declared, r.Fatal, len(r.Pages))
			continue
		}
		enc := r.Encryption
		if enc == nil || enc.Opened || enc.Handler == nil || *enc.Handler != "Standard" {
			t.Errorf("%q: encryption %+v", c.declared, enc)
			continue
		}
		switch {
		case c.want == nil && enc.Revision != nil:
			t.Errorf("%q: revision %d recorded, want null", c.declared, *enc.Revision)
		case c.want != nil && (enc.Revision == nil || *enc.Revision != *c.want):
			t.Errorf("%q: revision %v, want %d", c.declared, enc.Revision, *c.want)
		}
	}
}

// The revision the handler is opened under is read as strictly as the one
// recorded: a document the standard handler opens at /R 4 is not opened at
// /R 4.0, and its revision is null.
func TestRevisionThatIsARealIsNotOpened(t *testing.T) {
	for _, aes := range []bool{false, true} {
		b := &pdfgen.Builder{Compress: true, Encrypt: &pdfgen.Encryption{Revision: 4, AES: aes, Owner: "owner", Permissions: -1}}
		data := normalDocument(b)
		const from = "<< /Filter /Standard /V 4 /R 4 "
		// The same length, so every offset in the file still holds.
		for to, opens := range map[string]bool{
			"<</Filter/Standard /V 4 /R 4.0 ": false,
			"<</Filter/Standard /V 4 /R   4 ": true,
		} {
			if len(to) != len(from) || bytes.Count(data, []byte(from)) != 1 {
				t.Fatalf("the replacement %q does not fit", to)
			}
			r := extract(t, bytes.Replace(data, []byte(from), []byte(to), 1))
			enc := r.Encryption
			if enc == nil {
				t.Fatalf("aes %v, %q: no encryption reported", aes, to)
			}
			if opens {
				if !enc.Opened || r.Fatal != nil || enc.Revision == nil || *enc.Revision != 4 || len(r.Pages) != 3 {
					t.Errorf("aes %v, %q: %+v %+v", aes, to, enc, r.Fatal)
				}
				continue
			}
			if enc.Opened || r.Fatal == nil || r.Fatal.Code != "pdf-encrypted" || enc.Revision != nil || len(r.Pages) != 0 {
				t.Errorf("aes %v, %q: opened %v, revision %v, fatal %+v", aes, to, enc.Opened, enc.Revision, r.Fatal)
			}
		}
	}
}

// An integer token is an optional sign and digits within the int64 range.
// A token of that shape past the range is a real of its magnitude, and one
// that only looks numeric is a real of the value it was always read as, so
// no integer object stands for something the document did not write.
func TestIntegerTokensAreLiterals(t *testing.T) {
	for _, c := range []struct {
		text string
		want object
	}{
		{"42", int64(42)},
		{"+42", int64(42)},
		{"-42", int64(-42)},
		{"-0", int64(0)},
		{"9223372036854775807", int64(9223372036854775807)},
		{"-9223372036854775808", int64(-9223372036854775808)},
		{"9223372036854775808", float64(9223372036854775808)},
		{"99999999999999999999", float64(1e20)},
		{"-99999999999999999999", float64(-1e20)},
		{"--4", float64(0)},
		{"++4", float64(4)},
		{"4-2", float64(0)},
		{"-", float64(0)},
		{"4.0", float64(4)},
	} {
		p := &parser{lex: newLexer([]byte(c.text), 0)}
		got, err := p.parseObject(0)
		if err != nil || got != c.want {
			t.Errorf("%q: %#v %v, want %#v", c.text, got, err, c.want)
		}
	}
}

// An /Encrypt that is the null object, written as null or through a reference
// to the null object, names no encryption dictionary: the document is read as
// one that is not encrypted. One that names an object the reader cannot read,
// or a value that is not a dictionary, is a dictionary that cannot be read.
func TestEncryptThatIsNullNamesNoDictionary(t *testing.T) {
	for _, c := range []struct {
		name, encrypt string
		opens         bool
	}{
		{"null", "/Encrypt null", true},
		{"a reference to the null object", "/Encrypt NULL 0 R", true},
		{"a reference to no object", "/Encrypt 999 0 R", false},
		{"a number", "/Encrypt 5", false},
	} {
		t.Run(c.name, func(t *testing.T) {
			b := &pdfgen.Builder{}
			null := b.Add(pdfgen.Object{Body: "null"})
			data := normalDocument(b)
			root := []byte(fmt.Sprintf("/Root %d 0 R /ID", b.Root))
			if bytes.Count(data, root) != 1 {
				t.Fatal("the trailer's /Root is not found once")
			}
			encrypt := strings.ReplaceAll(c.encrypt, "NULL", fmt.Sprint(null))
			r := extract(t, bytes.Replace(data, root, []byte(fmt.Sprintf("/Root %d 0 R %s /ID", b.Root, encrypt)), 1))
			if c.opens {
				if r.Fatal != nil || r.Encryption != nil || len(r.Pages) != 3 || len(r.Problems) != 0 {
					t.Fatalf("fatal %+v encryption %+v pages %d problems %+v", r.Fatal, r.Encryption, len(r.Pages), r.Problems)
				}
				return
			}
			if r.Fatal == nil || r.Fatal.Code != "pdf-encrypted" || r.Encryption == nil || r.Encryption.Opened || r.Encryption.Handler != nil || r.Encryption.Revision != nil || len(r.Pages) != 0 {
				t.Fatalf("fatal %+v encryption %+v pages %d", r.Fatal, r.Encryption, len(r.Pages))
			}
		})
	}
}

// withoutCatalog is a document of one page whose trailer names no catalog and
// that holds none, with the trailer's /Encrypt the one given.
func withoutCatalog(t *testing.T, b *pdfgen.Builder, encrypt func(b *pdfgen.Builder) string) []byte {
	t.Helper()
	extra := ""
	if encrypt != nil {
		extra = encrypt(b)
	}
	helv := b.Font("Helvetica", "WinAnsiEncoding", "")
	b.Pages([]pdfgen.Page{{Content: shown("text", 700), Fonts: map[string]int{"F1": helv}}})
	data := b.Bytes()
	if bytes.Contains(data, []byte("/Catalog")) {
		t.Fatal("the document holds a catalog")
	}
	data = replaceOnce(t, data, `/Root 0 0 R `, "")
	if extra != "" {
		data = replaceOnce(t, data, `/ID \[`, extra+" /ID [")
	}
	return data
}

// The encryption dictionary a trailer names is read before the catalog is
// looked for: a document with no catalog whose encryption does not open is
// pdf-encrypted, and one whose encryption opens is pdf-malformed with its
// encryption declared and opened. With no encryption dictionary, a document
// with no catalog is pdf-malformed and declares none.
func TestEncryptionIsReadBeforeTheCatalog(t *testing.T) {
	zeros := strings.Repeat("00", 32)
	notOpened := withoutCatalog(t, &pdfgen.Builder{}, func(b *pdfgen.Builder) string {
		return fmt.Sprintf("/Encrypt %d 0 R", b.Add(pdfgen.Object{Body: "<< /Filter /Standard /V 2 /R 3 /Length 128 /O <" + zeros + "> /U <" + zeros + "> /P -4 >>"}))
	})
	r := extract(t, notOpened)
	if r.Fatal == nil || r.Fatal.Code != "pdf-encrypted" || r.Encryption == nil || r.Encryption.Opened || r.Encryption.Handler == nil || *r.Encryption.Handler != "Standard" || r.Encryption.Revision == nil || *r.Encryption.Revision != 3 {
		t.Fatalf("not opened: fatal %+v encryption %+v", r.Fatal, r.Encryption)
	}
	opened := withoutCatalog(t, &pdfgen.Builder{Encrypt: &pdfgen.Encryption{Revision: 3, Owner: "owner", Permissions: -4}}, nil)
	r = extract(t, opened)
	if r.Fatal == nil || r.Fatal.Code != "pdf-malformed" || r.Encryption == nil || !r.Encryption.Opened || r.Encryption.Revision == nil || *r.Encryption.Revision != 3 || len(r.Pages) != 0 {
		t.Fatalf("opened: fatal %+v encryption %+v", r.Fatal, r.Encryption)
	}
	r = extract(t, withoutCatalog(t, &pdfgen.Builder{}, nil))
	if r.Fatal == nil || r.Fatal.Code != "pdf-malformed" || r.Encryption != nil || len(r.Pages) != 0 {
		t.Fatalf("no encryption: fatal %+v encryption %+v", r.Fatal, r.Encryption)
	}
}

// The handler is the encryption dictionary's /Filter name as the document
// declares it, and null where those bytes are not text a record carries: the
// record holds the name as declared or nothing, not a reading of it with a
// replacement character in place of each byte it could not carry. The
// document is not opened either way, and which handler this reader opens is
// decided on the name's bytes.
func TestDeclaredHandlerIsTheNameOrNull(t *testing.T) {
	name := func(s string) *string { return &s }
	for _, c := range []struct {
		what     string
		declared string
		want     *string
	}{
		{"a name of ASCII", "/Filter /Handler", name("Handler")},
		{"a name whose escapes are valid UTF-8", "/Filter /caf#C3#A9", name("café")},
		{"a name with a byte that is no UTF-8", "/Filter /#FFhandler", nil},
		{"a name of one byte that is no UTF-8", "/Filter /#80", nil},
		{"a name cut off in the middle of a rune", "/Filter /caf#C3", nil},
		{"no name", "", nil},
		{"a /Filter that is not a name", "/Filter (Standard)", nil},
	} {
		t.Run(c.what, func(t *testing.T) {
			r := extract(t, withEncryptionDictionary(t, "<< "+c.declared+" /V 2 /R 3 /P -1 >>"))
			if r.Fatal == nil || r.Fatal.Code != "pdf-encrypted" || len(r.Pages) != 0 {
				t.Fatalf("fatal %+v, %d pages", r.Fatal, len(r.Pages))
			}
			enc := r.Encryption
			if enc == nil || enc.Opened || enc.Revision == nil || *enc.Revision != 3 {
				t.Fatalf("encryption %+v", enc)
			}
			switch {
			case c.want == nil && enc.Handler != nil:
				t.Fatalf("handler %q recorded, want null", *enc.Handler)
			case c.want != nil && (enc.Handler == nil || *enc.Handler != *c.want):
				t.Fatalf("handler %v, want %q", enc.Handler, *c.want)
			}
		})
	}
}
