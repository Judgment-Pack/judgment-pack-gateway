package pdf

import "fmt"

// What the tests of package pdf_test reach of the reader's own: the events
// of every reading of an encryption dictionary, and the files the internal
// tests build.

// EncryptionEvent is encryptionEvent.
type EncryptionEvent = encryptionEvent

const (
	EncryptionBegan      = encryptionBegan
	EncryptionNamed      = encryptionNamed
	EncryptionReached    = encryptionReached
	EncryptionField      = encryptionField
	EncryptionDecided    = encryptionDecided
	EncryptionEnded      = encryptionEnded
	EncryptionGeneration = encryptionGeneration
)

// TraceEncryption has f told of every event of every reading of an
// encryption dictionary, and of every replacement of the cross-reference,
// until the function it returns is called.
func TraceEncryption(f func(event EncryptionEvent, reading, generation int, field string, info *Encryption, err error)) func() {
	encryptionTraced = func(_ *Document, event encryptionEvent, reading, generation int, field string, info *Encryption, err error) {
		f(event, reading, generation, field, info, err)
	}
	return func() { encryptionTraced = nil }
}

// IsDeadline is isDeadline.
func IsDeadline(err error) bool { return isDeadline(err) }

// StopCryptFile and StopRebuiltCryptFile are the sweep's encrypted files.
func StopCryptFile() []byte        { return stopCryptFile() }
func StopRebuiltCryptFile() []byte { return stopRebuiltCryptFile() }

// RebuiltEncryptionFiles are the files of
// TestReadsEncryptionIsEstablishedUnderTheCrossReferenceInForce, by name:
// two encryption dictionaries under one number, deriving two keys, and a
// cross-reference that a read of the page's content or of the first
// dictionary's /O rebuilds.
func RebuiltEncryptionFiles() map[string][]byte {
	const permissions = -1
	oldO, _, oldU := readsRC4Key("one", permissions)
	newO, newKey, newU := readsRC4Key("two", permissions)
	dictionary := func(o, u []byte) string {
		return fmt.Sprintf("<< /Filter /Standard /V 1 /R 2 /P %d /O <%x> /U <%x> >>", permissions, o, u)
	}
	content := []byte(shown("NEW", 700))
	page := []readsObject{
		{1, "<< /Type /Catalog /Pages 2 0 R >>"},
		{2, "<< /Type /Pages /Kids [3 0 R] /Count 1 >>"},
		{3, "<< /Type /Page /Parent 2 0 R /Resources << /Font << /F1 7 0 R >> >> /Contents 6 0 R >>"},
		{6, readsStreamObject("", string(readsRC4Encrypt(newKey, 6, content)))},
		{7, "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>"},
	}
	trailer := fmt.Sprintf("/Encrypt 9 0 R /ID [<%x> <%x>]", readsFileID, readsFileID)
	return map[string][]byte{
		"the page's content is what rebuilds": readsRawTrailer(append(append([]readsObject{}, page...),
			readsObject{9, dictionary(oldO, oldU)}, readsObject{9, dictionary(newO, newU)}), 6, nil, trailer),
		"a member of the encryption dictionary is": readsRawTrailer(append(append([]readsObject{}, page...),
			readsObject{9, fmt.Sprintf("<< /Filter /Standard /V 1 /R 2 /P %d /O 10 0 R /U <%x> >>", permissions, oldU)},
			readsObject{10, fmt.Sprintf("<%x>", oldO)},
			readsObject{9, dictionary(newO, newU)}), 10, nil, trailer),
	}
}
