package pdf

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/rc4"
	"crypto/sha256"
	"crypto/sha512"
	"errors"
	"fmt"
	"unicode/utf8"
)

// Encryption is what a document's encryption dictionary declares -- its
// /Filter name, nil where the dictionary holds no name there or where the
// name's bytes are not valid UTF-8, since the record carries the name as the
// document declares it and not a substitution for it, and its /R, nil where
// the dictionary holds no integer within the canonical domain's range there
// -- and whether this reader opened it. Which handler this reader opens is
// decided on the name's bytes, whether or not the record carries them.
type Encryption struct {
	Handler  *string
	Revision *int64
	Opened   bool
}

// cryptMethod is how strings or streams are encrypted.
type cryptMethod int

const (
	cryptNone cryptMethod = iota
	cryptRC4
	cryptAESV2
	cryptAESV3
)

// cryptHandler is the standard security handler, opened with an empty
// user password: the file key and the methods for strings and streams.
type cryptHandler struct {
	key             []byte
	strings         cryptMethod
	streams         cryptMethod
	revision        int
	encryptMetadata bool
}

var passwordPad = []byte{
	0x28, 0xBF, 0x4E, 0x5E, 0x4E, 0x75, 0x8A, 0x41, 0x64, 0x00, 0x4E, 0x56, 0xFF, 0xFA, 0x01, 0x08,
	0x2E, 0x2E, 0x00, 0xB6, 0xD0, 0x68, 0x3E, 0x80, 0x2F, 0x0C, 0xA9, 0xFE, 0x64, 0x53, 0x69, 0x7A,
}

var errPassword = errors.New("a user password is required")

// openEncryption reads the trailer's /Encrypt and tries the empty user
// password. It returns what the document declares, and a handler when it
// opened. An unsupported handler or revision is reported as not opened
// with the reason. An /Encrypt that is absent or the null object names no
// encryption dictionary; one that names an object the reader cannot read, or
// that is not a dictionary, is a dictionary that cannot be read.
func (d *Document) openEncryption() (*Encryption, error) {
	ev, ok := d.trailer["Encrypt"]
	if !ok {
		return nil, nil
	}
	// The encryption dictionary itself is never encrypted; resolve it
	// before the handler is installed.
	declared, read := d.resolveRead(ev)
	if read && declared == nil {
		return nil, nil
	}
	enc := d.dictOf(declared)
	if enc == nil {
		return &Encryption{}, malformed("/Encrypt is not a dictionary")
	}
	info := &Encryption{}
	filter, hasFilter := d.nameOf(enc["Filter"])
	if hasFilter && utf8.ValidString(string(filter)) {
		name := string(filter)
		info.Handler = &name
	}
	v, _ := d.intOf(enc["V"])
	// The revision is recorded as declared, and the handler opened under it,
	// only when it is an integer the record can carry: a real such as 4.0 is
	// no revision, and is not opened as one.
	r, hasRevision := d.declaredInteger(enc["R"])
	if hasRevision {
		revision := r
		info.Revision = &revision
	}
	if filter != "Standard" {
		return info, fmt.Errorf("security handler %q is not one this reader implements", filter)
	}
	length := int64(40)
	if l, ok := d.intOf(enc["Length"]); ok {
		length = l
	}
	o, _ := d.resolve(enc["O"]).(String)
	u, _ := d.resolve(enc["U"]).(String)
	p, pok := d.intOf(enc["P"])
	if !pok {
		return info, malformed("/Encrypt has no /P")
	}
	var id []byte
	if ids := d.arrayOf(d.trailer["ID"]); len(ids) > 0 {
		if s, ok := d.resolve(ids[0]).(String); ok {
			id = []byte(s)
		}
	}
	encryptMetadata := true
	if em, ok := d.resolve(enc["EncryptMetadata"]).(bool); ok {
		encryptMetadata = em
	}
	h := &cryptHandler{revision: int(r), encryptMetadata: encryptMetadata}
	switch {
	case !hasRevision:
		return info, errors.New("a standard security handler with no integer revision is not one this reader implements")
	case r == 2 || r == 3 || (r == 4 && (v == 1 || v == 2 || v == 4)):
		if len(o) < 32 || len(u) < 32 {
			return info, malformed("/O or /U shorter than 32 bytes")
		}
		n := 5
		if r >= 3 {
			if length < 40 || length > 128 || length%8 != 0 {
				return info, malformed("/Length %d out of range", length)
			}
			n = int(length / 8)
		}
		key := computeLegacyKey(nil, o[:32], int32(p), id, int(r), n, encryptMetadata)
		if !checkLegacyUser(key, u[:32], id, int(r)) {
			return info, errPassword
		}
		h.key = key
		h.strings, h.streams = cryptRC4, cryptRC4
		if v == 4 {
			sm, tm, err := d.cryptFilterMethods(enc)
			if err != nil {
				return info, err
			}
			h.strings, h.streams = sm, tm
		}
	case r == 5 || r == 6:
		if v != 5 {
			return info, malformed("/R %d with /V %d", r, v)
		}
		if len(u) < 48 || len(o) < 48 {
			return info, malformed("/O or /U shorter than 48 bytes")
		}
		ue, _ := d.resolve(enc["UE"]).(String)
		if len(ue) < 32 {
			return info, malformed("/UE shorter than 32 bytes")
		}
		validationSalt, keySalt := u[32:40], u[40:48]
		hash := hash2B
		if r == 5 {
			hash = func(password, salt, udata []byte) []byte {
				sum := sha256.Sum256(append(append(append([]byte{}, password...), salt...), udata...))
				return sum[:]
			}
		}
		if !bytes.Equal(hash(nil, validationSalt, nil), u[:32]) {
			return info, errPassword
		}
		intermediate := hash(nil, keySalt, nil)
		block, err := aes.NewCipher(intermediate)
		if err != nil {
			return info, err
		}
		fileKey := make([]byte, 32)
		cipher.NewCBCDecrypter(block, make([]byte, 16)).CryptBlocks(fileKey, ue[:32])
		h.key = fileKey
		sm, tm, err := d.cryptFilterMethods(enc)
		if err != nil {
			return info, err
		}
		h.strings, h.streams = sm, tm
	default:
		return info, fmt.Errorf("standard security handler revision %d is not one this reader implements", r)
	}
	info.Opened = true
	d.crypt = h
	// Objects parsed before the handler was installed (the encryption
	// dictionary's own referents) are not encrypted content; anything
	// cached so far is dropped so that strings and streams are read
	// through the handler from here. What they were charged stays charged:
	// the trailer holds some of them still, and reading them again through
	// the handler is charged again, which leaves the count above what the
	// reader holds and never below it.
	d.cache = map[int]object{}
	d.objStms = map[int]*objStm{}
	d.objStmHeaders = map[int]*objStmParsed{}
	return info, nil
}

// maxDeclaredInteger is the largest magnitude of an integer the record
// carries: 2^53 - 1, the canonical domain's range.
const maxDeclaredInteger = 1<<53 - 1

// declaredInteger resolves v and returns it when it is an integer the
// document wrote within -(2^53 - 1) to 2^53 - 1, with ok false otherwise: a
// real is not one, even with no fraction.
func (d *Document) declaredInteger(v object) (int64, bool) {
	i, ok := d.resolve(v).(int64)
	if !ok || i < -maxDeclaredInteger || i > maxDeclaredInteger {
		return 0, false
	}
	return i, true
}

// cryptFilterMethods reads /StmF and /StrF through /CF for V4 and V5.
func (d *Document) cryptFilterMethods(enc Dict) (strings, streams cryptMethod, err error) {
	cf := d.dictOf(enc["CF"])
	method := func(name Name) (cryptMethod, error) {
		if name == "" || name == "Identity" {
			return cryptNone, nil
		}
		if cf == nil {
			return cryptNone, malformed("/CF is missing")
		}
		f := d.dictOf(cf[name])
		if f == nil {
			return cryptNone, malformed("crypt filter %q is not in /CF", name)
		}
		cfm, _ := d.nameOf(f["CFM"])
		switch cfm {
		case "None", "":
			return cryptNone, nil
		case "V2":
			return cryptRC4, nil
		case "AESV2":
			return cryptAESV2, nil
		case "AESV3":
			return cryptAESV3, nil
		}
		return cryptNone, fmt.Errorf("crypt filter method %q is not one this reader implements", cfm)
	}
	strF := Name("Identity")
	if n, ok := d.nameOf(enc["StrF"]); ok {
		strF = n
	}
	stmF := Name("Identity")
	if n, ok := d.nameOf(enc["StmF"]); ok {
		stmF = n
	}
	if strings, err = method(strF); err != nil {
		return
	}
	streams, err = method(stmF)
	return
}

// computeLegacyKey is algorithm 2 of the specification: the file key
// from a password for revisions 2 to 4.
func computeLegacyKey(password, o []byte, p int32, id []byte, r, n int, encryptMetadata bool) []byte {
	padded := append(append([]byte{}, password...), passwordPad...)[:32]
	h := md5.New()
	h.Write(padded)
	h.Write(o)
	h.Write([]byte{byte(p), byte(p >> 8), byte(p >> 16), byte(p >> 24)})
	h.Write(id)
	if r >= 4 && !encryptMetadata {
		h.Write([]byte{0xff, 0xff, 0xff, 0xff})
	}
	key := h.Sum(nil)
	if r >= 3 {
		for i := 0; i < 50; i++ {
			sum := md5.Sum(key[:n])
			key = sum[:]
		}
	}
	return key[:n]
}

// checkLegacyUser is algorithms 4 and 5: does the key open the document
// as the user password's owner would see it.
func checkLegacyUser(key, u, id []byte, r int) bool {
	if r == 2 {
		c, err := rc4.NewCipher(key)
		if err != nil {
			return false
		}
		out := make([]byte, 32)
		c.XORKeyStream(out, passwordPad)
		return bytes.Equal(out, u)
	}
	h := md5.New()
	h.Write(passwordPad)
	h.Write(id)
	x := h.Sum(nil)
	for i := 0; i < 20; i++ {
		k := make([]byte, len(key))
		for j := range key {
			k[j] = key[j] ^ byte(i)
		}
		c, err := rc4.NewCipher(k)
		if err != nil {
			return false
		}
		c.XORKeyStream(x, x)
	}
	return bytes.Equal(x, u[:16])
}

// hash2B is algorithm 2.B of ISO 32000-2 for revision 6.
func hash2B(password, salt, udata []byte) []byte {
	k0 := sha256.Sum256(append(append(append([]byte{}, password...), salt...), udata...))
	k := k0[:]
	for i := 0; ; i++ {
		k1 := make([]byte, 0, 64*(len(password)+len(k)+len(udata)))
		for j := 0; j < 64; j++ {
			k1 = append(k1, password...)
			k1 = append(k1, k...)
			k1 = append(k1, udata...)
		}
		block, err := aes.NewCipher(k[:16])
		if err != nil {
			return k
		}
		e := make([]byte, len(k1))
		cipher.NewCBCEncrypter(block, k[16:32]).CryptBlocks(e, k1)
		sum := 0
		for _, b := range e[:16] {
			sum += int(b)
		}
		switch sum % 3 {
		case 0:
			s := sha256.Sum256(e)
			k = s[:]
		case 1:
			s := sha512.Sum384(e)
			k = s[:]
		case 2:
			s := sha512.Sum512(e)
			k = s[:]
		}
		if i >= 63 && int(e[len(e)-1]) <= i-32 {
			break
		}
	}
	return k[:32]
}

// objectKey derives the per-object key for revisions 2 to 4.
func (h *cryptHandler) objectKey(num, gen int, aesMethod bool) []byte {
	m := md5.New()
	m.Write(h.key)
	m.Write([]byte{byte(num), byte(num >> 8), byte(num >> 16), byte(gen), byte(gen >> 8)})
	if aesMethod {
		m.Write([]byte{0x73, 0x41, 0x6C, 0x54})
	}
	key := m.Sum(nil)
	n := len(h.key) + 5
	if n > 16 {
		n = 16
	}
	return key[:n]
}

func (h *cryptHandler) decrypt(method cryptMethod, data []byte, num, gen int) ([]byte, error) {
	switch method {
	case cryptNone:
		return data, nil
	case cryptRC4:
		c, err := rc4.NewCipher(h.objectKey(num, gen, false))
		if err != nil {
			return nil, err
		}
		out := make([]byte, len(data))
		c.XORKeyStream(out, data)
		return out, nil
	case cryptAESV2, cryptAESV3:
		key := h.key
		if method == cryptAESV2 {
			key = h.objectKey(num, gen, true)
		}
		block, err := aes.NewCipher(key)
		if err != nil {
			return nil, err
		}
		if len(data) < 16 {
			return nil, malformed("AES data shorter than an IV")
		}
		iv, body := data[:16], data[16:]
		body = body[:len(body)-len(body)%16]
		out := make([]byte, len(body))
		cipher.NewCBCDecrypter(block, iv).CryptBlocks(out, body)
		// PKCS#5 padding; a wrong pad is data as it is.
		if n := len(out); n > 0 {
			pad := int(out[n-1])
			if pad >= 1 && pad <= 16 && pad <= n {
				out = out[:n-pad]
			}
		}
		return out, nil
	}
	return nil, errors.New("unknown crypt method")
}

// decryptStream decrypts a stream's raw bytes, unless the stream is one
// the handler leaves alone: an /Identity crypt filter of its own, or
// metadata when metadata is not encrypted.
func (h *cryptHandler) decryptStream(s *stream, data []byte) ([]byte, error) {
	if s.dict["Type"] == Name("Metadata") && !h.encryptMetadata {
		return data, nil
	}
	if f, ok := s.dict["Filter"].(Name); ok && f == "Crypt" {
		return data, nil
	}
	if fs, ok := s.dict["Filter"].(Array); ok {
		for _, f := range fs {
			if f == Name("Crypt") {
				return data, nil
			}
		}
	}
	return h.decrypt(h.streams, data, s.num, s.gen)
}

// decryptObject decrypts every string inside an object read directly
// from the file. Objects from object streams are never passed here: the
// stream was decrypted whole.
func (h *cryptHandler) decryptObject(v object, num, gen int) object {
	switch x := v.(type) {
	case String:
		out, err := h.decrypt(h.strings, []byte(x), num, gen)
		if err != nil {
			return x
		}
		return String(out)
	case Array:
		for i := range x {
			x[i] = h.decryptObject(x[i], num, gen)
		}
		return x
	case Dict:
		for k := range x {
			x[k] = h.decryptObject(x[k], num, gen)
		}
		return x
	case *stream:
		x.dict = h.decryptObject(x.dict, num, gen).(Dict)
		return x
	}
	return v
}
