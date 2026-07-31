package main

// The write path: content-addressed artifacts, signed chained receipts, and the
// signed seal registry. SPEC.md §1 is normative for every byte written here.

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"time"
)

const seedBytes = ed25519.SeedSize // 32

// sessionPattern is SPEC.md §3a. A session id names a directory under the store
// and a verifier discovers sessions by ENUMERATING that directory, so an id that
// escaped the receipts root would produce genuinely signed receipts verification
// could never find.
var sessionPattern = regexp.MustCompile(`^[A-Za-z0-9._-]{1,128}$`)

func requireSession(sessionID string) error {
	if !sessionPattern.MatchString(sessionID) || sessionID == "." || sessionID == ".." {
		return fmt.Errorf("session id must match %s", sessionPattern)
	}
	return nil
}

// argumentsKey derives the key for the arguments commitment from the signing
// seed. Arguments are committed to with a keyed digest rather than a plain hash
// so a third party cannot brute-force a small argument space out of a receipt.
// The consequence is deliberate and stated in SPEC.md §1.2: a public verifier
// cannot recompute this value, and does not need to, because the signature
// covers it.
func argumentsKey(seed []byte) []byte {
	sum := sha256.Sum256(append([]byte("judgment-pack-gateway/arguments-key/2:"), seed...))
	return sum[:]
}

type store struct {
	root      string
	seed      []byte
	private   ed25519.PrivateKey
	publicKey ed25519.PublicKey
	keyID     string
	authority string
}

func newStore(root string, seed []byte, authority string) (*store, error) {
	if len(seed) != seedBytes {
		return nil, fmt.Errorf("an Ed25519 signing seed is %d bytes", seedBytes)
	}
	private := ed25519.NewKeyFromSeed(seed)
	public := private.Public().(ed25519.PublicKey)
	for _, dir := range []string{"artifacts", "receipts"} {
		if err := os.MkdirAll(filepath.Join(root, dir), 0o755); err != nil {
			return nil, err
		}
	}
	return &store{
		root: root, seed: seed, private: private, publicKey: public,
		keyID: keyIDFor(public), authority: authority,
	}, nil
}

// write puts bytes at `near`. With exclusive set it refuses to replace an
// existing file, which is what makes the receipt log append-only.
func (s *store) write(near string, data []byte, exclusive bool) error {
	var suffix [6]byte
	if _, err := rand.Read(suffix[:]); err != nil {
		return err
	}
	tmp := fmt.Sprintf("%s.%d.%s.tmp", near, os.Getpid(), hex.EncodeToString(suffix[:]))
	handle, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if _, err := handle.Write(data); err != nil {
		handle.Close()
		os.Remove(tmp)
		return err
	}
	if err := handle.Sync(); err != nil {
		handle.Close()
		os.Remove(tmp)
		return err
	}
	if err := handle.Close(); err != nil {
		os.Remove(tmp)
		return err
	}
	defer os.Remove(tmp)
	if exclusive {
		if err := os.Link(tmp, near); err != nil {
			if errors.Is(err, os.ErrExist) {
				return fmt.Errorf("receipt already exists (append-only): %s", near)
			}
			return err
		}
	} else if err := os.Rename(tmp, near); err != nil {
		return err
	}
	syncDir(filepath.Dir(near))
	return nil
}

func syncDir(path string) {
	handle, err := os.Open(path)
	if err != nil {
		return
	}
	defer handle.Close()
	_ = handle.Sync()
}

// retain stores canonical result bytes under their own digest and returns the
// resultDigest a receipt carries.
func (s *store) retain(canonical []byte) (string, error) {
	sum := sha256.Sum256(canonical)
	hexSum := hex.EncodeToString(sum[:])
	if err := s.write(filepath.Join(s.root, "artifacts", hexSum), canonical, false); err != nil {
		return "", err
	}
	return "sha256:" + hexSum, nil
}

// stamp signs a receipt core and appends it to its session. The caller supplies
// every member except keyId and signature.
func (s *store) stamp(core *vObject) (*vObject, string, error) {
	sessionValue, ok := core.get("sessionId")
	if !ok {
		return nil, "", errors.New("receipt core has no sessionId")
	}
	sessionID, ok := sessionValue.(vString)
	if !ok {
		return nil, "", errors.New("sessionId is not a string")
	}
	if err := requireSession(string(sessionID)); err != nil {
		return nil, "", err
	}
	receiptsRoot := filepath.Join(s.root, "receipts")
	sessionDir := filepath.Join(receiptsRoot, string(sessionID))
	// Defence in depth: never write outside the enumerated root, even if the
	// token rule above is ever loosened.
	resolved, err := filepath.Abs(sessionDir)
	if err != nil {
		return nil, "", err
	}
	rootAbs, err := filepath.Abs(receiptsRoot)
	if err != nil {
		return nil, "", err
	}
	if filepath.Dir(resolved) != rootAbs {
		return nil, "", errors.New("session directory escapes the receipt store")
	}
	if err := os.MkdirAll(sessionDir, 0o755); err != nil {
		return nil, "", err
	}

	indexValue, ok := core.get("callIndex")
	if !ok {
		return nil, "", errors.New("receipt core has no callIndex")
	}
	index, ok := indexValue.(vInt)
	if !ok {
		return nil, "", errors.New("callIndex is not an integer")
	}

	core.set("keyId", vString(s.keyID))
	signature := ed25519.Sign(s.private, append([]byte(receiptContext), canon(core)...))
	signatureHex := hex.EncodeToString(signature)

	stored := newObject()
	for _, name := range core.names {
		v, _ := core.get(name)
		stored.set(name, v)
	}
	stored.set("signature", vString(signatureHex))

	body := append(canon(stored), '\n')
	path := filepath.Join(sessionDir, fmt.Sprintf("%d.json", int64(index)))
	if err := s.write(path, body, true); err != nil {
		return nil, "", err
	}
	return stored, signatureHex, nil
}

// --- the seal registry (write side) ---------------------------------------

type registryWriter struct {
	path  string
	seed  []byte
	priv  ed25519.PrivateKey
	keyID string
}

func newRegistryWriter(path string, seed []byte) (*registryWriter, error) {
	if len(seed) != seedBytes {
		return nil, fmt.Errorf("an Ed25519 signing seed is %d bytes", seedBytes)
	}
	if dir := filepath.Dir(path); dir != "" {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return nil, err
		}
	}
	priv := ed25519.NewKeyFromSeed(seed)
	return &registryWriter{
		path: path, seed: seed, priv: priv,
		keyID: keyIDFor(priv.Public().(ed25519.PublicKey)),
	}, nil
}

// seal appends a signed final count. Append-only: sealing an already sealed
// session is refused, so a count can never be re-sealed to a smaller value.
func (w *registryWriter) seal(sessionID string, finalCount int64, sealedAt string) (*vObject, error) {
	if err := requireSession(sessionID); err != nil {
		return nil, err
	}
	existing, err := os.ReadFile(w.path)
	if err != nil && !os.IsNotExist(err) {
		return nil, err
	}
	for _, line := range splitLines(existing) {
		v, err := parseJSON(line)
		if err != nil {
			continue
		}
		if obj, ok := v.(*vObject); ok {
			if name, ok := memberString(obj, "sessionId"); ok && name == sessionID {
				return nil, fmt.Errorf("session already sealed: %s", sessionID)
			}
		}
	}

	signature := ed25519.Sign(w.priv, sealSigningInput(sessionID, finalCount, sealedAt, w.keyID))
	record := newObject()
	record.set("sessionId", vString(sessionID))
	record.set("finalCount", vInt(finalCount))
	record.set("sealedAt", vString(sealedAt))
	record.set("keyId", vString(w.keyID))
	record.set("signature", vString(hex.EncodeToString(signature)))

	handle, err := os.OpenFile(w.path, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600)
	if err != nil {
		return nil, err
	}
	defer handle.Close()
	if _, err := handle.Write(append(canon(record), '\n')); err != nil {
		return nil, err
	}
	if err := handle.Sync(); err != nil {
		return nil, err
	}
	return record, nil
}

func splitLines(data []byte) [][]byte {
	var out [][]byte
	start := 0
	for i := 0; i <= len(data); i++ {
		if i == len(data) || data[i] == '\n' {
			line := data[start:i]
			if len(trimSpace(line)) > 0 {
				out = append(out, line)
			}
			start = i + 1
		}
	}
	return out
}

func trimSpace(data []byte) []byte {
	start, end := 0, len(data)
	for start < end && (data[start] == ' ' || data[start] == '\t' || data[start] == '\r' || data[start] == '\n') {
		start++
	}
	for end > start && (data[end-1] == ' ' || data[end-1] == '\t' || data[end-1] == '\r' || data[end-1] == '\n') {
		end--
	}
	return data[start:end]
}

func nowStamp() string {
	return time.Now().UTC().Truncate(time.Second).Format("2006-01-02T15:04:05Z")
}
