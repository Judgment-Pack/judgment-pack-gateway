package main

// SPEC.md §9 leads this implementation. Statements are artifacts, not receipt
// chain entries, and have their own signing domain.
import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"time"
)

const descriptorStatementContext = "judgment-pack-gateway/descriptor-statement/1:"
const maxDescriptorStatementBytes = 16 << 10

func descriptorDigestBytes(data []byte) string {
	sum := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(sum[:])
}

type descriptorProvenance struct{ snapshot, statement, binding string }

// The receipt format is portable; do not use host filepath rules to decide a
// binding name's lexical form (a colon, for example, is a volume on Windows).
func isDescriptorBindingRef(ref string) bool {
	name, pin, ok := strings.Cut(ref, "@")
	return ok && name != "" && name != "." && name != ".." && !strings.ContainsAny(name, "/\\@") && isDigest(pin)
}

func (p descriptorProvenance) value() *vObject {
	o := newObject()
	o.set("snapshot", vString(p.snapshot))
	o.set("statement", vString(p.statement))
	o.set("binding", vString(p.binding))
	return o
}

func descriptorProvenanceFrom(v value) (*descriptorProvenance, error) {
	o, ok := v.(*vObject)
	if !ok || exactlyMembers(o, map[string]bool{"snapshot": true, "statement": true, "binding": true}, "descriptorProvenance") != nil {
		return nil, errors.New("descriptorProvenance must contain exactly snapshot, statement and binding")
	}
	p := &descriptorProvenance{}
	p.snapshot, _ = memberString(o, "snapshot")
	p.statement, _ = memberString(o, "statement")
	p.binding, _ = memberString(o, "binding")
	if !isDigest(p.snapshot) || !isDigest(p.statement) || !isDescriptorBindingRef(p.binding) {
		return nil, errors.New("descriptorProvenance has an invalid reference")
	}
	return p, nil
}

// retainDescriptorCapture uses the same durable blob contract as results. No
// statement is minted from a bare adapter envelope during acquisition.
func (s *store) retainDescriptorCapture(data []byte, operation string) (descriptorProvenance, error) {
	snap, err := parseSnapshot(data)
	if err != nil {
		return descriptorProvenance{}, err
	}
	if operation != "live" && operation != "write" {
		return descriptorProvenance{}, errors.New("invalid descriptor operation")
	}
	if snap.operation != "" && snap.operation != operation {
		return descriptorProvenance{}, errors.New("descriptor operation mismatch")
	}
	p := descriptorProvenance{binding: snap.binding}
	p.snapshot, err = s.retain(data)
	if err != nil {
		return p, err
	}
	o := newObject()
	for k, v := range map[string]string{"statementVersion": "1", "authority": s.authority, "keyId": s.keyID, "source": snap.platform + "/" + operation, "binding": snap.binding, "snapshot": p.snapshot, "endpoint": snap.endpoint, "capturedAt": snap.capturedAt} {
		o.set(k, vString(v))
	}
	sig := ed25519.Sign(s.private, append([]byte(descriptorStatementContext), canon(o)...))
	o.set("signature", vString(hex.EncodeToString(sig)))
	raw := canon(o)
	if len(raw) > maxDescriptorStatementBytes {
		return p, errors.New("descriptor statement exceeds its bound")
	}
	p.statement, err = s.retain(raw)
	return p, err
}

func readDescriptorArtifacts(root string, p descriptorProvenance) ([]byte, []byte, string) {
	if _, err := descriptorProvenanceFrom(p.value()); err != nil {
		return nil, nil, "descriptor-provenance-mismatch"
	}
	snapshot, e1 := readBounded(filepath.Join(root, "artifacts", strings.TrimPrefix(p.snapshot, "sha256:")), maxSnapshotBytes)
	statement, e2 := readBounded(filepath.Join(root, "artifacts", strings.TrimPrefix(p.statement, "sha256:")), maxDescriptorStatementBytes)
	if e1 != nil || e2 != nil {
		return nil, nil, "descriptor-provenance-missing"
	}
	return snapshot, statement, ""
}

// remote is whether the acquisition reached a remote server (transport
// "http"): its statement must then name that same, nonempty endpoint, and an
// empty one -- a local capture -- does not cover it (SPEC.md §9).
func checkDescriptorProvenance(root string, p descriptorProvenance, authority, source, endpoint string, remote bool, keys []reachedKey) string {
	snapshot, statement, status := readDescriptorArtifacts(root, p)
	if status != "" {
		return status
	}
	fail := "descriptor-provenance-mismatch"
	if descriptorDigestBytes(snapshot) != p.snapshot || descriptorDigestBytes(statement) != p.statement {
		return fail
	}
	v, err := parseJSON(statement)
	if err != nil || !bytes.Equal(canon(v), statement) {
		return fail
	}
	o, ok := v.(*vObject)
	if !ok || exactlyMembers(o, map[string]bool{"statementVersion": true, "authority": true, "keyId": true, "source": true, "binding": true, "snapshot": true, "endpoint": true, "capturedAt": true, "signature": true}, "descriptor statement") != nil {
		return fail
	}
	fields := map[string]string{}
	for _, name := range o.names {
		s, ok := memberString(o, name)
		if !ok {
			return fail
		}
		fields[name] = s
	}
	if fields["statementVersion"] != "1" || fields["authority"] != authority || fields["source"] != source || fields["binding"] != p.binding || fields["snapshot"] != p.snapshot || !isLowerHexOfLen(fields["keyId"], 32) || !isSignature3(fields["signature"]) || !capturedAtForm.MatchString(fields["capturedAt"]) {
		return fail
	}
	if _, err := time.Parse(time.RFC3339, fields["capturedAt"]); err != nil {
		return fail
	}
	if ep := fields["endpoint"]; (ep != "" || remote) && (!isRemoteEndpoint(ep) || ep != endpoint) {
		return fail
	}
	core := newObject()
	for _, name := range o.names {
		if name != "signature" {
			value, _ := o.get(name)
			core.set(name, value)
		}
	}
	sig, _ := hex.DecodeString(fields["signature"])
	for _, key := range keys {
		if key.keyID == fields["keyId"] && ed25519.Verify(key.key, append([]byte(descriptorStatementContext), canon(core)...), sig) {
			return "ok"
		}
	}
	return fail
}

func retainConnectedCapture(cfg engineConfig, data []byte, operation string) (descriptorProvenance, error) {
	seed, err := loadSeed(cfg.seed)
	if err != nil {
		return descriptorProvenance{}, err
	}
	s, err := newStore(cfg.store, seed, cfg.authority)
	if err != nil {
		return descriptorProvenance{}, err
	}
	return s.retainDescriptorCapture(data, operation)
}

func platformProvenance(p platformConfig, b binding, operation string) *descriptorProvenance {
	statement := p.descriptorStatements[operation]
	if statement == "" {
		return nil
	}
	snapshot := p.operationDescriptors[operation]
	if !b.hasOwnerDeclarations() {
		snapshot = p.descriptors
	}
	return &descriptorProvenance{snapshot: snapshot, statement: statement, binding: p.binding}
}

func descriptorStatementPinsMatch(p platformConfig, b binding) error {
	if p.descriptorStatements == nil {
		return nil
	} // explicit recapture upgrades historical registrations
	expected := map[string]string{}
	if b.hasOwnerDeclarations() {
		expected = p.operationDescriptors
	} else if p.descriptors != "" {
		if b.live != nil {
			expected["live"] = p.descriptors
		} else if b.write != nil && p.write {
			expected["write"] = p.descriptors
		}
	}
	if len(expected) != len(p.descriptorStatements) {
		return fmt.Errorf("platform %s: descriptorStatements must cover exactly the captured operations", p.name)
	}
	for op := range expected {
		if !isDigest(p.descriptorStatements[op]) {
			return fmt.Errorf("platform %s: missing descriptor statement for %s", p.name, op)
		}
	}
	return nil
}

// Add statement pins without changing any other platform's historical pins.
func renderDescriptorStatements(data []byte, platform string, pins map[string]string) ([]byte, error) {
	v, err := parseJSON(data)
	if err != nil {
		return nil, err
	}
	o := v.(*vObject)
	if version, _ := memberString(o, "engineVersion"); !versionAtLeast(version, "12") {
		o.set("engineVersion", vString("12"))
	}
	ps, _ := o.get("platforms")
	pv, _ := ps.(*vObject).get(platform)
	values := newObject()
	for op, pin := range pins {
		values.set(op, vString(pin))
	}
	pv.(*vObject).set("descriptorStatements", values)
	var text strings.Builder
	formatValue(&text, o, "")
	text.WriteByte('\n')
	if text.Len() > maxEngineConfigBytes {
		return nil, errors.New("configuration with descriptor statements exceeds bound")
	}
	return []byte(text.String()), nil
}
