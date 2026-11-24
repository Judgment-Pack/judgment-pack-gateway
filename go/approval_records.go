package main

// Approval records resolved against a directory the operator fills
// (docs/adr/0063-act-resolves-cited-approval-records-against-an-operator-filled-directory.md).
// From engine configuration version 52 a configuration may name
// approvalRecords: the gateway's, and a scoped write platform's own. Where
// the directory of the action's scope is named, every citation of
// action.approvals is resolved before anything is sent: the record is the
// file <dir>/<kind>/<id>, and its digest is the SHA-256 of the file's
// bytes. Nothing is synchronized or fetched, and the directory is never
// walked: resolution is a look at three names and a hash of one file. A
// citation that does not resolve refuses the action with one fixed
// sentence, and an action whose citations all resolve says so under the
// signature (action.approvalsResolved). Where no directory is named, a
// citation is the requester's claim, exactly as before.

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"unicode/utf8"
)

// approvalRecordsVersion is the engine configuration version from which a
// configuration may name approvalRecords (ADR-0063). An earlier version
// refuses the member by name, and a configuration without it reads every
// citation as its requester's claim, as before.
const approvalRecordsVersion = "52"

// maxApprovalRecordBytes bounds the bytes read of one approval record: at
// most one more than this is read, and a record longer than this does not
// resolve, so no file is read whole to find it is too long.
const maxApprovalRecordBytes = 1 << 20

// approvalUnresolved is the one refusal of a citation that does not
// resolve: missing, not a regular file, a link at any level, longer than
// the bound, replaced while it was read, or of another digest. It names
// neither the directory, nor a path, nor which of these it was, nor which
// citation, so the answer is the same whatever another scope holds.
const approvalUnresolved = "a cited approval record does not resolve: every citation names a record this gateway holds, by its kind, its id and the digest of its bytes, before anything is sent"

// approvalSegmentRule is what a citation's kind and id each must be for the
// record to be named by them.
const approvalSegmentRule = `each one path segment: not "." or "..", no "/" or "\", no control character, and only code points below U+0300, which NFC leaves as they are`

// approvalRecordSegment reports whether s may name one level under the
// approval-record directory: one path segment, never one that names the
// level itself or the one above, no separator of any platform, no NUL or
// other control character, and every code point below U+0300. No code point
// below U+0300 decomposes, combines or is reordered under NFC, so such a
// segment is in NFC, and no other spelling of it names the same record
// where a filesystem normalizes names. A segment with a code point at or
// above U+0300 is refused whether or not it is in NFC: telling the two
// apart needs the Unicode normalization tables, which this module does not
// carry.
func approvalRecordSegment(s string) bool {
	if s == "" || s == "." || s == ".." || !utf8.ValidString(s) {
		return false
	}
	for _, r := range s {
		if r == '/' || r == '\\' || r < 0x20 || r == 0x7f || (r >= 0x80 && r < 0xa0) || r >= 0x300 {
			return false
		}
	}
	return true
}

// approvalRecordStatted runs between the look at a record and its opening;
// a test replaces the record there.
var approvalRecordStatted = func(string) {}

// approvalRecordsFor is the directory an action's citations resolve in
// (ADR-0063, decision 5): a write fixed to a scope identifier resolves in
// its platform's directory and nowhere else, every other write in the
// gateway's. "" where none is named: the citations are then claims.
func (g *gatewayService) approvalRecordsFor(spec sourceSpec) string {
	if spec.scope != "" {
		return spec.approvalRecords
	}
	return g.approvalRecords
}

// resolveApprovals resolves every citation of approvals, the request's
// action.approvals member, in dir, or refuses at the approvals step. Each
// citation's kind and id are held to approvalRecordSegment first, by the
// request alone; then each record is resolved, and one that does not
// resolve is answered with approvalUnresolved.
func resolveApprovals(dir string, approvals value) error {
	list := approvalList(approvals)
	for i, c := range list {
		if !approvalRecordSegment(c.kind) || !approvalRecordSegment(c.id) {
			return actRefusal{"approvals", fmt.Sprintf("approvals[%d] cannot name an approval record: its kind and its id are %s", i, approvalSegmentRule)}
		}
	}
	r, err := openApprovalRoot(dir)
	if err != nil {
		return actRefusal{"approvals", approvalUnresolved}
	}
	defer r.close()
	for _, c := range list {
		if !r.resolves(c) {
			return actRefusal{"approvals", approvalUnresolved}
		}
	}
	return nil
}

// approvalList is the citations of the member requestApprovals answered.
func approvalList(v value) []approvalCitation {
	arr, _ := v.(vArray)
	out := make([]approvalCitation, 0, len(arr))
	for _, entry := range arr {
		obj, _ := entry.(*vObject)
		if obj == nil {
			continue
		}
		kind, _ := memberString(obj, "kind")
		id, _ := memberString(obj, "id")
		digest, _ := memberString(obj, "digest")
		out = append(out, approvalCitation{kind: kind, id: id, digest: digest})
	}
	return out
}

// approvalRoot is one request's view of an approval-record directory: the
// directory opened as an os.Root, so that nothing it resolves leads outside
// it, even where a level is swapped for a link after it was looked at, and
// the listings it read, each read once for the request whatever the number
// of its citations.
type approvalRoot struct {
	dir      string
	root     *os.Root
	listings map[string]map[string]bool
}

// openApprovalRoot opens dir as the request's approval root. dir must be a
// directory and not a link, and the root opened must be the directory
// looked at.
func openApprovalRoot(dir string) (*approvalRoot, error) {
	seen, err := os.Lstat(dir)
	if err != nil || !seen.IsDir() {
		return nil, errors.New("the approval-record directory is not a directory")
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		return nil, err
	}
	opened, err := root.Stat(".")
	if err != nil || !os.SameFile(seen, opened) {
		root.Close()
		return nil, errors.New("the approval-record directory was replaced")
	}
	return &approvalRoot{dir: dir, root: root, listings: map[string]map[string]bool{}}, nil
}

func (r *approvalRoot) close() { r.root.Close() }

// resolves reports whether <kind>/<id> under the root is a regular file
// whose bytes, at most maxApprovalRecordBytes of them, hash to the
// citation's digest. No link is followed at any level: the kind's
// directory and the record are each looked at without following one, the
// record is opened through the root without following one
// (approvalOpenFlags), which refuses any path leading outside the root,
// and the file opened must be the file looked at, so a record replaced
// between the look and the read does not resolve. The kind's directory and
// the record must each be listed under the name cited, byte for byte, so a
// file system that folds case does not resolve a citation of ABC by a
// record stored as abc.
func (r *approvalRoot) resolves(c approvalCitation) bool {
	info, err := r.root.Lstat(c.kind)
	if err != nil || !info.IsDir() || !r.listed(".", c.kind) {
		return false
	}
	name := c.kind + "/" + c.id
	seen, err := r.root.Lstat(name)
	if err != nil || !seen.Mode().IsRegular() || !r.listed(c.kind, c.id) {
		return false
	}
	approvalRecordStatted(filepath.Join(r.dir, c.kind, c.id))
	f, err := r.root.OpenFile(name, approvalOpenFlags, 0)
	if err != nil {
		return false
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil || !opened.Mode().IsRegular() || !os.SameFile(seen, opened) {
		return false
	}
	data, err := io.ReadAll(io.LimitReader(f, maxApprovalRecordBytes+1))
	if err != nil || len(data) > maxApprovalRecordBytes {
		return false
	}
	sum := sha256.Sum256(data)
	return c.digest == "sha256:"+hex.EncodeToString(sum[:])
}

// listed reports whether the root's directory at level lists an entry
// named exactly name, byte for byte. A look by name may succeed by another
// name where the file system folds case or normalizes names; the listing
// gives the names as stored. Each level is listed once for the request.
func (r *approvalRoot) listed(level, name string) bool {
	names, read := r.listings[level]
	if !read {
		names = approvalListing(r.root, level)
		r.listings[level] = names
	}
	return names[name]
}

// approvalListing is the names the root's directory at level lists, or
// none where it does not open as a directory.
func approvalListing(root *os.Root, level string) map[string]bool {
	names := map[string]bool{}
	d, err := root.Open(level)
	if err != nil {
		return names
	}
	defer d.Close()
	for {
		piece, err := d.Readdirnames(256)
		for _, n := range piece {
			names[n] = true
		}
		if err != nil {
			return names
		}
	}
}

// parsePlatformApprovalRecords reads a platform's approvalRecords
// (ADR-0063): from approvalRecordsVersion, the approval-record directory of
// a write fixed to a scope identifier, placed as its decisionRecords is.
// Where the directory lies is held by approvalRecordsApart once every
// platform is read.
func parsePlatformApprovalRecords(p *vObject, name, version string, write bool, scope string) (string, error) {
	v, present := p.get("approvalRecords")
	if !present {
		return "", nil
	}
	if !versionAtLeast(version, approvalRecordsVersion) {
		return "", fmt.Errorf("engine configuration: platform %s: approvalRecords is a version-%s member; engineVersion %s has no approvalRecords", name, approvalRecordsVersion, version)
	}
	if !write || scope == "" {
		return "", fmt.Errorf("engine configuration: platform %s: approvalRecords is the approval-record directory of a write fixed to a scope identifier, and the platform is not one; an unscoped write resolves its citations in the gateway's approvalRecords", name)
	}
	dir, ok := stringOf(v)
	if !ok || !filepath.IsAbs(dir) {
		return "", fmt.Errorf("engine configuration: platform %s: approvalRecords must be an absolute path", name)
	}
	if err := requirePlainSpelling(dir, false); err != nil {
		return "", fmt.Errorf("engine configuration: platform %s: approvalRecords: %w", name, err)
	}
	return dir, nil
}

// parseApprovalRecords reads the configuration's approvalRecords, the
// gateway's approval-record directory, "" where it names none.
func parseApprovalRecords(obj *vObject, version string) (string, error) {
	if _, present := obj.get("approvalRecords"); !present {
		return "", nil
	}
	if !versionAtLeast(version, approvalRecordsVersion) {
		return "", fmt.Errorf("engine configuration: approvalRecords is a version-%s member; engineVersion %s has no approvalRecords", approvalRecordsVersion, version)
	}
	dir, err := requireAbsolutePath(obj, "approvalRecords")
	if err != nil {
		return "", fmt.Errorf("engine configuration: %v", err)
	}
	if err := requirePlainSpelling(dir, false); err != nil {
		return "", fmt.Errorf("engine configuration: approvalRecords: %w", err)
	}
	return dir, nil
}

// approvalRecordsApart holds the approval-record directories as
// decisionRecordsApart holds the decision-record ones (ADR-0063, decision
// 5): a scoped write's is never the gateway's, never another scope's, and
// never beneath or above either; platforms of one scope identifier may
// share one. Where the gateway names one, every write fixed to a scope
// identifier names its own, so that no scope's citations stay unresolved
// while the gateway's are resolved.
func approvalRecordsApart(gateway string, platforms []platformConfig, nested func(a, b string) bool) error {
	for i, p := range platforms {
		if p.approvalRecords == "" {
			if gateway != "" && p.write && p.scope != "" {
				return fmt.Errorf("engine configuration: platform %s: the gateway names approvalRecords, and a write fixed to a scope identifier then needs its own, a directory apart from the gateway's and from every other scope's", p.name)
			}
			continue
		}
		if gateway != "" && nested(p.approvalRecords, gateway) {
			return fmt.Errorf("engine configuration: platform %s: approvalRecords is the gateway's approvalRecords, or beneath or above it; a write fixed to a scope identifier resolves its citations in a directory of its own", p.name)
		}
		for _, q := range platforms[i+1:] {
			if q.approvalRecords != "" && q.scope != p.scope && nested(p.approvalRecords, q.approvalRecords) {
				return fmt.Errorf("engine configuration: platforms %s and %s are fixed to different scope identifiers, and one's approvalRecords is the other's, or beneath or above it", p.name, q.name)
			}
		}
	}
	return nil
}

// holdApprovalRecords is the start's check of an approval-record directory:
// its place as a decision-record directory's is judged, and then its
// ownership (holdDecisionRecords). The gateway never makes or writes it, so
// it is there at start, a directory and not a link, since no link is
// followed when a record is resolved.
func holdApprovalRecords(dir string, host engineHost) error {
	info, err := os.Lstat(dir)
	switch {
	case err != nil:
		return fmt.Errorf("%s: %v; the operator makes and fills it before the gateway starts", dir, err)
	case info.Mode()&os.ModeSymlink != 0:
		return fmt.Errorf("%s is a symbolic link, which resolution does not follow; name the directory where it is", dir)
	case !info.IsDir():
		return fmt.Errorf("%s is not a directory", dir)
	}
	return holdDecisionRecords(dir, host)
}
