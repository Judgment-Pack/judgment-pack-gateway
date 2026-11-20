package main

// Session labels (ADR-0051, #550). From labelsVersion the session a caller
// names to /acquire, /seal and /act is a label in its scope's namespace --
// the scope identifier of the session, or none -- mapped to a session id the
// gateway mints on the label's first use there and keeps in the store. The
// receipt, the seal, the registry and the verifiers keep the session id as
// before: what a caller of one scope is answered, and what is read to answer
// it, depends on that scope's namespace alone, never on whether another
// scope uses the label.
//
// The filesystem kind keeps one file per label, labels/<hex>.json, where
// <hex> is SHA-256 over sessionLabelDomain and the canonical {label, scope},
// holding the canonical {label, scope, sessionId}. It is written exclusively,
// synced, and its directory synced, before the session's first receipt: a
// crash after it leaves a mapping with no receipts, whose id the label's next
// use takes up. The verifiers pass labels/ over (SPEC.md §3a). The
// PostgreSQL kind keeps a row of gateway.session_labels for each label
// (session_labels_pg.go).

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// labelsVersion is the engine configuration version from which a session is
// named by a label in its scope (ADR-0051).
const labelsVersion = "39"

// sessionLabelDomain prefixes what a label's file name digests.
const sessionLabelDomain = "judgment-pack-gateway/session-label/1:"

// labelsDir is the store member that keeps the labels of the filesystem kind.
const labelsDir = "labels"

// labelFileLimit bounds a label's file as it is read: the three members at
// their longest, with room.
const labelFileLimit = 4096

// mintedSessionPattern is the form of a session id the gateway mints: 128
// random bits as 32 lowercase hexadecimal characters, of the session id form
// (SPEC.md §3a).
var mintedSessionPattern = regexp.MustCompile(`^[0-9a-f]{32}$`)

const (
	refusalLabelUnread   = "session %s: its label could not be read in the store, so which session it names is not known; it is refused rather than taken for unused"
	refusalLabelUnstored = "session %s: its label could not be recorded in the store, and nothing was run"
)

// labelKeeper keeps a store's labels. scope is a scope identifier, "" for
// none.
type labelKeeper interface {
	// labelSession is the session id label names in scope's namespace, ""
	// where it names none there. Nothing of another namespace is read.
	labelSession(scope, label string) (string, error)
	// recordLabel records id for label in scope's namespace, unless an id
	// is recorded for it already, and answers the id recorded.
	recordLabel(scope, label, id string) (string, error)
	// labelEntries is every label the store keeps, of every namespace.
	labelEntries() ([]labelEntry, error)
	// labelsOf is the labels of scope's namespace alone, in label order.
	labelsOf(scope string) ([]labelEntry, error)
}

// labelEntry is one label as the store keeps it; file is its name in
// labels/ on the filesystem kind.
type labelEntry struct {
	file, label, scope, sessionID string
}

// mintSessionID is a new session id of the minted form.
func mintSessionID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}

// labelScopeValue is a namespace as a label's file names it: the scope
// identifier, or null for none.
func labelScopeValue(scope string) value {
	if scope == "" {
		return vNull{}
	}
	return vString(scope)
}

// labelFileName is the name of label's file in scope's namespace.
func labelFileName(scope, label string) string {
	key := newObject()
	key.set("label", vString(label))
	key.set("scope", labelScopeValue(scope))
	sum := sha256.Sum256(append([]byte(sessionLabelDomain), canon(key)...))
	return hex.EncodeToString(sum[:]) + ".json"
}

// labelFileBytes is what label's file holds: the canonical {label, scope,
// sessionId}, newline-terminated.
func labelFileBytes(scope, label, id string) []byte {
	entry := newObject()
	entry.set("label", vString(label))
	entry.set("scope", labelScopeValue(scope))
	entry.set("sessionId", vString(id))
	return append(canon(entry), '\n')
}

// readLabelFile is the entry a label's file holds, held to its form: its
// bytes the canonical entry of a label of the session id form, a scope
// identifier or null, and a minted session id, and its name the one that
// label and scope give. Anything else is an error: the gateway alone writes
// these files.
func readLabelFile(name string, data []byte) (labelEntry, error) {
	bad := fmt.Errorf("label file %s does not hold a label of this gateway's form", name)
	v, err := parseJSON(data)
	if err != nil {
		return labelEntry{}, bad
	}
	obj, ok := v.(*vObject)
	if !ok || len(obj.names) != 3 {
		return labelEntry{}, bad
	}
	label, labelOK := memberString(obj, "label")
	id, idOK := memberString(obj, "sessionId")
	scopeValue, present := obj.get("scope")
	if !labelOK || !idOK || !present || requireSession(label) != nil || !mintedSessionPattern.MatchString(id) {
		return labelEntry{}, bad
	}
	scope := ""
	switch s := scopeValue.(type) {
	case vNull:
	case vString:
		if s == "" {
			return labelEntry{}, bad
		}
		scope = string(s)
	default:
		return labelEntry{}, bad
	}
	if string(data) != string(labelFileBytes(scope, label, id)) || name != labelFileName(scope, label) {
		return labelEntry{}, bad
	}
	return labelEntry{file: name, label: label, scope: scope, sessionID: id}, nil
}

// fsLabels keeps labels in a store directory of the filesystem kind.
// looked, where it is set, is told each namespace and label a lookup or a
// record reads: a test's way of seeing that nothing of another scope's
// namespace is read.
type fsLabels struct {
	root   string
	looked func(scope, label string)
}

func (l fsLabels) dir() string { return filepath.Join(l.root, labelsDir) }

// held is whether labels/ is there, as a directory and not a link; an
// error where it is something else or cannot be looked at.
func (l fsLabels) held() (bool, error) {
	info, err := os.Lstat(l.dir())
	switch {
	case err != nil && absent(err):
		return false, nil
	case err != nil:
		return false, err
	case !info.IsDir():
		return false, fmt.Errorf("%s is in the store as something other than a directory", labelsDir)
	}
	return true, nil
}

func (l fsLabels) labelSession(scope, label string) (string, error) {
	if l.looked != nil {
		l.looked(scope, label)
	}
	if held, err := l.held(); err != nil || !held {
		return "", err
	}
	name := labelFileName(scope, label)
	path := filepath.Join(l.dir(), name)
	if _, err := os.Lstat(path); err != nil {
		if absent(err) {
			return "", nil
		}
		return "", err
	}
	data, err := readBounded(path, labelFileLimit)
	if err != nil {
		return "", err
	}
	entry, err := readLabelFile(name, data)
	if err != nil {
		return "", err
	}
	if entry.label != label || entry.scope != scope {
		return "", fmt.Errorf("label file %s names another label", name)
	}
	return entry.sessionID, nil
}

func (l fsLabels) recordLabel(scope, label, id string) (string, error) {
	held, err := l.held()
	if err != nil {
		return "", err
	}
	if !held {
		if err := os.Mkdir(l.dir(), 0o700); err != nil && !errors.Is(err, os.ErrExist) {
			return "", err
		}
		if held, err = l.held(); err != nil || !held {
			return "", fmt.Errorf("%s could not be made in the store: %v", labelsDir, err)
		}
		syncDir(l.root)
	}
	// exclusively: a name already there is another request's label, whose
	// id is the one the label names
	err = fsWriteFile(filepath.Join(l.dir(), labelFileName(scope, label)), labelFileBytes(scope, label, id), true)
	if faultOf(err) == faultTaken {
		recorded, err := l.labelSession(scope, label)
		if err == nil && recorded == "" {
			err = errors.New("a label taken is not there")
		}
		return recorded, err
	}
	if err != nil {
		return "", err
	}
	return id, nil
}

func (l fsLabels) labelEntries() ([]labelEntry, error) {
	if held, err := l.held(); err != nil || !held {
		return nil, err
	}
	dir, err := os.Open(l.dir())
	if err != nil {
		return nil, err
	}
	defer dir.Close()
	var entries []labelEntry
	for {
		batch, err := dir.ReadDir(256)
		for _, e := range batch {
			name := e.Name()
			if strings.HasSuffix(name, ".tmp") {
				continue // a staging file a write cut off left behind
			}
			if !e.Type().IsRegular() {
				return nil, fmt.Errorf("label %s is not a regular file", name)
			}
			data, err := readBounded(filepath.Join(l.dir(), name), labelFileLimit)
			if err != nil {
				return nil, err
			}
			entry, err := readLabelFile(name, data)
			if err != nil {
				return nil, err
			}
			entries = append(entries, entry)
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].label < entries[j].label })
	return entries, nil
}

func (l fsLabels) labelsOf(scope string) ([]labelEntry, error) {
	entries, err := l.labelEntries()
	if err != nil {
		return nil, err
	}
	var of []labelEntry
	for _, e := range entries {
		if e.scope == scope {
			of = append(of, e)
		}
	}
	return of, nil
}

// removeLabelFiles removes the named files of labels/ and syncs it: the
// labels of sessions a removal's records, already durable, name.
func removeLabelFiles(storeRoot string, files []string) error {
	for _, name := range files {
		if err := os.Remove(filepath.Join(storeRoot, labelsDir, name)); err != nil && !absent(err) {
			return err
		}
	}
	if len(files) > 0 {
		syncDir(filepath.Join(storeRoot, labelsDir))
	}
	return nil
}

// labelFilesOf is the files of the labels a removal takes with its sessions:
// each whose namespace is scope, where scope is not "", and each that names
// one of sessions.
func labelFilesOf(keeper labelKeeper, scope string, sessions []string) ([]string, error) {
	entries, err := keeper.labelEntries()
	if err != nil {
		return nil, err
	}
	removed := map[string]bool{}
	for _, s := range sessions {
		removed[s] = true
	}
	var files []string
	for _, e := range entries {
		if (scope != "" && e.scope == scope) || removed[e.sessionID] {
			files = append(files, e.file)
		}
	}
	return files, nil
}

// sessionOfLabel is the session id label names in scope's namespace, minted
// and recorded on the label's first use there: a new id is minted again
// where it is a session this process or the store holds already.
func (g *gatewayService) sessionOfLabel(label, scope string) (string, error) {
	id, err := g.labels.labelSession(scope, label)
	if err != nil {
		return "", fmt.Errorf(refusalLabelUnread, label)
	}
	if id != "" {
		return id, nil
	}
	for attempt := 0; attempt < 4; attempt++ {
		fresh, err := mintSessionID()
		if err != nil {
			return "", fmt.Errorf(refusalLabelUnstored, label)
		}
		if g.sessionTaken(fresh) {
			continue
		}
		recorded, err := g.labels.recordLabel(scope, label, fresh)
		if err != nil {
			return "", fmt.Errorf(refusalLabelUnstored, label)
		}
		return recorded, nil
	}
	return "", fmt.Errorf(refusalLabelUnstored, label)
}

// sessionTaken is whether a minted id is a session already: one this
// process holds, or one the store holds anything of, or cannot show.
func (g *gatewayService) sessionTaken(id string) bool {
	g.mu.Lock()
	_, held := g.sessions[id]
	g.mu.Unlock()
	if held {
		return true
	}
	if g.kind != nil {
		_, err := g.store.receipts.listEntries(id)
		return faultOf(err) != faultAbsent
	}
	_, err := os.Lstat(filepath.Join(g.storeRoot, "receipts", id))
	return !(err != nil && absent(err))
}

// sealLabelled is /seal from labelsVersion: the label looked up in the
// namespace of the scope the request names, or of none where it names none,
// and nowhere else. A label not there, and a namespace the caller does not
// reach, are answered no such session, with nothing else read: not the
// registry, and nothing of another scope. A label there seals its session as
// /seal seals one by its id.
func (g *gatewayService) sealLabelled(label string, asked requestedScope, reach scopeReach) (map[string]any, error) {
	if err := requireSession(label); err != nil {
		return nil, badRequest{err}
	}
	noSuch := badRequest{fmt.Errorf("no such session: %s", label)}
	scope := ""
	if asked.named {
		scope = asked.value
	}
	if (asked.named && scope == "") || !reach.holds(scope) {
		return nil, noSuch
	}
	id, err := g.labels.labelSession(scope, label)
	if err != nil {
		return nil, fmt.Errorf(refusalLabelUnread, label)
	}
	if id == "" {
		return nil, noSuch
	}
	out, err := g.sealFor(id, reach)
	var refused badRequest
	if errors.As(err, &refused) && refused.Error() == "no such session: "+id {
		return nil, noSuch
	}
	return out, err
}

// unlabelledOpen is, from labelsVersion, the sessions the store holds open
// that no label names: sessions named before the version, which a label
// never addresses. The start refuses while there is one (labelsAtStart).
func (g *gatewayService) unlabelledOpen() ([]string, error) {
	seals, err := g.engineSeals()
	if err != nil {
		return nil, err
	}
	entries, err := g.labels.labelEntries()
	if err != nil {
		return nil, err
	}
	labelled := map[string]bool{}
	for _, e := range entries {
		labelled[e.sessionID] = true
	}
	var open []string
	if pg, onKind := g.kind.(*pgKind); onKind {
		// every series of every scope that holds a receipt, in one snapshot
		held, err := pg.seriesHoldingEntries()
		if err != nil {
			return nil, err
		}
		for _, s := range held {
			if _, sealed := seals[s]; !sealed && !labelled[s] {
				open = append(open, s)
			}
		}
		return open, nil
	}
	if g.kind != nil {
		return nil, errors.New("the store's kind lists no sessions to ask whether a label names them")
	}
	sessions, err := listSessions(g.storeRoot)
	if err != nil {
		return nil, err
	}
	for _, s := range sessions {
		if _, sealed := seals[s]; sealed || labelled[s] {
			continue
		}
		if g.leftInStoreRefusal(s, "", false) != "" {
			open = append(open, s)
		}
	}
	return open, nil
}

// labelsAtStart refuses a start from labelsVersion while the store holds a
// session open that no label names, naming gateway seal-open --all: such a
// session was named by its caller before the version, and is sealed before
// labels are read, so no session is ever addressed by both a name and a
// label. A store that cannot be read refuses the start too.
func labelsAtStart(service *gatewayService) error {
	if service.labels == nil {
		return nil
	}
	open, err := service.unlabelledOpen()
	if err != nil {
		return fmt.Errorf("engine configuration version %s reads sessions by label (ADR-0051), and whether the store holds a session open from before it could not be read: %v; the gateway does not start", labelsVersion, err)
	}
	if len(open) == 0 {
		return nil
	}
	named := open
	if len(named) > 5 {
		named = named[:5]
	}
	return fmt.Errorf("engine configuration version %s reads the session a request names as a label in its scope (ADR-0051), and the store holds %d session(s) open that no label names, left from before that version (%s); such a session is sealed before the upgrade: stop the gateway, run gateway seal-open --all, and start again; the gateway does not start", labelsVersion, len(open), strings.Join(named, ", "))
}

const sessionsUsage = `usage: gateway sessions --config <engine.json> (--scope <identifier> | --no-scope) [--label <label>]
Prints, for one scope identifier's namespace, or with --no-scope for the
namespace of no scope identifier, a "label sessionId" line for each session
label the store keeps there (ADR-0051), in label order; with --label, that
label's line alone, or exits 1 where the namespace has no such label. Reads
the store with the gateway running or stopped, and writes nothing.
--scope none names the scope identifier "none".`

func cmdSessions(args []string, stdout, stderr io.Writer) int {
	flags := map[string]string{}
	noScope := false
	for rest := args; len(rest) > 0; {
		name := rest[0]
		if name == "--no-scope" && !noScope {
			noScope, rest = true, rest[1:]
			continue
		}
		if (name != "--config" && name != "--scope" && name != "--label") || len(rest) < 2 || flags[name] != "" || rest[1] == "" {
			fmt.Fprintln(stderr, sessionsUsage)
			return 2
		}
		flags[name], rest = rest[1], rest[2:]
	}
	_, labelGiven := flags["--label"]
	if flags["--config"] == "" || (flags["--scope"] == "") == !noScope {
		fmt.Fprintln(stderr, sessionsUsage)
		return 2
	}
	scope := flags["--scope"]
	if !noScope && !isScopeIdentifier(scope) {
		fmt.Fprintln(stderr, "gateway sessions: --scope is a scope identifier: "+scopeForm)
		return 2
	}
	if labelGiven && requireSession(flags["--label"]) != nil {
		fmt.Fprintln(stderr, "gateway sessions: --label has the form of a session id (SPEC.md §3a)")
		return 2
	}
	data, err := readBounded(flags["--config"], maxEngineConfigBytes)
	if err != nil {
		fmt.Fprintln(stderr, "gateway sessions: engine configuration:", err)
		return 1
	}
	cfg, err := parseEngineConfig(data)
	if err != nil {
		fmt.Fprintln(stderr, "gateway sessions:", err)
		return 1
	}
	if !versionAtLeast(cfg.version, labelsVersion) {
		fmt.Fprintf(stderr, "gateway sessions: the configuration is of engineVersion %s, which names sessions by the caller's name; labels are read from engineVersion %s (ADR-0051)\n", cfg.version, labelsVersion)
		return 1
	}
	keeper, closeKeeper, err := labelKeeperFor(cfg)
	if err != nil {
		fmt.Fprintln(stderr, "gateway sessions:", err)
		return 1
	}
	defer closeKeeper()
	if labelGiven {
		id, err := keeper.labelSession(scope, flags["--label"])
		if err != nil {
			fmt.Fprintln(stderr, "gateway sessions: the label could not be read:", err)
			return 1
		}
		if id == "" {
			fmt.Fprintf(stderr, "gateway sessions: no label %s in the namespace\n", flags["--label"])
			return 1
		}
		fmt.Fprintf(stdout, "%s %s\n", flags["--label"], id)
		return 0
	}
	entries, err := keeper.labelsOf(scope)
	if err != nil {
		fmt.Fprintln(stderr, "gateway sessions: the labels could not be read:", err)
		return 1
	}
	for _, e := range entries {
		fmt.Fprintf(stdout, "%s %s\n", e.label, e.sessionID)
	}
	return 0
}

// labelKeeperFor is the labels of the store a configuration names, and what
// closes what it opened: on the PostgreSQL kind, read through the run-time
// login, each namespace through its own scope's view (pgLabelsFor).
func labelKeeperFor(cfg engineConfig) (labelKeeper, func(), error) {
	if cfg.storage != nil {
		return pgLabelsFor(cfg)
	}
	return fsLabels{root: cfg.store}, func() {}, nil
}
