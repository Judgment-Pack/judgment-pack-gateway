package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"
	"unicode"
	"unicode/utf8"
)

// connectRequest is what the operator asked `connect` to write: a platform
// entry, in the terms the configuration file uses.
type connectRequest struct {
	config      string
	platform    string
	binding     string            // a catalog name; the pin is computed here
	credentials map[string]string // by operation: the path as written; never a value
	user        string
	endpoint    string
	environment []string // KEY=VALUE
	write       bool
	replace     bool
}

// connectOutcome is what connect has to say: the statements the
// configuration was accepted under (a root signer, a host runtime socket),
// what each platform operation answered, and the file written.
type connectOutcome struct {
	statements []string
	answers    []string
	written    string
}

const (
	// checkTimeout is the time an adapter's check is given: an image the
	// runtime does not hold yet is pulled first, which an acquisition's
	// twenty seconds would not cover. The adapter is told the same figure,
	// and this process waits a little longer for it to stop what it ran.
	checkTimeout = 5 * time.Minute
	checkGrace   = 30 * time.Second
	// checkMaxOutput bounds an adapter's report: a report is a few lines.
	checkMaxOutput = 1 << 20
)

const connectUsage = "usage: gateway connect --config <engine.json> <platform> --binding <name> --credentials-file <operation>=<path>... --user <name> [--endpoint HOST] [--environment KEY=VALUE]... [--write] [--replace]"

// cmdConnect writes a platform entry into the engine's configuration:
// after holding the configuration it would produce to every refusal
// `serve` applies -- the paths it makes and the users it switches to
// included -- and after each of the platform's adapters, run once in
// check mode as the platform's user, has reported that the platform
// answered. Nothing is acquired and no receipt is minted; a platform that
// cannot be reached is not silently configured.
func cmdConnect(args []string) int {
	req, msg, ok := parseConnectArgs(args)
	if !ok {
		fmt.Fprintln(os.Stderr, msg)
		return 2
	}
	closeInheritedDescriptors()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	outcome, err := connect(ctx, req, osEngineHost(), runCheck)
	return printOutcome(os.Stdout, os.Stderr, req.platform, outcome, err)
}

// printOutcome writes what a connect produced -- each statement and each
// answer as one line whatever the platform answered (printable), then the
// error or what was written -- and returns the exit status.
func printOutcome(stdout, stderr io.Writer, platform string, out connectOutcome, err error) int {
	for _, statement := range out.statements {
		fmt.Fprintln(stderr, "connect:", printable(statement))
	}
	for _, answer := range out.answers {
		fmt.Fprintln(stdout, printable(answer))
	}
	if err != nil {
		fmt.Fprintln(stderr, "connect:", printable(err.Error()))
		return 1
	}
	fmt.Fprintf(stdout, "%s: written to %s\n", printable(platform), printable(out.written))
	return 0
}

// printable is text for one line of a terminal: every character that is
// not graphic -- a newline, a carriage return, the escape that starts a
// terminal control sequence, an invalid byte -- is written in its escaped
// form, so what a platform or an adapter answered cannot end the line,
// forge another, or move the cursor. A backslash is left as it is: it
// forges nothing, and a Windows path is made of them. Applied after
// redaction, at the point of printing, and nowhere else.
func printable(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		switch {
		case r == utf8.RuneError && size == 1:
			fmt.Fprintf(&b, `\x%02x`, s[i])
		case r == '\n':
			b.WriteString(`\n`)
		case r == '\r':
			b.WriteString(`\r`)
		case r == '\t':
			b.WriteString(`\t`)
		case unicode.IsGraphic(r):
			b.WriteRune(r)
		case r > 0xffff:
			fmt.Fprintf(&b, `\U%08x`, r)
		default:
			fmt.Fprintf(&b, `\u%04x`, r)
		}
		i += size
	}
	return b.String()
}

// parseConnectArgs reads the command line; the platform is the one
// positional argument, wherever it stands among the flags.
func parseConnectArgs(args []string) (connectRequest, string, bool) {
	req := connectRequest{credentials: map[string]string{}}
	fs := flag.NewFlagSet("connect", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fs.StringVar(&req.config, "config", "", "")
	fs.StringVar(&req.binding, "binding", "", "")
	var credentialsErr error
	fs.Func("credentials-file", "", func(s string) error {
		op, path, ok := strings.Cut(s, "=")
		if !ok || op == "" || path == "" {
			credentialsErr = fmt.Errorf("--credentials-file expects <operation>=<path>, not %q", s)
			return nil
		}
		if _, twice := req.credentials[op]; twice {
			credentialsErr = fmt.Errorf("--credentials-file names %s twice", op)
			return nil
		}
		req.credentials[op] = path
		return nil
	})
	fs.StringVar(&req.user, "user", "", "")
	fs.StringVar(&req.endpoint, "endpoint", "", "")
	fs.Func("environment", "", func(s string) error { req.environment = append(req.environment, s); return nil })
	fs.BoolVar(&req.write, "write", false, "")
	fs.BoolVar(&req.replace, "replace", false, "")
	// Go's flag parsing stops at the first word that is not a flag; the
	// platform may stand there, and parsing resumes after it.
	for {
		if err := fs.Parse(args); err != nil {
			return req, connectUsage + "\n" + err.Error(), false
		}
		rest := fs.Args()
		if len(rest) == 0 {
			break
		}
		if req.platform != "" {
			return req, connectUsage + "\n" + fmt.Sprintf("one platform, not %q and %q", req.platform, rest[0]), false
		}
		req.platform, args = rest[0], rest[1:]
	}
	if credentialsErr != nil {
		return req, connectUsage + "\n" + credentialsErr.Error(), false
	}
	if req.platform == "" || req.config == "" || req.binding == "" || len(req.credentials) == 0 || req.user == "" {
		return req, connectUsage, false
	}
	return req, "", true
}

// connect is the command without the process around it. check runs one
// derived source's adapter in check mode and returns its report; the
// caller decides as whom.
func connect(ctx context.Context, req connectRequest, host engineHost, check func(context.Context, sourceSpec) ([]byte, error)) (connectOutcome, error) {
	var out connectOutcome
	if err := validPlatformName(req.platform); err != nil {
		return out, err
	}
	// The file's directory is held open from here to the rename, so what
	// is read, written beside it and put in place is in that directory
	// whatever a path component is swapped for meanwhile; the file must
	// be one this command can put in place, judged before any adapter is
	// run for nothing; and one connect at a time holds the file.
	file, err := openConfigFile(req.config)
	if err != nil {
		return out, err
	}
	defer file.close()
	data, err := file.read()
	if err != nil {
		return out, err
	}
	cfg, err := parseEngineConfig(data)
	if err != nil {
		return out, err
	}
	index := -1
	for i, p := range cfg.platforms {
		if p.name == req.platform {
			index = i
		}
	}
	if index >= 0 && !req.replace {
		return out, fmt.Errorf("platform %s is already configured in %s; --replace replaces its entry", req.platform, req.config)
	}
	if index >= 0 {
		// The entry replaced is not resolved: its pin is what --replace
		// may be repairing. Every other platform is.
		cfg.platforms = append(cfg.platforms[:index:index], cfg.platforms[index+1:]...)
	}
	// Every platform kept is resolved too: a pin the catalog no longer
	// digests to is found here, not at the next start.
	bindings, err := resolveEngineConfig(&cfg, host.account)
	if err != nil {
		return out, err
	}
	ref, b, err := pinBinding(cfg.catalog, req.binding)
	if err != nil {
		return out, err
	}
	entry, err := newPlatformEntry(req, ref, b, host.account)
	if err != nil {
		return out, err
	}
	// The configuration as it would be, held to every refusal serve
	// applies, and to the size serve reads, before anything is asked.
	candidate := cfg
	candidate.platforms = append(append([]platformConfig(nil), cfg.platforms...), entry)
	sort.Slice(candidate.platforms, func(i, j int) bool { return candidate.platforms[i].name < candidate.platforms[j].name })
	bindings[req.platform] = b
	text, err := renderPlatformEntry(data, req, ref)
	if err != nil {
		return out, err
	}
	if len(text) > maxEngineConfigBytes {
		return out, fmt.Errorf("the configuration with %s would exceed %d bytes, which serve does not read", req.platform, maxEngineConfigBytes)
	}
	statements, err := engineRefusals(&candidate, host)
	if err != nil {
		return out, err
	}
	out.statements = statements
	// The seed as serve judges it -- owned by this process, private,
	// regular, a seed -- so a connect does not succeed where the next
	// start would refuse; what is read is discarded.
	if _, err := loadSeed(candidate.seed); err != nil {
		return out, fmt.Errorf("seed: %v", err)
	}
	// The paths serve makes, judged as serve would before making them.
	if err := preflightPaths(candidate.store, candidate.registry, candidate.decisionRecords); err != nil {
		return out, err
	}
	sources := deriveSources(candidate, bindings)
	// Every source's user, held as serve holds them at start -- the
	// platforms already configured included, whose accounts may have
	// changed since they were written -- before any adapter is run.
	if err := host.switching(sources); err != nil {
		return out, err
	}
	// The platform's own sources, each asked once; the first that cannot
	// answer ends the connect, and nothing is written.
	var names []string
	for name := range sources {
		if strings.HasPrefix(name, req.platform+"/") {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	for _, name := range names {
		report, err := check(ctx, sources[name])
		if err != nil {
			return out, fmt.Errorf("%s: %v", name, err)
		}
		answer, err := describeCheck(sources[name].shape, report)
		if err != nil {
			return out, fmt.Errorf("%s: %v", name, err)
		}
		out.answers = append(out.answers, name+": "+answer)
	}
	// The file is put in place only if it is still what was read: a
	// connect that raced this one is not written over.
	if err := file.replace(data, text); err != nil {
		return out, err
	}
	out.written = req.config
	return out, nil
}

// pinBinding reads a catalog entry by name and pins it: the reference the
// configuration will carry, and the binding those bytes hold.
func pinBinding(catalog, name string) (string, binding, error) {
	if name == "" || name != filepath.Base(name) || strings.ContainsAny(name, "/\\@") || name == "." || name == ".." {
		return "", binding{}, fmt.Errorf("binding %q is not a catalog name", name)
	}
	path := filepath.Join(catalog, name+".json")
	data, err := readBounded(path, maxEngineConfigBytes)
	if err != nil {
		return "", binding{}, fmt.Errorf("binding %s is not in the catalog %s: %v", name, catalog, err)
	}
	sum := sha256.Sum256(data)
	ref := name + "@sha256:" + hex.EncodeToString(sum[:])
	b, err := parseBinding(data)
	if err != nil {
		return "", binding{}, fmt.Errorf("binding %s: %v", ref, err)
	}
	if b.platform != name {
		return "", binding{}, fmt.Errorf("binding %s: the file names platform %q", ref, b.platform)
	}
	return ref, b, nil
}

// newPlatformEntry is the platform as the configuration will hold it,
// under the rules the parser applies to one it reads, with a credentials
// file for exactly the operations the binding offers.
func newPlatformEntry(req connectRequest, ref string, b binding, account func(name string) (int, string, error)) (platformConfig, error) {
	p := platformConfig{name: req.platform, binding: ref, user: req.user, endpoint: req.endpoint, write: req.write, credentials: map[string]string{}}
	// Everything written into the file is written as JSON text, which
	// carries only valid UTF-8: a byte that is not would come back as a
	// different path, or name.
	for _, s := range append([]string{req.platform, req.binding, req.user, req.endpoint}, req.environment...) {
		if !utf8.ValidString(s) {
			return p, errors.New("a request value is not valid UTF-8; it could not be written as given")
		}
	}
	for op, path := range req.credentials {
		if !utf8.ValidString(op) || !utf8.ValidString(path) {
			return p, errors.New("a credentials path is not valid UTF-8; it could not be written as given")
		}
		credentials, err := cleanAbsolutePath("credentials-file "+op, path)
		if err != nil {
			return p, err
		}
		p.credentials[op] = credentials
	}
	if err := credentialsMatch(p.credentials, b); err != nil {
		return p, fmt.Errorf("platform %s: %v", req.platform, err)
	}
	if req.user == "" {
		return p, errors.New("user must name the OS user the platform's adapters run as")
	}
	seen := map[string]bool{}
	for _, pair := range req.environment {
		key, value, ok := strings.Cut(pair, "=")
		if !ok || key == "" || strings.ContainsAny(key, "=\x00") || strings.ContainsAny(value, "\n\x00") {
			return p, fmt.Errorf("environment %q is not KEY=VALUE", pair)
		}
		if sameEnvKey(key, "HOME") || sameEnvKey(key, "PATH") {
			return p, fmt.Errorf("environment may not set %s; HOME is the user's own and PATH the engine's", key)
		}
		if seen[key] {
			return p, fmt.Errorf("environment sets %s twice", key)
		}
		seen[key] = true
		p.environment = append(p.environment, key+"="+value)
	}
	uid, home, err := account(req.user)
	if err != nil {
		return p, fmt.Errorf("platform %s: %v", req.platform, err)
	}
	p.uid, p.home = uid, home
	return p, nil
}

// runCheck starts the derived source's adapter with --check in front of
// its arguments, in its declared environment and its own process group,
// with nothing on stdin, and returns what it reported. A failure carries
// the adapter's first line of stderr, which is where an adapter says why.
func runCheck(ctx context.Context, spec sourceSpec) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, checkTimeout+checkGrace)
	defer cancel()
	path, err := exec.LookPath(spec.argv[0])
	if err != nil {
		return nil, fmt.Errorf("adapter could not be started: %v", err)
	}
	argv := append(append([]string{spec.argv[0], "--check", "--timeout=" + checkTimeout.String()}, spec.check...), spec.argv[1:]...)
	cmd := exec.CommandContext(ctx, path, argv[1:]...)
	cmd.Args = argv
	cmd.Stdin = bytes.NewReader(nil)
	cmd.Env = sourceEnvironment(spec)
	group, err := prepareSourceProcess(cmd, spec.user)
	if err != nil {
		return nil, err
	}
	cmd.WaitDelay = sourceWaitDelay
	stdout := &boundedBuffer{limit: checkMaxOutput, stop: cancel}
	stderr := &boundedBuffer{limit: 4096}
	cmd.Stdout, cmd.Stderr = stdout, stderr
	if err := group.start(cmd); err != nil {
		group.reap()
		return nil, fmt.Errorf("adapter could not be started: %v", err)
	}
	waitErr := cmd.Wait()
	group.reap()
	if stdout.overflowed {
		return nil, fmt.Errorf("the adapter's report exceeds %d bytes", checkMaxOutput)
	}
	if waitErr != nil {
		if errors.Is(waitErr, exec.ErrWaitDelay) {
			return nil, errors.New("the adapter exited but left its output open past the deadline; a descendant is holding the pipe")
		}
		// An adapter that could not check writes why as a report of the
		// same shape; failing that, its first line of stderr says.
		if reason, ok := failedCheck(stdout.buf.Bytes()); ok {
			return nil, errors.New(reason)
		}
		first, _, _ := strings.Cut(strings.TrimSpace(stderr.buf.String()), "\n")
		if len(first) > 200 {
			first = first[:200]
		}
		if first == "" {
			first = waitErr.Error()
		}
		return nil, errors.New(first)
	}
	return stdout.buf.Bytes(), nil
}

// failedCheck reads the report of a check that did not succeed: its
// reason, when the bytes are such a report.
func failedCheck(report []byte) (string, bool) {
	var top map[string]json.RawMessage
	if err := json.Unmarshal(report, &top); err != nil || len(top) != 1 || len(top["check"]) == 0 {
		return "", false
	}
	var check struct {
		Status  string `json:"status"`
		Message string `json:"message"`
	}
	if err := json.Unmarshal(top["check"], &check); err != nil || check.Status != "failed" || check.Message == "" {
		return "", false
	}
	return check.Message, true
}

// describeCheck reads an adapter's report and says what the platform
// answered, in one line for the operator.
func describeCheck(shape string, report []byte) (string, error) {
	var top map[string]json.RawMessage
	if err := json.Unmarshal(report, &top); err != nil || len(top) != 1 || len(top["check"]) == 0 {
		return "", errors.New("the adapter's report is not a check report")
	}
	var check struct {
		Adapter struct {
			Name    string `json:"name"`
			Version string `json:"version"`
			Digest  string `json:"digest"`
		} `json:"adapter"`
		Status  string `json:"status"`
		Message string `json:"message"`
		Server  struct {
			Name    string `json:"name"`
			Version string `json:"version"`
		} `json:"server"`
		ProtocolVersion string   `json:"protocolVersion"`
		Tools           []string `json:"tools"`
		Probe           *struct {
			Tool     string `json:"tool"`
			Answered bool   `json:"answered"`
		} `json:"probe"`
	}
	if err := json.Unmarshal(top["check"], &check); err != nil || check.Adapter.Name == "" || check.Adapter.Digest == "" {
		return "", errors.New("the adapter's report is not a check report")
	}
	if check.Status != "succeeded" {
		return "", fmt.Errorf("the adapter reported %q, not a success", check.Status)
	}
	who := check.Adapter.Name
	if check.Adapter.Version != "" {
		who += ":" + check.Adapter.Version
	}
	who += " (" + check.Adapter.Digest + ")"
	switch shape {
	case "airbyte":
		return who + " answered " + check.Status + ": " + check.Message, nil
	case "mcp":
		if check.ProtocolVersion == "" {
			return "", errors.New("the adapter's report names no protocol version")
		}
		server := strings.TrimSpace(check.Server.Name + " " + check.Server.Version)
		if server == "" {
			server = "an unnamed server"
		}
		line := who + ": server " + server + ", protocol " + check.ProtocolVersion + ", tools " + strings.Join(check.Tools, ", ")
		if check.Probe != nil {
			if !check.Probe.Answered {
				return "", fmt.Errorf("the probe %q did not answer", check.Probe.Tool)
			}
			line += "; " + check.Probe.Tool + " answered"
		}
		return line, nil
	}
	return "", fmt.Errorf("no check for shape %q", shape)
}

// renderPlatformEntry is the configuration with the entry in it, as the
// engine writes its own form: the file re-read as a value, the platform
// set under platforms, the whole rendered with members in canonical order.
func renderPlatformEntry(data []byte, req connectRequest, ref string) ([]byte, error) {
	v, err := parseJSON(data)
	if err != nil {
		return nil, fmt.Errorf("engine configuration: %v", err)
	}
	obj, err := requireObject(v, "engine configuration")
	if err != nil {
		return nil, err
	}
	platformsValue, _ := obj.get("platforms")
	platforms, err := requireObject(platformsValue, "platforms")
	if err != nil {
		return nil, err
	}
	entry := newObject()
	entry.set("binding", vString(ref))
	credentials := newObject()
	ops := make([]string, 0, len(req.credentials))
	for op := range req.credentials {
		ops = append(ops, op)
	}
	sort.Strings(ops)
	for _, op := range ops {
		file := newObject()
		file.set("file", vString(req.credentials[op]))
		credentials.set(op, file)
	}
	entry.set("credentials", credentials)
	entry.set("user", vString(req.user))
	if req.endpoint != "" {
		entry.set("endpoint", vString(req.endpoint))
	}
	if len(req.environment) > 0 {
		env := newObject()
		for _, pair := range req.environment {
			key, value, _ := strings.Cut(pair, "=")
			env.set(key, vString(value))
		}
		entry.set("environment", env)
	}
	if req.write {
		entry.set("write", vBool(true))
	}
	platforms.set(req.platform, entry)
	var sb strings.Builder
	formatValue(&sb, obj, "")
	sb.WriteByte('\n')
	return []byte(sb.String()), nil
}

// configFile is the engine configuration held for one connect: its
// directory open, so every read, write beside it and rename is in that
// directory whatever a path component is swapped for meanwhile; a lock
// beside it, so one connect at a time writes; and the file judged as one
// this command can put in place.
type configFile struct {
	dir    *os.Root
	base   string
	mode   os.FileMode
	owner  fileOwnerIDs
	unlock func()
	// afterOpen, when set, runs between opening the file and judging the
	// entry: a test's way of putting another file in the entry's place
	// at exactly that moment.
	afterOpen func()
}

func openConfigFile(path string) (*configFile, error) {
	dir, err := os.OpenRoot(filepath.Dir(path))
	if err != nil {
		return nil, fmt.Errorf("engine configuration: %v", err)
	}
	f := &configFile{dir: dir, base: filepath.Base(path)}
	// The directory itself must be one nobody else could replace an entry
	// of: owned by root or by this process, and writable beyond its owner
	// only with the sticky bit -- else another user could swap the private
	// directory the new file is written in before the rename.
	if info, err := dir.Stat("."); err != nil {
		dir.Close()
		return nil, fmt.Errorf("engine configuration: %v", err)
	} else if err := parentHeld(info); err != nil {
		dir.Close()
		return nil, fmt.Errorf("engine configuration: %s %v", filepath.Dir(path), err)
	}
	info, err := f.regular()
	if err != nil {
		dir.Close()
		return nil, err
	}
	f.mode = info.Mode().Perm()
	f.owner = ownerIDsOf(info)
	unlock, err := lockBeside(dir, f.base, f.owner)
	if err != nil {
		dir.Close()
		return nil, fmt.Errorf("engine configuration: %v", err)
	}
	f.unlock = unlock
	return f, nil
}

// regular is the file's state, refused when it is a link or not a file:
// the operator names the file, and a link's owner would otherwise choose
// which file the entry lands in.
func (f *configFile) regular() (os.FileInfo, error) {
	info, err := f.dir.Lstat(f.base)
	if err != nil {
		return nil, fmt.Errorf("engine configuration: %v", err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("engine configuration: %s is a symbolic link; name the file itself", filepath.Join(f.dir.Name(), f.base))
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("engine configuration: %s is not a regular file", filepath.Join(f.dir.Name(), f.base))
	}
	return info, nil
}

// read opens the file in the held directory without blocking, and reads
// the descriptor it holds only when that descriptor is the directory
// entry's own regular file: the entry judged and the file read are the
// same inode, so neither a link put in the file's place -- which the held
// directory would follow, within itself -- nor a FIFO, which would block,
// is read.
func (f *configFile) read() ([]byte, error) {
	file, err := openConfigForRead(f.dir, f.base)
	if err != nil {
		return nil, fmt.Errorf("engine configuration: %v", err)
	}
	defer file.Close()
	if f.afterOpen != nil {
		f.afterOpen()
	}
	info, err := file.Stat()
	if err != nil {
		return nil, fmt.Errorf("engine configuration: %v", err)
	}
	entry, err := f.regular()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || !os.SameFile(entry, info) {
		return nil, fmt.Errorf("engine configuration: %s is not the regular file it was", filepath.Join(f.dir.Name(), f.base))
	}
	data, err := readBoundedFrom(file, f.base, maxEngineConfigBytes)
	if err != nil {
		return nil, fmt.Errorf("engine configuration: %v", err)
	}
	return data, nil
}

// replace writes the content into a directory of this process's own,
// made beside the file for the purpose (0700, so no other user can swap
// what is in it), gives the new file the old one's mode and owner through
// the open descriptor, and renames it into place -- provided, read again
// just before the rename, the file still holds what the checks were run
// against. That holds against another connect, which takes the lock; an
// editor that does not is not held out, and its save in the instant
// between that read and the rename would be written over.
func (f *configFile) replace(read, content []byte) error {
	if _, err := f.regular(); err != nil {
		return err
	}
	var suffix [4]byte
	if _, err := rand.Read(suffix[:]); err != nil {
		return err
	}
	private := f.base + ".connect-" + hex.EncodeToString(suffix[:])
	if err := f.dir.Mkdir(private, 0o700); err != nil {
		return fmt.Errorf("engine configuration: %v", err)
	}
	defer f.dir.RemoveAll(private)
	tmp := private + "/new"
	file, err := f.dir.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, f.mode)
	if err != nil {
		return fmt.Errorf("engine configuration: %v", err)
	}
	fail := func(err error) error {
		file.Close()
		return fmt.Errorf("engine configuration: %v", err)
	}
	if _, err := file.Write(content); err != nil {
		return fail(err)
	}
	if err := file.Sync(); err != nil {
		return fail(err)
	}
	// The mode as it was, whatever the umask narrowed it to at creation,
	// and the owner as it was -- a directory with the setgid bit would
	// otherwise give the file its group -- both through the descriptor,
	// so they land on the file written and not on a name; or the rename
	// does not happen: a file the signer could read must stay one it can
	// read.
	if err := file.Chmod(f.mode); err != nil {
		return fail(err)
	}
	if err := keepOwner(file, f.owner); err != nil {
		return fail(err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("engine configuration: %v", err)
	}
	current, err := f.read()
	if err != nil {
		return err
	}
	if !bytes.Equal(current, read) {
		return errors.New("engine configuration: the file changed while the checks ran; run connect again")
	}
	if err := f.dir.Rename(tmp, f.base); err != nil {
		return fmt.Errorf("engine configuration: %v", err)
	}
	return nil
}

func (f *configFile) close() {
	if f.unlock != nil {
		f.unlock()
	}
	f.dir.Close()
}

// formatValue writes a value as indented JSON with members in canonical
// order: the form the engine writes its configuration in.
func formatValue(sb *strings.Builder, v value, indent string) {
	switch x := v.(type) {
	case *vObject:
		if len(x.names) == 0 {
			sb.WriteString("{}")
			return
		}
		names := append([]string(nil), x.names...)
		sort.Strings(names)
		sb.WriteString("{\n")
		for i, name := range names {
			sb.WriteString(indent + "  ")
			writeCanonicalString(sb, name)
			sb.WriteString(": ")
			formatValue(sb, x.byName[name], indent+"  ")
			if i+1 < len(names) {
				sb.WriteByte(',')
			}
			sb.WriteByte('\n')
		}
		sb.WriteString(indent + "}")
	case vArray:
		if len(x) == 0 {
			sb.WriteString("[]")
			return
		}
		sb.WriteString("[\n")
		for i, item := range x {
			sb.WriteString(indent + "  ")
			formatValue(sb, item, indent+"  ")
			if i+1 < len(x) {
				sb.WriteByte(',')
			}
			sb.WriteByte('\n')
		}
		sb.WriteString(indent + "]")
	default:
		x.canonWrite(sb)
	}
}
